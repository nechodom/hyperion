//! `/install` — show install command + manage node enrollment tokens.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{NodeInviteMint, NodeInviteSummary, NodeSummary};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "install.html")]
struct InstallTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    master_url: &'a str,
    invites: Vec<NodeInviteSummary>,
    nodes: Vec<NodeSummary>,
    just_minted: Option<NodeInviteMint>,
    error: Option<String>,
    csrf_create: String,
    csrf_revoke: String,
    /// CSRF token for the per-row "Test connectivity" button.
    /// Same wildcard token covers both inline HTMX POSTs and the
    /// JS-free fallback.
    csrf_test: String,
    /// CSRF for the per-row "Update node" button (apt + hyperion).
    csrf_update: String,
}

pub async fn get_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Minting + revoking invite tokens enrols new boxes into the
    // cluster. Viewers shouldn't even see the page — the plaintext
    // token + master URL on the install one-liner is enough to
    // social-engineer a misconfigured node into a malicious cluster.
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required+for+node+enrollment").into_response());
    }
    let invites = fetch_invites(&state).await.unwrap_or_default();
    let nodes = fetch_nodes(&state).await.unwrap_or_default();
    let master_url = derive_master_url(&state, &headers).await;
    let tpl = InstallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "install",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        master_url: &master_url,
        invites,
        nodes,
        just_minted: None,
        error: None,
        csrf_create: csrf_token(&state, &ctx, "/install/invite"),
        csrf_revoke: csrf_token(&state, &ctx, "/install/invite/revoke"),
        csrf_test: csrf_token(&state, &ctx, "/install/test-node"),
        csrf_update: csrf_token(&state, &ctx, "/install/update-node"),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct CreateForm {
    label: String,
    #[serde(default = "default_ttl")]
    ttl_hours: i64,
}
fn default_ttl() -> i64 {
    24
}

pub async fn post_invite(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required+for+node+enrollment").into_response());
    }
    let label = form.label.trim().to_string();
    if label.is_empty() {
        return Ok(render_with_error(&state, &ctx, &headers, "Label must not be empty").await);
    }
    let ttl_secs = form.ttl_hours.clamp(1, 30 * 24) * 3600;
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::InviteCreate { label, ttl_secs },
    )
    .await?;
    let mint = match resp {
        RpcResponse::InviteCreate(m) => m,
        RpcResponse::Error(e) => {
            return Ok(render_with_error(&state, &ctx, &headers, &e.to_string()).await);
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let invites = fetch_invites(&state).await.unwrap_or_default();
    let nodes = fetch_nodes(&state).await.unwrap_or_default();
    let master_url = derive_master_url(&state, &headers).await;
    let tpl = InstallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "install",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        master_url: &master_url,
        invites,
        nodes,
        just_minted: Some(mint),
        error: None,
        csrf_create: csrf_token(&state, &ctx, "/install/invite"),
        csrf_revoke: csrf_token(&state, &ctx, "/install/invite/revoke"),
        csrf_test: csrf_token(&state, &ctx, "/install/test-node"),
        csrf_update: csrf_token(&state, &ctx, "/install/update-node"),
    };
    // The rendered page carries the plaintext invite token. Make sure
    // browser/proxy caches don't keep it around past the first view.
    let mut response = Html(tpl.render()?).into_response();
    let h = response.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    h.insert(axum::http::header::PRAGMA, axum::http::HeaderValue::from_static("no-cache"));
    h.insert("vary", axum::http::HeaderValue::from_static("Cookie"));
    Ok(response)
}

#[derive(Deserialize)]
pub struct RevokeForm {
    token_hash: String,
}

pub async fn post_revoke(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RevokeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required+for+node+enrollment").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::InviteRevoke {
            token_hash: form.token_hash,
        },
    )
    .await?;
    match resp {
        RpcResponse::InviteRevoke => Ok(Redirect::to("/install").into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /install/update-node — super_admin only.
///
/// Starts a background apt + hyperion update on the chosen node
/// via the signed-RPC channel. Returns immediately; operator polls
/// status via /install/update-node-status or sees the log on
/// /install (auto-refresh shows the rolling tail).
#[derive(Deserialize)]
pub struct UpdateNodeForm {
    node_id: String,
    #[serde(default)]
    do_apt: Option<String>,
    #[serde(default)]
    do_hyperion: Option<String>,
}

pub async fn post_update_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<UpdateNodeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let node_id = form.node_id.trim().to_string();
    if node_id.is_empty() {
        return Err(AppError::BadRequest("missing node_id".into()));
    }
    let do_apt = matches!(form.do_apt.as_deref(), Some("on" | "true" | "1"));
    let do_hyperion = matches!(form.do_hyperion.as_deref(), Some("on" | "true" | "1"));
    if !do_apt && !do_hyperion {
        return Ok(Redirect::to(
            "/install?flash_error=nothing+to+update+%28tick+at+least+one+option%29",
        )
        .into_response());
    }
    // Special-case: target "local" runs the update on the master itself.
    let target = if node_id == "local" || node_id.is_empty() {
        None
    } else {
        Some(node_id.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::NodeUpdateRun { do_apt, do_hyperion },
    )
    .await?;
    match resp {
        RpcResponse::NodeUpdateRun { started_at } => {
            Ok(Redirect::to(&format!(
                "/install?flash=update+started+%28unix%3A{}%29#node-{}",
                started_at,
                urlencode(&node_id)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => {
            Ok(Redirect::to(&format!(
                "/install?flash_error={}",
                urlencode(&format!("update failed to start: {e}"))
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// GET /install/update-node-status?node_id=… — returns a tiny HTML
/// fragment with state pill + log tail. UI polls this via HTMX.
#[derive(Deserialize)]
pub struct UpdateNodeStatusQuery {
    node_id: String,
}

pub async fn get_update_node_status(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<UpdateNodeStatusQuery>,
) -> Response {
    if !ctx.is_super_admin() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<span class=\"pill err\">admin only</span>",
        )
            .into_response();
    }
    let node_id = q.node_id.trim();
    let target = if node_id == "local" || node_id.is_empty() {
        None
    } else {
        Some(node_id)
    };
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target, Request::NodeUpdateStatus).await;
    let body = match resp {
        Ok(RpcResponse::NodeUpdateStatus(s)) => render_update_status(&s),
        Ok(RpcResponse::Error(e)) => format!(
            "<div class=\"text-soft small\">status RPC error: {}</div>",
            html_escape(&e.to_string())
        ),
        Ok(_) => "<div class=\"text-soft small\">unexpected response</div>".to_string(),
        Err(e) => format!(
            "<div class=\"text-soft small\">unreachable: {}</div>",
            html_escape(&e.to_string())
        ),
    };
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Format a NodeUpdateStatus as a small HTML fragment for the
/// /install per-row poll target.
fn render_update_status(s: &hyperion_types::NodeUpdateStatus) -> String {
    if s.started_at == 0 {
        return "<span class=\"text-soft small\">no update has run on this node</span>"
            .to_string();
    }
    let pill = match s.state.as_str() {
        "running" => "<span class=\"pill warn pulse\">running</span>",
        "succeeded" => "<span class=\"pill ok\">done</span>",
        "failed" => "<span class=\"pill err\">failed</span>",
        _ => "<span class=\"pill\">unknown</span>",
    };
    let scope = match (s.do_apt, s.do_hyperion) {
        (true, true) => "apt + hyperion",
        (true, false) => "apt only",
        (false, true) => "hyperion only",
        _ => "nothing",
    };
    let mut out = format!(
        "<div style=\"display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap\">\
            {pill} <span class=\"text-soft small\">{scope}</span>"
    );
    if s.state == "failed" {
        out.push_str(&format!(
            " <span class=\"text-soft small\">exit {}</span>",
            s.exit_code
        ));
    }
    out.push_str("</div>");
    if !s.log_tail.is_empty() {
        out.push_str(&format!(
            "<pre style=\"max-height:14rem;overflow:auto;background:var(--surface-1);padding:0.5rem 0.7rem;border-radius:6px;margin:0.5rem 0 0;font-size:0.78rem;line-height:1.45\">{}</pre>",
            html_escape(&s.log_tail)
        ));
    }
    out
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b' ' => "+".to_string(),
            b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b if b.is_ascii_alphanumeric() => (b as char).to_string(),
            b => format!("%{:02X}", b),
        })
        .collect()
}

/// POST /install/test-node — super_admin only.
///
/// Master-side connectivity probe to a remote node. Replaces the
/// "ssh in + curl :9443 + check ss -tlnp" debug ritual: master
/// dispatches an `AgentInfo` over the signed-RPC channel and
/// reports back what happened. Operator gets one of:
///   - ✓ reachable (with agent version + hosting count for sanity)
///   - ✗ no public_ip on record
///   - ✗ remote-RPC signer not loaded
///   - ✗ connection failed (curl message verbatim)
///   - ✗ auth failed (pubkey not yet propagated; wait a heartbeat)
///
/// Returned as HTML fragment so the page can swap it inline via
/// HTMX without reloading.
#[derive(Deserialize)]
pub struct TestNodeForm {
    node_id: String,
}

pub async fn post_test_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<TestNodeForm>,
) -> Response {
    if !ctx.is_super_admin() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<span class=\"pill err\">admin role required</span>",
        )
            .into_response();
    }
    let node_id = form.node_id.trim();
    if node_id.is_empty() {
        return html_pill_err("missing node_id");
    }
    let started = std::time::Instant::now();
    let result = crate::dispatcher::dispatch_to_node(
        &state,
        Some(node_id),
        Request::AgentInfo,
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis();
    match result {
        Ok(RpcResponse::AgentInfo(info)) => html_pill_ok(&format!(
            "reachable · v{} · {} hostings · {} ms",
            info.version, info.hostings_count, elapsed_ms
        )),
        Ok(RpcResponse::Error(e)) => html_pill_err(&format!("agent error: {e}")),
        Ok(_) => html_pill_err("unexpected response"),
        Err(e) => html_pill_err(&e.to_string()),
    }
}

fn html_pill_ok(msg: &str) -> Response {
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        format!(
            "<span class=\"pill ok\" title=\"{}\">✓ {}</span>",
            html_escape(msg),
            html_escape(msg)
        ),
    )
        .into_response()
}

fn html_pill_err(msg: &str) -> Response {
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        format!(
            "<span class=\"pill err\" title=\"{}\">✗ {}</span>",
            html_escape(msg),
            html_escape(msg)
        ),
    )
        .into_response()
}

/// Minimal HTML-attribute escape sufficient for the pill above.
/// (askama would be overkill for a single-fragment response.)
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn fetch_invites(state: &SharedState) -> Result<Vec<NodeInviteSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::InviteList).await?;
    match resp {
        RpcResponse::InviteList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_nodes(state: &SharedState) -> Result<Vec<NodeSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await?;
    match resp {
        RpcResponse::NodesList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// derive_master_url lives in handlers::mod — see there for the
// loopback-detection logic and the public-IP fallback rationale.
use super::derive_master_url;

fn csrf_token(state: &SharedState, ctx: &AuthCtx, form_id: &str) -> String {
    let sid = ctx
        .session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default();
    hyperion_auth::csrf::mint(
        state.csrf_key.as_ref(),
        &sid,
        form_id,
        hyperion_types::now_secs(),
    )
}

async fn render_with_error(
    state: &SharedState,
    ctx: &AuthCtx,
    headers: &HeaderMap,
    message: &str,
) -> Response {
    let invites = fetch_invites(state).await.unwrap_or_default();
    let nodes = fetch_nodes(state).await.unwrap_or_default();
    let master_url = derive_master_url(state, headers).await;
    let tpl = InstallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "install",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        master_url: &master_url,
        invites,
        nodes,
        just_minted: None,
        error: Some(message.to_string()),
        csrf_create: csrf_token(state, ctx, "/install/invite"),
        csrf_revoke: csrf_token(state, ctx, "/install/invite/revoke"),
        csrf_test: csrf_token(state, ctx, "/install/test-node"),
        csrf_update: csrf_token(state, ctx, "/install/update-node"),
    };
    Html(
        tpl.render()
            .unwrap_or_else(|_| "<h1>render error</h1>".into()),
    )
    .into_response()
}
