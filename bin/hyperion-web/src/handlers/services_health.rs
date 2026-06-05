//! `/services` — operator-facing system services health page.
//!
//! Lists the systemd units Hyperion depends on (nginx, mariadb,
//! postgresql, php-fpm versions, vsftpd, hyperion-agent, hyperion-web)
//! with active/enabled/sub-state for each, colour-coded by severity.
//! Includes per-row Restart / Install buttons for super_admin.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{NodeSummary, ServicesHealth};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "services_health.html")]
struct ServicesHealthTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    health: ServicesHealth,
    error: Option<String>,
    flash: Option<String>,
    flash_error: Option<String>,
    is_super_admin: bool,
    csrf_token: String,
    /// All enrolled remote nodes (used to render the node switcher).
    /// Empty on single-node setups.
    nodes: Vec<NodeSummary>,
    /// Currently-displayed node — "" / "local" for master, else
    /// the node_id we dispatched to.
    current_node: String,
    /// Human label for the page header ("master" / node label).
    current_label: String,
}

#[derive(Deserialize, Default)]
pub struct ServicesQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    flash_error: Option<String>,
    /// Target node for the probe — "" / missing = master.
    #[serde(default)]
    node: Option<String>,
}

pub async fn get_services_health(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<ServicesQuery>,
) -> Result<Response, AppError> {
    let target = q.node.as_deref();
    let dispatch = match crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::ServicesHealth,
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(e) => Err(e),
    };
    let (health, error) = match dispatch {
        Ok(RpcResponse::ServicesHealth(h)) => (h, None),
        Ok(RpcResponse::Error(e)) => (ServicesHealth::default(), Some(e.to_string())),
        Ok(_) => (
            ServicesHealth::default(),
            Some("unexpected agent response".into()),
        ),
        Err(e) => (ServicesHealth::default(), Some(e.to_string())),
    };
    let nodes = fetch_node_list(&state).await.unwrap_or_default();
    let current_node = match target {
        None | Some("") | Some("local") => String::new(),
        Some(s) => s.to_string(),
    };
    let current_label = label_for_node(&current_node, &nodes);
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let tpl = ServicesHealthTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "services",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        health,
        error,
        flash: q.flash,
        flash_error: q.flash_error,
        is_super_admin: ctx.is_super_admin(),
        csrf_token,
        nodes,
        current_node,
        current_label,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Fetch enrolled nodes from the master so the page can render the
/// "View on node:" switcher. Failure logs + leaves the switcher
/// empty — single-node UX still works.
async fn fetch_node_list(state: &SharedState) -> Result<Vec<NodeSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await?;
    match resp {
        RpcResponse::NodesList(v) => Ok(v),
        _ => Err(AppError::Internal("unexpected NodesList response".into())),
    }
}

fn label_for_node(current: &str, nodes: &[NodeSummary]) -> String {
    if current.is_empty() {
        return "master (this node)".to_string();
    }
    nodes
        .iter()
        .find(|n| n.node_id == current)
        .map(|n| match n.public_ip.as_deref() {
            Some(ip) if !ip.is_empty() => format!("{} ({})", n.label, ip),
            _ => n.label.clone(),
        })
        .unwrap_or_else(|| current.to_string())
}

#[derive(Deserialize)]
pub struct ServiceActionForm {
    pub name: String,
    /// Target node ("" / "local" / node_id). Same convention as
    /// the GET handler.
    #[serde(default)]
    pub node: String,
}

/// POST /services/restart — super_admin only.
pub async fn post_service_restart(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ServiceActionForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let target = if form.node.is_empty()
        || form.node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(form.node.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::ServiceRestart {
            name: form.name.clone(),
        },
    )
    .await?;
    let dest = match resp {
        RpcResponse::ServiceRestart => format!(
            "/services?{}flash=Service+{}+restarted",
            query_node_prefix(target),
            urlencode(&form.name),
        ),
        RpcResponse::Error(e) => format!(
            "/services?{}flash_error={}",
            query_node_prefix(target),
            urlencode(&e.to_string()),
        ),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}

/// POST /services/install — super_admin only.
///
/// The RPC now starts a background apt-get install + systemctl
/// enable task and returns immediately. The page redirect lands
/// the operator on /services where a live-progress panel (polled
/// via HTMX) shows the rolling log tail until the job finishes.
pub async fn post_service_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ServiceActionForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let target = if form.node.is_empty()
        || form.node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(form.node.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::ServiceInstall {
            name: form.name.clone(),
        },
    )
    .await?;
    let dest = match resp {
        RpcResponse::ServiceInstall => format!(
            "/services?{}flash=Install+of+{}+started+%E2%80%94+see+live+progress+below#install-progress",
            query_node_prefix(target),
            urlencode(&form.name),
        ),
        RpcResponse::Error(e) => format!(
            "/services?{}flash_error={}",
            query_node_prefix(target),
            urlencode(&e.to_string()),
        ),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}

/// GET /services/install-status?node=… — tiny HTML fragment with
/// the live state pill + log tail. UI polls via HTMX. No-cache.
#[derive(Deserialize, Default)]
pub struct InstallStatusQuery {
    #[serde(default)]
    pub node: Option<String>,
}

pub async fn get_service_install_status(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<InstallStatusQuery>,
) -> Response {
    if !ctx.is_admin_or_higher() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<span class=\"pill err\">admin only</span>",
        )
            .into_response();
    }
    let target = match q.node.as_deref() {
        None | Some("") | Some("local") => None,
        Some(s) => Some(s),
    };
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target, Request::ServiceInstallStatus).await;
    let body = match resp {
        Ok(RpcResponse::ServiceInstallStatus(s)) => render_install_status(&s),
        Ok(RpcResponse::Error(e)) => format!(
            "<div class=\"text-soft small\">status RPC error: {}</div>",
            escape(&e.to_string())
        ),
        Ok(_) => "<div class=\"text-soft small\">unexpected response</div>".to_string(),
        Err(e) => format!(
            "<div class=\"text-soft small\">unreachable: {}</div>",
            escape(&e.to_string())
        ),
    };
    (
        axum::http::StatusCode::OK,
        [
            ("content-type", "text/html; charset=utf-8"),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response()
}

fn render_install_status(s: &hyperion_types::ServiceInstallStatus) -> String {
    if s.started_at == 0 {
        return "<div class=\"text-soft small\">no service install has run on this node yet — click <strong>Install</strong> on a row above</div>".to_string();
    }
    let pill = match s.state.as_str() {
        "running" => "<span class=\"pill warn pulse\">installing…</span>",
        "succeeded" => "<span class=\"pill ok\">installed</span>",
        "failed" => "<span class=\"pill err\">failed</span>",
        _ => "<span class=\"pill\">unknown</span>",
    };
    let mut out = format!(
        "<div style=\"display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap\">\
            {pill} <strong>{}</strong> <span class=\"text-soft small\">(apt pkg <code>{}</code>)</span>",
        escape(&s.service_name),
        escape(&s.pkg),
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
            "<pre style=\"max-height:18rem;overflow:auto;background:var(--surface-1);padding:0.6rem 0.8rem;border-radius:6px;margin:0.6rem 0 0;font-size:0.78rem;line-height:1.45\">{}</pre>",
            escape(&s.log_tail)
        ));
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render `node=<id>&` for redirects, or empty for the master so
/// the URL stays clean. Always include the trailing `&` because
/// the callers chain `flash=` after it.
fn query_node_prefix(target: Option<&str>) -> String {
    match target {
        Some(id) if !id.is_empty() => format!("node={}&", urlencode(id)),
        _ => String::new(),
    }
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

#[derive(Deserialize)]
pub struct RemountForm {
    /// Target node — empty / "local" = master, otherwise node_id
    /// from /install. Matches the same pattern as the install/
    /// restart forms on this page.
    #[serde(default)]
    pub node: String,
}

/// POST /services/remount-usr-rw — one-click `mount -o remount,rw /`
/// against the chosen node. Used when the operator hit the
/// "/usr is not writable" preflight on a service-install attempt
/// and would otherwise have to SSH in. Confirmation modal in the
/// template warns about the risk (non-persistent across reboots,
/// might fail on snap-managed images).
pub async fn post_remount_usr_rw(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RemountForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let target = if form.node.is_empty()
        || form.node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(form.node.as_str())
    };
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target, Request::RemountUsrRw).await?;
    let dest = match resp {
        RpcResponse::RemountUsrRw { success, message } => {
            let label = if success { "flash" } else { "flash_error" };
            let head = if success {
                "/usr is now writable — retry the install."
            } else {
                "Remount FAILED — see details:"
            };
            // Strip newlines so the redirect Location header stays
            // single-line; the body is short anyway.
            let msg = format!("{head} {}", message.replace('\n', " "));
            format!(
                "/services?{}{label}={}",
                query_node_prefix(target),
                urlencode(&msg)
            )
        }
        RpcResponse::Error(e) => format!(
            "/services?{}flash_error={}",
            query_node_prefix(target),
            urlencode(&e.to_string())
        ),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}
