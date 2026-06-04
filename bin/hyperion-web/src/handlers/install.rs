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
    };
    Html(
        tpl.render()
            .unwrap_or_else(|_| "<h1>render error</h1>".into()),
    )
    .into_response()
}
