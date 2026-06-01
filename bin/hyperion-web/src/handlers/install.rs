//! `/install` — show install command + manage node enrollment tokens.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{NodeInviteMint, NodeInviteSummary};
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
    just_minted: Option<NodeInviteMint>,
    error: Option<String>,
    csrf_create: String,
    csrf_revoke: String,
}

pub async fn get_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let invites = fetch_invites(&state).await.unwrap_or_default();
    let master_url = derive_master_url(&state);
    let tpl = InstallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "install",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        master_url: &master_url,
        invites,
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
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    let label = form.label.trim().to_string();
    if label.is_empty() {
        return Ok(render_with_error(&state, &ctx, "Label must not be empty").await);
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
            return Ok(render_with_error(&state, &ctx, &e.to_string()).await);
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let invites = fetch_invites(&state).await.unwrap_or_default();
    let master_url = derive_master_url(&state);
    let tpl = InstallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "install",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        master_url: &master_url,
        invites,
        just_minted: Some(mint),
        error: None,
        csrf_create: csrf_token(&state, &ctx, "/install/invite"),
        csrf_revoke: csrf_token(&state, &ctx, "/install/invite/revoke"),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct RevokeForm {
    token_hash: String,
}

pub async fn post_revoke(
    State(state): State<SharedState>,
    Form(form): Form<RevokeForm>,
) -> Result<Response, AppError> {
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

fn derive_master_url(state: &SharedState) -> String {
    // Best-effort: take the listen address from config, prefix with https://
    // (or http:// if secure_cookies is off). Operator can override via the
    // page form later if needed.
    let scheme = if state.cfg.web.secure_cookies {
        "https"
    } else {
        "http"
    };
    format!("{}://{}", scheme, &state.cfg.web.listen)
}

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

async fn render_with_error(state: &SharedState, ctx: &AuthCtx, message: &str) -> Response {
    let invites = fetch_invites(state).await.unwrap_or_default();
    let master_url = derive_master_url(state);
    let tpl = InstallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "install",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        master_url: &master_url,
        invites,
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
