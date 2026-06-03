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
use hyperion_types::ServicesHealth;
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
}

#[derive(Deserialize, Default)]
pub struct ServicesQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    flash_error: Option<String>,
}

pub async fn get_services_health(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<ServicesQuery>,
) -> Result<Response, AppError> {
    let (health, error) = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ServicesHealth,
    )
    .await
    {
        Ok(RpcResponse::ServicesHealth(h)) => (h, None),
        Ok(RpcResponse::Error(e)) => (ServicesHealth::default(), Some(e.to_string())),
        Ok(_) => (
            ServicesHealth::default(),
            Some("unexpected agent response".into()),
        ),
        Err(e) => (ServicesHealth::default(), Some(format!("rpc: {e}"))),
    };
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
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct ServiceActionForm {
    pub name: String,
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
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ServiceRestart { name: form.name.clone() },
    )
    .await
    .map_err(AppError::from)?;
    let dest = match resp {
        RpcResponse::ServiceRestart => format!("/services?flash=Service+{}+restarted", urlencode(&form.name)),
        RpcResponse::Error(e) => format!("/services?flash_error={}", urlencode(&e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}

/// POST /services/install — super_admin only.
pub async fn post_service_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ServiceActionForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ServiceInstall { name: form.name.clone() },
    )
    .await
    .map_err(AppError::from)?;
    let dest = match resp {
        RpcResponse::ServiceInstall => format!("/services?flash=Service+{}+installed+and+started", urlencode(&form.name)),
        RpcResponse::Error(e) => format!("/services?flash_error={}", urlencode(&e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
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
