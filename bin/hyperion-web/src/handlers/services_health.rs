//! `/services` — operator-facing system services health page.
//!
//! Lists the systemd units Hyperion depends on (nginx, mariadb,
//! postgresql, php-fpm versions, vsftpd, hyperion-agent, hyperion-web)
//! with active/enabled/sub-state for each, colour-coded by severity.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::ServicesHealth;

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
}

pub async fn get_services_health(
    State(state): State<SharedState>,
    ctx: AuthCtx,
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
    let tpl = ServicesHealthTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "services",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        health,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
}
