use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::AuditEntryWire;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    rows: Vec<AuditEntryWire>,
    limit: i64,
}

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

pub async fn get_audit(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<AuditQuery>,
) -> Result<Response, AppError> {
    let limit = q.limit.clamp(1, 1000);
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::AuditList { limit }).await?;
    let rows = match resp {
        RpcResponse::AuditList(v) => v,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let tpl = AuditTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "audit",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows,
        limit,
    };
    Ok(Html(tpl.render()?).into_response())
}
