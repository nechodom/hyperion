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
    total_count: usize,
    limit: i64,
    q: String,
    action_filter: String,
    result_filter: String,
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    q: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    result: String,
}

fn default_limit() -> i64 {
    200
}

pub async fn get_audit(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<AuditQuery>,
) -> Result<Response, AppError> {
    let limit = q.limit.clamp(1, 1000);
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::AuditList { limit }).await?;
    let all = match resp {
        RpcResponse::AuditList(v) => v,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let total_count = all.len();
    let needle = q.q.trim().to_lowercase();
    let action_filter = q.action.trim().to_lowercase();
    let result_filter = q.result.trim().to_lowercase();
    let rows: Vec<AuditEntryWire> = all
        .into_iter()
        .filter(|r| {
            if needle.is_empty() {
                return true;
            }
            r.action.to_lowercase().contains(&needle)
                || r.target
                    .as_deref()
                    .map(|t| t.to_lowercase().contains(&needle))
                    .unwrap_or(false)
                || r.actor_label.to_lowercase().contains(&needle)
                || r.payload_json.to_lowercase().contains(&needle)
        })
        .filter(|r| action_filter.is_empty() || r.action.to_lowercase().contains(&action_filter))
        .filter(|r| result_filter.is_empty() || r.result.to_lowercase() == result_filter)
        .collect();
    let tpl = AuditTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "audit",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows,
        total_count,
        limit,
        q: q.q,
        action_filter,
        result_filter,
    };
    Ok(Html(tpl.render()?).into_response())
}
