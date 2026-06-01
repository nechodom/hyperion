use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::AgentInfo;
use hyperion_types::HostingSummary;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    agent_info: Option<AgentInfo>,
    recent: Vec<HostingSummary>,
    error: Option<String>,
}

pub async fn get_dashboard(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let (info, recent, error) = fetch(&state).await;
    let tpl = DashboardTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "dashboard",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        agent_info: info,
        recent,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
}

async fn fetch(state: &SharedState) -> (Option<AgentInfo>, Vec<HostingSummary>, Option<String>) {
    let info = match hyperion_rpc_client::call(&state.agent_socket, Request::AgentInfo).await {
        Ok(RpcResponse::AgentInfo(i)) => Some(i),
        Ok(RpcResponse::Error(e)) => {
            return (None, vec![], Some(format!("agent: {e}")));
        }
        Ok(_) => return (None, vec![], Some("unexpected agent response".into())),
        Err(e) => return (None, vec![], Some(format!("rpc: {e}"))),
    };
    let recent = match hyperion_rpc_client::call(&state.agent_socket, Request::HostingList).await {
        Ok(RpcResponse::HostingList(mut v)) => {
            v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            v.into_iter().take(8).collect()
        }
        _ => vec![],
    };
    (info, recent, None)
}
