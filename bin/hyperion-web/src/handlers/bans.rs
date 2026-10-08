//! /bans — the old cluster ban list, now the "Banned now" section of
//! /protection (which also shows what the WAF refused and the ban history).
//! `GET /bans` redirects there; `POST /bans/unban` stays, lifting a ban on
//! its owning node.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use serde::Deserialize;

/// GET /bans — moved; bookmarks and old links land on the bans section.
pub async fn get_bans() -> Response {
    Redirect::permanent("/protection#bans").into_response()
}

#[derive(Deserialize)]
pub struct ClusterUnbanForm {
    pub ip: String,
    /// Node the ban lives on ("local" = master).
    #[serde(default)]
    pub node_id: String,
}

/// POST /bans/unban — lift a ban on its owning node, then back to the bans
/// section of /protection.
pub async fn post_unban(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::Form(form): axum::Form<ClusterUnbanForm>,
) -> Result<Response, AppError> {
    // Cluster-wide bans: require all-hostings scope (tenant roles with
    // SecurityManage act only on their own hostings, not the cluster view).
    if !(ctx.can(Capability::SecurityManage) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let target = if form.node_id.is_empty() || form.node_id == "local" {
        None
    } else {
        Some(form.node_id.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::BanRemove {
            ip: form.ip.trim().to_string(),
            // Unrestricted: this is the cluster-wide bans page, which is
            // already admin-gated. The per-hosting route passes its selector
            // so the node can refuse a ban that is not that site's.
            sel: None,
        },
    )
    .await?;
    match resp {
        RpcResponse::BanRemove => {
            Ok(Redirect::to("/protection?flash=ban+lifted#bans").into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/protection?flash_error={}#bans",
            url::form_urlencoded::byte_serialize(e.to_string().as_bytes()).collect::<String>()
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
