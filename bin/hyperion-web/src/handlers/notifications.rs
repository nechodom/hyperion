//! Bell-icon notification feed.
//!
//! Three endpoints back the dropdown in base.html:
//!   - GET  /api/notifications/feed?limit=10
//!   - POST /api/notifications/mark-read   { id }
//!   - POST /api/notifications/mark-all-read
//!
//! All three require an authenticated session (any role) and scope
//! every query to the session's user_id. RPC layer enforces the
//! same scoping at the DB level — so a malicious user can't mark
//! someone else's notification read even if they craft the body.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hyperion_rpc::{Request, Response as RpcResponse};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct FeedQuery {
    /// Cap: rpc layer clamps to [1, 100]. Default 10 = dropdown size.
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 {
    10
}

pub async fn get_feed(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<FeedQuery>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsFeed {
            user_id: sess.user_id,
            limit: q.limit,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::NotificationsFeed(feed) => Ok((
            [(
                header::CACHE_CONTROL,
                "no-store, no-cache, must-revalidate",
            )],
            Json(feed),
        )
            .into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Debug, Deserialize)]
pub struct MarkReadBody {
    pub id: i64,
}

pub async fn post_mark_read(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Json(body): Json<MarkReadBody>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsMarkRead {
            user_id: sess.user_id,
            notification_id: body.id,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::NotificationsMarkRead => Ok(StatusCode::NO_CONTENT.into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_mark_all_read(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsMarkAllRead {
            user_id: sess.user_id,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::NotificationsMarkAllRead { marked } => Ok((
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"marked\":{}}}", marked),
        )
            .into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
