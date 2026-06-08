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
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use hyperion_rpc::{Request, Response as RpcResponse};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "notifications.html")]
struct NotificationsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    items: Vec<hyperion_types::NotificationView>,
    kind_filter: String,
    /// Sorted distinct kinds for the filter dropdown.
    known_kinds: Vec<(String, bool)>,
    csrf_token: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct ArchiveQuery {
    #[serde(default)]
    pub kind: String,
}

/// GET /notifications — full archive view (bell dropdown only
/// shows the last 10). Filter by kind, mark-all-read inline,
/// jump-to-source links from each row.
pub async fn get_archive(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<ArchiveQuery>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsFeed {
            user_id: sess.user_id,
            // Bell shows 10; archive shows up to 500 — practical
            // ceiling for skimming + the RPC layer clamps higher.
            limit: 500,
        },
    )
    .await
    .map_err(AppError::from)?;
    let feed = match resp {
        RpcResponse::NotificationsFeed(f) => f,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let kind_filter = q.kind.trim().to_string();
    let mut kinds_set: std::collections::BTreeSet<String> =
        feed.items.iter().map(|i| i.kind.clone()).collect();
    // Always include the current filter even if no rows match (so the
    // dropdown shows it as the active selection).
    if !kind_filter.is_empty() {
        kinds_set.insert(kind_filter.clone());
    }
    let known_kinds: Vec<(String, bool)> = kinds_set
        .into_iter()
        .map(|k| {
            let selected = k == kind_filter;
            (k, selected)
        })
        .collect();
    let items: Vec<hyperion_types::NotificationView> = feed
        .items
        .into_iter()
        .filter(|i| kind_filter.is_empty() || i.kind == kind_filter)
        .collect();
    let tpl = NotificationsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "notifications",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        items,
        kind_filter,
        known_kinds,
        csrf_token: super::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

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
