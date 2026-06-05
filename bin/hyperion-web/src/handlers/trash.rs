//! /trash — cluster-wide list of soft-deleted (trashed) hostings.
//!
//! When `cluster.trash_enabled = true` in agent.toml, deleting a
//! hosting moves it here instead of nuking files / DB / OS user.
//! Operators can Restore (un-trash → Active again) or "Delete
//! permanently" (skip the retention window and run the hard-delete
//! pipeline immediately). The scheduler purges entries past
//! `trash_retention_days` automatically.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::TrashEntry;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "trash.html")]
struct TrashTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    entries: Vec<TrashEntry>,
    trash_enabled: bool,
    retention_days: i64,
    csrf_token: String,
    error: Option<String>,
    flash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TrashQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn get_trash(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<TrashQuery>,
) -> Result<Response, AppError> {
    // Cluster admin chrome — viewers + customers can't see the
    // /trash overview. Operator role can (they're the ones who
    // probably hit Delete by mistake and want to restore).
    if ctx.is_read_only() {
        return Ok(Redirect::to("/").into_response());
    }

    let cluster_cfg = crate::handlers::hostings::fetch_cluster_config(&state).await;
    let mut entries: Vec<TrashEntry> = Vec::new();

    // Master local.
    if let Ok(RpcResponse::TrashList(rows)) =
        crate::dispatcher::dispatch_to_node(&state, None, Request::TrashList).await
    {
        let mut rows = rows;
        for r in &mut rows {
            if r.node_id.is_empty() {
                r.node_id = crate::dispatcher::LOCAL_NODE_SENTINEL.to_string();
            }
        }
        entries.extend(rows);
    }

    // Enrolled workers.
    let workers = crate::handlers::hostings::fetch_remote_nodes(&state)
        .await
        .unwrap_or_default();
    for n in workers {
        if let Ok(RpcResponse::TrashList(rows)) = crate::dispatcher::dispatch_to_node(
            &state,
            Some(&n.node_id),
            Request::TrashList,
        )
        .await
        {
            let mut rows = rows;
            for r in &mut rows {
                r.node_id = n.node_id.clone();
            }
            entries.extend(rows);
        }
    }

    // Soonest-purge first so the operator can act on the urgent
    // recovery candidates first.
    entries.sort_by_key(|e| e.purge_at);

    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let tpl = TrashTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "trash",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        entries,
        trash_enabled: cluster_cfg.trash_enabled,
        retention_days: cluster_cfg.trash_retention_days,
        csrf_token,
        error: q.error,
        flash: q.flash,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct TrashActionForm {
    pub selector: String,
    #[serde(default)]
    pub target_node: String,
}

pub async fn post_trash_restore(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<TrashActionForm>,
) -> Result<Response, AppError> {
    if ctx.is_read_only() {
        return Err(AppError::Forbidden);
    }
    let sel = crate::handlers::hostings::parse_selector_public(&form.selector)?;
    let target = if form.target_node.is_empty()
        || form.target_node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(form.target_node.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::TrashRestore(sel),
    )
    .await?;
    match resp {
        RpcResponse::TrashRestore => Ok(Redirect::to(&format!(
            "/trash?flash=Restored+{}",
            urlencode(&form.selector)
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/trash?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_trash_purge(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<TrashActionForm>,
) -> Result<Response, AppError> {
    if ctx.is_read_only() {
        return Err(AppError::Forbidden);
    }
    let sel = crate::handlers::hostings::parse_selector_public(&form.selector)?;
    let target = if form.target_node.is_empty()
        || form.target_node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(form.target_node.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::TrashPurge(sel),
    )
    .await?;
    match resp {
        RpcResponse::TrashPurge => Ok(Redirect::to(&format!(
            "/trash?flash=Permanently+deleted+{}",
            urlencode(&form.selector)
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/trash?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Helper for templates: turn `seconds_remaining` into a friendly
/// "5 days 3 hours" string for the table. 0 → "purging soon".
pub fn fmt_remaining(secs: &i64) -> String {
    let s = *secs;
    if s <= 0 {
        return "purging soon".into();
    }
    let days = s / 86400;
    let hours = (s % 86400) / 3600;
    let mins = (s % 3600) / 60;
    if days >= 1 {
        if hours > 0 {
            format!("{days}d {hours}h")
        } else {
            format!("{days}d")
        }
    } else if hours >= 1 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}
