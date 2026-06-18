//! `/emails` — global email log.
//!
//! The per-hosting "Emails" tab on hostings_detail filters to
//! `email_log.hosting_id = <that_id>`. Test emails + cluster-wide
//! notifications (billing summaries, master alerts) have
//! `hosting_id = NULL` — they're invisible there by design. This
//! page is the operator's view of EVERYTHING: pass-through filter
//! params for kind/state/hosting.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::EmailLogEntry;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "emails.html")]
struct EmailsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    rows: Vec<EmailLogEntry>,
    /// Applied filter values for sticky form rendering.
    filter_kind: String,
    filter_state: String,
    filter_hosting: String,
    /// Counters across the unfiltered current view.
    total: usize,
    ok_count: usize,
    failed_count: usize,
    /// Set when the agent's email_log_list RPC errored — most
    /// likely the `email_log` table doesn't exist on disk because
    /// migration 017 hasn't been applied yet (operator pulled new
    /// code but didn't restart hyperion-agent). Template renders a
    /// red banner with the fix command.
    rpc_error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct EmailsQuery {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub hosting: String,
}

pub async fn get_emails(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<EmailsQuery>,
) -> Result<Response, AppError> {
    // Subjects + recipients + SMTP error messages leak operational
    // info across the whole cluster. A viewer with per-hosting
    // access to ONE site shouldn't see notifications for every
    // other site. The per-hosting Emails tab is correctly scoped.
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let hosting_id: Option<String> = if q.hosting.trim().is_empty() {
        None
    } else {
        Some(q.hosting.trim().to_string())
    };
    // Fetch a generous page — 200 covers a few days of activity on a
    // busy node without paginating yet. Distinguish "no rows" from
    // "agent errored" so the template can surface the right hint.
    //
    // Cluster-wide fan-in: outbound mail from sites is logged on the node
    // that SENT it, so a worker's sites' mail is invisible from the
    // master-local log. Fetch master + every worker (best-effort), tag
    // each entry with its node, merge + sort by sent_at desc, cap at 200.
    let req = Request::EmailLogList {
        hosting_id,
        limit: 200,
    };
    let (mut raw, rpc_error): (Vec<EmailLogEntry>, Option<String>) =
        match hyperion_rpc_client::call(&state.agent_socket, req.clone()).await {
            Ok(RpcResponse::EmailLogList(r)) => (r, None),
            Ok(RpcResponse::Error(e)) => (vec![], Some(e.to_string())),
            Ok(_) => (vec![], Some("unexpected agent response".into())),
            Err(e) => (vec![], Some(format!("rpc: {e}"))),
        };
    for e in &mut raw {
        e.node = Some("master".to_string());
    }
    let workers = crate::handlers::hostings::fetch_remote_nodes(&state)
        .await
        .unwrap_or_default();
    for (n, resp) in crate::dispatcher::fan_out(&state, workers, req).await {
        if let RpcResponse::EmailLogList(mut remote) = resp {
            let label = if n.label.is_empty() {
                n.node_id.clone()
            } else {
                n.label.clone()
            };
            for e in &mut remote {
                e.node = Some(label.clone());
            }
            raw.extend(remote);
        }
    }
    raw.sort_by(|a, b| b.sent_at.cmp(&a.sent_at));
    raw.truncate(200);
    // Apply UI-only kind/state filters in memory — the agent doesn't
    // need a new RPC variant for this. Cheap at 200 rows.
    let rows: Vec<EmailLogEntry> = raw
        .into_iter()
        .filter(|r| q.kind.is_empty() || r.kind == q.kind)
        .filter(|r| q.state.is_empty() || r.state == q.state)
        .collect();
    let total = rows.len();
    let ok_count = rows.iter().filter(|r| r.state == "ok").count();
    let failed_count = rows.iter().filter(|r| r.state == "failed").count();
    let tpl = EmailsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "emails",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows,
        filter_kind: q.kind,
        filter_state: q.state,
        filter_hosting: q.hosting,
        total,
        ok_count,
        failed_count,
        rpc_error,
    };
    Ok(Html(tpl.render()?).into_response())
}
