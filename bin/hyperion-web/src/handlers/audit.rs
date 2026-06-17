use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::AuditEntryWire;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    rows: Vec<AuditEntryWire>,
    /// Total audit entries returned by the agent (before our in-memory filter)
    total_count: usize,
    /// Count after filters apply
    filtered_count: usize,
    limit: i64,
    q: String,
    action_filter: String,
    result_filter: String,
    since_filter: String,
    /// Distinct `action` values seen in the data so the filter is a
    /// pick-list instead of "guess the action name". Sorted
    /// alphabetically. The bool flag is precomputed `is_selected` so
    /// the template doesn't need string equality (askama would need
    /// deref syntax we'd rather not push into templates).
    known_actions: Vec<(String, bool)>,
    /// Session-wide CSRF token for the inline "Verify chain"
    /// HTMX-driven button. Wildcard scope so a single token
    /// covers all state-changing actions on this page (today
    /// just one, but the verify card can grow more buttons
    /// without re-plumbing).
    csrf_token: String,
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
    /// One of: "" (all time), "1h", "24h", "7d", "30d".
    /// Anything else is silently ignored (treated as all).
    #[serde(default)]
    since: String,
}

fn default_limit() -> i64 {
    200
}

/// Translate a coarse time-range chip into a Unix-seconds cutoff
/// (entries with `ts >= cutoff` pass the filter). `None` = no filter.
fn since_cutoff(now: i64, label: &str) -> Option<i64> {
    let secs: i64 = match label {
        "1h" => 3600,
        "24h" => 86_400,
        "7d" => 604_800,
        "30d" => 2_592_000,
        _ => return None,
    };
    // Clamp to 0 — i64 doesn't saturate at zero, and a negative
    // cutoff would still pass all timestamps but obscures the intent.
    Some((now - secs).max(0))
}

pub async fn get_audit(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<AuditQuery>,
) -> Result<Response, AppError> {
    // The audit log contains every state-changing operation across
    // every hosting + user + cluster-wide event. Subjects + JSON
    // payloads leak cross-tenant operational data — viewer with
    // access to one site can read everything else.
    if !ctx.is_admin_or_higher() {
        return Ok(
            axum::response::Redirect::to("/?flash_error=admin+role+required").into_response(),
        );
    }
    let limit = q.limit.clamp(1, 1000);
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::AuditList { limit }).await?;
    let all = match resp {
        RpcResponse::AuditList(v) => v,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let total_count = all.len();

    let needle = q.q.trim().to_lowercase();
    let action_filter = q.action.trim().to_string(); // case-preserving for exact match

    // Distinct action set — derived from the data itself so the filter
    // dropdown only shows things the operator could actually find.
    // Each entry carries a precomputed `is_selected` flag for the
    // template.
    let known_actions: Vec<(String, bool)> = all
        .iter()
        .map(|r| r.action.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|a| {
            let selected = a == action_filter;
            (a, selected)
        })
        .collect();
    let result_filter = q.result.trim().to_lowercase();
    let since_label = q.since.trim().to_string();
    let cutoff = since_cutoff(hyperion_types::now_secs(), &since_label);

    let rows: Vec<AuditEntryWire> = all
        .into_iter()
        .filter(|r| match cutoff {
            Some(c) => r.ts >= c,
            None => true,
        })
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
        // Action filter — exact match when the user picked from the
        // dropdown, fallback to "contains" so manual typing still works.
        .filter(|r| {
            action_filter.is_empty()
                || r.action == action_filter
                || r.action
                    .to_lowercase()
                    .contains(&action_filter.to_lowercase())
        })
        .filter(|r| result_filter.is_empty() || r.result.to_lowercase() == result_filter)
        .collect();
    let filtered_count = rows.len();
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let tpl = AuditTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "audit",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows,
        total_count,
        filtered_count,
        limit,
        q: q.q,
        action_filter,
        result_filter,
        since_filter: since_label,
        known_actions,
        csrf_token,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// HTMX-target endpoint behind the "Verify chain" button on the
/// audit page. Walks the entire log, returns an HTML pill that
/// drops into a sibling target div. Read-only — admin-only at
/// the role level, but causes no side effects so we don't gate
/// it behind CSRF either.
pub async fn post_verify_chain(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            Html("<div class=\"pill err\">admin role required</div>".to_string()).into_response(),
        );
    }
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::AuditVerifyChain).await?;
    let html = match resp {
        RpcResponse::AuditVerifyChain {
            ok: true,
            rows_checked,
            ..
        } => format!(
            "<div class=\"pill ok\">✓ Chain verified · {rows_checked} row{}</div>",
            if rows_checked == 1 { "" } else { "s" }
        ),
        RpcResponse::AuditVerifyChain {
            ok: false,
            rows_checked,
            message,
        } => format!(
            "<div class=\"pill err\" title=\"{}\">✗ Chain BROKEN at row · {rows_checked} row{} checked</div>",
            askama_escape::escape(&message, askama_escape::Html),
            if rows_checked == 1 { "" } else { "s" }
        ),
        RpcResponse::Error(e) => format!(
            "<div class=\"pill err\">verify failed: {}</div>",
            askama_escape::escape(&e.to_string(), askama_escape::Html)
        ),
        _ => "<div class=\"pill err\">unexpected response</div>".into(),
    };
    Ok(Html(html).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_cutoff_recognises_only_known_labels() {
        // Pick `now` large enough that 30d back stays positive so we
        // separately test the saturation case below.
        let now = 10_000_000;
        assert_eq!(since_cutoff(now, "1h"), Some(9_996_400));
        assert_eq!(since_cutoff(now, "24h"), Some(9_913_600));
        assert_eq!(since_cutoff(now, "7d"), Some(9_395_200));
        assert_eq!(since_cutoff(now, "30d"), Some(10_000_000 - 2_592_000));
        assert_eq!(since_cutoff(now, ""), None);
        assert_eq!(since_cutoff(now, "bogus"), None);
        assert_eq!(since_cutoff(now, "1H"), None, "label is case-sensitive");
    }

    /// saturating_sub guards against tiny `now` values (e.g. on a
    /// freshly-booted system where the clock is unset). We must not
    /// produce a negative timestamp.
    #[test]
    fn since_cutoff_saturates_on_tiny_now() {
        assert_eq!(since_cutoff(10, "30d"), Some(0));
    }
}
