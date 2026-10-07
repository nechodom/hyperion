//! `/emails` — global email log.
//!
//! The per-hosting "Emails" tab on hostings_detail filters to
//! `email_log.hosting_id = <that_id>`. Test emails + cluster-wide
//! notifications (billing summaries, master alerts) have
//! `hosting_id = NULL` — they're invisible there by design. This
//! page is the operator's view of EVERYTHING, merged from every node.
//!
//! Layout follows /jobs: a verdict line ("did anything fail lately?"),
//! search + type select + state segments, then the mail bucketed by day.
//! Each row folds open to the full preview, the relay's reply and the
//! error, so a long SMTP error never stretches the list.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::EmailLogEntry;
use serde::Deserialize;
use std::collections::HashMap;

/// How many rows each node is asked for. The agent clamps to 500; asking for
/// the most it will give means the type list, counts and search all cover a
/// few weeks rather than a few days.
const NODE_WINDOW: i64 = 500;
/// How many rows the page renders at most, after filtering.
const LIST_SHOWN: usize = 300;

#[derive(Template)]
#[template(path = "emails.html")]
struct EmailsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    /// Filtered rows, bucketed by local calendar day, newest first.
    days: Vec<DayGroup>,
    /// "Is mail getting out?" — computed over the whole window, not the
    /// filtered view, so narrowing the list never hides a failure.
    verdict: String,
    verdict_tone: &'static str,
    /// Per-state counts for the segments (after site + type + search).
    counts: StateCounts,
    /// `(kind, label)` for every kind present in the window.
    kinds: Vec<(String, String)>,
    kind_filter: String,
    state_filter: String,
    q: String,
    /// Raw `hosting` param (an id) and the domain it resolved to, for the
    /// "Site: example.cz ×" chip. The id is kept so the per-site links from
    /// the hosting page keep working after a rename.
    hosting_filter: String,
    hosting_label: String,
    seg_hrefs: SegHrefs,
    /// Href that drops the site filter but keeps the rest.
    clear_site_href: String,
    /// More matching mail exists than is shown, or a node's window filled.
    truncated: bool,
    /// Nothing in the window at all (as opposed to nothing matching).
    window_empty: bool,
    /// Set when the master's own email_log_list RPC errored — most likely
    /// the `email_log` table doesn't exist because migration 017 hasn't been
    /// applied (update.sh ran without restarting hyperion-agent).
    rpc_error: Option<String>,
    /// Set when a node's response failed authentication and its log
    /// entries were therefore discarded — the list below is INCOMPLETE.
    node_auth_warning: Option<String>,
}

/// One email as the list renders it — everything pre-formatted.
pub struct MailRow {
    pub ok: bool,
    pub subject: String,
    pub kind_label: String,
    pub to_address: String,
    pub hosting_id: Option<String>,
    /// Domain when the hosting still exists; a short id otherwise.
    pub site_label: Option<String>,
    /// False when the hosting is gone — no link to a 404.
    pub site_exists: bool,
    pub node: Option<String>,
    /// First line of the error, trimmed for the scan line.
    pub error_line: String,
    pub error_full: String,
    pub preview: String,
    /// "250" for the scan line; the full reply sits in the fold.
    pub reply_code: String,
    pub reply_full: String,
    pub sent_ago: String,
    pub sent_abs: String,
}

pub struct DayGroup {
    pub label: String,
    pub rows: Vec<MailRow>,
}

#[derive(Default)]
pub struct StateCounts {
    pub all: usize,
    pub ok: usize,
    pub failed: usize,
}

pub struct SegHrefs {
    pub all: String,
    pub ok: String,
    pub failed: String,
}

#[derive(Deserialize, Default)]
pub struct EmailsQuery {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub hosting: String,
    #[serde(default)]
    pub q: String,
}

/// What the operator calls an email kind. The stored kind is a short
/// identifier and used to be shown raw (`care_report`).
pub fn kind_label(kind: &str) -> String {
    match kind {
        "test" => "Test email",
        "monitor" => "Uptime alert",
        "quota" => "Disk quota",
        "billing" => "Billing",
        "care_report" => "Care report",
        "expiry" => "Expiry warning",
        "alert" => "Alert",
        "backup" => "Backup",
        "cert" => "Certificate",
        "other" => "Other",
        other => return crate::handlers::stats::fmt_action_label(other),
    }
    .to_string()
}

/// The relay's reply, split into the 3-digit code for the scan line and the
/// whole reply for the fold.
///
/// Rows written before the adapter stored a readable line hold lettre's
/// `Debug` form — `Code { severity: PositiveCompletion, category: MailSystem,
/// detail: Zero }` — which is decoded back to "250" here.
pub fn smtp_reply(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if raw.starts_with("Code {") {
        let digit = |names: &[(&str, char)]| {
            names
                .iter()
                .find(|(n, _)| raw.contains(&format!(": {n}")))
                .map(|(_, d)| *d)
        };
        let severity = digit(&[
            ("PositiveCompletion", '2'),
            ("PositiveIntermediate", '3'),
            ("TransientNegativeCompletion", '4'),
            ("PermanentNegativeCompletion", '5'),
        ]);
        let category = digit(&[
            ("Syntax", '0'),
            ("Information", '1'),
            ("Connections", '2'),
            ("Unspecified3", '3'),
            ("Unspecified4", '4'),
            ("MailSystem", '5'),
        ]);
        let detail = digit(&[
            ("Zero", '0'),
            ("One", '1'),
            ("Two", '2'),
            ("Three", '3'),
            ("Four", '4'),
            ("Five", '5'),
            ("Six", '6'),
            ("Seven", '7'),
            ("Eight", '8'),
            ("Nine", '9'),
        ]);
        return match (severity, category, detail) {
            (Some(s), Some(c), Some(d)) => {
                let code = format!("{s}{c}{d}");
                (code.clone(), code)
            }
            _ => (String::new(), raw.to_string()),
        };
    }
    let code = raw
        .split_whitespace()
        .next()
        .filter(|w| w.len() == 3 && w.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or_default()
        .to_string();
    (code, raw.to_string())
}

fn first_line(s: &str, max: usize) -> String {
    let line = s
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default();
    if line.chars().count() > max {
        format!("{}…", line.chars().take(max).collect::<String>())
    } else {
        line.to_string()
    }
}

pub(crate) fn fmt_local(ts: i64, fmt: &str) -> String {
    use chrono::{Local, TimeZone};
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.format(fmt).to_string())
        .unwrap_or_default()
}

/// "Today" / "Yesterday" / "Mon 5 Oct 2026", in the panel host's local time.
pub(crate) fn day_label(ts: i64, now: i64) -> String {
    use chrono::{Local, TimeZone};
    let day = |t: i64| Local.timestamp_opt(t, 0).single().map(|d| d.date_naive());
    match (day(ts), day(now)) {
        (Some(d), Some(today)) if d == today => "Today".into(),
        (Some(d), Some(today)) if today.pred_opt() == Some(d) => "Yesterday".into(),
        _ => fmt_local(ts, "%a %-d %b %Y"),
    }
}

fn short_id(id: &str) -> String {
    format!("{}…", id.chars().take(8).collect::<String>())
}

fn mail_row(e: EmailLogEntry, domains: &HashMap<String, String>) -> MailRow {
    let (reply_code, reply_full) = e.smtp_code.as_deref().map(smtp_reply).unwrap_or_default();
    let error_full = e.error.clone().unwrap_or_default();
    let (site_label, site_exists) = match e.hosting_id.as_deref() {
        Some(id) => match domains.get(id) {
            Some(d) => (Some(d.clone()), true),
            None => (Some(short_id(id)), false),
        },
        None => (None, false),
    };
    MailRow {
        ok: e.state == "ok",
        kind_label: kind_label(&e.kind),
        error_line: first_line(&error_full, 160),
        error_full,
        preview: e.body_preview.trim().to_string(),
        reply_code,
        reply_full,
        sent_ago: crate::handlers::stats::fmt_ago(&e.sent_at),
        sent_abs: fmt_local(e.sent_at, "%Y-%m-%d %H:%M:%S"),
        subject: if e.subject.trim().is_empty() {
            "(no subject)".into()
        } else {
            e.subject
        },
        to_address: e.to_address,
        hosting_id: e.hosting_id,
        site_label,
        site_exists,
        node: e.node,
    }
}

/// Headline for the page. A failure in the last day outranks everything —
/// it is the one thing on this page that may need the operator.
fn verdict(rows: &[EmailLogEntry], now: i64) -> (String, &'static str) {
    let day: Vec<&EmailLogEntry> = rows.iter().filter(|e| now - e.sent_at < 86_400).collect();
    let failed = day.iter().filter(|e| e.state != "ok").count();
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    if failed > 0 {
        // Newest first, so this is the latest failure — the one most likely
        // to describe the relay as it is right now.
        let latest = day
            .iter()
            .find(|e| e.state != "ok")
            .and_then(|e| e.error.as_deref())
            .map(|e| first_line(e, 120))
            .unwrap_or_default();
        let mut s = format!(
            "{} out of {} in the last 24 hours",
            plural(failed, "email failed", "emails failed"),
            day.len()
        );
        if !latest.is_empty() {
            s.push_str(&format!(" — latest: {latest}"));
        }
        (s, "err")
    } else if !day.is_empty() {
        (
            format!(
                "{} in the last 24 hours, none failed",
                plural(day.len(), "email sent", "emails sent")
            ),
            "ok",
        )
    } else if let Some(last) = rows.first() {
        (
            format!(
                "Nothing sent in the last 24 hours · last email {}",
                crate::handlers::stats::fmt_ago(&last.sent_at)
            ),
            "muted",
        )
    } else {
        ("No email sent yet".into(), "muted")
    }
}

fn emails_href(state: &str, kind: &str, q: &str, hosting: &str) -> String {
    let mut parts = Vec::new();
    for (k, v) in [
        ("hosting", hosting),
        ("state", state),
        ("kind", kind),
        ("q", q),
    ] {
        if !v.is_empty() {
            parts.push(format!("{k}={}", urlencode(v)));
        }
    }
    if parts.is_empty() {
        "/emails".into()
    } else {
        format!("/emails?{}", parts.join("&"))
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b' ' => "+".to_string(),
            b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b if b.is_ascii_alphanumeric() => (b as char).to_string(),
            b => format!("%{:02X}", b),
        })
        .collect()
}

fn matches_q(e: &EmailLogEntry, q: &str, domains: &HashMap<String, String>) -> bool {
    let has = |s: &str| s.to_lowercase().contains(q);
    has(&e.to_address)
        || has(&e.subject)
        || has(&e.kind)
        || has(&kind_label(&e.kind))
        || e.error.as_deref().is_some_and(has)
        // The relay's reply carries the queue id — what you have in hand
        // when chasing one message through the relay's own log.
        || e.smtp_code.as_deref().is_some_and(has)
        || e.node.as_deref().is_some_and(has)
        || e.hosting_id.as_deref().is_some_and(|id| {
            has(id) || domains.get(id).is_some_and(|d| has(d))
        })
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
    if !ctx.can(Capability::EmailLogView) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let hosting_filter = q.hosting.trim().to_string();
    let kind_filter = q.kind.trim().to_string();
    let state_filter = match q.state.trim() {
        s @ ("ok" | "failed") => s.to_string(),
        _ => String::new(),
    };
    let search = q.q.trim().to_string();
    let needle = search.to_lowercase();

    // Cluster-wide fan-in: outbound mail is logged on the node that SENT
    // it, so a worker's sites' mail is invisible from the master-local log.
    // The hosting listing (for domains) runs alongside — it is its own
    // fan-out, and waiting for one before starting the other doubles the
    // page's latency for nothing.
    let req = Request::EmailLogList {
        hosting_id: (!hosting_filter.is_empty()).then(|| hosting_filter.clone()),
        limit: NODE_WINDOW,
    };
    let ((mut window, rpc_error, node_auth_warning, window_full), hostings) = tokio::join!(
        fetch_all(&state, req),
        crate::handlers::hostings::list_hostings(&state),
    );
    let domains: HashMap<String, String> = hostings
        .unwrap_or_default()
        .into_iter()
        .map(|h| (h.id.as_str().to_string(), h.domain))
        .collect();
    window.sort_by(|a, b| b.sent_at.cmp(&a.sent_at));
    let now = hyperion_types::now_secs();
    let (verdict, verdict_tone) = verdict(&window, now);

    let mut kinds: Vec<(String, String)> = Vec::new();
    for e in &window {
        if !kinds.iter().any(|(k, _)| k == &e.kind) {
            kinds.push((e.kind.clone(), kind_label(&e.kind)));
        }
    }
    kinds.sort_by(|a, b| a.1.cmp(&b.1));

    // Type + search narrow the set; the segments count within it; the state
    // segment then picks. Filtering happens over the FULL merged window
    // before the cap — capping first would drop matching worker rows that
    // fall outside the global most-recent slice.
    let narrowed: Vec<EmailLogEntry> = window
        .iter()
        .filter(|e| kind_filter.is_empty() || e.kind == kind_filter)
        .filter(|e| needle.is_empty() || matches_q(e, &needle, &domains))
        .cloned()
        .collect();
    let counts = StateCounts {
        all: narrowed.len(),
        ok: narrowed.iter().filter(|e| e.state == "ok").count(),
        failed: narrowed.iter().filter(|e| e.state != "ok").count(),
    };
    let mut shown: Vec<EmailLogEntry> = narrowed
        .into_iter()
        .filter(|e| match state_filter.as_str() {
            "ok" => e.state == "ok",
            "failed" => e.state != "ok",
            _ => true,
        })
        .collect();
    let truncated = window_full || shown.len() > LIST_SHOWN;
    shown.truncate(LIST_SHOWN);

    let mut days: Vec<DayGroup> = Vec::new();
    for e in shown {
        let label = day_label(e.sent_at, now);
        let row = mail_row(e, &domains);
        match days.last_mut() {
            Some(d) if d.label == label => d.rows.push(row),
            _ => days.push(DayGroup {
                label,
                rows: vec![row],
            }),
        }
    }

    let hosting_label = if hosting_filter.is_empty() {
        String::new()
    } else {
        domains
            .get(&hosting_filter)
            .cloned()
            .unwrap_or_else(|| short_id(&hosting_filter))
    };
    let seg_hrefs = SegHrefs {
        all: emails_href("", &kind_filter, &search, &hosting_filter),
        ok: emails_href("ok", &kind_filter, &search, &hosting_filter),
        failed: emails_href("failed", &kind_filter, &search, &hosting_filter),
    };
    let tpl = EmailsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "emails",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        window_empty: window.is_empty(),
        days,
        verdict,
        verdict_tone,
        counts,
        kinds,
        clear_site_href: emails_href(&state_filter, &kind_filter, &search, ""),
        kind_filter,
        state_filter,
        q: search,
        hosting_filter,
        hosting_label,
        seg_hrefs,
        truncated,
        rpc_error,
        node_auth_warning,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Master + every worker, each entry tagged with the node it came from.
/// Returns (entries, master's error, node-auth banner, any node's window
/// filled — i.e. older mail exists that isn't in the merged set).
async fn fetch_all(
    state: &SharedState,
    req: Request,
) -> (Vec<EmailLogEntry>, Option<String>, Option<String>, bool) {
    let (mut all, rpc_error): (Vec<EmailLogEntry>, Option<String>) =
        match hyperion_rpc_client::call(&state.agent_socket, req.clone()).await {
            Ok(RpcResponse::EmailLogList(r)) => (r, None),
            Ok(RpcResponse::Error(e)) => (vec![], Some(e.to_string())),
            Ok(_) => (vec![], Some("unexpected agent response".into())),
            Err(e) => (vec![], Some(format!("rpc: {e}"))),
        };
    let mut window_full = all.len() as i64 >= NODE_WINDOW;
    for e in &mut all {
        e.node = Some("master".to_string());
    }
    let workers = crate::handlers::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default();
    let (answered, failed) = crate::dispatcher::fan_out_reporting(state, workers, req).await;
    let node_auth_warning = super::node_auth_warning(&failed);
    for (n, resp) in answered {
        if let RpcResponse::EmailLogList(mut remote) = resp {
            window_full |= remote.len() as i64 >= NODE_WINDOW;
            let label = if n.label.is_empty() {
                n.node_id.clone()
            } else {
                n.label.clone()
            };
            for e in &mut remote {
                e.node = Some(label.clone());
            }
            all.extend(remote);
        }
    }
    (all, rpc_error, node_auth_warning, window_full)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(state: &str, sent_at: i64, error: Option<&str>) -> EmailLogEntry {
        EmailLogEntry {
            id: 1,
            hosting_id: None,
            to_address: "ops@example.cz".into(),
            subject: "s".into(),
            body_preview: String::new(),
            kind: "monitor".into(),
            state: state.into(),
            error: error.map(str::to_string),
            smtp_code: None,
            sent_at,
            node: None,
        }
    }

    #[test]
    fn legacy_debug_code_decodes_to_digits() {
        let (code, full) =
            smtp_reply("Code { severity: PositiveCompletion, category: MailSystem, detail: Zero }");
        assert_eq!(code, "250");
        assert_eq!(full, "250");
        let (code, _) = smtp_reply(
            "Code { severity: PermanentNegativeCompletion, category: MailSystem, detail: Four }",
        );
        assert_eq!(code, "554");
    }

    #[test]
    fn readable_reply_keeps_queue_id() {
        let (code, full) = smtp_reply("250 2.0.0 Ok: queued as 4ZQ1x");
        assert_eq!(code, "250");
        assert_eq!(full, "250 2.0.0 Ok: queued as 4ZQ1x");
        let (code, full) = smtp_reply("weird");
        assert_eq!(code, "");
        assert_eq!(full, "weird");
    }

    #[test]
    fn verdict_names_the_latest_failure() {
        let now = 1_000_000;
        let rows = vec![
            entry(
                "failed",
                now - 60,
                Some("smtp send: connection refused\nmore"),
            ),
            entry("ok", now - 120, None),
            entry("failed", now - 200, Some("older error")),
        ];
        let (s, tone) = verdict(&rows, now);
        assert_eq!(tone, "err");
        assert_eq!(
            s,
            "2 emails failed out of 3 in the last 24 hours — latest: smtp send: connection refused"
        );
    }

    #[test]
    fn verdict_ignores_failures_older_than_a_day() {
        let now = 1_000_000;
        let rows = vec![
            entry("ok", now - 60, None),
            entry("failed", now - 2 * 86_400, Some("old")),
        ];
        assert_eq!(
            verdict(&rows, now),
            (
                "1 email sent in the last 24 hours, none failed".into(),
                "ok"
            )
        );
        assert_eq!(verdict(&[], now), ("No email sent yet".into(), "muted"));
    }

    #[test]
    fn href_keeps_filters_and_encodes_search() {
        assert_eq!(emails_href("", "", "", ""), "/emails");
        assert_eq!(
            emails_href("failed", "care_report", "a b&c", "h1"),
            "/emails?hosting=h1&state=failed&kind=care_report&q=a+b%26c"
        );
    }

    #[test]
    fn unknown_kind_still_gets_a_label() {
        assert_eq!(kind_label("care_report"), "Care report");
        assert!(!kind_label("some_new_kind").is_empty());
    }
}
