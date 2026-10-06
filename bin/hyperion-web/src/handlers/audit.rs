//! `/audit` — the cluster-wide audit log.
//!
//! Every node keeps its own hash-chained `audit_log`. The page asks each one
//! for a filtered page (`AuditSearch`, the filters run in the node's SQL over
//! the whole table) and merges the answers newest first. A node too old to
//! know `AuditSearch` is asked for its newest entries instead and filtered
//! here; the page says so, because for that node a search only reaches that
//! window.

use crate::auth::AuthCtx;
use crate::dispatcher::DispatchError;
use crate::error::AppError;
use crate::handlers::jobs::{day_label, fmt_local, looks_like_hosting_id, urlencode};
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::{AuditActionCount, AuditEntryWire, AuditSearchFilter};
use hyperion_state::capabilities::Capability;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Rows per page on screen.
const PAGE_LIMIT: usize = 100;
/// Rows per node per round while exporting.
const EXPORT_PAGE: usize = 1000;
/// Export ceiling — beyond this the operator should narrow the filter.
const EXPORT_MAX_ROWS: usize = 50_000;
/// What an older node (no `AuditSearch`) is asked for instead.
const FALLBACK_WINDOW: i64 = 1000;

/// For the template's older-node note.
pub fn fallback_window() -> i64 {
    FALLBACK_WINDOW
}

// ── Categories ──────────────────────────────────────────────────────────
//
// Matched on the first dotted segment, so `web.` never swallows
// `web_session.`. Anything not listed is "System" — new action kinds land
// there rather than nowhere.

const SITES: &[&str] = &[
    "hosting.",
    "wp.",
    "wordpress.",
    "wp_asset.",
    "database.",
    "db.",
    "ftp.",
    "backup.",
    "quota.",
    "php.",
    "package.",
    "profile.",
];
const ACCESS: &[&str] = &["web.", "web_session.", "api_key."];
const CERTS: &[&str] = &["cert."];

/// `(key, label)` for every segment, in display order.
const SEGMENTS: &[(&str, &str)] = &[
    ("", "All"),
    ("sites", "Sites"),
    ("access", "Sign-ins & users"),
    ("certs", "Certificates"),
    ("system", "System"),
    ("failed", "Failed"),
];

fn category_of(action: &str) -> &'static str {
    let starts = |set: &[&str]| set.iter().any(|p| action.starts_with(p));
    if starts(SITES) {
        "sites"
    } else if starts(ACCESS) {
        "access"
    } else if starts(CERTS) {
        "certs"
    } else {
        "system"
    }
}

/// Unknown keys fall back to "" (everything) rather than an empty page.
fn normalize_cat(cat: &str) -> &'static str {
    SEGMENTS
        .iter()
        .map(|(k, _)| *k)
        .find(|k| *k == cat)
        .unwrap_or("")
}

/// Time-window choices: `(key, label, seconds)`.
const WINDOWS: &[(&str, &str, i64)] = &[
    ("1h", "Last hour", 3600),
    ("24h", "Last 24 hours", 86_400),
    ("7d", "Last 7 days", 604_800),
    ("30d", "Last 30 days", 2_592_000),
];

/// Translate a time-window key into a Unix-seconds cutoff (entries with
/// `ts >= cutoff` pass). `None` = no window.
fn since_cutoff(now: i64, label: &str) -> Option<i64> {
    let secs = WINDOWS.iter().find(|(k, _, _)| *k == label)?.2;
    // Clamp to 0 — a negative cutoff would still pass everything but
    // obscures the intent.
    Some((now - secs).max(0))
}

// ── Query + filter ──────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    cat: String,
    /// Pre-rework links (`?result=failed`) still land on the Failed segment.
    #[serde(default)]
    result: String,
    /// "" (all time), "1h", "24h", "7d", "30d"; anything else = all time.
    #[serde(default)]
    since: String,
    /// Paging cursor: show entries strictly older than this Unix time.
    #[serde(default)]
    before: Option<i64>,
    /// `csv` = download every matching entry instead of the page.
    #[serde(default)]
    export: String,
}

struct Selection {
    q: String,
    action: String,
    cat: &'static str,
    since: String,
    before: Option<i64>,
}

impl Selection {
    fn from_query(q: &AuditQuery) -> Self {
        let mut cat = normalize_cat(q.cat.trim());
        if cat.is_empty() && q.result.trim().eq_ignore_ascii_case("failed") {
            cat = "failed";
        }
        let since = q.since.trim();
        Selection {
            q: q.q.trim().to_string(),
            action: q.action.trim().to_string(),
            cat,
            since: if WINDOWS.iter().any(|(k, _, _)| *k == since) {
                since.to_string()
            } else {
                String::new()
            },
            before: q.before.filter(|b| *b > 0),
        }
    }

    fn filter(&self, now: i64, limit: usize, q_alt: Vec<String>) -> AuditSearchFilter {
        let (prefixes, not_prefixes, failed_only) = match self.cat {
            "sites" => (strings(SITES), vec![], false),
            "access" => (strings(ACCESS), vec![], false),
            "certs" => (strings(CERTS), vec![], false),
            "system" => (
                vec![],
                SITES
                    .iter()
                    .chain(ACCESS)
                    .chain(CERTS)
                    .map(|s| s.to_string())
                    .collect(),
                false,
            ),
            "failed" => (vec![], vec![], true),
            _ => (vec![], vec![], false),
        };
        AuditSearchFilter {
            q: self.q.clone(),
            q_alt,
            action: self.action.clone(),
            prefixes,
            not_prefixes,
            failed_only,
            since: since_cutoff(now, &self.since),
            before: self.before,
            limit: limit as i64,
        }
    }

    /// `/audit?…` for this selection with one field swapped. `before` is
    /// only kept when asked for: changing any filter starts from the newest.
    fn href(&self, cat: &str, action: &str, before: Option<i64>) -> String {
        let mut parts = Vec::new();
        if !self.q.is_empty() {
            parts.push(format!("q={}", urlencode(&self.q)));
        }
        if !cat.is_empty() {
            parts.push(format!("cat={}", urlencode(cat)));
        }
        if !action.is_empty() {
            parts.push(format!("action={}", urlencode(action)));
        }
        if !self.since.is_empty() {
            parts.push(format!("since={}", urlencode(&self.since)));
        }
        if let Some(b) = before {
            parts.push(format!("before={b}"));
        }
        if parts.is_empty() {
            "/audit".into()
        } else {
            format!("/audit?{}", parts.join("&"))
        }
    }
}

fn strings(set: &[&str]) -> Vec<String> {
    set.iter().map(|s| s.to_string()).collect()
}

/// The SQL filter, replayed in memory for an older node's window. Matches
/// `hyperion_state::audit::search` (ASCII case-insensitive substring).
fn entry_matches(e: &AuditEntryWire, f: &AuditSearchFilter, scope_only: bool) -> bool {
    let q = f.q.trim();
    if !q.is_empty() {
        let needles: Vec<String> = std::iter::once(q)
            .chain(f.q_alt.iter().map(|s| s.trim()).filter(|s| !s.is_empty()))
            .map(str::to_ascii_lowercase)
            .collect();
        let fields = [
            e.action.as_str(),
            e.target.as_deref().unwrap_or(""),
            e.actor_label.as_str(),
            e.payload_json.as_str(),
        ];
        let hit = needles.iter().any(|n| {
            fields
                .iter()
                .any(|s| s.to_ascii_lowercase().contains(n.as_str()))
        });
        if !hit {
            return false;
        }
    }
    if f.since.is_some_and(|s| e.ts < s) {
        return false;
    }
    if scope_only {
        return true;
    }
    if !f.action.is_empty() && e.action != f.action {
        return false;
    }
    if !f.prefixes.is_empty() && !f.prefixes.iter().any(|p| e.action.starts_with(p.as_str())) {
        return false;
    }
    if f.not_prefixes
        .iter()
        .any(|p| e.action.starts_with(p.as_str()))
    {
        return false;
    }
    if f.failed_only && e.result == "ok" {
        return false;
    }
    if f.before.is_some_and(|b| e.ts >= b) {
        return false;
    }
    true
}

// ── Fetch ───────────────────────────────────────────────────────────────

/// One node's answer.
struct NodeBatch {
    label: String,
    rows: Vec<AuditEntryWire>,
    /// The node returned a whole page, so it may hold older matches.
    full: bool,
    actions: Vec<AuditActionCount>,
    total: i64,
}

struct Fetched {
    batches: Vec<NodeBatch>,
    /// Nodes that only answered `AuditList` (older agent).
    partial: Vec<String>,
    /// Nodes that didn't answer at all (other than auth failures, which
    /// `node_auth_warning` reports with its own wording).
    missing: Vec<String>,
    node_auth_warning: Option<String>,
    multi_node: bool,
}

fn node_label(n: &hyperion_types::NodeSummary) -> String {
    if n.label.is_empty() {
        n.node_id.clone()
    } else {
        n.label.clone()
    }
}

fn batch_from_search(label: String, resp: RpcResponse, limit: usize) -> Option<NodeBatch> {
    match resp {
        RpcResponse::AuditSearch {
            rows,
            actions,
            total,
        } => Some(NodeBatch {
            full: rows.len() >= limit,
            label,
            rows,
            actions,
            total,
        }),
        _ => None,
    }
}

/// An older node's newest window, filtered and counted here.
fn batch_from_window(
    label: String,
    window: Vec<AuditEntryWire>,
    f: &AuditSearchFilter,
) -> NodeBatch {
    let total = window.len() as i64;
    let mut counts: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for e in window.iter().filter(|e| entry_matches(e, f, true)) {
        let c = counts.entry(e.action.clone()).or_default();
        c.0 += 1;
        if e.result != "ok" {
            c.1 += 1;
        }
    }
    let mut rows: Vec<AuditEntryWire> = window
        .into_iter()
        .filter(|e| entry_matches(e, f, false))
        .collect();
    rows.sort_by(|a, b| b.ts.cmp(&a.ts).then(b.id.cmp(&a.id)));
    rows.truncate(f.limit.max(1) as usize);
    NodeBatch {
        label,
        rows,
        // The window is all there is to search; nothing older is reachable.
        full: false,
        actions: counts
            .into_iter()
            .map(|(action, (total, failed))| AuditActionCount {
                action,
                total,
                failed,
            })
            .collect(),
        total,
    }
}

async fn fetch(state: &SharedState, f: &AuditSearchFilter) -> Result<Fetched, AppError> {
    let limit = f.limit.max(1) as usize;
    let mut batches = Vec::new();
    let mut partial = Vec::new();
    let mut missing = Vec::new();

    // The master's own log. The local agent can briefly lag the panel
    // during an update, so it gets the same fallback as a worker.
    let local = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AuditSearch { filter: f.clone() },
    )
    .await;
    match local
        .ok()
        .and_then(|r| batch_from_search("master".into(), r, limit))
    {
        Some(b) => batches.push(b),
        None => {
            let resp = hyperion_rpc_client::call(
                &state.agent_socket,
                Request::AuditList {
                    limit: FALLBACK_WINDOW,
                },
            )
            .await?;
            match resp {
                RpcResponse::AuditList(v) => {
                    batches.push(batch_from_window("master".into(), v, f));
                    partial.push("master".into());
                }
                RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
                _ => return Err(AppError::Internal("unexpected response".into())),
            }
        }
    }

    // Workers, best-effort: one slow or offline node never blocks the page.
    let workers = crate::handlers::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default();
    let multi_node = !workers.is_empty();
    let (answered, failed) = crate::dispatcher::fan_out_reporting(
        state,
        workers,
        Request::AuditSearch { filter: f.clone() },
    )
    .await;
    let node_auth_warning = super::node_auth_warning(&failed);
    for (n, resp) in answered {
        let label = node_label(&n);
        match batch_from_search(label.clone(), resp, limit) {
            Some(b) => batches.push(b),
            None => missing.push(label),
        }
    }
    for (n, err) in failed {
        let label = node_label(&n);
        match err {
            // An older agent can't decode `AuditSearch` and answers 400.
            DispatchError::Remote(_) => {
                let retry = crate::dispatcher::dispatch_to_node(
                    state,
                    Some(n.node_id.as_str()),
                    Request::AuditList {
                        limit: FALLBACK_WINDOW,
                    },
                )
                .await;
                match retry {
                    Ok(RpcResponse::AuditList(v)) => {
                        batches.push(batch_from_window(label.clone(), v, f));
                        partial.push(label);
                    }
                    _ => missing.push(label),
                }
            }
            DispatchError::ResponseAuthFailed { .. } => {}
            _ => missing.push(label),
        }
    }
    for b in &mut batches {
        for e in &mut b.rows {
            e.node = Some(b.label.clone());
        }
    }
    Ok(Fetched {
        batches,
        partial,
        missing,
        node_auth_warning,
        multi_node,
    })
}

/// Merge per-node pages into one newest-first page and the cursor for the
/// next one.
///
/// A node that filled its page may hold more rows at or below the oldest
/// timestamp it returned, so only rows strictly newer than the highest such
/// "frontier" are known complete. The page is cut on a timestamp boundary
/// (never splitting one second's rows across pages), so `ts < cursor` on the
/// next request neither skips nor repeats a row.
fn merge_page(batches: &[NodeBatch], limit: usize) -> (Vec<AuditEntryWire>, Option<i64>) {
    let frontier = batches
        .iter()
        .filter(|b| b.full)
        .filter_map(|b| b.rows.iter().map(|e| e.ts).min())
        .max();
    let mut all: Vec<AuditEntryWire> = batches.iter().flat_map(|b| b.rows.clone()).collect();
    all.sort_by(|a, b| {
        b.ts.cmp(&a.ts)
            .then_with(|| a.node.cmp(&b.node))
            .then(b.id.cmp(&a.id))
    });
    let complete: Vec<AuditEntryWire> = all
        .iter()
        .filter(|e| frontier.map_or(true, |f| e.ts > f))
        .cloned()
        .collect();

    if complete.is_empty() {
        // Degenerate: one node returned a full page all inside one second.
        // Show it and move on; the rest of that second is skipped.
        let page: Vec<AuditEntryWire> = all.into_iter().take(limit).collect();
        let next = if frontier.is_some() {
            page.last().map(|e| e.ts)
        } else {
            None
        };
        return (page, next);
    }

    let mut page: Vec<AuditEntryWire> = complete.iter().take(limit).cloned().collect();
    if complete.len() > page.len() {
        let boundary = page.last().map(|e| e.ts);
        if complete.get(page.len()).map(|e| e.ts) == boundary {
            let kept = page.iter().filter(|e| Some(e.ts) != boundary).count();
            if kept > 0 {
                page.truncate(kept);
            } else {
                // A whole page inside one second: take all of that second.
                page = complete
                    .iter()
                    .filter(|e| Some(e.ts) == boundary)
                    .cloned()
                    .collect();
            }
        }
    }
    let more = complete.len() > page.len() || frontier.is_some();
    let next = if more {
        page.last().map(|e| e.ts)
    } else {
        None
    };
    (page, next)
}

// ── Hosting ids ↔ domains ───────────────────────────────────────────────
//
// Many entries name a hosting by its id. Searching a domain (what the
// hosting page's "audit trail" link does) has to find those too, and a row
// reads better with the domain.

/// `(id, domain)` for every hosting the cluster reports. Empty on failure:
/// the page then just searches and shows what was recorded.
async fn hosting_names(state: &SharedState) -> Vec<(String, String)> {
    crate::handlers::hostings::list_hostings(state)
        .await
        .map(|v| {
            v.into_iter()
                .map(|h| (h.id.as_str().to_string(), h.domain))
                .collect()
        })
        .unwrap_or_default()
}

/// Extra needles for the search box: the ids of hostings whose domain
/// contains `q`, or the domain when `q` is a hosting id. Capped so a short
/// query can't build a giant WHERE clause.
fn alt_needles(q: &str, names: &[(String, String)]) -> Vec<String> {
    let q = q.trim();
    if q.is_empty() {
        return vec![];
    }
    if looks_like_hosting_id(q) {
        return names
            .iter()
            .filter(|(id, _)| id.eq_ignore_ascii_case(q))
            .map(|(_, d)| d.clone())
            .collect();
    }
    let ql = q.to_ascii_lowercase();
    names
        .iter()
        .filter(|(_, d)| d.to_ascii_lowercase().contains(&ql))
        .map(|(id, _)| id.clone())
        .take(50)
        .collect()
}

/// Swap a hosting-id target for its domain. A deleted hosting keeps its
/// id: nothing else names it.
fn name_targets(rows: &mut [AuditEntryWire], names: &[(String, String)]) {
    for e in rows {
        if let Some(d) = e
            .target
            .as_deref()
            .filter(|t| looks_like_hosting_id(t))
            .and_then(|t| names.iter().find(|(id, _)| id == t))
            .map(|(_, d)| d.clone())
        {
            e.target = Some(d);
        }
    }
}

// ── View model ──────────────────────────────────────────────────────────

pub struct AuditRow {
    title: String,
    action: String,
    target: Option<String>,
    failed: bool,
    result: String,
    summary: String,
    fields: Vec<(String, String)>,
    /// A payload that isn't a JSON object, shown as-is.
    payload_raw: String,
    when_ago: String,
    when_abs: String,
    actor: String,
    actor_uid: i64,
    node: String,
    id: i64,
    hash: String,
    hash_short: String,
    target_href: String,
    actor_href: String,
}

pub struct DayGroup {
    label: String,
    rows: Vec<AuditRow>,
}

pub struct Segment {
    key: &'static str,
    label: &'static str,
    count: i64,
    href: String,
}

pub struct ActionOption {
    action: String,
    label: String,
    count: i64,
    selected: bool,
}

pub struct WindowOption {
    key: &'static str,
    label: &'static str,
    selected: bool,
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        format!("{}…", s.chars().take(max).collect::<String>())
    } else {
        s.to_string()
    }
}

fn json_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items)
            if items.iter().all(|i| !i.is_object() && !i.is_array()) =>
        {
            items.iter().map(json_scalar).collect::<Vec<_>>().join(", ")
        }
        other => other.to_string(),
    }
}

/// `"php_memory_mb"` → `"php memory MB"`-ish: words split, the handful of
/// abbreviations payloads use spelled the way people write them.
fn payload_key(k: &str) -> String {
    k.split(['_', '-', '.'])
        .filter(|w| !w.is_empty())
        .map(|w| match w {
            "ip" => "IP",
            "id" => "ID",
            "mb" => "MB",
            "gb" => "GB",
            "php" => "PHP",
            "url" => "URL",
            "wp" => "WordPress",
            "db" => "database",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Payload → `(key, value)` rows, plus the one-line summary under the
/// title. A key whose value just repeats the target ("domain") or is empty
/// carries nothing and is left out.
fn payload_view(payload: &str, target: Option<&str>) -> (Vec<(String, String)>, String, String) {
    let trimmed = payload.trim();
    if trimmed.is_empty() || trimmed == "{}" || trimmed == "null" {
        return (vec![], String::new(), String::new());
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(trimmed)
    else {
        return (vec![], String::new(), clip(trimmed, 2000));
    };
    let fields: Vec<(String, String)> = map
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| (payload_key(k), json_scalar(v)))
        .filter(|(_, v)| !v.is_empty() && Some(v.as_str()) != target)
        .map(|(k, v)| (k, clip(&v, 600)))
        .collect();
    let summary = fields
        .iter()
        .take(3)
        .map(|(k, v)| format!("{k}: {}", clip(v, 60)))
        .collect::<Vec<_>>()
        .join(" · ");
    (fields, summary, String::new())
}

fn audit_row(e: AuditEntryWire, sel: &Selection) -> AuditRow {
    let (fields, summary, payload_raw) = payload_view(&e.payload_json, e.target.as_deref());
    let failed = e.result != "ok";
    let scoped = |needle: &str| {
        Selection {
            q: needle.to_string(),
            action: String::new(),
            cat: "",
            since: sel.since.clone(),
            before: None,
        }
        .href("", "", None)
    };
    AuditRow {
        title: crate::handlers::stats::fmt_action_label(&e.action),
        target_href: e.target.as_deref().map(scoped).unwrap_or_default(),
        actor_href: scoped(&e.actor_label),
        failed,
        result: if failed {
            e.result.clone()
        } else {
            String::new()
        },
        summary,
        fields,
        payload_raw,
        when_ago: crate::handlers::stats::fmt_ago(&e.ts),
        when_abs: fmt_local(e.ts, "%Y-%m-%d %H:%M:%S %:z"),
        actor: e.actor_label,
        actor_uid: e.actor_uid,
        node: e.node.unwrap_or_default(),
        id: e.id,
        hash_short: e.row_hash.chars().take(16).collect(),
        hash: e.row_hash,
        action: e.action,
        target: e.target,
    }
}

fn group_by_day(rows: Vec<AuditEntryWire>, sel: &Selection, now: i64) -> Vec<DayGroup> {
    let mut days: Vec<DayGroup> = Vec::new();
    for e in rows {
        let label = day_label(e.ts, now);
        if days.last().map(|d| d.label != label).unwrap_or(true) {
            days.push(DayGroup {
                label,
                rows: Vec::new(),
            });
        }
        if let Some(d) = days.last_mut() {
            d.rows.push(audit_row(e, sel));
        }
    }
    days
}

// ── Page ────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    days: Vec<DayGroup>,
    shown: usize,
    /// Entries matching every filter, across the cluster.
    matching: i64,
    /// Every entry on every node that answered.
    total: i64,
    q: String,
    cat: &'static str,
    action_filter: String,
    action_options: Vec<ActionOption>,
    windows: Vec<WindowOption>,
    since_filter: String,
    segments: Vec<Segment>,
    filtered: bool,
    paged: bool,
    newest_href: String,
    older_href: String,
    export_href: String,
    reset_href: &'static str,
    multi_node: bool,
    partial_nodes: String,
    missing_nodes: String,
    /// Session-wide token for the htmx "Verify chain" POST.
    csrf_token: String,
    /// Set when a node's response failed authentication and its entries
    /// were discarded. On the audit log this matters twice over: the
    /// missing rows are exactly the record of what happened on a node the
    /// master can no longer authenticate.
    node_auth_warning: Option<String>,
}

pub async fn get_audit(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(query): Query<AuditQuery>,
) -> Result<Response, AppError> {
    // The audit log holds every state-changing operation across every
    // hosting, user and node; subjects and payloads leak cross-tenant data.
    if !ctx.can(Capability::AuditView) {
        return Ok(
            axum::response::Redirect::to("/?flash_error=admin+role+required").into_response(),
        );
    }
    let sel = Selection::from_query(&query);
    let now = hyperion_types::now_secs();
    if query.export.trim().eq_ignore_ascii_case("csv") {
        return export_csv(&state, &sel, now).await;
    }

    let mut names = if sel.q.is_empty() {
        None
    } else {
        Some(hosting_names(&state).await)
    };
    let alt = alt_needles(&sel.q, names.as_deref().unwrap_or_default());
    let filter = sel.filter(now, PAGE_LIMIT, alt);
    let fetched = fetch(&state, &filter).await?;
    let (mut rows, next_before) = merge_page(&fetched.batches, PAGE_LIMIT);
    if names.is_none()
        && rows
            .iter()
            .any(|e| e.target.as_deref().is_some_and(looks_like_hosting_id))
    {
        names = Some(hosting_names(&state).await);
    }
    name_targets(&mut rows, names.as_deref().unwrap_or_default());

    // Counts over the scope (search box + window), summed across nodes.
    let mut counts: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for b in &fetched.batches {
        for c in &b.actions {
            let slot = counts.entry(c.action.clone()).or_default();
            slot.0 += c.total;
            slot.1 += c.failed;
        }
    }
    let total: i64 = fetched.batches.iter().map(|b| b.total).sum();
    let in_cat =
        |action: &str, cat: &str| cat.is_empty() || cat == "failed" || category_of(action) == cat;
    let seg_count = |key: &str| -> i64 {
        counts
            .iter()
            .map(|(a, (t, f))| match key {
                "" => *t,
                "failed" => *f,
                k if category_of(a) == k => *t,
                _ => 0,
            })
            .sum()
    };
    let segments = SEGMENTS
        .iter()
        .map(|(key, label)| Segment {
            key,
            label,
            count: seg_count(key),
            href: sel.href(key, "", None),
        })
        .collect();
    let matching: i64 = counts
        .iter()
        .filter(|(a, _)| in_cat(a, sel.cat))
        .filter(|(a, _)| sel.action.is_empty() || **a == sel.action)
        .map(|(_, (t, f))| if sel.cat == "failed" { *f } else { *t })
        .sum();

    // The pick-list holds the kinds in the current segment that occur in
    // the scope, by label. A selected kind with no rows stays listed so the
    // select doesn't silently show "All actions".
    let mut action_options: Vec<ActionOption> = counts
        .iter()
        .filter(|(a, _)| in_cat(a, sel.cat))
        .map(|(a, (t, f))| ActionOption {
            label: crate::handlers::stats::fmt_action_label(a),
            count: if sel.cat == "failed" { *f } else { *t },
            selected: *a == sel.action,
            action: a.clone(),
        })
        .filter(|o| o.count > 0 || o.selected)
        .collect();
    if !sel.action.is_empty() && !action_options.iter().any(|o| o.selected) {
        action_options.push(ActionOption {
            label: crate::handlers::stats::fmt_action_label(&sel.action),
            count: 0,
            selected: true,
            action: sel.action.clone(),
        });
    }
    action_options.sort_by(|a, b| a.label.cmp(&b.label));

    let windows = WINDOWS
        .iter()
        .map(|(key, label, _)| WindowOption {
            key,
            label,
            selected: *key == sel.since,
        })
        .collect();

    let shown = rows.len();
    let days = group_by_day(rows, &sel, now);
    let tpl = AuditTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "audit",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        days,
        shown,
        matching,
        total,
        filtered: !sel.q.is_empty()
            || !sel.cat.is_empty()
            || !sel.action.is_empty()
            || !sel.since.is_empty(),
        paged: sel.before.is_some(),
        newest_href: sel.href(sel.cat, &sel.action, None),
        older_href: next_before
            .map(|b| sel.href(sel.cat, &sel.action, Some(b)))
            .unwrap_or_default(),
        export_href: {
            let base = sel.href(sel.cat, &sel.action, None);
            if base.contains('?') {
                format!("{base}&export=csv")
            } else {
                format!("{base}?export=csv")
            }
        },
        reset_href: "/audit",
        q: sel.q.clone(),
        cat: sel.cat,
        action_filter: sel.action.clone(),
        action_options,
        windows,
        since_filter: sel.since.clone(),
        segments,
        multi_node: fetched.multi_node,
        partial_nodes: fetched.partial.join(", "),
        missing_nodes: fetched.missing.join(", "),
        csrf_token: super::session_csrf_token(&state, &ctx),
        node_auth_warning: fetched.node_auth_warning,
    };
    Ok(Html(tpl.render()?).into_response())
}

// ── CSV export ──────────────────────────────────────────────────────────

/// One CSV cell. Quoted always; a leading `= + - @` (or tab/CR) is
/// prefixed with `'` so a spreadsheet shows the text instead of running it
/// as a formula — targets and payloads carry operator- and tenant-typed
/// strings.
fn csv_cell(s: &str) -> String {
    let guarded = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

async fn export_csv(state: &SharedState, sel: &Selection, now: i64) -> Result<Response, AppError> {
    let mut out = String::from(
        "id,node,time_utc,unix_ts,actor,actor_uid,action,description,target,result,payload,row_hash\n",
    );
    // Ids stay ids in the export (they're what the chain hashed), but a
    // domain search still has to reach them.
    let names = if sel.q.is_empty() {
        vec![]
    } else {
        hosting_names(state).await
    };
    let mut filter = sel.filter(now, EXPORT_PAGE, alt_needles(&sel.q, &names));
    // The page's own cursor is ignored: an export always starts at the
    // newest match.
    filter.before = None;
    let mut written = 0usize;
    let mut truncated = false;
    loop {
        let fetched = fetch(state, &filter).await?;
        let (rows, next) = merge_page(&fetched.batches, EXPORT_PAGE);
        for e in &rows {
            let time = chrono::DateTime::from_timestamp(e.ts, 0)
                .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default();
            let cells = [
                e.id.to_string(),
                csv_cell(e.node.as_deref().unwrap_or("")),
                time,
                e.ts.to_string(),
                csv_cell(&e.actor_label),
                e.actor_uid.to_string(),
                csv_cell(&e.action),
                csv_cell(&crate::handlers::stats::fmt_action_label(&e.action)),
                csv_cell(e.target.as_deref().unwrap_or("")),
                csv_cell(&e.result),
                csv_cell(&e.payload_json),
                csv_cell(&e.row_hash),
            ];
            out.push_str(&cells.join(","));
            out.push('\n');
        }
        written += rows.len();
        match next {
            Some(b) if written < EXPORT_MAX_ROWS => filter.before = Some(b),
            Some(_) => {
                truncated = true;
                break;
            }
            None => break,
        }
    }
    let name = format!("audit-{}.csv", fmt_local(now, "%Y%m%d-%H%M"));
    let mut resp = (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        out,
    )
        .into_response();
    if truncated {
        // Visible to scripts; the browser download itself can't carry a note.
        resp.headers_mut().insert(
            "x-hyperion-truncated",
            axum::http::HeaderValue::from_static("true"),
        );
    }
    Ok(resp)
}

// ── Chain verification ──────────────────────────────────────────────────

/// htmx target behind "Verify chain". Every node keeps its own chain, so
/// each one walks its own and the answers are listed per node. Read-only.
pub async fn post_verify_chain(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::AuditView) {
        return Ok(
            Html("<div class=\"pill err\">admin role required</div>".to_string()).into_response(),
        );
    }
    let esc = |s: &str| askama_escape::escape(s, askama_escape::Html).to_string();
    let line = |node: &str, resp: Result<RpcResponse, String>| -> (bool, String) {
        let (ok, text) = match resp {
            Ok(RpcResponse::AuditVerifyChain {
                ok: true,
                rows_checked,
                ..
            }) => (
                true,
                format!(
                    "intact · {rows_checked} entr{}",
                    if rows_checked == 1 { "y" } else { "ies" }
                ),
            ),
            Ok(RpcResponse::AuditVerifyChain {
                ok: false,
                rows_checked,
                message,
            }) => (
                false,
                format!("BROKEN — {} · {rows_checked} checked", esc(&message)),
            ),
            Ok(RpcResponse::Error(e)) => (false, format!("check failed: {}", esc(&e.to_string()))),
            Ok(_) => (false, "unexpected response".into()),
            Err(e) => (false, format!("no answer: {}", esc(&e))),
        };
        (
            ok,
            format!(
                "<li class=\"{}\"><span class=\"dot\"></span><strong>{}</strong><span>{}</span></li>",
                if ok { "ok" } else { "err" },
                esc(node),
                text
            ),
        )
    };

    let mut items = Vec::new();
    let local = hyperion_rpc_client::call(&state.agent_socket, Request::AuditVerifyChain)
        .await
        .map_err(|e| e.to_string());
    items.push(line("master", local));
    let workers = crate::handlers::hostings::fetch_remote_nodes(&state)
        .await
        .unwrap_or_default();
    let (answered, failed) =
        crate::dispatcher::fan_out_reporting(&state, workers, Request::AuditVerifyChain).await;
    let mut remote: Vec<(String, Result<RpcResponse, String>)> = answered
        .into_iter()
        .map(|(n, r)| (node_label(&n), Ok(r)))
        .chain(
            failed
                .into_iter()
                .map(|(n, e)| (node_label(&n), Err(e.to_string()))),
        )
        .collect();
    remote.sort_by(|a, b| a.0.cmp(&b.0));
    for (label, r) in remote {
        items.push(line(&label, r));
    }
    let all_ok = items.iter().all(|(ok, _)| *ok);
    let html = format!(
        "<div class=\"audit-verify {}\"><div class=\"audit-verify-head\">{}</div><ul>{}</ul></div>",
        if all_ok { "ok" } else { "err" },
        if all_ok {
            "Every chain checks out — no entry has been edited or removed."
        } else {
            "A chain did not verify — an entry was changed or removed outside a retention purge, or the check could not run."
        },
        items
            .into_iter()
            .map(|(_, li)| li)
            .collect::<Vec<_>>()
            .join("")
    );
    Ok(Html(html).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: i64, ts: i64, action: &str, result: &str) -> AuditEntryWire {
        AuditEntryWire {
            id,
            ts,
            actor_uid: 1,
            actor_label: "kevin".into(),
            action: action.into(),
            target: Some("a.example".into()),
            payload_json: r#"{"domain":"a.example","from_mb":256,"to_mb":384}"#.into(),
            result: result.into(),
            node: None,
            row_hash: "ab".repeat(32),
        }
    }

    fn batch(label: &str, ts: &[i64], full: bool) -> NodeBatch {
        NodeBatch {
            label: label.into(),
            rows: ts
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let mut e = entry(i as i64 + 1, *t, "hosting.create", "ok");
                    e.node = Some(label.into());
                    e
                })
                .collect(),
            full,
            actions: vec![],
            total: ts.len() as i64,
        }
    }

    #[test]
    fn since_cutoff_recognises_only_known_labels() {
        let now = 10_000_000;
        assert_eq!(since_cutoff(now, "1h"), Some(9_996_400));
        assert_eq!(since_cutoff(now, "24h"), Some(9_913_600));
        assert_eq!(since_cutoff(now, "7d"), Some(9_395_200));
        assert_eq!(since_cutoff(now, "30d"), Some(10_000_000 - 2_592_000));
        assert_eq!(since_cutoff(now, ""), None);
        assert_eq!(since_cutoff(now, "bogus"), None);
        assert_eq!(since_cutoff(now, "1H"), None, "label is case-sensitive");
        assert_eq!(since_cutoff(10, "30d"), Some(0), "never negative");
    }

    #[test]
    fn categories_split_on_the_first_segment() {
        assert_eq!(category_of("hosting.create"), "sites");
        assert_eq!(category_of("wp_asset.upload"), "sites");
        assert_eq!(category_of("web.login.ok"), "access");
        assert_eq!(category_of("web_session.revoke"), "access");
        assert_eq!(category_of("cert.renew"), "certs");
        assert_eq!(category_of("node.enroll"), "system");
        assert_eq!(category_of("brand.new.kind"), "system");
        // A prefix is a whole segment: `webhook.` is not `web.`.
        assert_eq!(category_of("webhook.fire"), "system");
    }

    #[test]
    fn old_result_link_lands_on_failed_segment() {
        let q = AuditQuery {
            result: "failed".into(),
            ..Default::default()
        };
        assert_eq!(Selection::from_query(&q).cat, "failed");
        let q = AuditQuery {
            cat: "nonsense".into(),
            since: "2y".into(),
            ..Default::default()
        };
        let sel = Selection::from_query(&q);
        assert_eq!(sel.cat, "");
        assert_eq!(sel.since, "");
    }

    #[test]
    fn system_segment_excludes_every_other_category() {
        let sel = Selection {
            q: String::new(),
            action: String::new(),
            cat: "system",
            since: String::new(),
            before: None,
        };
        let f = sel.filter(0, 10, vec![]);
        let e = entry(1, 1, "node.enroll", "ok");
        assert!(entry_matches(&e, &f, false));
        for a in [
            "hosting.create",
            "web.login.ok",
            "web_session.revoke",
            "cert.renew",
        ] {
            assert!(!entry_matches(&entry(1, 1, a, "ok"), &f, false), "{a}");
        }
    }

    #[test]
    fn hrefs_drop_the_cursor_unless_asked() {
        let sel = Selection {
            q: "a b".into(),
            action: "cert.renew".into(),
            cat: "certs",
            since: "7d".into(),
            before: Some(500),
        };
        assert_eq!(
            sel.href("failed", "", None),
            "/audit?q=a+b&cat=failed&since=7d"
        );
        assert_eq!(
            sel.href(sel.cat, &sel.action, Some(400)),
            "/audit?q=a+b&cat=certs&action=cert.renew&since=7d&before=400"
        );
    }

    #[test]
    fn merge_never_splits_a_second_or_passes_a_full_node() {
        // Node b filled its page; its oldest row is ts 50, so nothing at or
        // below 50 is known complete.
        let batches = vec![
            batch("a", &[100, 90, 50, 40, 30], false),
            batch("b", &[95, 60, 50], true),
        ];
        let (page, next) = merge_page(&batches, 10);
        let ts: Vec<i64> = page.iter().map(|e| e.ts).collect();
        assert_eq!(ts, vec![100, 95, 90, 60]);
        assert_eq!(next, Some(60));

        // Limit cuts inside a second: the whole second moves to the next page.
        let batches = vec![batch("a", &[100, 90, 90, 80], false)];
        let (page, next) = merge_page(&batches, 2);
        assert_eq!(page.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![100]);
        assert_eq!(next, Some(100));

        // Everything fits, nobody full: no next page.
        let batches = vec![batch("a", &[3, 2], false), batch("b", &[1], false)];
        let (page, next) = merge_page(&batches, 10);
        assert_eq!(page.len(), 3);
        assert_eq!(next, None);

        // A page entirely inside one second is shown whole.
        let batches = vec![batch("a", &[7, 7, 7], false)];
        let (page, next) = merge_page(&batches, 2);
        assert_eq!(page.len(), 3);
        assert_eq!(next, None);
    }

    #[test]
    fn old_node_window_is_filtered_and_counted_locally() {
        let window = vec![
            entry(3, 30, "cert.renew", "failed"),
            entry(2, 20, "hosting.create", "ok"),
            entry(1, 10, "web.login.ok", "ok"),
        ];
        let f = AuditSearchFilter {
            failed_only: true,
            since: Some(15),
            limit: 10,
            ..Default::default()
        };
        let b = batch_from_window("old".into(), window, &f);
        assert_eq!(b.rows.iter().map(|e| e.id).collect::<Vec<_>>(), vec![3]);
        assert!(!b.full);
        assert_eq!(b.total, 3);
        // Counts cover the scope (window), not the failed-only cut.
        assert_eq!(
            b.actions
                .iter()
                .map(|c| (c.action.as_str(), c.total, c.failed))
                .collect::<Vec<_>>(),
            vec![("cert.renew", 1, 1), ("hosting.create", 1, 0)]
        );
    }

    #[test]
    fn payload_view_drops_the_target_and_summarises() {
        let (fields, summary, raw) = payload_view(
            r#"{"domain":"a.example","from_mb":256,"to_mb":384,"note":null}"#,
            Some("a.example"),
        );
        assert_eq!(
            fields,
            vec![
                ("from MB".into(), "256".into()),
                ("to MB".into(), "384".into())
            ]
        );
        assert_eq!(summary, "from MB: 256 · to MB: 384");
        assert!(raw.is_empty());
        assert_eq!(
            payload_view("{}", None),
            (vec![], String::new(), String::new())
        );
        let (_, _, raw) = payload_view("not json", None);
        assert_eq!(raw, "not json");
        let (fields, _, _) = payload_view(r#"{"aliases":["a","b"]}"#, None);
        assert_eq!(fields, vec![("aliases".into(), "a, b".into())]);
    }

    #[test]
    fn domain_search_reaches_entries_that_name_the_hosting_id() {
        let id = "01a110ad-4c30-7692-831e-e3308222b095";
        let names = vec![
            (id.to_string(), "shop.example".to_string()),
            (
                "01a110ad-4c30-7692-831e-e3308222b096".into(),
                "blog.test".into(),
            ),
        ];
        assert_eq!(alt_needles("SHOP", &names), vec![id.to_string()]);
        assert_eq!(alt_needles(id, &names), vec!["shop.example".to_string()]);
        assert!(alt_needles("", &names).is_empty());

        let mut e = entry(1, 1, "hosting.suspend", "ok");
        e.target = Some(id.into());
        e.payload_json = "{}".into();
        let f = AuditSearchFilter {
            q: "shop.example".into(),
            q_alt: alt_needles("shop.example", &names),
            limit: 10,
            ..Default::default()
        };
        assert!(entry_matches(&e, &f, false));

        let mut rows = vec![e];
        name_targets(&mut rows, &names);
        assert_eq!(rows[0].target.as_deref(), Some("shop.example"));
    }

    #[test]
    fn csv_cells_are_quoted_and_formula_safe() {
        assert_eq!(csv_cell("plain"), "\"plain\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=HYPERLINK(1)"), "\"'=HYPERLINK(1)\"");
        assert_eq!(csv_cell("-1"), "\"'-1\"");
    }
}
