//! /vulns — cluster-wide WordPress updates.
//!
//! Fans `VulnFindingsList` out across the master + every enrolled node and
//! sorts each WordPress site by what it needs from an operator:
//!
//! * **Needs you** — a major update, an update held back because the site's
//!   auto-update is off, or a plugin whose auto-update is paused after it kept
//!   failing (usually a licence-gated download).
//! * **Couldn't check** — the last scan could not read the site, the sweep has
//!   not reached it yet or for days, or the node is too old to say whether an
//!   update applies itself.
//! * **Updating itself** — same-major updates the next nightly sweep applies.
//! * **Up to date.**
//!
//! [`component_state`] and [`site_bucket`] are the only place those rules
//! live, so the segment counts, the verdict, the rows and the sidebar dot
//! cannot disagree. The scan + storage happen in the agent's
//! `wp_vuln_scan_tick`; this page only reads the stored results.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{HostingVulnSummary, WpVulnFinding};
use serde::Deserialize;

/// A site whose last good scan is older than this is "not checked lately".
/// The sweep runs daily (and four minutes after every agent start), so two
/// days without one means the sweep is not reaching it.
pub(crate) const STALE_SECS: i64 = 2 * 86_400;

/// What one site needs from an operator. Ordered by urgency: the page lists
/// buckets in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Bucket {
    Needs,
    Unchecked,
    Updating,
    Clean,
}

impl Bucket {
    pub const ALL: [Bucket; 4] = [
        Bucket::Needs,
        Bucket::Unchecked,
        Bucket::Updating,
        Bucket::Clean,
    ];

    /// The `show=` query value.
    pub fn key(self) -> &'static str {
        match self {
            Bucket::Needs => "needs",
            Bucket::Unchecked => "unchecked",
            Bucket::Updating => "auto",
            Bucket::Clean => "ok",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Bucket::Needs => "Needs you",
            Bucket::Unchecked => "Couldn't check",
            Bucket::Updating => "Updating itself",
            Bucket::Clean => "Up to date",
        }
    }

    /// Pill / segment-dot tone.
    pub fn tone(self) -> &'static str {
        match self {
            Bucket::Needs | Bucket::Unchecked => "warn",
            Bucket::Updating => "info",
            Bucket::Clean => "ok",
        }
    }

    fn from_key(k: &str) -> Option<Bucket> {
        Bucket::ALL.into_iter().find(|b| b.key() == k)
    }
}

/// What happens to one outdated component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompState {
    /// A major update — never applied automatically.
    Major,
    /// Same-major, but the site's auto-update is off.
    AutoOff,
    /// Same-major, but auto-update is paused after repeated failures.
    Paused,
    /// Same-major, and the node is too old to report the auto-update switch.
    Unknown,
    /// Same-major, failed in an earlier sweep, retried in the next one.
    Retrying,
    /// Same-major; the next sweep applies it.
    Next,
}

impl CompState {
    pub fn needs_you(self) -> bool {
        matches!(
            self,
            CompState::Major | CompState::AutoOff | CompState::Paused
        )
    }

    pub fn applies_itself(self) -> bool {
        matches!(self, CompState::Retrying | CompState::Next)
    }

    /// Dot tone in the fold.
    pub fn tone(self) -> &'static str {
        if self.needs_you() {
            "warn"
        } else {
            ""
        }
    }
}

/// The one rule for a plugin/theme finding.
pub fn component_state(f: &WpVulnFinding, auto_update: Option<bool>, now: i64) -> CompState {
    if !f.auto_updatable {
        return CompState::Major;
    }
    match auto_update {
        None => CompState::Unknown,
        Some(false) => CompState::AutoOff,
        Some(true) if f.auto_update_paused_until > now => CompState::Paused,
        Some(true) if f.auto_update_failures > 0 => CompState::Retrying,
        Some(true) => CompState::Next,
    }
}

/// The same rule for a core release. Core has no pause map: a failed minor
/// core update alerts on its own and is retried every sweep.
pub fn core_state(update_type: &str, auto_update: Option<bool>) -> CompState {
    if !update_type.eq_ignore_ascii_case("minor") {
        return CompState::Major;
    }
    match auto_update {
        None => CompState::Unknown,
        Some(false) => CompState::AutoOff,
        Some(true) => CompState::Next,
    }
}

/// Why a site's update status is not current, if it is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckProblem {
    /// The sweep has not reached it yet.
    Never,
    /// The latest attempt could not read the site.
    Failed,
    /// No good scan for longer than [`STALE_SECS`].
    Stale,
}

pub fn check_problem(s: &HostingVulnSummary, now: i64) -> Option<CheckProblem> {
    if s.failed_at > 0 {
        Some(CheckProblem::Failed)
    } else if s.scanned_at <= 0 {
        Some(CheckProblem::Never)
    } else if now - s.scanned_at > STALE_SECS {
        Some(CheckProblem::Stale)
    } else {
        None
    }
}

/// Every component state of a site — plugins/themes then core.
fn states(s: &HostingVulnSummary, now: i64) -> Vec<CompState> {
    let mut v: Vec<CompState> = s
        .findings
        .iter()
        .map(|f| component_state(f, s.auto_update, now))
        .collect();
    v.extend(
        s.core_updates
            .iter()
            .map(|u| core_state(&u.update_type, s.auto_update)),
    );
    v
}

/// The one rule for a site. What needs a person wins, even over a failed
/// check — the last good scan still showed it, and it does not go away by
/// itself.
pub fn site_bucket(s: &HostingVulnSummary, now: i64) -> Bucket {
    let st = states(s, now);
    if st.iter().any(|c| c.needs_you()) {
        Bucket::Needs
    } else if check_problem(s, now).is_some() || st.contains(&CompState::Unknown) {
        Bucket::Unchecked
    } else if st.iter().any(|c| c.applies_itself()) {
        Bucket::Updating
    } else {
        Bucket::Clean
    }
}

/// Sites that need a person — the sidebar dot.
pub fn needs_you_sites(rows: &[HostingVulnSummary], now: i64) -> usize {
    rows.iter()
        .filter(|s| site_bucket(s, now) == Bucket::Needs)
        .count()
}

// ---------------------------------------------------------------------------
// View model
// ---------------------------------------------------------------------------

pub struct CompRow {
    pub name: String,
    /// "plugin" | "theme" | "core"
    pub kind: &'static str,
    pub from: String,
    pub to: String,
    /// "major" | "minor" | "patch"
    pub update_type: String,
    pub state: CompState,
    /// What happens to it, in a few words.
    pub what: String,
    /// The last auto-update error, when there is one.
    pub error: String,
}

pub struct SiteRow {
    pub hosting_id: String,
    pub domain: String,
    pub node: String,
    pub bucket: Bucket,
    pub comps: Vec<CompRow>,
    /// The summary line under the domain.
    pub headline: String,
    /// Components beyond the headline one.
    pub more: usize,
    pub checked_ago: String,
    pub checked_abs: String,
    /// "auto-update on" | "auto-update off" | "auto-update unknown"
    pub auto_label: &'static str,
    pub auto_update: Option<bool>,
    /// Why the result is not current, in a sentence; empty when it is.
    pub problem: String,
    /// "WordPress 6.6.2", "WordPress 6.5.3 · core not checked", or "".
    pub core_line: String,
    /// "14 plugins & themes checked · 3 updated by the last sweep" …
    pub facts: String,
}

fn kind_static(kind: &str) -> &'static str {
    match kind {
        "theme" => "theme",
        _ => "plugin",
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn fmt_date(ts: i64) -> String {
    super::emails::fmt_local(ts, "%-d %b %Y")
}

fn what_for(state: CompState, f: Option<&WpVulnFinding>) -> String {
    match state {
        CompState::Major => "waits for you — majors never apply themselves".into(),
        CompState::AutoOff => "auto-update is off for this site — waits for you".into(),
        CompState::Paused => {
            let (n, until) = f.map_or((0, 0), |f| {
                (f.auto_update_failures, f.auto_update_paused_until)
            });
            format!(
                "auto-update paused until {} after {} — usually a plugin that needs a licence key",
                fmt_date(until),
                plural(n as usize, "failed try", "failed tries"),
            )
        }
        CompState::Unknown => {
            "this node's agent is too old to say whether it applies itself".into()
        }
        CompState::Retrying => {
            let n = f.map_or(0, |f| f.auto_update_failures);
            format!(
                "failed {} — tried again in the next sweep",
                plural(n as usize, "time", "times")
            )
        }
        CompState::Next => "applied by the next sweep".into(),
    }
}

/// Short tag for the summary line.
fn short_what(state: CompState) -> &'static str {
    match state {
        CompState::Major => "major",
        CompState::AutoOff => "auto-update off",
        CompState::Paused => "auto-update paused",
        CompState::Unknown => "may not apply itself",
        CompState::Retrying => "retrying",
        CompState::Next => "next sweep",
    }
}

fn comp_rows(s: &HostingVulnSummary, now: i64) -> Vec<CompRow> {
    let mut rows: Vec<CompRow> = s
        .findings
        .iter()
        .map(|f| {
            let state = component_state(f, s.auto_update, now);
            CompRow {
                name: if f.name.trim().is_empty() {
                    f.slug.clone()
                } else {
                    f.name.clone()
                },
                kind: kind_static(&f.kind),
                from: f.installed_version.clone(),
                to: f.patched_version.clone(),
                update_type: f.update_type.clone(),
                state,
                what: what_for(state, Some(f)),
                error: f.auto_update_error.clone(),
            }
        })
        .collect();
    for u in &s.core_updates {
        let state = core_state(&u.update_type, s.auto_update);
        rows.push(CompRow {
            name: "WordPress".into(),
            kind: "core",
            from: s.core_version.clone(),
            to: u.version.clone(),
            update_type: u.update_type.to_lowercase(),
            state,
            what: what_for(state, None),
            error: String::new(),
        });
    }
    // What needs a person first, then what applies itself; majors (incl.
    // core) before minors within each.
    let rank = |c: &CompRow| -> (u8, u8) {
        let s = if c.state.needs_you() {
            0
        } else if c.state == CompState::Unknown {
            1
        } else {
            2
        };
        let t = match c.update_type.as_str() {
            "major" => 0,
            "minor" => 1,
            _ => 2,
        };
        (s, t)
    };
    rows.sort_by_key(rank);
    rows
}

/// The same component rows for a live scan from a site's WordPress tab, so
/// the tab and the cluster page say the same thing about each update.
pub(crate) fn scan_comp_rows(
    scan: &hyperion_types::WpVulnScanResult,
    auto_update: bool,
    now: i64,
) -> Vec<CompRow> {
    let s = HostingVulnSummary {
        findings: scan.findings.clone(),
        auto_update: Some(auto_update),
        core_version: scan.core_version.clone(),
        core_checked: scan.core_checked,
        core_updates: scan.core_updates.clone(),
        ..Default::default()
    };
    comp_rows(&s, now)
}

fn problem_text(s: &HostingVulnSummary, p: &CheckProblem, now: i64) -> String {
    let ago = |t: i64| crate::handlers::stats::fmt_ago(&t);
    match p {
        CheckProblem::Never => {
            "Not checked yet — the nightly sweep reaches it within a day.".into()
        }
        CheckProblem::Failed if s.scanned_at <= 0 => {
            format!("Couldn't read the site ({}): {}", ago(s.failed_at), s.error)
        }
        CheckProblem::Failed => format!(
            "The last check ({}) couldn't read the site: {}. Showing the result from {}.",
            ago(s.failed_at),
            s.error,
            ago(s.scanned_at)
        ),
        CheckProblem::Stale => format!(
            "Not checked for {} — the nightly sweep is not reaching this site.",
            plural(((now - s.scanned_at) / 86_400) as usize, "day", "days")
        ),
    }
}

pub fn site_row(s: &HostingVulnSummary, now: i64) -> SiteRow {
    let bucket = site_bucket(s, now);
    let comps = comp_rows(s, now);
    let problem = check_problem(s, now)
        .map(|p| problem_text(s, &p, now))
        .unwrap_or_default();
    let core_line = if s.core_version.is_empty() && !s.core_checked {
        String::new()
    } else if s.core_checked {
        format!("WordPress {}", s.core_version)
    } else {
        format!("WordPress {} · core not checked", s.core_version)
    };
    let headline = match comps.first() {
        Some(c) if bucket != Bucket::Unchecked || problem.is_empty() => {
            format!("{} {} → {} · {}", c.name, c.from, c.to, short_what(c.state))
        }
        _ if !problem.is_empty() => problem.clone(),
        _ => {
            let mut parts = Vec::new();
            if s.checked > 0 {
                parts.push(format!(
                    "{} current",
                    plural(s.checked as usize, "plugin or theme", "plugins & themes")
                ));
            } else {
                parts.push("plugins & themes current".into());
            }
            parts.push(if s.core_checked {
                "core current".into()
            } else {
                "core not checked".into()
            });
            parts.join(" · ")
        }
    };
    let mut facts = Vec::new();
    if s.checked > 0 {
        facts.push(format!(
            "{} checked",
            plural(s.checked as usize, "plugin or theme", "plugins & themes")
        ));
    }
    if s.auto_updated > 0 {
        facts.push(format!(
            "{} by the last sweep",
            plural(s.auto_updated as usize, "update applied", "updates applied")
        ));
    }
    SiteRow {
        hosting_id: s.hosting_id.clone(),
        domain: s.domain.clone(),
        node: s.node_id.clone(),
        bucket,
        more: comps.len().saturating_sub(1),
        comps,
        headline,
        checked_ago: if s.scanned_at > 0 {
            format!("checked {}", crate::handlers::stats::fmt_ago(&s.scanned_at))
        } else {
            "never checked".into()
        },
        checked_abs: if s.scanned_at > 0 {
            super::emails::fmt_local(s.scanned_at, "%-d %b %Y %H:%M")
        } else {
            String::new()
        },
        auto_label: match s.auto_update {
            Some(true) => "auto-update on",
            Some(false) => "auto-update off",
            None => "auto-update unknown",
        },
        auto_update: s.auto_update,
        problem,
        core_line,
        facts: facts.join(" · "),
    }
}

/// The fleet verdict: one sentence and its tone.
pub fn verdict(rows: &[HostingVulnSummary], now: i64) -> (String, &'static str) {
    let mut by = [0usize; 4];
    let (mut majors, mut paused, mut off, mut next) = (0usize, 0usize, 0usize, 0usize);
    for s in rows {
        by[site_bucket(s, now) as usize] += 1;
        for c in states(s, now) {
            match c {
                CompState::Major => majors += 1,
                CompState::Paused => paused += 1,
                CompState::AutoOff => off += 1,
                CompState::Retrying | CompState::Next => next += 1,
                CompState::Unknown => {}
            }
        }
    }
    let [needs, unchecked, updating, _clean] = by;
    let latest = rows.iter().map(|s| s.scanned_at).max().unwrap_or(0);
    let suffix = if latest > 0 {
        format!(
            " · last checked {}",
            crate::handlers::stats::fmt_ago(&latest)
        )
    } else {
        String::new()
    };
    if needs > 0 {
        let mut parts = Vec::new();
        if majors > 0 {
            parts.push(plural(majors, "major update", "major updates"));
        }
        if paused > 0 {
            parts.push(plural(paused, "paused plugin", "paused plugins"));
        }
        if off > 0 {
            parts.push(format!(
                "{} held back by auto-update off",
                plural(off, "update", "updates")
            ));
        }
        let verb = if needs == 1 { "needs" } else { "need" };
        (
            format!(
                "{} {verb} you — {}{suffix}",
                plural(needs, "site", "sites"),
                parts.join(", ")
            ),
            "warn",
        )
    } else if unchecked > 0 {
        (
            format!(
                "Nothing waits on you, but {} couldn't be checked{suffix}",
                plural(unchecked, "site", "sites")
            ),
            "warn",
        )
    } else if updating > 0 {
        (
            format!(
                "Nothing needs you — {} by the next sweep{suffix}",
                plural(next, "update is applied", "updates are applied")
            ),
            "ok",
        )
    } else {
        (
            format!(
                "All {} up to date{suffix}",
                plural(rows.len(), "WordPress site is", "WordPress sites are")
            ),
            "ok",
        )
    }
}

fn matches_q(s: &HostingVulnSummary, q: &str) -> bool {
    let has = |v: &str| v.to_lowercase().contains(q);
    has(&s.domain)
        || has(&s.node_id)
        || s.findings.iter().any(|f| has(&f.slug) || has(&f.name))
        || (!s.core_updates.is_empty() && has("wordpress core"))
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

fn vulns_href(show: &str, node: &str, q: &str) -> String {
    let parts: Vec<String> = [("show", show), ("node", node), ("q", q)]
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect();
    if parts.is_empty() {
        "/vulns".into()
    } else {
        format!("/vulns?{}", parts.join("&"))
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub struct Segment {
    pub key: &'static str,
    pub label: &'static str,
    pub tone: &'static str,
    pub count: usize,
    pub href: String,
    pub active: bool,
}

pub struct GroupView {
    pub bucket: Bucket,
    pub rows: Vec<SiteRow>,
}

#[derive(Template)]
#[template(path = "vulns.html")]
struct VulnsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    /// No WordPress site anywhere (before any filter).
    fleet_empty: bool,
    verdict: String,
    verdict_tone: &'static str,
    q: String,
    node_filter: String,
    show: String,
    nodes: Vec<String>,
    all_count: usize,
    all_href: String,
    segments: Vec<Segment>,
    groups: Vec<GroupView>,
    /// Set when a node's response failed authentication and its findings
    /// were therefore discarded — "everything is up to date" would be a
    /// lie for that node.
    node_auth_warning: Option<String>,
    /// Nodes that did not answer at all; their sites are missing.
    unreachable: Vec<String>,
}

#[derive(Deserialize, Default)]
pub struct VulnsQuery {
    #[serde(default)]
    pub show: String,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub q: String,
}

/// Every node's list, labelled with the node it came from, plus the
/// authentication banner text and the nodes that did not answer.
pub(crate) async fn collect_all(
    state: &SharedState,
) -> (Vec<HostingVulnSummary>, Option<String>, Vec<String>) {
    let mut all: Vec<HostingVulnSummary> = Vec::new();
    let mut unreachable = Vec::new();
    match hyperion_rpc_client::call(&state.agent_socket, Request::VulnFindingsList).await {
        Ok(RpcResponse::VulnFindingsList(items)) => {
            for mut it in items {
                it.node_id = "master".into();
                all.push(it);
            }
        }
        _ => unreachable.push("master".to_string()),
    }
    let mut node_auth_warning = None;
    if let Ok(RpcResponse::NodesList(nodes)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        let (answered, failed) =
            crate::dispatcher::fan_out_reporting(state, nodes, Request::VulnFindingsList).await;
        for (n, resp) in answered {
            if let RpcResponse::VulnFindingsList(items) = resp {
                for mut it in items {
                    it.node_id = n.label.clone();
                    all.push(it);
                }
            }
        }
        node_auth_warning = super::node_auth_warning(&failed);
        // Authentication failures have their own banner; everything else
        // (down, timed out) would otherwise vanish without a word.
        for (n, e) in &failed {
            if !matches!(
                e,
                crate::dispatcher::DispatchError::ResponseAuthFailed { .. }
            ) {
                unreachable.push(if n.label.is_empty() {
                    n.node_id.clone()
                } else {
                    n.label.clone()
                });
            }
        }
    }
    (all, node_auth_warning, unreachable)
}

/// Sidebar-dot cache: the dot polls every minute from every open tab, and a
/// cluster fan-out per poll per tab is not worth a number read at a glance.
static NAV_CACHE: std::sync::Mutex<Option<(std::time::Instant, usize)>> =
    std::sync::Mutex::new(None);
const NAV_TTL: std::time::Duration = std::time::Duration::from_secs(300);

fn nav_cache_put(n: usize) {
    if let Ok(mut g) = NAV_CACHE.lock() {
        *g = Some((std::time::Instant::now(), n));
    }
}

/// Sites across the cluster that need a person, cached for five minutes.
pub(crate) async fn needs_you_count_cached(state: &SharedState) -> usize {
    if let Ok(g) = NAV_CACHE.lock() {
        if let Some((at, n)) = *g {
            if at.elapsed() < NAV_TTL {
                return n;
            }
        }
    }
    let (rows, _, _) = collect_all(state).await;
    let n = needs_you_sites(&rows, hyperion_types::now_secs());
    nav_cache_put(n);
    n
}

pub async fn get_vulns(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(query): Query<VulnsQuery>,
) -> Result<Response, AppError> {
    // Cluster-wide WP-vuln overview: tenant roles hold WpVulnView for their own
    // sites, so require all-hostings scope for the cross-cluster view.
    if !(ctx.can(Capability::WpVulnView) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let now = hyperion_types::now_secs();
    let (all, node_auth_warning, unreachable) = collect_all(&state).await;
    // The page just did the fan-out the dot would; keep them in step.
    nav_cache_put(needs_you_sites(&all, now));

    let (verdict, verdict_tone) = verdict(&all, now);
    let mut nodes: Vec<String> = all.iter().map(|s| s.node_id.clone()).collect();
    nodes.sort();
    nodes.dedup();

    let q = query.q.trim().to_string();
    let q_lower = q.to_lowercase();
    let node_filter = query.node.trim().to_string();
    let show_bucket = Bucket::from_key(query.show.trim());
    let show = show_bucket.map(|b| b.key()).unwrap_or("").to_string();

    // Counts are over the search box + node select, BEFORE the segment, so a
    // segment never reads 0 just because another one is selected.
    let mut filtered: Vec<SiteRow> = all
        .iter()
        .filter(|s| node_filter.is_empty() || s.node_id == node_filter)
        .filter(|s| q_lower.is_empty() || matches_q(s, &q_lower))
        .map(|s| site_row(s, now))
        .collect();
    let mut counts = [0usize; 4];
    for r in &filtered {
        counts[r.bucket as usize] += 1;
    }
    let segments = Bucket::ALL
        .into_iter()
        .map(|b| Segment {
            key: b.key(),
            label: b.label(),
            tone: b.tone(),
            count: counts[b as usize],
            href: vulns_href(b.key(), &node_filter, &q),
            active: show_bucket == Some(b),
        })
        .collect();

    // Most to do first inside a bucket, then by name.
    filtered.sort_by(|a, b| {
        let todo = |r: &SiteRow| r.comps.iter().filter(|c| c.state.needs_you()).count();
        a.bucket
            .cmp(&b.bucket)
            .then(todo(b).cmp(&todo(a)))
            .then(a.domain.cmp(&b.domain))
    });
    let mut groups: Vec<GroupView> = Vec::new();
    for r in filtered {
        if show_bucket.is_some_and(|b| b != r.bucket) {
            continue;
        }
        match groups.last_mut() {
            Some(g) if g.bucket == r.bucket => g.rows.push(r),
            _ => groups.push(GroupView {
                bucket: r.bucket,
                rows: vec![r],
            }),
        }
    }

    let tpl = VulnsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "vulns",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        fleet_empty: all.is_empty(),
        verdict,
        verdict_tone,
        all_count: counts.iter().sum(),
        all_href: vulns_href("", &node_filter, &q),
        q,
        node_filter,
        show,
        nodes,
        segments,
        groups,
        node_auth_warning,
        unreachable,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::WpCoreUpdate;

    const NOW: i64 = 1_800_000_000;

    fn finding(slug: &str, from: &str, to: &str) -> WpVulnFinding {
        let major = from.split('.').next() != to.split('.').next();
        WpVulnFinding {
            slug: slug.into(),
            name: slug.into(),
            installed_version: from.into(),
            patched_version: to.into(),
            kind: "plugin".into(),
            update_type: if major { "major" } else { "minor" }.into(),
            severity: if major { "high" } else { "medium" }.into(),
            auto_updatable: !major,
            ..Default::default()
        }
    }

    fn site(findings: Vec<WpVulnFinding>, auto: Option<bool>) -> HostingVulnSummary {
        HostingVulnSummary {
            hosting_id: "h1".into(),
            domain: "kos.cz".into(),
            node_id: "master".into(),
            scanned_at: NOW - 3_600,
            findings,
            auto_update: auto,
            checked: 12,
            core_version: "6.6.2".into(),
            core_checked: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_major_waits_for_a_person_whatever_the_switch() {
        let f = finding("woocommerce", "8.7.0", "9.0.1");
        for auto in [Some(true), Some(false), None] {
            assert_eq!(component_state(&f, auto, NOW), CompState::Major);
        }
        assert_eq!(site_bucket(&site(vec![f], Some(true)), NOW), Bucket::Needs);
    }

    #[test]
    fn a_minor_applies_itself_only_when_the_site_lets_it() {
        let f = finding("akismet", "5.3.1", "5.3.3");
        assert_eq!(component_state(&f, Some(true), NOW), CompState::Next);
        assert_eq!(
            site_bucket(&site(vec![f.clone()], Some(true)), NOW),
            Bucket::Updating
        );
        assert_eq!(component_state(&f, Some(false), NOW), CompState::AutoOff);
        assert_eq!(
            site_bucket(&site(vec![f], Some(false)), NOW),
            Bucket::Needs,
            "auto-update off: nothing happens without a person"
        );
    }

    /// An older agent does not report the switch. The page must not promise
    /// the update applies itself — nor claim it waits.
    #[test]
    fn an_old_node_never_reads_as_updating_itself() {
        let f = finding("akismet", "5.3.1", "5.3.3");
        assert_eq!(component_state(&f, None, NOW), CompState::Unknown);
        let row = site_row(&site(vec![f], None), NOW);
        assert_eq!(row.bucket, Bucket::Unchecked);
        assert_eq!(row.auto_label, "auto-update unknown");
        assert!(
            row.comps[0].what.contains("too old"),
            "{}",
            row.comps[0].what
        );
    }

    #[test]
    fn a_paused_plugin_needs_you_and_says_why() {
        let mut f = finding("acf-pro", "6.2.0", "6.3.1");
        f.auto_update_failures = 2;
        f.auto_update_paused_until = NOW + 86_400;
        f.auto_update_error = "Download failed. Unauthorized".into();
        let row = site_row(&site(vec![f.clone()], Some(true)), NOW);
        assert_eq!(row.bucket, Bucket::Needs);
        assert_eq!(row.comps[0].state, CompState::Paused);
        assert!(
            row.comps[0].what.contains("2 failed tries"),
            "{}",
            row.comps[0].what
        );
        assert_eq!(row.comps[0].error, "Download failed. Unauthorized");

        // A lapsed pause is retried — back to applying itself.
        f.auto_update_paused_until = NOW - 1;
        assert_eq!(component_state(&f, Some(true), NOW), CompState::Retrying);
    }

    #[test]
    fn core_majors_wait_and_core_minors_follow_the_switch() {
        let mut s = site(vec![], Some(true));
        s.core_updates = vec![
            WpCoreUpdate {
                version: "6.7.0".into(),
                update_type: "major".into(),
            },
            WpCoreUpdate {
                version: "6.6.3".into(),
                update_type: "minor".into(),
            },
        ];
        let row = site_row(&s, NOW);
        assert_eq!(row.bucket, Bucket::Needs);
        assert_eq!(row.comps.len(), 2);
        assert_eq!(row.comps[0].kind, "core");
        assert_eq!(row.comps[0].to, "6.7.0", "the major leads");
        assert_eq!(row.comps[1].state, CompState::Next);
        assert!(
            row.headline.starts_with("WordPress 6.6.2 → 6.7.0"),
            "{}",
            row.headline
        );
    }

    /// "Up to date" must not speak for core when core was not checked.
    #[test]
    fn an_up_to_date_row_only_vouches_for_core_when_core_was_checked() {
        let mut s = site(vec![], Some(true));
        assert_eq!(site_bucket(&s, NOW), Bucket::Clean);
        assert_eq!(
            site_row(&s, NOW).headline,
            "12 plugins & themes current · core current"
        );
        s.core_checked = false;
        assert!(site_row(&s, NOW).headline.ends_with("core not checked"));
        assert!(site_row(&s, NOW).core_line.contains("core not checked"));
    }

    #[test]
    fn never_failed_and_stale_checks_are_named() {
        let mut never = site(vec![], Some(true));
        never.scanned_at = 0;
        never.core_checked = false;
        let row = site_row(&never, NOW);
        assert_eq!(row.bucket, Bucket::Unchecked);
        assert!(
            row.headline.starts_with("Not checked yet"),
            "{}",
            row.headline
        );
        assert_eq!(row.checked_ago, "never checked");

        let mut failed = site(vec![finding("akismet", "5.3.1", "5.3.3")], Some(true));
        failed.failed_at = NOW - 60;
        failed.error = "plugins: Error establishing a database connection".into();
        let row = site_row(&failed, NOW);
        assert_eq!(
            row.bucket,
            Bucket::Unchecked,
            "a failed check outranks updating itself"
        );
        assert!(
            row.problem.contains("database connection"),
            "{}",
            row.problem
        );
        assert!(
            row.headline.contains("database connection"),
            "{}",
            row.headline
        );

        let mut stale = site(vec![], Some(true));
        stale.scanned_at = NOW - 3 * 86_400;
        let row = site_row(&stale, NOW);
        assert_eq!(row.bucket, Bucket::Unchecked);
        assert!(row.problem.contains("3 days"), "{}", row.problem);
    }

    /// What a person must do outranks a failed check — the last good scan
    /// still showed it, and it does not go away by itself.
    #[test]
    fn needs_you_outranks_a_failed_check() {
        let mut s = site(vec![finding("woocommerce", "8.7.0", "9.0.1")], Some(true));
        s.failed_at = NOW - 60;
        s.error = "x".into();
        let row = site_row(&s, NOW);
        assert_eq!(row.bucket, Bucket::Needs);
        assert!(!row.problem.is_empty(), "the failure is still said");
        assert!(row.headline.starts_with("woocommerce"), "{}", row.headline);
    }

    #[test]
    fn verdict_counts_what_needs_a_person() {
        let a = site(
            vec![
                finding("woocommerce", "8.7.0", "9.0.1"),
                finding("akismet", "5.3.1", "5.3.3"),
            ],
            Some(true),
        );
        let b = site(vec![finding("yoast", "22.4", "22.5")], Some(false));
        let c = site(vec![], Some(true));
        let (text, tone) = verdict(&[a, b, c], NOW);
        assert_eq!(tone, "warn");
        assert!(
            text.starts_with(
                "2 sites need you — 1 major update, 1 update held back by auto-update off"
            ),
            "{text}"
        );
        assert_eq!(needs_you_sites(&[site(vec![], Some(true))], NOW), 0);

        let (text, tone) = verdict(
            &[site(vec![finding("akismet", "5.3.1", "5.3.3")], Some(true))],
            NOW,
        );
        assert_eq!(tone, "ok");
        assert!(
            text.starts_with("Nothing needs you — 1 update is applied by the next sweep"),
            "{text}"
        );

        let (text, _) = verdict(&[site(vec![], Some(true)), site(vec![], Some(true))], NOW);
        assert!(
            text.starts_with("All 2 WordPress sites are up to date"),
            "{text}"
        );
    }

    #[test]
    fn search_reaches_plugin_names_and_href_keeps_filters() {
        let s = site(vec![finding("woocommerce", "8.7.0", "9.0.1")], Some(true));
        assert!(matches_q(&s, "wooc"));
        assert!(matches_q(&s, "kos"));
        assert!(!matches_q(&s, "akismet"));
        assert_eq!(
            vulns_href("needs", "node 2", "a&b"),
            "/vulns?show=needs&node=node+2&q=a%26b"
        );
        assert_eq!(vulns_href("", "", ""), "/vulns");
    }
}
