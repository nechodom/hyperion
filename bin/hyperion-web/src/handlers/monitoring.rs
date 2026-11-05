//! /monitoring — cluster-wide list of every hosting with monitor
//! enabled, showing alert state, 24h success rate, avg latency,
//! and the node the hosting lives on. Fans out MonitorOverview
//! to the master + every enrolled worker and merges the rows.
//!
//! The URL checks (the master's own checks of addresses, kept by the agent)
//! are listed on the same page, above the hostings, so there is one place to
//! look. They exist only while the Docker module is on for the cluster; the
//! form that adds and changes them is `_url_monitors.html`.

use crate::auth::AuthCtx;
use crate::dispatcher::LOCAL_NODE_SENTINEL;
use crate::error::AppError;
use crate::state::SharedState;
use crate::url_watch::{derive_node, Derived};
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::url_monitor::{
    UrlMonitorInput, UrlMonitorView, URL_DEFAULT_ALERT_AFTER, URL_DEFAULT_INTERVAL_SECS,
    URL_MIN_INTERVAL_SECS,
};
use hyperion_types::MonitorOverviewItem;
use serde::Deserialize;

/// The master's own box has no outside vantage point. Said on the page, next
/// to the list and the form.
pub(crate) const MASTER_LIMITATION: &str = "Checks run from the master. An app on the \
     master's own box has no outside vantage point: when the master itself is down, so is the \
     check, and nothing says so.";

/// One URL check as the page draws it.
struct UrlRow {
    url: String,
    /// `alerting`, `unknown` or `ok`.
    state: &'static str,
    interval: String,
    expects: String,
    node: String,
    success: String,
    success_tone: &'static str,
    avg: String,
    last_error: Option<String>,
    last_probe: String,
    cert: Option<(String, &'static str)>,
    edit_href: String,
    delete_action: String,
}

/// A node the form can pin a check to.
struct NodeChoice {
    value: String,
    label: String,
}

/// The add / change form, as it is drawn (fresh, filled from a check, or
/// refilled after a refusal).
struct UrlForm {
    /// Hidden id; empty when adding.
    id: String,
    url: String,
    interval_secs: String,
    expected_status: String,
    alert_after_fails: String,
    alert_email: String,
    /// A Slack webhook / generic webhook is stored. Their addresses are
    /// never drawn, not even masked.
    slack_set: bool,
    webhook_set: bool,
    /// `auto`, `local` or an enrolled node id.
    node: String,
    nodes: Vec<NodeChoice>,
    /// The caller may set the webhooks (administrators only).
    channels_editable: bool,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "monitoring.html")]
struct MonitoringTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    items: Vec<MonitorOverviewItem>,
    alerting_count: usize,
    healthy_count: usize,
    unknown_count: usize,
    /// Set when a node's response failed authentication and its monitors
    /// were therefore discarded — the table below is INCOMPLETE. On an
    /// availability page especially, a silently missing node reads as
    /// "nothing is alerting".
    node_auth_warning: Option<String>,
    /// The Docker module is on and the caller may read the checks.
    show_urls: bool,
    can_manage_urls: bool,
    urls: Vec<UrlRow>,
    url_form: Option<UrlForm>,
    limitation: &'static str,
    flash: Option<&'static str>,
    flash_error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct MonitoringQuery {
    #[serde(default)]
    pub edit: Option<i64>,
    /// Anything: open the empty form.
    #[serde(default)]
    pub new: Option<String>,
    /// A known code, never text: `saved` or `deleted`.
    #[serde(default)]
    pub flash: Option<String>,
}

fn can_read_urls(ctx: &AuthCtx) -> bool {
    ctx.can(Capability::MonitoringView) && ctx.scope_all()
}

fn can_write_urls(ctx: &AuthCtx) -> bool {
    ctx.can(Capability::MonitoringManage) && ctx.scope_all()
}

pub async fn get_monitoring(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<MonitoringQuery>,
) -> Result<Response, AppError> {
    // Cluster-wide overview: it fans out across every node and lists EVERY
    // tenant's hostings (domain, node, health). The rows are not filtered by
    // per-hosting access, so a tenant-scoped role (operator/customer/viewer)
    // would enumerate other tenants' inventory here. Restrict to admin+;
    // tenant-scoped users still get per-hosting monitoring on each detail page.
    if !can_read_urls(&ctx) {
        return Ok(Redirect::to("/").into_response());
    }
    let flash = match q.flash.as_deref() {
        Some("saved") => Some("URL check saved."),
        Some("deleted") => Some("URL check deleted."),
        _ => None,
    };
    // The form is opened by a link; only someone who may save it gets one.
    let want_form = can_write_urls(&ctx) && (q.edit.is_some() || q.new.is_some());
    render_page(&state, &ctx, want_form.then_some(q.edit), None, flash, None).await
}

/// The page. `open_form` is `Some(None)` for an empty form, `Some(Some(id))`
/// to change a check; `refill` replaces the form's values after a refusal.
async fn render_page(
    state: &SharedState,
    ctx: &AuthCtx,
    open_form: Option<Option<i64>>,
    refill: Option<UrlForm>,
    flash: Option<&'static str>,
    flash_error: Option<String>,
) -> Result<Response, AppError> {
    let (mut items, failed) = collect_overview(state).await;
    let node_auth_warning = crate::handlers::node_auth_warning(&failed);

    // Resort the merged list — agents already sort their own slice,
    // but the merge needs to re-apply the alerting-first rule globally.
    items.sort_by(|a, b| {
        let alert_rank = |s: &str| match s {
            "alerting" => 0,
            "unknown" => 1,
            _ => 2,
        };
        let ra = alert_rank(a.alert_state.as_str());
        let rb = alert_rank(b.alert_state.as_str());
        ra.cmp(&rb)
            .then(a.success_pct_24h.cmp(&b.success_pct_24h))
            .then(a.domain.cmp(&b.domain))
    });

    let mut alerting_count = items.iter().filter(|i| i.alert_state == "alerting").count();
    let mut unknown_count = items.iter().filter(|i| i.alert_state == "unknown").count();
    let mut healthy_count = items.len() - alerting_count - unknown_count;

    let can_manage_urls = can_write_urls(ctx);
    let (show_urls, monitors) = fetch_urls(state).await;
    for m in &monitors {
        match m.alert_state.as_str() {
            "alerting" => alerting_count += 1,
            "unknown" => unknown_count += 1,
            _ => healthy_count += 1,
        }
    }
    let nodes = node_choices(state).await;
    let mut urls: Vec<UrlRow> = monitors.iter().map(|m| url_row(m, &nodes)).collect();
    // The ones that need a person first.
    urls.sort_by_key(|u| match u.state {
        "alerting" => 0,
        "unknown" => 1,
        _ => 2,
    });

    let url_form = if show_urls && can_manage_urls {
        match (refill, open_form) {
            (Some(f), _) => Some(f),
            (None, Some(None)) => Some(blank_form(nodes, ctx.is_admin_or_higher())),
            (None, Some(Some(id))) => monitors
                .iter()
                .find(|m| m.id == id)
                .map(|m| filled_form(m, nodes, ctx.is_admin_or_higher())),
            (None, None) => None,
        }
    } else {
        None
    };

    let tpl = MonitoringTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "monitoring",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(state, ctx),
        items,
        alerting_count,
        healthy_count,
        unknown_count,
        node_auth_warning,
        show_urls,
        can_manage_urls,
        urls,
        url_form,
        limitation: MASTER_LIMITATION,
        flash,
        flash_error,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Is the module on, and what are the checks? A refusal or a silent agent
/// reads as "no checks": the page is the hostings' page first.
async fn fetch_urls(state: &SharedState) -> (bool, Vec<UrlMonitorView>) {
    match crate::dispatcher::dispatch_to_node(state, None, Request::UrlMonitorList).await {
        Ok(RpcResponse::UrlMonitorList(l)) if l.enabled => (true, l.monitors),
        _ => (false, Vec::new()),
    }
}

/// Where a check can be pinned: the master and every enrolled node.
async fn node_choices(state: &SharedState) -> Vec<NodeChoice> {
    let mut v = vec![NodeChoice {
        value: LOCAL_NODE_SENTINEL.to_string(),
        label: "master".to_string(),
    }];
    for n in crate::handlers::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default()
    {
        v.push(NodeChoice {
            label: if n.label.is_empty() {
                n.node_id.clone()
            } else {
                n.label.clone()
            },
            value: n.node_id,
        });
    }
    v
}

fn node_label(nodes: &[NodeChoice], stored: &Option<String>) -> String {
    match stored.as_deref() {
        None => "no hosting".to_string(),
        Some(id) => nodes
            .iter()
            .find(|n| n.value == id)
            .map(|n| n.label.clone())
            // A node that is no longer enrolled: say so rather than hide it.
            .unwrap_or_else(|| id.to_string()),
    }
}

fn url_row(m: &UrlMonitorView, nodes: &[NodeChoice]) -> UrlRow {
    let state = match m.alert_state.as_str() {
        "alerting" => "alerting",
        "unknown" => "unknown",
        _ => "ok",
    };
    let (success, success_tone) = if m.samples_24h == 0 {
        ("—".to_string(), "")
    } else {
        (
            format!("{}%", m.success_pct_24h),
            match m.success_pct_24h {
                99..=100 => "var(--success)",
                95..=98 => "var(--warn)",
                _ => "var(--danger)",
            },
        )
    };
    let cert = m.cert_expires_at.map(|at| {
        let left = at - hyperion_types::now_secs();
        let days = left.div_euclid(86_400);
        if left <= 0 {
            ("certificate expired".to_string(), "err")
        } else if days < 3 {
            (format!("certificate: {days} d left"), "err")
        } else if days < 14 {
            (format!("certificate: {days} d left"), "warn")
        } else {
            (format!("certificate: {days} d left"), "")
        }
    });
    UrlRow {
        url: m.url.clone(),
        state,
        interval: format!("every {}", fmt_secs(m.interval_secs)),
        expects: m
            .expected_status
            .map(|s| format!("expects {s}"))
            .unwrap_or_else(|| "expects 2xx/3xx".to_string()),
        node: node_label(nodes, &m.node_id),
        success,
        success_tone,
        avg: if m.avg_ms_24h == 0 {
            "—".into()
        } else {
            format!("{} ms", m.avg_ms_24h)
        },
        last_error: (state == "alerting")
            .then(|| m.last_error.clone())
            .flatten(),
        last_probe: crate::handlers::stats::fmt_ago(&m.last_sampled_at),
        cert,
        edit_href: format!("/monitoring?edit={}#url-form", m.id),
        delete_action: format!("/monitoring/urls/{}/delete", m.id),
    }
}

fn fmt_secs(s: i64) -> String {
    if s % 3600 == 0 {
        format!("{} h", s / 3600)
    } else if s % 60 == 0 {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}

fn blank_form(nodes: Vec<NodeChoice>, admin: bool) -> UrlForm {
    UrlForm {
        id: String::new(),
        url: String::new(),
        interval_secs: URL_DEFAULT_INTERVAL_SECS.to_string(),
        expected_status: String::new(),
        alert_after_fails: URL_DEFAULT_ALERT_AFTER.to_string(),
        alert_email: String::new(),
        slack_set: false,
        webhook_set: false,
        node: "auto".to_string(),
        nodes,
        channels_editable: admin,
        error: None,
    }
}

fn filled_form(m: &UrlMonitorView, nodes: Vec<NodeChoice>, admin: bool) -> UrlForm {
    UrlForm {
        id: m.id.to_string(),
        url: m.url.clone(),
        interval_secs: m.interval_secs.to_string(),
        expected_status: m.expected_status.map(|s| s.to_string()).unwrap_or_default(),
        alert_after_fails: m.alert_after_fails.to_string(),
        alert_email: m.alert_email.clone(),
        slack_set: m.alert_slack_set,
        webhook_set: m.alert_webhook_set,
        node: if m.node_manual {
            m.node_id.clone().unwrap_or_else(|| "none".to_string())
        } else {
            "auto".to_string()
        },
        nodes,
        channels_editable: admin,
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Saving and deleting
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct UrlFormBody {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub interval_secs: String,
    #[serde(default)]
    pub expected_status: String,
    #[serde(default)]
    pub alert_after_fails: String,
    #[serde(default)]
    pub alert_email: String,
    #[serde(default)]
    pub alert_slack_webhook: String,
    #[serde(default)]
    pub clear_slack_webhook: Option<String>,
    #[serde(default)]
    pub alert_webhook_url: String,
    #[serde(default)]
    pub clear_webhook_url: Option<String>,
    /// `auto`, `none`, `local` or an enrolled node id.
    #[serde(default)]
    pub node: String,
}

/// Write access, and the reason when it is missing.
fn require_write(ctx: &AuthCtx) -> Result<(), AppError> {
    if can_write_urls(ctx) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// POST /monitoring/urls — add a check, or change the one in `id`.
pub async fn post_url_save(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(f): Form<UrlFormBody>,
) -> Result<Response, AppError> {
    require_write(&ctx)?;
    let admin = ctx.is_admin_or_higher();
    let (enabled, monitors) = fetch_urls(&state).await;
    let nodes = node_choices(&state).await;

    let existing =
        f.id.trim()
            .parse::<i64>()
            .ok()
            .and_then(|id| monitors.iter().find(|m| m.id == id));
    let refuse = |msg: &str, nodes: Vec<NodeChoice>| UrlForm {
        id: f.id.trim().to_string(),
        url: f.url.trim().to_string(),
        interval_secs: f.interval_secs.trim().to_string(),
        expected_status: f.expected_status.trim().to_string(),
        alert_after_fails: f.alert_after_fails.trim().to_string(),
        alert_email: f.alert_email.trim().to_string(),
        slack_set: existing.is_some_and(|m| m.alert_slack_set),
        webhook_set: existing.is_some_and(|m| m.alert_webhook_set),
        node: f.node.clone(),
        nodes,
        channels_editable: admin,
        error: Some(msg.to_string()),
    };
    let rerender = |form: UrlForm| async {
        let msg = form.error.clone();
        render_page(&state, &ctx, Some(None), Some(form), None, msg).await
    };

    if !enabled {
        return rerender(refuse(
            "URL checks belong to the Docker module. Turn the Docker module on first.",
            nodes,
        ))
        .await;
    }
    if !f.id.trim().is_empty() && existing.is_none() {
        return rerender(refuse("That URL check no longer exists.", nodes)).await;
    }
    let number = |raw: &str, what: &str, default: Option<i64>| -> Result<Option<i64>, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(default);
        }
        raw.parse::<i64>()
            .map(Some)
            .map_err(|_| format!("{what} must be a whole number"))
    };
    let parsed = (|| -> Result<(i64, Option<i64>, i64), String> {
        let interval = number(
            &f.interval_secs,
            "The interval",
            Some(URL_DEFAULT_INTERVAL_SECS),
        )?;
        let expected = number(&f.expected_status, "The expected status", None)?;
        let after = number(
            &f.alert_after_fails,
            "Alert after",
            Some(URL_DEFAULT_ALERT_AFTER),
        )?;
        Ok((
            interval.unwrap_or(URL_DEFAULT_INTERVAL_SECS),
            expected,
            after.unwrap_or(URL_DEFAULT_ALERT_AFTER),
        ))
    })();
    let (interval_secs, expected_status, alert_after_fails) = match parsed {
        Ok(p) => p,
        Err(m) => return rerender(refuse(&m, nodes)).await,
    };
    if interval_secs < URL_MIN_INTERVAL_SECS {
        return rerender(refuse(
            &format!("The interval must be at least {URL_MIN_INTERVAL_SECS} seconds."),
            nodes,
        ))
        .await;
    }

    // Who owns the address: asked live unless the operator said.
    let url = f.url.trim().to_string();
    let (node_id, node_manual) = match f.node.trim() {
        "" | "auto" => match derive_node(&state, &url).await {
            Derived::Node(n) => (n, false),
            // A node that did not answer cannot disown its domain: keep what
            // was stored.
            Derived::Unknown => (existing.and_then(|m| m.node_id.clone()), false),
        },
        "none" => (None, true),
        chosen => {
            if !nodes.iter().any(|n| n.value == chosen) {
                return rerender(refuse("That node is not enrolled.", nodes)).await;
            }
            (Some(chosen.to_string()), true)
        }
    };

    let input = UrlMonitorInput {
        id: existing.map(|m| m.id),
        url,
        interval_secs,
        expected_status,
        alert_after_fails,
        alert_email: Some(f.alert_email.trim().to_string()).filter(|e| !e.is_empty()),
        // Webhooks are administrators' input. Anyone else's fields are
        // ignored and the stored ones kept.
        alert_slack_webhook: admin.then(|| f.alert_slack_webhook.trim().to_string()),
        clear_slack_webhook: admin && f.clear_slack_webhook.is_some(),
        alert_webhook_url: admin.then(|| f.alert_webhook_url.trim().to_string()),
        clear_webhook_url: admin && f.clear_webhook_url.is_some(),
        node_id,
        node_manual,
        actor: ctx.username.clone(),
    };
    match crate::dispatcher::dispatch_to_node(&state, None, Request::UrlMonitorSet(input)).await {
        Ok(RpcResponse::UrlMonitorSet { .. }) => {
            state.caches.nav_dots.invalidate();
            Ok(Redirect::to("/monitoring?flash=saved").into_response())
        }
        Ok(RpcResponse::Error(e)) => rerender(refuse(&refusal_text(&e), nodes)).await,
        Ok(_) => Err(AppError::Internal("unexpected agent response".into())),
        Err(e) => Err(e.into()),
    }
}

/// What the agent refused, as the operator should read it. Validation texts
/// are written for them already; anything else is a fault of ours.
fn refusal_text(e: &hyperion_rpc::error::RpcError) -> String {
    match e {
        hyperion_rpc::error::RpcError::Validation { message } => message.clone(),
        hyperion_rpc::error::RpcError::NotFound { .. } => "That URL check no longer exists.".into(),
        _ => "The agent could not save the check. See its log.".into(),
    }
}

/// POST /monitoring/urls/:id/delete
pub async fn post_url_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    require_write(&ctx)?;
    let actor = ctx.username.clone();
    match crate::dispatcher::dispatch_to_node(&state, None, Request::UrlMonitorDelete { id, actor })
        .await
    {
        Ok(RpcResponse::UrlMonitorDeleted) => {
            state.caches.nav_dots.invalidate();
            Ok(Redirect::to("/monitoring?flash=deleted").into_response())
        }
        Ok(RpcResponse::Error(e)) => Err(AppError::Rpc(e.to_string())),
        Ok(_) => Err(AppError::Internal("unexpected agent response".into())),
        Err(e) => Err(e.into()),
    }
}

/// How many URL checks are alerting, for the sidebar dot. Zero while the
/// module is off, for a caller who may not read them, or when the agent does
/// not answer.
pub(crate) async fn urls_alerting(state: &SharedState) -> usize {
    fetch_urls(state)
        .await
        .1
        .iter()
        .filter(|m| m.alert_state == "alerting")
        .count()
}

/// `MonitorOverview` from the master and every enrolled worker, merged, plus
/// the workers that dropped out. Master rows carry the LOCAL sentinel and
/// worker rows the enrolled `node_id`. Shared with the sidebar's monitoring
/// dot, which must count the same sites this page lists.
pub(crate) async fn collect_overview(
    state: &SharedState,
) -> (
    Vec<MonitorOverviewItem>,
    Vec<(
        hyperion_types::NodeSummary,
        crate::dispatcher::DispatchError,
    )>,
) {
    let mut items: Vec<MonitorOverviewItem> = Vec::new();

    // Master local.
    if let Ok(RpcResponse::MonitorOverview(rows)) =
        crate::dispatcher::dispatch_to_node(state, None, Request::MonitorOverview).await
    {
        let mut rows = rows;
        for r in &mut rows {
            // Rows from the master local socket are local regardless of
            // the node_id they stored — master rows stamp the hostname
            // (e.g. "s4"), not empty. Tag them all with the LOCAL
            // sentinel unconditionally (the old is_empty() guard left
            // "s4" in place, which becomes the 400 "node s4 is not
            // enrolled" the moment a monitor action form reuses it).
            r.node_id = crate::dispatcher::LOCAL_NODE_SENTINEL.to_string();
        }
        items.extend(rows);
    }

    // Every enrolled worker. Goes through the shared fan-out helper (not a
    // hand-rolled `if let Ok(..)` loop) so a node is queried concurrently AND
    // a dropped node is logged + reportable — the old loop swallowed a failed
    // response signature with no trace at all.
    let workers = crate::handlers::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default();
    let (answered, failed) =
        crate::dispatcher::fan_out_reporting(state, workers, Request::MonitorOverview).await;
    for (n, resp) in answered {
        if let RpcResponse::MonitorOverview(mut rows) = resp {
            for r in &mut rows {
                r.node_id = n.node_id.clone();
            }
            items.extend(rows);
        }
    }
    (items, failed)
}
