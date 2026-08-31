//! `/stats` — cluster, per-node, and overall stats page.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{ClusterStats, NodeMetricsHistory, NodeStats};
use serde::Deserialize;

/// Inline-SVG sparkline derived from a metric series. The template
/// pastes `path_d` directly into an SVG `<path d="...">` element AND
/// exposes `points_json` on the SVG as `data-points` so the
/// interactive-chart JS in base.html can render hover tooltips.
#[derive(Debug, Clone)]
pub struct Sparkline {
    /// SVG path data — single polyline from (0,h) → (w,h) baseline.
    pub path_d: String,
    /// Path for the area fill below the line (closed polygon).
    pub area_d: String,
    /// Latest sample value, formatted for display ("1.42", "73%", etc.)
    pub latest_label: String,
    /// Peak value seen in the window ("1.8 max").
    pub peak_label: String,
    /// Average value across the window.
    pub avg_label: String,
    /// "load" | "mem" | "bw" | "reqs" — drives the colour class in CSS.
    pub kind: &'static str,
    /// Whether we had enough data for a meaningful chart (≥2 samples).
    pub has_data: bool,
    /// JSON-serialized list of `{x, y, v, t}` for every sample, in
    /// viewBox coordinates. JS uses this to locate the nearest point
    /// on mousemove and pop a tooltip. `v` is the formatted value
    /// label, `t` is the formatted time label. Empty when has_data
    /// is false; the JS no-ops in that case.
    pub points_json: String,
}

/// One line of the per-site breakdown table.
///
/// [`hyperion_types::HostingStats`] carries no `node_id` — attribution
/// comes from *which node answered* — so the node's display label is
/// stapled on here as the rows are collected.
#[derive(Debug, Clone)]
pub struct SiteRow {
    pub hosting_id: String,
    pub domain: String,
    /// Display label of the node this site lives on. Only rendered in
    /// the cluster view; in a single-node view the column is dropped.
    pub node_label: String,
    pub cpu_pct_x100: i64,
    pub mem_rss_bytes: i64,
    pub disk_bytes: i64,
    /// `bw_in + bw_out` over the last 24 h — what the Traffic column sorts on.
    pub bw_bytes_24h: i64,
    pub bw_in_bytes_24h: i64,
    pub bw_out_bytes_24h: i64,
    pub requests_24h: i64,
    pub sampled_at: i64,
    /// False when the sampler has not written a usage row for this site
    /// yet. The row still renders, with zeros — "not measured yet" is not
    /// an error, and dropping the row would make a fresh site look missing.
    pub has_samples: bool,
    /// Width % of the share bar drawn in the ACTIVE sort column, relative
    /// to the heaviest row. 0 when that column is all zeros (or when
    /// sorting by domain, where a bar would mean nothing).
    pub bar_pct: i64,
}

#[derive(Template)]
#[template(path = "stats.html")]
struct StatsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    cluster: Option<ClusterStats>,
    /// Σ of every node's local backup archives, and how many. Kept out of
    /// ClusterStats because it is a property of the BOX, not of the sites
    /// it hosts — the two disk figures above deliberately exclude it.
    backup_bytes_total: i64,
    backup_count_total: i64,
    /// The node selected via `?node=<id>`; defaults to the first node
    /// when the cluster has any. None means "no nodes yet".
    selected_node: Option<NodeStats>,
    /// Inline sparkline data for the selected node.
    spark_load: Sparkline,
    spark_mem: Sparkline,
    spark_bw: Sparkline,
    spark_reqs: Sparkline,
    /// Sample window size used for sparklines (oldest..=newest).
    samples_in_window: usize,
    /// How many minutes the sparkline window covers, for the legend.
    window_minutes: i64,
    error: Option<String>,
    /// All enrolled remote nodes — drives the "View on node:"
    /// switcher in the page header. Empty on single-node setups.
    all_nodes: Vec<hyperion_types::NodeSummary>,
    /// Echoes `query.node` so the switcher highlights the
    /// currently-displayed node.
    current_node: String,
    /// Human-friendly label of the displayed node ("master" / node label).
    current_label: String,
    /// Set when a node's response failed authentication and its stats were
    /// therefore discarded — the cluster totals below UNDERCOUNT.
    node_auth_warning: Option<String>,
    /// Per-site breakdown — "which site is eating the box?". Already
    /// sorted heaviest-first by `sort`.
    sites: Vec<SiteRow>,
    /// Canonical sort key echoed back so the column headers can mark the
    /// active one. One of disk|cpu|ram|traffic|requests|domain.
    sort: &'static str,
    /// True in the cluster view only — the Node column is dead weight
    /// when every row belongs to the same node.
    show_node_col: bool,
    /// Column totals, so each cell can show its share via `fmt_percent`
    /// and the table can foot with a Σ row.
    sites_total_cpu_x100: i64,
    sites_total_mem: i64,
    sites_total_disk: i64,
    sites_total_bw: i64,
    sites_total_reqs: i64,
}

#[derive(Deserialize, Default)]
pub struct StatsQuery {
    #[serde(default)]
    node: String,
    /// Per-site table sort column. Server-side on purpose: the table
    /// lives inside the 30 s live-refresh region, and client-side sorting
    /// would be undone by every swap.
    #[serde(default)]
    sort: String,
}

pub async fn get_stats(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(query): Query<StatsQuery>,
) -> Result<Response, AppError> {
    // Cluster/node-aggregate stats expose every tenant's resource usage, so
    // gate on MonitoringView + all-hostings scope (admin-equivalent). Tenant
    // roles see their own usage on each hosting's detail page instead.
    if !(ctx.can(Capability::MonitoringView) && ctx.scope_all()) {
        return Ok(axum::response::Redirect::to("/").into_response());
    }
    // View mode:
    //   - empty / "cluster" → AGGREGATE across master + all enrolled nodes
    //   - "local"           → master local only
    //   - "<node_id>"       → single-node view via signed RPC
    //
    // The cluster default makes /stats with no params show the
    // multi-node overview, which is what most operators want first.
    // To see just the master's view they pick "master only".
    let is_cluster_view = query.node.is_empty() || query.node == "cluster";
    let target_owned = query.node.clone();
    let target = if is_cluster_view || target_owned == crate::dispatcher::LOCAL_NODE_SENTINEL {
        None
    } else {
        Some(target_owned.as_str())
    };

    // Always fetch the list of enrolled nodes from the master.
    let all_nodes = match hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(),
    };

    // Cluster aggregate: fetch ClusterStats from master + every
    // enrolled node in parallel, sum the totals, concatenate the
    // nodes arrays. Single-node mode just hits one agent.
    let (cluster, mut error, node_auth_warning) = if is_cluster_view {
        let agg = aggregate_cluster_stats(&state, &all_nodes).await;
        match agg {
            Ok((c, warning)) => (Some(c), None, warning),
            Err(e) => (None, Some(e), None),
        }
    } else {
        let cluster_res =
            crate::dispatcher::dispatch_to_node(&state, target, Request::ClusterStats).await;
        match cluster_res {
            Ok(RpcResponse::ClusterStats(mut c)) => {
                // The agent fills NodeStats.node_id with its own hostname.
                // Rewrite it to the dispatch target (LOCAL sentinel for
                // master, else the enrolled id) — mirrors
                // aggregate_cluster_stats. Without this the node-switcher
                // tabs link to ?node=<hostname>, which 400s with "node
                // <hostname> is not enrolled", and selected_node (compared
                // against query.node = "local"/enrolled id) never matches,
                // so the master view loses its load/memory cards.
                let id = target
                    .unwrap_or(crate::dispatcher::LOCAL_NODE_SENTINEL)
                    .to_string();
                for n in &mut c.nodes {
                    n.node_id = id.clone();
                }
                (Some(c), None, None)
            }
            Ok(RpcResponse::Error(e)) => (None, Some(e.to_string()), None),
            Ok(_) => (None, Some("unexpected agent response".into()), None),
            // Single-node view: DispatchError's own Display already spells
            // out "response failed authentication", and it lands in the
            // page's error banner, so there is nothing to add here.
            Err(e) => (None, Some(e.to_string()), None),
        }
    };

    let current_label = if is_cluster_view {
        "cluster (all nodes)".to_string()
    } else {
        label_for_node(&query.node, &all_nodes)
    };

    // History (sparklines) is per-node: in cluster mode we pull
    // master's history as a representative — sparklines for "the
    // cluster" don't have a single agent-level meaning. Operators
    // who want a node-specific history switch the dropdown.
    let history_target = if is_cluster_view { None } else { target };
    // The per-site breakdown is its own fan-out round. Run it CONCURRENTLY
    // with the history fetch — serialising a third cluster-wide round trip
    // would add a whole RPC latency to every /stats load on a multi-node
    // setup, and the two answers don't depend on each other.
    let (history_res, (mut sites, sites_auth_warning)) = tokio::join!(
        crate::dispatcher::dispatch_to_node(
            &state,
            history_target,
            Request::NodeMetricsHistory { limit: 48 },
        ),
        collect_site_rows(&state, target, is_cluster_view, &all_nodes, &current_label),
    );

    // A node whose sites were discarded for a bad signature must be
    // reported even if the ClusterStats round happened to authenticate.
    let node_auth_warning = node_auth_warning.or(sites_auth_warning);

    let sort = normalize_site_sort(&query.sort);
    sort_site_rows(&mut sites, sort);
    let sites_total_cpu_x100 = sites.iter().map(|r| r.cpu_pct_x100).sum();
    let sites_total_mem = sites.iter().map(|r| r.mem_rss_bytes).sum();
    let sites_total_disk = sites.iter().map(|r| r.disk_bytes).sum();
    let sites_total_bw = sites.iter().map(|r| r.bw_bytes_24h).sum();
    let sites_total_reqs = sites.iter().map(|r| r.requests_24h).sum();

    let history: NodeMetricsHistory = match history_res {
        Ok(RpcResponse::NodeMetricsHistory(h)) => h,
        Ok(RpcResponse::Error(e)) => {
            if error.is_none() {
                error = Some(format!("history: {e}"));
            }
            NodeMetricsHistory::default()
        }
        _ => NodeMetricsHistory::default(),
    };

    let selected_node = cluster.as_ref().and_then(|c| {
        if !query.node.is_empty() {
            c.nodes.iter().find(|n| n.node_id == query.node).cloned()
        } else {
            c.nodes.first().cloned()
        }
    });

    let samples_in_window = history.samples.len();
    let window_minutes = if samples_in_window >= 2 {
        let first = history.samples.first().map(|s| s.at).unwrap_or(0);
        let last = history.samples.last().map(|s| s.at).unwrap_or(0);
        ((last - first) / 60).max(0)
    } else {
        0
    };

    let spark_load = build_sparkline(
        history
            .samples
            .iter()
            .map(|s| (s.at, s.loadavg_1m_x100 as f64 / 100.0)),
        "load",
        |v| format!("{v:.2}"),
    );
    let spark_mem = build_sparkline(
        history.samples.iter().map(|s| {
            let pct = if s.mem_total_kib > 0 {
                (s.mem_used_kib as f64 / s.mem_total_kib as f64) * 100.0
            } else {
                0.0
            };
            (s.at, pct)
        }),
        "mem",
        |v| format!("{:.0}%", v),
    );
    let spark_bw = build_sparkline(
        history
            .samples
            .iter()
            .map(|s| (s.at, s.total_bw_out_24h as f64)),
        "bw",
        |v| fmt_bytes(&(v as i64)),
    );
    let spark_reqs = build_sparkline(
        history
            .samples
            .iter()
            .map(|s| (s.at, s.total_requests_24h as f64)),
        "reqs",
        |v| format!("{}", v as i64),
    );

    let tpl = StatsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "stats",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        // Sum across whatever nodes answered — an unreachable node
        // contributes 0 rather than making the whole figure unavailable.
        backup_bytes_total: cluster
            .as_ref()
            .map(|c| c.nodes.iter().map(|n| n.backup_bytes).sum())
            .unwrap_or(0),
        backup_count_total: cluster
            .as_ref()
            .map(|c| c.nodes.iter().map(|n| n.backup_count).sum())
            .unwrap_or(0),
        cluster,
        selected_node,
        spark_load,
        spark_mem,
        spark_bw,
        spark_reqs,
        samples_in_window,
        window_minutes,
        error,
        all_nodes,
        current_node: query.node.clone(),
        current_label,
        node_auth_warning,
        sites,
        sort,
        show_node_col: is_cluster_view,
        sites_total_cpu_x100,
        sites_total_mem,
        sites_total_disk,
        sites_total_bw,
        sites_total_reqs,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Collect the per-site breakdown for the current view.
///
/// Mirrors the node switcher exactly: a specific node gets exactly that
/// node's sites, the cluster view fans out over master + every enrolled
/// node. Returns the rows plus the banner text for any node whose
/// response failed AUTHENTICATION — those sites are missing from the
/// table, and a short table must never read as "the sites are gone".
async fn collect_site_rows(
    state: &SharedState,
    target: Option<&str>,
    is_cluster_view: bool,
    all_nodes: &[hyperion_types::NodeSummary],
    single_node_label: &str,
) -> (Vec<SiteRow>, Option<String>) {
    let mut rows: Vec<SiteRow> = Vec::new();
    if !is_cluster_view {
        // Single node: one dispatch. A failure here is already spelled out
        // by the ClusterStats round's error banner, so stay quiet.
        if let Ok(RpcResponse::HostingStatsAll(v)) =
            crate::dispatcher::dispatch_to_node(state, target, Request::HostingStatsAll).await
        {
            push_site_rows(&mut rows, v, single_node_label);
        }
        return (rows, None);
    }

    // Master first, then every enrolled node through the shared fan-out.
    if let Ok(RpcResponse::HostingStatsAll(v)) =
        crate::dispatcher::dispatch_to_node(state, None, Request::HostingStatsAll).await
    {
        // Just "master" — this label sits in a per-row tag in a table that
        // is already tight on width; the long form belongs in the node
        // switcher and the node detail card, not on every line.
        push_site_rows(&mut rows, v, "master");
    }
    let (answered, failed) =
        crate::dispatcher::fan_out_reporting(state, all_nodes.to_vec(), Request::HostingStatsAll)
            .await;
    for (n, resp) in answered {
        if let RpcResponse::HostingStatsAll(v) = resp {
            let label = if n.label.is_empty() {
                n.node_id.clone()
            } else {
                n.label.clone()
            };
            push_site_rows(&mut rows, v, &label);
        }
    }
    (rows, crate::handlers::node_auth_warning(&failed))
}

/// Convert one node's `HostingStats` batch into table rows, stamping the
/// node label the answer arrived from.
fn push_site_rows(out: &mut Vec<SiteRow>, stats: Vec<hyperion_types::HostingStats>, node: &str) {
    out.extend(stats.into_iter().map(|s| SiteRow {
        hosting_id: s.hosting_id.0,
        domain: s.domain,
        node_label: node.to_string(),
        cpu_pct_x100: s.cpu_pct_x100,
        mem_rss_bytes: s.mem_rss_bytes,
        disk_bytes: s.disk_bytes,
        bw_bytes_24h: s.bw_in_bytes_24h.saturating_add(s.bw_out_bytes_24h),
        bw_in_bytes_24h: s.bw_in_bytes_24h,
        bw_out_bytes_24h: s.bw_out_bytes_24h,
        requests_24h: s.requests_24h,
        sampled_at: s.sampled_at,
        has_samples: s.last_request_at.is_some(),
        bar_pct: 0,
    }));
}

/// Map `?sort=` onto a canonical column key. Anything unrecognised
/// (including the empty default) falls back to **disk**: it is the one
/// column populated for every site from the first `du` sweep, so the
/// default ordering is meaningful even before the CPU/RSS sampler has
/// ticked.
pub fn normalize_site_sort(s: &str) -> &'static str {
    match s {
        "cpu" => "cpu",
        "ram" | "mem" => "ram",
        "traffic" | "bw" => "traffic",
        "requests" | "reqs" => "requests",
        "domain" | "site" => "domain",
        _ => "disk",
    }
}

/// The numeric value the given column sorts on. `domain` has none.
fn site_sort_key(r: &SiteRow, sort: &str) -> i64 {
    match sort {
        "cpu" => r.cpu_pct_x100,
        "ram" => r.mem_rss_bytes,
        "traffic" => r.bw_bytes_24h,
        "requests" => r.requests_24h,
        _ => r.disk_bytes,
    }
}

/// Sort heaviest-first on `sort` (A→Z for `domain`) and fill in `bar_pct`
/// for the active column, scaled against the heaviest row so the top site
/// reads as a full bar.
pub fn sort_site_rows(rows: &mut [SiteRow], sort: &str) {
    if sort == "domain" {
        rows.sort_by(|a, b| a.domain.cmp(&b.domain));
        for r in rows.iter_mut() {
            r.bar_pct = 0;
        }
        return;
    }
    // Domain is the tie-break so equal-usage rows (very common: a shelf of
    // idle sites all at 0 CPU) keep a stable, alphabetical order instead of
    // reshuffling on every 30 s live refresh.
    rows.sort_by(|a, b| {
        site_sort_key(b, sort)
            .cmp(&site_sort_key(a, sort))
            .then_with(|| a.domain.cmp(&b.domain))
    });
    let max = rows
        .iter()
        .map(|r| site_sort_key(r, sort))
        .max()
        .unwrap_or(0);
    for r in rows.iter_mut() {
        r.bar_pct = if max > 0 {
            (site_sort_key(r, sort).saturating_mul(100) / max).clamp(0, 100)
        } else {
            0
        };
    }
}

/// Build a synthetic cluster-wide ClusterStats by fan-out:
///   - master local socket
///   - signed RPC to every enrolled node
/// Sums the numeric totals, concatenates per-node arrays.
/// Failing fetches are logged + skipped — partial answers are
/// better than no answer.
///
/// Also returns the banner text for any node whose response failed
/// AUTHENTICATION. Those nodes get no placeholder row: an `agent_online:
/// false` line would file a possible forgery under "the worker is down",
/// which is the one reading the operator must not take away.
async fn aggregate_cluster_stats(
    state: &SharedState,
    nodes: &[hyperion_types::NodeSummary],
) -> Result<(ClusterStats, Option<String>), String> {
    let mut total = ClusterStats::default();

    // Master local. We rewrite the returned NodeStats's node_id
    // to the "local" sentinel so the template's per-node tab links
    // (?node=<n.node_id>) route back through dispatch_to_node
    // correctly. Without this rewrite the master's tab would link
    // to ?node=s4 (the hostname), and the dispatcher — which only
    // knows about ENROLLED nodes — would error out with
    // "target node s4 is not enrolled".
    match crate::dispatcher::dispatch_to_node(state, None, Request::ClusterStats).await {
        Ok(RpcResponse::ClusterStats(mut c)) => {
            for n in &mut c.nodes {
                n.node_id = crate::dispatcher::LOCAL_NODE_SENTINEL.to_string();
                if n.label.is_empty() {
                    n.label = "master (this node)".to_string();
                }
            }
            merge_cluster(&mut total, &c);
        }
        Ok(RpcResponse::Error(e)) => {
            tracing::warn!(error=%e, "cluster aggregate: master fetch errored");
        }
        Err(e) => {
            tracing::warn!(error=%e, "cluster aggregate: master fetch unreachable");
        }
        _ => {}
    }

    // Every enrolled node, through the shared concurrent fan-out helper.
    // Same helper as every other aggregate page: it logs an excluded node
    // and hands back WHY, so a response that failed authentication stops
    // being indistinguishable from a quiet worker.
    let (answered, failed) =
        crate::dispatcher::fan_out_reporting(state, nodes.to_vec(), Request::ClusterStats).await;
    for (n, resp) in answered {
        match resp {
            RpcResponse::ClusterStats(mut c) => {
                // Same node_id rewrite as for master — the worker
                // returns its OWN hostname-based node_id, but the
                // master's dispatcher only knows the enrolled id.
                // Rewrite so per-node tab links route correctly.
                for row in &mut c.nodes {
                    row.node_id = n.node_id.clone();
                }
                merge_cluster(&mut total, &c);
            }
            RpcResponse::Error(e) => {
                tracing::warn!(node=%n.node_id, error=%e, "cluster aggregate: remote fetch errored");
                // Surface as a placeholder NodeStats so the operator
                // sees "this node didn't answer" instead of just
                // missing from the table.
                total.nodes.push(offline_placeholder(&n.node_id));
            }
            _ => {}
        }
    }
    for (n, e) in &failed {
        // Downtime keeps its "agent offline" placeholder row. A response
        // that failed AUTHENTICATION does not get one — see this
        // function's doc comment — the banner tells that story instead.
        if !matches!(
            e,
            crate::dispatcher::DispatchError::ResponseAuthFailed { .. }
        ) {
            total.nodes.push(offline_placeholder(&n.node_id));
        }
    }
    Ok((total, crate::handlers::node_auth_warning(&failed)))
}

/// A zeroed `NodeStats` row for a node that didn't answer, so the node
/// table shows "agent offline" instead of quietly losing the row.
fn offline_placeholder(node_id: &str) -> hyperion_types::NodeStats {
    hyperion_types::NodeStats {
        backup_bytes: 0,
        backup_count: 0,
        node_id: node_id.to_string(),
        label: node_id.to_string(),
        hostings_count: 0,
        hostings_active: 0,
        hostings_suspended: 0,
        hostings_failed: 0,
        total_disk_bytes: 0,
        hostings_disk_bytes: 0,
        node_disk_total_bytes: 0,
        total_bw_out_24h: 0,
        total_requests_24h: 0,
        loadavg_1m_x100: 0,
        mem_total_kib: 0,
        mem_used_kib: 0,
        uptime_secs: 0,
        sampled_at: 0,
        agent_version: String::new(),
        agent_online: false,
        cpu_pct_x100: 0,
        swap_total_kib: 0,
        swap_used_kib: 0,
        psi_cpu_x100: 0,
        psi_mem_x100: 0,
        psi_io_x100: 0,
        net_rx_bps: 0,
        net_tx_bps: 0,
        oom_kills_24h: 0,
        last_oom_at: 0,
    }
}

/// Add `src`'s totals into `dst` and append its nodes array.
fn merge_cluster(dst: &mut ClusterStats, src: &ClusterStats) {
    dst.total_hostings += src.total_hostings;
    dst.total_active += src.total_active;
    dst.total_suspended += src.total_suspended;
    dst.total_failed += src.total_failed;
    dst.total_disk_bytes += src.total_disk_bytes;
    dst.total_hostings_disk_bytes += src.total_hostings_disk_bytes;
    dst.total_node_disk_total_bytes += src.total_node_disk_total_bytes;
    dst.total_bw_out_24h += src.total_bw_out_24h;
    dst.total_requests_24h += src.total_requests_24h;
    dst.nodes.extend(src.nodes.iter().cloned());
}

fn label_for_node(current: &str, nodes: &[hyperion_types::NodeSummary]) -> String {
    if current.is_empty() || current == crate::dispatcher::LOCAL_NODE_SENTINEL {
        return "master (this node)".to_string();
    }
    nodes
        .iter()
        .find(|n| n.node_id == current)
        .map(|n| match n.public_ip.as_deref() {
            Some(ip) if !ip.is_empty() => format!("{} ({})", n.label, ip),
            _ => n.label.clone(),
        })
        .unwrap_or_else(|| current.to_string())
}

/// Generate an SVG path + per-point JSON for hover tooltips. Callers
/// pass `(timestamp_unix, value)` pairs so the tooltip can show the
/// real time bucket instead of just an index.
pub fn build_sparkline<I, F>(points: I, kind: &'static str, fmt: F) -> Sparkline
where
    I: IntoIterator<Item = (i64, f64)>,
    F: Fn(f64) -> String,
{
    const W: f64 = 600.0;
    const H: f64 = 60.0;
    const PAD: f64 = 4.0;

    let pts: Vec<(i64, f64)> = points.into_iter().collect();
    if pts.len() < 2 {
        return Sparkline {
            path_d: String::new(),
            area_d: String::new(),
            latest_label: "—".into(),
            peak_label: "—".into(),
            avg_label: "—".into(),
            kind,
            has_data: false,
            points_json: "[]".into(),
        };
    }
    let values: Vec<f64> = pts.iter().map(|(_, v)| *v).collect();
    let max = values
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max)
        .max(0.0);
    // Zero-base the y-axis. These series are all non-negative magnitudes
    // (load, memory %, requests, bandwidth, response time), so anchoring at 0
    // shows the TRUE size of each change. Auto-scaling to the series minimum
    // made a 71%→73% memory wobble fill the whole chart and look alarming.
    let min = 0.0_f64;
    let range = (max - min).max(1e-9);
    let n = pts.len() as f64;
    let dx = W / (n - 1.0);

    let mut path = String::with_capacity(pts.len() * 16);
    // Build the points_json on the same pass so they share coords.
    let mut pj: Vec<String> = Vec::with_capacity(pts.len());
    for (i, (ts, v)) in pts.iter().enumerate() {
        let x = i as f64 * dx;
        let norm = (*v - min) / range;
        let y = PAD + (1.0 - norm) * (H - 2.0 * PAD);
        if i == 0 {
            path.push_str(&format!("M{x:.1},{y:.1}"));
        } else {
            path.push_str(&format!(" L{x:.1},{y:.1}"));
        }
        // Escape the value label for JSON — it's already operator-
        // generated text but may contain quotes (unlikely) or
        // backslashes (also unlikely). serde_json handles it cleanly.
        let v_label = fmt(*v);
        let t_label = fmt_time_label(*ts);
        pj.push(format!(
            "{{\"x\":{:.1},\"y\":{:.1},\"v\":{},\"t\":{}}}",
            x,
            y,
            json_str(&v_label),
            json_str(&t_label),
        ));
    }
    let area = format!("{path} L{:.1},{H} L0,{H} Z", W);
    let points_json = format!("[{}]", pj.join(","));

    let latest = *values.last().unwrap_or(&0.0);
    let sum: f64 = values.iter().sum();
    let avg = sum / n;
    Sparkline {
        path_d: path,
        area_d: area,
        latest_label: fmt(latest),
        peak_label: fmt(max),
        avg_label: fmt(avg),
        kind,
        has_data: true,
        points_json,
    }
}

/// Render a Unix timestamp as `HH:MM` UTC for the chart tooltip.
/// We DON'T bother with the operator's local timezone because the
/// stats page is server-internal — UTC is consistent across nodes.
fn fmt_time_label(ts: i64) -> String {
    use chrono::{DateTime, Utc};
    DateTime::<Utc>::from_timestamp(ts, 0)
        .map(|d| d.format("%H:%M").to_string())
        .unwrap_or_else(|| "—".into())
}

/// Minimal JSON string escaper. Avoids pulling serde_json into this
/// hot path for the sake of a label that's almost always a clean
/// ASCII number — but we still need to handle the occasional quote.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Clamp a response-time-ish ms value into a 10-100% bar height for
/// the monitor sparkline. <50ms = 30%, 5000ms = 100%, log scale-ish.
pub fn clamp_height_percent(ms: &i64) -> i64 {
    let ms = (*ms).max(0);

    if ms < 50 {
        30
    } else if ms < 200 {
        50
    } else if ms < 1000 {
        70
    } else if ms < 3000 {
        85
    } else {
        100
    }
}

/// Format a byte count as a short string (e.g. "1.4 GiB"). Public for use
/// from other handlers + templates.
pub fn fmt_bytes(n: &i64) -> String {
    let n = *n as f64;
    let units = ["B", "kiB", "MiB", "GiB", "TiB"];
    let mut i = 0;
    let mut v = n;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", n as i64, units[i])
    } else {
        format!("{:.1} {}", v, units[i])
    }
}

/// Integer percent `used / total`, floored and clamped to 0..=100. Returns 0
/// when capacity is unknown (`total <= 0`). Takes `&i64` like `fmt_bytes` so
/// templates call it the same way, e.g.
/// `disk_used_pct(c.total_disk_bytes, c.total_node_disk_total_bytes)`.
pub fn disk_used_pct(used: &i64, total: &i64) -> i64 {
    if *total <= 0 {
        0
    } else {
        (used.saturating_mul(100) / *total).clamp(0, 100)
    }
}

/// Build a tiny inline SVG polyline from a list of i64 values,
/// normalised against the series max. Used by the hosting detail
/// Stats card to render usage trends without pulling in a JS chart
/// library.
///
/// `extractor` projects the bucket to a single i64 (disk, bw_out,
/// requests, etc.). Empty inputs return an empty string.
pub fn sparkline_svg(
    buckets: &[hyperion_types::HostingUsageBucket],
    extractor: fn(&hyperion_types::HostingUsageBucket) -> i64,
) -> String {
    if buckets.len() < 2 {
        return String::new();
    }
    let vals: Vec<i64> = buckets.iter().map(extractor).collect();
    let max = vals.iter().copied().max().unwrap_or(1).max(1);
    let n = vals.len();
    let w: f64 = 220.0;
    let h: f64 = 36.0;
    let dx = if n > 1 { w / (n as f64 - 1.0) } else { 0.0 };
    let mut points = String::with_capacity(n * 12);
    for (i, v) in vals.iter().enumerate() {
        let x = i as f64 * dx;
        // Invert Y because SVG y grows downward, leaving 2 px top/bottom pad.
        let y = h - 2.0 - ((*v as f64 / max as f64) * (h - 4.0));
        if i > 0 {
            points.push(' ');
        }
        points.push_str(&format!("{:.1},{:.1}", x, y));
    }
    format!(
        r##"<svg viewBox="0 0 {w:.0} {h:.0}" preserveAspectRatio="none" style="width:100%;height:36px;display:block">
            <polyline fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" points="{points}"/>
            </svg>"##,
        w = w,
        h = h,
        points = points,
    )
}

/// Convenience projections used by the Stats card.
pub fn bucket_disk(b: &hyperion_types::HostingUsageBucket) -> i64 {
    b.disk_used_bytes
}
pub fn bucket_bw_in(b: &hyperion_types::HostingUsageBucket) -> i64 {
    b.bw_in_bytes
}
pub fn bucket_bw_out(b: &hyperion_types::HostingUsageBucket) -> i64 {
    b.bw_out_bytes
}
pub fn bucket_requests(b: &hyperion_types::HostingUsageBucket) -> i64 {
    b.php_requests
}

/// 0-decimal percent display. Returns "?" if total == 0.
pub fn fmt_percent(num: &i64, total: &i64) -> String {
    if *total <= 0 {
        return "?".into();
    }
    let p = (*num as f64 / *total as f64 * 100.0).round() as i64;
    format!("{p}%")
}

/// Display a "× 100" percentage (CPU %, PSI pressure) with one decimal:
/// `4250` → `42.5%`.
pub fn fmt_pct_x100(v: &i64) -> String {
    format!("{:.1}%", *v as f64 / 100.0)
}

/// Bytes/sec → human rate, e.g. `1.2 MB/s`.
pub fn fmt_rate(bps: &i64) -> String {
    format!("{}/s", fmt_bytes(bps))
}

/// Load average from the stored ×100 integer.
pub fn fmt_load(la_x100: &i64) -> String {
    format!("{:.2}", *la_x100 as f64 / 100.0)
}

/// Format a duration as "Xd Yh Zm".
pub fn fmt_uptime(secs: &i64) -> String {
    if *secs <= 0 {
        return "—".into();
    }
    let secs = *secs;
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

/// Relative timestamp display — "2m ago", "1h 30m ago", "3d ago", "12 Apr".
pub fn fmt_ago(ts: &i64) -> String {
    if *ts <= 0 {
        return "—".into();
    }
    let now = hyperion_types::now_secs();
    let delta = (now - *ts).max(0);
    if delta < 60 {
        return "just now".into();
    }
    if delta < 3600 {
        return format!("{}m ago", delta / 60);
    }
    if delta < 86400 {
        let h = delta / 3600;
        let m = (delta % 3600) / 60;
        if m > 0 && h < 6 {
            return format!("{h}h {m}m ago");
        }
        return format!("{h}h ago");
    }
    if delta < 7 * 86400 {
        let d = delta / 86400;
        return format!("{d}d ago");
    }
    // Older than a week — render a calendar date in UTC.
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(*ts, 0)
        .single()
        .map(|dt| dt.format("%d %b %Y").to_string())
        .unwrap_or_else(|| format!("{ts}"))
}

/// Render a FUTURE timestamp (e.g. `next_billing_at`). `fmt_ago` clamps
/// negative deltas to 0, so it renders every future date as "just now";
/// this one shows the calendar date, with an "in Nd" hint when it's
/// close. `due now` / `overdue` when the date has passed.
pub fn fmt_future(ts: &i64) -> String {
    if *ts <= 0 {
        return "—".into();
    }
    use chrono::{TimeZone, Utc};
    let date = Utc
        .timestamp_opt(*ts, 0)
        .single()
        .map(|dt| dt.format("%d %b %Y").to_string())
        .unwrap_or_else(|| format!("{ts}"));
    let delta = *ts - hyperion_types::now_secs();
    if delta <= 0 {
        return format!("overdue ({date})");
    }
    let days = delta / 86400;
    if days == 0 {
        format!("today ({date})")
    } else if days < 45 {
        format!("in {days}d · {date}")
    } else {
        date
    }
}

/// Truncate a long opaque ID to the first 10 chars + ellipsis. Used for
/// hosting IDs in the activity feed where a full ULID/UUIDv7 line-wraps
/// ugly. Caller is expected to put the full ID in a `title="…"`.
pub fn fmt_short_id(s: &str) -> String {
    if s.chars().count() <= 12 {
        return s.to_string();
    }
    let head: String = s.chars().take(10).collect();
    format!("{head}…")
}

/// Humanize a dotted audit action label for the Recent activity
/// feed. `hosting.resume` → "Resumed", `wp.plugin.action` →
/// "WordPress plugin", `service.install.start` → "Service install
/// started". Falls through to the raw string for unknown codes
/// so we don't lose information.
pub fn fmt_action_label(s: &str) -> String {
    fmt_action_label_inner(s)
}

fn fmt_action_label_inner(s: &str) -> String {
    match s {
        "hosting.create" => "Created hosting",
        "hosting.delete" => "Deleted hosting",
        "hosting.suspend" => "Suspended",
        "hosting.resume" => "Resumed",
        "hosting.set_vhost_options" => "Vhost options",
        "hosting.set_wp_debug" => "WP debug toggled",
        "hosting.set_redis" => "Redis toggled",
        "hosting.rotate_redis_password" => "Redis password rotated",
        "hosting.file.write" => "File saved",
        "hosting.file.delete" => "File deleted",
        "hosting.file.mkdir" => "Folder created",
        "hosting.file.rename" => "File renamed",
        "hosting.set_limits" => "Limits updated",
        "hosting.acme_email.set" => "ACME email set",
        "wp.install" => "WordPress installed",
        "wp.plugin.action" => "WordPress plugin",
        "wp.theme.action" => "WordPress theme",
        "wp.reset_password" => "WP password reset",
        "db.reset_password" => "DB password reset",
        "ftp.set_password" => "FTP password set",
        "ftp.disable" => "FTP disabled",
        "cert.issue" => "Cert issued",
        "cert.renew" => "Cert renewed",
        "cert.renew.attempt" => "Cert renew attempted",
        "backup.now" => "Backup taken",
        "backup.restore" => "Backup restored",
        "service.install.start" => "Service install started",
        "service.install.finish" => "Service install finished",
        "service.restart" => "Service restarted",
        "agent.config.update" => "Agent config updated",
        // Named explicitly rather than left to the generator, which produced
        // "Web login 2FA succeeded" — a sentence about the mechanism, on the
        // one event where the reader wants a person and a verb.
        "web.login.ok" => "Signed in",
        "web.login.2fa_ok" => "Signed in with 2FA",
        "web.login.failed" => "Sign-in failed",
        "web.login.2fa_failed" => "2FA check failed",
        "web.user.locked" => "Account locked",
        "web.user.create" => "User created",
        "web.user.set_role" => "User role changed",
        "web.user.2fa_disabled" => "2FA disabled",
        "node.enroll" => "Node enrolled",
        "node.revoke" => "Node revoked",
        "hosting.migration.move" => "Hosting migrated",
        "hosting.rotate_wp_debug_log" => "debug.log rotated",
        // Anything not named above gets a GENERATED label instead of the
        // raw kind. The hand map exists for the labels where natural
        // English beats a mechanical one; the generator exists because the
        // codebase writes ~160 distinct kinds and grows more with every
        // feature — a hand list alone is permanently behind, which is
        // exactly how `wp.vuln.scan` reached the operator's screen raw.
        other => return humanize_kind(other),
    }
    .to_string()
}

/// Mechanical kind → label: split on `.`/`_`, expand the abbreviations the
/// codebase actually uses, capitalize once. "wp.vuln.scan" → "WordPress
/// vulnerability scan"; "web.login.2fa_ok" → "Web login 2FA succeeded".
fn humanize_kind(kind: &str) -> String {
    let words: Vec<&str> = kind
        .split(['.', '_'])
        .filter(|w| !w.is_empty())
        .map(|w| match w {
            "wp" => "WordPress",
            "db" => "database",
            "cert" => "certificate",
            "vuln" => "vulnerability",
            "2fa" => "2FA",
            "acme" => "ACME",
            "ftp" => "FTP",
            "dns" => "DNS",
            "dkim" => "DKIM",
            "spf" => "SPF",
            "geoip" => "GeoIP",
            "smtp" => "SMTP",
            "tls" => "TLS",
            "s3" => "S3",
            "kv" => "settings",
            "ok" => "succeeded",
            "rofs" => "read-only rootfs",
            "autofix" => "auto-repaired",
            "creds" => "credentials",
            "config" => "configuration",
            other => other,
        })
        .collect();
    let joined = words.join(" ");
    let mut c = joined.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => joined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact kinds from the operator's notification feed that rendered
    /// raw. Every one must come out readable — and the generator, not the
    /// hand map, is what guarantees the NEXT new kind does too.
    #[test]
    fn action_labels_are_readable() {
        assert_eq!(
            fmt_action_label("wp.vuln.scan"),
            "WordPress vulnerability scan"
        );
        assert_eq!(
            fmt_action_label("wp.integrity.scan"),
            "WordPress integrity scan"
        );
        // The sign-in kinds are now named by hand. The generator produced
        // "Web login 2FA succeeded" — a sentence about the mechanism, on the
        // one event where the reader is looking for a person and a verb.
        assert_eq!(fmt_action_label("web.login.2fa_ok"), "Signed in with 2FA");
        assert_eq!(fmt_action_label("web.login.ok"), "Signed in");
        assert_eq!(fmt_action_label("web.login.failed"), "Sign-in failed");
        assert_eq!(
            fmt_action_label("cert.panel_adopted"),
            "Certificate panel adopted"
        );
        assert_eq!(
            fmt_action_label("system.rofs_autofix"),
            "System read-only rootfs auto-repaired"
        );
        // Hand-mapped ones keep their natural labels.
        assert_eq!(fmt_action_label("hosting.create"), "Created hosting");
        // No input renders as its raw dotted form.
        assert_ne!(fmt_action_label("geoip.creds.set"), "geoip.creds.set");
    }

    fn site(domain: &str, cpu: i64, mem: i64, disk: i64, bw: i64, reqs: i64) -> SiteRow {
        SiteRow {
            hosting_id: format!("id-{domain}"),
            domain: domain.to_string(),
            node_label: "n1".into(),
            cpu_pct_x100: cpu,
            mem_rss_bytes: mem,
            disk_bytes: disk,
            bw_bytes_24h: bw,
            bw_in_bytes_24h: bw / 2,
            bw_out_bytes_24h: bw - bw / 2,
            requests_24h: reqs,
            sampled_at: 1_700_000_000,
            has_samples: true,
            bar_pct: 0,
        }
    }

    #[test]
    fn normalize_site_sort_defaults_to_disk() {
        assert_eq!(normalize_site_sort(""), "disk");
        assert_eq!(normalize_site_sort("nonsense"), "disk");
        assert_eq!(normalize_site_sort("disk"), "disk");
        // Aliases so an operator-typed URL still lands somewhere sane.
        assert_eq!(normalize_site_sort("mem"), "ram");
        assert_eq!(normalize_site_sort("bw"), "traffic");
        assert_eq!(normalize_site_sort("reqs"), "requests");
        assert_eq!(normalize_site_sort("site"), "domain");
    }

    #[test]
    fn sort_site_rows_puts_heaviest_first_and_scales_bars() {
        let mut rows = vec![
            site("small.test", 100, 10, 1_000, 5, 5),
            site("huge.test", 900, 90, 4_000, 50, 50),
            site("mid.test", 500, 50, 2_000, 25, 25),
        ];
        sort_site_rows(&mut rows, "disk");
        assert_eq!(
            rows.iter().map(|r| r.domain.as_str()).collect::<Vec<_>>(),
            ["huge.test", "mid.test", "small.test"],
            "default column must lead with the biggest consumer"
        );
        // Bar is scaled against the heaviest row, so the top site is full.
        assert_eq!(rows[0].bar_pct, 100);
        assert_eq!(rows[1].bar_pct, 50);
        assert_eq!(rows[2].bar_pct, 25);
    }

    #[test]
    fn sort_site_rows_honours_every_column() {
        let mut rows = vec![
            site("a.test", 900, 10, 1_000, 5, 500),
            site("b.test", 100, 90, 4_000, 50, 5),
        ];
        for (sort, want_first) in [
            ("cpu", "a.test"),
            ("ram", "b.test"),
            ("disk", "b.test"),
            ("traffic", "b.test"),
            ("requests", "a.test"),
        ] {
            sort_site_rows(&mut rows, sort);
            assert_eq!(rows[0].domain, want_first, "sort={sort}");
        }
        // Domain sort is alphabetical, and draws no share bar — "a is
        // bigger than b" is not a claim an A→Z listing gets to make.
        sort_site_rows(&mut rows, "domain");
        assert_eq!(rows[0].domain, "a.test");
        assert!(rows.iter().all(|r| r.bar_pct == 0));
    }

    #[test]
    fn sort_site_rows_all_zero_column_does_not_divide_by_zero() {
        // Every site freshly created, sampler hasn't ticked: the whole
        // column is 0. Must render as empty bars, not panic.
        let mut rows = vec![site("a.test", 0, 0, 0, 0, 0), site("b.test", 0, 0, 0, 0, 0)];
        sort_site_rows(&mut rows, "cpu");
        assert!(rows.iter().all(|r| r.bar_pct == 0));
        // Ties fall back to domain order, so the 30 s live refresh can't
        // reshuffle a shelf of idle sites on every swap.
        assert_eq!(rows[0].domain, "a.test");
        assert_eq!(rows[1].domain, "b.test");
    }

    #[test]
    fn push_site_rows_keeps_unsampled_sites_with_zeros() {
        let mut out = Vec::new();
        push_site_rows(
            &mut out,
            vec![hyperion_types::HostingStats {
                hosting_id: hyperion_types::HostingId("h1".into()),
                domain: "fresh.test".into(),
                disk_bytes: 0,
                bw_in_bytes_24h: 0,
                bw_out_bytes_24h: 0,
                requests_24h: 0,
                last_request_at: None,
                sampled_at: 1_700_000_000,
                mem_rss_bytes: 0,
                cpu_pct_x100: 0,
            }],
            "worker-2",
        );
        assert_eq!(out.len(), 1, "a never-sampled site must still get a row");
        assert!(!out[0].has_samples);
        // HostingStats carries no node_id — attribution comes from the
        // node that answered, and must survive the conversion.
        assert_eq!(out[0].node_label, "worker-2");
    }

    #[test]
    fn push_site_rows_traffic_is_in_plus_out() {
        let mut out = Vec::new();
        push_site_rows(
            &mut out,
            vec![hyperion_types::HostingStats {
                hosting_id: hyperion_types::HostingId("h1".into()),
                domain: "busy.test".into(),
                disk_bytes: 10,
                bw_in_bytes_24h: 300,
                bw_out_bytes_24h: 700,
                requests_24h: 42,
                last_request_at: Some(1_700_000_000),
                sampled_at: 1_700_000_000,
                mem_rss_bytes: 5,
                cpu_pct_x100: 250,
            }],
            "master (this node)",
        );
        assert_eq!(out[0].bw_bytes_24h, 1_000);
        assert!(out[0].has_samples);
    }

    #[test]
    fn build_sparkline_empty_returns_placeholder() {
        let s = build_sparkline(std::iter::empty::<(i64, f64)>(), "load", |v| format!("{v}"));
        assert!(!s.has_data, "empty input must mark sparkline as no-data");
        assert_eq!(s.latest_label, "—");
        assert_eq!(s.peak_label, "—");
        assert_eq!(s.path_d, "");
    }

    #[test]
    fn build_sparkline_single_sample_returns_placeholder() {
        // 1 sample = no line to draw (need at least 2 endpoints).
        let s = build_sparkline(std::iter::once((1700_000_000_i64, 1.0)), "mem", |v| {
            format!("{v}")
        });
        assert!(!s.has_data);
    }

    #[test]
    fn build_sparkline_two_samples_renders_line() {
        let s = build_sparkline(
            [(1_700_000_000_i64, 1.0), (1_700_000_060, 3.0)],
            "load",
            |v| format!("{v:.1}"),
        );
        assert!(s.has_data);
        // Two points → one M + one L.
        assert!(s.path_d.starts_with('M'), "path must start with Move");
        assert!(s.path_d.contains('L'), "path must contain a Line segment");
        // Y is flipped: smaller value is lower on screen (closer to H=60).
        // First sample (1.0) is the min → y near baseline (large y).
        // Last sample (3.0) is the max → y near top (small y).
        // path_d format: "M0.0,YY.Y L600.0,YY.Y"
        assert!(s.latest_label == "3.0");
        assert!(s.peak_label == "3.0", "peak is the max");
        assert!(s.avg_label == "2.0", "avg of [1,3] is 2");
        // Area path closes back to baseline.
        assert!(s.area_d.contains("L0,60"));
        assert!(s.area_d.ends_with('Z'));
    }

    #[test]
    fn build_sparkline_flat_series_does_not_divide_by_zero() {
        // All samples equal → range collapses to 0; must not produce
        // NaN/Inf in path data.
        let s = build_sparkline(
            [
                (1_700_000_000_i64, 5.0),
                (1_700_000_060, 5.0),
                (1_700_000_120, 5.0),
            ],
            "load",
            |v| format!("{v}"),
        );
        assert!(s.has_data);
        assert!(!s.path_d.contains("NaN"));
        assert!(!s.path_d.contains("inf"));
        assert_eq!(s.peak_label, "5");
        assert_eq!(s.latest_label, "5");
    }

    #[test]
    fn build_sparkline_negative_values_handled() {
        // Load avg shouldn't go negative in practice, but mem % could
        // when total=0 (we coerce to 0.0). Make sure negatives
        // don't break the path.
        let s = build_sparkline(
            [
                (1_700_000_000_i64, -1.0),
                (1_700_000_060, 0.0),
                (1_700_000_120, 1.0),
            ],
            "load",
            |v| format!("{v:.1}"),
        );
        assert!(s.has_data);
        assert_eq!(s.latest_label, "1.0");
        assert_eq!(s.peak_label, "1.0");
        // Avg = (-1 + 0 + 1)/3 = 0
        assert_eq!(s.avg_label, "0.0");
    }
}
