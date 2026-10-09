use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::handlers::stats::{build_sparkline, Sparkline};
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::AgentInfo;
use hyperion_rpc::AuditEntryWire;
use hyperion_types::{
    ClusterStats, DashboardAlert, HostingSummary, NodeMetricsHistory, ServicesHealth, UpdateStatus,
};

/// Truncate a git SHA to the first 12 chars (or fewer if the SHA is
/// shorter). Pre-computed in the handler so the template doesn't need
/// a custom askama filter for this.
fn short_sha(s: &str) -> String {
    s.chars().take(12).collect()
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    agent_info: Option<AgentInfo>,
    recent: Vec<HostingSummary>,
    cluster: Option<ClusterStats>,
    activity: Vec<AuditEntryWire>,
    /// hosting_id → domain lookup so the activity feed can render
    /// a friendly site name instead of the opaque ULID. Filled by
    /// the handler from the `recent` + `cluster` lists.
    hosting_domains: std::collections::HashMap<String, String>,
    alerts: Vec<DashboardAlert>,
    services_health: ServicesHealth,
    spark_load: Sparkline,
    spark_bw: Sparkline,
    /// Realtime network in/out on one shared-scale chart.
    spark_net: crate::handlers::stats::DualSparkline,
    /// Live rx/tx headline rates (bytes/sec), summed across nodes.
    net_in_now: i64,
    net_out_now: i64,
    /// Backup bytes still on node disk vs recorded off-site, cluster-wide.
    backup_on_disk: i64,
    backup_offsite: i64,
    samples_in_window: usize,
    /// Wall-clock span the load/bandwidth sparklines cover ("3h 55m"),
    /// so the graph titles say a time instead of a sample count.
    spark_window: String,
    /// Tenant-scoped roles get no cluster tiles, node graphs or audit feed —
    /// the template drops those blocks instead of rendering empty "—" tiles.
    is_tenant: bool,
    update_status: UpdateStatus,
    update_current_short: String,
    update_latest_short: String,
    error: Option<String>,
    /// Set when a node's response failed authentication and its hostings
    /// were therefore discarded — the "recent hostings" card is
    /// INCOMPLETE.
    node_auth_warning: Option<String>,
}

pub async fn get_dashboard(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let (info, recent, error, node_auth_warning) = fetch(&state).await;
    // Tenant-scoped roles (operator/customer/viewer) land on this shared page
    // too. They must NOT see other tenants' hostings or a cluster-wide audit
    // feed here: filter the hosting cards to their grants and (below) suppress
    // the cluster blocks. Admin+ keeps the full cluster view.
    let is_tenant = ctx.is_tenant_scoped();
    let recent = if is_tenant {
        crate::handlers::hostings::filter_by_access(&state, &ctx, recent).await
    } else {
        recent
    };
    // Fetch all the dashboard inputs in parallel — they're independent
    // and the page renders against whatever survives.
    let (cluster_res, activity_res, alerts_res, health_res, history_res, net_res, update_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::ClusterStats),
        // Over-fetch: sign-ins are filtered out below and would otherwise
        // crowd every real change off the feed.
        hyperion_rpc_client::call(&state.agent_socket, Request::AuditList { limit: 60 }),
        hyperion_rpc_client::call(&state.agent_socket, Request::DashboardAlerts),
        hyperion_rpc_client::call(&state.agent_socket, Request::ServicesHealth),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::NodeMetricsHistory { limit: 48 }
        ),
        // The realtime net ring (seconds-scale) for the live throughput graph.
        hyperion_rpc_client::call(&state.agent_socket, Request::NetHistory { limit: 240 }),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::UpdateCheck {
                force_refresh: false
            }
        ),
    );
    let cluster = match cluster_res {
        Ok(RpcResponse::ClusterStats(c)) => Some(c),
        _ => None,
    };
    let activity: Vec<AuditEntryWire> = match activity_res {
        Ok(RpcResponse::AuditList(v)) => v
            .into_iter()
            .filter(|a| !is_session_noise(&a.action))
            .take(ACTIVITY_ROWS)
            .collect(),
        _ => vec![],
    };
    let mut alerts = match alerts_res {
        Ok(RpcResponse::DashboardAlerts(v)) => v,
        _ => vec![],
    };
    // Errors first: only three alerts show before the fold, and those three
    // should be the ones that are broken now, not the oldest warnings.
    alerts.sort_by_key(|a| severity_rank(&a.severity));
    let services_health = match health_res {
        Ok(RpcResponse::ServicesHealth(h)) => h,
        _ => ServicesHealth::default(),
    };
    let history: NodeMetricsHistory = match history_res {
        Ok(RpcResponse::NodeMetricsHistory(h)) => h,
        _ => NodeMetricsHistory::default(),
    };
    let update_status: UpdateStatus = match update_res {
        Ok(RpcResponse::UpdateCheck(u)) => u,
        _ => UpdateStatus::default(),
    };
    // Suppress cluster-wide blocks for tenant-scoped roles — these aggregate
    // across all tenants (cluster stats, the global audit feed, cluster alerts).
    let (cluster, activity, alerts) = if is_tenant {
        (None, Vec::new(), Vec::new())
    } else {
        (cluster, activity, alerts)
    };
    let update_current_short = short_sha(&update_status.current_sha);
    let update_latest_short = short_sha(&update_status.latest_sha);
    let samples_in_window = history.samples.len();
    let spark_window = match (history.samples.first(), history.samples.last()) {
        (Some(a), Some(b)) => fmt_window((a.at - b.at).abs()),
        _ => String::new(),
    };
    let spark_load = build_sparkline(
        history
            .samples
            .iter()
            .map(|s| (s.at, s.loadavg_1m_x100 as f64 / 100.0)),
        "load",
        |v| format!("{v:.2}"),
    );
    let spark_bw = build_sparkline(
        history
            .samples
            .iter()
            .map(|s| (s.at, s.total_bw_out_24h as f64)),
        "bw",
        |v| crate::handlers::stats::fmt_bytes(&(v as i64)),
    );
    // Realtime network in/out on one shared-scale chart.
    let net_history = match net_res {
        Ok(RpcResponse::NetHistory(h)) => h,
        _ => hyperion_types::NetHistory::default(),
    };
    let net_in_pts: Vec<(i64, f64)> = net_history
        .samples
        .iter()
        .map(|s| (s.at, s.rx_bps as f64))
        .collect();
    let net_out_pts: Vec<(i64, f64)> = net_history
        .samples
        .iter()
        .map(|s| (s.at, s.tx_bps as f64))
        .collect();
    let spark_net = crate::handlers::stats::build_dual_sparkline(&net_in_pts, &net_out_pts, |v| {
        crate::handlers::stats::fmt_rate(&(v as i64))
    });
    // Live headline rates + the backup on-disk/off-site split, summed across
    // whatever nodes answered. Zero for tenant-scoped roles (no cluster view).
    let (net_in_now, net_out_now, backup_on_disk, backup_offsite) = cluster
        .as_ref()
        .map(|c| {
            (
                c.nodes.iter().map(|n| n.net_rx_bps).sum(),
                c.nodes.iter().map(|n| n.net_tx_bps).sum(),
                c.nodes.iter().map(|n| n.backup_bytes).sum(),
                c.nodes
                    .iter()
                    .flat_map(|n| n.backup_storage.iter())
                    .map(|r| r.offsite_bytes)
                    .sum(),
            )
        })
        .unwrap_or((0, 0, 0, 0));
    // Build hosting_id → domain map from the full list so the
    // activity feed renders friendly site names instead of raw
    // ULIDs. Fetched once via HostingList (also feeds `recent`
    // above), so this is a free pass through the same data.
    let mut hosting_domains: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    if is_tenant {
        // Tenant-scoped: only map the domains they're allowed to see (from the
        // already access-filtered `recent`), never the full cluster list.
        for h in &recent {
            hosting_domains.insert(h.id.as_str().to_string(), h.domain.clone());
        }
    } else if let Ok(RpcResponse::HostingList(all)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingList).await
    {
        for h in all {
            hosting_domains.insert(h.id.as_str().to_string(), h.domain);
        }
    }

    let tpl = DashboardTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "dashboard",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        agent_info: info,
        recent,
        cluster,
        activity,
        alerts,
        services_health,
        spark_load,
        spark_bw,
        spark_net,
        net_in_now,
        net_out_now,
        backup_on_disk,
        backup_offsite,
        samples_in_window,
        spark_window,
        is_tenant,
        update_status,
        update_current_short,
        update_latest_short,
        error,
        hosting_domains,
        node_auth_warning,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Rows the Recent activity feed shows after filtering.
const ACTIVITY_ROWS: usize = 10;

/// Successful sign-ins and session bookkeeping: on a panel one person uses
/// all day they are most of the audit log, and they push every real change
/// off the dashboard feed. Failed sign-ins stay — those are worth a look.
/// The full trail is one click away in /audit.
fn is_session_noise(action: &str) -> bool {
    matches!(action, "web.login.ok" | "web.login.2fa_ok") || action.starts_with("web_session.")
}

/// Graph-title span, rounded the way a person says it: "4h", "45m", "2d".
fn fmt_window(secs: i64) -> String {
    match secs {
        s if s >= 2 * 86400 => format!("{}d", (s + 43200) / 86400),
        s if s >= 3600 => format!("{}h", (s + 1800) / 3600),
        s => format!("{}m", (s + 30) / 60),
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "error" => 0,
        "warn" => 1,
        _ => 2,
    }
}

/// Returns `(agent info, recent hostings, page error, node-auth warning)`.
/// The last element is `Some` when a node's hostings were dropped because
/// its response failed authentication — the card must not read as "this
/// operator has fewer sites than they do".
async fn fetch(
    state: &SharedState,
) -> (
    Option<AgentInfo>,
    Vec<HostingSummary>,
    Option<String>,
    Option<String>,
) {
    let info = match hyperion_rpc_client::call(&state.agent_socket, Request::AgentInfo).await {
        Ok(RpcResponse::AgentInfo(i)) => Some(i),
        Ok(RpcResponse::Error(e)) => {
            return (None, vec![], Some(format!("agent: {e}")), None);
        }
        Ok(_) => return (None, vec![], Some("unexpected agent response".into()), None),
        Err(e) => return (None, vec![], Some(format!("rpc: {e}")), None),
    };
    // Recent hostings — fan-out across master + every enrolled
    // worker so a hosting created on `s4` shows up on the master's
    // dashboard. Previously only master-local was probed which
    // matched what /hostings did pre-fanout, but now the operator
    // expects parity. RECENT_ROWS of them, with "View all →" on
    // the card linking to /hostings for the full table.
    let (recent, node_auth_warning) = fetch_recent_multi_node(state).await;
    (info, recent, None, node_auth_warning)
}

/// Newest websites shown on the dashboard; "View all" links to /hostings.
const RECENT_ROWS: usize = 10;

async fn fetch_recent_multi_node(state: &SharedState) -> (Vec<HostingSummary>, Option<String>) {
    // Master's own hostings — tag with the LOCAL sentinel so the
    // dashboard's node-chip rendering keeps working.
    let mut all: Vec<HostingSummary> =
        match hyperion_rpc_client::call(&state.agent_socket, Request::HostingList).await {
            Ok(RpcResponse::HostingList(mut v)) => {
                for r in &mut v {
                    r.node_id = Some(crate::dispatcher::LOCAL_NODE_SENTINEL.to_string());
                }
                v
            }
            _ => Vec::new(),
        };
    // Each enrolled remote node, best-effort.
    let nodes: Vec<hyperion_types::NodeSummary> = match crate::dispatcher::cached_nodes(state)
        .await
        .map(hyperion_rpc::codec::Response::NodesList)
    {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(),
    };
    // Concurrent fan-out (see dispatcher::fan_out): the landing page must not
    // block on the slowest worker.
    let (answered, failed) =
        crate::dispatcher::fan_out_reporting(state, nodes, Request::HostingList).await;
    for (n, resp) in answered {
        if let RpcResponse::HostingList(mut remote) = resp {
            for r in &mut remote {
                r.node_id = Some(n.node_id.clone());
            }
            all.extend(remote);
        }
    }
    all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    (
        all.into_iter().take(RECENT_ROWS).collect(),
        crate::handlers::node_auth_warning(&failed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_noise_hides_successful_sign_ins_only() {
        assert!(is_session_noise("web.login.ok"));
        assert!(is_session_noise("web.login.2fa_ok"));
        assert!(is_session_noise("web_session.revoke"));
        assert!(is_session_noise("web_session.revoke_all"));
        // Failures and account changes are signal, not noise.
        assert!(!is_session_noise("web.login.failed"));
        assert!(!is_session_noise("web.login.2fa_failed"));
        assert!(!is_session_noise("web.user.create"));
        assert!(!is_session_noise("backup.now"));
    }

    #[test]
    fn window_label_rounds() {
        assert_eq!(fmt_window(3 * 3600 + 55 * 60), "4h");
        assert_eq!(fmt_window(45 * 60), "45m");
        assert_eq!(fmt_window(3 * 86400), "3d");
    }

    #[test]
    fn alerts_sort_errors_first() {
        let mut v = vec!["info", "warn", "error", "warn"];
        v.sort_by_key(|s| severity_rank(s));
        assert_eq!(v, ["error", "warn", "warn", "info"]);
    }
}
