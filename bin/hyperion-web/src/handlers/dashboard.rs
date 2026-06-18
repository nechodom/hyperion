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
    samples_in_window: usize,
    update_status: UpdateStatus,
    update_current_short: String,
    update_latest_short: String,
    error: Option<String>,
}

pub async fn get_dashboard(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let (info, recent, error) = fetch(&state).await;
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
    let (cluster_res, activity_res, alerts_res, health_res, history_res, update_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::ClusterStats),
        hyperion_rpc_client::call(&state.agent_socket, Request::AuditList { limit: 10 }),
        hyperion_rpc_client::call(&state.agent_socket, Request::DashboardAlerts),
        hyperion_rpc_client::call(&state.agent_socket, Request::ServicesHealth),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::NodeMetricsHistory { limit: 48 }
        ),
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
    let activity = match activity_res {
        Ok(RpcResponse::AuditList(v)) => v,
        _ => vec![],
    };
    let alerts = match alerts_res {
        Ok(RpcResponse::DashboardAlerts(v)) => v,
        _ => vec![],
    };
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
        samples_in_window,
        update_status,
        update_current_short,
        update_latest_short,
        error,
        hosting_domains,
    };
    Ok(Html(tpl.render()?).into_response())
}

async fn fetch(state: &SharedState) -> (Option<AgentInfo>, Vec<HostingSummary>, Option<String>) {
    let info = match hyperion_rpc_client::call(&state.agent_socket, Request::AgentInfo).await {
        Ok(RpcResponse::AgentInfo(i)) => Some(i),
        Ok(RpcResponse::Error(e)) => {
            return (None, vec![], Some(format!("agent: {e}")));
        }
        Ok(_) => return (None, vec![], Some("unexpected agent response".into())),
        Err(e) => return (None, vec![], Some(format!("rpc: {e}"))),
    };
    // Recent hostings — fan-out across master + every enrolled
    // worker so a hosting created on `s4` shows up on the master's
    // dashboard. Previously only master-local was probed which
    // matched what /hostings did pre-fanout, but now the operator
    // expects parity. Bumped to 15 (was 8) with "View all →" on
    // the card linking to /hostings for the full table.
    let recent = fetch_recent_multi_node(state).await;
    (info, recent, None)
}

async fn fetch_recent_multi_node(state: &SharedState) -> Vec<HostingSummary> {
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
    let nodes: Vec<hyperion_types::NodeSummary> =
        match hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await {
            Ok(RpcResponse::NodesList(v)) => v,
            _ => Vec::new(),
        };
    // Concurrent fan-out (see dispatcher::fan_out): the landing page must not
    // block on the slowest worker.
    for (n, resp) in crate::dispatcher::fan_out(state, nodes, Request::HostingList).await {
        if let RpcResponse::HostingList(mut remote) = resp {
            for r in &mut remote {
                r.node_id = Some(n.node_id.clone());
            }
            all.extend(remote);
        }
    }
    all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    all.into_iter().take(15).collect()
}
