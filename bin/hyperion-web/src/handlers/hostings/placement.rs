//! Server facts and auto-placement of new hostings.

use super::*;

#[derive(Deserialize)]
pub struct ServerFactsQuery {
    #[serde(default)]
    pub(super) node: String,
}

/// GET /hostings/new/server-facts?node=… — the live line on a server card of
/// the test-site form: how many sites it carries, how full its disk is, its
/// load. One request per card, so a slow or dead server can't hold up the
/// form; it just says it isn't answering.
pub async fn get_server_facts(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<ServerFactsQuery>,
) -> Response {
    let html = |body: String| {
        (
            axum::http::StatusCode::OK,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response()
    };
    if !ctx.can(Capability::HostingCreate) {
        return (axum::http::StatusCode::FORBIDDEN, "").into_response();
    }
    let node = q.node.trim();
    if !node
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return (axum::http::StatusCode::BAD_REQUEST, "").into_response();
    }
    match crate::dispatcher::dispatch_to_node(&state, node_target(node), Request::NodeStats).await {
        Ok(RpcResponse::NodeStats(s)) => html(render_server_facts(&s)),
        _ => html("<span class=\"srv-fact is-err\">not answering</span>".into()),
    }
}

/// The facts line: figures stay grey; a disk past 90 % takes the warning
/// colour, because that is the one thing that should change the choice.
pub(super) fn render_server_facts(s: &hyperion_types::NodeStats) -> String {
    let mut out = format!(
        "<span class=\"srv-fact\">{} site{}</span>",
        s.hostings_count,
        if s.hostings_count == 1 { "" } else { "s" }
    );
    if s.node_disk_total_bytes > 0 {
        let used = (s.total_disk_bytes.max(0) as f64) / (s.node_disk_total_bytes as f64);
        let free_gb = (s.node_disk_total_bytes - s.total_disk_bytes).max(0) as f64 / 1e9;
        let tone = if used >= 0.9 { " is-warn" } else { "" };
        out.push_str(&format!(
            "<span class=\"srv-fact{tone}\" title=\"{:.0} % of the disk in use\">{free_gb:.0} GB free</span>",
            used * 100.0
        ));
    }
    out.push_str(&format!(
        "<span class=\"srv-fact\" title=\"1-minute load average\">load {:.2}</span>",
        s.loadavg_1m_x100 as f64 / 100.0
    ));
    out
}

/// Auto-placement: pick the best-fit node for a new hosting when
/// the operator chose the "auto" sentinel in the create form.
///
/// Strategy (lower is better):
///   - Disqualify offline workers entirely.
///   - Score = 0.45·hostings + 0.35·loadavg + 0.20·mem_pct
///     normalised across the candidate set so a single node never
///     dominates by virtue of having the largest absolute numbers.
///   - Tiebreak by lexicographically smaller node_id (stable).
///   - Master is INCLUDED as a candidate iff
///     `cluster.master_accepts_hostings = true`.
///
/// Returns the chosen target string ready for the existing
/// dispatcher contract:
///   - `Some("worker-id")` to dispatch to a worker
///   - `Some(LOCAL_NODE_SENTINEL)` to dispatch locally
///   - `None` when no candidate qualifies (caller falls back to
///     master / error).
pub(super) async fn pick_auto_placement_target(state: &SharedState) -> Option<String> {
    use hyperion_types::NodeStats;

    // A drained node takes no new sites — that is the whole promise of the
    // Drain button, and the placer never checked it.
    let nodes: Vec<_> = fetch_remote_nodes(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|n| !n.is_drained)
        .collect();
    let master_accepts = fetch_master_accepts_hostings(state).await;

    // Collect candidate NodeStats. Each entry is (target_string, NodeStats).
    let mut candidates: Vec<(String, NodeStats)> = Vec::with_capacity(nodes.len() + 1);

    if master_accepts {
        if let Ok(RpcResponse::ClusterStats(c)) =
            hyperion_rpc_client::call(&state.agent_socket, Request::ClusterStats).await
        {
            if let Some(mut n) = c.nodes.into_iter().next() {
                if n.label.is_empty() {
                    n.label = "master".into();
                }
                if n.agent_online {
                    candidates.push((crate::dispatcher::LOCAL_NODE_SENTINEL.to_string(), n));
                }
            }
        }
    }

    // Concurrently: asked one at a time, a single slow node held the
    // create form for its whole timeout before the next was even asked.
    let (answered, failed) =
        crate::dispatcher::fan_out_reporting(state, nodes, Request::ClusterStats).await;
    for (ns, _) in failed {
        tracing::warn!(node = %ns.node_id, "auto-placement: stats unavailable; skipping");
    }
    for (ns, resp) in answered {
        if let RpcResponse::ClusterStats(c) = resp {
            if let Some(stat) = c.nodes.into_iter().next() {
                if stat.agent_online {
                    candidates.push((ns.node_id.clone(), stat));
                }
            }
        }
    }

    if candidates.is_empty() {
        return None;
    }

    // Normalise each axis to [0, 1]. Lower = better. A zero-range
    // axis collapses to 0 contribution (every candidate is equal on
    // that axis).
    let max_host = candidates
        .iter()
        .map(|(_, s)| s.hostings_count)
        .max()
        .unwrap_or(0);
    let max_load = candidates
        .iter()
        .map(|(_, s)| s.loadavg_1m_x100)
        .max()
        .unwrap_or(0);
    let max_mem_pct: f64 = candidates
        .iter()
        .map(|(_, s)| mem_pct(s))
        .fold(0.0_f64, f64::max);

    let mut scored: Vec<(String, f64)> = candidates
        .iter()
        .map(|(id, s)| {
            let h = if max_host > 0 {
                s.hostings_count as f64 / max_host as f64
            } else {
                0.0
            };
            let l = if max_load > 0 {
                s.loadavg_1m_x100 as f64 / max_load as f64
            } else {
                0.0
            };
            let m_pct = mem_pct(s);
            let m = if max_mem_pct > 0.0 {
                m_pct / max_mem_pct
            } else {
                0.0
            };
            let score = 0.45 * h + 0.35 * l + 0.20 * m;
            (id.clone(), score)
        })
        .collect();
    // Stable tiebreak: lexicographically smaller node_id wins.
    scored.sort_by(|a, b| {
        a.1.partial_cmp(&b.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    scored.into_iter().next().map(|(id, _)| id)
}

pub(super) fn mem_pct(s: &hyperion_types::NodeStats) -> f64 {
    if s.mem_total_kib <= 0 {
        return 0.0;
    }
    (s.mem_used_kib as f64 / s.mem_total_kib as f64).clamp(0.0, 1.0)
}
