//! Finding a hosting on whichever node holds it.

use super::*;

/// Locate which node a hosting lives on, so per-hosting actions
/// (suspend, resume, set-limits, backup, cert, …) dispatched from
/// the detail page land on the right agent.
///
/// Strategy: try the master's local socket first (the common case).
/// On NotFound, fan out across enrolled nodes. The first one that
/// returns the hosting wins; its `node_id` is returned so the
/// handler can pass it to `dispatch_to_node`.
///
/// A DOMAIN lookup does not stop at a suspended or trashed answer: a Move
/// leaves the original parked (suspended) on the source under the same
/// domain, and the master is asked first, so taking its answer resolved
/// every domain-addressed action after a Move to the copy that no longer
/// serves the site. The parked answer is kept and returned only when no
/// node has a live one (see [`LookupPick`]).
///
/// Returns `(HostingDetail, node_id_or_None)`. `None` means master.
pub async fn find_hosting_anywhere(
    state: &SharedState,
    sel: HostingSelector,
) -> Result<(hyperion_types::HostingDetail, Option<String>), AppError> {
    let mut pick = LookupPick::new(&sel);
    // 1. Master local.
    match hyperion_rpc_client::call(&state.agent_socket, Request::HostingGet(sel.clone())).await {
        Ok(RpcResponse::HostingGet(d)) if detail_matches(&sel, d.id.as_str(), &d.domain) => {
            if let Some(hit) = pick.offer(d.state, (d, None)) {
                return Ok(hit);
            }
        }
        Ok(RpcResponse::HostingGet(d)) => {
            // Cannot be an attack — this is our own socket — so it is a bug
            // worth seeing rather than something to route around.
            tracing::error!(
                asked = ?sel, got = %d.id.as_str(), domain = %d.domain,
                "master answered HostingGet with a different hosting"
            );
            return Err(AppError::NotFound);
        }
        Ok(RpcResponse::Error(e)) if !is_not_found_error(&e) => {
            return Err(AppError::Rpc(e.to_string()));
        }
        Ok(_) => {}
        Err(e) => return Err(AppError::from(e)),
    }
    // 2. Fan out to enrolled nodes.
    let nodes_resp = crate::dispatcher::cached_nodes(state)
        .await
        .map(hyperion_rpc::codec::Response::NodesList);
    let nodes: Vec<hyperion_types::NodeSummary> = match nodes_resp {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(),
    };
    let mut node_problem: Option<AppError> = None;
    for n in nodes {
        let r = crate::dispatcher::dispatch_to_node(
            state,
            Some(&n.node_id),
            Request::HostingGet(sel.clone()),
        )
        .await;
        match r {
            Ok(RpcResponse::HostingGet(d)) if detail_matches(&sel, d.id.as_str(), &d.domain) => {
                if let Some(hit) = pick.offer(d.state, (d, Some(n.node_id))) {
                    return Ok(hit);
                }
            }
            Ok(RpcResponse::HostingGet(d)) => {
                // A node answered for a hosting that is not the one asked
                // for. Every authorization gate downstream keys on the
                // returned `detail.id`, and this same lookup picks the node
                // every later RPC is dispatched to — so an answer accepted
                // here makes the answering node the resolver for someone
                // else's site. Refuse it and keep asking; a node cannot take
                // over a hosting by being enrolled more recently.
                tracing::error!(
                    node = %n.node_id, asked = ?sel,
                    got_id = %d.id.as_str(), got_domain = %d.domain,
                    "SECURITY: node answered HostingGet with a hosting that was not asked for"
                );
                continue;
            }
            Ok(_) => continue, // not on this node (NotFound / other)
            Err(e) => {
                // Node unreachable / errored — remember it. If the hosting
                // turns up on no node BUT one was down, that outage is the
                // likely reason; surfacing "node X is down" beats a misleading
                // 404 that makes operators think the site was deleted.
                node_problem = Some(AppError::from(e));
                continue;
            }
        }
    }
    // No live copy anywhere: the parked one is the site, as it was before.
    // Preferred over a node error too — that is what the master-first
    // lookup always answered for a hosting it held.
    if let Some(hit) = pick.into_fallback() {
        return Ok(hit);
    }
    if let Some(e) = node_problem {
        return Err(e);
    }
    Err(AppError::NotFound)
}

/// Which of the matching answers a cluster lookup settles on.
///
/// An `Id` names exactly one row, so the first match is the answer whatever
/// its state. A `Domain` can match several rows across the cluster — after a
/// Move the source keeps the original SUSPENDED (and a trash keeps a row
/// TRASHED) under the same name — so a parked answer is held back while the
/// remaining nodes are asked, and the first LIVE match wins. The first parked
/// answer is the fallback when nothing live turns up.
pub(super) struct LookupPick<T> {
    pub(super) prefer_live: bool,
    pub(super) fallback: Option<T>,
}

impl<T> LookupPick<T> {
    pub(super) fn new(sel: &HostingSelector) -> Self {
        LookupPick {
            prefer_live: matches!(sel, HostingSelector::Domain(_)),
            fallback: None,
        }
    }

    /// Offer one matching answer. `Some` = take it now; `None` = keep asking.
    pub(super) fn offer(&mut self, st: hyperion_types::HostingState, hit: T) -> Option<T> {
        use hyperion_types::HostingState;
        let parked = matches!(st, HostingState::Suspended | HostingState::Trashed);
        if !self.prefer_live || !parked {
            return Some(hit);
        }
        if self.fallback.is_none() {
            self.fallback = Some(hit);
        }
        None
    }

    pub(super) fn into_fallback(self) -> Option<T> {
        self.fallback
    }
}

pub(super) fn is_not_found_error(e: &hyperion_rpc::error::RpcError) -> bool {
    matches!(e, hyperion_rpc::error::RpcError::NotFound { .. })
}

/// Is this the hosting that was actually asked for?
///
/// The cluster lookup asks every enrolled node in turn and takes the first
/// answer. Nothing checked that the answer matched the question, so a node
/// that replied to EVERY `HostingGet` — a compromised agent, a stolen node
/// secret, an operator-supplied node — became the resolver for every hosting
/// in the cluster that is not on the master. That is not a read-only problem:
/// the same call picks the node each later RPC is dispatched to, so file
/// browse and write, suspend, limits, certificates, backups and the WordPress
/// tooling all follow it, and the authorization gates key on the `detail.id`
/// the node itself returned.
///
/// Nodes are asked in `enrolled_at DESC` order, so the newest node is asked
/// first — a freshly enrolled rogue would win against every existing one.
pub(super) fn detail_matches(sel: &HostingSelector, got_id: &str, got_domain: &str) -> bool {
    match sel {
        HostingSelector::Id(id) => got_id == id.as_str(),
        // Case-insensitively: a domain is a hostname, and the selector may
        // come from a URL the operator typed.
        HostingSelector::Domain(dm) => got_domain.eq_ignore_ascii_case(dm.as_str()),
    }
}

pub(crate) async fn list_hostings(state: &SharedState) -> Result<Vec<HostingSummary>, String> {
    list_hostings_reporting(state).await.map(|(rows, _)| rows)
}

/// [`list_hostings`] that also hands back the nodes the fan-out dropped,
/// mirroring `dispatcher::fan_out` / `fan_out_reporting`. The /hostings
/// page uses this one so a node whose response failed AUTHENTICATION
/// gets a banner instead of quietly shrinking the table; the JSON/API
/// callers keep the plain list.
pub(crate) async fn list_hostings_reporting(
    state: &SharedState,
) -> Result<
    (
        Vec<HostingSummary>,
        Vec<(
            hyperion_types::NodeSummary,
            crate::dispatcher::DispatchError,
        )>,
    ),
    String,
> {
    // 1. Master's own hostings (always included).
    let local_resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingList)
        .await
        .map_err(|e| e.to_string())?;
    let mut local: Vec<HostingSummary> = match local_resp {
        RpcResponse::HostingList(v) => v,
        RpcResponse::Error(e) => return Err(e.to_string()),
        _ => return Err("unexpected response".into()),
    };
    for r in &mut local {
        r.node_id = Some(crate::dispatcher::LOCAL_NODE_SENTINEL.to_string());
    }

    // 2. Enrolled remote nodes — best-effort fan-out.
    let nodes_resp = crate::dispatcher::cached_nodes(state)
        .await
        .map(hyperion_rpc::codec::Response::NodesList);
    let nodes: Vec<hyperion_types::NodeSummary> = match nodes_resp {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(), // failed lookup — fall back to master-only
    };
    let mut all = local;
    // Query every worker CONCURRENTLY (see dispatcher::fan_out): one slow or
    // wedged node no longer stalls the whole /hostings (+ search + domain-check)
    // page — wall-clock is bounded by the slowest single node, not the sum.
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
    Ok((all, failed))
}
