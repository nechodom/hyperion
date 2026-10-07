//! Brings worker alerts to the master's bell.
//!
//! A worker has no web users — accounts live on the master — so an alert a
//! worker's own ticks raise (a broken page, a failed certificate, a
//! read-only filesystem) is parked in the worker's `notification_outbox`.
//! This loop pulls each worker's outbox after the last row already
//! collected and hands it to the master agent, which fans it out to the
//! admins. Pull, not push: a node never calls the master (same model as
//! backup progress).
//!
//! The cursor lives in the master's own notifications (`MAX(origin_id)` per
//! node) and rows are unique per `(user, node, origin_id)`, so a restart or
//! a lost reply re-reads at most one batch and never duplicates a row.

use crate::state::SharedState;
use hyperion_rpc::codec::{Request, Response};

/// How often every worker's outbox is read. The bell polls once a minute.
const INTERVAL_SECS: u64 = 30;
/// Rows per outbox read; a node that has more is read again at once.
const BATCH: i64 = 200;
/// Upper bound on reads per node per pass, so a node with a huge backlog
/// cannot hold the loop.
const MAX_BATCHES: usize = 10;

pub fn spawn(state: SharedState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(INTERVAL_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // Only a master has workers to collect from.
            if state.deployment_mode.read().await.as_str() != "master" {
                continue;
            }
            let n = collect_once(&state).await;
            if n > 0 {
                tracing::info!(written = n, "notifications: collected worker alerts");
            }
        }
    });
}

/// One pass over every worker. Returns the notification rows written.
pub async fn collect_once(state: &SharedState) -> i64 {
    let nodes = match crate::handlers::hostings::fetch_remote_nodes(state).await {
        Ok(n) => n,
        Err(e) => {
            tracing::debug!(error = %e, "notifications: node list failed");
            return 0;
        }
    };
    let mut written = 0;
    for node in nodes {
        written += collect_node(state, &node.node_id).await;
    }
    written
}

async fn collect_node(state: &SharedState, node_id: &str) -> i64 {
    let mut written = 0;
    for _ in 0..MAX_BATCHES {
        let cursor = match local(
            state,
            Request::NotificationsNodeCursor {
                node_id: node_id.to_string(),
            },
        )
        .await
        {
            Some(Response::NotificationsNodeCursor(c)) => c,
            _ => return written,
        };
        let items = match crate::dispatcher::dispatch_to_node(
            state,
            Some(node_id),
            Request::NotificationsOutbox {
                after_id: cursor,
                limit: BATCH,
            },
        )
        .await
        {
            Ok(Response::NotificationsOutbox(items)) => items,
            // An agent from before the outbox answers with an error; a
            // down node fails to dispatch. Neither is news worth a WARN
            // every 30 seconds — the Nodes page already says it is down.
            Ok(other) => {
                tracing::debug!(node = node_id, ?other, "notifications: outbox not readable");
                return written;
            }
            Err(e) => {
                tracing::debug!(node = node_id, error = %e, "notifications: outbox not reachable");
                return written;
            }
        };
        if items.is_empty() {
            return written;
        }
        let full = items.len() as i64 >= BATCH;
        match local(
            state,
            Request::NotificationsIngest {
                node_id: node_id.to_string(),
                items,
            },
        )
        .await
        {
            // Nothing written means nothing moved the cursor (no admin
            // here yet): reading on would fetch the same batch again.
            Some(Response::NotificationsIngest { written: 0 }) => return written,
            Some(Response::NotificationsIngest { written: n }) => written += n,
            other => {
                tracing::warn!(node = node_id, ?other, "notifications: ingest failed");
                return written;
            }
        }
        if !full {
            return written;
        }
    }
    written
}

async fn local(state: &SharedState, req: Request) -> Option<Response> {
    hyperion_rpc_client::call(&state.agent_socket, req)
        .await
        .ok()
}
