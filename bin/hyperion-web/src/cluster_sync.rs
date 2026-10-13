//! Keeps every node on the master's cluster-wide settings.
//!
//! Before this, a cluster-wide save (backup retention, the customer letters,
//! ...) was pushed to the nodes once, at save time, and a node that was down
//! for it — or enrolled later — kept its old value forever. Some settings
//! (the off-site FTP target, the Let's Encrypt contact, auto-update, the
//! brute-force thresholds) never left the master at all, and the S3 targets
//! never reached a worker's scheduled backups.
//!
//! This loop closes all of that. Every few minutes, and a few seconds after
//! any save that could change the answer, it builds the payload out of the
//! master's own agent.toml and S3 targets (see `hyperion_core::cluster_sync`),
//! asks each node which revision it last applied, and sends the payload to
//! every node that is behind. Pull-free: the master calls the node, never the
//! other way round (same model as the notification collector).
//!
//! The master always wins. The per-node settings page shows a synced node's
//! values read-only for that reason — an edit there would be undone by the
//! next pass.

use crate::dispatcher::DispatchError;
use crate::state::SharedState;
use hyperion_rpc::codec::{Request, Response};
use std::collections::HashMap;
use std::path::PathBuf;

/// Regular pass. Saves kick an earlier one.
const INTERVAL_SECS: u64 = 300;
/// A save restarts the master's agent ~3 s later, and the payload needs that
/// agent (the S3 target list). Wait it out before running a kicked pass.
const KICK_DELAY_SECS: u64 = 8;
/// After a pass that could not even build the payload, try again this soon.
const RETRY_SECS: u64 = 60;
/// Per-node budget for the revision question. The apply itself gets the
/// dispatcher's own ceiling.
const ASK_TIMEOUT_SECS: u64 = 15;

/// Where one node stands, as of the last pass that reached it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Already had the master's current revision.
    InSync,
    /// Was behind and took the payload in this pass.
    Applied,
    /// Runs an agent from before the sync; it keeps whatever its own file
    /// says, and its settings page stays editable.
    OldAgent,
    /// Could not be asked, or refused the payload. `detail` says which.
    Failed,
}

#[derive(Clone, Debug)]
pub struct NodeSync {
    pub state: SyncState,
    /// Unix seconds of the pass this came from.
    pub at: i64,
    /// Human sentence for the Nodes page / node settings page.
    pub detail: String,
}

impl NodeSync {
    /// Short verdict for a status pill.
    pub fn verdict(&self) -> &'static str {
        match self.state {
            SyncState::InSync | SyncState::Applied => "in sync",
            SyncState::OldAgent => "not synced (old agent)",
            SyncState::Failed => "sync failed",
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self.state, SyncState::InSync | SyncState::Applied)
    }

    /// Whether the master manages this node's synced settings. Everything
    /// but an agent too old to take them.
    pub fn managed(&self) -> bool {
        self.state != SyncState::OldAgent
    }
}

/// The loop's handle: kick it, read what it last saw.
pub struct SyncCtl {
    kick: tokio::sync::Notify,
    status: tokio::sync::RwLock<HashMap<String, NodeSync>>,
    agent_toml: PathBuf,
}

impl Default for SyncCtl {
    fn default() -> Self {
        Self::new(PathBuf::from("/etc/hyperion/agent.toml"))
    }
}

impl SyncCtl {
    pub fn new(agent_toml: PathBuf) -> Self {
        SyncCtl {
            kick: tokio::sync::Notify::new(),
            status: tokio::sync::RwLock::new(HashMap::new()),
            agent_toml,
        }
    }

    /// Ask for a pass soon (after [`KICK_DELAY_SECS`]). Cheap; call it after
    /// every save that could change a synced value.
    pub fn kick(&self) {
        self.kick.notify_one();
    }

    pub async fn status_for(&self, node_id: &str) -> Option<NodeSync> {
        self.status.read().await.get(node_id).cloned()
    }

    pub async fn all(&self) -> HashMap<String, NodeSync> {
        self.status.read().await.clone()
    }
}

pub fn spawn(state: SharedState) {
    tokio::spawn(async move {
        // First pass shortly after start: the master's agent may be coming
        // up alongside us.
        let mut next = std::time::Duration::from_secs(20);
        loop {
            let kicked = tokio::select! {
                _ = tokio::time::sleep(next) => false,
                _ = state.cluster_sync.kick.notified() => true,
            };
            if kicked {
                tokio::time::sleep(std::time::Duration::from_secs(KICK_DELAY_SECS)).await;
            }
            next = std::time::Duration::from_secs(INTERVAL_SECS);
            // Only a master has nodes to keep in step.
            if state.deployment_mode.read().await.as_str() != "master" {
                continue;
            }
            match sync_once(&state).await {
                Ok(n) if n > 0 => tracing::info!(updated = n, "settings sync: nodes updated"),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "settings sync: pass skipped");
                    next = std::time::Duration::from_secs(RETRY_SECS);
                }
            }
        }
    });
}

/// The master's enabled S3 targets, secrets inline — or an error when the
/// list could not be read. Unlike `resolve_s3_targets`, a failed read must
/// NOT come back as an empty list: synced to the nodes, that would delete
/// every worker's targets while the master's agent restarts.
async fn master_s3_targets(
    state: &SharedState,
) -> Result<Vec<hyperion_types::S3BackupTarget>, String> {
    match hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetList).await {
        Ok(Response::BackupTargetList(_)) => {}
        Ok(Response::Error(e)) => return Err(format!("S3 target list: {e}")),
        Ok(_) => return Err("S3 target list: unexpected answer".into()),
        Err(e) => return Err(format!("S3 target list: {e}")),
    }
    // Readable: the shared resolver now gives the same rows, upload-ready.
    Ok(crate::handlers::hostings::resolve_s3_targets(state).await)
}

/// One pass over every node. Returns how many took a new payload.
pub async fn sync_once(state: &SharedState) -> Result<usize, String> {
    let raw = tokio::fs::read_to_string(&state.cluster_sync.agent_toml)
        .await
        .map_err(|e| format!("read {}: {e}", state.cluster_sync.agent_toml.display()))?;
    let sections = hyperion_core::cluster_sync::extract_sections(&raw)?;
    let targets = master_s3_targets(state).await?;
    let revision = hyperion_core::cluster_sync::revision(&sections, &targets);
    let nodes = crate::handlers::hostings::fetch_remote_nodes(state)
        .await
        .map_err(|e| format!("node list: {e}"))?;
    let wire: Vec<(String, hyperion_rpc::codec::RedactedFields)> = sections
        .into_iter()
        .map(|s| (s.section, s.fields.into()))
        .collect();

    let mut set = tokio::task::JoinSet::new();
    for n in &nodes {
        let st = state.clone();
        let node_id = n.node_id.clone();
        let rev = revision.clone();
        let wire = wire.clone();
        let targets = targets.clone();
        set.spawn(async move {
            let r = sync_node(&st, &node_id, rev, wire, targets).await;
            (node_id, r)
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut fresh = HashMap::new();
    let mut applied = 0;
    while let Some(joined) = set.join_next().await {
        let Ok((node_id, (st, detail))) = joined else {
            continue;
        };
        if st == SyncState::Applied {
            applied += 1;
        }
        if st == SyncState::Failed {
            tracing::warn!(node = %node_id, %detail, "settings sync: node not updated");
        }
        fresh.insert(
            node_id,
            NodeSync {
                state: st,
                at: now,
                detail,
            },
        );
    }
    // Replace wholesale: a node that was removed drops out of the map.
    *state.cluster_sync.status.write().await = fresh;
    Ok(applied)
}

/// Is this the answer of an agent that does not know the request at all?
/// Such an agent fails to decode it and answers HTTP 400, which curl reports
/// as exit 22 — the same signal the per-node settings page relies on.
pub(crate) fn is_old_agent(e: &DispatchError) -> bool {
    matches!(
        e,
        DispatchError::Remote(hyperion_rpc_client::remote::RemoteClientError::HttpError {
            code: Some(22),
            ..
        })
    )
}

async fn sync_node(
    state: &SharedState,
    node_id: &str,
    revision: String,
    sections: Vec<(String, hyperion_rpc::codec::RedactedFields)>,
    s3_targets: Vec<hyperion_types::S3BackupTarget>,
) -> (SyncState, String) {
    let asked = tokio::time::timeout(
        std::time::Duration::from_secs(ASK_TIMEOUT_SECS),
        crate::dispatcher::dispatch_to_node(state, Some(node_id), Request::ClusterConfigRevision),
    )
    .await;
    match asked {
        Ok(Ok(Response::ClusterConfigRevision(Some(r)))) if r == revision => {
            return (
                SyncState::InSync,
                "has the master's current settings".to_string(),
            )
        }
        Ok(Ok(Response::ClusterConfigRevision(_))) => {}
        Ok(Ok(Response::Error(e))) => return (SyncState::Failed, e.to_string()),
        Ok(Ok(_)) => {
            return (
                SyncState::Failed,
                "answered with something unexpected".to_string(),
            )
        }
        Ok(Err(e)) if is_old_agent(&e) => {
            return (
                SyncState::OldAgent,
                "runs an older agent that cannot take the master's settings — update it; until \
                 then it keeps its own"
                    .to_string(),
            )
        }
        Ok(Err(e)) => return (SyncState::Failed, e.to_string()),
        Err(_) => {
            return (
                SyncState::Failed,
                format!("did not answer within {ASK_TIMEOUT_SECS}s"),
            )
        }
    }
    match crate::dispatcher::dispatch_to_node(
        state,
        Some(node_id),
        Request::ClusterConfigApply {
            revision,
            sections,
            s3_targets,
        },
    )
    .await
    {
        Ok(Response::ClusterConfigApply {
            restart_scheduled,
            ignored,
        }) => {
            let mut detail = "took the master's settings".to_string();
            if restart_scheduled {
                detail.push_str("; its agent restarts once no job is running");
            }
            if !ignored.is_empty() {
                detail.push_str(&format!(
                    "; skipped {} it does not know yet — update it",
                    ignored.join(", ")
                ));
            }
            (SyncState::Applied, detail)
        }
        Ok(Response::Error(e)) => (SyncState::Failed, format!("refused them: {e}")),
        Ok(_) => (
            SyncState::Failed,
            "answered with something unexpected".to_string(),
        ),
        Err(e) => (SyncState::Failed, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_old_agent_leaves_the_node_unmanaged() {
        let mk = |state| NodeSync {
            state,
            at: 0,
            detail: String::new(),
        };
        assert!(mk(SyncState::InSync).managed());
        assert!(mk(SyncState::Applied).managed());
        assert!(mk(SyncState::Failed).managed());
        assert!(!mk(SyncState::OldAgent).managed());
        assert!(mk(SyncState::Applied).is_ok());
        assert!(!mk(SyncState::Failed).is_ok());
    }

    #[test]
    fn curl_22_is_an_old_agent_and_nothing_else_is() {
        use hyperion_rpc_client::remote::RemoteClientError;
        let old = DispatchError::Remote(RemoteClientError::HttpError {
            code: Some(22),
            stderr: String::new(),
        });
        assert!(is_old_agent(&old));
        let down = DispatchError::NodeUnreachable {
            node_id: "n".into(),
            kind: "refused".into(),
        };
        assert!(!is_old_agent(&down));
    }
}
