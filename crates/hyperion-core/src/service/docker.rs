//! The Docker monitoring module's install state.
//!
//! Turning the module on is a promise that this node may run `docker`, so it
//! is refused unless `docker version` answers. Turning it off leaves nothing
//! behind. Everything docker does is a read; the only writes in this file go
//! to Hyperion's own database.

use super::*;
use hyperion_adapters::docker::{parse_version, DockerCmd, DockerError};
use hyperion_types::docker::DockerModuleState;

/// `docker version` and `buildx version` print a few hundred bytes.
const VERSION_MAX_BYTES: usize = 64 * 1024;

fn db_err(what: &str, e: hyperion_state::StateError) -> RpcError {
    RpcError::Internal_with(format!("{what}: {e}"))
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Is the module on for this node? Every module tick checks this first,
    /// so with it off nothing here runs a `docker` process. A database error
    /// reads as off: a tick that cannot tell does nothing.
    pub async fn docker_module_enabled(&self) -> bool {
        hyperion_state::docker::node_installed(&self.pool)
            .await
            .unwrap_or(false)
    }

    /// The module's state on this node. `docker version` runs only while the
    /// module is on; a daemon that does not answer just leaves the version
    /// empty.
    pub async fn docker_module_status(&self) -> Result<DockerModuleState, RpcError> {
        let row = hyperion_state::docker::get_module(&self.pool)
            .await
            .map_err(|e| db_err("docker_module_status", e))?;
        let docker_version = if row.node_installed {
            self.docker_server_version().await.ok()
        } else {
            None
        };
        Ok(DockerModuleState {
            cluster_installed: row.cluster_installed,
            node_installed: row.node_installed,
            buildx: row.buildx,
            docker_version,
        })
    }

    /// Turn the module on for this node. Refused, with the state left off,
    /// unless the docker CLI is installed and its daemon answers.
    pub async fn docker_node_install(&self) -> Result<DockerModuleState, RpcError> {
        let version = match self.docker_server_version().await {
            Ok(v) => v,
            Err(e) => {
                self.append_audit(
                    "docker.node.install",
                    None,
                    &serde_json::json!({"error": e.to_string()}).to_string(),
                    "refused",
                )
                .await;
                return Err(e);
            }
        };
        // buildx only decides whether a later feature can inspect remote
        // images; its absence is a fact to record, not a reason to refuse.
        let buildx = self
            .adapters
            .docker_read(DockerCmd::BuildxVersion, VERSION_MAX_BYTES)
            .await
            .is_ok();
        hyperion_state::docker::set_node_installed(&self.pool, buildx, now_secs())
            .await
            .map_err(|e| db_err("docker_node_install", e))?;
        self.append_audit(
            "docker.node.install",
            None,
            &serde_json::json!({"docker": version, "buildx": buildx}).to_string(),
            "ok",
        )
        .await;
        let row = hyperion_state::docker::get_module(&self.pool)
            .await
            .map_err(|e| db_err("docker_node_install", e))?;
        Ok(DockerModuleState {
            cluster_installed: row.cluster_installed,
            node_installed: row.node_installed,
            buildx: row.buildx,
            docker_version: Some(version),
        })
    }

    /// Turn the module off for this node and delete what it kept. No docker
    /// command is involved; hostings are not touched.
    pub async fn docker_node_remove(&self) -> Result<DockerModuleState, RpcError> {
        hyperion_state::docker::clear_node(&self.pool)
            .await
            .map_err(|e| db_err("docker_node_remove", e))?;
        self.append_audit("docker.node.remove", None, "{}", "ok")
            .await;
        self.docker_module_status().await
    }

    /// Master: turn the module on for the cluster. Only bookkeeping; each
    /// node is turned on with [`Self::docker_node_install`].
    pub async fn docker_cluster_install(&self) -> Result<DockerModuleState, RpcError> {
        hyperion_state::docker::set_cluster_installed(&self.pool)
            .await
            .map_err(|e| db_err("docker_cluster_install", e))?;
        self.append_audit("docker.cluster.install", None, "{}", "ok")
            .await;
        self.docker_module_status().await
    }

    /// Master: turn the cluster flag off and forget which nodes ran the
    /// module. Node data is cleared per node by [`Self::docker_node_remove`].
    pub async fn docker_cluster_remove(&self) -> Result<DockerModuleState, RpcError> {
        hyperion_state::docker::clear_cluster(&self.pool)
            .await
            .map_err(|e| db_err("docker_cluster_remove", e))?;
        self.append_audit("docker.cluster.remove", None, "{}", "ok")
            .await;
        self.docker_module_status().await
    }

    /// Master: record that `node_id` runs the module (or no longer does).
    pub async fn docker_node_register(
        &self,
        node_id: &str,
        installed: bool,
    ) -> Result<(), RpcError> {
        let node_id = node_id.trim();
        if node_id.is_empty() || node_id.len() > 128 || node_id.chars().any(|c| c.is_control()) {
            return Err(RpcError::Validation {
                message: "node id is empty, too long or has control characters".into(),
            });
        }
        if installed {
            hyperion_state::docker::register_node(&self.pool, node_id, now_secs()).await
        } else {
            hyperion_state::docker::unregister_node(&self.pool, node_id).await
        }
        .map_err(|e| db_err("docker_node_register", e))
    }

    /// `docker version`, reduced to the daemon's version, with errors worded
    /// for the operator who is trying to turn the module on.
    async fn docker_server_version(&self) -> Result<String, RpcError> {
        let out = self
            .adapters
            .docker_read(DockerCmd::Version, VERSION_MAX_BYTES)
            .await
            .map_err(|e| match e {
                DockerError::NotInstalled => RpcError::Validation {
                    message: "Docker is not installed on this node. Install Docker first, \
                              then turn the module on."
                        .into(),
                },
                DockerError::NotResponding => daemon_silent(),
                other => RpcError::Internal_with(format!("docker version: {other}")),
            })?;
        let v = parse_version(&out)
            .map_err(|e| RpcError::Internal_with(format!("docker version: {e}")))?;
        v.server.ok_or_else(daemon_silent)
    }
}

fn daemon_silent() -> RpcError {
    RpcError::Validation {
        message: "Docker is installed but its daemon is not responding. Start Docker and \
                  try again."
            .into(),
    }
}
