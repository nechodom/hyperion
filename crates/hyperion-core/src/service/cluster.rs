//! Cluster-wide settings sync between master and nodes.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Where this node keeps what the master's settings sync gave it (the
    /// revision and the S3 targets), beside its agent.toml.
    pub(super) fn cluster_sync_path(&self) -> Option<std::path::PathBuf> {
        self.agent_config_path
            .as_deref()
            .and_then(|p| p.parent())
            .map(|d| d.join(crate::cluster_sync::STATE_FILE))
    }

    /// The last master-settings sync this node applied, if any.
    pub(super) fn cluster_sync_state(&self) -> Option<crate::cluster_sync::NodeSyncState> {
        crate::cluster_sync::read_state(&self.cluster_sync_path()?)
    }

    /// The master-settings revision this node last applied.
    pub async fn cluster_config_revision(&self) -> Result<Option<String>, RpcError> {
        Ok(self.cluster_sync_state().map(|s| s.revision))
    }

    /// Apply the master's cluster-wide settings on THIS node.
    ///
    /// Every synced section of agent.toml is replaced by the master's values
    /// (see [`crate::cluster_sync`]); the S3 targets go into the node's sync
    /// file, where the scheduled backup sweep reads them. The file is only
    /// rewritten when a value actually changed, and the agent restarts only
    /// when a section it reads at start-up changed — and then not until no
    /// job or backup is running, so a sync never kills a backup halfway.
    ///
    /// Refused on the master: its own file is the source of the payload.
    pub async fn cluster_config_apply(
        &self,
        revision: String,
        sections: Vec<(String, std::collections::BTreeMap<String, String>)>,
        s3_targets: Vec<hyperion_types::S3BackupTarget>,
    ) -> Result<(bool, Vec<String>), RpcError> {
        if !self.is_worker_node() {
            return Err(RpcError::Validation {
                message: "this node is not an enrolled worker — the master's settings are the \
                          source of the sync, not a copy of it"
                    .into(),
            });
        }
        let path = self
            .agent_config_path
            .as_ref()
            .ok_or_else(|| RpcError::Validation {
                message: "agent_config_path not wired — settings sync disabled".into(),
            })?;
        let sync_path = self
            .cluster_sync_path()
            .ok_or_else(|| RpcError::Validation {
                message: "agent_config_path not wired — settings sync disabled".into(),
            })?;
        let sections: Vec<crate::cluster_sync::SyncedSection> = sections
            .into_iter()
            .map(|(section, fields)| crate::cluster_sync::SyncedSection { section, fields })
            .collect();

        // One apply at a time: two overlapping syncs would each read the
        // file, change it, and the second write would drop the first's.
        static APPLY_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _gate = APPLY_GATE.lock().await;

        let mut doc = crate::config_persist::load(path)
            .map_err(|e| RpcError::Internal_with(format!("agent.toml read failed: {e}")))?;
        let outcome = crate::cluster_sync::apply_sections(&mut doc, &sections, |s, f| {
            parse_agent_section_fields(s, f).map_err(|e| e.to_string())
        })
        .map_err(|message| RpcError::Validation { message })?;
        if !outcome.changed.is_empty() {
            crate::config_persist::save(path, &doc)
                .map_err(|e| RpcError::Internal_with(format!("config write failed: {e}")))?;
        }
        // The revision goes down LAST: if anything above failed, the node
        // still reports the old one and the next sync pass tries again.
        let target_names: Vec<String> = s3_targets.iter().map(|t| t.name.clone()).collect();
        crate::cluster_sync::write_state(
            &sync_path,
            &crate::cluster_sync::NodeSyncState {
                revision: revision.clone(),
                applied_at: now_secs(),
                s3_targets,
            },
        )
        .map_err(|e| {
            RpcError::Internal_with(format!("could not write {}: {e}", sync_path.display()))
        })?;

        let restart = outcome
            .changed
            .iter()
            .any(|c| crate::cluster_sync::RESTART_SECTIONS.contains(&c.as_str()));
        // Audit names, never values (an FTP password is among them).
        self.append_audit(
            "cluster.config.apply",
            None,
            &serde_json::json!({
                "revision": revision,
                "changed": outcome.changed,
                "ignored": outcome.ignored,
                "s3_targets": target_names,
                "restart": restart,
            })
            .to_string(),
            "ok",
        )
        .await;
        if restart {
            self.restart_agent_when_idle();
        }
        Ok((restart, outcome.ignored))
    }

    /// Restart this agent once nothing is running — the same "is real work in
    /// flight?" rule `update.sh` waits on. Gives up waiting after six hours
    /// (whatever is still "running" by then is a row a crash left behind) and
    /// restarts anyway. At most one waiter at a time: later calls are folded
    /// into it, since one restart picks up every change.
    pub(super) fn restart_agent_when_idle(&self) {
        static PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if PENDING.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let pool = self.pool.clone();
        tokio::spawn(async move {
            const JOB_STALE_SECS: i64 = 3600;
            const BACKUP_STALE_SECS: i64 = 6 * 3600;
            const MAX_WAIT_SECS: i64 = 6 * 3600;
            // Let the RPC answer get back before anything goes down.
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let started = now_secs();
            loop {
                let busy = hyperion_state::jobs::running_work_count(
                    &pool,
                    now_secs(),
                    JOB_STALE_SECS,
                    BACKUP_STALE_SECS,
                )
                .await
                .unwrap_or(0);
                if busy == 0 || now_secs() - started > MAX_WAIT_SECS {
                    break;
                }
                tracing::info!(
                    running = busy,
                    "settings from the master need an agent restart — waiting for running work"
                );
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
            match tokio::process::Command::new("/usr/bin/systemctl")
                .args(["restart", "hyperion-agent"])
                .output()
                .await
            {
                Ok(o) if o.status.success() => {
                    tracing::info!("restart after master settings sync: ok")
                }
                Ok(o) => {
                    PENDING.store(false, std::sync::atomic::Ordering::SeqCst);
                    tracing::error!(
                        stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                        "restart after master settings sync failed — restart hyperion-agent manually"
                    )
                }
                Err(e) => {
                    PENDING.store(false, std::sync::atomic::Ordering::SeqCst);
                    tracing::error!(error = %e, "restart after master settings sync: spawn failed")
                }
            }
        });
    }
}
