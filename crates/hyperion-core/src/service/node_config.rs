//! Reading and writing this node's agent.toml through the panel.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Sanitised view of the agent's effective config — no secrets.
    /// Reads from the live `HostingService` state (which mirrors
    /// agent.toml as loaded at startup). For values stored on
    /// `RealAdapter`, the agent.rs forwarder doesn't have access
    /// here; the nginx_user is left empty if unavailable.
    pub async fn agent_config_view(
        &self,
        hostname: &str,
        version: &str,
    ) -> Result<hyperion_types::AgentConfigView, RpcError> {
        // `[email]` and `[slack]` come from agent.toml when it can be read —
        // see `email_view_from_toml` — and from the boot copy otherwise.
        let toml_path = self.agent_config_path.as_deref();
        let email_view = match toml_path.and_then(read_email_section) {
            Some(e) => email_view_from_toml(e),
            None => match &self.email_config {
                Some(cfg) => hyperion_types::EmailConfigView {
                    enabled: true,
                    smtp_host: cfg.smtp_host.clone(),
                    smtp_port: cfg.smtp_port,
                    smtp_user: cfg.smtp_user.clone(),
                    smtp_password_set: !cfg.smtp_password.is_empty(),
                    from_address: cfg.from_address.clone(),
                    from_name: cfg.from_name.clone(),
                    security: cfg.security.clone(),
                    default_to: self.email_default_to.clone().unwrap_or_default(),
                },
                None => hyperion_types::EmailConfigView {
                    default_to: self.email_default_to.clone().unwrap_or_default(),
                    ..Default::default()
                },
            },
        };
        let slack_view = hyperion_types::SlackConfigView {
            default_webhook_set: toml_path
                .and_then(slack_webhook_set_in_toml)
                .unwrap_or_else(|| {
                    self.slack_default_webhook
                        .as_deref()
                        .map(|s| !s.is_empty())
                        .unwrap_or(false)
                }),
        };
        // Read from agent.toml, NOT from `self.remote_backup`.
        //
        // Those fields are set once at agent boot and never mutated, and the
        // web layer schedules the agent restart three seconds AFTER it sends
        // the redirect — so the page an operator lands on after saving is
        // guaranteed to be pre-restart. Built from memory, the form came back
        // showing the OLD host, the OLD user and the OLD "pushing / local
        // only" pill, and the save looked like it had not happened. It had.
        //
        // Worse: `None => default()` blanked every field when the checkbox was
        // unticked, even though agent.toml still held the host and path — so
        // disabling the push looked like the configuration had been erased.
        // "Off" and "gone" are not the same state.
        //
        // The `[protection]` card on this same tab already reads straight off
        // agent.toml, which is why that one reflects a save immediately.
        let backup_remote_view = read_backup_remote_section(self.agent_config_path.as_deref());
        let backup_retention_view =
            read_backup_retention_section(self.agent_config_path.as_deref());
        let acme_view = hyperion_types::AcmeConfigView {
            contact_email: self.acme_contact_email.clone(),
            directory_url: String::new(), // not stored here
            challenge_dir: self.paths.acme_challenge_root.clone(),
        };
        // Cluster section is read directly from agent.toml's
        // [cluster] table (we don't keep it on Service because it's
        // UI-only — the agent itself doesn't enforce it; the master
        // web UI does, by hiding the master target option).
        let cluster_view = read_cluster_section(self.agent_config_path.as_deref());
        Ok(hyperion_types::AgentConfigView {
            update_auto: self.auto_update_enabled(),
            hostname: hostname.to_string(),
            agent_version: version.to_string(),
            nginx_user: self.adapters.nginx_user(),
            acme: acme_view,
            email: email_view,
            slack: slack_view,
            backup_remote: backup_remote_view,
            backup_retention: backup_retention_view,
            backup: {
                let p = read_local_copy_policy(self.agent_config_path.as_deref());
                hyperion_types::BackupConfigView {
                    drop_local_after_offsite: p.drop,
                    keep_local_latest: p.keep_latest as i64,
                }
            },
            cluster: cluster_view,
            notifications: read_notifications_section(self.agent_config_path.as_deref()),
            snapshot_retention: read_snapshot_retention(self.agent_config_path.as_deref()),
            performance: self.performance_config_view().await,
        })
    }

    /// `[performance]` for the Settings page: the source, strategy, whether a
    /// key is set (never the key itself) and whether a local Lighthouse works.
    pub(super) async fn performance_config_view(&self) -> hyperion_types::PerformanceConfigView {
        let cfg = self.performance_config();
        let lighthouse_available =
            cfg.cwv_source == "lighthouse" && hyperion_adapters::perf::lighthouse_available().await;
        hyperion_types::PerformanceConfigView {
            cwv_source: cfg.cwv_source.clone(),
            strategy: cfg.strategy_label().to_string(),
            psi_key_set: !cfg.psi_api_key.trim().is_empty(),
            lighthouse_available,
            cwv_interval_days: cfg.cwv_interval_days as i64,
        }
    }

    /// Apply per-section updates to agent.toml on disk. Operator
    /// still needs to `systemctl restart hyperion-agent` for the
    /// running daemon to pick up the new values — the UI reminds
    /// them with a flash message.
    pub async fn agent_config_update(
        &self,
        section: String,
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<(), RpcError> {
        let path = self
            .agent_config_path
            .as_ref()
            .ok_or_else(|| RpcError::Validation {
                message: "agent_config_path not wired — UI editing disabled".into(),
            })?;
        let parsed = parse_agent_section_fields(&section, &fields)?;
        // Convert to the &[(&str, FieldValue)] shape the persist module
        // wants. Done in two steps so the &str references live long
        // enough for the slice.
        let owned: Vec<(String, crate::config_persist::FieldValue)> = parsed;
        let view: Vec<(&str, crate::config_persist::FieldValue)> =
            owned.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        crate::config_persist::set_many(path, &section, &view)
            .map_err(|e| RpcError::Internal_with(format!("config write failed: {e}")))?;
        // Audit. Don't echo field values (might be a password).
        let field_names: Vec<&str> = fields.keys().map(|s| s.as_str()).collect();
        self.append_audit(
            "agent.config.update",
            None,
            &serde_json::json!({"section": section, "fields": field_names}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Set THIS node's `[email]` config and apply it. Unlike the generic
    /// `agent_config_update` (master-only, restarted by hyperion-web), this is
    /// dispatchable to any node over the signed channel — it writes the node's
    /// own agent.toml, applies postfix live (no restart needed for PHP mail()),
    /// then schedules a short delayed self-restart so the agent's in-memory
    /// email config (used for Hyperion's own notifications) also refreshes. The
    /// delay lets this RPC's response return before the agent bounces.
    pub async fn email_config_set(
        &self,
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<(), RpcError> {
        self.node_config_set("email".to_string(), fields).await
    }

    /// This node's agent.toml exactly as it is on disk, secrets masked HERE —
    /// so a worker's SMTP / FTP password never crosses the wire to the panel.
    /// Read fresh on every call: right after a save the file runs a few
    /// seconds ahead of the restarting agent, and the page must show the file.
    pub async fn node_config_read(&self) -> Result<String, RpcError> {
        let path = self
            .agent_config_path
            .as_ref()
            .ok_or_else(|| RpcError::Validation {
                message: "agent_config_path not wired — config reading disabled".into(),
            })?;
        let raw = tokio::fs::read_to_string(path).await.map_err(|e| {
            RpcError::Internal_with(format!("could not read {}: {e}", path.display()))
        })?;
        Ok(crate::config_persist::mask_secrets(&raw))
    }

    /// Write one section of THIS node's agent.toml and make it take effect.
    ///
    /// The per-node counterpart of `agent_config_update`: that one only writes
    /// the file and leaves the restart to hyperion-web, which can restart the
    /// master's agent and nobody else's. This one is dispatched to any node
    /// over the signed channel, so it restarts the agent it runs in — detached
    /// and delayed, so this RPC's answer is back before the agent goes down.
    /// Same validation as `agent_config_update` (`parse_agent_section_fields`).
    pub async fn node_config_set(
        &self,
        section: String,
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<(), RpcError> {
        let is_email = section == "email";
        self.agent_config_update(section, fields).await?;
        if is_email {
            // Apply postfix immediately from the just-written agent.toml.
            let _ = self.mta_reconfigure().await;
        }
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            match tokio::process::Command::new("/usr/bin/systemctl")
                .args(["restart", "hyperion-agent"])
                .output()
                .await
            {
                Ok(o) if o.status.success() => {
                    tracing::info!("self-restart after node config set: ok")
                }
                Ok(o) => tracing::error!(
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "self-restart after node config set failed — restart hyperion-agent manually"
                ),
                Err(e) => tracing::error!(error = %e, "self-restart spawn failed"),
            }
        });
        Ok(())
    }
}
