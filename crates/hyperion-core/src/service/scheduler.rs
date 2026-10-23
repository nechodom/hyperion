//! The scheduler tick: due expiries and scheduled actions.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    pub async fn upcoming_expiries(
        &self,
        within_seconds: i64,
    ) -> Result<Vec<hyperion_types::ExpiringHosting>, RpcError> {
        let rows = hyperion_state::scheduler::list_with_expiry(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        let cutoff = now_secs() + within_seconds.max(0);
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let exp = r.expires_at?;
                if exp <= cutoff {
                    Some(hyperion_types::ExpiringHosting {
                        id: r.id,
                        domain: r.domain,
                        expires_at: exp,
                        owner_email: r.owner_email,
                        grace_days: r.grace_days,
                    })
                } else {
                    None
                }
            })
            .collect())
    }

    /// Drive one tick of the scheduler. Returns the number of actions
    /// processed (success + failed). Designed to be called both manually
    /// and from a tokio interval task in hyperion-agent.
    pub async fn scheduler_tick(&self) -> Result<i64, RpcError> {
        // 0. Sweep spent and expired import tokens.
        //
        // `import_tokens::cleanup` existed with no caller at all, so every
        // finished, failed, cancelled and expired transfer row accumulated for
        // the life of the install. Best-effort: a failure here must not stop the
        // expiry sweep the rest of this function does. The cutoff keeps a day of
        // finished rows so the wizard can still show what happened recently.
        {
            let cutoff = now_secs() - 24 * 60 * 60;
            match hyperion_state::import_tokens::cleanup(&self.pool, cutoff).await {
                Ok(n) if n > 0 => tracing::debug!(rows = n, "swept old import tokens"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error=%e, "import token sweep failed"),
            }
        }

        // 1. Make sure every hosting with an expires_at has its scheduled rows.
        self.reconcile_scheduled_rows()
            .await
            .map_err(|e| RpcError::Internal_with(format!("reconcile: {e}")))?;

        // 2. Take a slice of due, pending actions.
        let now = now_secs();
        let due = hyperion_state::scheduler::pending_due(&self.pool, now, 100)
            .await
            .map_err(|e| RpcError::Internal_with(format!("pending_due: {e}")))?;
        let mut processed = 0i64;
        for action in due {
            hyperion_state::scheduler::mark_running(&self.pool, action.id, now)
                .await
                .map_err(|e| RpcError::Internal_with(format!("mark_running: {e}")))?;
            let result = self.run_action(&action).await;
            match result {
                Ok(()) => {
                    hyperion_state::scheduler::mark_done(&self.pool, action.id)
                        .await
                        .map_err(|e| RpcError::Internal_with(format!("mark_done: {e}")))?;
                }
                Err(e) => {
                    tracing::warn!(action_id=action.id, error=%e, "scheduled action failed");
                    hyperion_state::scheduler::mark_failed_or_retry(&self.pool, action.id, &e, 3)
                        .await
                        .map_err(|e| RpcError::Internal_with(format!("mark_failed: {e}")))?;
                }
            }
            processed += 1;
        }

        // Best-effort housekeeping: wipe migration bundle dirs older
        // than 7 days. Operators frequently forget to clean these up
        // after a migration completes, and they can be many GB
        // (entire wp-content trees). Failure here is non-fatal — log
        // and continue.
        if let Err(e) = self.prune_old_migration_bundles().await {
            tracing::warn!(error=%e, "migration bundle prune failed");
        }
        // Trash GC: hard-delete any trashed hosting past the
        // retention window. No-op when cluster.trash_enabled = false.
        if let Err(e) = self.trash_gc_tick().await {
            tracing::warn!(error=%e, "trash GC failed");
        }
        // Audit retention: purge audit_log entries older than the
        // configured window. No-op when audit_retention_days = 0
        // (the default — keep forever). Updates the chain anchor
        // so verify_chain keeps working on the truncated chain.
        if let Err(e) = self.audit_retention_tick().await {
            tracing::warn!(error=%e, "audit retention failed");
        }
        // The bell's archive (and a worker's outbox) keep 90 days. This
        // existed from the start but was never called, so the table grew
        // for as long as the box ran.
        if let Err(e) = hyperion_state::notifications::gc_older_than(
            &self.pool,
            NOTIFICATION_RETENTION_SECS,
            now_secs(),
        )
        .await
        {
            tracing::warn!(error=%e, "notification retention failed");
        }
        Ok(processed)
    }

    /// Purge audit_log entries older than `cluster.audit_retention_days`.
    /// No-op when the setting is 0. Logs an info line each time entries
    /// are actually purged so operators see "I lost N audit rows on
    /// 2026-06-09" in journald — important context if anyone ever
    /// challenges the chain.
    pub(crate) async fn audit_retention_tick(&self) -> Result<(), RpcError> {
        let cluster_cfg = read_cluster_section(self.agent_config_path.as_deref());
        if cluster_cfg.audit_retention_days <= 0 {
            return Ok(());
        }
        let cutoff = now_secs() - cluster_cfg.audit_retention_days * 86_400;
        let (deleted, new_anchor) =
            hyperion_state::audit::purge_older_than(&self.pool, cutoff, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("audit purge: {e}")))?;
        if deleted > 0 {
            tracing::info!(
                deleted,
                retention_days = cluster_cfg.audit_retention_days,
                anchor_set = new_anchor.is_some(),
                "audit retention purge"
            );
        }
        Ok(())
    }

    /// Remove `/var/lib/hyperion/migration/<id>/` directories whose
    /// mtime is older than 7 days. The bundle download URL also
    /// expires after ~1h, so anything older than a week is dead
    /// inventory the operator clearly no longer needs.
    ///
    /// Also sweeps `/var/lib/hyperion/migration-incoming/inc_*`: the
    /// download staging of an import that died before its own cleanup ran
    /// (agent restart mid-download) holds a partial archive of plaintext
    /// site data that nothing else would ever remove.
    pub(crate) async fn prune_old_migration_bundles(&self) -> Result<u32, RpcError> {
        let week = std::time::Duration::from_secs(7 * 86_400);
        let bundles = prune_migration_bundle_dir(
            &std::path::PathBuf::from("/var/lib/hyperion/migration"),
            week,
        )
        .await?;
        let incoming = prune_migration_bundle_dir(
            &std::path::PathBuf::from("/var/lib/hyperion/migration-incoming"),
            week,
        )
        .await?;
        Ok(bundles.saturating_add(incoming))
    }

    pub(super) async fn reconcile_scheduled_rows(&self) -> Result<(), hyperion_state::StateError> {
        let rows = hyperion_state::scheduler::list_with_expiry(&self.pool).await?;
        let now = now_secs();
        for r in rows {
            let Some(exp) = r.expires_at else { continue };
            let offsets = hyperion_state::scheduler::parse_offsets(&r.warning_offsets_days);
            // Map each offset to a notification kind. Beyond the spec's
            // 30/7/1-day defaults we still queue extras, but we tag any
            // offset >= 30 as Notify30d, 7..30 as Notify7d, <7 as Notify1d
            // (good-enough bucketing for v1).
            for offset_days in &offsets {
                let kind = if *offset_days >= 30 {
                    hyperion_state::scheduler::ScheduledKind::Notify30d
                } else if *offset_days >= 7 {
                    hyperion_state::scheduler::ScheduledKind::Notify7d
                } else {
                    hyperion_state::scheduler::ScheduledKind::Notify1d
                };
                let due = exp - offset_days * 86_400;
                if due > now - 7 * 86_400 {
                    hyperion_state::scheduler::upsert(&self.pool, &r.id, kind, due, now).await?;
                }
            }
            hyperion_state::scheduler::upsert(
                &self.pool,
                &r.id,
                hyperion_state::scheduler::ScheduledKind::SuspendExpired,
                exp,
                now,
            )
            .await?;
            let delete_at = exp + r.grace_days.max(1) * 86_400;
            hyperion_state::scheduler::upsert(
                &self.pool,
                &r.id,
                hyperion_state::scheduler::ScheduledKind::DeleteExpired,
                delete_at,
                now,
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn reschedule_actions_for(
        &self,
        id: &HostingId,
        expires_at: i64,
        grace_days: i64,
        offsets: &[i64],
    ) -> Result<(), RpcError> {
        let now = now_secs();
        for offset_days in offsets {
            let kind = if *offset_days >= 30 {
                hyperion_state::scheduler::ScheduledKind::Notify30d
            } else if *offset_days >= 7 {
                hyperion_state::scheduler::ScheduledKind::Notify7d
            } else {
                hyperion_state::scheduler::ScheduledKind::Notify1d
            };
            let due = expires_at - offset_days * 86_400;
            if due > now - 7 * 86_400 {
                hyperion_state::scheduler::upsert(&self.pool, id, kind, due, now)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
            }
        }
        hyperion_state::scheduler::upsert(
            &self.pool,
            id,
            hyperion_state::scheduler::ScheduledKind::SuspendExpired,
            expires_at,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
        let delete_at = expires_at + grace_days.max(1) * 86_400;
        hyperion_state::scheduler::upsert(
            &self.pool,
            id,
            hyperion_state::scheduler::ScheduledKind::DeleteExpired,
            delete_at,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
        Ok(())
    }

    pub(super) async fn run_action(
        &self,
        action: &hyperion_state::scheduler::ScheduledRow,
    ) -> Result<(), String> {
        use hyperion_state::scheduler::ScheduledKind;
        match action.action {
            ScheduledKind::Notify30d | ScheduledKind::Notify7d | ScheduledKind::Notify1d => {
                let row = hyperion_state::scheduler::get_expiry(&self.pool, &action.hosting_id)
                    .await
                    .map_err(|e| e.to_string())?;
                let email = row
                    .as_ref()
                    .and_then(|r| r.owner_email.as_deref())
                    .map(str::trim)
                    .filter(|e| !e.is_empty());
                // Either everything the warning needs, or the reason there
                // will be no warning. The next action queued for this hosting
                // is the suspend, so a silently dropped warning is the
                // customer's only notice disappearing — it gets a loud log
                // line and an audit row that does NOT read "ok".
                let sendable = match (row.as_ref(), email, self.email_config.is_some()) {
                    (_, _, false) => Err("no SMTP relay configured ([email] in agent.toml)"),
                    (None, _, _) => Err("hosting row no longer exists"),
                    (Some(_), None, _) => Err("hosting has no owner_email"),
                    (Some(r), Some(to), _) => match r.expires_at {
                        Some(exp) => Ok((r, exp, to)),
                        None => Err("hosting has no expires_at"),
                    },
                };
                // `letter` is carried out of the match so the audit row can
                // name WHICH body the customer received. Like the care
                // report, the template comes from the agent.toml of the node
                // running this sweep, so master and worker legitimately
                // answer differently and the row is the only lasting record
                // of which one this was. Only a warning that actually went
                // out has a letter; the other two arms leave it `None`
                // rather than name a body nobody was sent.
                let (result, reason, letter) = match sendable {
                    Ok((r, exp, to)) => {
                        let template = self.expiry_warning_template();
                        // The CUSTOMER's last notice before suspension — it
                        // follows the site's language, not the cluster's.
                        let cat = self.letter_catalog_for(&r.id).await;
                        let letter = letter_origin_with(&template, &cat, EXPIRY_FRAME_IDS);
                        let subject_template =
                            read_notifications_section(self.agent_config_path.as_deref())
                                .expiry_warning_subject_template;
                        let (subject, body) = expiry_warning_mail_with(
                            &cat,
                            &r.domain,
                            exp,
                            r.grace_days,
                            now_secs(),
                            &template,
                            &subject_template,
                        );
                        // A relay failure still leaves this an `Ok(())`, so
                        // the row is marked done rather than bounced back to
                        // 'pending' to re-send every tick forever — same
                        // treatment the billing sweep gives its reminders.
                        // What it must NOT do is claim the customer was
                        // warned: the audit row and the log line say which of
                        // the two happened.
                        if self
                            .notify_email(
                                to,
                                &subject,
                                &body,
                                Some(action.hosting_id.as_str()),
                                EXPIRY_EMAIL_KIND,
                            )
                            .await
                        {
                            tracing::info!(
                                hosting=%action.hosting_id, action=action.action.as_str(),
                                owner=%to, letter=letter, "expiry warning sent",
                            );
                            ("ok", None, Some(letter))
                        } else {
                            let why = "the SMTP relay refused the message \
                                       (see the site's Emails tab)";
                            tracing::warn!(
                                hosting=%action.hosting_id, action=action.action.as_str(),
                                owner=%to, reason=why,
                                "expiry warning NOT sent — the customer gets no notice before suspension",
                            );
                            ("failed", Some(why), None)
                        }
                    }
                    Err(why) => {
                        tracing::warn!(
                            hosting=%action.hosting_id, action=action.action.as_str(),
                            reason=why,
                            "expiry warning NOT sent — the customer gets no notice before suspension",
                        );
                        ("skipped", Some(why), None)
                    }
                };
                self.append_audit(
                    "scheduler.notify",
                    Some(action.hosting_id.as_str()),
                    &serde_json::json!({
                        "kind": action.action.as_str(),
                        "to": email,
                        "reason": reason,
                        "letter": letter,
                    })
                    .to_string(),
                    result,
                )
                .await;
                Ok(())
            }
            ScheduledKind::SuspendExpired => self
                .suspend(
                    HostingSelector::Id(action.hosting_id.clone()),
                    hyperion_types::SuspendReason::Expired,
                )
                .await
                .map_err(|e| e.to_string()),
            ScheduledKind::DeleteExpired => self
                .delete(
                    HostingSelector::Id(action.hosting_id.clone()),
                    hyperion_rpc::wire::DeleteOpts::default(),
                )
                .await
                .map_err(|e| e.to_string()),
        }
    }
}
