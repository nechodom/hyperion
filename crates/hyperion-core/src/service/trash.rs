//! The hosting trash: soft delete, restore, purge and the GC tick.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ────────────────────────── Trash / recycle bin ──────────────────────────

    /// Move a hosting to the trash. Same side-effects as suspend
    /// (nginx 503, FPM stop, DB lock, OS user locked, processes
    /// killed) PLUS set state=Trashed + stamp `trashed_at`. Files /
    /// DB / OS user / certs are PRESERVED — the scheduler GC's
    /// them later, or the operator can purge / restore explicitly
    /// from /trash.
    ///
    /// Internal: called from `delete()` when cluster.trash_enabled.
    pub(super) async fn trash_hosting(&self, detail: HostingDetail) -> Result<(), RpcError> {
        // Mirror the suspend side-effects.
        // Logged, not discarded. The FPM pool is stopped a few lines below,
        // so a vhost that never went live means the site answers 502 rather
        // than the notice — and silence here is why that looked like a
        // mystery rather than a failed step.
        if let Err(e) = self
            .adapters
            .nginx_apply_suspended(
                &detail.domain,
                detail.aliases.clone(),
                Some(TRASH_NOTICE.into()),
            )
            .await
        {
            tracing::error!(
                error = %e, domain = %detail.domain,
                "trash: could not apply the suspended vhost — the site will answer 502"
            );
        }
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_lock(db.engine, &db.db_user).await;
        }
        {
            // State and login policy in one critical section, so a reconcile
            // or a racing transition never sees one without the other.
            let _serial = LOGIN_LOCKS.lock().await;
            // A site suspended by an older version has no record yet and only
            // a password lock to undo later.
            let legacy = detail.state == HostingState::Suspended
                && matches!(self.login_lock_record(&detail.id).await, Ok(None));
            hostings::mark_trashed(&self.pool, &detail.id, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("mark trashed: {e}")))?;
            self.apply_login_policy_held(&detail.id, Some(legacy)).await;
        }
        let _ = self.adapters.kill_user_procs(&detail.system_user).await;

        self.append_audit(
            "hosting.trash",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        // Notify admins so the bell catches "this site went to trash".
        self.notify_admins_say(
            "warn",
            "ops.trash",
            &[("domain", &detail.domain)],
            "/trash",
            "hosting.trash",
        )
        .await;
        Ok(())
    }

    /// Restore a trashed hosting back to Active. Reverses the
    /// suspend side-effects (unlock OS user, unlock DB, restart
    /// FPM, write the real vhost back). Refuses if state isn't
    /// Trashed.
    pub async fn restore_from_trash(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Trashed {
            return Err(RpcError::Conflict {
                message: format!(
                    "hosting must be in trash to restore (current state: {})",
                    detail.state.as_str()
                ),
            });
        }
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_unlock(db.engine, &db.db_user).await;
        }
        if let Some(ver) = detail.php_version {
            let _ = self.fpm_ensure_with_limits(&detail, ver).await;
        }
        let _ = self.adapters.nginx_write_vhost(&detail).await;
        // Before un-trashing, while the scheduler is still holding them: cancel
        // the expiry actions that fell due during the stay. See
        // `scheduler::pending_due` — replayed, a `DeleteExpired` put the site
        // straight back in the trash within five minutes of this restore, or
        // hard-deleted it with the trash switched off.
        let now = now_secs();
        let dropped =
            hyperion_state::scheduler::cancel_overdue_for_hosting(&self.pool, &detail.id, now)
                .await
                .map_err(|e| RpcError::Internal_with(format!("expiry actions: {e}")))?;
        let dropped: Vec<&str> = dropped.iter().map(|k| k.as_str()).collect();
        if !dropped.is_empty() {
            tracing::warn!(
                domain = %detail.domain, actions = ?dropped,
                "restored from trash: expiry actions that fell due meanwhile were cancelled — \
                 set a new expiry if the site should still expire"
            );
        }
        {
            let _serial = LOGIN_LOCKS.lock().await;
            // Legacy only if it is STILL in the trash with no record: a
            // restore that already ran cleared the record on its way out.
            let still_trashed = self
                .get(HostingSelector::Id(detail.id.clone()))
                .await
                .is_ok_and(|d| d.state == HostingState::Trashed);
            let legacy =
                still_trashed && matches!(self.login_lock_record(&detail.id).await, Ok(None));
            hostings::unmark_trashed(&self.pool, &detail.id, now)
                .await
                .map_err(|e| RpcError::Internal_with(format!("unmark: {e}")))?;
            self.apply_login_policy_held(&detail.id, Some(legacy)).await;
        }
        self.append_audit(
            "hosting.trash.restore",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "expiry_actions_cancelled": dropped,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Permanently delete a trashed hosting NOW (skips waiting for
    /// the GC). Operator-driven. Hosting state must be Trashed —
    /// refuses on Active so the caller doesn't bypass the trash
    /// flow by accident.
    pub async fn purge_from_trash(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel.clone()).await?;
        if detail.state != HostingState::Trashed {
            return Err(RpcError::Conflict {
                message: format!(
                    "purge_from_trash refuses non-trashed hosting (state: {})",
                    detail.state.as_str()
                ),
            });
        }
        // First need to flip back to Deleting (the delete() guard
        // refuses to re-trash a trashed row). We bypass delete() and
        // call the hard-delete machinery directly here so the trash
        // setting doesn't redirect us back into trash().
        self.hard_delete_internal(detail, DeleteOpts::default())
            .await?;
        Ok(())
    }

    /// Tick: iterate trashed rows past their retention window and
    /// hard-delete each. Called by the scheduler. Returns the
    /// number of rows GC'd.
    pub async fn trash_gc_tick(&self) -> Result<i64, RpcError> {
        let cluster_cfg = read_cluster_section(self.agent_config_path.as_deref());
        if !cluster_cfg.trash_enabled {
            return Ok(0);
        }
        let retention_secs = cluster_cfg.trash_retention_days * 24 * 3600;
        let expired = hostings::list_trashed_expired(&self.pool, now_secs(), retention_secs)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list expired: {e}")))?;
        let mut purged = 0i64;
        for row in expired {
            let id = row.id.clone();
            // Build a HostingDetail from the row (mirror service::get).
            let sel = HostingSelector::Id(id.clone());
            if let Ok(detail) = self.get(sel).await {
                if self
                    .hard_delete_internal(detail, DeleteOpts::default())
                    .await
                    .is_ok()
                {
                    purged += 1;
                }
            }
        }
        if purged > 0 {
            tracing::info!(count = purged, "trash GC: purged expired hostings");
        }
        Ok(purged)
    }

    /// The hard-delete pipeline extracted so both `delete()` (when
    /// trash is off) and `purge_from_trash()` / GC (when trash is
    /// on) can share it. Keeps the existing public delete() body
    /// readable instead of branching deep inside.
    pub(super) async fn hard_delete_internal(
        &self,
        detail: HostingDetail,
        opts: DeleteOpts,
    ) -> Result<(), RpcError> {
        hostings::set_state(&self.pool, &detail.id, HostingState::Deleting, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set deleting: {e}")))?;
        let _ = self
            .adapters
            .nginx_delete_vhost(&detail.domain, Some(detail.id.to_string()))
            .await;
        let _ = self.adapters.acme_delete(&detail.domain).await;
        let _ = certificates::delete(&self.pool, &detail.domain).await;
        if let Some(db) = detail.database.as_ref() {
            if !opts.keep_database {
                let _ = self
                    .adapters
                    .db_drop(db.engine, &db.db_name, &db.db_user)
                    .await;
            }
        }
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        // Extra FTP logins are real passwd entries. The DB rows go with the
        // hosting via ON DELETE CASCADE, so if the accounts are not removed
        // HERE the cascade takes the only record of them and they stay on the
        // box forever — with a working password and, because they share the
        // site's uid, whatever that uid is next given.
        if let Ok(logins) =
            hyperion_state::ftp_accounts::logins_for_hosting(&self.pool, &detail.id).await
        {
            for login in logins {
                if let Err(e) = hyperion_adapters::ftp::delete_extra_login(&login).await {
                    tracing::error!(
                        error = %e, login = %login,
                        "delete: could not remove an extra FTP login — it will outlive the hosting"
                    );
                }
            }
        }
        let hosting_root = format!(
            "{}/{}/{}",
            self.paths.home_root, detail.system_user, detail.domain
        );
        let _ = self.adapters.remove_hosting_tree(&hosting_root).await;
        // State is `deleting` by now, so the site counts as neither online
        // nor offline: its extra logins stay shut on the way out, and its
        // system user is decided by whatever hostings remain on it.
        {
            let _serial = LOGIN_LOCKS.lock().await;
            let legacy = matches!(
                detail.state,
                HostingState::Suspended | HostingState::Trashed
            ) && matches!(self.login_lock_record(&detail.id).await, Ok(None));
            self.apply_login_policy_held(&detail.id, Some(legacy)).await;
        }
        if !opts.keep_user {
            let (others,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM hostings WHERE system_user_id = (SELECT id FROM system_users WHERE name = ?) AND id != ?")
                    .bind(&detail.system_user)
                    .bind(detail.id.as_str())
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("count: {e}")))?;
            if others == 0 {
                // `userdel` refuses (exit 8) while any process still holds the
                // account's UID, and this hosting's PHP-FPM workers do until
                // the pool is gone. The trash and suspend paths already kill
                // them; delete did not, so the failure was swallowed by the
                // `let _ =` below and the Linux user OUTLIVED the hosting —
                // while the `system_users` row was dropped anyway, which is
                // the orphan state the create-rollback goes to some length to
                // avoid. Killing here is right: the hosting is being
                // destroyed, so its processes are meant to stop.
                let _ = self.adapters.kill_user_procs(&detail.system_user).await;
                if let Err(e) = self.adapters.delete_user(&detail.system_user).await {
                    tracing::error!(
                        error = %e, user = %detail.system_user,
                        "delete: the Linux user survived — it will collide with the \
                         next hosting that derives the same name"
                    );
                }
                if let Ok(Some(row)) =
                    system_users::get_by_name(&self.pool, &detail.system_user).await
                {
                    let _ = system_users::delete(&self.pool, row.id).await;
                }
            }
        }
        // Stop DKIM signing + destroy this domain's key material. Otherwise a
        // future hosting that reclaims the same domain (domains are unique +
        // freed on delete) would inherit the old private key via genkey's
        // reuse-if-present path, letting the PRIOR owner forge DKIM-signed mail
        // for the new owner's domain. Best-effort — the node may not run DKIM.
        let _ = hyperion_adapters::dkim::disable_signing(
            &detail.domain,
            hyperion_adapters::dkim::DEFAULT_SELECTOR,
        )
        .await;
        let _ = hyperion_adapters::dkim::purge_keys(&detail.domain).await;
        // The snapshot repository: every snapshot of the site, its database
        // dumps and the password beside them. Kept for ever before this, long
        // after the customer was gone. The path is the hosting's ULID under a
        // root-owned directory, never a name a tenant controls.
        {
            let repo = hyperion_adapters::restic::Repo::for_hosting(
                hyperion_adapters::restic::REPO_BASE,
                detail.id.as_str(),
            );
            let site_lock = snapshot_lock(&detail.id);
            let _no_snapshot_meanwhile = site_lock.lock().await;
            match tokio::fs::remove_dir_all(&repo.path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::error!(
                    error = %e, domain = %detail.domain,
                    "purge: could not remove the site's snapshot repository"
                ),
            }
        }
        // The git deploy key and token live outside the site tree, in the
        // node's secret store; without this they outlived the site for ever.
        self.git_sync_forget(&detail).await;
        // Drop generic per-hosting KV (notes/tags/etc.) so a future
        // hosting reusing this ULID doesn't inherit stale metadata.
        let _ = hyperion_state::hosting_kv::delete_all(&self.pool, detail.id.as_str()).await;
        // WAF hit records and the root-owned hit log go with the site —
        // rotated copies too: logrotate only ever rotates `*.log`, so once
        // the live file is gone nothing else would remove `<id>.log.1…`.
        let _ = hyperion_state::waf::delete_hosting(&self.pool, detail.id.as_str()).await;
        remove_waf_logs(
            std::path::Path::new(hyperion_adapters::nginx::WAF_LOG_DIR),
            detail.id.as_str(),
        )
        .await;
        hostings::delete(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete row: {e}")))?;
        // The last site using the Core Rule Set gone: unload it (it costs
        // memory in every nginx process). Best-effort — boot re-checks.
        if detail.vhost_options.crs_settings().mode != hyperion_types::crs::CrsMode::Off {
            let _ = self.crs_sync().await;
        }
        self.append_audit(
            "hosting.purge",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Read all trashed hostings + compute the "days remaining"
    /// for the /trash list. Returns the wire-friendly summary.
    pub async fn list_trash(&self) -> Result<Vec<hyperion_types::TrashEntry>, RpcError> {
        let cluster_cfg = read_cluster_section(self.agent_config_path.as_deref());
        let retention_secs = cluster_cfg.trash_retention_days * 24 * 3600;
        let now = now_secs();
        let rows = hostings::list_trashed(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list trashed: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let trashed_at = r.trashed_at.unwrap_or(0);
                let purge_at = trashed_at + retention_secs;
                let secs_remaining = (purge_at - now).max(0);
                hyperion_types::TrashEntry {
                    id: r.id.as_str().to_string(),
                    domain: r.domain,
                    trashed_at,
                    purge_at,
                    seconds_remaining: secs_remaining,
                    node_id: r.node_id.unwrap_or_default(),
                }
            })
            .collect())
    }
}

/// The notice a trashed site's suspended vhost shows.
///
/// A constant because two places render it: `trash_hosting`, and the
/// certificate renewal that re-applies the suspended vhost to reload nginx.
/// `trash_hosting` writes no suspension row, so the renewal used to find no
/// reason on file and put the generic "temporarily unavailable" text on a
/// site that is not coming back.
pub(super) const TRASH_NOTICE: &str = "Hosting is in trash";
