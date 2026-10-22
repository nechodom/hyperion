//! restic snapshots: taking, listing, retention, diff and restore.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Take a snapshot of this site before something changes it.
    ///
    /// Best-effort by design, and that is a deliberate trade: a site whose
    /// snapshot could not be taken should still get its security update. The
    /// snapshot is insurance, and refusing to apply a patch because the
    /// insurance was unavailable leaves the site exposed for certain in
    /// order to avoid a risk that is merely possible.
    ///
    /// Returns the snapshot's short id when one was taken. `None` covers
    /// every reason there is no snapshot — restic not installed, the engine
    /// switched off, the site having no document tree — because the caller
    /// does the same thing with all of them.
    pub async fn snapshot_before_change(
        &self,
        detail: &HostingDetail,
        tag: &str,
    ) -> Option<String> {
        use hyperion_adapters::restic;
        if !self.snapshots_enabled || !self.protection_mode_now().takes_snapshots() {
            return None;
        }
        let root = detail.root_dir.trim();
        if root.is_empty() {
            return None;
        }
        if !restic::available().await {
            // Said once per attempt at debug: an operator who has not opted
            // in should not have their journal filled with it.
            tracing::debug!("snapshots: restic is not installed on this node");
            return None;
        }
        // One restic operation per site at a time: a snapshot, a restore, a
        // delete and the retention sweep all need the repository, and restic's
        // own lock makes the loser fail rather than wait.
        let site_lock = snapshot_lock(&detail.id);
        let _one_at_a_time = site_lock.lock().await;
        let repo = match restic::ensure_repo(restic::REPO_BASE, detail.id.as_str()).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e, "snapshots: repository unavailable");
                return None;
            }
        };
        // The DATABASE, staged beside the repositories so it goes into the
        // same snapshot as the files.
        //
        // Without this a snapshot is half a site. Restoring files alone onto a
        // WordPress database that has moved on gives a site that is broken in
        // a way nobody asked for — and this is the copy the panel offers to
        // roll back to after an update, which is exactly when the two are most
        // likely to have diverged.
        //
        // Best-effort, like everything else here: a site whose dump failed
        // still gets its files snapshotted and still gets its security update.
        // What must NOT happen is a snapshot that silently claims to hold a
        // database it does not, so the tag records which kind this is and
        // `snapshot_list` reports it.
        let mut paths = vec![root.to_string()];
        let mut has_db = false;
        // A token unique to THIS run, so two overlapping snapshots of the same
        // site cannot write the same dump file.
        let run_token = blake3::hash(format!("{}-{}", detail.id.as_str(), now_secs()).as_bytes())
            .to_hex()[..16]
            .to_string();
        let mut staged_dump: Option<std::path::PathBuf> = None;
        if let Some(db) = detail.database.as_ref() {
            match restic::ensure_db_stage(detail.id.as_str(), &run_token).await {
                Ok(dump_path) => {
                    let dumped = match db.engine {
                        hyperion_types::DbProvision::MariaDB => {
                            hyperion_adapters::backup::dump_mariadb(&db.db_name, &dump_path).await
                        }
                        hyperion_types::DbProvision::Postgres => {
                            hyperion_adapters::backup::dump_postgres(&db.db_name, &dump_path).await
                        }
                    };
                    match dumped {
                        Ok(_) => {
                            paths.push(dump_path.display().to_string());
                            staged_dump = Some(dump_path);
                            has_db = true;
                        }
                        Err(e) => {
                            tracing::warn!(
                                domain = %detail.domain, error = %e,
                                "snapshots: database dump failed, snapshotting files only"
                            );
                            restic::clear_db_stage(&dump_path).await;
                        }
                    }
                }
                Err(e) => tracing::warn!(
                    domain = %detail.domain, error = %e,
                    "snapshots: could not stage a database dump, snapshotting files only"
                ),
            }
        }
        // A second tag, so a restore can tell from the snapshot LIST whether
        // there is a database in it without fetching the file list first.
        let mut tags: Vec<&str> = vec![tag];
        if has_db {
            tags.push(restic::TAG_WITH_DB);
        }
        let result = restic::backup(&repo, &paths, &tags).await;
        // Before anything else can fail: the dump is a plaintext copy of the
        // customer's database and must not outlive the call that made it.
        if let Some(p) = staged_dump.as_deref() {
            restic::clear_db_stage(p).await;
        }
        match result {
            Ok(id) => {
                tracing::info!(domain = %detail.domain, snapshot = %id, tag, "snapshots: taken");
                // Retention straight after the snapshot as well as on the daily
                // sweep: this is the moment the repository just grew.
                if let Err(e) = self.apply_snapshot_retention_held(&repo, detail).await {
                    tracing::warn!(domain = %detail.domain, error = %e, "snapshots: retention failed");
                }
                Some(id)
            }
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e, "snapshots: backup failed");
                None
            }
        }
    }

    /// Snapshots this site has, newest last.
    pub async fn snapshot_list(
        &self,
        sel: HostingSelector,
    ) -> Result<Vec<hyperion_types::SnapshotSummary>, RpcError> {
        use hyperion_adapters::restic;
        let detail = self.get(sel).await?;
        if !restic::available().await {
            return Ok(Vec::new());
        }
        let repo = restic::Repo::for_hosting(restic::REPO_BASE, detail.id.as_str());
        // A site that has never been snapshotted has no repository, and that
        // is not an error — it is the answer "none yet".
        if !tokio::fs::try_exists(&repo.password_file)
            .await
            .unwrap_or(false)
        {
            return Ok(Vec::new());
        }
        let rows = restic::snapshots(&repo)
            .await
            .map_err(|e| RpcError::Internal_with(format!("snapshot list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|s| hyperion_types::SnapshotSummary {
                id: s.id,
                time: s.time,
                tags: s.tags,
            })
            .collect())
    }

    /// The node's `[protection] mode`, read from agent.toml NOW.
    ///
    /// Read live rather than once at boot: the setting was saved from the
    /// panel, pushed to every node, and never read by the running service —
    /// the switch from #150 did nothing until this. A node without a config
    /// path (tests) keeps what it was built with.
    pub(super) fn protection_mode_now(&self) -> hyperion_types::ProtectionMode {
        match self.agent_config_path.as_deref() {
            Some(path) => hyperion_types::ProtectionMode::parse(
                &read_cluster_section(Some(path)).protection_mode,
            ),
            None => self.protection_mode,
        }
    }

    /// How long this node keeps snapshots, read from agent.toml now.
    pub(super) fn snapshot_retention_now(&self) -> hyperion_types::SnapshotRetention {
        match self.agent_config_path.as_deref() {
            Some(path) => read_snapshot_retention(Some(path)),
            None => hyperion_types::SnapshotRetention::default(),
        }
    }

    /// Apply the retention rule to one repository. The caller holds the
    /// site's snapshot lock. Returns how many snapshots it deleted.
    pub(super) async fn apply_snapshot_retention_held(
        &self,
        repo: &hyperion_adapters::restic::Repo,
        detail: &HostingDetail,
    ) -> Result<usize, RpcError> {
        let rule = self.snapshot_retention_now();
        if rule.keep_days == 0 {
            return Ok(0);
        }
        let listed = snapshot_summaries(repo).await?;
        let expired: Vec<String> = rule
            .expired(&listed, now_secs())
            .into_iter()
            .map(|s| s.id.clone())
            .collect();
        if expired.is_empty() {
            return Ok(0);
        }
        forget_with_unlock(repo, &expired).await?;
        tracing::info!(
            domain = %detail.domain, deleted = expired.len(),
            keep_days = rule.keep_days, keep_last = rule.keep_last,
            "snapshots: retention deleted old snapshots"
        );
        Ok(expired.len())
    }

    /// Everything the Snapshots section needs, from this (the owning) node.
    pub async fn snapshot_overview(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::SnapshotOverview, RpcError> {
        use hyperion_adapters::restic;
        let detail = self.get(sel).await?;
        let mode = self.protection_mode_now();
        let installed = restic::available().await;
        let engine = if !installed {
            "not_installed"
        } else if !self.snapshots_enabled {
            "disabled"
        } else if !mode.takes_snapshots() {
            "mode_off"
        } else {
            "ready"
        };
        let repo = restic::Repo::for_hosting(restic::REPO_BASE, detail.id.as_str());
        let has_repo = tokio::fs::try_exists(&repo.password_file)
            .await
            .unwrap_or(false);
        let (snapshots, repo_bytes) = if installed && has_repo {
            (
                snapshot_summaries(&repo).await?,
                restic::repo_size(&repo).await,
            )
        } else {
            (Vec::new(), 0)
        };
        Ok(hyperion_types::SnapshotOverview {
            snapshots,
            engine: engine.to_string(),
            protection_mode: mode.as_str().to_string(),
            retention: self.snapshot_retention_now(),
            repo_bytes,
        })
    }

    /// Delete snapshots of one site: the listed ids, or every one of them.
    ///
    /// Checked afterwards, not trusted: restic exits 0 for an id it does not
    /// recognise, so "deleted" is only reported once a fresh listing no longer
    /// has them. Returns how many were deleted.
    pub async fn snapshot_delete(
        &self,
        sel: HostingSelector,
        ids: Vec<String>,
        all: bool,
    ) -> Result<u32, RpcError> {
        use hyperion_adapters::restic;
        let detail = self.get(sel).await?;
        if !all && ids.is_empty() {
            return Err(RpcError::Validation {
                message: "no snapshot was selected".into(),
            });
        }
        for id in &ids {
            if !restic::is_snapshot_id(id) {
                return Err(RpcError::Validation {
                    message: format!("not a snapshot id: {id:?}"),
                });
            }
        }
        if !restic::available().await {
            return Err(RpcError::Validation {
                message: "restic is not installed on the node that owns this site".into(),
            });
        }
        let repo = restic::Repo::for_hosting(restic::REPO_BASE, detail.id.as_str());
        if !tokio::fs::try_exists(&repo.password_file)
            .await
            .unwrap_or(false)
        {
            return Err(RpcError::NotFound {
                kind: "snapshot".into(),
                id: detail.domain.clone(),
            });
        }
        let site_lock = snapshot_lock(&detail.id);
        let _one_at_a_time = site_lock.lock().await;
        // Clear a stale lock if a previous killed-mid-prune left one — otherwise
        // the operator's retry cannot even list, let alone prune.
        let listed = list_with_unlock(&repo).await?;
        let targets: Vec<String> = if all {
            listed.iter().map(|s| s.id.clone()).collect()
        } else {
            let mut t = Vec::new();
            for id in &ids {
                // Matched against the listing, so a stale page asking for a
                // snapshot that is already gone gets told so.
                match listed.iter().find(|s| &s.id == id) {
                    Some(s) => t.push(s.id.clone()),
                    None => {
                        return Err(RpcError::NotFound {
                            kind: "snapshot".into(),
                            id: id.clone(),
                        })
                    }
                }
            }
            t
        };
        if targets.is_empty() {
            // Nothing left to forget — which is also what a retry sees after a
            // delete that forgot everything and then failed while pruning. So
            // prune on its own, or that space is never freed.
            if all {
                prune_with_unlock(&repo).await?;
            }
            return Ok(0);
        }
        if let Err(e) = forget_with_unlock(&repo, &targets).await {
            // restic forgets first and prunes second. If the prune is what
            // failed, the snapshots ARE gone: record that, and say the space
            // was not freed, rather than report a delete that did not happen.
            let still_there = snapshot_summaries(&repo).await.unwrap_or_default();
            let removed: Vec<&String> = targets
                .iter()
                .filter(|t| !still_there.iter().any(|s| &s.id == *t))
                .collect();
            if removed.is_empty() {
                return Err(e);
            }
            self.append_audit(
                "hosting.snapshot.delete",
                Some(detail.id.as_str()),
                &serde_json::json!({
                    "domain": detail.domain,
                    "all": all,
                    "snapshots": removed,
                    "space_reclaimed": false,
                })
                .to_string(),
                "warn",
            )
            .await;
            // The retry advice depends on which delete this was. Telling a
            // SINGLE-snapshot delete to "delete all again" would destroy every
            // remaining snapshot — the one "delete all" control wipes the site.
            // And the daily retention sweep only prunes when a snapshot expires,
            // so it is not a reliable retry on a keep_days=0 (never-expire) site;
            // do not promise it.
            let retry = if all {
                "Click Delete all snapshots again to retry — it now clears any \
                 stale lock and reclaims the space."
            } else {
                "The space is reclaimed the next time this site's repository is \
                 pruned — another delete here, or the retention sweep once a \
                 snapshot expires."
            };
            return Err(RpcError::Internal_with(format!(
                "{} snapshot(s) were deleted, but reclaiming their disk space failed ({e}). {retry}",
                removed.len()
            )));
        }
        let remaining = snapshot_summaries(&repo).await?;
        let survivors: Vec<&str> = remaining
            .iter()
            .filter(|s| targets.contains(&s.id))
            .map(|s| s.id.as_str())
            .collect();
        if !survivors.is_empty() {
            return Err(RpcError::Internal_with(format!(
                "restic reported success, but these snapshots are still there: {}",
                survivors.join(", ")
            )));
        }
        self.append_audit(
            "hosting.snapshot.delete",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "all": all,
                "snapshots": targets,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(targets.len() as u32)
    }

    /// Apply snapshot retention to every site on this node that has a
    /// repository. Daily, from the agent: without it a site that takes no new
    /// snapshots (no pending updates) never has an old one deleted. Returns
    /// how many snapshots it deleted.
    pub async fn snapshot_retention_tick(&self) -> Result<usize, RpcError> {
        use hyperion_adapters::restic;
        if self.snapshot_retention_now().keep_days == 0 || !restic::available().await {
            return Ok(0);
        }
        let mut deleted = 0usize;
        for h in self.list().await? {
            let repo = restic::Repo::for_hosting(restic::REPO_BASE, h.id.as_str());
            if !tokio::fs::try_exists(&repo.password_file)
                .await
                .unwrap_or(false)
            {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(h.id.clone())).await else {
                continue;
            };
            let site_lock = snapshot_lock(&detail.id);
            let _one_at_a_time = site_lock.lock().await;
            match self.apply_snapshot_retention_held(&repo, &detail).await {
                Ok(n) => deleted += n,
                Err(e) => tracing::warn!(
                    domain = %detail.domain, error = %e,
                    "snapshots: retention sweep failed for this site"
                ),
            }
        }
        Ok(deleted)
    }

    /// The safety snapshot a restore takes, WITHOUT the retention prune.
    ///
    /// `snapshot_before_change` prunes immediately after taking one, which is
    /// right everywhere else — it is the only moment we know the repository
    /// grew. During a restore it is not: adding one more snapshot can push the
    /// oldest past `keep_last`, and the one that falls off could be the one
    /// being restored. Retention resumes with the next ordinary snapshot.
    pub(super) async fn snapshot_for_restore(&self, detail: &HostingDetail) -> Option<String> {
        use hyperion_adapters::restic;
        if !self.snapshots_enabled || !restic::available().await {
            return None;
        }
        let root = detail.root_dir.trim();
        if root.is_empty() {
            return None;
        }
        let repo = restic::ensure_repo(restic::REPO_BASE, detail.id.as_str())
            .await
            .ok()?;
        restic::backup_no_prune(&repo, &[root.to_string()], &["pre-restore"])
            .await
            .ok()
            .filter(|id| !id.is_empty())
    }

    /// Move the restored database dump out of the tenant's tree.
    ///
    /// Returns the root-owned path it now lives at, or `None` when the
    /// snapshot carried no dump. The staging tree is inside a directory the
    /// site's own user owns, so a dump left there is one they can read and —
    /// far worse — one they can REPLACE before it is fed to the database
    /// superuser. Located by scanning rather than by a predicted filename,
    /// because the name carries a per-run token.
    pub(super) async fn lift_restored_dump(
        &self,
        staging: &std::path::Path,
        hosting_id: &str,
        token: &str,
    ) -> Result<Option<std::path::PathBuf>, String> {
        use hyperion_adapters::restic;
        let from_dir = join_absolute(
            staging,
            &restic::db_stage_dir(hosting_id).display().to_string(),
        );
        let Some(src) = find_restored_dump(&from_dir).await else {
            return Ok(None);
        };
        // SECURITY (TOCTOU): the staging directory sits INSIDE the site
        // directory, which the site's own unix user owns — so between restic
        // writing the dump and this read, the tenant can rename staging aside
        // and drop their OWN `<token>.sql` at the same path. Imported, it would
        // run as the database superuser (a tenant -> DB-admin / cross-tenant
        // escalation). Copying to a root-owned directory protects the copy's
        // DESTINATION but not its SOURCE, so it is not enough on its own.
        //
        // Defence: open the file by a descriptor and verify THROUGH that
        // descriptor that it is a regular file owned by ROOT (uid 0). restic
        // restores the dump with the uid it carries in the snapshot, which is 0
        // because hyperion stages every dump under a root-only /var/lib path;
        // an unprivileged tenant cannot create a root-owned file. The copy then
        // streams from this same descriptor, so the check and the read see one
        // inode — a swapped-in tenant dump (uid != 0) is refused.
        use tokio::io::AsyncWriteExt;
        let mut src_file = open_root_owned_dump(&src).await?;
        let dst = restic::ensure_db_stage(hosting_id, &format!("restore-{token}"))
            .await
            .map_err(|e| e.to_string())?;
        // A stream copy from the verified descriptor, not a rename: /var/lib and
        // /home are routinely separate filesystems and a cross-device rename
        // simply fails. Reading the fd (not the path again) keeps the ownership
        // check and the copy on the same inode.
        let mut dst_file = tokio::fs::File::create(&dst)
            .await
            .map_err(|e| format!("create dump copy: {e}"))?;
        tokio::io::copy(&mut src_file, &mut dst_file)
            .await
            .map_err(|e| format!("copy dump: {e}"))?;
        dst_file
            .flush()
            .await
            .map_err(|e| format!("flush dump copy: {e}"))?;
        Ok(Some(dst))
    }

    /// A root-owned directory to park the tree a restore replaced.
    ///
    /// On the same filesystem as the site so the move is a rename, and OUTSIDE
    /// the site directory so the permission repair never walks it and the
    /// tenant's disk quota never counts it.
    pub(super) async fn quarantine_dir(
        &self,
        detail: &HostingDetail,
        stamp: i64,
    ) -> Result<std::path::PathBuf, String> {
        let base = std::path::Path::new(&self.paths.home_root).join(".hyperion-replaced");
        tokio::fs::create_dir_all(&base)
            .await
            .map_err(|e| format!("create {}: {e}", base.display()))?;
        set_dir_mode(&base, 0o700).await?;
        Ok(base.join(format!("{}-{stamp}", detail.id.as_str())))
    }

    /// Put a snapshot back.
    ///
    /// # Why this REPLACES the tree instead of restoring over it
    ///
    /// `restic restore` writes the snapshot's files into the target and leaves
    /// everything else alone, so restoring a pre-compromise snapshot over a
    /// hacked site keeps every dropped backdoor — and the panel would report
    /// success. That is not a restore; it is a state the site was never in.
    /// So the snapshot is restored into a staging directory, the live tree is
    /// moved ASIDE (not deleted — a restore is itself destructive and the
    /// operator may have picked the wrong one), and the restored tree is moved
    /// into its place.
    ///
    /// Staging lives INSIDE the site directory, because the swap is two
    /// renames and a rename cannot cross a filesystem: `/var/lib` and `/home`
    /// are routinely separate mounts. That means creating a directory in a
    /// tree the tenant owns, so it is created with `create_dir` and an
    /// unpredictable name — `create_dir` fails outright if the path already
    /// exists, symlink included, which is exactly the pre-planted-symlink
    /// attack it has to refuse.
    ///
    /// # Ownership
    ///
    /// restic restores the uid/gid recorded in the snapshot. A site whose uid
    /// has changed since — a rebuild, an import, a move between nodes — would
    /// come back owned by a user that no longer maps to it: PHP could not
    /// write, and the site would 403. The tree is therefore re-owned
    /// afterwards, the same way the archive restore does it.
    pub async fn snapshot_restore(
        &self,
        sel: HostingSelector,
        snapshot: String,
        mode: hyperion_types::BackupRestoreMode,
    ) -> Result<hyperion_types::SnapshotRestoreOutcome, RpcError> {
        let detail = self.get(sel).await?;
        // Held for the whole restore, safety snapshot included: the daily
        // retention sweep must not delete the snapshot being put back.
        let site_lock = snapshot_lock(&detail.id);
        let _one_at_a_time = site_lock.lock().await;

        let plan = snapshot_restore_preflight(&detail, &snapshot, mode).await?;

        // A restore is destructive, so the state being replaced gets its own
        // snapshot first. Best-effort by design — refusing to restore because
        // the safety snapshot failed would block the operator at the exact
        // moment they are trying to fix a broken site — but it is REPORTED,
        // so "we kept a copy" and "we could not" never look the same.
        //
        // Deliberately NOT the pruning variant: taking one more snapshot can
        // push the oldest past `keep_last`, and the one it deletes could be
        // the one being restored. Retention resumes with the next ordinary
        // snapshot.
        let safety = self.snapshot_for_restore(&detail).await;

        check_restore_space(&plan).await?;
        let stamp = now_secs();
        let staging = make_restore_staging(&plan.site_dir, detail.id.as_str(), stamp).await?;
        let staged = self
            .restore_from_staging(&detail, &plan, &snapshot, mode, &staging, stamp)
            .await;
        // Every exit path, and idempotent: the success path has already
        // removed it before the permission repair (see restore_from_staging).
        let _ = tokio::fs::remove_dir_all(&staging).await;
        let (secure_dump, kept_aside) = staged?;

        let mut db_restored = false;
        if let (Some(db), Some(dump)) = (detail.database.as_ref(), secure_dump.as_deref()) {
            self.import_restored_dump(
                &detail,
                db,
                dump,
                &plan,
                &snapshot,
                mode,
                kept_aside.as_deref(),
            )
            .await?;
            db_restored = true;
        }

        self.append_audit(
            "hosting.snapshot_restore",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "snapshot": snapshot,
                "mode": mode.as_str(),
                "files_restored": mode.restores_files(),
                "db_restored": db_restored,
                "safety_snapshot": safety,
                "previous_site_kept_at": kept_aside,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::SnapshotRestoreOutcome {
            snapshot,
            files_restored: mode.restores_files(),
            db_restored,
            safety_snapshot: safety.unwrap_or_default(),
            previous_site_kept_at: kept_aside.unwrap_or_default(),
        })
    }

    /// restic into `staging`, the database dump lifted out of the tenant's
    /// tree, and — when files are restored — the swap. Returns the lifted
    /// dump and where the replaced tree was kept. A dump already lifted is
    /// cleared again if a later step fails.
    pub(super) async fn restore_from_staging(
        &self,
        detail: &HostingDetail,
        plan: &SnapshotRestorePlan,
        snapshot: &str,
        mode: hyperion_types::BackupRestoreMode,
        staging: &std::path::Path,
        stamp: i64,
    ) -> Result<(Option<std::path::PathBuf>, Option<String>), RpcError> {
        use hyperion_adapters::restic;
        restic::restore(&plan.repo, snapshot, &staging.display().to_string())
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "restic_restore".into(),
                reason: e.to_string(),
            })?;

        // Get the dump OUT of the tenant's tree before anything else happens.
        //
        // site_dir belongs to the site's own unix user, so while the dump sits
        // under it they can rename the staging directory and put their own
        // file at that path. Importing it later would run their SQL as the
        // database superuser. Copying it to a root-owned directory no tenant
        // can reach removes the whole class: after this, the path being
        // imported is one nobody but root has ever been able to write.
        let mut secure_dump: Option<std::path::PathBuf> = None;
        if mode.restores_db() && detail.database.is_some() {
            match self
                .lift_restored_dump(staging, detail.id.as_str(), &stamp.to_string())
                .await
            {
                Ok(Some(p)) => secure_dump = Some(p),
                Ok(None) => {
                    return Err(RpcError::Validation {
                        message: format!(
                            "snapshot {snapshot} holds no database dump — restore the files \
                             only, or use a backup archive."
                        ),
                    })
                }
                Err(e) => return Err(RpcError::Internal_with(format!("restore dump: {e}"))),
            }
        }

        if !mode.restores_files() {
            return Ok((secure_dump, None));
        }
        match self
            .swap_in_restored_tree(detail, plan, snapshot, staging, stamp)
            .await
        {
            Ok(kept_aside) => Ok((secure_dump, kept_aside)),
            Err(e) => {
                // A plaintext copy of the customer's database must not
                // outlive the restore that wanted it.
                if let Some(dump) = secure_dump.as_deref() {
                    restic::clear_db_stage(dump).await;
                }
                Err(e)
            }
        }
    }

    /// Replace the live document root with the restored one. Returns where
    /// the replaced tree was kept (`None` when there was none).
    pub(super) async fn swap_in_restored_tree(
        &self,
        detail: &HostingDetail,
        plan: &SnapshotRestorePlan,
        snapshot: &str,
        staging: &std::path::Path,
        stamp: i64,
    ) -> Result<Option<String>, RpcError> {
        let root = plan.root.as_str();
        // restic reproduces ABSOLUTE paths under the target, so the files are
        // at <staging><root>.
        let restored_root = join_absolute(staging, root);
        if !tokio::fs::try_exists(&restored_root).await.unwrap_or(false) {
            return Err(RpcError::Validation {
                message: format!(
                    "snapshot {snapshot} does not contain {root} — it may belong to a site \
                     whose document root has since moved"
                ),
            });
        }
        // The replaced tree goes OUTSIDE site_dir, into a root-owned
        // quarantine on the same filesystem.
        //
        // Leaving it beside the new one looked tidier and was wrong twice
        // over: `repair_tree_permissions` walks the whole site dir, so it
        // would publish the old wp-config.php to every local user at 0644
        // and keep it that way for ever; and the tree stays owned by the
        // site user, so it counts against the disk quota and can trip the
        // overage suspend on a site that has just been repaired.
        let aside = self
            .quarantine_dir(detail, stamp)
            .await
            .map_err(|e| RpcError::Internal_with(format!("restore quarantine: {e}")))?;
        // A site whose document root is gone is exactly the site somebody
        // is trying to restore. Nothing to move aside is not an error.
        let had_root = tokio::fs::try_exists(root).await.unwrap_or(false);
        if had_root {
            if let Err(e) = tokio::fs::rename(root, &aside).await {
                return Err(RpcError::ProvisioningFailed {
                    stage: "restore_swap".into(),
                    reason: format!("could not move the current site aside: {e}"),
                });
            }
        }
        if let Err(e) = tokio::fs::rename(&restored_root, root).await {
            // Put it back. Leaving a site with NO document root because
            // the second rename failed is far worse than a failed restore.
            if had_root {
                let _ = tokio::fs::rename(&aside, root).await;
            }
            return Err(RpcError::ProvisioningFailed {
                stage: "restore_swap".into(),
                reason: format!("could not move the restored site into place: {e}"),
            });
        }
        // Staging goes BEFORE the permission repair, not after.
        //
        // The repair walks the whole site directory with chown -R and
        // find -exec chmod, so anything still sitting in staging would be
        // handed to the tenant at 0644 — which for a restored database
        // dump means every other local user can read the customer's data,
        // and the copy this code is about to import would be one the
        // tenant could have rewritten.
        let _ = tokio::fs::remove_dir_all(staging).await;
        // restic restored the snapshot's uid/gid. Re-own before anything
        // tries to serve the site.
        if let Err(e) = repair_tree_permissions(&detail.system_user, &plan.site_dir).await {
            tracing::warn!(domain = %detail.domain, error = %e,
                "snapshot restore: ownership repair failed");
        }
        Ok(had_root.then(|| aside.display().to_string()))
    }

    /// Import the lifted dump, and clear it either way. When the import
    /// fails the files are already swapped, so they are put back: a failed
    /// restore must leave the site as it was rather than half-way between
    /// two states — new files against an old schema is a broken site nobody
    /// asked for, and the error message would read as though nothing had
    /// happened.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn import_restored_dump(
        &self,
        detail: &HostingDetail,
        db: &DbSummary,
        dump: &std::path::Path,
        plan: &SnapshotRestorePlan,
        snapshot: &str,
        mode: hyperion_types::BackupRestoreMode,
        kept_aside: Option<&str>,
    ) -> Result<(), RpcError> {
        let imported = match db.engine {
            hyperion_types::DbProvision::MariaDB => {
                hyperion_adapters::backup::restore_mariadb_dump(&db.db_name, dump).await
            }
            hyperion_types::DbProvision::Postgres => {
                hyperion_adapters::backup::restore_postgres_dump(&db.db_name, dump).await
            }
        };
        hyperion_adapters::restic::clear_db_stage(dump).await;
        let Err(e) = imported else {
            return Ok(());
        };
        let root = plan.root.as_str();
        let mut rolled_back = false;
        if let Some(aside) = kept_aside {
            let _ = tokio::fs::remove_dir_all(root).await;
            rolled_back = tokio::fs::rename(aside, root).await.is_ok();
            if rolled_back {
                let _ = repair_tree_permissions(&detail.system_user, &plan.site_dir).await;
            }
        }
        self.append_audit(
            "hosting.snapshot_restore",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "snapshot": snapshot,
                "mode": mode.as_str(),
                "db_error": e.to_string(),
                "files_rolled_back": rolled_back,
                "previous_site_kept_at": kept_aside,
            })
            .to_string(),
            "error",
        )
        .await;
        Err(RpcError::ProvisioningFailed {
            stage: "db_import".into(),
            reason: if rolled_back {
                format!("{e} — the files were put back as they were")
            } else {
                format!(
                    "{e} — WARNING: the files were already replaced and could not \
                     be put back. The previous ones are at {}",
                    kept_aside.unwrap_or("(nowhere)")
                )
            },
        })
    }

    /// What changed between two snapshots — the question an operator asks
    /// every time a site breaks after an update, and the one a `tar.gz`
    /// cannot answer.
    pub async fn snapshot_diff(
        &self,
        sel: HostingSelector,
        from: String,
        to: String,
    ) -> Result<hyperion_types::SnapshotDiff, RpcError> {
        use hyperion_adapters::restic;
        let detail = self.get(sel).await?;
        // Ids come from a form. Restic ids are hex; anything else is either a
        // typo or an attempt to smuggle an argument, and both stop here.
        for id in [&from, &to] {
            if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(RpcError::Validation {
                    message: format!("not a snapshot id: {id:?}"),
                });
            }
        }
        let repo = restic::Repo::for_hosting(restic::REPO_BASE, detail.id.as_str());
        let d = restic::diff(&repo, &from, &to)
            .await
            .map_err(|e| RpcError::Internal_with(format!("snapshot diff: {e}")))?;
        Ok(hyperion_types::SnapshotDiff {
            added: d.added as i64,
            removed: d.removed as i64,
            modified: d.modified as i64,
            sample: d.sample,
        })
    }
}

/// The per-site lock around restic operations.
pub(super) fn snapshot_lock(id: &HostingId) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    let map = LOCKS.get_or_init(Default::default);
    let mut guard = map.lock().unwrap_or_else(|p| p.into_inner());
    guard.entry(id.as_str().to_string()).or_default().clone()
}

/// A repository's snapshots as the panel types them, newest last.
pub(super) async fn snapshot_summaries(
    repo: &hyperion_adapters::restic::Repo,
) -> Result<Vec<hyperion_types::SnapshotSummary>, RpcError> {
    hyperion_adapters::restic::snapshots(repo)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|s| hyperion_types::SnapshotSummary {
                    id: s.id,
                    time: s.time,
                    tags: s.tags,
                })
                .collect()
        })
        .map_err(|e| RpcError::Internal_with(format!("snapshot list: {e}")))
}

/// `forget --prune`, clearing a stale lock and trying once more if a killed
/// restic left one behind.
pub(super) async fn forget_with_unlock(
    repo: &hyperion_adapters::restic::Repo,
    ids: &[String],
) -> Result<(), RpcError> {
    use hyperion_adapters::restic;
    match restic::forget_ids(repo, ids).await {
        Ok(()) => Ok(()),
        Err(e) if restic::is_lock_error(&e) => {
            restic::unlock_stale(repo)
                .await
                .map_err(|e| RpcError::Internal_with(format!("snapshot unlock: {e}")))?;
            restic::forget_ids(repo, ids)
                .await
                .map_err(|e| RpcError::Internal_with(format!("snapshot delete: {e}")))
        }
        Err(e) => Err(RpcError::Internal_with(format!("snapshot delete: {e}"))),
    }
}

/// `prune`, clearing a stale lock and trying once more.
///
/// The delete-all recovery path (a bare prune after a delete that forgot the
/// snapshots and then died before pruning) exists precisely for the
/// killed-mid-prune case — and a killed restic is exactly what leaves the
/// stale lock behind. So this is the one prune that MUST clear the lock, or the
/// operator's "delete all again" retry hits the very lock it is meant to clean
/// up and the repository stays wedged.
pub(super) async fn prune_with_unlock(
    repo: &hyperion_adapters::restic::Repo,
) -> Result<(), RpcError> {
    use hyperion_adapters::restic;
    match restic::prune(repo).await {
        Ok(()) => Ok(()),
        Err(e) if restic::is_lock_error(&e) => {
            restic::unlock_stale(repo)
                .await
                .map_err(|e| RpcError::Internal_with(format!("snapshot unlock: {e}")))?;
            restic::prune(repo)
                .await
                .map_err(|e| RpcError::Internal_with(format!("snapshot prune: {e}")))
        }
        Err(e) => Err(RpcError::Internal_with(format!("snapshot prune: {e}"))),
    }
}

/// List snapshots, clearing a stale lock and trying once more.
///
/// `restic snapshots` takes a shared lock, which a stale EXCLUSIVE lock (left by
/// a killed `forget --prune`) blocks. The delete path lists before it acts, so
/// without this the retry after a killed-mid-prune fails at the listing and
/// never reaches the recovery prune.
pub(super) async fn list_with_unlock(
    repo: &hyperion_adapters::restic::Repo,
) -> Result<Vec<hyperion_types::SnapshotSummary>, RpcError> {
    use hyperion_adapters::restic;
    let map = |rows: Vec<restic::Snapshot>| -> Vec<hyperion_types::SnapshotSummary> {
        rows.into_iter()
            .map(|s| hyperion_types::SnapshotSummary {
                id: s.id,
                time: s.time,
                tags: s.tags,
            })
            .collect()
    };
    match restic::snapshots(repo).await {
        Ok(rows) => Ok(map(rows)),
        Err(e) if restic::is_lock_error(&e) => {
            restic::unlock_stale(repo)
                .await
                .map_err(|e| RpcError::Internal_with(format!("snapshot unlock: {e}")))?;
            restic::snapshots(repo)
                .await
                .map(map)
                .map_err(|e| RpcError::Internal_with(format!("snapshot list: {e}")))
        }
        Err(e) => Err(RpcError::Internal_with(format!("snapshot list: {e}"))),
    }
}

/// `[snapshots] keep_days` / `keep_last` as they are on disk. Absent keys fall
/// back to `[backup_retention]`, which is what snapshots followed before they
/// had their own rule — so an upgrade changes nothing until the operator
/// sets one.
pub(crate) fn read_snapshot_retention(
    cfg_path: Option<&std::path::Path>,
) -> hyperion_types::SnapshotRetention {
    let archives = read_backup_retention_section(cfg_path);
    let fallback = hyperion_types::SnapshotRetention {
        keep_days: archives.max_age_days.clamp(0, 36_500) as u32,
        keep_last: archives.keep_latest_n.clamp(0, 1_000) as u32,
    };
    let Some(doc) = read_agent_doc(cfg_path) else {
        return fallback;
    };
    let sec = doc.get("snapshots");
    let int = |key: &str| {
        sec.and_then(|s| s.get(key))
            .and_then(|v| v.as_integer())
            .map(|v| v.clamp(0, 36_500) as u32)
    };
    hyperion_types::SnapshotRetention {
        keep_days: int("keep_days").unwrap_or(fallback.keep_days),
        keep_last: int("keep_last").unwrap_or(fallback.keep_last),
    }
}

/// What a snapshot restore works on, once the request has been checked.
pub(super) struct SnapshotRestorePlan {
    repo: hyperion_adapters::restic::Repo,
    /// The document root.
    root: String,
    /// Its parent — the site directory, owned by the tenant.
    site_dir: std::path::PathBuf,
}

/// Everything a restore can be refused for before a single byte moves.
pub(super) async fn snapshot_restore_preflight(
    detail: &HostingDetail,
    snapshot: &str,
    mode: hyperion_types::BackupRestoreMode,
) -> Result<SnapshotRestorePlan, RpcError> {
    use hyperion_adapters::restic;
    let refuse = |message: String| Err(RpcError::Validation { message });
    // Ids come from a form. Restic ids are hex; anything else is a typo or
    // an attempt to smuggle an argument (`latest`, `--target`) into a
    // command line, and both stop here.
    if snapshot.is_empty()
        || snapshot.len() > 64
        || !snapshot.chars().all(|c| c.is_ascii_hexdigit())
    {
        return refuse(format!("not a snapshot id: {snapshot:?}"));
    }
    if !restic::available().await {
        return refuse("restic is not installed on the node that owns this site".into());
    }
    let repo = restic::Repo::for_hosting(restic::REPO_BASE, detail.id.as_str());
    if !tokio::fs::try_exists(&repo.password_file)
        .await
        .unwrap_or(false)
    {
        return refuse("this site has no snapshot repository".into());
    }
    let root = detail.root_dir.trim().to_string();
    if root.is_empty() {
        return refuse("this site has no document root".into());
    }
    let Some(site_dir) = std::path::Path::new(&root)
        .parent()
        .map(|p| p.to_path_buf())
    else {
        return refuse(format!("document root {root} has no parent directory"));
    };

    // Does this snapshot HOLD a database, if one was asked for?
    //
    // Asked here, before a single byte moves. The first version of this
    // checked after the swap, which meant the ordinary restore of any
    // snapshot taken before dumps existed replaced the site and THEN
    // reported failure — the operator ends up with a half-restored site
    // and an error message that reads like nothing happened.
    if mode.restores_db() && detail.database.is_some() {
        let listed = restic::snapshots(&repo).await.unwrap_or_default();
        let known = listed
            .iter()
            .find(|s| s.id.starts_with(snapshot) || snapshot.starts_with(&s.id));
        // Not in the list at all: let restic be the judge rather than
        // refusing on our own hand-rolled parse of its output.
        if let Some(s) = known {
            if !s.tags.iter().any(|t| t == restic::TAG_WITH_DB) {
                return refuse(format!(
                    "snapshot {snapshot} holds no database — it was taken before \
                     snapshots included one, or its dump failed. Restore the files \
                     only, or use a backup archive."
                ));
            }
        }
    }
    Ok(SnapshotRestorePlan {
        repo,
        root,
        site_dir,
    })
}

/// Disk: the swap holds the restored tree AND the old one at once. Unknown
/// stays unknown — a missing measurement must not silently become a pass,
/// but neither may it block a restore on a filesystem `df` could not read.
pub(super) async fn check_restore_space(plan: &SnapshotRestorePlan) -> Result<(), RpcError> {
    let need = dir_size_bytes(std::path::Path::new(&plan.root)).await;
    let (Some(need), Some(avail)) = (need, fs_avail_bytes(&plan.site_dir).await) else {
        return Ok(());
    };
    // The restored tree is roughly the size of the current one, and the old
    // one stays beside it until the operator deletes it.
    let want = need.saturating_add(need / 4);
    if avail < want {
        return Err(RpcError::Validation {
            message: format!(
                "not enough free space to restore safely: {} available, about {} needed \
                 to hold the restored site beside the current one",
                human_bytes(avail as i64),
                human_bytes(want as i64),
            ),
        });
    }
    Ok(())
}

/// Staging, created inside the site dir so the swap is two renames.
/// `create_dir`, never `create_dir_all`: it fails if the path exists at all
/// — including as a symlink the site's own user planted first, which is the
/// whole reason the name is unguessable.
pub(super) async fn make_restore_staging(
    site_dir: &std::path::Path,
    hosting_id: &str,
    stamp: i64,
) -> Result<std::path::PathBuf, RpcError> {
    let staging = site_dir.join(format!(
        ".hyperion-restore-{stamp}-{}",
        &blake3::hash(format!("{hosting_id}{stamp}").as_bytes()).to_hex()[..12]
    ));
    tokio::fs::create_dir(&staging).await.map_err(|e| {
        RpcError::Internal_with(format!("restore staging {}: {e}", staging.display()))
    })?;
    // 0700 and root-owned. `create_dir` uses the umask, which on a default
    // 022 is 0755 — and this directory is about to hold a plaintext copy of
    // the customer's database inside a tree every other tenant can reach. An
    // unguessable name is not a substitute for a mode: a 0755 parent is
    // listable.
    if let Err(e) = set_dir_mode(&staging, 0o700).await {
        let _ = tokio::fs::remove_dir_all(&staging).await;
        return Err(RpcError::Internal_with(format!(
            "restore staging {}: {e}",
            staging.display()
        )));
    }
    Ok(staging)
}
