//! Local backups: run, schedule, prune, restore, and the per-hosting cadence
//! settings.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// The full backup taken before an automatic update batch. Local only
    /// (a rollback copy, never pushed off-site or dropped), marked
    /// `pre-update` and HELD from the moment it exists: the sweep releases it
    /// only once every update in the batch went in cleanly, and it is deleted
    /// 24 hours after that. A failed batch — or an agent that died half-way —
    /// keeps it; a site keeps one pre-update backup plus its oldest held one,
    /// which only a clean batch and a week replace (see
    /// `pre_update_due_for_prune`).
    ///
    /// Returns the run id; an error means no usable backup exists and the
    /// caller must not update.
    pub(crate) async fn pre_update_backup(&self, id: &HostingId) -> Result<i64, String> {
        let run = self
            .backup_run_for(
                HostingSelector::Id(id.clone()),
                Vec::new(),
                OffsiteSource::NotWanted,
                None,
                hyperion_state::backups::PURPOSE_PRE_UPDATE,
            )
            .await
            .map_err(|e| e.to_string())?;
        if run.state != "ok" {
            return Err(run
                .error_message
                .unwrap_or_else(|| format!("backup ended in state {}", run.state)));
        }
        Ok(run.id)
    }

    /// Produce a tar.gz + DB dump backup. Single 'local' target for v1.
    ///
    /// The RPC entry point, i.e. every backup a HUMAN asked for: the panel
    /// and the API resolve the cluster's off-site targets on the master
    /// (that is the only node whose `backup_targets` table has any) and send
    /// them with the request, so `s3_targets` is exactly what this run may
    /// upload to. Internal snapshots that were never meant to leave the node
    /// call `backup_run` with `OffsiteSource::NotWanted` instead.
    pub async fn backup_now(
        &self,
        sel: HostingSelector,
        s3_targets: Vec<hyperion_types::S3BackupTarget>,
        progress_job_id: Option<String>,
    ) -> Result<hyperion_types::BackupRunWire, RpcError> {
        self.backup_run(sel, s3_targets, OffsiteSource::Caller, progress_job_id)
            .await
    }

    /// The backup itself. `offsite` says what an EMPTY `s3_targets` means for
    /// this particular run — see `OffsiteSource`, and the honesty rule it
    /// exists to keep: a backup that never left the node must not be
    /// indistinguishable from one that did.
    pub(super) async fn backup_run(
        &self,
        sel: HostingSelector,
        s3_targets: Vec<hyperion_types::S3BackupTarget>,
        offsite: OffsiteSource,
        progress_job_id: Option<String>,
    ) -> Result<hyperion_types::BackupRunWire, RpcError> {
        self.backup_run_for(sel, s3_targets, offsite, progress_job_id, "")
            .await
    }

    /// [`Self::backup_run`] for a run with a `purpose` (migration 083). The
    /// purpose is written — held — the moment the row exists, BEFORE the
    /// prune at the end of the run: written afterwards, the new run would
    /// count once as one of the site's newest backups and could push a real
    /// one past the floor.
    pub(super) async fn backup_run_for(
        &self,
        sel: HostingSelector,
        s3_targets: Vec<hyperion_types::S3BackupTarget>,
        offsite: OffsiteSource,
        progress_job_id: Option<String>,
        purpose: &str,
    ) -> Result<hyperion_types::BackupRunWire, RpcError> {
        let detail = self.get(sel).await?;
        let backup_root = self.paths.backup_root.clone();
        // Publish the phases up front as pending so the progress page shows the
        // whole plan (files → database → off-site), then advance each as we go.
        // Off-site only appears when this run actually has somewhere to send.
        let pj = progress_job_id.as_deref();
        let will_offsite = offsite != OffsiteSource::NotWanted
            && (self.remote_backup.is_some() || !s3_targets.is_empty());
        let mut subs = backup_substeps(detail.database.is_some(), will_offsite);
        self.publish_backup_progress(pj, &subs).await;
        // One stamp for the row AND the file names, so a run that dies
        // leaves files [`Self::remove_dead_run_files`] can find from the row.
        let started = now_secs();
        let run_id = hyperion_state::backups::start(&self.pool, &detail.id, "local", started)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup start: {e}")))?;
        // A rollback snapshot exists to be a LOCAL copy to roll back to. Mark
        // it never-off-site the moment its row exists, so the on-demand
        // "copy off-site, then delete local" action can never push it away or
        // drop the local copy. The fresh-backup path below skips its own FTP
        // push, S3 push and local drop for NotWanted; this protects it from the
        // LATER paths.
        if offsite == OffsiteSource::NotWanted {
            if let Err(e) = hyperion_state::backups::mark_no_offsite(&self.pool, run_id).await {
                tracing::warn!(error = %e, "could not mark rollback snapshot no_offsite");
            }
        }
        if !purpose.is_empty() {
            hyperion_state::backups::set_purpose(&self.pool, run_id, purpose, true)
                .await
                .map_err(|e| RpcError::Internal_with(format!("backup purpose: {e}")))?;
        }
        let files = BackupFiles::new(&backup_root, &detail, started);
        // This run's archive is busy until its own push is done: a backup of
        // the same site finishing meanwhile must not drop it from under the
        // upload. Released just before this run's own drop step below.
        let archive_busy = ArchiveInUse::claim(&files.archive);

        if let Some(msg) = self.backup_disk_shortfall(&detail, &backup_root).await {
            hyperion_state::backups::mark_failed(&self.pool, run_id, &msg, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("mark_failed: {e}")))?;
            return Err(RpcError::ProvisioningFailed {
                stage: "backup".into(),
                reason: msg,
            });
        }

        // Run the backup. Failures roll the row to 'failed'.
        let (archive_bytes, dump_bytes) = match self
            .write_local_backup(&detail, &files, pj, &mut subs)
            .await
        {
            Ok(sizes) => sizes,
            Err(e) => return Err(self.fail_backup_run(run_id, &files, pj, &mut subs, e).await),
        };
        self.record_local_backup(&detail, run_id, &files, archive_bytes, dump_bytes)
            .await?;

        if will_offsite {
            self.bump_substep(pj, &mut subs, "offsite", "running", -1, "")
                .await;
        }
        // Did the off-site copy actually land ANYWHERE? Drives the
        // "offsite" sub-step's terminal state — the push is best-effort
        // and its failures never propagate as Err, so without this the
        // sub-step would show green "done" while the backup row records
        // the copy as failed. Set true only on real evidence: an FTP
        // upload that succeeded (and did not fail re-verify), or at
        // least one S3 target whose push fully succeeded.
        let mut offsite_ok = false;
        // Never for a rollback snapshot (`NotWanted`): its whole purpose is a
        // LOCAL copy to roll back to, and the S3 push and the local drop below
        // already leave it alone — the FTP push used to be the one path that
        // still sent it away.
        if offsite != OffsiteSource::NotWanted {
            if let Some(remote) = self.remote_backup.as_ref() {
                offsite_ok |= self.push_backup_ftp(&detail, run_id, &files, remote).await;
            }
        }
        // The S3 targets this run pushed to (regardless of whether the push
        // reported success — the drop step re-verifies each independently),
        // plus the names of the ones whose push FULLY succeeded. The latter is
        // what makes dropping the local copy safe for age-encrypted targets,
        // whose off-site copy can only be re-checked by existence.
        let (s3_pushed_targets, s3_push_ok) = if offsite != OffsiteSource::NotWanted {
            self.push_backup_s3_for_run(&detail, &files, offsite, &s3_targets)
                .await
        } else {
            (Vec::new(), std::collections::HashSet::new())
        };
        // At least one S3 target whose push FULLY succeeded also counts
        // the off-site copy as landed — and is recorded on the run,
        // because the S3 push writes no `remote_state`: without it an
        // S3-only backup is off-site with nothing on its row to say so.
        if !s3_push_ok.is_empty() {
            offsite_ok = true;
            let names: Vec<String> = s3_push_ok.iter().cloned().collect();
            let _ = hyperion_state::backups::set_s3_ok_targets(&self.pool, run_id, &names).await;
        }
        if will_offsite {
            if offsite_ok {
                self.bump_substep(pj, &mut subs, "offsite", "done", 100, "")
                    .await;
            } else {
                // Best-effort push reached nowhere (unreachable target,
                // bad credentials, an unusable pin, or a failed
                // re-verify). Say so instead of a green "done" that
                // contradicts the backup row.
                self.bump_substep(
                    pj,
                    &mut subs,
                    "offsite",
                    "failed",
                    0,
                    "off-site copy did not succeed — see the Backups tab",
                )
                .await;
            }
        }

        // Drop local copies once they are VERIFIED off-site (global
        // opt-in, off by default) — this run's, and any older local
        // copy of this site that is on record as off-site, past the
        // newest `keep_local_latest` the node keeps. So switching the
        // option on frees a site's older copies at its next backup
        // instead of only ever acting on new ones. Never for
        // `NotWanted` runs — those are the pre-change rollback
        // snapshots, whose whole purpose is a LOCAL copy to roll back
        // to; they were never pushed off-site, so dropping them would
        // delete the only copy (and the sweep skips their rows too).
        // Every copy is re-verified independently before it goes.
        drop(archive_busy);
        if offsite != OffsiteSource::NotWanted {
            let policy = read_local_copy_policy(self.agent_config_path.as_deref());
            if policy.drop {
                let evidence: HashMap<i64, std::collections::HashSet<String>> =
                    std::iter::once((run_id, s3_push_ok)).collect();
                let _ = self
                    .enforce_local_copies(
                        &detail,
                        policy.keep_latest,
                        &s3_pushed_targets,
                        &evidence,
                    )
                    .await;
            }
        }
        // Apply retention policy. Failures are audit-logged but don't
        // propagate — operator still has the just-made backup.
        if let Err(e) = self.prune_old_backups(&detail.id).await {
            tracing::warn!(domain=%detail.domain, error=%e, "backup retention prune failed");
        }

        let rows = hyperion_state::backups::list_for(&self.pool, &detail.id, 1)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list_for: {e}")))?;
        let r = rows.into_iter().next().ok_or(RpcError::Internal {
            message: "row vanished after write (concurrent delete?)".into(),
        })?;
        Ok(run_to_wire(r))
    }

    /// Disk preflight: if the backup volume is too tight, fail fast with a
    /// clear, actionable message BEFORE `tar` writes a truncated archive
    /// that eats the last free bytes. Conservative on purpose — when free
    /// space is this low you want to refuse, not gamble on compression.
    /// Unknown sizes (df/du failed) ⇒ skip the check rather than block.
    pub(super) async fn backup_disk_shortfall(
        &self,
        detail: &HostingDetail,
        backup_root: &str,
    ) -> Option<String> {
        let htdocs = std::path::PathBuf::from(&self.paths.home_root)
            .join(&detail.system_user)
            .join(&detail.domain)
            .join("htdocs");
        let src = dir_size_bytes(&htdocs).await?;
        let avail = fs_avail_bytes(std::path::Path::new(backup_root)).await?;
        // Room for ~the full source (incompressible assets barely
        // shrink) + 256 MiB for the SQL dump and tar's working set.
        let need = src.saturating_add(256 * 1024 * 1024);
        (avail < need).then(|| {
            format!(
                "not enough disk space: backup of {} needs ~{} MiB but only {} MiB \
                 is free on the backup volume — prune old backups or free space first",
                detail.domain,
                need / 1_048_576,
                avail / 1_048_576
            )
        })
    }

    /// Archive htdocs, dump the database when there is one, and write the
    /// manifest beside them. Returns the archive and dump sizes.
    pub(super) async fn write_local_backup(
        &self,
        detail: &HostingDetail,
        files: &BackupFiles,
        pj: Option<&str>,
        subs: &mut [hyperion_types::JobSubstep],
    ) -> Result<(u64, Option<u64>), String> {
        // 1. Archive htdocs (parent of htdocs)
        self.bump_substep(pj, subs, "files", "running", -1, "")
            .await;
        let host_root = std::path::PathBuf::from(&self.paths.home_root)
            .join(&detail.system_user)
            .join(&detail.domain);
        let archive_bytes = hyperion_adapters::backup::make_archive(
            &host_root,
            "htdocs",
            &files.archive,
            Some(&detail.system_user),
        )
        .await
        .map_err(|e| format!("archive: {e}"))?;
        self.bump_substep(
            pj,
            subs,
            "files",
            "done",
            100,
            &human_bytes(archive_bytes as i64),
        )
        .await;
        // 2. Optional DB dump.
        let dump_bytes =
            if let (Some(db), Some(dump_p)) = (detail.database.as_ref(), files.dump.as_ref()) {
                self.bump_substep(pj, subs, "db", "running", -1, "").await;
                let n = match db.engine {
                    hyperion_types::DbProvision::MariaDB => {
                        hyperion_adapters::backup::dump_mariadb(&db.db_name, dump_p).await
                    }
                    hyperion_types::DbProvision::Postgres => {
                        hyperion_adapters::backup::dump_postgres(&db.db_name, dump_p).await
                    }
                };
                let n = n.map_err(|e| format!("db dump: {e}"))?;
                self.bump_substep(pj, subs, "db", "done", 100, &human_bytes(n as i64))
                    .await;
                Some(n)
            } else {
                None
            };
        // 3. Write manifest next to archive.
        let manifest = hyperion_adapters::backup::BackupManifest {
            hosting_id: detail.id.0.clone(),
            domain: detail.domain.clone(),
            system_user: detail.system_user.clone(),
            php_version: detail.php_version.map(|v| v.as_str().to_string()),
            database: detail
                .database
                .as_ref()
                .map(|db| hyperion_adapters::backup::ManifestDb {
                    engine: hyperion_adapters::backup::engine_str(db.engine).to_string(),
                    name: db.db_name.clone(),
                    user: db.db_user.clone(),
                }),
            started_at: files.ts,
            schema_version: 1,
        };
        hyperion_adapters::backup::write_manifest(&manifest, &files.manifest)
            .await
            .map_err(|e| format!("manifest: {e}"))?;
        Ok((archive_bytes, dump_bytes))
    }

    /// Mark the run `ok`, hash the archive and audit it.
    pub(super) async fn record_local_backup(
        &self,
        detail: &HostingDetail,
        run_id: i64,
        files: &BackupFiles,
        archive_bytes: u64,
        dump_bytes: Option<u64>,
    ) -> Result<(), RpcError> {
        let total = archive_bytes as i64 + dump_bytes.unwrap_or(0) as i64;
        let dump_str = files.dump.as_ref().map(|p| p.display().to_string());
        hyperion_state::backups::mark_ok(
            &self.pool,
            run_id,
            &files.archive.display().to_string(),
            dump_str.as_deref(),
            total,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("mark_ok: {e}")))?;
        // Hash it. Until now the entire integrity assurance for a
        // backup was "the file is not zero bytes" — while the
        // MIGRATION path hashes and verifies on the other side. A
        // backup nothing can check is a backup nobody can trust, and
        // `tar tf` does not count: a zero-padded truncation exits 0.
        //
        // Stored with its algorithm in front, because
        // `compute_sha256` computes BLAKE3 and a bare hex string in a
        // column called `sha256_hex` is a lie a future reader would
        // act on.
        let digest = match compute_sha256(&files.archive).await {
            Ok(h) => format!("blake3:{h}"),
            Err(e) => {
                tracing::warn!(domain=%detail.domain, error=%e,
                    "backup: could not hash the archive");
                String::new()
            }
        };
        if !digest.is_empty() {
            let _ = hyperion_state::backups::set_sha256(&self.pool, run_id, &digest).await;
        }
        self.append_audit(
            "hosting.backup",
            Some(detail.id.as_str()),
            &serde_json::json!({"target":"local","bytes":total,"digest":digest}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// A failed run: mark whatever phase was in flight as failed so the
    /// progress page shows WHERE it broke, remove the partial files (a failed
    /// ENOSPC run must not keep eating disk), and fail the row. Returns the
    /// error the caller propagates.
    pub(super) async fn fail_backup_run(
        &self,
        run_id: i64,
        files: &BackupFiles,
        pj: Option<&str>,
        subs: &mut [hyperion_types::JobSubstep],
        error: String,
    ) -> RpcError {
        let trimmed: String = error.chars().take(2000).collect();
        for s in subs.iter_mut() {
            if s.state == "running" || s.state == "pending" {
                s.state = "failed".to_string();
                if s.note.is_empty() {
                    s.note = trimmed.clone();
                }
            }
        }
        self.publish_backup_progress(pj, subs).await;
        let _ = tokio::fs::remove_file(&files.archive).await;
        if let Some(p) = files.dump.as_ref() {
            let _ = tokio::fs::remove_file(p).await;
        }
        let _ = tokio::fs::remove_file(&files.manifest).await;
        if let Err(e) =
            hyperion_state::backups::mark_failed(&self.pool, run_id, &trimmed, now_secs()).await
        {
            return RpcError::Internal_with(format!("mark_failed: {e}"));
        }
        RpcError::ProvisioningFailed {
            stage: "backup".into(),
            reason: trimmed,
        }
    }

    /// Push this run to the agent.toml FTP/SFTP remote. Failures don't roll
    /// back the local backup row — the operator still has the local copy.
    /// Returns whether the copy landed (and was not contradicted by the
    /// re-verify).
    pub(super) async fn push_backup_ftp(
        &self,
        detail: &HostingDetail,
        run_id: i64,
        files: &BackupFiles,
        remote: &RemoteBackupConfig,
    ) -> bool {
        let hosting_dir = format!(
            "{}/{}",
            remote.base_path.trim_end_matches('/'),
            detail.system_user
        );
        let upload = hyperion_adapters::backup::RemoteUpload {
            scheme: &remote.scheme,
            host: &remote.host,
            port: remote.port,
            user: &remote.user,
            password: &remote.password,
            remote_dir: &hosting_dir,
        };
        let archive_result =
            hyperion_adapters::backup::upload_remote(&files.archive, &upload).await;
        let dump_result = match files.dump.as_ref() {
            Some(p) => Some(hyperion_adapters::backup::upload_remote(p, &upload).await),
            None => None,
        };
        let (ok, note) = match (&archive_result, &dump_result) {
            (Ok(_), None) => (true, "archive pushed".to_string()),
            (Ok(_), Some(Ok(_))) => (true, "archive + dump pushed".into()),
            (Ok(_), Some(Err(e))) => (false, format!("archive ok, dump failed: {e}")),
            (Err(e), _) => (false, format!("archive push failed: {e}")),
        };
        // Written to the RUN, not only to the audit log. The audit log is
        // cluster-wide, admin-only and reached from another page; the
        // question "is this backup off-site?" is asked while looking at the
        // backup.
        let blob_key = archive_result.as_deref().unwrap_or("").to_string();
        let _ = hyperion_state::backups::set_remote(
            &self.pool,
            run_id,
            &blob_key,
            if ok { "ok" } else { "failed" },
            if ok { "" } else { &note },
        )
        .await;
        let mut landed = false;
        // And then LOOK. A zero exit from curl says the transfer returned
        // success, not that the bytes are on the far side — and those are
        // different claims, so they get different words: `ok` versus
        // `verified`.
        if ok {
            // Upload returned success — the copy landed, unless the re-verify
            // below positively contradicts it. Both files are checked: the
            // dump is half the backup, and "off-site ✓" must mean what the
            // drop step will later demand before it deletes anything.
            landed = true;
            let (state, vnote) =
                ftp_verify_run(&files.archive, files.dump.as_deref(), &upload).await;
            match state {
                "verified" => {
                    let _ = hyperion_state::backups::set_remote(
                        &self.pool, run_id, &blob_key, "verified", "",
                    )
                    .await;
                }
                "failed" => {
                    // We LOOKED and a file is not there at the right size —
                    // that is a failed off-site copy.
                    landed = false;
                    let _ = hyperion_state::backups::set_remote(
                        &self.pool, run_id, &blob_key, "failed", &vnote,
                    )
                    .await;
                    tracing::warn!(domain=%detail.domain, note=%vnote,
                        "remote backup: upload reported success but a file is not \
                         there at the right size");
                }
                // Could not LOOK is not the same as failed. The row stays
                // `ok` — exactly as strong a claim as the evidence supports.
                _ => {}
            }
            // The FTP keep-latest rule, only once THIS backup is on the
            // server: pruning after a push that did not land would leave the
            // site fewer copies than the rule promises.
            if landed {
                let keep = read_ftp_keep_latest(self.agent_config_path.as_deref());
                match self
                    .prune_ftp_keep_latest(detail, &upload, keep, &files.archive_name)
                    .await
                {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(domain=%detail.domain, pruned=n, keep,
                        "remote backup: older off-site copies pruned"),
                    Err(e) => tracing::warn!(domain=%detail.domain, error=%e,
                        "remote backup: keep-latest prune skipped"),
                }
            }
        }
        self.append_audit(
            "hosting.backup.remote",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "scheme": remote.scheme,
                "host": remote.host,
                "dir": hosting_dir,
                "note": note,
            })
            .to_string(),
            if ok { "ok" } else { "failed" },
        )
        .await;
        if !ok {
            tracing::warn!(domain=%detail.domain, note=%note, "remote backup push failed");
        }
        landed
    }

    /// Off-site S3 push (encrypted with age when a recipient is set,
    /// streamed so it needs no extra local disk). Best-effort — never rolls
    /// back the local backup. A hosting pinned to one target (a client who
    /// pays for their own vault) goes there and nowhere else; an unpinned
    /// one goes to every target the caller resolved, as it always has.
    /// Re-pinning only redirects NEW backups — whatever the site already put
    /// on its old target stays there until that target's own retention
    /// drops it.
    ///
    /// Every way of NOT uploading ends in an audit row, except the two that
    /// promised nothing (see `OffsiteSource` and `offsite_gap_reason`). A
    /// local-only copy of a backup the customer pays to have off-site is the
    /// failure this is here to make visible: it has no other symptom until
    /// the day the node is gone and someone goes looking for the archive.
    ///
    /// Returns the targets pushed to and the names whose push fully
    /// succeeded.
    pub(super) async fn push_backup_s3_for_run<'t>(
        &self,
        detail: &HostingDetail,
        files: &BackupFiles,
        offsite: OffsiteSource,
        s3_targets: &'t [hyperion_types::S3BackupTarget],
    ) -> (
        Vec<&'t hyperion_types::S3BackupTarget>,
        std::collections::HashSet<String>,
    ) {
        let mut paths: Vec<std::path::PathBuf> = vec![files.archive.clone()];
        if let Some(p) = files.dump.as_ref() {
            paths.push(p.clone());
        }
        paths.push(files.manifest.clone());
        let mut pushed: Vec<&'t hyperion_types::S3BackupTarget> = Vec::new();
        let mut ok = std::collections::HashSet::new();
        let pin = self.offsite_pin(detail.id.as_str()).await;
        match choose_offsite_targets(pin.as_deref(), s3_targets) {
            OffsiteChoice::NodeDefault(t) => {
                ok.extend(self.push_backup_to_s3(detail, &paths, t).await);
                // Borrow the caller's `s3_targets`, not the `pin`-lifetime-tied
                // slice the enum handed back — the result outlives `pin`.
                pushed.extend(s3_targets.iter());
            }
            OffsiteChoice::Pinned(t) => {
                ok.extend(
                    self.push_backup_to_s3(detail, &paths, std::slice::from_ref(t))
                        .await,
                );
                // Same reason: re-borrow the one element out of `s3_targets`
                // by identity, so the reference isn't tied to `pin`.
                if let Some(row) = s3_targets.iter().find(|x| std::ptr::eq(*x, t)) {
                    pushed.push(row);
                }
            }
            OffsiteChoice::Unresolved(name) => {
                // Same outcome — nothing uploaded — but the two ways of
                // getting here need opposite fixes, so the row has to carry
                // which one it was. A pin that named a target this run could
                // not use is the operator's to repair; a run that carried no
                // targets at all is not a broken pin, and sending them after
                // the bucket's credentials would waste their afternoon on a
                // bug that isn't there.
                let why = if s3_targets.is_empty() {
                    self.offsite_gap_reason(offsite).unwrap_or(
                        "this backup run carried no off-site targets at all, so the \
                         target this site is pinned to could not be used",
                    )
                } else {
                    "the pinned target was not among the ones this run could use \
                     (disabled, deleted, renamed, or its credentials did not read) — \
                     nothing was uploaded, because a bucket nobody chose is not a \
                     substitute for the one that was"
                };
                tracing::warn!(
                    domain = %detail.domain,
                    target = %name,
                    reason = why,
                    "off-site copy did NOT happen for a site pinned to a target"
                );
                self.audit_s3(detail, name, false, why).await;
            }
            OffsiteChoice::NoTargets => {
                // Unpinned, and this run has nowhere to push. Only a row when
                // something was in fact promised — an install with no
                // off-site configured would otherwise collect a red row per
                // backup for a copy nobody asked for, which is how a real one
                // stops being read.
                if let Some(why) = self.offsite_gap_reason(offsite) {
                    self.audit_s3(detail, "(none)", false, why).await;
                }
            }
        }
        (pushed, ok)
    }

    /// The off-site target this hosting is pinned to, or `None` when it
    /// follows the node default. Lives in the OWNING node's `hosting_kv`
    /// beside the backup cadence, because that's where the backup actually
    /// runs. A blank value reads as unpinned, so clearing the picker is
    /// indistinguishable from never having set it.
    pub(super) async fn offsite_pin(&self, hosting_id: &str) -> Option<String> {
        hyperion_state::hosting_kv::get(&self.pool, hosting_id, BACKUP_KV_TARGET)
            .await
            .ok()
            .flatten()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// Why a run that pushed nothing off-site is worth recording — or `None`
    /// when nothing was missing.
    ///
    /// The whole question is what an EMPTY target list means, and only the
    /// caller plus this node's own identity can answer it. A backup the panel
    /// asked for carries the targets the master resolved, so empty means the
    /// operator has none that can take a copy — which the Backups card
    /// already says in as many words. A SCHEDULED run reads this node's own
    /// table, and on a worker that table is empty by design: there, empty
    /// does not mean "no off-site wanted", it means the cluster's targets
    /// never reached the run, while the panel goes on offering this site's
    /// owner a destination.
    pub(super) fn offsite_gap_reason(&self, source: OffsiteSource) -> Option<&'static str> {
        match source {
            // Once the master's settings sync has reached this worker, an
            // empty list means the same as on the master: no target exists.
            OffsiteSource::ThisNode
                if self.is_worker_node() && self.cluster_sync_state().is_none() =>
            {
                Some(OFFSITE_WORKER_HAS_NO_TARGETS)
            }
            OffsiteSource::ThisNode | OffsiteSource::Caller | OffsiteSource::NotWanted => None,
        }
    }

    /// Push the just-made backup files to every S3 target the master resolved
    /// and passed in (secret inline). Works the same whether this node is the
    /// master or a worker — the targets table only lives on the master, so the
    /// targets travel in the BackupNow request rather than being read from this
    /// node's (possibly empty) DB. Best-effort: uploads each file (age-encrypted
    /// + streamed when a recipient is set), prunes the remote to the newest
    /// `retention_daily` backups, and audits one row per target. Never errors.
    ///
    /// Returns the evidence keys (`s3_evidence_key`: name + a fingerprint of
    /// endpoint, bucket and age recipient) of the targets whose push FULLY
    /// succeeded (every file uploaded). The drop-local step needs this for age-encrypted targets:
    /// their off-site copy can only be re-verified by EXISTENCE (the ciphertext
    /// size cannot match the plaintext), and an age stream that dies part-way
    /// can leave a non-empty but truncated — undecryptable — object behind
    /// while `upload_s3` returns `Err`. Pairing "the push returned Ok" (age
    /// exited 0 ⇒ the whole ciphertext was streamed) with "the object exists"
    /// closes that hole. Unencrypted / FTP don't need it — their independent
    /// size check already catches a short copy.
    pub(super) async fn push_backup_to_s3(
        &self,
        detail: &hyperion_types::HostingDetail,
        files: &[std::path::PathBuf],
        targets: &[hyperion_types::S3BackupTarget],
    ) -> Vec<String> {
        let mut fully_ok: Vec<String> = Vec::new();
        for row in targets {
            let target = hyperion_adapters::backup::S3UploadTarget {
                endpoint: &row.endpoint,
                bucket: &row.bucket,
                region: &row.region,
                access_key_id: &row.access_key_id,
                secret_access_key: &row.secret_access_key,
                age_recipient: row.age_recipient.as_deref(),
            };
            // Keys live under <system_user>/ ; the trailing slash keeps the
            // prune listing scoped to exactly this hosting's objects.
            let prefix = format!("{}/", detail.system_user);
            let mut ok = true;
            let mut notes: Vec<String> = Vec::new();
            for f in files {
                let fname = f.file_name().and_then(|n| n.to_str()).unwrap_or("backup");
                let key = format!("{prefix}{fname}");
                if let Err(e) = hyperion_adapters::backup::upload_s3(f, &key, &target).await {
                    ok = false;
                    notes.push(format!("{fname}: {e}"));
                }
            }
            if ok && row.retention_daily > 0 {
                match hyperion_adapters::backup::s3_prune_keep_latest(
                    &prefix,
                    row.retention_daily as usize,
                    &target,
                )
                .await
                {
                    Ok(n) if n > 0 => notes.push(format!("pruned {n} old object(s)")),
                    Ok(_) => {}
                    Err(e) => notes.push(format!("prune skipped: {e}")),
                }
            }
            let summary = if notes.is_empty() {
                "uploaded".to_string()
            } else {
                notes.join("; ")
            };
            if !ok {
                tracing::warn!(domain=%detail.domain, target=%row.name, note=%summary, "S3 backup push failed");
            } else {
                fully_ok.push(s3_evidence_key(row));
            }
            self.audit_s3(detail, &row.name, ok, &summary).await;
        }
        fully_ok
    }

    pub(super) async fn audit_s3(
        &self,
        detail: &hyperion_types::HostingDetail,
        target_name: &str,
        ok: bool,
        note: &str,
    ) {
        self.append_audit(
            "hosting.backup.s3",
            Some(detail.id.as_str()),
            &serde_json::json!({ "target": target_name, "note": note }).to_string(),
            if ok { "ok" } else { "failed" },
        )
        .await;
    }

    /// Apply the drop-local option to ONE site: keep its newest `keep_latest`
    /// local copies, and drop the local copy of every older backup that is
    /// INDEPENDENTLY re-verified off-site (see `local_copies_to_drop` for which
    /// rows qualify). Returns each attempted run with what happened to it.
    ///
    /// `push_evidence` holds the runs pushed moments ago by the caller (the
    /// backup that just finished, or a backfill's uploads). Those runs are
    /// candidates whatever their row says. The S3 evidence an age-encrypted
    /// target needs (see `file_is_offsite`) is read from each run's row, FRESH,
    /// at the moment it is checked — the pushes above already wrote it there,
    /// and a later push that failed has already taken it away again. Anything
    /// else is confirmed by FTP size or unencrypted S3 size alone — which is
    /// the point: a copy that is already off-site is dropped without being
    /// sent again.
    ///
    /// Stops at the first run whose off-site copy could not be LOOKED at
    /// (every destination failed to answer): the next run would ask the same
    /// unreachable host and wait out the same timeouts, and a scheduled sweep
    /// runs sites one after another. The next backup tries again.
    pub(super) async fn enforce_local_copies(
        &self,
        detail: &hyperion_types::HostingDetail,
        keep_latest: usize,
        s3_targets: &[&hyperion_types::S3BackupTarget],
        push_evidence: &std::collections::HashMap<i64, std::collections::HashSet<String>>,
    ) -> Vec<(i64, DropLocalOutcome)> {
        let rows = match hyperion_state::backups::list_for(&self.pool, &detail.id, 1000).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e,
                    "drop-local: could not list this site's backups — keeping every local copy");
                return Vec::new();
            }
        };
        let just_pushed: std::collections::HashSet<i64> = push_evidence.keys().copied().collect();
        let candidates = local_copies_to_drop(&rows, keep_latest, &just_pushed);
        // A stored "could not confirm" belongs to a copy the drop step will
        // still ask about. One the node now keeps on purpose (inside the keep
        // window, or with no off-site record) would otherwise show a stale
        // warning until retention removes it.
        for r in rows
            .iter()
            .filter(|r| is_local_copy(r) && !r.local_note.is_empty() && !candidates.contains(&r.id))
        {
            let _ = hyperion_state::backups::set_local_note(&self.pool, r.id, "").await;
        }
        let mut done = Vec::new();
        for id in candidates {
            let Some(run) = rows.iter().find(|r| r.id == id) else {
                continue;
            };
            let outcome = self
                .drop_run_local_if_offsite(detail, run.id, s3_targets, Some(&run.local_note))
                .await;
            done.push((id, outcome));
            // Nowhere off-site to look, or nobody answered: no other run of
            // this site will fare better right now.
            if matches!(
                outcome,
                DropLocalOutcome::NoDestination | DropLocalOutcome::Unreachable
            ) {
                break;
            }
        }
        done
    }

    /// Hand one EXISTING run's local files to the verified-drop gate, from its
    /// row as it is NOW (a sweep's list can be minutes old: a re-push may have
    /// failed and taken a target off the run's S3 evidence since).
    ///
    /// * A run some operation on this node is using right now — a restore
    ///   reading it, a backup or a push still sending it — is left alone
    ///   (`Busy`): deleting it would cut that operation off part-way. The gate
    ///   checks again, atomically, right before it deletes.
    /// * Only the files still on disk are offered: a dump that was removed
    ///   separately has nothing left to lose, and asking the remote about a
    ///   file we cannot even stat would keep the archive forever.
    /// * When NONE of the run's files is on disk, nothing is deleted and the
    ///   row is left as it is — absence alone is not proof (a backup volume
    ///   that did not mount looks exactly like this, and clearing every row
    ///   then would orphan every archive once it is back). The run is reported
    ///   `MissingLocally`, with a note, never as a copy that was "kept".
    pub(super) async fn drop_run_local_if_offsite(
        &self,
        detail: &hyperion_types::HostingDetail,
        run_id: i64,
        s3_targets: &[&hyperion_types::S3BackupTarget],
        record_keep: Option<&str>,
    ) -> DropLocalOutcome {
        let run = match hyperion_state::backups::get_by_id(&self.pool, run_id).await {
            Ok(Some(r)) if r.hosting_id == detail.id => r,
            _ => return DropLocalOutcome::Kept,
        };
        // Defence in depth: the callers already skip these, but this is the
        // one door every sweep goes through.
        if run.no_offsite || run.state != "ok" {
            return DropLocalOutcome::Kept;
        }
        let Some(archive) = run.archive_path.as_deref().map(std::path::Path::new) else {
            return DropLocalOutcome::Kept;
        };
        if archive_in_use(archive) {
            return DropLocalOutcome::Busy;
        }
        // Exists / gone / could-not-look are three answers; only a definite
        // "gone" is reported as missing.
        let archive_here = match tokio::fs::try_exists(archive).await {
            Ok(b) => b,
            Err(_) => return DropLocalOutcome::Kept,
        };
        let dump = match run.db_dump_path.as_deref().map(std::path::Path::new) {
            Some(p) => match tokio::fs::try_exists(p).await {
                Ok(true) => Some(p),
                Ok(false) => None,
                Err(_) => return DropLocalOutcome::Kept,
            },
            None => None,
        };
        let mut files: Vec<(&str, &std::path::Path)> = Vec::with_capacity(2);
        if archive_here {
            files.push(("archive", archive));
        }
        if let Some(d) = dump {
            files.push(("database dump", d));
        }
        if files.is_empty() {
            if let Some(prev) = record_keep {
                if prev != LOCAL_FILES_MISSING_NOTE {
                    let _ = hyperion_state::backups::set_local_note(
                        &self.pool,
                        run.id,
                        LOCAL_FILES_MISSING_NOTE,
                    )
                    .await;
                    self.append_audit(
                        "hosting.backup.drop_local",
                        Some(detail.id.as_str()),
                        &serde_json::json!({ "run_id": run.id, "note": LOCAL_FILES_MISSING_NOTE })
                            .to_string(),
                        "failed",
                    )
                    .await;
                }
            }
            return DropLocalOutcome::MissingLocally;
        }
        let evidence: std::collections::HashSet<String> =
            run.s3_ok_targets.iter().cloned().collect();
        self.maybe_drop_local_after_offsite(
            detail,
            &run,
            archive,
            &files,
            s3_targets,
            &evidence,
            0,
            record_keep,
        )
        .await
    }

    /// Delete the LOCAL copy of a backup — but ONLY after every local file it
    /// would delete has been INDEPENDENTLY re-verified present off-site. This
    /// is the whole of the "drop local once verified off-site" option, and the
    /// one place data can be lost if it is wrong, so it never trusts the run's
    /// `remote_state`: it re-checks each file against the destinations it is
    /// handed.
    ///
    /// `files` are what is verified and deleted (the archive and/or the DB
    /// dump, labelled). `archive_path` is the run's archive, used only to find
    /// its `.manifest.json`, which goes with them: nothing ever reads it back
    /// (it is a write-only description of the run, and the run's row keeps the
    /// same facts), so once the archive it describes is gone from this node it
    /// is only an orphan that no prune can find again.
    ///
    /// Only when every file is confirmed does it clear the DB paths and then
    /// delete the files. `run_id` names the row whose local paths are cleared
    /// first so a crash mid-delete leaves a harmless orphan, never a row
    /// pointing at a gone file. Checking stops at the first file that is not
    /// confirmed — one is enough to keep the copy.
    ///
    /// `record_keep` says what to do when the copy is KEPT: `None` is a silent
    /// probe (the caller has a fallback, e.g. push again and retry, so a
    /// refusal here is not news); `Some(prev)` writes the reason onto the row,
    /// a warning and an audit row — the last two only when the reason differs
    /// from `prev`, the row's current note, so a copy that stays unconfirmed is
    /// not re-reported after every backup.
    ///
    /// `run` is the row as the caller read it; `own_claims` is how many holds
    /// on the archive the caller itself has (1 when it pushed the file under a
    /// claim, else 0). Before anything is cleared, the archive is reserved for
    /// deletion — refused (`Busy`) while anyone else holds it — and the row is
    /// read again: if its paths or its S3 evidence moved since `run` was read,
    /// nothing is deleted.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn maybe_drop_local_after_offsite(
        &self,
        detail: &hyperion_types::HostingDetail,
        run: &hyperion_state::backups::BackupRun,
        archive_path: &std::path::Path,
        files: &[(&str, &std::path::Path)],
        s3_targets: &[&hyperion_types::S3BackupTarget],
        s3_push_ok: &std::collections::HashSet<String>,
        own_claims: usize,
        record_keep: Option<&str>,
    ) -> DropLocalOutcome {
        let run_id = run.id;
        // The FTP destination, if this node has one. Rebuilt here from the
        // same inputs the push uses rather than threaded through, so the
        // borrow stays local to this step.
        let ftp = self.remote_backup.as_ref().map(|remote| {
            let hosting_dir = format!(
                "{}/{}",
                remote.base_path.trim_end_matches('/'),
                detail.system_user
            );
            (remote, hosting_dir)
        });
        // A destination has to exist, or there is nothing off-site to fall
        // back on — never delete the only copy.
        let used_offsite = ftp.is_some() || !s3_targets.is_empty();
        if !used_offsite {
            return DropLocalOutcome::NoDestination;
        }

        // Keys live under <system_user>/ , same prefix the S3 push used.
        let prefix = format!("{}/", detail.system_user);
        let mut confirmed: Vec<bool> = Vec::with_capacity(files.len());
        let mut first_unconfirmed: Option<(&str, OffsiteCheck)> = None;
        for (label, f) in files {
            let check = self
                .file_is_offsite(f, &prefix, ftp.as_ref(), s3_targets, s3_push_ok)
                .await;
            confirmed.push(check == OffsiteCheck::Confirmed);
            if check != OffsiteCheck::Confirmed {
                first_unconfirmed = Some((label, check));
                break;
            }
        }

        if !may_drop_local_after_offsite(used_offsite, &confirmed) || first_unconfirmed.is_some() {
            let unreachable = matches!(first_unconfirmed, Some((_, OffsiteCheck::Unreachable)));
            let outcome = if unreachable {
                DropLocalOutcome::Unreachable
            } else {
                DropLocalOutcome::Kept
            };
            let Some(prev) = record_keep else {
                return outcome;
            };
            let what: Vec<&str> = first_unconfirmed.map(|(l, _)| l).into_iter().collect();
            let note = local_kept_unconfirmed_note(&what);
            if prev != note {
                tracing::warn!(
                    domain = %detail.domain,
                    run_id,
                    note = %note,
                    "drop-local: keeping the local backup — could not confirm every file is off-site"
                );
                let _ = hyperion_state::backups::set_local_note(&self.pool, run_id, &note).await;
                self.append_audit(
                    "hosting.backup.drop_local",
                    Some(detail.id.as_str()),
                    &serde_json::json!({ "run_id": run_id, "note": note }).to_string(),
                    "failed",
                )
                .await;
            } else {
                tracing::debug!(domain = %detail.domain, run_id,
                    "drop-local: still not confirmed off-site (unchanged)");
            }
            return outcome;
        }

        // Every file is confirmed off-site. Reserve the archive for deletion:
        // from here until the files are gone, no restore or push can start on
        // it, and if one is running now, nothing is deleted.
        let Some(_reservation) = try_reserve_drop(archive_path, own_claims) else {
            return DropLocalOutcome::Busy;
        };
        // And the row must still be the one that was checked: same local
        // files, same S3 evidence (a push that failed meanwhile takes its
        // target off the list — the object it vouched for may now be cut
        // short).
        match hyperion_state::backups::get_by_id(&self.pool, run_id).await {
            Ok(Some(now))
                if now.archive_path == run.archive_path
                    && now.db_dump_path == run.db_dump_path
                    && now.s3_ok_targets == run.s3_ok_targets
                    && !now.no_offsite => {}
            _ => return DropLocalOutcome::Kept,
        }
        // Clear the DB paths FIRST, then
        // delete: if the process dies between the two, the worst case is a
        // harmless orphan file on disk (the next prune ignores it, since its
        // row no longer names it) rather than a row pointing at a file that is
        // gone — which is a dead Download/Restore button on the Backups card.
        if let Err(e) = hyperion_state::backups::clear_local_paths(&self.pool, run_id).await {
            // The paths still point at real files, so leave those files in
            // place — deleting them now would create exactly the dead-button
            // state the ordering above exists to avoid.
            tracing::warn!(
                domain = %detail.domain, error = %e,
                "drop-local: could not clear the local paths — keeping the local files"
            );
            return DropLocalOutcome::Kept;
        }
        // The paths are already NULL in the DB, so a remove that fails leaves
        // only a harmless orphan file that retention can no longer see (its row
        // does not name it) — not data loss, but worth a line so the wasted
        // disk is explainable rather than mysterious.
        let manifest = manifest_path_for(archive_path);
        for f in files.iter().map(|(_, f)| *f).chain(manifest.as_deref()) {
            if let Err(e) = tokio::fs::remove_file(f).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        domain = %detail.domain, path = %f.display(), error = %e,
                        "drop-local: cleared the DB path but could not delete the local file \
                         — it is now an orphan on disk"
                    );
                }
            }
        }
        tracing::info!(
            domain = %detail.domain,
            run_id,
            "drop-local: removed the local backup copy — verified off-site"
        );
        self.append_audit(
            "hosting.backup.drop_local",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "run_id": run_id,
                "note": "local copy removed after the off-site copy was verified"
            })
            .to_string(),
            "ok",
        )
        .await;
        DropLocalOutcome::Dropped
    }

    /// Is one local backup file INDEPENDENTLY confirmed present off-site, on
    /// any destination handed in? A conservative predicate for the drop-local
    /// gate: only `Confirmed` licenses a delete. The other two answers both
    /// keep the local copy and differ only in what the caller does next:
    /// `NotConfirmed` means a destination ANSWERED (absent, wrong size, no size
    /// given) or was not asked; `Unreachable` means every destination that was
    /// asked failed to answer at all, so the next file on the same host would
    /// too.
    ///
    /// Two data-safety rules live here:
    ///   * FTP is verified by size (`verify_remote`), and only `Ok(Some(true))`
    ///     counts — `Ok(None)`/`Err` are "could not look", not confirmation.
    ///   * S3 keys carry a `.age` suffix and are ciphertext when the target
    ///     has an age recipient, so an ENCRYPTED object is confirmed by
    ///     EXISTENCE only (its size cannot match the plaintext) — but existence
    ///     alone can't tell a whole ciphertext from a truncated one, so an age
    ///     target is trusted ONLY when a push of this run to it is on record as
    ///     having FULLY succeeded (`s3_push_ok`: this process's push, or the
    ///     run's stored `s3_ok_targets`): a partial age stream returns `Err`
    ///     from `upload_s3`, so it never lands in that set, and a failed
    ///     re-push removes the target from the stored list. An UNENCRYPTED
    ///     object must match the local byte count exactly, which catches
    ///     truncation directly, so it needs no such pairing.
    pub(super) async fn file_is_offsite(
        &self,
        file: &std::path::Path,
        prefix: &str,
        ftp: Option<&(&RemoteBackupConfig, String)>,
        s3_targets: &[&hyperion_types::S3BackupTarget],
        s3_push_ok: &std::collections::HashSet<String>,
    ) -> OffsiteCheck {
        let mut asked = 0usize;
        let mut answered = 0usize;
        // FTP first — cheapest, and it verifies by size on its own.
        if let Some((remote, hosting_dir)) = ftp {
            let upload = hyperion_adapters::backup::RemoteUpload {
                scheme: &remote.scheme,
                host: &remote.host,
                port: remote.port,
                user: &remote.user,
                password: &remote.password,
                remote_dir: hosting_dir,
            };
            asked += 1;
            match hyperion_adapters::backup::verify_remote(file, &upload).await {
                Ok(Some(true)) => return OffsiteCheck::Confirmed,
                Ok(_) => answered += 1,
                // Reached, logged in, and the server said no: no such
                // directory (9), could not access the file (19), command
                // refused (21), no such file (78). That is an ANSWER about
                // this file — the next one may well be there.
                Err(hyperion_adapters::AdapterError::Command { code, .. }) if ftp_said_no(code) => {
                    answered += 1
                }
                // Transport failures (refused, timed out, TLS, login) stay
                // "could not look".
                Err(_) => {}
            }
        }

        // S3: needs the local byte count for the unencrypted size check. If we
        // cannot even stat the local file, we cannot confirm anything by
        // size — keep the copy.
        if !s3_targets.is_empty() {
            let local_len = match tokio::fs::metadata(file).await {
                Ok(m) => m.len(),
                Err(_) => return OffsiteCheck::NotConfirmed,
            };
            let fname = file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("backup");
            for row in s3_targets {
                let target = hyperion_adapters::backup::S3UploadTarget {
                    endpoint: &row.endpoint,
                    bucket: &row.bucket,
                    region: &row.region,
                    access_key_id: &row.access_key_id,
                    secret_access_key: &row.secret_access_key,
                    age_recipient: row.age_recipient.as_deref(),
                };
                let age = target
                    .age_recipient
                    .map(str::trim)
                    .filter(|r| !r.is_empty())
                    .is_some();
                // Existence-only verification of an age object is worthless if
                // the upload that produced it may have been truncated — so an
                // age target only counts with a complete push on record.
                // Unencrypted needs no such gate: `n == local` below catches a
                // short copy on its own.
                if age && !s3_push_ok.contains(&s3_evidence_key(row)) {
                    continue;
                }
                let key = if age {
                    format!("{prefix}{fname}.age")
                } else {
                    format!("{prefix}{fname}")
                };
                asked += 1;
                if let Ok(remote) = hyperion_adapters::backup::s3_object_size(&key, &target).await {
                    answered += 1;
                    if hyperion_adapters::backup::s3_offsite_confirmed(remote, local_len, age) {
                        return OffsiteCheck::Confirmed;
                    }
                }
            }
        }
        if asked > 0 && answered == 0 {
            OffsiteCheck::Unreachable
        } else {
            OffsiteCheck::NotConfirmed
        }
    }

    /// Drop backup archives older than `retention.max_age_days` from disk
    /// AND from the backup_runs table, keeping the newest
    /// `retention.keep_latest_n` per hosting regardless of age. Pre-update
    /// backups go by their own rule — see [`pre_update_due_for_prune`].
    pub(crate) async fn prune_old_backups(&self, hosting_id: &HostingId) -> Result<u64, RpcError> {
        self.prune_backups(hosting_id, false).await
    }

    /// Only the pre-update rule of [`Self::prune_old_backups`]: what the
    /// expiry sweep runs, so a clean pre-update backup goes 24 hours after its
    /// updates whether or not the site takes another backup by then — and
    /// without moving when its ordinary backups age out.
    pub(crate) async fn prune_pre_update_backups(
        &self,
        hosting_id: &HostingId,
    ) -> Result<u64, RpcError> {
        self.prune_backups(hosting_id, true).await
    }

    /// Every site's pre-update backups past their deadline, plus all but the
    /// newest one of each site. Run by the agent's five-minute scheduler.
    pub async fn pre_update_backups_expire_tick(&self) -> Result<u64, RpcError> {
        let ids = hyperion_state::backups::hostings_with_pre_update(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("pre-update expiry: {e}")))?;
        let mut pruned = 0;
        for id in ids {
            match self.prune_pre_update_backups(&id).await {
                Ok(n) => pruned += n,
                Err(e) => {
                    tracing::warn!(hosting_id = %id.as_str(), error = %e, "pre-update expiry failed")
                }
            }
        }
        Ok(pruned)
    }

    async fn prune_backups(
        &self,
        hosting_id: &HostingId,
        pre_update_only: bool,
    ) -> Result<u64, RpcError> {
        let rows = hyperion_state::backups::list_for(&self.pool, hosting_id, 1000)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list_for: {e}")))?;
        // Read now, not at boot: the panel saves the rule on every node, and a
        // worker applying the one it started with would ignore that save until
        // something restarted it.
        let global = match self.agent_config_path.as_deref() {
            Some(path) => {
                let v = read_backup_retention_section(Some(path));
                BackupRetention {
                    max_age_days: v.max_age_days,
                    keep_latest_n: v.keep_latest_n,
                }
            }
            None => self.retention.clone(),
        };
        // Per-hosting overrides (from a profile or care plan), 0/absent = fall
        // back to the node-wide rule. So a plan can promise a customer a longer
        // history without changing everyone else's.
        let id = hosting_id.as_str();
        let over = |k: &'static str| {
            let pool = self.pool.clone();
            let id = id.to_string();
            async move {
                hyperion_state::hosting_kv::get(&pool, &id, k)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|v| v.trim().parse::<i64>().ok())
                    .filter(|n| *n > 0)
            }
        };
        let retention = BackupRetention {
            max_age_days: over(BACKUP_KV_KEEP_DAYS)
                .await
                .unwrap_or(global.max_age_days),
            keep_latest_n: over(BACKUP_KV_KEEP_LAST)
                .await
                .unwrap_or(global.keep_latest_n),
        };
        let now = now_secs();
        let cutoff = now - retention.max_age_days.max(1) * 24 * 3600;
        let keep = retention.keep_latest_n.max(1) as usize;
        let mut pruned = 0u64;
        let mut good_kept = 0usize;
        // A newer successful pre-update backup has been seen: older ones are
        // superseded — a site keeps one, plus the oldest held one below.
        let mut newer_pre_update = false;
        // ...and one of those newer ones went in cleanly (released).
        let mut newer_released = false;
        // The last copy from before an update went wrong (or before one that
        // is still running). A newer pre-update backup of the same site is a
        // copy of whatever that update left behind — a nightly batch retried
        // on a broken site, or a second update clicked while the first is
        // still going — and must not take its place.
        let oldest_held = rows
            .iter()
            .rev()
            .find(|r| r.is_pre_update() && r.state == "ok" && r.held)
            .map(|r| r.id);
        // Newest first. The newest N GOOD backups are kept however old. Failed
        // and running rows used to count towards N, so a run of failures pushed
        // the last good archives past the floor and they were deleted — the
        // moment they mattered most.
        for r in rows {
            if r.state == "running" {
                continue;
            }
            if r.is_pre_update() {
                // Its own rule, and never one of the site's newest N: a
                // nightly update batch must not push the real scheduled
                // backups past the floor.
                let superseded = newer_pre_update
                    && (Some(r.id) != oldest_held
                        || (newer_released
                            && r.finished_at.unwrap_or(r.started_at)
                                <= now - hyperion_state::backups::HELD_PRE_UPDATE_MIN_KEEP_SECS));
                if r.state == "ok" {
                    newer_pre_update = true;
                    newer_released |= !r.held;
                }
                if !pre_update_due_for_prune(&r, superseded, now) {
                    continue;
                }
            } else if pre_update_only {
                continue;
            } else {
                if r.state == "ok" && good_kept < keep {
                    good_kept += 1;
                    continue;
                }
                if r.started_at >= cutoff {
                    continue;
                }
            }
            // A restore (or a push) is reading it right now: pruning it would
            // pull the database dump out from under the restore. The next
            // prune gets it. Reserved, not just checked, and held until the
            // row is gone: a restore that starts between a check and the
            // delete would otherwise lose its dump half-way.
            let _reservation = match r.archive_path.as_deref() {
                Some(p) => match try_reserve_drop(std::path::Path::new(p), 0) {
                    Some(res) => Some(res),
                    None => continue,
                },
                None => None,
            };
            if let Some(p) = r.archive_path.as_deref() {
                let _ = tokio::fs::remove_file(p).await;
                // The run's manifest sits beside its archive and was never
                // removed with it, so every pruned backup left one behind.
                if let Some(m) = manifest_path_for(std::path::Path::new(p)) {
                    let _ = tokio::fs::remove_file(m).await;
                }
            }
            if let Some(p) = r.db_dump_path.as_deref() {
                let _ = tokio::fs::remove_file(p).await;
            }
            if let Err(e) = hyperion_state::backups::delete_by_id(&self.pool, r.id).await {
                tracing::warn!(id = r.id, error=%e, "delete backup row");
                continue;
            }
            pruned += 1;
        }
        if pruned > 0 {
            self.append_audit(
                "hosting.backup.prune",
                Some(hosting_id.as_str()),
                &serde_json::json!({"pruned": pruned}).to_string(),
                "ok",
            )
            .await;
        }
        Ok(pruned)
    }

    pub async fn backup_list(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<hyperion_types::BackupRunWire>, RpcError> {
        let detail = self.get(sel).await?;
        let rows = hyperion_state::backups::list_for(&self.pool, &detail.id, limit.clamp(1, 500))
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        // Say, per row, why a local copy that is on record as off-site is
        // still on disk. Read from THIS node's agent.toml — the node that owns
        // the site and would do the dropping — not the master's, which is all
        // the Settings page can show.
        let policy = read_local_copy_policy(self.agent_config_path.as_deref());
        let mut local_rank = 0usize;
        Ok(rows
            .into_iter()
            .map(|r| {
                let rank = is_local_copy(&r).then(|| {
                    local_rank += 1;
                    local_rank - 1
                });
                let (kind, note) = local_kept_reason(&r, policy, rank);
                let mut w = run_to_wire(r);
                w.local_kept = kind.to_string();
                w.local_note = note;
                w
            })
            .collect())
    }

    /// Enabled S3 backup targets resolved from THIS node's `backup_targets`
    /// table (secret read inline from its 0600 file). On the master / a single
    /// node this returns the configured targets; on a worker (where the table
    /// is empty) it returns none, so a scheduled backup there still runs to the
    /// local backup_root + the FTP target in agent.toml. Mirrors the web's
    /// resolve_s3_targets but reads the local DB directly (the agent can't RPC
    /// the master for these).
    pub(super) async fn resolve_local_s3_targets(&self) -> Vec<hyperion_types::S3BackupTarget> {
        let rows = match hyperion_state::backup_targets::list(&self.pool).await {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for r in rows {
            if !r.enabled || r.kind != "s3" {
                continue;
            }
            let Some(path) = r.secret_key_id.as_deref() else {
                continue;
            };
            let secret = match tokio::fs::read_to_string(path).await {
                Ok(s) => s.trim().to_string(),
                Err(_) => continue,
            };
            out.push(hyperion_types::S3BackupTarget {
                name: r.name,
                endpoint: r.endpoint,
                bucket: r.bucket,
                region: r.region,
                access_key_id: r.access_key_id,
                secret_access_key: secret,
                age_recipient: r.age_recipient,
                retention_daily: r.retention_daily,
            });
        }
        // On a worker the table is empty; the cluster's targets arrive with
        // the master's settings sync instead. A name already in the table
        // wins (that row is this node's own, deliberately configured).
        if self.is_worker_node() {
            if let Some(st) = self.cluster_sync_state() {
                for t in st.s3_targets {
                    if !out.iter().any(|o| o.name == t.name) {
                        out.push(t);
                    }
                }
            }
        }
        out
    }

    /// Per-node recurring-backup driver. For every LOCAL Active hosting whose
    /// `backup_cadence` (hosting_kv, seeded from its profile) is due, run the
    /// same `backup_now` the manual button does (local + FTP + any local S3
    /// targets, with the existing disk preflight + retention pruning), then
    /// stamp `backup_last_run_at`. Best-effort + idempotent: the last-run stamp
    /// is written on every attempt (success OR failure) so a persistently
    /// failing site retries on its next cadence rather than hammering hourly;
    /// failures are logged and recorded in `backup_runs`. Returns how many
    /// backups it started. Runs on every node (backups are node-local).
    ///
    /// The off-site half is NOT the same as the manual button's, and the
    /// difference is invisible from the panel: the S3 targets it uploads to
    /// are read from this node's own table, which on a worker is empty by
    /// design. Marking the runs `OffsiteSource::ThisNode` is what lets each
    /// one record that it stayed here — see `offsite_gap_reason`.
    pub async fn scheduled_backups_tick(&self) -> Result<i64, RpcError> {
        let hostings = self
            .list()
            .await
            .map_err(|e| RpcError::Internal_with(format!("scheduled backups: list: {e}")))?;
        // Resolve S3 targets once for the whole sweep.
        let s3_targets = self.resolve_local_s3_targets().await;
        // A worker that resolved none is the case this sweep cannot fix and
        // must not hide: every backup it is about to take stays on this node.
        // Each one gets its own audit row; this is the same sentence in the
        // journal, once per sweep rather than once per site, because the
        // journal is where an operator looks for "what did the agent do at
        // 04:00" and a missing off-site copy has no other symptom until the
        // node is gone. Logged only when the sweep actually ran something —
        // a node with nothing due has nothing to warn about.
        let offsite_gap = self.offsite_gap_reason(OffsiteSource::ThisNode);
        let now = now_secs();
        let mut started = 0i64;
        for h in hostings {
            if h.state != hyperion_types::HostingState::Active {
                continue;
            }
            let cadence =
                hyperion_state::hosting_kv::get(&self.pool, h.id.as_str(), BACKUP_KV_CADENCE)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default();
            // A "custom" cadence reads its period from `backup_interval_days`
            // (1..=365); the presets keep their fixed seconds. Off/unknown, or a
            // custom cadence with no valid interval, is not due.
            let cadence_secs = if cadence.trim() == "custom" {
                match hyperion_state::hosting_kv::get(
                    &self.pool,
                    h.id.as_str(),
                    BACKUP_KV_INTERVAL_DAYS,
                )
                .await
                .ok()
                .flatten()
                .and_then(|v| v.trim().parse::<i64>().ok())
                .filter(|d| (1..=365).contains(d))
                {
                    Some(days) => days * 86_400,
                    None => continue,
                }
            } else {
                match backup_cadence_secs(&cadence) {
                    Some(s) => s,
                    None => continue, // off / unknown
                }
            };
            // In snapshots-only mode this sweep stops — EXCEPT where a care
            // package sells backups to this site.
            //
            // A package is a record that a customer paid for something, and a
            // display preference does not get to cancel it. The alternative
            // was to let the mode win and quietly stop delivering a service
            // that is still being billed, with the care report going on
            // saying backups are included. So the promise wins, the site
            // keeps its backups, and the panel explains why it is still
            // taking them in a mode that says it should not be.
            if !self.protection_mode_now().schedules_backups() {
                if !self.backups_are_sold_to(&h.id).await {
                    continue;
                }
                tracing::debug!(
                    domain = %h.domain,
                    "scheduled backups: snapshots-only mode, but a care package sells backups \
                     to this site — keeping them"
                );
            }
            let last_run =
                hyperion_state::hosting_kv::get(&self.pool, h.id.as_str(), BACKUP_KV_LAST_RUN)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
            let at_min = hyperion_state::hosting_kv::get(&self.pool, h.id.as_str(), BACKUP_KV_AT)
                .await
                .ok()
                .flatten()
                .and_then(|v| parse_backup_at(&v));
            if !backup_due_at(&chrono::Local, cadence_secs, last_run, now, at_min) {
                continue;
            }
            // Stamp the attempt BEFORE running so a slow/looping backup can't be
            // re-triggered on the next tick (and a failure waits a full cadence).
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                h.id.as_str(),
                BACKUP_KV_LAST_RUN,
                &now.to_string(),
                now,
            )
            .await;
            started += 1;
            match self
                .backup_run(
                    HostingSelector::Id(h.id.clone()),
                    s3_targets.clone(),
                    OffsiteSource::ThisNode,
                    None,
                )
                .await
            {
                Ok(_) => {
                    tracing::info!(hosting_id = %h.id.as_str(), cadence = %cadence, "scheduled backup ok");
                }
                Err(e) => {
                    tracing::warn!(
                        hosting_id = %h.id.as_str(),
                        cadence = %cadence,
                        error = %e,
                        "scheduled backup failed; will retry next cadence (see backup_runs)"
                    );
                }
            }
        }
        if started > 0 {
            if let Some(why) = offsite_gap {
                tracing::warn!(
                    backups = started,
                    reason = why,
                    "scheduled backups stayed on this node — no off-site copy was made"
                );
            }
        }
        Ok(started)
    }

    /// Delete a single backup run + its archive file(s) on disk.
    /// Refuses when the backup is still `running` (would orphan the
    /// in-flight process). Logs `backup.delete` in the audit log
    /// regardless of disk-removal success — DB row removal is the
    /// source of truth and we want the audit chain to reflect it.
    pub async fn backup_delete(
        &self,
        sel: HostingSelector,
        backup_id: i64,
    ) -> Result<(), RpcError> {
        // Bound to the authorized hosting. Deleting by bare id let a tenant
        // destroy every backup on the node in a loop.
        let row = self.backup_owned_by(sel, backup_id).await?;
        if row.state == "running" {
            return Err(RpcError::Validation {
                message: "refusing to delete a backup that is still running. \
                          Wait for it to finish (or fail) first."
                    .into(),
            });
        }
        // Best-effort disk removal — don't block the DB delete if the
        // archive is already gone (operator can delete the row to clean
        // up zombie entries). Track outcomes for audit.
        let mut disk_removed = 0u8;
        let mut disk_errors: Vec<String> = Vec::new();
        // The manifest beside the archive goes with it — no column names it,
        // so leaving it was a stray file per deleted backup.
        let manifest = row
            .archive_path
            .as_deref()
            .and_then(|p| manifest_path_for(std::path::Path::new(p)))
            .map(|m| m.display().to_string());
        for p in [row.archive_path.clone(), row.db_dump_path.clone(), manifest]
            .into_iter()
            .flatten()
        {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => disk_removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Already gone — fine.
                }
                Err(e) => {
                    disk_errors.push(format!("{p}: {e}"));
                }
            }
        }
        // Now drop the DB row regardless of disk outcomes.
        hyperion_state::backups::delete_by_id(&self.pool, backup_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete backup row: {e}")))?;

        self.append_audit(
            "backup.delete",
            Some(row.hosting_id.as_str()),
            &serde_json::json!({
                "backup_id": backup_id,
                "target": row.target,
                "state": row.state,
                "files_removed": disk_removed,
                "disk_errors": disk_errors,
            })
            .to_string(),
            if disk_errors.is_empty() {
                "ok"
            } else {
                "partial"
            },
        )
        .await;
        Ok(())
    }

    pub async fn backup_restore(
        &self,
        sel: HostingSelector,
        archive_path: String,
        mode: hyperion_types::BackupRestoreMode,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // Whitelist the path — must live under one of OUR backup roots.
        let p = std::path::PathBuf::from(&archive_path);
        let canonical = p.canonicalize().map_err(|e| RpcError::Validation {
            message: format!("archive not readable: {e}"),
        })?;
        let allowed_roots = [
            std::path::PathBuf::from(&self.paths.backup_root),
            std::path::PathBuf::from("/var/lib/hyperion/backups/incoming"),
            // Migration export staging — `hosting_export` hardlinks the
            // archive here and `hosting_import` reads it back. Without
            // this, every cross-node `Migrate to another node` flow
            // would 400 with "not under allowed backup root".
            std::path::PathBuf::from("/var/lib/hyperion/migration"),
            // Migration pull staging — `hosting_import_from_url` writes
            // the downloaded archive here, then calls `backup_restore`
            // on it. Same gap; without this the new one-click import
            // workflow fails at the very last step.
            std::path::PathBuf::from("/var/lib/hyperion/migration-incoming"),
        ];
        if !allowed_roots.iter().any(|r| canonical.starts_with(r)) {
            return Err(RpcError::Validation {
                message: format!(
                    "archive {} is not under an allowed backup root",
                    canonical.display()
                ),
            });
        }
        // The archive (and its dump beside it) is in use until this returns:
        // the drop-local sweep and the retention prune leave it alone. If a
        // drop is deleting it at this very moment, refuse rather than extract
        // a file that is going away — it was verified off-site first.
        let Some(_busy) = ArchiveInUse::try_claim(&canonical) else {
            return Err(RpcError::Validation {
                message: "this backup is being removed from local disk right now (it is verified \
                          off-site) — restore it from the site's Off-site panel instead"
                    .into(),
            });
        };
        // Where the dump is, and whether it is there NOW — before minutes of
        // extraction. A dump that was here at the start and is gone by the
        // database step is a restore that would put back the files of one
        // moment over the database of another and call it done; that has to
        // fail loudly, whatever removed it.
        let sibling_dump = canonical.file_stem().and_then(|s| s.to_str()).map(|stem| {
            // strip the trailing ".tar" if present from .tar.gz double-ext
            let trim = stem.strip_suffix(".tar").unwrap_or(stem);
            canonical
                .parent()
                .unwrap_or(std::path::Path::new("/"))
                .join(format!("{trim}.sql"))
        });
        let dump_at_start = sibling_dump.as_deref().is_some_and(|p| p.exists());

        // 1. Extract tar.gz over the hosting root (unless db-only).
        let host_root = std::path::PathBuf::from(&self.paths.home_root)
            .join(&detail.system_user)
            .join(&detail.domain);
        if mode.restores_files() {
            tracing::info!(domain = %detail.domain, archive = %canonical.display(),
                mode = mode.as_str(), "restoring backup files");
            let restore_result =
                hyperion_adapters::backup::restore_archive(&canonical, &host_root).await;
            if let Err(e) = restore_result {
                return Err(RpcError::ProvisioningFailed {
                    stage: "tar_extract".into(),
                    reason: e.to_string(),
                });
            }
            // `tar -xzf` as root PRESERVES the archive's ownership, so a
            // restore from another box — or from a backup taken when the uid
            // differed — leaves the tree owned by someone the site user is
            // not. PHP then cannot write, wp-cli fails, and the site 403s or
            // 404s depending on the modes that came with it. Reuse the same
            // repair the panel button and the import pipeline run, so all
            // three doors leave the tree in one state.
            if let Err(e) = repair_tree_permissions(&detail.system_user, &host_root).await {
                tracing::warn!(
                    error = %e, domain = %detail.domain,
                    "restore: permission repair failed — the site may be unwritable"
                );
            }
        }

        // 2. Look for sibling .sql dump and restore it if hosting has a DB
        //    (unless files-only). For db-only restores a missing dump is
        //    an error — the operator explicitly asked to put a DB back.
        if mode.restores_db() {
            let mut dump_found = false;
            if let Some(sibling) = sibling_dump.as_ref() {
                if !sibling.exists() && dump_at_start && detail.database.is_some() {
                    return Err(RpcError::ProvisioningFailed {
                        stage: "db_restore".into(),
                        reason: "the backup's database dump disappeared while the files were \
                                 being restored — the files were put back, the database was \
                                 NOT; restore the database again from this backup's off-site \
                                 copy"
                            .into(),
                    });
                }
                if sibling.exists() {
                    dump_found = true;
                    if let Some(db) = &detail.database {
                        let restore = self.restore_db_dump(&detail.id, db, sibling).await;
                        if let Err(e) = restore {
                            return Err(RpcError::ProvisioningFailed {
                                stage: "db_restore".into(),
                                reason: e.to_string(),
                            });
                        }
                    }
                }
            }
            if mode == hyperion_types::BackupRestoreMode::DbOnly && !dump_found {
                return Err(RpcError::Validation {
                    message: "db-only restore requested but this backup has no .sql dump \
                              (the hosting may have had no database when it was taken)"
                        .into(),
                });
            }
        }

        self.append_audit(
            "hosting.restore",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "archive": canonical.display().to_string(),
                "mode": mode.as_str(),
            })
            .to_string(),
            "ok",
        )
        .await;
        self.purge_page_cache_after(detail.id.as_str(), "hosting.restore")
            .await;

        Ok(())
    }

    /// Resolve a backup id and prove it belongs to the hosting the caller was
    /// authorized for.
    ///
    /// The web layer authorizes a SELECTOR and then forwards a client-supplied
    /// backup id. Without this the id was never checked against it: ids are a
    /// dense node-wide sequence, so a tenant with one site could walk them and
    /// reach every co-tenant's archive — which contains their files AND their
    /// SQL dump. The old defence was "the path is under a backup root", and
    /// every tenant's archives are under the same root.
    ///
    /// Answers NotFound, never Forbidden: a distinguishable "exists but not
    /// yours" turns the id space into an oracle for how many sites the node
    /// hosts and when each was last backed up.
    pub(super) async fn backup_owned_by(
        &self,
        sel: HostingSelector,
        backup_id: i64,
    ) -> Result<hyperion_state::backups::BackupRun, RpcError> {
        let detail = self.get(sel).await?;
        let run = hyperion_state::backups::get_by_id(&self.pool, backup_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup lookup: {e}")))?
            .filter(|r| r.hosting_id == detail.id)
            .ok_or_else(|| RpcError::NotFound {
                kind: "backup".into(),
                id: backup_id.to_string(),
            })?;
        Ok(run)
    }

    /// Stream one slice of a backup archive for download. Validates the
    /// backup belongs to a real hosting and its path is under a backup
    /// root, then reads up to `len` bytes from `offset`. `len == 0`
    /// returns metadata only.
    pub async fn backup_fetch_chunk(
        &self,
        sel: HostingSelector,
        backup_id: i64,
        offset: u64,
        len: u32,
    ) -> Result<(String, u64, String, bool), RpcError> {
        use base64::Engine;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        // Bound to the hosting the caller was authorized for. The backup-root
        // prefix check below stays as defence in depth, but it is not an
        // authorization: every tenant's archives live under the same root.
        let run = self.backup_owned_by(sel, backup_id).await?;
        let archive_path = run.archive_path.ok_or_else(|| RpcError::Validation {
            message: "backup has no archive file to download".into(),
        })?;
        let canonical = std::path::PathBuf::from(&archive_path)
            .canonicalize()
            .map_err(|e| RpcError::Validation {
                message: format!("archive not readable: {e}"),
            })?;
        let allowed_roots = [
            std::path::PathBuf::from(&self.paths.backup_root),
            std::path::PathBuf::from("/var/lib/hyperion/backups"),
        ];
        if !allowed_roots.iter().any(|r| canonical.starts_with(r)) {
            return Err(RpcError::Validation {
                message: "archive is not under an allowed backup root".into(),
            });
        }
        let filename = canonical
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("backup.tar.gz")
            .to_string();
        let total_size = tokio::fs::metadata(&canonical)
            .await
            .map(|m| m.len())
            .map_err(|e| RpcError::Internal_with(format!("stat archive: {e}")))?;
        if len == 0 {
            return Ok((String::new(), total_size, filename, offset >= total_size));
        }
        let mut file = tokio::fs::File::open(&canonical)
            .await
            .map_err(|e| RpcError::Internal_with(format!("open archive: {e}")))?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| RpcError::Internal_with(format!("seek archive: {e}")))?;
        let mut buf = vec![0u8; len as usize];
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = file
                .read(&mut buf[filled..])
                .await
                .map_err(|e| RpcError::Internal_with(format!("read archive: {e}")))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        let eof = offset + filled as u64 >= total_size;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
        Ok((data_b64, total_size, filename, eof))
    }

    /// Restore a backup archive into a BRAND-NEW hosting at `new_domain`,
    /// mirroring the source hosting's php/db/kind config. Runs
    /// `wp search-replace` afterwards when the snapshot is WordPress so
    /// the cloned site serves under its new URL. Rolls back the new
    /// hosting if any step fails. Same-node only (the web layer dispatches
    /// to the source's owning node).
    pub async fn backup_restore_as_new(
        &self,
        sel: HostingSelector,
        archive_path: String,
        new_domain: String,
    ) -> Result<(String, String), RpcError> {
        let source = self.get(sel).await?;
        let new_dom =
            hyperion_validate::Domain::parse(&new_domain).map_err(|e| RpcError::Validation {
                message: format!("new domain invalid: {e}"),
            })?;
        if new_dom.as_str() == source.domain {
            return Err(RpcError::Validation {
                message: "new domain must differ from the source domain".into(),
            });
        }
        // Provision the new hosting mirroring the source's config. cert
        // is re-issued later by the operator (same as a fresh create).
        let create = HostingCreateReq {
            domain: new_dom.clone(),
            aliases: vec![],
            php_version: source.php_version,
            database: source.database.as_ref().map(|d| d.engine),
            system_user: None,
            kind: source.kind.clone(),
            proxy_upstream_url: source.proxy_upstream_url.clone(),
        };
        let created = self.create(create).await?;

        // Restore files + DB into the new hosting. On failure, roll back
        // the half-created hosting so the operator can retry cleanly.
        if let Err(e) = self
            .backup_restore(
                HostingSelector::Id(created.id.clone()),
                archive_path,
                hyperion_types::BackupRestoreMode::FilesAndDb,
            )
            .await
        {
            tracing::warn!(
                hosting = %created.id.as_str(),
                error = %e,
                "restore-as-new: restore failed — rolling back new hosting"
            );
            self.roll_back_created(&created.id).await;
            return Err(e);
        }

        // WordPress URL rewrite: if the restored tree is a WP install,
        // point it at the new domain. Best-effort — a non-WP site or a
        // wp-cli hiccup shouldn't fail the whole restore (files + DB are
        // already in place). Runs wp-cli directly (same path as
        // wp_reset_password) since the AdapterPort surface doesn't carry
        // a generic search-replace.
        if let Ok(new_detail) = self.get(HostingSelector::Id(created.id.clone())).await {
            let old_url = format!("//{}", source.domain);
            let new_url = format!("//{}", new_dom.as_str());
            let sr_args = [
                "search-replace",
                old_url.as_str(),
                new_url.as_str(),
                "--all-tables",
                "--skip-columns=guid",
                "--report-changed-only",
            ];
            let argv = hyperion_adapters::wpcli::build_argv(
                &new_detail.system_user,
                &new_detail.root_dir,
                &sr_args,
            );
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            match hyperion_adapters::cmd::run("/usr/bin/sudo", &argv_refs).await {
                Ok(_) => {
                    // Flush caches so the new host's pages render fresh.
                    let flush = hyperion_adapters::wpcli::build_argv(
                        &new_detail.system_user,
                        &new_detail.root_dir,
                        &["cache", "flush"],
                    );
                    let flush_refs: Vec<&str> = flush.iter().map(String::as_str).collect();
                    let _ = hyperion_adapters::cmd::run("/usr/bin/sudo", &flush_refs).await;
                }
                Err(e) => {
                    tracing::info!(
                        hosting = %created.id.as_str(),
                        error = %e,
                        "restore-as-new: wp search-replace skipped (not a WP site or wp-cli error)"
                    );
                }
            }
        }

        self.append_audit(
            "hosting.restore_as_new",
            Some(created.id.as_str()),
            &serde_json::json!({
                "source": source.domain,
                "new_domain": new_dom.as_str(),
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok((
            created.id.as_str().to_string(),
            new_dom.as_str().to_string(),
        ))
    }
}

pub(super) fn run_to_wire(r: hyperion_state::backups::BackupRun) -> hyperion_types::BackupRunWire {
    let delete_at = r.pre_update_delete_at().unwrap_or(0);
    hyperion_types::BackupRunWire {
        sha256_hex: r.sha256_hex,
        remote_blob_key: r.remote_blob_key,
        remote_state: r.remote_state,
        remote_error: r.remote_error,
        no_offsite: r.no_offsite,
        // Derived per node policy by `backup_list`, not stored as-is.
        local_kept: String::new(),
        local_note: String::new(),
        s3_ok_targets: r.s3_ok_targets,
        delete_at,
        purpose: r.purpose,
        held: r.held,
        id: r.id,
        hosting_id: r.hosting_id,
        target: r.target,
        started_at: r.started_at,
        finished_at: r.finished_at,
        state: r.state,
        archive_path: r.archive_path,
        db_dump_path: r.db_dump_path,
        bytes_total: r.bytes_total,
        error_message: r.error_message,
    }
}
/// `hosting_kv` key: per-hosting recurring-backup cadence
/// ("off"|"daily"|"weekly"|"monthly"|"custom"); seeded from a profile or a
/// care package at apply/enforce time.
pub(super) const BACKUP_KV_CADENCE: &str = "backup_cadence";
/// `hosting_kv` key: custom backup period in days, read only when
/// [`BACKUP_KV_CADENCE`] is "custom" (1..=365). Seeded by a profile
/// (migration 070) or a care package (071); 0/absent = not due.
pub(super) const BACKUP_KV_INTERVAL_DAYS: &str = "backup_interval_days";
/// `hosting_kv` key: local time of day ("HH:MM", the node's timezone) the
/// scheduled backup runs at. Absent/blank = any time — due as soon as the
/// cadence has elapsed, which is what every site did before this key existed.
pub(super) const BACKUP_KV_AT: &str = "backup_at";
/// `hosting_kv` keys: per-hosting retention overrides read at prune time —
/// keep archives this many days / keep at least this many. > 0 overrides the
/// node-wide `[backup_retention]` rule; 0/absent = fall back to it.
pub(super) const BACKUP_KV_KEEP_DAYS: &str = "backup_keep_days";
pub(super) const BACKUP_KV_KEEP_LAST: &str = "backup_keep_last";
/// `hosting_kv` key: unix-secs of the last successful scheduled backup.
pub(super) const BACKUP_KV_LAST_RUN: &str = "backup_last_run_at";
/// `hosting_kv` key: the ONE off-site target this hosting's backups go to,
/// held as `backup_targets.name` (unique in that table). Absent/blank = the
/// node default, i.e. every target the caller resolved — what every install
/// did before this key existed. The name rather than the row id because a
/// worker has no `backup_targets` table of its own: the name is the only
/// identifier that survives into the `S3BackupTarget` the master sends with
/// the request, so it's the only one both sides can agree on.
pub(super) const BACKUP_KV_TARGET: &str = "backup_target";

/// Canonicalise a backup cadence string to one of the four known values; any
/// unknown/empty input becomes "off" so a stray value never schedules backups.
pub(super) fn canonical_backup_cadence(c: &str) -> &'static str {
    match c.trim() {
        "daily" => "daily",
        "weekly" => "weekly",
        "monthly" => "monthly",
        // "custom" reads its period from backup_interval_days.
        "custom" => "custom",
        _ => "off",
    }
}

/// Seconds in one backup cadence, or `None` for "off"/unknown (never due).
pub(super) fn backup_cadence_secs(c: &str) -> Option<i64> {
    match canonical_backup_cadence(c) {
        "daily" => Some(86_400),
        "weekly" => Some(7 * 86_400),
        "monthly" => Some(30 * 86_400),
        _ => None,
    }
}

/// A scheduled backup is due when the cadence has elapsed since the last run.
/// `last_run == 0` (never) is always due, so enabling a cadence triggers a
/// prompt first backup.
pub(super) fn backup_due(cadence_secs: i64, last_run: i64, now: i64) -> bool {
    now.saturating_sub(last_run) >= cadence_secs
}

/// How long after its set time a never-run site still takes its first
/// backup. Past it, the first one waits for the same time tomorrow, so turning
/// a schedule on at noon does not start a backup at noon when the operator
/// asked for 03:00.
pub(super) const BACKUP_AT_FIRST_RUN_GRACE_SECS: i64 = 2 * 3600;

/// Parse a [`BACKUP_KV_AT`] value ("HH:MM", 24-hour) into minutes after local
/// midnight. Anything else is `None` — "any time", the behaviour before the
/// key existed.
pub(super) fn parse_backup_at(s: &str) -> Option<u32> {
    let (h, m) = s.trim().split_once(':')?;
    if h.is_empty() || h.len() > 2 || m.len() != 2 {
        return None;
    }
    let (h, m) = (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/// Unix seconds of `at_min` minutes past midnight, `days` after the local
/// calendar day that `ts` falls on. A time skipped by a DST jump resolves to
/// the hour after it.
pub(super) fn local_slot<Tz: chrono::TimeZone>(
    tz: &Tz,
    ts: i64,
    days: i64,
    at_min: u32,
) -> Option<i64> {
    use chrono::{Duration, NaiveTime};
    let day = tz.timestamp_opt(ts, 0).earliest()?.date_naive() + Duration::days(days);
    let at = NaiveTime::from_hms_opt(at_min / 60, at_min % 60, 0)?;
    let naive = day.and_time(at);
    tz.from_local_datetime(&naive)
        .earliest()
        .or_else(|| {
            tz.from_local_datetime(&(naive + Duration::hours(1)))
                .earliest()
        })
        .map(|d| d.timestamp())
}

/// [`backup_due`] with an optional time of day. Without one it IS
/// `backup_due`. With one, the next backup is due at that local time on the
/// day the cadence lands on, counted in calendar days from the day of the last
/// run — so "daily at 03:00" stays at 03:00 even when a run starts late, and a
/// late catch-up run (node was down) snaps the next one back onto the set time.
/// A site that never ran takes its first backup at the next occurrence of the
/// time, not immediately.
pub(super) fn backup_due_at<Tz: chrono::TimeZone>(
    tz: &Tz,
    cadence_secs: i64,
    last_run: i64,
    now: i64,
    at_min: Option<u32>,
) -> bool {
    let Some(at_min) = at_min else {
        return backup_due(cadence_secs, last_run, now);
    };
    if last_run <= 0 {
        return match local_slot(tz, now, 0, at_min) {
            Some(slot) => now >= slot && now < slot + BACKUP_AT_FIRST_RUN_GRACE_SECS,
            None => false,
        };
    }
    let days = (cadence_secs / 86_400).max(1);
    match local_slot(tz, last_run, days, at_min) {
        Some(slot) => now >= slot,
        // Unrepresentable local time: fall back to the plain elapsed rule
        // rather than never backing up.
        None => backup_due(cadence_secs, last_run, now),
    }
}

/// Ensure the `quota` user-space tools are installed (quotaon / quotacheck /
/// setquota ship in Debian's `quota` package, absent from a base install).
/// Installs on demand via apt — assumes root (the caller already checked).
/// Returns a clear, actionable message on failure instead of letting the
/// downstream commands fail with a bare "No such file or directory".
/// `<target>` + `<absolute path>`, the way `restic restore --target` lays it
/// out: restoring `/home/u/site/htdocs` into `/tmp/x` yields
/// `/tmp/x/home/u/site/htdocs`.
///
/// `Path::join` with an absolute argument REPLACES the base rather than
/// appending to it, which would silently point every restore at the live tree.
/// The one `.sql` file restic put in the restored staging directory.
///
/// REGULAR FILES ONLY, and that is the whole point of the function. This
/// directory sits inside a tree the site's own unix user owns, and whatever
/// comes back from here is handed to the database superuser. A symlink left
/// there is a redirect to a file of the tenant's choosing, and following it
/// would execute their SQL as root.
///
/// `symlink_metadata`, never `metadata`: the latter follows the link and
/// reports on the TARGET, so a symlink pointing at a real file passes an
/// `is_file()` check while still being a symlink.
pub(super) async fn find_restored_dump(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    while let Ok(Some(e)) = rd.next_entry().await {
        let is_regular = tokio::fs::symlink_metadata(e.path())
            .await
            .map(|m| m.file_type().is_file())
            .unwrap_or(false);
        if is_regular && e.path().extension().is_some_and(|x| x == "sql") {
            return Some(e.path());
        }
    }
    None
}

/// Open a restored database dump and verify, THROUGH the descriptor, that it is
/// a regular file owned by ROOT.
///
/// The snapshot restore stages inside the site directory, which the tenant
/// owns, so the dump's path is briefly tenant-swappable (see the call site in
/// `lift_restored_dump`). A dump restic wrote carries uid 0 — hyperion stages
/// every dump under a root-only `/var/lib` path — and an unprivileged tenant
/// cannot create a root-owned file, so `uid == 0` distinguishes the real dump
/// from a planted one. Returning the open descriptor lets the caller copy from
/// the very inode it just checked, closing the check-then-use race.
pub(super) async fn open_root_owned_dump(src: &std::path::Path) -> Result<tokio::fs::File, String> {
    use std::os::unix::fs::MetadataExt;
    let f = tokio::fs::File::open(src)
        .await
        .map_err(|e| format!("open restored dump: {e}"))?;
    let meta = f
        .metadata()
        .await
        .map_err(|e| format!("stat restored dump: {e}"))?;
    if !meta.is_file() || meta.uid() != 0 {
        return Err(format!(
            "the restored database dump at {} is not a root-owned regular file (uid {}) — \
             refusing to import it: the restore's staging directory may have been tampered with",
            src.display(),
            meta.uid()
        ));
    }
    Ok(f)
}

/// The phases a backup run shows on its progress page, all pending.
pub(super) fn backup_substeps(has_db: bool, will_offsite: bool) -> Vec<hyperion_types::JobSubstep> {
    let mut subs = vec![hyperion_types::JobSubstep::pending(
        "files",
        "Back up files",
    )];
    if has_db {
        subs.push(hyperion_types::JobSubstep::pending(
            "db",
            "Back up database",
        ));
    }
    if will_offsite {
        subs.push(hyperion_types::JobSubstep::pending(
            "offsite",
            "Copy off-site",
        ));
    }
    subs
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Remove what a run that died mid-backup left on disk: its archive, dump
    /// and manifest, found by the name [`BackupFiles`] gives them. Runs since
    /// the row and the names share one stamp match exactly; older ones took
    /// the stamp a moment after the row, so a few seconds after it are tried
    /// too. A file a push or restore holds is kept. Best-effort: a hosting
    /// that is gone leaves its files to the untracked-files cleanup.
    pub(super) async fn remove_dead_run_files(&self, hosting_id: &str, started_at: i64) {
        let Ok(detail) = self
            .get(HostingSelector::Id(HostingId(hosting_id.to_string())))
            .await
        else {
            return;
        };
        // A file another row names is that run's, not this one's — two runs
        // of a site a second apart would otherwise share a candidate name.
        let Ok((claimed, _)) = hyperion_state::backups::claimed_local_files(&self.pool).await
        else {
            return;
        };
        let mut removed = 0u32;
        for ts in started_at..=started_at + 5 {
            let files = BackupFiles::new(&self.paths.backup_root, &detail, ts);
            let names = [Some(files.archive), files.dump, Some(files.manifest)];
            if names
                .iter()
                .flatten()
                .any(|p| claimed.iter().any(|c| std::path::Path::new(c) == p))
            {
                continue;
            }
            for p in names.into_iter().flatten() {
                if archive_in_use(&p) {
                    continue;
                }
                // Regular files only: never follow a link out of the
                // backup directory.
                let is_file = tokio::fs::symlink_metadata(&p)
                    .await
                    .is_ok_and(|m| m.is_file());
                if is_file && tokio::fs::remove_file(&p).await.is_ok() {
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            tracing::warn!(
                domain = %detail.domain, started_at, files = removed,
                "removed the files a crashed backup run left behind"
            );
        }
    }
}

/// Where one backup run's files go: `<backup_root>/<user>/<domain>-<ts>.*`.
pub(super) struct BackupFiles {
    pub(super) ts: i64,
    pub(super) archive_name: String,
    pub(super) archive: std::path::PathBuf,
    /// Only when the hosting has a database.
    pub(super) dump: Option<std::path::PathBuf>,
    pub(super) manifest: std::path::PathBuf,
}

impl BackupFiles {
    pub(super) fn new(backup_root: &str, detail: &HostingDetail, ts: i64) -> Self {
        let dir = std::path::PathBuf::from(backup_root).join(&detail.system_user);
        let archive_name = format!("{}-{}.tar.gz", detail.domain, ts);
        BackupFiles {
            ts,
            archive: dir.join(&archive_name),
            archive_name,
            dump: detail
                .database
                .as_ref()
                .map(|_| dir.join(format!("{}-{}.sql", detail.domain, ts))),
            manifest: dir.join(format!("{}-{}.manifest.json", detail.domain, ts)),
        }
    }
}
