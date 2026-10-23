//! Off-site backup copies (S3, FTP/SFTP): push, verify, restore, drop-local
//! policy.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// The FTP destination for one site, or `None` when none is configured.
    pub(super) fn remote_upload_for(
        &self,
        detail: &HostingDetail,
    ) -> Option<(hyperion_adapters::backup::RemoteUpload<'_>, String)> {
        let remote = self.remote_backup.as_ref()?;
        let dir = format!(
            "{}/{}",
            remote.base_path.trim_end_matches('/'),
            detail.system_user
        );
        Some((
            hyperion_adapters::backup::RemoteUpload {
                scheme: &remote.scheme,
                host: &remote.host,
                port: remote.port,
                user: &remote.user,
                password: &remote.password,
                remote_dir: "",
            },
            dir,
        ))
    }

    /// What this site actually has on the off-site store.
    ///
    /// Read from the REMOTE, not from our own rows. The rows say what we tried
    /// to upload; this says what is there — and after a node is lost, the rows
    /// are gone and this is the only answer left.
    pub async fn backup_offsite_list(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::OffsiteListing, RpcError> {
        let detail = self.get(sel).await?;
        let Some((mut up, dir)) = self.remote_upload_for(&detail) else {
            return Err(RpcError::Validation {
                message: "no off-site backup target is configured on this node".into(),
            });
        };
        up.remote_dir = &dir;
        let listed = hyperion_adapters::backup::list_remote(&up)
            .await
            .map_err(|e| RpcError::Internal_with(format!("off-site list: {e}")))?;
        // `None` = the remote has no directory for this site. The folder is
        // created by the first upload, so this is what a site whose backups
        // all predate the target looks like — an ordinary state with an
        // obvious fix, not a fault.
        let Some(files) = listed else {
            return Ok(hyperion_types::OffsiteListing::default());
        };
        // The remote folder is per SYSTEM USER, and hostings can share one —
        // so it also holds the other sites' archives. Listed unfiltered, this
        // site's card offered "Restore" on a sibling's backup, which would
        // have put another domain's files and database over this one.
        Ok(hyperion_types::OffsiteListing {
            directory_exists: true,
            files: files
                .into_iter()
                .filter(|f| offsite_file_belongs(&detail.domain, &f.name))
                .map(|f| hyperion_types::OffsiteFile {
                    name: f.name,
                    bytes: f.bytes as i64,
                })
                .collect(),
        })
    }

    /// Push ONE existing backup run off-site — FTP/FTPS/SFTP (the node-local
    /// destination) and every resolved/pinned S3 target — record the outcome on
    /// its row, and, when `drop_local`, hand the local files to the
    /// verified-drop gate.
    ///
    /// This is the single shared path behind both the estate-wide backfill and
    /// the per-hosting on-demand action, so ALL the data-safety logic — the
    /// independent re-verification, the clear-paths-then-delete ordering, and
    /// the age/S3 existence caveat (an age target is trusted only when THIS
    /// push to it fully succeeded, tracked in `s3_push_ok`) — lives in exactly
    /// one place: `maybe_drop_local_after_offsite`. This method never deletes a
    /// local file itself.
    ///
    /// `s3_targets` are the master-resolved destinations shipped in the request
    /// (the table is master-only). Empty is the historical FTP-only behaviour.
    pub(super) async fn push_run_offsite(
        &self,
        run: &hyperion_state::backups::BackupRun,
        s3_targets: &[hyperion_types::S3BackupTarget],
        drop_local: bool,
    ) -> RunOffsiteOutcome {
        let mut out = RunOffsiteOutcome::default();
        // A rollback snapshot must never leave the node, and its local copy is
        // the whole point of it — never push it, never drop it. Defence in
        // depth: `list_needing_offsite` already excludes these, and the
        // per-hosting caller skips them, but the single shared push path is the
        // one place that must not be able to touch one.
        if run.no_offsite {
            return out;
        }
        let Some(archive) = run.archive_path.clone() else {
            out.missing_locally = true;
            return out;
        };
        // The row can name a file that is gone — removed by hand, or lost with
        // a disk. Nothing left to send. Only a run with NO off-site copy on
        // record is marked failed: one that is already off-site keeps that
        // record, which is still true.
        if !tokio::fs::try_exists(&archive).await.unwrap_or(false) {
            if !run.offsite_on_record() {
                let _ = hyperion_state::backups::set_remote(
                    &self.pool,
                    run.id,
                    "",
                    "failed",
                    "the local archive is gone — removed before it was ever copied off-site",
                )
                .await;
            }
            out.missing_locally = true;
            return out;
        }
        let Ok(detail) = self.get(HostingSelector::Id(run.hosting_id.clone())).await else {
            out.failed = true;
            return out;
        };
        let archive_path = std::path::PathBuf::from(&archive);
        // Busy while it is being sent, so a sweep elsewhere does not drop it
        // mid-upload. A drop deleting it right now wins: there is nothing to
        // send once it is gone, and it is gone because it was verified
        // off-site.
        let Some(_busy) = ArchiveInUse::try_claim(&archive_path) else {
            return out;
        };
        // Only offer the dump to a push (and to the drop gate) if it still
        // exists — a run may have been made before dumps were kept, or the
        // dump pruned separately.
        let dump_path: Option<std::path::PathBuf> = match run.db_dump_path.as_deref() {
            Some(p) if tokio::fs::try_exists(p).await.unwrap_or(false) => {
                Some(std::path::PathBuf::from(p))
            }
            _ => None,
        };

        // `landed` = at least one destination accepted the archive (and, for
        // FTP, the dump too). It is deliberately NOT the same as "safe to
        // drop": the drop gate re-verifies each file independently below.
        let mut landed = false;

        // ── FTP/FTPS/SFTP — the single node-local destination ──
        if let Some((mut up, dir)) = self.remote_upload_for(&detail) {
            up.remote_dir = &dir;
            match hyperion_adapters::backup::upload_remote(&archive_path, &up).await {
                Ok(url) => {
                    // The dump is half the backup; a run whose dump did not make
                    // it must not be recorded as safely off-site.
                    let mut dump_note = String::new();
                    if let Some(dp) = dump_path.as_ref() {
                        if let Err(e) = hyperion_adapters::backup::upload_remote(dp, &up).await {
                            dump_note = format!("archive pushed, database dump failed: {e}");
                        }
                    }
                    if !dump_note.is_empty() {
                        let _ = hyperion_state::backups::set_remote(
                            &self.pool, run.id, &url, "failed", &dump_note,
                        )
                        .await;
                    } else {
                        // Tri-state, same words as a fresh backup: `failed`
                        // means we LOOKED and a file is not there.
                        let (state, note) =
                            ftp_verify_run(&archive_path, dump_path.as_deref(), &up).await;
                        let _ = hyperion_state::backups::set_remote(
                            &self.pool, run.id, &url, state, &note,
                        )
                        .await;
                        if state != "failed" {
                            landed = true;
                        }
                    }
                }
                Err(e) => {
                    // FTP failed. An S3 target below may still take the copy,
                    // and the drop gate is what decides safety — but the FTP
                    // record must not go on claiming what may no longer be
                    // true. A re-push OVERWRITES the remote file, so one that
                    // died half-way can leave a truncated archive behind a row
                    // still reading "off-site ✓", and the off-site restore
                    // would then fetch that. Look at what is there now and
                    // record that; nothing at all was recorded before, so a
                    // run that never made it off-site showed no reason why.
                    let (state, _) = ftp_verify_run(&archive_path, dump_path.as_deref(), &up).await;
                    let ftp_on_record = matches!(run.remote_state.as_str(), "ok" | "verified");
                    if state == "failed" || (!ftp_on_record && state != "verified") {
                        let why = if state == "failed" {
                            format!(
                                "off-site push failed: {e} — the remote copy is now missing or \
                                 the wrong size"
                            )
                        } else {
                            format!("off-site push failed: {e}")
                        };
                        let _ = hyperion_state::backups::set_remote(
                            &self.pool,
                            run.id,
                            &run.remote_blob_key,
                            "failed",
                            &why,
                        )
                        .await;
                    }
                }
            }
        }

        // ── S3 (master-resolved, honouring the hosting's pin) ──
        let mut s3_push_ok: std::collections::HashSet<String> = Default::default();
        let mut s3_pushed_targets: Vec<&hyperion_types::S3BackupTarget> = Vec::new();
        if !s3_targets.is_empty() {
            let mut files: Vec<std::path::PathBuf> = vec![archive_path.clone()];
            if let Some(dp) = dump_path.as_ref() {
                files.push(dp.clone());
            }
            let pin = self.offsite_pin(detail.id.as_str()).await;
            match choose_offsite_targets(pin.as_deref(), s3_targets) {
                OffsiteChoice::NodeDefault(t) => {
                    s3_push_ok.extend(self.push_backup_to_s3(&detail, &files, t).await);
                    // Re-borrow from the fn-scoped slice, not the pin-tied one.
                    s3_pushed_targets.extend(s3_targets.iter());
                }
                OffsiteChoice::Pinned(t) => {
                    s3_push_ok.extend(
                        self.push_backup_to_s3(&detail, &files, std::slice::from_ref(t))
                            .await,
                    );
                    if let Some(row) = s3_targets.iter().find(|x| std::ptr::eq(*x, t)) {
                        s3_pushed_targets.push(row);
                    }
                }
                // Pinned-but-unusable, or nothing to push to: the fresh-backup
                // path audits these; here the row already carries its state and
                // a re-push adds no new information, so stay quiet.
                OffsiteChoice::Unresolved(_) | OffsiteChoice::NoTargets => {}
            }
            if !s3_push_ok.is_empty() {
                landed = true;
            }
            // Keep the run's record of complete S3 pushes true: a target
            // pushed in full now is added, and one that was pushed to now and
            // did NOT complete is removed — its object may have just been
            // overwritten with a truncated one, and for an age target this
            // record is all that stands between "the object exists" and "the
            // whole ciphertext exists".
            let attempted: std::collections::HashSet<&str> =
                s3_pushed_targets.iter().map(|t| t.name.as_str()).collect();
            let mut on_record: std::collections::HashSet<String> = run
                .s3_ok_targets
                .iter()
                .filter(|k| !attempted.contains(s3_evidence_name(k)))
                .cloned()
                .collect();
            on_record.extend(s3_push_ok.iter().cloned());
            let mut names: Vec<String> = on_record.into_iter().collect();
            names.sort();
            if names != run.s3_ok_targets {
                let _ =
                    hyperion_state::backups::set_s3_ok_targets(&self.pool, run.id, &names).await;
            }
            s3_push_ok = names.into_iter().collect();
        }

        if landed {
            out.pushed = true;
        } else {
            out.failed = true;
        }

        // The drop only ever runs on a push that landed somewhere, and even
        // then the gate independently re-verifies before it removes anything.
        if drop_local && landed {
            let mut files: Vec<(&str, &std::path::Path)> =
                vec![("archive", archive_path.as_path())];
            if let Some(d) = dump_path.as_deref() {
                files.push(("database dump", d));
            }
            // The row as this push left it (remote state, S3 evidence): the
            // gate re-reads it before deleting and refuses if it moved.
            let fresh = match hyperion_state::backups::get_by_id(&self.pool, run.id).await {
                Ok(Some(r)) => r,
                _ => {
                    out.kept_local = true;
                    out.s3_push_ok = s3_push_ok;
                    return out;
                }
            };
            match self
                .maybe_drop_local_after_offsite(
                    &detail,
                    &fresh,
                    &archive_path,
                    &files,
                    &s3_pushed_targets,
                    &s3_push_ok,
                    1,
                    Some(&fresh.local_note),
                )
                .await
            {
                DropLocalOutcome::Dropped => out.dropped = true,
                _ => out.kept_local = true,
            }
        }
        out.s3_push_ok = s3_push_ok;
        out
    }

    /// Push local backups that have never reached the off-site store, oldest
    /// first (the oldest is the closest to being pruned off local disk).
    ///
    /// `drop_local` additionally removes each local copy once it is
    /// independently confirmed off-site; `s3_targets` are the master-resolved
    /// S3 destinations (empty keeps the FTP-only behaviour). Estate-wide, so it
    /// walks EVERY tenant's rows on this node — the caller must hold the
    /// estate-wide authorization.
    pub async fn backup_offsite_backfill(
        &self,
        limit: i64,
        drop_local: bool,
        s3_targets: Vec<hyperion_types::S3BackupTarget>,
    ) -> Result<hyperion_types::OffsiteBackfillResult, RpcError> {
        let mut out = hyperion_types::OffsiteBackfillResult::default();
        if self.remote_backup.is_none() && s3_targets.is_empty() {
            return Err(RpcError::Validation {
                message: "no off-site backup target is configured on this node".into(),
            });
        }
        let runs = hyperion_state::backups::list_needing_offsite(&self.pool, limit.clamp(1, 500))
            .await
            .map_err(|e| RpcError::Internal_with(format!("backfill list: {e}")))?;
        out.considered = runs.len() as i64;
        // Push first, drop after: the drop is applied per site below, under the
        // node's "keep the newest N local copies" rule, so a sweep never drops
        // a copy the node is set to keep. What each push proved is carried
        // over as evidence (an age-encrypted target can only confirm a copy
        // this process just pushed in full).
        let mut evidence: std::collections::HashMap<i64, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        let mut sites: Vec<HostingId> = Vec::new();
        for run in runs {
            let o = self.push_run_offsite(&run, &s3_targets, false).await;
            out.pushed += o.pushed as i64;
            out.failed += o.failed as i64;
            out.missing_locally += o.missing_locally as i64;
            if o.pushed {
                evidence.insert(run.id, o.s3_push_ok);
                if !sites.contains(&run.hosting_id) {
                    sites.push(run.hosting_id.clone());
                }
            }
        }
        if drop_local {
            // Also every site still holding a local copy of a backup that was
            // ALREADY off-site — those were never "needing off-site", so the
            // push above never saw them, and they are exactly the copies an
            // operator who just switched dropping on is looking at.
            match hyperion_state::backups::hostings_with_offsite_local_copies(&self.pool).await {
                Ok(more) => {
                    for h in more {
                        if !sites.contains(&h) {
                            sites.push(h);
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e,
                    "backfill: could not list sites with off-site copies still on disk"),
            }
            let policy = read_local_copy_policy(self.agent_config_path.as_deref());
            let keep = policy.keep_latest;
            if policy.keep_unreadable {
                // "Keep none" is the most aggressive reading of a typo; refuse
                // to drop anything until the file says what it means.
                sites.clear();
                out.note = "No local copy was deleted: [backup] keep_local_latest in this node's \
                            agent.toml is not a whole number — fix it (Settings → Backups \
                            → Local copies) and run this again."
                    .into();
            }
            let targets: Vec<&hyperion_types::S3BackupTarget> = s3_targets.iter().collect();
            for h in sites {
                let Ok(detail) = self.get(HostingSelector::Id(h)).await else {
                    continue;
                };
                for (id, o) in self
                    .enforce_local_copies(&detail, keep, &targets, &evidence)
                    .await
                {
                    match o {
                        DropLocalOutcome::Dropped => {
                            out.dropped += 1;
                            if !evidence.contains_key(&id) {
                                out.already_offsite += 1;
                            }
                        }
                        DropLocalOutcome::MissingLocally => out.missing_locally += 1,
                        o if o.kept() => out.kept_local += 1,
                        _ => {}
                    }
                }
            }
        }
        self.append_audit(
            "backup.offsite_backfill",
            None,
            &serde_json::json!({
                "considered": out.considered,
                "pushed": out.pushed,
                "failed": out.failed,
                "missing_locally": out.missing_locally,
                "dropped": out.dropped,
                "kept_local": out.kept_local,
                "already_offsite": out.already_offsite,
                "drop_local": drop_local,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(out)
    }

    /// Push one or more EXISTING local backups of a single hosting off-site,
    /// then — when `drop_local` — delete each local copy once it is
    /// independently confirmed off-site. The per-node backup id is bound to the
    /// authorized hosting via `backup_owned_by`, so an unbound id cannot reach
    /// another site's backups.
    pub async fn backup_offsite_push_drop(
        &self,
        sel: HostingSelector,
        backup_ids: Vec<i64>,
        s3_targets: Vec<hyperion_types::S3BackupTarget>,
        drop_local: bool,
    ) -> Result<hyperion_types::OffsiteBackfillResult, RpcError> {
        // There has to be somewhere to push, or this is a no-op that would read
        // as success — and, with drop on, an invitation to delete a local copy
        // that reached nowhere.
        if self.remote_backup.is_none() && s3_targets.is_empty() {
            return Err(RpcError::Validation {
                message: "no off-site backup target is configured — nothing to push to".into(),
            });
        }
        // Resolve the hosting once, both to fail fast on a bad selector and to
        // label the audit; each id is still re-bound to it below.
        let detail = self.get(sel.clone()).await?;
        let mut out = hyperion_types::OffsiteBackfillResult::default();
        for id in backup_ids {
            let run = match self.backup_owned_by(sel.clone(), id).await {
                Ok(r) => r,
                // A tampered/stale id that does not belong to this hosting: not
                // a push failure of a real backup, but the caller asked for it,
                // so it is not silently ignored either.
                Err(_) => {
                    out.failed += 1;
                    continue;
                }
            };
            // A still-running backup has no complete archive to send.
            if run.state == "running" {
                out.failed += 1;
                continue;
            }
            // A rollback snapshot is never eligible — skip it silently rather
            // than counting a failure the operator did not cause. The button
            // is hidden for these rows; reaching here means a tampered/stale
            // POST, which is exactly what the shared-path guard also stops.
            if run.no_offsite {
                continue;
            }
            out.considered += 1;
            // Already off-site on record? Re-check it where it is and drop the
            // local copy without sending it again — the gate verifies each
            // file independently, so this is exactly as safe as dropping
            // after a fresh push, and a 300 MiB archive that is already on
            // the FTP does not cross the wire twice. Silent on refusal: the
            // push below is the fallback and reports for itself.
            if drop_local && run.offsite_on_record() && run.archive_path.is_some() {
                let targets: Vec<&hyperion_types::S3BackupTarget> = s3_targets.iter().collect();
                match self
                    .drop_run_local_if_offsite(&detail, run.id, &targets, None)
                    .await
                {
                    DropLocalOutcome::Dropped => {
                        out.dropped += 1;
                        out.already_offsite += 1;
                        continue;
                    }
                    // Already off-site and no longer on disk: the row was set
                    // straight; there is nothing to send or drop.
                    DropLocalOutcome::MissingLocally => {
                        out.missing_locally += 1;
                        continue;
                    }
                    // A restore or push is using it right now — try later.
                    DropLocalOutcome::Busy => {
                        out.kept_local += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            let o = self.push_run_offsite(&run, &s3_targets, drop_local).await;
            out.pushed += o.pushed as i64;
            out.failed += o.failed as i64;
            out.missing_locally += o.missing_locally as i64;
            out.dropped += o.dropped as i64;
            out.kept_local += o.kept_local as i64;
        }
        self.append_audit(
            "backup.offsite_push_drop",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "considered": out.considered,
                "pushed": out.pushed,
                "failed": out.failed,
                "missing_locally": out.missing_locally,
                "dropped": out.dropped,
                "kept_local": out.kept_local,
                "already_offsite": out.already_offsite,
                "drop_local": drop_local,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(out)
    }

    /// Fetch a backup back off the remote store and restore it.
    ///
    /// The half that did not exist. An off-site copy that cannot be read back
    /// is not a backup, and until now nothing in this codebase could read one.
    ///
    /// The download lands under the incoming directory the upload restore path
    /// already whitelists, so the archive goes through exactly the same
    /// extractor — sandboxed, symlink-refusing, permission-repairing — as one
    /// the operator uploaded by hand. Nothing about "it came from the remote"
    /// gets it a shortcut.
    pub async fn backup_offsite_restore(
        &self,
        sel: HostingSelector,
        filename: String,
        mode: hyperion_types::BackupRestoreMode,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel.clone()).await?;
        let Some((mut up, dir)) = self.remote_upload_for(&detail) else {
            return Err(RpcError::Validation {
                message: "no off-site backup target is configured on this node".into(),
            });
        };
        up.remote_dir = &dir;
        // The remote folder is shared by every hosting of this system user;
        // only this site's own archives may be put back over it.
        if !offsite_file_belongs(&detail.domain, &filename) || filename.ends_with(".sql") {
            return Err(RpcError::Validation {
                message: format!(
                    "{filename:?} is not an off-site backup of {}",
                    detail.domain
                ),
            });
        }
        // Under the per-hosting incoming directory, which `backup_restore`
        // already allows and which keeps one site's fetched archive out of
        // another's — and in a folder of its OWN inside it. With one shared
        // folder, two restores of the same archive wrote the same path, and
        // the second download truncated the file the first was extracting.
        let dest_dir = std::path::PathBuf::from("/var/lib/hyperion/backups/incoming")
            .join(detail.id.as_str())
            .join(format!(
                "offsite-{}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));
        tokio::fs::create_dir_all(&dest_dir)
            .await
            .map_err(|e| RpcError::Internal_with(format!("create {}: {e}", dest_dir.display())))?;
        // Whatever happens next, the fetched copy goes: it is still on the
        // remote, and a multi-GB archive left here after every restore filled
        // the node one restore at a time — nothing else ever cleans this
        // folder.
        let restored = self
            .offsite_fetch_and_restore(sel, &detail, &up, &dest_dir, &filename, mode)
            .await;
        if let Err(e) = tokio::fs::remove_dir_all(&dest_dir).await {
            tracing::warn!(dir = %dest_dir.display(), error = %e,
                "off-site restore: could not remove the fetched copy");
        }
        restored
    }

    /// Delete one backup's copy from the FTP/FTPS/SFTP target — the archive
    /// and the database dump beside it.
    ///
    /// Named either by `backup_id` (a row of this site, whose recorded upload
    /// URL gives the file) or by `filename` (the Off-site copies card, which
    /// lists the server itself and may show files no row knows about any
    /// more). Either way only this site's own files: the folder is shared by
    /// every hosting of the system user.
    ///
    /// Rows that pointed at the file stop claiming it: a row with nothing
    /// else left — no local archive, no S3 copy — is deleted, any other is
    /// marked `removed` so the backfill does not send it straight back.
    pub async fn backup_offsite_delete(
        &self,
        sel: HostingSelector,
        backup_id: Option<i64>,
        filename: Option<String>,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel.clone()).await?;
        let Some((mut up, dir)) = self.remote_upload_for(&detail) else {
            return Err(RpcError::Validation {
                message: "no FTP/SFTP off-site target is configured on this node".into(),
            });
        };
        up.remote_dir = &dir;
        let name = match (backup_id, filename) {
            (Some(id), _) => {
                let run = self.backup_owned_by(sel, id).await?;
                hyperion_types::limits::ftp_archive_name(&run.remote_blob_key)
                    .map(str::to_string)
                    .ok_or_else(|| RpcError::Validation {
                        message: "this backup has no copy on the FTP target".into(),
                    })?
            }
            (None, Some(f)) => f.trim().to_string(),
            (None, None) => {
                return Err(RpcError::Validation {
                    message: "name a backup or a file to delete".into(),
                })
            }
        };
        if !offsite_file_belongs(&detail.domain, &name) || name.ends_with(".sql") {
            return Err(RpcError::Validation {
                message: format!("{name:?} is not an off-site backup of {}", detail.domain),
            });
        }
        let dump = format!("{}.sql", offsite_stem(&name));
        let deleted =
            hyperion_adapters::backup::delete_remote(&[name.as_str(), dump.as_str()], &up).await;
        let (forgotten, rows_deleted) = if deleted.is_ok() {
            self.forget_ftp_copies(
                &detail,
                std::slice::from_ref(&name),
                "deleted from the off-site target",
                backup_id,
            )
            .await
        } else {
            (0, 0)
        };
        self.append_audit(
            "hosting.backup.offsite_delete",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "file": name,
                "backup_id": backup_id,
                "rows_marked": forgotten,
                "rows_deleted": rows_deleted,
                "error": deleted.as_ref().err().map(|e| e.to_string()),
            })
            .to_string(),
            if deleted.is_ok() { "ok" } else { "failed" },
        )
        .await;
        deleted.map_err(|e| RpcError::Internal_with(format!("off-site delete: {e}")))?;
        Ok(format!(
            "deleted {name} (and its database dump, if it had one) from the off-site target"
        ))
    }

    /// Make this site's rows stop claiming FTP copies that are gone: delete a
    /// row with nothing else left, mark any other `removed` with `why`.
    /// `spare` is a row the caller deletes itself right after (the backups
    /// list's "delete everywhere"): only marked, so the caller's own delete
    /// still finds it rather than reporting "not found" for a delete that
    /// worked. Returns `(marked, deleted)`.
    pub(super) async fn forget_ftp_copies(
        &self,
        detail: &HostingDetail,
        names: &[String],
        why: &str,
        spare: Option<i64>,
    ) -> (usize, usize) {
        let Ok(rows) = hyperion_state::backups::list_for(&self.pool, &detail.id, 10_000).await
        else {
            return (0, 0);
        };
        let (mut marked, mut deleted) = (0, 0);
        for r in rows {
            let Some(n) = hyperion_types::limits::ftp_archive_name(&r.remote_blob_key) else {
                continue;
            };
            if !names.iter().any(|x| x == n) {
                continue;
            }
            if r.archive_path.is_none()
                && r.s3_ok_targets.is_empty()
                && r.state != "running"
                && spare != Some(r.id)
            {
                if hyperion_state::backups::delete_by_id(&self.pool, r.id)
                    .await
                    .is_ok()
                {
                    deleted += 1;
                }
            } else if hyperion_state::backups::set_remote(&self.pool, r.id, "", "removed", why)
                .await
                .is_ok()
            {
                marked += 1;
            }
        }
        (marked, deleted)
    }

    /// The FTP keep-latest rule: after a push, delete this site's archives on
    /// the FTP target beyond the newest `keep`, with their dumps. `keep` 0 is
    /// off. Never touches `just_pushed`, and never deletes on a listing it
    /// could not read. Returns how many archives went.
    pub(super) async fn prune_ftp_keep_latest(
        &self,
        detail: &HostingDetail,
        up: &hyperion_adapters::backup::RemoteUpload<'_>,
        keep: usize,
        just_pushed: &str,
    ) -> Result<usize, String> {
        if keep == 0 {
            return Ok(0);
        }
        let Some(files) = hyperion_adapters::backup::list_remote(up)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(0);
        };
        let drop = ftp_archives_beyond_keep(
            &detail.domain,
            files.iter().map(|f| f.name.as_str()),
            keep,
            just_pushed,
        );
        if drop.is_empty() {
            return Ok(0);
        }
        let dumps: Vec<String> = drop
            .iter()
            .map(|n| format!("{}.sql", offsite_stem(n)))
            .collect();
        let mut all: Vec<&str> = drop.iter().map(String::as_str).collect();
        all.extend(dumps.iter().map(String::as_str));
        hyperion_adapters::backup::delete_remote(&all, up)
            .await
            .map_err(|e| e.to_string())?;
        self.forget_ftp_copies(
            detail,
            &drop,
            &format!("deleted from the off-site target by its keep-newest-{keep} rule"),
            None,
        )
        .await;
        self.append_audit(
            "hosting.backup.offsite_prune",
            Some(detail.id.as_str()),
            &serde_json::json!({ "keep": keep, "deleted": drop }).to_string(),
            "ok",
        )
        .await;
        Ok(drop.len())
    }

    /// The body of [`Self::backup_offsite_restore`]: everything it fetches
    /// lands in `dest_dir`, which the caller removes afterwards.
    pub(super) async fn offsite_fetch_and_restore(
        &self,
        sel: HostingSelector,
        detail: &HostingDetail,
        up: &hyperion_adapters::backup::RemoteUpload<'_>,
        dest_dir: &std::path::Path,
        filename: &str,
        mode: hyperion_types::BackupRestoreMode,
    ) -> Result<String, RpcError> {
        let dest = dest_dir.join(filename);
        // Room for the archive, the dump beside it and the extraction to come.
        // A remote serving an endless stream must not be able to fill the node
        // and take every site on it down; unknown free space falls back to a
        // fixed ceiling rather than to none. Measured once the folder exists:
        // `df` on a path that is not there fails, and every first restore of a
        // site used to run on the fallback instead of the real number.
        let mut budget = fs_avail_bytes(dest_dir)
            .await
            .map(|free| free.saturating_sub(free / 5))
            .unwrap_or(64 * 1024 * 1024 * 1024);

        // The DATABASE — fetched FIRST.
        //
        // `backup_restore` finds the dump as a SIBLING of the archive — same
        // directory, same stem, `.sql` — so fetching only the tar meant the
        // file was never there, the restore quietly did files only, and the
        // panel reported "files and database restored". A restore that says it
        // put the database back and did not is worse than one that refuses,
        // because the operator stops looking.
        //
        // First, because the refusal for a missing dump used to come only
        // after the whole archive had crossed the wire — gigabytes downloaded
        // to be thrown away. And only for a site that HAS a database: one
        // without has nothing to put a dump into, and refusing it for a dump
        // it does not need turned "files and database" into a dead button.
        let mut db_fetched = false;
        if mode.restores_db() && detail.database.is_some() {
            let dump_name = format!(
                "{}.sql",
                filename
                    .strip_suffix(".tar.gz")
                    .or_else(|| filename.strip_suffix(".tgz"))
                    .unwrap_or(filename)
            );
            match hyperion_adapters::backup::download_remote(
                &dump_name,
                &dest_dir.join(&dump_name),
                up,
                budget,
            )
            .await
            {
                Ok(n) => {
                    db_fetched = true;
                    budget = budget.saturating_sub(n);
                    tracing::info!(domain=%detail.domain, file=%dump_name, bytes=n,
                        "off-site restore: database dump fetched");
                }
                Err(e) => {
                    // Refuse rather than silently degrade to files-only.
                    return Err(RpcError::Validation {
                        message: format!(
                            "the off-site copy of {filename} has no database dump beside it \
                             ({dump_name}): {e}. Restore the files only, or pick a backup whose \
                             dump is on the remote too."
                        ),
                    });
                }
            }
        }
        let bytes = hyperion_adapters::backup::download_remote(filename, &dest, up, budget)
            .await
            .map_err(|e| RpcError::Internal_with(format!("off-site download: {e}")))?;
        tracing::info!(domain=%detail.domain, file=%filename, bytes,
            "off-site restore: archive fetched");
        // The restore runs FIRST; the audit row records what happened rather
        // than what was intended. Writing "ok" before the work is a claim
        // about the future.
        let restored = self
            .backup_restore(sel, dest.display().to_string(), mode)
            .await;
        self.append_audit(
            "hosting.backup.offsite_restore",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "file": filename,
                "bytes": bytes,
                "mode": mode.as_str(),
                "database_fetched": db_fetched,
            })
            .to_string(),
            if restored.is_ok() { "ok" } else { "failed" },
        )
        .await;
        restored?;
        Ok(format!(
            "restored {filename} ({bytes} bytes){} from the off-site copy",
            if db_fetched { " and its database" } else { "" }
        ))
    }

    // ============================================================
    //  backup_targets — off-site S3-compatible destinations.
    //  This commit ships the CONFIG storage + probe (curl HEAD
    //  against the bucket) + UI; the actual scheduled upload
    //  loop lands as the next commit so this one stays
    //  readable. Operators can configure their Wasabi / B2 /
    //  Minio bucket today and verify the credentials work
    //  via the probe; uploads start flowing once the runner
    //  ships.
    // ============================================================

    pub async fn backup_target_list(
        &self,
    ) -> Result<Vec<hyperion_types::BackupTargetView>, RpcError> {
        let rows = hyperion_state::backup_targets::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup_target_list: {e}")))?;
        Ok(rows.into_iter().map(backup_target_row_to_view).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn backup_target_upsert(
        &self,
        id: Option<i64>,
        name: String,
        kind: String,
        endpoint: String,
        bucket: String,
        region: String,
        access_key_id: String,
        secret_key: Option<String>,
        age_recipient: Option<String>,
        retention_daily: i64,
        retention_weekly: i64,
        retention_monthly: i64,
        enabled: bool,
    ) -> Result<i64, RpcError> {
        // Minimal validation — name + endpoint + bucket can't be
        // empty; rest is up to the operator (an empty
        // age_recipient means "no client-side encryption", which
        // we warn about in the UI but allow).
        if name.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "target name is required".into(),
            });
        }
        if endpoint.trim().is_empty() || bucket.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "endpoint + bucket are required".into(),
            });
        }
        // Secret handling: when the caller passed a fresh
        // secret_key, persist it under /etc/hyperion/secrets/ with
        // 0600 perms and store the path back in the row. When
        // secret_key is None on an UPDATE, leave the existing
        // secret_key_id alone (lets the UI render the form
        // without re-prompting for the secret on every edit).
        let now = now_secs();
        let mut replaced_secret: Option<String> = None;
        let secret_path = if let Some(plaintext) = secret_key.as_deref() {
            // Random filename — it must NOT depend on the row id. For a NEW
            // target the id is unknown here, and the old code reused
            // `backup-0.key` (id.unwrap_or(0)), so every newly-created target
            // overwrote the previous one's secret and both rows pointed at the
            // same file → wrong credentials. A fresh ULID-named file per write
            // makes multi-target collision impossible.
            let fresh = format!(
                "/etc/hyperion/secrets/backup-{}.key",
                ulid::Ulid::new().to_string().to_ascii_lowercase()
            );
            // The target's current secret, if it has one: replaced below once
            // the row points at the new file, so stale credentials don't
            // linger on disk.
            let current = match id {
                Some(existing_id) => hyperion_state::backup_targets::get(&self.pool, existing_id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|r| r.secret_key_id),
                None => None,
            };
            if let Err(e) = write_secret_file(&fresh, plaintext.as_bytes()).await {
                tracing::warn!(path = %fresh, error = %e, "backup secret write failed");
                // An edit of a target that has working credentials is
                // refused: the old code stored the new (never written) path
                // and deleted the old file first, so a full disk or a
                // permissions slip cost the target its credentials.
                if current.is_some() {
                    return Err(RpcError::Internal_with(format!(
                        "could not store the new secret key ({e}) — the target keeps its \
                         current one and was not changed"
                    )));
                }
                // A new target (or one with no secret yet) is stored without
                // a secret: the Backups page shows it as taking no copy, and
                // why, rather than pointing at a file that does not exist.
                None
            } else {
                replaced_secret = current.filter(|p| *p != fresh);
                Some(fresh)
            }
        } else if let Some(existing_id) = id {
            // No new secret on update → keep the existing path.
            hyperion_state::backup_targets::get(&self.pool, existing_id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("backup_target get: {e}")))?
                .and_then(|r| r.secret_key_id)
        } else {
            None
        };

        let new_id = hyperion_state::backup_targets::upsert(
            &self.pool,
            hyperion_state::backup_targets::UpsertReq {
                id,
                name: name.trim(),
                kind: kind.trim(),
                endpoint: endpoint.trim(),
                bucket: bucket.trim(),
                region: region.trim(),
                access_key_id: access_key_id.trim(),
                secret_key_id: secret_path.as_deref(),
                age_recipient: age_recipient.as_deref(),
                retention_daily,
                retention_weekly,
                retention_monthly,
                enabled,
                now,
            },
        )
        .await;
        let new_id = match new_id {
            Ok(id) => id,
            Err(e) => {
                // The row still points at the old secret; the new file is
                // the one to drop.
                if secret_key.is_some() {
                    if let Some(p) = &secret_path {
                        let _ = tokio::fs::remove_file(p).await;
                    }
                }
                return Err(RpcError::Internal_with(format!(
                    "backup_target upsert: {e}"
                )));
            }
        };
        if let Some(old) = replaced_secret {
            let _ = tokio::fs::remove_file(&old).await;
        }

        self.append_audit(
            "backup.target.upsert",
            Some(&new_id.to_string()),
            &serde_json::json!({
                "name": name,
                "endpoint": endpoint,
                "bucket": bucket,
                "enabled": enabled,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(new_id)
    }

    pub async fn backup_target_delete(&self, id: i64) -> Result<(), RpcError> {
        // Best-effort: shred the on-disk secret file too, so deleting a target
        // doesn't leave its S3 credentials lying in /etc/hyperion/secrets.
        if let Ok(Some(row)) = hyperion_state::backup_targets::get(&self.pool, id).await {
            if let Some(path) = row.secret_key_id {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        hyperion_state::backup_targets::delete(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup_target delete: {e}")))?;
        self.append_audit("backup.target.delete", Some(&id.to_string()), "{}", "ok")
            .await;
        Ok(())
    }

    pub async fn backup_target_probe(
        &self,
        id: i64,
    ) -> Result<hyperion_types::BackupTargetProbe, RpcError> {
        let target = hyperion_state::backup_targets::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup_target get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "backup_target".into(),
                id: id.to_string(),
            })?;
        // Probe: HEAD <endpoint>/<bucket>/. AWS-style auth is
        // operator-handled via aws CLI configured on the host (the
        // runner shells out to `aws --endpoint-url=… s3 cp`). The
        // probe here just confirms the endpoint is reachable +
        // returns valid HTTP. Real auth verification ships with
        // the runner.
        let url = format!(
            "{}/{}",
            target.endpoint.trim_end_matches('/'),
            target.bucket
        );
        let start = now_secs();
        let out = tokio::process::Command::new("/usr/bin/curl")
            .args([
                "-sS",
                "-I",
                "--max-time",
                "10",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                &url,
            ])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("spawn curl: {e}")))?;
        let latency = (now_secs() - start) * 1000;
        let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // Any HTTP code that isn't a connection error counts as
        // "endpoint reachable". 200/403 (forbidden without creds)
        // are both fine — they prove the bucket URL responds. DNS
        // failure / TCP refused / timeout ⇒ curl exits non-zero.
        let ok = out.status.success() && !code.is_empty();
        let message = if ok {
            format!("endpoint reachable (HTTP {code})")
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            format!(
                "probe failed: {} (curl exit {:?})",
                stderr.trim(),
                out.status.code()
            )
        };
        Ok(hyperion_types::BackupTargetProbe {
            ok,
            message,
            put_latency_ms: latency,
        })
    }

    /// Connection check for the node's configured FTP/FTPS/SFTP off-site target
    /// (`[backup_remote]`): connect + log in + list the base directory. Lets the
    /// operator confirm the target works without running a whole backup.
    pub async fn backup_remote_probe(&self) -> Result<hyperion_types::BackupTargetProbe, RpcError> {
        let Some(remote) = self.remote_backup.as_ref() else {
            return Ok(hyperion_types::BackupTargetProbe {
                ok: false,
                message: "no FTP/FTPS/SFTP off-site target is configured on this node".into(),
                put_latency_ms: 0,
            });
        };
        let upload = hyperion_adapters::backup::RemoteUpload {
            scheme: &remote.scheme,
            host: &remote.host,
            port: remote.port,
            user: &remote.user,
            password: &remote.password,
            remote_dir: &remote.base_path,
        };
        let (ok, message, latency_ms) = hyperion_adapters::backup::probe_remote(&upload).await;
        Ok(hyperion_types::BackupTargetProbe {
            ok,
            message,
            put_latency_ms: latency_ms as i64,
        })
    }
}

/// Where a backup run's off-site targets came from, and therefore what an
/// EMPTY set of them means. Nothing downstream can tell from the list alone,
/// and guessing is wrong in both directions: read every empty list as
/// "nothing was wanted" and a worker's scheduled backups quietly stop leaving
/// the node; read every empty list as a failure and an install that never
/// bought off-site storage collects a red audit row per backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OffsiteSource {
    /// The panel or the API resolved the cluster's targets on the MASTER
    /// (where the table lives) and sent them with the request. Empty
    /// therefore means the operator has none that can take a copy — which
    /// the Backups card already says — so there is nothing to report.
    Caller,
    /// A scheduled run, using THIS node's own `backup_targets` table. On the
    /// master that is the same table the panel reads; on a worker it is empty
    /// by design, so empty here means the cluster's targets never reached the
    /// run rather than that no copy was wanted.
    ThisNode,
    /// An internal snapshot taken as a rollback safety net — the pre-export
    /// and pre-push backups. Nothing off-site was ever intended, so nothing
    /// is missing when nothing is uploaded.
    NotWanted,
}

/// Why a scheduled backup on a worker never leaves the node. Shared by the
/// audit row and the sweep's log line so the operator reads one explanation,
/// not two that have drifted apart.
pub(super) const OFFSITE_WORKER_HAS_NO_TARGETS: &str =
    "no off-site target reached this scheduled run: the cluster's off-site targets live in the \
     master's table and the master's settings sync has not reached this node yet, so this backup \
     exists only on this node. The sync runs every few minutes once the master and this node are \
     on the same version — the Nodes page shows whether this node is in sync";

/// Which of the resolved off-site targets one hosting's backup may use.
/// Borrows the caller's slice — nothing is copied until an upload happens.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum OffsiteChoice<'a> {
    /// No pin: every target the caller resolved. Never empty — "resolved
    /// nothing" is `NoTargets`, which is a different thing to report.
    NodeDefault(&'a [hyperion_types::S3BackupTarget]),
    /// Pinned to one target that is in the resolved set.
    Pinned(&'a hyperion_types::S3BackupTarget),
    /// Pinned to a target that ISN'T in the resolved set — disabled, deleted,
    /// renamed, its secret file didn't read, or this run carries no targets
    /// at all. Nothing is pushed: someone chose where this client's data
    /// goes, so silently falling back to the node's other buckets would put
    /// it somewhere nobody picked.
    Unresolved(&'a str),
    /// Unpinned, and the run resolved no targets. Whether that is a failure
    /// depends on where the (empty) list came from — see `OffsiteSource`.
    NoTargets,
}

/// Resolve one hosting's off-site destination against the targets the caller
/// already resolved (the master's table for a manual run, this node's for a
/// scheduled one).
///
/// An empty `resolved` used to swallow the pin and report the node default,
/// on the grounds that the callers passing none wanted none. That is what let
/// a worker's scheduled backup ignore a pin in silence: the caller's intent
/// now travels with the run as an `OffsiteSource`, so this function can say
/// plainly that a pinned target was not available.
pub(super) fn choose_offsite_targets<'a>(
    pin: Option<&'a str>,
    resolved: &'a [hyperion_types::S3BackupTarget],
) -> OffsiteChoice<'a> {
    match pin.map(str::trim).filter(|s| !s.is_empty()) {
        None if resolved.is_empty() => OffsiteChoice::NoTargets,
        None => OffsiteChoice::NodeDefault(resolved),
        Some(name) => match resolved.iter().find(|t| t.name == name) {
            Some(t) => OffsiteChoice::Pinned(t),
            None => OffsiteChoice::Unresolved(name),
        },
    }
}

/// May the local copy of a just-made backup be deleted?
///
/// The whole gate for the "drop local once verified off-site" option, isolated
/// as a pure predicate because getting it wrong deletes the only copy of
/// someone's data. Two conditions, both required:
///
///   * `used_offsite` — this run actually pushed to at least one off-site
///     destination (FTP or an S3 target). Without this, a run with NO
///     off-site at all would sail through the `all()` below on an empty
///     `files_confirmed` and delete the sole copy.
///   * every local file is INDEPENDENTLY confirmed present off-site
///     (`files_confirmed` non-empty and all true). A single unconfirmed file —
///     missing, short, the wrong size, or simply unreachable to re-check —
///     keeps the whole local copy.
///
/// The empty-slice guard is not redundant with `used_offsite`: `all()` is true
/// for an empty iterator, so without it a destination that confirmed nothing
/// would still license a delete.
pub(super) fn may_drop_local_after_offsite(used_offsite: bool, files_confirmed: &[bool]) -> bool {
    used_offsite && !files_confirmed.is_empty() && files_confirmed.iter().all(|&c| c)
}

/// Is this run a LOCAL copy the drop-local policy counts: a finished, good
/// backup whose archive is still on this node, and not a rollback snapshot
/// (those are local-only by design and outside the policy altogether).
pub(super) fn is_local_copy(r: &hyperion_state::backups::BackupRun) -> bool {
    r.state == "ok" && r.archive_path.is_some() && !r.no_offsite
}

/// Which runs' local copies the drop-local option should now TRY to drop for
/// one site, given its rows NEWEST FIRST. Pure, so the selection is tested on
/// its own; the drop gate still re-verifies every one before deleting.
///
///   * Only local copies count (`is_local_copy`), and the newest
///     `keep_latest` of them stay, whatever their off-site state — the
///     operator asked for that many fast restores on the box.
///   * Past those, a run qualifies only with evidence that it went off-site:
///     its row records it (FTP `ok`/`verified`, or a completed S3 push), or the
///     caller pushed it moments ago (`just_pushed`). A run with no such evidence is not asked about at all —
///     the answer would be "no" after every backup, and an operator who wants
///     those copied off-site has the backfill for it.
pub(super) fn local_copies_to_drop(
    rows: &[hyperion_state::backups::BackupRun],
    keep_latest: usize,
    just_pushed: &std::collections::HashSet<i64>,
) -> Vec<i64> {
    rows.iter()
        .filter(|r| is_local_copy(r))
        .skip(keep_latest)
        .filter(|r| just_pushed.contains(&r.id) || r.offsite_on_record())
        .map(|r| r.id)
        .collect()
}

/// Why a run's local copy is still on disk, as `(kind, words)` for the
/// Backups card — see `BackupRunWire::local_kept` for the kinds. `rank` is the
/// run's position among the site's local copies, newest first (`None` when it
/// is not one). Derived from the node's CURRENT policy each time the list is
/// read, so it can never go stale; only the "could not confirm" reason is
/// stored, because only the drop step knows it.
pub(super) fn local_kept_reason(
    r: &hyperion_state::backups::BackupRun,
    policy: LocalCopyPolicy,
    rank: Option<usize>,
) -> (&'static str, String) {
    if !is_local_copy(r) {
        return ("", String::new());
    }
    // A drop step that actually ran and refused is the most specific answer
    // there is — including an on-demand "Off-site & drop" on a node where the
    // automatic option is off, or on one of the newest copies. The note is
    // cleared with the local paths, so it exists only while the copy does.
    if r.local_note == LOCAL_FILES_MISSING_NOTE {
        return ("missing", r.local_note.clone());
    }
    if !r.local_note.is_empty() {
        return ("unconfirmed", r.local_note.clone());
    }
    let on_record = r.offsite_on_record();
    if !policy.drop {
        return if on_record {
            (
                "setting_off",
                "Kept on this node: \"Delete the local copy once it is verified off-site\" is \
                 off for this node (Settings → Backups → Local copies)."
                    .to_string(),
            )
        } else {
            ("", String::new())
        };
    }
    if on_record && rank.is_some_and(|k| k < policy.keep_latest) {
        return (
            "keep_newest",
            format!(
                "Kept on this node: one of the {} newest local copies it is set to keep \
                 (Settings → Backups → Local copies).",
                policy.keep_latest
            ),
        );
    }
    if on_record {
        return (
            "pending",
            "Dropped after this site's next archive backup (scheduled, or Back up now), once \
             it is re-checked off-site — or now, with \"Off-site & drop\"."
                .to_string(),
        );
    }
    ("", String::new())
}

/// The reason the drop step stores on a run whose copy it kept, naming the
/// files it could not confirm off-site. Stable wording on purpose: the audit
/// row is written only when this text changes, so a copy that stays
/// unconfirmed is not re-reported after every backup.
pub(super) fn local_kept_unconfirmed_note(unconfirmed: &[&str]) -> String {
    let what = match unconfirmed {
        [] => "the off-site copy".to_string(),
        [one] => format!("the off-site copy of the {one}"),
        many => format!("the off-site copy of the {}", many.join(" and the ")),
    };
    format!(
        "Kept on this node: {what} could not be confirmed (missing, the wrong size, or the \
         target could not be reached to check)."
    )
}

/// The note on a run whose local files are not on disk although its row
/// lists them — nothing deleted, row left as it is (an unmounted backup volume
/// looks exactly like this). Shown as its own kind on the Backups card.
pub(super) const LOCAL_FILES_MISSING_NOTE: &str =
    "The local files of this backup are not on disk, although it is listed here (removed outside \
     the panel, or the backup volume is not mounted). Nothing was deleted; retention retires the \
     entry as usual.";

/// curl exit codes that mean the FTP/SFTP server was reached and logged into,
/// and ANSWERED "no" about this path: no such directory (9), could not access
/// the file (19), a command was refused (21), no such file (78). Unlike a
/// transport failure, another file on the same server may still be there.
pub(super) fn ftp_said_no(curl_exit: i32) -> bool {
    matches!(curl_exit, 9 | 19 | 21 | 78)
}

/// The `.manifest.json` written beside a backup archive:
/// `<domain>-<ts>.tar.gz` → `<domain>-<ts>.manifest.json`, same directory.
/// `None` for a path that is not a `.tar.gz` — never guess at a sibling.
pub(super) fn manifest_path_for(archive: &std::path::Path) -> Option<std::path::PathBuf> {
    let name = archive.file_name()?.to_str()?;
    let stem = name.strip_suffix(".tar.gz")?;
    if stem.is_empty() {
        return None;
    }
    Some(archive.with_file_name(format!("{stem}.manifest.json")))
}

/// Is `name` one of `domain`'s own backup files on the off-site store?
///
/// The remote folder is per system user, and hostings can share one, so a
/// listing of it holds every sibling site's archives too. `backup_run` names
/// them `<domain>-<unix seconds>.tar.gz` (and `.sql` for the dump); the stamp
/// must be all digits, so `a.cz` never claims `a.cz-shop.cz-…`.
pub(super) fn offsite_file_belongs(domain: &str, name: &str) -> bool {
    let Some(rest) = name.strip_prefix(domain).and_then(|r| r.strip_prefix('-')) else {
        return false;
    };
    let stamp = rest
        .strip_suffix(".tar.gz")
        .or_else(|| rest.strip_suffix(".tgz"))
        .or_else(|| rest.strip_suffix(".sql"));
    matches!(stamp, Some(t) if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
}

/// `<domain>-<ts>.tar.gz` → `<domain>-<ts>`: the stem the dump shares.
pub(super) fn offsite_stem(name: &str) -> &str {
    name.strip_suffix(".tar.gz")
        .or_else(|| name.strip_suffix(".tgz"))
        .unwrap_or(name)
}

/// Which of `domain`'s archives on the FTP target fall outside the newest
/// `keep` — by the unix time in the name, never the server's own dates, which
/// an FTP listing gives to the minute at best. `just_pushed` is never one of
/// them, whatever its stamp says.
pub(super) fn ftp_archives_beyond_keep<'a>(
    domain: &str,
    names: impl Iterator<Item = &'a str>,
    keep: usize,
    just_pushed: &str,
) -> Vec<String> {
    let mut archives: Vec<(i64, &str)> = names
        .filter(|n| offsite_file_belongs(domain, n) && !n.ends_with(".sql"))
        .filter_map(|n| {
            let stamp = offsite_stem(n).rsplit('-').next()?.parse::<i64>().ok()?;
            Some((stamp, n))
        })
        .collect();
    archives.sort_by(|a, b| b.cmp(a));
    archives
        .into_iter()
        .skip(keep.max(1))
        .map(|(_, n)| n)
        .filter(|n| *n != just_pushed)
        .map(str::to_string)
        .collect()
}

/// `[backup_remote] keep_latest`, read live: 0 (or missing, or not a whole
/// number) is off — a typo must never be read as "keep nothing".
pub(crate) fn read_ftp_keep_latest(cfg_path: Option<&std::path::Path>) -> usize {
    read_agent_doc(cfg_path)
        .as_ref()
        .and_then(|d| d.get("backup_remote"))
        .and_then(|s| s.get("keep_latest"))
        .and_then(|v| v.as_integer())
        .filter(|n| *n > 0)
        .map(|n| n.min(1000) as usize)
        .unwrap_or(0)
}

/// What an FTP push can honestly claim, from the size re-check of each file it
/// sent: `(label, Some(true))` = listed back at the right size,
/// `Some(false)` = we LOOKED and it is missing or the wrong size, `None` = we
/// could not look (no size given, or unreachable).
///
/// `verified` only when EVERY file checked out — the dump is half the backup,
/// and the drop step demands both before it deletes anything, so "off-site ✓"
/// must not promise less. Any contradiction is `failed`, naming the file.
/// Otherwise `ok`: the upload returned success, and nothing proved otherwise.
pub(super) fn ftp_offsite_verdict(checks: &[(&str, Option<bool>)]) -> (&'static str, String) {
    if let Some((what, _)) = checks.iter().find(|(_, c)| *c == Some(false)) {
        return (
            "failed",
            format!("uploaded, but the remote {what} is missing or the wrong size"),
        );
    }
    if !checks.is_empty() && checks.iter().all(|(_, c)| *c == Some(true)) {
        return ("verified", String::new());
    }
    ("ok", String::new())
}

/// Re-check a just-uploaded archive (and its dump, when there is one) on the
/// FTP target and turn the answers into the run's remote state.
pub(super) async fn ftp_verify_run(
    archive: &std::path::Path,
    dump: Option<&std::path::Path>,
    up: &hyperion_adapters::backup::RemoteUpload<'_>,
) -> (&'static str, String) {
    let mut checks: Vec<(&str, Option<bool>)> = Vec::with_capacity(2);
    for (label, file) in
        std::iter::once(("archive", archive)).chain(dump.map(|d| ("database dump", d)))
    {
        let seen = match hyperion_adapters::backup::verify_remote(file, up).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(file = %file.display(), error = %e,
                    "remote backup: could not verify the uploaded copy");
                None
            }
        };
        checks.push((label, seen));
    }
    ftp_offsite_verdict(&checks)
}

/// What `maybe_drop_local_after_offsite` actually did — so an on-demand caller
/// can report "removed" vs "kept" instead of guessing from a fire-and-forget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DropLocalOutcome {
    /// Every file was confirmed off-site and the local copy was removed.
    Dropped,
    /// A destination was used but the copy was KEPT — a file could not be
    /// confirmed off-site, or the DB paths could not be cleared.
    Kept,
    /// No off-site destination was used, so there was nothing to fall back on
    /// and the local copy was left in place.
    NoDestination,
    /// KEPT because no destination answered at all (unreachable, timed out) —
    /// a sweep stops here instead of asking the same host about every older
    /// copy and waiting out every timeout.
    Unreachable,
    /// The archive is already gone from disk (and its dump too): nothing was
    /// deleted, the row was set straight. Not a "kept" copy.
    MissingLocally,
    /// Left alone because some operation on this node is using the archive
    /// right now (a restore reading it, a backup or push still sending it).
    Busy,
}

impl DropLocalOutcome {
    /// Did a local copy stay on disk although it was asked to go? What the
    /// job counts as `kept_local`.
    pub(super) fn kept(self) -> bool {
        matches!(self, Self::Kept | Self::Unreachable | Self::Busy)
    }
}

/// One file's answer from the off-site re-check (see `file_is_offsite`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OffsiteCheck {
    /// Present off-site at the right size (or, for an age target with a
    /// complete push on record, present at all).
    Confirmed,
    /// A destination answered, and it was not a confirmation — or none could
    /// be asked.
    NotConfirmed,
    /// Every destination asked failed to answer.
    Unreachable,
}

/// Backup archives some operation on THIS node is using right now — a
/// restore reading one, a backup writing and pushing its own, an on-demand
/// push sending one — counted, because two operations can hold the same file;
/// and the ones a drop is deleting right now.
///
/// The two sides exclude each other ATOMICALLY, under this one mutex: a drop
/// reserves an archive only while nobody else holds it (`try_reserve_drop`),
/// and nobody new can take it while the reservation stands
/// (`ArchiveInUse::try_claim`). Deleting an archive under a restore lets `tar`
/// finish from its open handle and then finds the database dump gone — files
/// of one moment over the database of another. In-process is enough: only the
/// agent that owns the files ever deletes them.
#[derive(Default)]
pub(super) struct ArchiveUse {
    pub(super) claims: usize,
    pub(super) dropping: bool,
}

pub(super) fn archives_in_use() -> &'static std::sync::Mutex<HashMap<std::path::PathBuf, ArchiveUse>>
{
    static IN_USE: std::sync::OnceLock<std::sync::Mutex<HashMap<std::path::PathBuf, ArchiveUse>>> =
        std::sync::OnceLock::new();
    IN_USE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// The registry key for an archive path: its directory canonicalized plus its
/// file name, so a key taken before the file exists (a backup about to write
/// it) matches one taken after, and a restore's canonical path matches the
/// row's spelling of it.
pub(super) fn archive_use_key(p: &std::path::Path) -> std::path::PathBuf {
    match (p.parent(), p.file_name()) {
        (Some(dir), Some(name)) => std::fs::canonicalize(dir)
            .unwrap_or_else(|_| dir.to_path_buf())
            .join(name),
        _ => p.to_path_buf(),
    }
}

/// Is some operation on this node using (or dropping) this archive right
/// now? A cheap pre-filter; the decision that counts is `try_reserve_drop`.
pub(super) fn archive_in_use(p: &std::path::Path) -> bool {
    let key = archive_use_key(p);
    archives_in_use()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .is_some_and(|u| u.claims > 0 || u.dropping)
}

/// Holds an archive as in use until dropped — on every exit path, so an early
/// return or an error can never leave a file protected forever.
pub(super) struct ArchiveInUse(pub(super) std::path::PathBuf);

impl ArchiveInUse {
    /// Claim an archive nobody can be dropping: one this backup is about to
    /// write.
    pub(super) fn claim(p: &std::path::Path) -> Self {
        let key = archive_use_key(p);
        archives_in_use()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default()
            .claims += 1;
        ArchiveInUse(key)
    }

    /// Claim an existing archive, unless a drop is deleting it right now.
    pub(super) fn try_claim(p: &std::path::Path) -> Option<Self> {
        let key = archive_use_key(p);
        let mut map = archives_in_use().lock().unwrap_or_else(|e| e.into_inner());
        let u = map.entry(key.clone()).or_default();
        if u.dropping {
            return None;
        }
        u.claims += 1;
        Some(ArchiveInUse(key))
    }
}

impl Drop for ArchiveInUse {
    fn drop(&mut self) {
        let mut map = archives_in_use().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(u) = map.get_mut(&self.0) {
            u.claims = u.claims.saturating_sub(1);
            if u.claims == 0 && !u.dropping {
                map.remove(&self.0);
            }
        }
    }
}

/// A drop's hold on an archive while it clears the row and deletes the files.
pub(super) struct DropReservation(pub(super) std::path::PathBuf);

/// Reserve an archive for deletion — only if nobody but the caller holds it
/// (`own_claims`: 1 when the caller itself pushed it under a claim, else 0)
/// and no other drop has it. While the reservation stands, `try_claim` fails,
/// so a restore or push cannot start on a file being deleted.
pub(super) fn try_reserve_drop(p: &std::path::Path, own_claims: usize) -> Option<DropReservation> {
    let key = archive_use_key(p);
    let mut map = archives_in_use().lock().unwrap_or_else(|e| e.into_inner());
    let u = map.entry(key.clone()).or_default();
    if u.dropping || u.claims > own_claims {
        if u.claims == 0 && !u.dropping {
            map.remove(&key);
        }
        return None;
    }
    u.dropping = true;
    Some(DropReservation(key))
}

impl Drop for DropReservation {
    fn drop(&mut self) {
        let mut map = archives_in_use().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(u) = map.get_mut(&self.0) {
            u.dropping = false;
            if u.claims == 0 {
                map.remove(&self.0);
            }
        }
    }
}

/// How a completed S3 push is recorded on a run: the target's name plus a
/// short fingerprint of WHERE and HOW it wrote — endpoint, bucket, age
/// recipient. Evidence earned against one configuration must not vouch for
/// another: an operator who edits a target in place to a new age recipient
/// (because the old identity was lost) has made every older ciphertext
/// undecryptable, and a name-only record would still let those objects
/// "confirm" a copy by existence and get the last readable copy deleted.
pub(super) fn s3_evidence_key(t: &hyperion_types::S3BackupTarget) -> String {
    let mut h = blake3::Hasher::new();
    for part in [
        t.endpoint.trim(),
        t.bucket.trim(),
        t.age_recipient.as_deref().map(str::trim).unwrap_or(""),
    ] {
        h.update(part.as_bytes());
        h.update(&[0]);
    }
    let hex = h.finalize().to_hex();
    format!("{}#{}", t.name, &hex[..16])
}

/// The target name part of an evidence key (`name#fingerprint`).
pub(super) fn s3_evidence_name(key: &str) -> &str {
    key.rsplit_once('#').map(|(n, _)| n).unwrap_or(key)
}

/// Per-run result of `push_run_offsite`, folded into an `OffsiteBackfillResult`
/// by both the estate-wide backfill and the per-hosting push-drop. Exactly one
/// of `pushed`/`failed`/`missing_locally` is set, plus at most one of
/// `dropped`/`kept_local` when a drop was requested.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RunOffsiteOutcome {
    pub(super) pushed: bool,
    pub(super) failed: bool,
    pub(super) missing_locally: bool,
    pub(super) dropped: bool,
    pub(super) kept_local: bool,
    /// The S3 targets this push FULLY succeeded to — evidence a later drop
    /// step needs for age-encrypted targets (see `file_is_offsite`).
    pub(super) s3_push_ok: std::collections::HashSet<String>,
}

pub(super) fn backup_target_row_to_view(
    r: hyperion_state::backup_targets::BackupTargetRow,
) -> hyperion_types::BackupTargetView {
    hyperion_types::BackupTargetView {
        id: r.id,
        name: r.name,
        kind: r.kind,
        endpoint: r.endpoint,
        bucket: r.bucket,
        region: r.region,
        access_key_id: r.access_key_id,
        secret_key_id: r.secret_key_id,
        age_recipient: r.age_recipient,
        retention_daily: r.retention_daily,
        retention_weekly: r.retention_weekly,
        retention_monthly: r.retention_monthly,
        enabled: r.enabled,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

/// Turn curl's stderr into the reason a health probe got no answer.
///
/// `curl -sS` prints one line such as `curl: (7) Failed to connect to
/// example.cz port 443 after 0 ms: Couldn't connect to server`. The
/// `curl: (N)` prefix is curl's exit code, which means nothing to an
/// operator; the rest is the useful part. Capped, so a pathological message
/// cannot flood the health line.
pub(super) fn curl_failure_reason(stderr: &str) -> String {
    let line = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let line = match line.strip_prefix("curl: (") {
        Some(rest) => rest.split_once(") ").map(|(_, msg)| msg).unwrap_or(rest),
        None => line,
    };
    line.chars().take(200).collect()
}
