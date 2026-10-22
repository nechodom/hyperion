//! Backups tab: run now, delete, restore, schedule and off-site target.

use super::*;

/// Does any listed backup keep its local copy only because the owning node
/// has "Delete the local copy once it is verified off-site" switched off? The
/// Archives card then says so once, above the table — "off-site ✓" next to a
/// local path otherwise reads as a delete that silently failed.
/// Does any listed backup have a copy on the FTP target? Decides whether the
/// bulk delete asks about the off-site copies at all.
pub(crate) fn any_ftp_copies(backups: &[hyperion_types::BackupRunWire]) -> bool {
    backups.iter().any(|b| b.ftp_file_name().is_some())
}

pub(crate) fn backups_kept_by_setting(backups: &[hyperion_types::BackupRunWire]) -> bool {
    backups.iter().any(|b| b.local_kept == "setting_off")
}

#[derive(Deserialize)]
pub struct BackupNowForm {
    pub selector: String,
    #[serde(default)]
    pub target_node: String,
}

/// Resolve the master's enabled S3 backup targets into upload-ready form
/// (secret read inline from its 0600 file — hyperion-web runs as root with
/// ReadWritePaths=/etc/hyperion). These ride in the `BackupNow` request so the
/// OWNING node — master OR worker — can push the backup off-site even though
/// the `backup_targets` table only lives in the master's DB. Best-effort: a
/// target whose secret file can't be read is skipped.
pub(crate) async fn resolve_s3_targets(state: &SharedState) -> Vec<hyperion_types::S3BackupTarget> {
    let rows = match hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetList).await
    {
        Ok(RpcResponse::BackupTargetList(v)) => v,
        _ => return Vec::new(),
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
    out
}

/// One entry in the Backups-card off-site picker. Names only — a target's
/// endpoint, bucket and credentials never reach the page.
pub struct BackupTargetOption {
    pub name: String,
    /// Empty when a backup could actually reach this target right now;
    /// otherwise WHY it couldn't, in the words the card prints next to it.
    pub unusable: String,
}

/// Every configured off-site target, each labelled with whether a backup could
/// actually reach it. The reasons mirror the filter in [`resolve_s3_targets`]
/// exactly: anything that function skips is listed here as unusable rather
/// than left out, so a target can't be picked (or stay picked) while quietly
/// doing nothing. The secret file is stat'd, never read — the page has no
/// business holding the plaintext.
///
/// `None` means the target list could not be read at all. Callers must not
/// flatten that into "no targets": an unreadable list would otherwise make a
/// perfectly good pin look like a dangling one.
pub(crate) async fn configured_backup_targets(
    state: &SharedState,
) -> Option<Vec<BackupTargetOption>> {
    let rows = match hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetList).await
    {
        Ok(RpcResponse::BackupTargetList(v)) => v,
        _ => return None,
    };
    let mut out = Vec::new();
    for r in rows {
        let unusable = if r.kind != "s3" {
            format!("a \"{}\" target — backups are only pushed to S3", r.kind)
        } else if !r.enabled {
            "disabled in Settings → Backups → Off-site targets".to_string()
        } else {
            match r.secret_key_id.as_deref() {
                None => "missing its secret key".to_string(),
                Some(p) if tokio::fs::metadata(p).await.is_err() => {
                    "missing its secret key file on this node".to_string()
                }
                Some(_) => String::new(),
            }
        };
        out.push(BackupTargetOption {
            name: r.name,
            unusable,
        });
    }
    Some(out)
}

/// What the card says about the target a hosting is pinned to. Empty when
/// there's no pin or the pin is fine; otherwise the sentence that stops a dead
/// pin from reading like a working one — a pinned site whose target can't take
/// the upload gets NO off-site copy at all (the runner refuses to reroute a
/// client's data to a bucket nobody chose).
pub(super) fn pinned_target_warning(pin: &str, options: &[BackupTargetOption]) -> String {
    if pin.is_empty() {
        return String::new();
    }
    match options.iter().find(|o| o.name == pin) {
        None => format!(
            "\"{pin}\" is not one of the configured off-site targets — backups of this site are \
             NOT being copied off-site."
        ),
        Some(o) if !o.unusable.is_empty() => format!(
            "\"{}\" is {} — backups of this site are NOT being copied off-site until that is fixed.",
            o.name, o.unusable
        ),
        Some(_) => String::new(),
    }
}

pub async fn post_backup_now(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupNowForm>,
) -> Result<Response, AppError> {
    // ── Synchronous pre-flight (must error immediately) ──
    // authz gate, selector resolution, dispatch-target resolution, and
    // the S3-target secret read (master-local, reads 0600 files) all
    // happen on the request thread so the operator gets auth/lookup
    // failures right away. Only the long-running BackupNow dispatch —
    // tar of the whole docroot, DB dump, optional S3 upload, which on a
    // big site is minutes — moves into the detached worker so closing
    // the browser no longer aborts the backup.
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let node = node_target(&form.target_node).map(String::from);
    let s3_targets = resolve_s3_targets(&state).await;

    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();

    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "backup",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_backup_now_job(reporter, job_state, node, sel, s3_targets).await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker: run the backup on the owning node and fold the
/// resulting archive path / size into the job log.
pub(crate) async fn run_backup_now_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    sel: HostingSelector,
    s3_targets: Vec<hyperion_types::S3BackupTarget>,
) {
    reporter
        .step("Backing up — files + database…", 10, "")
        .await;
    let job_id = reporter.id.clone();
    // The backup runs as ONE blocking RPC on the owning node. While it runs we
    // poll that node for the per-phase sub-steps it publishes under this job id
    // and mirror them into the job row, so the progress page shows subjobs
    // (files → database → off-site) advancing. The poll also keeps the row's
    // updated_at fresh, so it doubles as the stale-reaper heartbeat. `last`
    // remembers the newest non-empty sub-steps so we can finalize them from the
    // master side without a last-second node read racing the node's cleanup.
    let last: std::sync::Arc<tokio::sync::Mutex<Vec<hyperion_types::JobSubstep>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let poll = {
        let state = state.clone();
        let reporter = reporter.clone();
        let node = node.clone();
        let job_id = job_id.clone();
        let last = last.clone();
        tokio::spawn(async move {
            let mut pct = 10;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                match crate::dispatcher::dispatch_to_node(
                    &state,
                    node.as_deref(),
                    Request::BackupProgress {
                        job_id: job_id.clone(),
                    },
                )
                .await
                {
                    Ok(RpcResponse::BackupProgress(subs)) if !subs.is_empty() => {
                        *last.lock().await = subs.clone();
                        reporter.substeps(&subs).await;
                    }
                    _ => {
                        // No sub-steps yet (or an older node): keep the row
                        // alive with a coarse heartbeat so it is not reaped.
                        pct = (pct + 2).min(85);
                        reporter
                            .step("Still backing up — large sites take a while…", pct, "")
                            .await;
                    }
                }
            }
        })
    };
    let outcome = crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::BackupNow {
            sel,
            s3_targets,
            progress_job_id: Some(job_id),
        },
    )
    .await;
    poll.abort();
    // Finalize the sub-steps from the master's own last-seen list, so the card
    // does not freeze on a "running" phase after the job goes terminal. Success
    // ⇒ everything not skipped is done; failure ⇒ whatever was still in flight
    // is marked failed.
    {
        let ok = matches!(outcome, Ok(RpcResponse::BackupNow(_)));
        let mut subs = last.lock().await.clone();
        if !subs.is_empty() {
            for s in subs.iter_mut() {
                // Only promote steps still in flight. A step the node already
                // marked "failed" (e.g. a best-effort off-site copy that did
                // not land) or "skipped" must survive — the overall job is a
                // success, but forcing every step to green would hide exactly
                // the phase that did not.
                if s.state == "running" || s.state == "pending" {
                    if ok {
                        s.state = "done".to_string();
                        s.pct = 100;
                    } else {
                        s.state = "failed".to_string();
                    }
                }
            }
            reporter.substeps(&subs).await;
        }
    }
    match outcome {
        Ok(RpcResponse::BackupNow(run)) => {
            let mut log = format!("state={} bytes_total={}\n", run.state, run.bytes_total);
            if let Some(p) = &run.archive_path {
                log.push_str(&format!("archive: {p}\n"));
            }
            if let Some(p) = &run.db_dump_path {
                log.push_str(&format!("db dump: {p}\n"));
            }
            reporter.step("Backup complete.", 100, &log).await;
            reporter.finish(true, None).await;
        }
        Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
        Ok(_) => {
            reporter
                .finish(false, Some("unexpected agent response".into()))
                .await
        }
        Err(e) => reporter.finish(false, Some(e.to_string())).await,
    }
}

#[derive(Deserialize)]
pub struct BackupDeleteForm {
    pub(super) selector: String,
    pub(super) backup_id: i64,
    /// "1" = also delete the copy on the FTP target (the confirm dialog's
    /// checkbox writes it). Anything else leaves the off-site copy alone.
    #[serde(default)]
    pub(super) offsite: String,
}

/// Delete a backup's FTP copy BEFORE its row and local files go, so a refusal
/// leaves everything as it was and the operator can simply try again. `Ok(true)`
/// = deleted, `Ok(false)` = the backup has no FTP copy (nothing to do),
/// `Err` = it has one and it could not be deleted — or the node is too old to
/// know how, which must stop the delete rather than report one that half
/// happened.
pub(super) async fn delete_ftp_copy_first(
    state: &SharedState,
    node: Option<&str>,
    sel: HostingSelector,
    backup_id: i64,
) -> Result<bool, String> {
    match crate::dispatcher::dispatch_to_node(
        state,
        node,
        Request::BackupOffsiteDelete {
            sel,
            backup_id: Some(backup_id),
            filename: None,
        },
    )
    .await
    {
        Ok(RpcResponse::BackupOffsiteDelete(_)) => Ok(true),
        Ok(RpcResponse::Error(e)) => {
            let msg = e.to_string();
            if msg.contains("has no copy on the FTP target") {
                Ok(false)
            } else {
                Err(msg)
            }
        }
        Ok(_) => Err("unexpected agent response".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// POST /hostings/backups/delete — remove a single backup run + its
/// archive file. Refuses if the backup is still running.
pub async fn post_backup_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupDeleteForm>,
) -> Result<Response, AppError> {
    // form.selector controls the redirect target AND the owner node —
    // backup_id is the OWNER node's per-node autoincrement id, so this
    // MUST dispatch to the owner. Sending it to the master could delete
    // an unrelated master backup that happens to share the numeric id
    // (both start at 1), or NotFound → a 502. We still gate via the
    // selector because non-admins can only see the backup list for
    // hostings they have access to; a viewer probing arbitrary
    // backup_ids without a matching access grant gets 403 here.
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let mut ftp_deleted = false;
    if form.offsite == "1" {
        match delete_ftp_copy_first(&state, target_owned.as_deref(), sel.clone(), form.backup_id)
            .await
        {
            Ok(d) => ftp_deleted = d,
            Err(e) => {
                return Ok(Redirect::to(&format!(
                    "/hostings/{sel_url}?backup_error={}#backups",
                    urlencoding(&format!(
                    "nothing was deleted — the copy on the off-site FTP target could not be: {e}"
                ))
                ))
                .into_response())
            }
        }
    }
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::BackupDelete {
            // The node re-checks that this id belongs to `sel`. Authorizing
            // the selector here and forwarding a bare id was how a tenant
            // could delete every backup on the node.
            sel,
            backup_id: form.backup_id,
        },
    )
    .await?;
    match resp {
        // Said out loud: a delete that answered with nothing left the
        // operator scanning the list to see whether it had happened.
        RpcResponse::BackupDelete => Ok(Redirect::to(&format!(
            "/hostings/{sel_url}?backup_deleted={}#backups",
            urlencoding(if ftp_deleted {
                "Backup deleted, including its copy on the off-site FTP target."
            } else {
                "Backup deleted."
            })
        ))
        .into_response()),
        // The agent deliberately refuses to delete a still-running
        // backup — surface that as a flash, not a full 502 page.
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/{}?backup_error={}#backups",
            sel_url,
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct BackupDeleteBulkForm {
    pub(super) selector: String,
    /// Comma-separated backup ids. The template's checkboxes are UI-only; a
    /// tiny script joins the ticked ones into this single field, because
    /// axum's urlencoded `Form` can't gather repeated keys into a `Vec`
    /// (verified: it 422s with "expected a sequence").
    #[serde(default)]
    pub(super) backup_ids: String,
    /// "1" = also delete each one's copy on the FTP target.
    #[serde(default)]
    pub(super) offsite: String,
}

impl BackupDeleteBulkForm {
    /// Parse, de-dupe and cap the id list. Non-numeric fragments are dropped
    /// silently — the field is machine-written, so garbage means a tampered
    /// POST, not a user typo worth a message. The cap bounds how many RPCs one
    /// request can fan out to (the list only ever shows the 10 newest, so a
    /// well-behaved client sends at most that many).
    pub(super) fn ids(&self) -> Vec<i64> {
        let mut out: Vec<i64> = Vec::new();
        for tok in self.backup_ids.split(',') {
            if let Ok(n) = tok.trim().parse::<i64>() {
                if n > 0 && !out.contains(&n) {
                    out.push(n);
                }
            }
            if out.len() >= 100 {
                break;
            }
        }
        out
    }
}

/// POST /hostings/backups/delete-bulk — delete several backup runs (+ their
/// archive files) in one request. Same authorization and owner-dispatch as the
/// single delete; each id is deleted on the owning node, which re-checks that
/// the id belongs to `sel`, so authorizing the selector here and forwarding a
/// bare list can't reach another site's backups.
pub async fn post_backup_delete_bulk(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupDeleteBulkForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let ids = form.ids();
    if ids.is_empty() {
        // Nothing ticked (or a stale form) — no-op back to the list.
        return Ok(Redirect::to(&format!("/hostings/{sel_url}#backups")).into_response());
    }
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);

    let mut deleted = 0usize;
    let mut failed = 0usize;
    let mut ftp_deleted = 0usize;
    let mut first_error: Option<String> = None;
    for backup_id in ids {
        if form.offsite == "1" {
            match delete_ftp_copy_first(&state, target_owned.as_deref(), sel.clone(), backup_id)
                .await
            {
                Ok(d) => ftp_deleted += d as usize,
                // This one stays whole; the others go on.
                Err(e) => {
                    failed += 1;
                    first_error.get_or_insert(format!("off-site delete failed: {e}"));
                    continue;
                }
            }
        }
        let resp = crate::dispatcher::dispatch_to_node(
            &state,
            target_owned.as_deref(),
            Request::BackupDelete {
                sel: sel.clone(),
                backup_id,
            },
        )
        .await;
        match resp {
            Ok(RpcResponse::BackupDelete) => deleted += 1,
            Ok(RpcResponse::Error(e)) => {
                failed += 1;
                first_error.get_or_insert_with(|| e.to_string());
            }
            Ok(_) => {
                failed += 1;
                first_error.get_or_insert_with(|| "unexpected response".into());
            }
            Err(e) => {
                failed += 1;
                first_error.get_or_insert_with(|| e.to_string());
            }
        }
    }

    // All failed → an error flash carrying the first reason (usually "backup is
    // still running"). Otherwise a success summary that also notes any skips.
    if deleted == 0 {
        let msg = first_error.unwrap_or_else(|| "no archives were deleted".into());
        return Ok(Redirect::to(&format!(
            "/hostings/{sel_url}?backup_error={}#backups",
            urlencoding(&msg)
        ))
        .into_response());
    }
    let mut summary = format!(
        "{deleted} backup{} deleted",
        if deleted == 1 { "" } else { "s" }
    );
    if ftp_deleted > 0 {
        summary.push_str(&format!(
            " ({ftp_deleted} also from the off-site FTP target)"
        ));
    }
    if failed > 0 {
        summary.push_str(&format!(
            " · {failed} skipped ({})",
            first_error.unwrap_or_default()
        ));
    }
    Ok(Redirect::to(&format!(
        "/hostings/{sel_url}?backup_deleted={}#backups",
        urlencoding(&summary)
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct BackupOffsiteDropForm {
    pub(super) selector: String,
    /// Comma-separated backup ids. A per-row button sends one; the bulk button
    /// joins the ticked rows into this single field (axum's urlencoded `Form`
    /// can't gather repeated keys into a `Vec` — verified: it 422s).
    #[serde(default)]
    pub(super) backup_ids: String,
}

impl BackupOffsiteDropForm {
    /// Parse, de-dupe and cap the id list, same rules as the bulk delete.
    pub(super) fn ids(&self) -> Vec<i64> {
        let mut out: Vec<i64> = Vec::new();
        for tok in self.backup_ids.split(',') {
            if let Ok(n) = tok.trim().parse::<i64>() {
                if n > 0 && !out.contains(&n) {
                    out.push(n);
                }
            }
            if out.len() >= 100 {
                break;
            }
        }
        out
    }
}

/// POST /hostings/backups/offsite-drop — push one or more existing local
/// backups of a hosting off-site, then delete the local copy once it is
/// independently confirmed off-site. Serves both the per-row button (one id)
/// and the bulk button (many ids). Slow (real uploads), so it runs as a
/// background job like the backup itself.
pub async fn post_backup_offsite_drop(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupOffsiteDropForm>,
) -> Result<Response, AppError> {
    // Same authorization + owner-dispatch as delete: the backup id is the
    // owning node's per-node autoincrement, so the node re-checks each id
    // belongs to `sel`.
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let ids = form.ids();
    if ids.is_empty() {
        return Ok(Redirect::to(&format!("/hostings/{sel_url}#backups")).into_response());
    }
    let node = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    // Resolve the S3 targets on the request thread (master-local 0600 reads),
    // so the owning node can push to them too — not just the FTP target.
    let s3_targets = resolve_s3_targets(&state).await;

    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "offsite-drop",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_offsite_drop_job(reporter, job_state, node, sel, ids, s3_targets).await;
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker for [`post_backup_offsite_drop`]: push the chosen backups
/// off-site on the owning node and drop each verified local copy.
pub(crate) async fn run_offsite_drop_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    sel: HostingSelector,
    backup_ids: Vec<i64>,
    s3_targets: Vec<hyperion_types::S3BackupTarget>,
) {
    reporter
        .step(
            "Copying off-site, then dropping each local copy once verified…",
            10,
            "",
        )
        .await;
    // One blocking RPC (uploads + verify + delete); heartbeat the job row so a
    // large transfer is not reaped as stale mid-flight, same as the backup job.
    let hb = {
        let reporter = reporter.clone();
        tokio::spawn(async move {
            let mut pct = 10;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                pct = (pct + 5).min(85);
                reporter
                    .step(
                        "Still copying off-site — large archives take a while…",
                        pct,
                        "",
                    )
                    .await;
            }
        })
    };
    let outcome = crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::BackupOffsitePushDrop {
            sel,
            backup_ids,
            s3_targets,
            drop_local: true,
        },
    )
    .await;
    hb.abort();
    match outcome {
        Ok(RpcResponse::BackupOffsitePushDrop(r)) => {
            let mut log = format!(
                "considered: {}\npushed:     {}\nfailed:     {}\n",
                r.considered, r.pushed, r.failed
            );
            if r.missing_locally > 0 {
                log.push_str(&format!(
                    "GONE:       {} had no local archive left to send\n",
                    r.missing_locally
                ));
            }
            log.push_str(&format!(
                "dropped:    {} local cop{} removed after an independent off-site re-verify\n\
                 kept local: {} cop{} kept — could NOT be confirmed off-site\n",
                r.dropped,
                if r.dropped == 1 { "y" } else { "ies" },
                r.kept_local,
                if r.kept_local == 1 { "y" } else { "ies" },
            ));
            if r.already_offsite > 0 {
                log.push_str(&format!(
                    "            ({} of those were already off-site: re-checked there and \
                     dropped without being uploaded again)\n",
                    r.already_offsite
                ));
            }
            // Red when anything the operator selected FAILED — including ids
            // that no longer exist (a concurrent delete or a stale page): those
            // land in `failed` without touching `considered`, so a
            // `considered == 0` success clause would report green when every
            // selected item failed. Mirror the estate-wide sweep's predicate.
            //
            // And red when a copy was KEPT: the operator asked for the local
            // copy to go, and a green job next to a backup that is still on
            // disk reads as "done" when it is not.
            reporter.step("Finished.", 100, &log).await;
            let kept = (r.kept_local > 0).then(|| {
                format!(
                    "{} local cop{} kept — not confirmed off-site; the Backups tab says why",
                    r.kept_local,
                    if r.kept_local == 1 {
                        "y was"
                    } else {
                        "ies were"
                    },
                )
            });
            reporter.finish(r.failed == 0 && kept.is_none(), kept).await;
        }
        Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
        Ok(_) => {
            reporter
                .finish(false, Some("unexpected agent response".into()))
                .await
        }
        Err(e) => reporter.finish(false, Some(e.to_string())).await,
    }
}

#[derive(serde::Deserialize)]
pub struct BackupCadenceForm {
    pub selector: String,
    pub cadence: String,
    /// Days between backups, read only for `cadence = "custom"`.
    #[serde(default)]
    pub interval_days: String,
    /// "HH:MM" local time on the owning node, empty = any time.
    #[serde(default)]
    pub at: String,
}

/// Override a hosting's recurring-backup schedule: cadence, the custom period
/// in days and the time of day. Stored in the OWNING node's hosting_kv
/// ("backup_cadence" / "backup_interval_days" / "backup_at", keyed by ULID)
/// where scheduled_backups_tick reads them. Cadence canonicalised to
/// off|daily|weekly|monthly|custom.
pub async fn post_set_backup_cadence(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupCadenceForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let back = |key: &str, msg: &str| {
        Ok(Redirect::to(&format!(
            "/hostings/{}?{key}={}#backups",
            sel_url,
            urlencoding(msg)
        ))
        .into_response())
    };
    let (detail, target) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(_) => {
            return Ok(Redirect::to(&format!("/hostings/{}#backups", sel_url)).into_response());
        }
    };
    let value = match form.cadence.as_str() {
        "daily" => "daily",
        "weekly" => "weekly",
        "monthly" => "monthly",
        "custom" => "custom",
        _ => "off",
    };
    // A refused field refuses the whole save: half a schedule (custom with no
    // period) is a schedule the tick silently skips.
    let interval_days = if value == "custom" {
        match form.interval_days.trim().parse::<i64>() {
            Ok(d) if (1..=BACKUP_INTERVAL_MAX_DAYS).contains(&d) => Some(d),
            _ => {
                return back(
                    "flash_error",
                    &format!(
                        "The schedule was not saved — \"every N days\" needs a whole number of \
                         days from 1 to {BACKUP_INTERVAL_MAX_DAYS}."
                    ),
                );
            }
        }
    } else {
        None
    };
    let at = if form.at.trim().is_empty() {
        String::new()
    } else {
        match parse_backup_at(&form.at) {
            Some(t) => t,
            None => {
                return back(
                    "flash_error",
                    "The schedule was not saved — the time must be HH:MM (24-hour), or empty \
                     for any time.",
                );
            }
        }
    };
    let schedule = BackupSchedule {
        cadence: value.into(),
        interval_days: interval_days.unwrap_or(0),
        at: at.clone(),
    };
    // Period and time first, cadence last: a node that takes the first
    // writes and then becomes unreachable is left on its OLD cadence with the
    // new details, never on "custom" without a period.
    let mut writes: Vec<(&str, String)> = Vec::new();
    if let Some(d) = interval_days {
        writes.push(("backup_interval_days", d.to_string()));
    }
    writes.push(("backup_at", at));
    writes.push(("backup_cadence", value.to_string()));
    // Every result is read: a schedule that did not reach the owning node
    // must not come back as "saved" — nobody would find out until a backup
    // was needed and was not there.
    for (key, val) in writes {
        let saved = crate::dispatcher::dispatch_to_node(
            &state,
            target.as_deref(),
            Request::HostingKvSet {
                hosting_id: detail.id.as_str().to_string(),
                key: key.into(),
                value: val,
            },
        )
        .await;
        let err = match saved {
            Ok(RpcResponse::HostingKvSet) => continue,
            Ok(RpcResponse::Error(e)) => {
                format!("The schedule was not saved — the owning node refused it: {e}")
            }
            Ok(_) => "The schedule was not saved — unexpected response.".into(),
            Err(e) => {
                format!("The schedule was not saved — the owning node could not be reached: {e}")
            }
        };
        return back("flash_error", &err);
    }
    let msg = match value {
        "off" => "Automatic backups switched off — only when you click.".to_string(),
        _ => format!("Automatic backups saved: {}.", schedule.label()),
    };
    back("flash", &msg)
}

#[derive(serde::Deserialize)]
pub struct BackupTargetForm {
    pub selector: String,
    /// A `backup_targets.name`, or empty for "node default".
    #[serde(default)]
    pub target: String,
}

/// Pin this hosting's backups to ONE off-site target, or clear the pin back to
/// the node default. Stored in the OWNING node's hosting_kv ("backup_target"),
/// which is where `backup_now` reads it.
///
/// Admin-only on the server, not just in the markup: the target list is
/// cluster config, and an operator with BackupRun on one site must not be able
/// to aim that site's archives at another client's bucket.
///
/// A name that isn't configured is refused rather than stored — a pin that
/// resolves to nothing stops the site going off-site entirely, and that must
/// never be the silent result of a stale form.
pub async fn post_set_backup_target(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupTargetForm>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let (detail, target) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(_) => {
            return Ok(Redirect::to(&format!("/hostings/{}#backups", sel_url)).into_response());
        }
    };
    let want = form.target.trim().to_string();
    if !want.is_empty() {
        let refusal = match configured_backup_targets(&state).await {
            Some(options) if options.iter().any(|o| o.name == want) => None,
            Some(_) => Some(format!(
                "\"{want}\" is not a configured off-site target — nothing was changed."
            )),
            None => Some(
                "The configured off-site targets could not be read, so the destination was \
                 left as it was."
                    .to_string(),
            ),
        };
        if let Some(msg) = refusal {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?backup_target_error={}#backups",
                sel_url,
                urlencoding(&msg)
            ))
            .into_response());
        }
    }
    // A write that didn't land must not redirect as if it had: this key
    // decides where a paying client's data ends up.
    let saved = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::HostingKvSet {
            hosting_id: detail.id.as_str().to_string(),
            key: "backup_target".into(),
            value: want,
        },
    )
    .await;
    match saved {
        Ok(RpcResponse::HostingKvSet) => Ok(Redirect::to(&format!(
            "/hostings/{}?flash={}#backups",
            sel_url,
            urlencoding("Off-site destination saved.")
        ))
        .into_response()),
        Ok(RpcResponse::Error(e)) => Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#backups",
            sel_url,
            urlencoding(&format!(
                "The off-site destination was not saved — the owning node refused it: {e}"
            ))
        ))
        .into_response()),
        Ok(_) => Err(AppError::Internal("unexpected response".into())),
        Err(e) => Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#backups",
            sel_url,
            urlencoding(&format!(
                "The off-site destination was not saved — the owning node could not be reached: {e}"
            ))
        ))
        .into_response()),
    }
}

#[derive(Deserialize)]
pub struct RestoreForm {
    pub selector: String,
    pub archive_path: String,
    /// "files_and_db" (default) | "db_only" | "files_only".
    #[serde(default)]
    pub mode: String,
}

/// Map the restore-form's string into the typed enum. Unknown / empty
/// ⇒ full files+DB restore (the safe historical default).
pub(super) fn parse_restore_mode(s: &str) -> hyperion_types::BackupRestoreMode {
    match s {
        "db_only" => hyperion_types::BackupRestoreMode::DbOnly,
        "files_only" => hyperion_types::BackupRestoreMode::FilesOnly,
        _ => hyperion_types::BackupRestoreMode::FilesAndDb,
    }
}

/// Multipart upload of a tar.gz backup archive. Saved to
/// /var/lib/hyperion/backups/incoming/<sanitized-filename> then handed
/// off to the existing BackupRestore RPC.
pub async fn post_restore_upload(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    mut multipart: axum::extract::Multipart,
) -> Result<Response, AppError> {
    let mut selector: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        match field.name() {
            Some("selector") => {
                selector = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("selector: {e}")))?,
                );
            }
            Some("archive") => {
                filename = field.file_name().map(|s| {
                    s.chars()
                        .filter(|c| c.is_ascii_alphanumeric() || ['.', '-', '_'].contains(c))
                        .collect()
                });
                bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("read archive: {e}")))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }
    let selector = selector.ok_or_else(|| AppError::BadRequest("missing selector".into()))?;
    // Authorize BEFORE touching the filesystem — a viewer must not be
    // able to dump arbitrary tarballs into /var/lib/hyperion/backups
    // even if they can't ultimately trigger the restore.
    let sel = match require_manage_for_selector(&state, &ctx, &selector, Capability::BackupRestore)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let bytes = bytes.ok_or_else(|| AppError::BadRequest("missing archive file".into()))?;
    let filename = filename
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("upload-{}.tar.gz", hyperion_types::now_secs()));
    if !filename.ends_with(".tar.gz") {
        return Err(AppError::BadRequest(
            "archive must be a .tar.gz file".into(),
        ));
    }

    // Namespaced by hosting. A flat incoming/ directory meant the node could
    // not tell whose upload an archive was, so restore had nothing to check a
    // caller-supplied path against beyond "is it under a backup root" — and
    // every tenant's archives are under the same root.
    // Namespaced by the hosting's own id, resolved here rather than taken
    // from the request. A flat incoming/ directory meant the node could not
    // tell whose upload an archive was, so restore had nothing to check a
    // caller-supplied path against beyond "is it under a backup root" — and
    // every tenant's archives are under the same root.
    let (hosting_ns, owner_node) = find_hosting_anywhere(&state, sel.clone())
        .await
        .map(|(d, owner)| (d.id.as_str().to_string(), owner))
        .map_err(|e| AppError::Internal(format!("resolve hosting: {e}")))?;
    // The archive lands on THIS server's disk and the restore runs on this
    // server's agent. For a site on a worker neither is where the site is:
    // the restore used to fail with "not found" (or, by domain, could hit a
    // same-named site here). Say so plainly until uploads can be shipped to
    // the owning node.
    if let Some(node) = owner_node {
        let label = crate::dispatcher::cached_nodes(&state)
            .await
            .ok()
            .and_then(|v| v.into_iter().find(|n| n.node_id == node).map(|n| n.label))
            .unwrap_or(node);
        let msg = urlencoding(&format!(
            "Restoring from an uploaded archive works only for sites on the master, and this \
             site is on {label}. Nothing was changed. Restore one of the site's own backups \
             from the list below instead."
        ));
        return Ok(Redirect::to(&format!(
            "/hostings/{}?restore_error={msg}",
            urlencoding(&selector)
        ))
        .into_response());
    }
    let incoming_dir =
        std::path::PathBuf::from("/var/lib/hyperion/backups/incoming").join(&hosting_ns);
    tokio::fs::create_dir_all(&incoming_dir)
        .await
        .map_err(|e| AppError::Internal(format!("mkdir incoming: {e}")))?;
    let dest = incoming_dir.join(&filename);
    tokio::fs::write(&dest, &bytes)
        .await
        .map_err(|e| AppError::Internal(format!("write upload: {e}")))?;

    let sel_url = urlencoding(&selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupRestore {
            sel,
            archive_path: dest.display().to_string(),
            mode: hyperion_types::BackupRestoreMode::FilesAndDb,
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupRestore => {
            Ok(Redirect::to(&format!("/hostings/{}?restore=ok", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?restore_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_restore(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RestoreForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRestore)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    // ── Synchronous pre-flight (authz, form parse, restore-mode parse,
    // owner-node lookup). Only the BackupRestore dispatch — untar of the
    // whole archive plus a DB import, minutes on a large site — detaches
    // into the worker so a dropped browser can't abort a half-applied
    // restore.
    //
    // The backup archive + the hosting tree live on the owning node —
    // dispatch there (archive_path is the worker's local path).
    let (_, node) = find_hosting_anywhere(&state, sel.clone()).await?;
    let archive_path = form.archive_path.trim().to_string();
    let mode = parse_restore_mode(&form.mode);
    // Below admin, only this site's OWN archives. The node checks that the
    // path sits under a backup root — but that root holds every tenant's
    // archives, and `BackupRestore` is a capability customers have: a guessed
    // `<domain>-<unix time>.tar.gz` of somebody else's site would import their
    // files and database into this one. The rows of this site are the list of
    // what it may restore; the free-text path is an admin tool.
    if !ctx.is_admin_or_higher() {
        let own = fetch_backup_list(&state, node.as_deref(), sel.clone(), 1000)
            .await
            .unwrap_or_default();
        if !own
            .iter()
            .any(|b| b.archive_path.as_deref() == Some(archive_path.as_str()))
        {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?flash_error={}#backups",
                urlencoding(&form.selector),
                urlencoding("That archive is not one of this site's backups.")
            ))
            .into_response());
        }
    }

    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "restore",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_restore_job(reporter, job_state, node, sel, archive_path, mode).await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker: restore a backup archive on the owning node.
pub(crate) async fn run_restore_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    sel: HostingSelector,
    archive_path: String,
    mode: hyperion_types::BackupRestoreMode,
) {
    reporter
        .step(
            "Restoring backup — files + database…",
            10,
            &format!("archive: {archive_path}\n"),
        )
        .await;
    match crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::BackupRestore {
            sel,
            archive_path,
            mode,
        },
    )
    .await
    {
        Ok(RpcResponse::BackupRestore) => {
            reporter
                .step("Restore complete.", 100, "✓ archive restored")
                .await;
            reporter.finish(true, None).await;
        }
        Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
        Ok(_) => {
            reporter
                .finish(false, Some("unexpected agent response".into()))
                .await
        }
        Err(e) => reporter.finish(false, Some(e.to_string())).await,
    }
}

/// Stream a backup archive to the operator's browser as a download.
/// Pulls the file off the owning node in bounded chunks (so an archive
/// larger than MAX_FRAME still works) and pipes them straight to the
/// HTTP body via a tokio duplex pipe — never buffering the whole file
/// in the master's memory.
pub async fn get_backup_download(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path((selector, backup_id)): Path<(String, i64)>,
) -> Result<Response, AppError> {
    use base64::Engine;
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::BackupRun,
    )
    .await
    {
        return Ok(r);
    }
    // Metadata probe (len=0): total size + filename. The node re-checks that
    // the backup belongs to `sel` — the old comment claimed it validated "the
    // backup belongs to a hosting", which was true and useless: it belonged
    // to SOME hosting, not necessarily this one.
    let meta = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::BackupFetchChunk {
            sel: sel.clone(),
            backup_id,
            offset: 0,
            len: 0,
        },
    )
    .await?;
    let (total_size, filename) = match meta {
        RpcResponse::BackupFetchChunk {
            total_size,
            filename,
            ..
        } => (total_size, filename),
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };

    const CHUNK: u32 = 8 * 1024 * 1024;
    let (mut writer, reader) = tokio::io::duplex(CHUNK as usize);
    let task_state = state.clone();
    let task_owner = owner_node.clone();
    let task_sel = sel.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut offset: u64 = 0;
        loop {
            let resp = crate::dispatcher::dispatch_to_node(
                &task_state,
                task_owner.as_deref(),
                Request::BackupFetchChunk {
                    sel: task_sel.clone(),
                    backup_id,
                    offset,
                    len: CHUNK,
                },
            )
            .await;
            let (data_b64, eof) = match resp {
                Ok(RpcResponse::BackupFetchChunk { data_b64, eof, .. }) => (data_b64, eof),
                // Error/abort → drop the writer; the client sees a
                // truncated download rather than a hung connection.
                _ => break,
            };
            let bytes = match base64::engine::general_purpose::STANDARD.decode(data_b64.as_bytes())
            {
                Ok(b) => b,
                Err(_) => break,
            };
            if !bytes.is_empty() && writer.write_all(&bytes).await.is_err() {
                break; // client disconnected
            }
            offset += bytes.len() as u64;
            if eof || bytes.is_empty() {
                break;
            }
        }
        // writer dropped here → reader observes EOF
    });

    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = axum::body::Body::from_stream(stream);
    let safe_name = filename.replace(['"', '\\', '\n', '\r'], "");
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/gzip".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{safe_name}\""),
            ),
            (axum::http::header::CONTENT_LENGTH, total_size.to_string()),
        ],
        body,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct RestoreAsNewForm {
    pub selector: String,
    pub archive_path: String,
    pub new_domain: String,
}

/// Restore a backup archive into a brand-new hosting at a new domain.
/// Dispatched to the source's owning node (the new hosting is created
/// there). Long-running, but bounded — runs synchronously and redirects
/// to the new hosting on success.
pub async fn post_restore_as_new(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RestoreAsNewForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingMigrateClone,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // A free-text server path, like the custom-path restore: an admin tool.
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#backups",
            sel_url,
            urlencoding("Restoring into a new domain from a server path needs an admin.")
        ))
        .into_response());
    }
    let new_domain = form.new_domain.trim().to_string();
    if new_domain.is_empty() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?restore_error={}#backups",
            sel_url,
            urlencoding("Enter a new domain for the restored copy.")
        ))
        .into_response());
    }
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::BackupRestoreAsNew {
            sel,
            archive_path: form.archive_path.trim().to_string(),
            new_domain,
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupRestoreAsNew { domain, .. } => Ok(Redirect::to(&format!(
            "/hostings/{}?created=1",
            urlencoding(&domain)
        ))
        .into_response()),
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!(
                "/hostings/{}?restore_error={}#backups",
                sel_url, msg
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[cfg(test)]
mod backup_target_tests {
    use super::{pinned_target_warning, BackupTargetOption};

    fn opt(name: &str, unusable: &str) -> BackupTargetOption {
        BackupTargetOption {
            name: name.into(),
            unusable: unusable.into(),
        }
    }

    #[test]
    fn only_a_pin_that_cannot_receive_a_backup_warns() {
        let options = vec![opt("wasabi-eu", ""), opt("b2-cold", "disabled in Settings")];
        // No pin: the site follows the node default, nothing to warn about.
        assert!(pinned_target_warning("", &options).is_empty());
        // Pinned to a target that can take the upload: silence.
        assert!(pinned_target_warning("wasabi-eu", &options).is_empty());
        // Pinned to a configured but unusable one — the reason has to reach
        // the operator, and the sentence must not imply copies are happening.
        let disabled = pinned_target_warning("b2-cold", &options);
        assert!(disabled.contains("b2-cold"), "names the target: {disabled}");
        assert!(disabled.contains("disabled in Settings"), "{disabled}");
        assert!(disabled.contains("NOT being copied off-site"), "{disabled}");
        // Pinned to something that isn't configured at all (deleted/renamed).
        let gone = pinned_target_warning("gone", &options);
        assert!(gone.contains("not one of the configured"), "{gone}");
        assert!(gone.contains("NOT being copied off-site"), "{gone}");
    }
}
