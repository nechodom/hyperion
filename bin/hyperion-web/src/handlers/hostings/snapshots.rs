//! Snapshots card: take, delete, diff, restore.

use super::*;

#[derive(Template)]
#[template(path = "_hosting_snapshots_card.html")]
pub(super) struct SnapshotsCardTpl {
    pub(super) selector: String,
    pub(super) domain: String,
    /// Newest FIRST here, unlike the RPC: this is a list somebody reads, and
    /// the interesting snapshot is the most recent one.
    pub(super) rows: Vec<SnapshotRow>,
    pub(super) csrf_snapshot_now: String,
    pub(super) csrf_snapshot_diff: String,
    pub(super) csrf_snapshot_restore: String,
    pub(super) csrf_snapshot_delete: String,
    /// Whether THIS session may replace the site. Server-side: the handler
    /// re-checks the same capability, because hiding a button is not a
    /// permission check.
    pub(super) can_restore: bool,
    /// Whether THIS session may take or delete snapshots (`BackupRun`, the
    /// same capability as taking and deleting archives).
    pub(super) can_manage: bool,
    /// Whether THIS session may open Settings. Decided here: the card is
    /// swapped in by htmx, after the page's role shim has already run, so a
    /// `data-role-min` inside it hides nothing.
    pub(super) can_settings: bool,
    /// `ready`, `not_installed`, `disabled`, `mode_off`, or empty when the
    /// node could not be asked.
    pub(super) engine: String,
    /// The owning node's `[protection] mode`.
    pub(super) protection_mode: String,
    pub(super) retention: String,
    pub(super) repo_size: String,
    pub(super) diff: Option<hyperion_types::SnapshotDiff>,
    pub(super) diff_of: String,
    pub(super) error: Option<String>,
}

pub struct SnapshotRow {
    pub id: String,
    /// "3 h ago".
    pub when: String,
    /// "2026-09-16 21:41 UTC", for the tooltip and the confirm dialogs.
    pub when_exact: String,
    /// Why it was taken, in words.
    pub reason: String,
    /// The snapshot immediately older than this one, so "what changed" is
    /// one click. Empty on the oldest.
    pub previous: String,
    /// Does this snapshot carry a database dump? Read off the tag, because
    /// restic's list gives tags but not a file list. False for every snapshot
    /// taken before snapshots included one — and the card offers files-only
    /// there rather than a checkbox that would fail at the end of a restore.
    pub has_db: bool,
    /// Will retention delete it at the next sweep? Shown, so a snapshot does
    /// not vanish from under somebody who was about to restore it.
    pub expiring: bool,
}

/// The tag a snapshot was taken with, as a sentence fragment.
pub(super) fn snapshot_reason(tags: &[String]) -> String {
    let why = tags
        .iter()
        .find_map(|t| match t.as_str() {
            "pre-update" => Some("before automatic updates"),
            "pre-core-update" => Some("before a WordPress core update"),
            "pre-restore" => Some("before a restore"),
            "manual" => Some("taken by hand"),
            _ => None,
        })
        .unwrap_or("snapshot");
    why.to_string()
}

/// GET /hostings/:selector/snapshots-panel
pub async fn get_snapshots_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    render_snapshots(&state, &ctx, selector, None, String::new(), None).await
}

pub(super) async fn render_snapshots(
    state: &SharedState,
    ctx: &AuthCtx,
    selector: String,
    diff: Option<hyperion_types::SnapshotDiff>,
    diff_of: String,
    error: Option<String>,
) -> Result<Response, AppError> {
    // Evaluated once, before the closure borrows them: the same capabilities
    // the POST handlers enforce, so a rendered button always matches an action
    // that will be allowed.
    let can_restore = require_manage_for_selector(state, ctx, &selector, Capability::BackupRestore)
        .await
        .is_ok();
    let can_manage = require_manage_for_selector(state, ctx, &selector, Capability::BackupRun)
        .await
        .is_ok();
    let card = |rows: Vec<SnapshotRow>,
                domain: String,
                overview: Option<&hyperion_types::SnapshotOverview>,
                error: Option<String>| {
        Html(
            SnapshotsCardTpl {
                selector: selector.clone(),
                domain,
                rows,
                csrf_snapshot_now: csrf_token_for(state, ctx, "/hostings/snapshots/now"),
                csrf_snapshot_diff: csrf_token_for(state, ctx, "/hostings/snapshots/diff"),
                csrf_snapshot_restore: csrf_token_for(state, ctx, "/hostings/snapshots/restore"),
                csrf_snapshot_delete: csrf_token_for(state, ctx, "/hostings/snapshots/delete"),
                can_restore,
                can_manage,
                can_settings: ctx.can(Capability::SettingsManage),
                protection_mode: overview
                    .map(|o| o.protection_mode.clone())
                    .unwrap_or_default(),
                engine: overview.map(|o| o.engine.clone()).unwrap_or_default(),
                retention: overview.map(|o| o.retention.describe()).unwrap_or_default(),
                repo_size: overview
                    .filter(|o| o.repo_bytes > 0)
                    .map(|o| crate::handlers::stats::fmt_bytes(&(o.repo_bytes as i64)))
                    .unwrap_or_default(),
                diff: diff.clone(),
                diff_of: diff_of.clone(),
                error,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => return Ok(card(Vec::new(), String::new(), None, Some(e.to_string()))),
    };
    let (detail, owner) = match find_hosting_anywhere(state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => return Ok(card(Vec::new(), String::new(), None, Some(e.to_string()))),
    };
    if require_hosting_access(
        state,
        ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    .is_err()
    {
        return Ok(card(
            Vec::new(),
            detail.domain.clone(),
            None,
            Some("You do not have access to this hosting.".into()),
        ));
    }
    let overview = match crate::dispatcher::dispatch_to_node(
        state,
        owner.as_deref(),
        Request::SnapshotOverview { sel },
    )
    .await
    {
        Ok(RpcResponse::SnapshotOverview(o)) => o,
        Ok(RpcResponse::Error(e)) => {
            return Ok(card(
                Vec::new(),
                detail.domain.clone(),
                None,
                Some(e.to_string()),
            ))
        }
        Ok(_) => {
            return Ok(card(
                Vec::new(),
                detail.domain.clone(),
                None,
                Some("unexpected response from the node".into()),
            ))
        }
        Err(e) => {
            return Ok(card(
                Vec::new(),
                detail.domain.clone(),
                None,
                Some(format!(
                    "Could not ask the node that owns this site about its snapshots ({e}). A node \
                     running an older Hyperion cannot answer this yet."
                )),
            ))
        }
    };
    let now = hyperion_types::now_secs();
    let expiring: std::collections::HashSet<String> = overview
        .retention
        .expired(&overview.snapshots, now)
        .into_iter()
        .map(|s| s.id.clone())
        .collect();
    let list = &overview.snapshots;
    let mut rows: Vec<SnapshotRow> = Vec::with_capacity(list.len());
    for (i, s) in list.iter().enumerate() {
        let taken = s.taken_at();
        rows.push(SnapshotRow {
            previous: if i == 0 {
                String::new()
            } else {
                list[i - 1].id.clone()
            },
            has_db: s.has_database(),
            id: s.id.clone(),
            when: taken
                .map(|t| crate::handlers::stats::fmt_ago(&t))
                .unwrap_or_else(|| s.time.clone()),
            when_exact: taken
                .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| s.time.clone()),
            reason: snapshot_reason(&s.tags),
            expiring: expiring.contains(&s.id),
        });
    }
    rows.reverse();
    Ok(card(rows, detail.domain.clone(), Some(&overview), error))
}

#[derive(serde::Deserialize)]
pub struct SnapshotNowForm {
    pub selector: String,
}

/// POST /hostings/snapshots/now — take one by hand.
///
/// A background job, like "Back up now": the first snapshot of a large site
/// walks the whole tree and dumps the database, and a request that times out
/// half-way through left the operator clicking again into a second restic
/// run on the same repository.
pub async fn post_snapshot_now(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SnapshotNowForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "snapshot_now",
        Some(&form.selector),
        "{}",
        &ctx.username,
        actor_uid,
        move |reporter| async move {
            reporter
                .step("Taking a snapshot of the files and the database…", 10, "")
                .await;
            match crate::dispatcher::dispatch_to_node(
                &job_state,
                owner.as_deref(),
                Request::SnapshotNow { sel },
            )
            .await
            {
                // An empty id means nothing was taken — reported as a failure
                // with the reasons, because a job that says "done" and made
                // nothing is worse than one that refuses.
                Ok(RpcResponse::SnapshotNow(id)) if id.is_empty() => {
                    reporter
                        .finish(
                            false,
                            Some(
                                "No snapshot was taken. Either restic is not installed on the \
                                 node that owns this site, snapshots are switched off there \
                                 (Settings → Backups → What is kept), or the \
                                 site has no document tree. The agent log on that node says \
                                 which."
                                    .into(),
                            ),
                        )
                        .await
                }
                Ok(RpcResponse::SnapshotNow(id)) => {
                    reporter
                        .step("Snapshot taken.", 100, &format!("✓ snapshot {id}\n"))
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
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

#[derive(serde::Deserialize)]
pub struct SnapshotDeleteForm {
    pub selector: String,
    /// One snapshot id, or empty with `all`.
    #[serde(default)]
    pub snapshot: String,
    /// "1" to delete every snapshot of the site.
    #[serde(default)]
    pub all: String,
}

/// POST /hostings/snapshots/delete — delete one snapshot, or all of them.
///
/// Gated on `BackupRun`, the capability that deletes archives. A job, because
/// the delete prunes the repository to actually free the space, and pruning
/// rewrites pack files.
pub async fn post_snapshot_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SnapshotDeleteForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let all = matches!(form.all.as_str(), "1" | "true" | "on");
    let snapshot = form.snapshot.trim().to_string();
    if !all && snapshot.is_empty() {
        return render_snapshots(
            &state,
            &ctx,
            form.selector.clone(),
            None,
            String::new(),
            Some("No snapshot was selected.".into()),
        )
        .await;
    }
    // Resolved with `?`: a lookup that fails must not quietly send the delete
    // to the master instead of the node that owns the site.
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "snapshot_delete",
        Some(&form.selector),
        "{}",
        &ctx.username,
        actor_uid,
        move |reporter| async move {
            let what = if all {
                "every snapshot of this site".to_string()
            } else {
                format!("snapshot {snapshot}")
            };
            reporter
                .step(
                    &format!("Deleting {what} and freeing the space it used…"),
                    10,
                    "",
                )
                .await;
            let snapshots = if all { Vec::new() } else { vec![snapshot] };
            match crate::dispatcher::dispatch_to_node(
                &job_state,
                owner.as_deref(),
                Request::SnapshotDelete {
                    sel,
                    snapshots,
                    all,
                },
            )
            .await
            {
                Ok(RpcResponse::SnapshotDeleted(n)) => {
                    let log = if n == 0 {
                        "· nothing was left to delete; leftover space was reclaimed\n".to_string()
                    } else {
                        format!("✓ {n} snapshot(s) deleted, and the space they used freed\n")
                    };
                    reporter.step("Deleted.", 100, &log).await;
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
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

#[derive(serde::Deserialize)]
pub struct SnapshotDiffForm {
    pub selector: String,
    pub from: String,
    pub to: String,
}

#[derive(serde::Deserialize)]
pub struct SnapshotRestoreForm {
    pub selector: String,
    pub snapshot: String,
    /// Unchecked boxes are not posted at all, so absence means "not this
    /// half" — which is why both are `Option` rather than `bool`.
    #[serde(default)]
    pub files: Option<String>,
    #[serde(default)]
    pub database: Option<String>,
}

/// POST /hostings/snapshots/restore — put a snapshot back.
///
/// Gated on `BackupRestore`, not on the `HostingEditConfig` that guards
/// taking a snapshot: this replaces the site. It is the same act as restoring
/// an archive and it answers to the same capability, so a role built to let
/// somebody restore backups can restore snapshots too, and one built to let
/// them take snapshots cannot silently also let them destroy the site.
pub async fn post_snapshot_restore(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SnapshotRestoreForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRestore)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    // Neither half selected is a no-op, and a no-op reported as a running
    // restore is worse than an error: the operator walks away believing the
    // site was put back.
    let mode = match (form.files.is_some(), form.database.is_some()) {
        (true, true) => hyperion_types::BackupRestoreMode::FilesAndDb,
        (true, false) => hyperion_types::BackupRestoreMode::FilesOnly,
        (false, true) => hyperion_types::BackupRestoreMode::DbOnly,
        (false, false) => {
            return render_snapshots(
                &state,
                &ctx,
                form.selector.clone(),
                None,
                String::new(),
                Some(
                    "Nothing was selected to restore — tick the files, the database, or both."
                        .into(),
                ),
            )
            .await
        }
    };
    // Everything slow happens on the OWNING node, so resolve it here while we
    // still have a request to fail in.
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let snapshot = form.snapshot.trim().to_string();

    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "snapshot-restore",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_snapshot_restore_job(reporter, job_state, node, sel, snapshot, mode).await;
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker: put a snapshot back on the owning node.
pub(super) async fn run_snapshot_restore_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    sel: HostingSelector,
    snapshot: String,
    mode: hyperion_types::BackupRestoreMode,
) {
    reporter
        .step(
            "Restoring snapshot — the current site is kept beside it…",
            10,
            &format!(
                "snapshot: {snapshot}
restoring: {}
",
                mode.as_str()
            ),
        )
        .await;
    match crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::SnapshotRestore {
            sel,
            snapshot,
            mode,
        },
    )
    .await
    {
        Ok(RpcResponse::SnapshotRestore(out)) => {
            // Every line here is a distinction the operator has to be able to
            // make afterwards. A bare "done" is not something anybody can act
            // on when it turns out to have been the wrong snapshot.
            let mut log = String::new();
            log.push_str(if out.files_restored {
                "✓ files restored
"
            } else {
                "· files left alone
"
            });
            log.push_str(if out.db_restored {
                "✓ database restored
"
            } else {
                "· database left alone
"
            });
            if out.safety_snapshot.is_empty() {
                log.push_str(
                    "! no snapshot of the replaced state could be taken — there is no \
                     one-click way back
",
                );
            } else {
                log.push_str(&format!(
                    "✓ the state this replaced was kept as snapshot {}
",
                    out.safety_snapshot
                ));
            }
            if !out.previous_site_kept_at.is_empty() {
                log.push_str(&format!(
                    "· the previous files are still on the node at {}
  (delete them once the \
                     site is confirmed working — nothing cleans them up)
",
                    out.previous_site_kept_at
                ));
            }
            reporter.step("Restore complete.", 100, &log).await;
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

/// POST /hostings/snapshots/diff — what changed between two of them.
pub async fn post_snapshot_diff(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SnapshotDiffForm>,
) -> Result<Response, AppError> {
    let sel = match parse_selector(&form.selector) {
        Ok(s) => s,
        Err(e) => {
            return render_snapshots(
                &state,
                &ctx,
                form.selector.clone(),
                None,
                String::new(),
                Some(e.to_string()),
            )
            .await
        }
    };
    let (detail, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    // Reading a diff is reading the site's contents, so it is gated like the
    // rest of the detail page rather than like a change.
    if require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    .is_err()
    {
        return render_snapshots(
            &state,
            &ctx,
            form.selector,
            None,
            String::new(),
            Some("You do not have access to this hosting.".into()),
        )
        .await;
    }
    let label = format!("{} → {}", form.from, form.to);
    let (diff, error) = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::SnapshotDiff {
            sel,
            from: form.from.clone(),
            to: form.to.clone(),
        },
    )
    .await
    {
        Ok(RpcResponse::SnapshotDiff(d)) => (Some(d), None),
        Ok(RpcResponse::Error(e)) => (None, Some(e.to_string())),
        Ok(_) => (None, Some("unexpected response from the node".into())),
        Err(e) => (None, Some(e.to_string())),
    };
    render_snapshots(&state, &ctx, form.selector, diff, label, error).await
}
