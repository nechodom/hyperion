//! Off-site copies card.

use super::*;

// ============================================================
// Snapshots
// ============================================================

#[derive(Template)]
#[template(path = "_hosting_offsite_card.html")]
pub(super) struct OffsiteCardTpl {
    pub(super) selector: String,
    pub(super) detail_domain: String,
    /// One row per ARCHIVE, newest first. Each backup is two files on the
    /// remote — the tar and its `.sql` dump — and listing both gave the dump a
    /// Restore button of its own that could only fail.
    pub(super) rows: Vec<OffsiteRow>,
    /// Does the site have a database at all? A site without one restores
    /// files only; offering "files and database" there was a guaranteed
    /// refusal.
    pub(super) site_has_db: bool,
    /// Is there an off-site target at all? Distinct from "the listing was
    /// empty": no target is a thing to go and fix, an empty listing on a
    /// configured target is a thing to worry about.
    pub(super) configured: bool,
    /// Does the per-site directory exist on the remote?
    ///
    /// The third state, and the one production hit first: the folder is made
    /// by the first UPLOAD, so a site whose backups all predate the target
    /// has no directory — and curl answers that with exit 9, which the card
    /// used to surface as "internal error: off-site list". It is an ordinary
    /// state with an obvious fix.
    pub(super) directory_exists: bool,
    pub(super) can_restore: bool,
    pub(super) csrf_offsite_restore: String,
    /// May delete backups of this site (the same permission as Delete on the
    /// backups list).
    pub(super) can_delete: bool,
    pub(super) csrf_offsite_delete: String,
    pub(super) error: Option<String>,
}

pub struct OffsiteRow {
    pub name: String,
    pub bytes: i64,
    /// Size of the database dump beside it, when there is one.
    pub dump_bytes: Option<i64>,
    /// "3 d ago", from the unix time in the archive name. Empty for a file
    /// named some other way.
    pub when: String,
    pub when_exact: String,
    pub(super) taken_at: i64,
    /// Is this archive also on the node's disk? `None` = could not ask. The
    /// difference between deleting a spare copy and deleting the last one.
    pub on_node: Option<bool>,
}

/// Pair archives with their dumps and sort newest first.
pub(super) fn offsite_rows(
    files: &[hyperion_types::OffsiteFile],
    local: Option<&std::collections::HashSet<String>>,
) -> Vec<OffsiteRow> {
    let mut rows: Vec<OffsiteRow> = files
        .iter()
        .filter(|f| !f.name.ends_with(".sql"))
        .map(|f| {
            let stem = f
                .name
                .strip_suffix(".tar.gz")
                .or_else(|| f.name.strip_suffix(".tgz"))
                .unwrap_or(&f.name);
            let dump_bytes = files
                .iter()
                .find(|d| d.name == format!("{stem}.sql"))
                .map(|d| d.bytes);
            // `<domain>-<unix seconds>.tar.gz`, as backup_run names them.
            let taken_at = stem
                .rsplit('-')
                .next()
                .and_then(|t| t.parse::<i64>().ok())
                .filter(|t| *t > 1_000_000_000)
                .unwrap_or(0);
            OffsiteRow {
                name: f.name.clone(),
                bytes: f.bytes,
                dump_bytes,
                when: if taken_at > 0 {
                    crate::handlers::stats::fmt_ago(&taken_at)
                } else {
                    String::new()
                },
                when_exact: chrono::DateTime::from_timestamp(taken_at, 0)
                    .filter(|_| taken_at > 0)
                    .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                    .unwrap_or_default(),
                taken_at,
                on_node: local.map(|l| l.contains(&f.name)),
            }
        })
        .collect();
    rows.sort_by(|a, b| b.taken_at.cmp(&a.taken_at).then(b.name.cmp(&a.name)));
    rows
}

/// GET /hostings/:selector/offsite-panel
pub async fn get_offsite_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    render_offsite(&state, &ctx, selector, None).await
}

pub(super) async fn render_offsite(
    state: &SharedState,
    ctx: &AuthCtx,
    selector: String,
    error: Option<String>,
) -> Result<Response, AppError> {
    let can_restore = require_manage_for_selector(state, ctx, &selector, Capability::BackupRestore)
        .await
        .is_ok();
    let can_delete = require_manage_for_selector(state, ctx, &selector, Capability::BackupRun)
        .await
        .is_ok();
    let card = |rows: Vec<OffsiteRow>,
                configured: bool,
                directory_exists: bool,
                detail_domain: String,
                site_has_db: bool,
                error: Option<String>| {
        Html(
            OffsiteCardTpl {
                selector: selector.clone(),
                detail_domain,
                rows,
                site_has_db,
                configured,
                directory_exists,
                can_restore,
                csrf_offsite_restore: csrf_token_for(state, ctx, "/hostings/offsite-restore"),
                can_delete,
                csrf_offsite_delete: csrf_token_for(state, ctx, "/hostings/offsite-delete"),
                error,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return Ok(card(
                Vec::new(),
                false,
                false,
                String::new(),
                false,
                Some(e.to_string()),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(card(
                Vec::new(),
                false,
                false,
                String::new(),
                false,
                Some(e.to_string()),
            ))
        }
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
            false,
            false,
            detail.domain,
            false,
            Some("You do not have access to this hosting.".into()),
        ));
    }
    let site_has_db = detail.database.is_some();
    let sel_for_rows = sel.clone();
    match crate::dispatcher::dispatch_to_node(
        state,
        owner.as_deref(),
        Request::BackupOffsiteList { sel: sel.clone() },
    )
    .await
    {
        Ok(RpcResponse::BackupOffsiteList(listing)) => {
            // Which of these are still on the node too — read from the
            // node's own rows, by file name.
            let local: Option<std::collections::HashSet<String>> =
                fetch_backup_list(state, owner.as_deref(), sel_for_rows, 500)
                    .await
                    .ok()
                    .map(|rows| {
                        rows.iter()
                            .filter_map(|b| b.archive_path.as_deref())
                            .filter_map(|p| p.rsplit('/').next())
                            .map(str::to_string)
                            .collect()
                    });
            Ok(card(
                offsite_rows(&listing.files, local.as_ref()),
                true,
                listing.directory_exists,
                detail.domain,
                site_has_db,
                error,
            ))
        }
        // A validation error here is "no target configured", which is a
        // distinct state the card renders as advice rather than as a fault.
        Ok(RpcResponse::Error(e)) => {
            let msg = e.to_string();
            let no_target = msg.contains("no off-site backup target");
            Ok(card(
                Vec::new(),
                !no_target,
                false,
                detail.domain,
                site_has_db,
                if no_target { error } else { Some(msg) },
            ))
        }
        Ok(_) => Ok(card(
            Vec::new(),
            true,
            false,
            detail.domain,
            site_has_db,
            error,
        )),
        Err(e) => Ok(card(
            Vec::new(),
            true,
            false,
            detail.domain,
            site_has_db,
            Some(e.to_string()),
        )),
    }
}

#[derive(serde::Deserialize)]
pub struct OffsiteDeleteForm {
    pub selector: String,
    pub filename: String,
}

/// POST /hostings/offsite-delete — delete one archive (and its dump) from the
/// FTP target, from the Off-site copies card. Same permission as deleting a
/// backup from the list; the node re-checks the file is this site's own.
pub async fn post_offsite_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<OffsiteDeleteForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRun)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let flash = match crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::BackupOffsiteDelete {
            sel,
            backup_id: None,
            filename: Some(form.filename.trim().to_string()),
        },
    )
    .await
    {
        Ok(RpcResponse::BackupOffsiteDelete(msg)) => {
            format!("backup_deleted={}", urlencoding(&upper_first(&msg)))
        }
        Ok(RpcResponse::Error(e)) => format!("backup_error={}", urlencoding(&e.to_string())),
        Ok(_) => format!("backup_error={}", urlencoding("unexpected agent response")),
        Err(e) => format!("backup_error={}", urlencoding(&e.to_string())),
    };
    Ok(Redirect::to(&format!("/hostings/{sel_url}?{flash}#backups")).into_response())
}

#[derive(serde::Deserialize)]
pub struct OffsiteRestoreForm {
    pub selector: String,
    pub filename: String,
    /// "files_and_db" (default) | "files_only" | "db_only".
    #[serde(default)]
    pub mode: String,
}

/// POST /hostings/offsite-restore — fetch a backup back and restore it.
pub async fn post_offsite_restore(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<OffsiteRestoreForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::BackupRestore)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let filename = form.filename.trim().to_string();
    let mode = parse_restore_mode(form.mode.trim());
    // Not offered: an off-site restore fetches the whole archive before it
    // looks at the mode, so "database only" downloaded gigabytes to use none.
    if mode == hyperion_types::BackupRestoreMode::DbOnly {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#backups",
            urlencoding(&form.selector),
            urlencoding("A database-only restore from the off-site copy is not supported.")
        ))
        .into_response());
    }
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    // A download over somebody else's FTP plus a full restore. Nowhere near a
    // request's lifetime, and a dropped browser must not abort it half-way.
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "offsite-restore",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            reporter
                .step(
                    "Fetching the archive from the off-site store…",
                    10,
                    &format!(
                        "file: {filename}
"
                    ),
                )
                .await;
            match crate::dispatcher::dispatch_to_node(
                &job_state,
                node.as_deref(),
                Request::BackupOffsiteRestore {
                    sel,
                    filename,
                    mode,
                },
            )
            .await
            {
                Ok(RpcResponse::BackupOffsiteRestore(msg)) => {
                    reporter
                        .step("Restore complete.", 100, &format!("✓ {msg}"))
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
