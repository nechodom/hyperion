//! Bulk actions over many hostings.

use super::*;

#[derive(Deserialize)]
pub struct BulkForm {
    pub action: String,
    /// Comma-joined list of selectors (hosting ids). The list's per-row
    /// checkboxes are UI-only; a script joins the ticked ids into this one
    /// field. It is a `String`, not a `Vec`, on purpose: `axum::Form`
    /// (serde_urlencoded) cannot gather repeated urlencoded keys
    /// (`selected=a&selected=b`) into a `Vec` — it 422s with "expected a
    /// sequence", even for a single value. Parse with `selected_ids()`.
    #[serde(default)]
    pub selected: String,
    /// Asset id for the `install_asset` bulk action. Empty string
    /// (the wizard's "no asset picked" state) and missing field
    /// both map to 0 — install_asset then gets refused with a clean
    /// flash message rather than blowing up with a 422 deserialise
    /// error from serde trying to parse "" as i64.
    ///
    /// We accept the field as a String so the empty case is valid;
    /// `asset_id_parsed()` does the i64 conversion safely.
    #[serde(default)]
    pub asset_id: String,
    /// Whether to also activate the asset after install. Plain
    /// HTML checkbox → "on" when ticked, missing when not.
    #[serde(default)]
    pub activate: Option<String>,
}

impl BulkForm {
    /// Parse `asset_id` lazily. Empty / missing / non-numeric ⇒ 0
    /// (which the install_asset branch already rejects with a
    /// human flash, so falling through is safe).
    pub(super) fn asset_id_parsed(&self) -> i64 {
        self.asset_id.trim().parse().unwrap_or(0)
    }

    /// Split the comma-joined `selected` field into individual selectors,
    /// de-duped and blank-dropped, order preserved. The field is
    /// machine-written by the list script, so blanks/dupes mean a stale or
    /// tampered POST rather than a user typo worth a message. Selector *shape*
    /// is validated later, per item, by `parse_selector` in the job loop.
    ///
    /// NOT capped here: a cap in the parser would SILENTLY truncate a genuine
    /// "select all" on a large, unpaginated list — the operator would confirm
    /// "Delete 1200 hostings", the job would act on the first N, and finish
    /// green, leaving the rest untouched with no signal. `post_bulk` instead
    /// rejects an over-`MAX_BULK_SELECTION` batch outright, so the fan-out is
    /// still bounded but the operator is told rather than quietly obeyed. The
    /// de-dupe uses a set so parsing an oversized (bounded by the body limit)
    /// POST stays linear.
    pub(super) fn selected_ids(&self) -> Vec<String> {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut out: Vec<String> = Vec::new();
        for tok in self.selected.split(',') {
            let s = tok.trim();
            if !s.is_empty() && seen.insert(s) {
                out.push(s.to_string());
            }
        }
        out
    }
}

/// Most hostings one bulk POST may act on. A real "select all" on a big cluster
/// can exceed this; `post_bulk` then refuses the whole batch with a flash
/// telling the operator to narrow the filter, rather than silently acting on a
/// truncated prefix. Bounds RPC fan-out from a stale/tampered POST too.
pub(super) const MAX_BULK_SELECTION: usize = 1000;

pub async fn post_bulk(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BulkForm>,
) -> Result<Response, AppError> {
    // Bulk ops span arbitrary hostings (admin can pick anything in the
    // list). Operators with per-hosting grants don't get to run bulk
    // delete across the cluster — that's an admin-level lever.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let selected = form.selected_ids();
    if selected.is_empty() {
        return Ok(Redirect::to("/hostings?q=&state=").into_response());
    }
    // Refuse an oversized batch instead of silently truncating it. The list is
    // not paginated, so "select all" on a big cluster can tick more than we're
    // willing to fan out in one job; acting on a prefix and finishing green
    // would leave the rest untouched (and, for delete, is unrecoverable) with
    // no signal. Tell the operator to narrow the filter and retry.
    if selected.len() > MAX_BULK_SELECTION {
        let msg = format!(
            "Too many hostings selected at once ({}). This can act on at most {} in one go — \
             narrow the list with the search or state filter and run it in smaller batches. \
             Nothing was changed.",
            selected.len(),
            MAX_BULK_SELECTION,
        );
        return Ok(
            Redirect::to(&format!("/hostings?bulk_flash={}", urlencoding(&msg))).into_response(),
        );
    }
    // Pre-flight validation for install_asset — surface a single
    // clean error rather than echoing it per-selected hosting.
    if form.action == "install_asset" && form.asset_id_parsed() <= 0 {
        return Ok(Redirect::to(
            "/hostings?bulk_flash=Pick+an+asset+from+the+library+before+running+the+bulk+install",
        )
        .into_response());
    }
    // Validate the action up-front so an unknown verb fails fast
    // (synchronously) instead of erroring inside the background loop.
    if !matches!(
        form.action.as_str(),
        "suspend" | "resume" | "backup" | "delete" | "install_asset"
    ) {
        return Err(AppError::BadRequest(format!(
            "unknown bulk action: {}",
            form.action
        )));
    }
    let activate = matches!(form.activate.as_deref(), Some("on" | "true" | "1"));
    // Resolve S3 targets once for the whole bulk run (secret read — stays
    // synchronous); only the backup action uses them.
    let s3_targets = if form.action == "backup" {
        resolve_s3_targets(&state).await
    } else {
        Vec::new()
    };

    // The loop can span many hostings and minutes of work (backups, installs),
    // so run it as a detached background job with per-item progress instead of
    // blocking the request — a browser disconnect won't abort the batch.
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let action = form.action.clone();
    let asset_id = form.asset_id_parsed();
    let label = format!("{} × {} hosting(s)", action, selected.len());
    let job_state = state.clone();

    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "bulk",
        Some(&label),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_bulk_job(
                reporter, job_state, action, selected, s3_targets, asset_id, activate,
            )
            .await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker for a bulk action: applies `action` to each selected
/// hosting on its owning node, ticking per-item progress into the job. A
/// per-hosting failure is collected and the run continues; the job ends
/// `failed` (red) iff any item failed, with every failure listed in the log.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_bulk_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    action: String,
    selected: Vec<String>,
    s3_targets: Vec<hyperion_types::S3BackupTarget>,
    asset_id: i64,
    activate: bool,
) {
    let total = selected.len().max(1) as i64;
    let mut ok = 0i64;
    let mut errs: Vec<String> = vec![];
    for (i, sel_str) in selected.iter().enumerate() {
        let pct = (((i as i64) * 100) / total).clamp(1, 99);
        reporter
            .step(
                &format!("{action} {sel_str} ({}/{})", i + 1, selected.len()),
                pct,
                "",
            )
            .await;
        let sel = match parse_selector(sel_str) {
            Ok(s) => s,
            Err(e) => {
                errs.push(format!("{sel_str}: {e}"));
                continue;
            }
        };
        // Land each action on the node that owns the hosting (backups are
        // stored per node, and an action on the master NotFounds a worker row).
        let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
            .await
            .ok()
            .and_then(|(_d, n)| n);
        let req = match action.as_str() {
            "suspend" => Request::HostingSuspend {
                sel,
                reason: hyperion_types::SuspendReason::Manual {
                    message: Some("bulk suspend".into()),
                },
            },
            "resume" => Request::HostingResume(sel),
            "backup" => Request::BackupNow {
                sel,
                s3_targets: s3_targets.clone(),
                // Bulk action fan-out: one job covers many hostings, so a
                // per-phase sub-step card for a single backup does not apply.
                progress_job_id: None,
            },
            "delete" => Request::HostingDelete {
                sel,
                opts: hyperion_rpc::wire::DeleteOpts {
                    keep_user: false,
                    keep_database: false,
                },
            },
            "install_asset" => Request::WpInstallFromAsset {
                sel,
                asset_id,
                activate,
            },
            _ => {
                // Pre-validated in the handler; defensive only.
                errs.push(format!("{sel_str}: unknown action {action}"));
                continue;
            }
        };
        match crate::dispatcher::dispatch_to_node(&state, target_owned.as_deref(), req).await {
            Ok(RpcResponse::Error(e)) => errs.push(format!("{sel_str}: {e}")),
            Ok(_) => ok += 1,
            Err(e) => errs.push(format!("{sel_str}: {e}")),
        }
    }

    let noun = if ok == 1 { "hosting" } else { "hostings" };
    if errs.is_empty() {
        reporter
            .step(&format!("{action}: {ok} {noun} ok"), 100, "")
            .await;
        reporter.finish(true, None).await;
    } else {
        let summary = format!("{action}: {ok} {noun} ok, {} failed", errs.len());
        reporter.step(&summary, 100, &errs.join("\n")).await;
        reporter
            .finish(
                false,
                Some(format!("{} of {} failed", errs.len(), selected.len())),
            )
            .await;
    }
}
