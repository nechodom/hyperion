//! Delete, suspend, resume and operator notes.

use super::*;

#[derive(Deserialize)]
pub struct DeleteForm {
    pub(super) selector: String,
    #[serde(default)]
    pub(super) keep_user: Option<String>,
    #[serde(default)]
    pub(super) keep_db: Option<String>,
    /// Which node owns this hosting. Filled by the listing template
    /// from the aggregated HostingSummary.node_id field. Empty /
    /// "local" → master itself. Missing field defaults to master
    /// for backwards compatibility with the pre-multi-node form.
    #[serde(default)]
    pub(super) target_node: String,
}

pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingDelete)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let opts = DeleteOpts {
        keep_user: form.keep_user.as_deref() == Some("on"),
        keep_database: form.keep_db.as_deref() == Some("on"),
    };
    // Deleting is the slowest mutation we have — nginx reload, acme
    // cleanup, DROP DATABASE, rm -rf of the whole tree, userdel. On
    // a big site that's tens of seconds, which used to leave the
    // operator staring at a hung POST (and the browser console full
    // of aborted-fetch noise). Run it as a background job and land
    // on the job page with a live progress bar instead.
    //
    // Dispatch goes to the node that actually owns the hosting.
    // Without this, deletes always hit the master and silently do
    // nothing for hostings provisioned on a worker (the very bug
    // that left orphan rows blocking the UNIQUE(domain) constraint
    // on retry).
    let target_owned: Option<String> = node_target(&form.target_node).map(String::from);
    let payload = serde_json::json!({
        "selector": form.selector,
        "keep_user": opts.keep_user,
        "keep_database": opts.keep_database,
        "target_node": form.target_node,
    });
    let actor_label = ctx.username.clone();
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let job_state = state.clone();
    let job_selector = form.selector.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "hosting_delete",
        Some(&form.selector),
        &payload.to_string(),
        &actor_label,
        actor_uid,
        move |reporter| async move {
            reporter
                .step(
                    &format!("Deleting {job_selector} — vhost, certificate, database, files…"),
                    20,
                    "",
                )
                .await;
            let hosting_id = crate::handlers::acme_dns_ssl::hosting_id_of(
                &job_state,
                target_owned.as_deref(),
                &sel,
            )
            .await;
            let resp = crate::dispatcher::dispatch_to_node(
                &job_state,
                target_owned.as_deref(),
                Request::HostingDelete { sel, opts },
            )
            .await;
            match resp {
                Ok(RpcResponse::HostingDelete) => {
                    // Gone for good (not trashed): its acme-dns labels go too.
                    if let Some(id) = hosting_id {
                        crate::handlers::acme_dns_ssl::forget_hosting_if_gone(
                            &job_state,
                            target_owned.as_deref(),
                            &id,
                        )
                        .await;
                    }
                    reporter
                        .step("Hosting deleted.", 100, "✓ hosting removed")
                        .await;
                    reporter.finish(true, None).await;
                }
                Ok(RpcResponse::Error(e)) => {
                    reporter.finish(false, Some(e.to_string())).await;
                }
                Ok(_) => {
                    reporter
                        .finish(false, Some("unexpected agent response".into()))
                        .await;
                }
                Err(e) => {
                    reporter.finish(false, Some(e.to_string())).await;
                }
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

#[derive(Deserialize)]
pub struct NotesForm {
    pub selector: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: String,
}

/// Normalise a comma-separated tag string into trimmed, lowercased,
/// deduped, charset-limited tokens (≤12 tags, ≤24 chars each).
pub(super) fn normalize_tags(raw: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for t in raw.split(',') {
        let cleaned: String = t
            .trim()
            .to_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
            .take(24)
            .collect();
        let cleaned = cleaned.trim().to_string();
        if cleaned.is_empty() {
            continue;
        }
        if seen.insert(cleaned.clone()) {
            out.push(cleaned);
        }
        if out.len() >= 12 {
            break;
        }
    }
    out
}

/// POST /hostings/notes — save the operator note + tags. Panel-side
/// metadata stored in the master's hosting_kv (keyed by ULID), so it
/// is the same regardless of which node hosts the site.
pub async fn post_set_notes(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<NotesForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // Resolve the ULID (the selector may be a domain) for the KV key.
    let hosting_id = match find_hosting_anywhere(&state, sel).await {
        Ok((d, _)) => d.id.as_str().to_string(),
        Err(_) => {
            return Ok(Redirect::to(&format!("/hostings/{sel_url}")).into_response());
        }
    };
    let notes: String = form.notes.replace('\r', "").chars().take(2000).collect();
    let tags = normalize_tags(&form.tags).join(",");
    // Master-side metadata → local socket.
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingKvSet {
            hosting_id: hosting_id.clone(),
            key: "notes".into(),
            value: notes,
        },
    )
    .await;
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingKvSet {
            hosting_id,
            key: "tags".into(),
            value: tags,
        },
    )
    .await;
    Ok(save_result(
        &headers,
        true,
        "Notes & tags saved.",
        format!(
            "/hostings/{sel_url}?flash={}#overview",
            urlencoding("Notes & tags saved.")
        ),
    ))
}

#[derive(Deserialize)]
pub struct SuspendForm {
    pub(super) selector: String,
    #[serde(default)]
    pub(super) reason: String,
    /// Node where the hosting lives — populated by the detail
    /// page's target_node injector. Empty / "local" → master.
    #[serde(default)]
    pub(super) target_node: String,
}

pub async fn post_suspend(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SuspendForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingSuspend)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let reason = hyperion_types::SuspendReason::Manual {
        message: if form.reason.trim().is_empty() {
            None
        } else {
            Some(form.reason.trim().to_string())
        },
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSuspend { sel, reason },
    )
    .await?;
    match resp {
        RpcResponse::HostingSuspend => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ResumeForm {
    pub(super) selector: String,
    #[serde(default)]
    pub(super) target_node: String,
}

pub async fn post_resume(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ResumeForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingSuspend)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let target = node_target(&form.target_node);
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target, Request::HostingResume(sel)).await?;
    match resp {
        RpcResponse::HostingResume => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
