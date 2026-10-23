//! WordPress staging create and push.

use super::*;

#[derive(Deserialize)]
pub struct StagingForm {
    pub selector: String,
    /// Optional custom staging hostname typed on the create form.
    /// Empty/absent ⇒ fall back to the saved override or `staging.<domain>`.
    #[serde(default)]
    pub staging_domain: Option<String>,
}

/// Create a staging.<domain> copy of a WordPress site.
pub async fn post_wp_staging_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<StagingForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // A staging copy is a NEW hosting the node provisions, so it needs the
    // create capability, not just manage on the source — otherwise a customer
    // with only per-hosting WpManage could spin up (unbilled) extra sites,
    // the same bypass /hostings/transfer closes for Copy.
    if !ctx.can(Capability::HostingCreate) {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?error={}#staging",
            sel_url,
            urlencoding("creating a staging site needs the hosting-create permission")
        ))
        .into_response());
    }
    // Effective staging hostname: the freshly-typed value wins; else the
    // saved per-hosting override; else None (the node uses staging.<domain>).
    let staging_override: Option<String> = match form
        .staging_domain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => Some(s.to_ascii_lowercase()),
        None => read_master_kv(&state, &form.selector, "staging_domain").await,
    };
    let target: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::WpStagingCreate {
            sel,
            staging_domain: staging_override,
        },
    )
    .await?;
    match resp {
        RpcResponse::WpStagingCreate { staging_domain } => {
            // Persist the hostname actually used so push + "Open staging"
            // stay consistent (panel-side metadata, master's hosting_kv).
            let _ = hyperion_rpc_client::call(
                &state.agent_socket,
                Request::HostingKvSet {
                    hosting_id: form.selector.clone(),
                    key: "staging_domain".into(),
                    value: staging_domain.clone(),
                },
            )
            .await;
            Ok(Redirect::to(&format!(
                "/hostings/{}?created=1",
                urlencoding(&staging_domain)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!(
                "/hostings/{}?staging_error={}#wordpress",
                sel_url, msg
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Push the staging copy back over production.
pub async fn post_wp_staging_push(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<StagingForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    // ── Synchronous pre-flight (authz, staging-hostname KV lookup,
    // owner-node lookup). Only the WpStagingPush dispatch — rsync the
    // staging docroot over prod plus a search-replace DB rewrite, which
    // can run for a while — detaches into the worker so a dropped
    // browser can't abort a half-applied push.
    //
    // Push must target the same staging hostname create used.
    let staging_override = read_master_kv(&state, &form.selector, "staging_domain").await;
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);

    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "staging_push",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_wp_staging_push_job(reporter, job_state, node, sel, staging_override).await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker: push the staging site over production on the
/// owning node.
pub(super) async fn run_wp_staging_push_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    sel: HostingSelector,
    staging_domain: Option<String>,
) {
    reporter.step("Pushing staging → production…", 10, "").await;
    match crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::WpStagingPush {
            sel,
            staging_domain,
        },
    )
    .await
    {
        Ok(RpcResponse::WpStagingPush) => {
            reporter
                .step("Staging pushed to production.", 100, "✓ push complete")
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
