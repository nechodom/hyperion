//! Automated page check card.

use super::*;

// ============================================================
// Automated page check
// ============================================================

#[derive(Template)]
#[template(path = "_hosting_sitecheck_card.html")]
pub(super) struct SiteCheckCardTpl {
    pub(super) selector: String,
    /// `None` until a walk has run. Distinct from a walk that ran and found
    /// nothing: the card says "not checked yet", never "all good".
    pub(super) report: Option<hyperion_types::SiteCheckReport>,
    pub(super) checked_ago: String,
    pub(super) csrf_run: String,
    pub(super) error: Option<String>,
}

/// GET /hostings/:selector/sitecheck-panel — the LAST walk, from store.
///
/// Never runs one: a crawl is up to fifty requests against the customer's
/// own site, and a page render is not a thing that should cost that. The
/// button below spawns it as a job.
pub async fn get_sitecheck_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let card = |report: Option<hyperion_types::SiteCheckReport>, error: Option<String>| {
        let checked_ago = report
            .as_ref()
            .map(|r| crate::handlers::stats::fmt_ago(&r.checked_at))
            .unwrap_or_default();
        Html(
            SiteCheckCardTpl {
                selector: selector.clone(),
                report,
                checked_ago,
                csrf_run: csrf_token_for(&state, &ctx, "/hostings/site-check"),
                error,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => return Ok(card(None, Some(e.to_string()))),
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => return Ok(card(None, Some(e.to_string()))),
    };
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
        return Ok(card(
            None,
            Some("You do not have access to this hosting.".into()),
        ));
    }
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::SiteCheckLast { sel },
    )
    .await
    {
        Ok(RpcResponse::SiteCheckLast(r)) => Ok(card(r, None)),
        Ok(RpcResponse::Error(e)) => Ok(card(None, Some(e.to_string()))),
        Ok(_) => Ok(card(None, Some("unexpected response from the node".into()))),
        Err(e) => Ok(card(None, Some(e.to_string()))),
    }
}

#[derive(serde::Deserialize)]
pub struct SiteCheckForm {
    pub selector: String,
}

/// POST /hostings/site-check — walk the site now, as a background job.
///
/// A job rather than an inline request: the crawl is up to fifty fetches,
/// each with a twenty-second ceiling, so a sick site would hold the
/// connection open for minutes and lose the result when the operator's
/// browser gave up.
pub async fn post_site_check(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SiteCheckForm>,
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
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "site_check",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            reporter
                .step("Fetching pages, links and images…", 20, "")
                .await;
            let outcome = crate::dispatcher::dispatch_to_node(
                &job_state,
                owner.as_deref(),
                Request::SiteCheckRun { sel },
            )
            .await;
            match outcome {
                Ok(RpcResponse::SiteCheck(r)) if r.error.is_empty() => {
                    let summary = format!(
                        "{} of {} page(s) answered, {} link(s) checked, {} problem(s) found.\n{}",
                        r.pages_ok(),
                        r.pages.len(),
                        r.links_checked,
                        r.findings.len(),
                        r.findings
                            .iter()
                            .map(|f| format!("[{}] {} — {}", f.severity, f.url, f.detail))
                            .collect::<Vec<_>>()
                            .join("\n")
                    );
                    reporter.step("Done", 100, &summary).await;
                    reporter.finish(true, None).await;
                }
                // The crawl could not START. Reported as a failed job rather
                // than a clean one with an empty result, which would read as
                // "nothing wrong with the site".
                Ok(RpcResponse::SiteCheck(r)) => {
                    reporter.finish(false, Some(r.error)).await;
                }
                Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
                Ok(_) => {
                    reporter
                        .finish(false, Some("unexpected response from the node".into()))
                        .await
                }
                Err(e) => reporter.finish(false, Some(e.to_string())).await,
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}
