//! Performance and Core Web Vitals card.

use super::*;

#[derive(Template)]
#[template(path = "_hosting_performance_card.html")]
pub(super) struct PerformanceCardTpl {
    pub(super) selector: String,
    pub(super) cwv: Option<hyperion_types::CwvResult>,
    pub(super) source: String,
    pub(super) strategy: String,
    pub(super) lighthouse_available: bool,
    pub(super) can_measure: bool,
    pub(super) measured_ago: String,
    pub(super) csrf_measure: String,
    pub(super) error: Option<String>,
}

/// GET /hostings/:selector/performance-panel — the last Core Web Vitals, from
/// the owning node. Never measures; the button below spawns that as a job.
pub async fn get_performance_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let can_measure =
        require_manage_for_selector(&state, &ctx, &selector, Capability::HostingEditConfig)
            .await
            .is_ok();
    let card = |view: hyperion_types::PerformanceView, error: Option<String>| {
        let measured_ago = view
            .care
            .cwv
            .as_ref()
            .filter(|c| c.measured_at > 0)
            .map(|c| crate::handlers::stats::fmt_ago(&c.measured_at))
            .unwrap_or_default();
        Html(
            PerformanceCardTpl {
                selector: selector.clone(),
                cwv: view.care.cwv,
                source: view.cwv_source,
                strategy: view.strategy,
                lighthouse_available: view.lighthouse_available,
                can_measure,
                measured_ago,
                csrf_measure: csrf_token_for(&state, &ctx, "/hostings/performance/measure"),
                error,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => return Ok(card(Default::default(), Some(e.to_string()))),
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => return Ok(card(Default::default(), Some(e.to_string()))),
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
            Default::default(),
            Some("You do not have access to this hosting.".into()),
        ));
    }
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::PerformanceView { sel },
    )
    .await
    {
        Ok(RpcResponse::PerformanceView(v)) => Ok(card(v, None)),
        Ok(RpcResponse::Error(e)) => Ok(card(Default::default(), Some(e.to_string()))),
        Ok(_) => Ok(card(
            Default::default(),
            Some("unexpected response from the node".into()),
        )),
        // An older agent does not know PerformanceView — say so rather than
        // show a raw decode error.
        Err(e) => Ok(card(
            Default::default(),
            Some(format!(
                "Could not read performance from the owning node ({e})."
            )),
        )),
    }
}

#[derive(serde::Deserialize)]
pub struct CwvMeasureForm {
    pub selector: String,
}

/// POST /hostings/performance/measure — measure Core Web Vitals now, as a job.
///
/// A job because a browser load (local Lighthouse) or a round trip to Google
/// takes far longer than a request should hold open.
pub async fn post_cwv_measure(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CwvMeasureForm>,
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
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "cwv_measure",
        Some(&form.selector),
        "{}",
        &ctx.username,
        actor_uid,
        move |reporter| async move {
            reporter.step("Measuring Core Web Vitals…", 20, "").await;
            match crate::dispatcher::dispatch_to_node(
                &job_state,
                owner.as_deref(),
                Request::CwvMeasure { sel },
            )
            .await
            {
                Ok(RpcResponse::CwvResult(c)) => {
                    let mut log = format!("source: {}, {}\n", c.source, c.strategy);
                    if let Some(m) = c.best() {
                        log.push_str(&format!(
                            "LCP {:?} ms, CLS(x1000) {:?}, INP {:?} ms, score {:?}\n",
                            m.lcp_ms, m.cls_x1000, m.inp_ms, c.perf_score
                        ));
                    }
                    reporter.step("Measured.", 100, &log).await;
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
