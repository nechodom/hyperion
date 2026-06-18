//! Live-progress UI for any background job.
//!
//! Three endpoints:
//!   * `GET /jobs`            — list all jobs, newest first
//!   * `GET /jobs/<id>`       — single-job page (full chrome)
//!   * `GET /jobs/<id>/progress` — HTMX fragment swapped into the
//!     progress card every 2 seconds; the polling stops itself
//!     once the job goes terminal.
//!
//! Plus one cross-handler primitive (`spawn_job`) that any handler
//! kicking off long work uses to: open the row → tokio::spawn the
//! actual work → return immediately with a redirect to /jobs/<id>.
//! See `handlers::hostings::post_migration_move` for the canonical
//! caller.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path as AxPath, Query, State};
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "jobs_list.html")]
struct JobsListTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    jobs: Vec<hyperion_types::JobView>,
    kind_filter: String,
    state_filter: String,
}

#[derive(Template)]
#[template(path = "job_detail.html")]
struct JobDetailTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    job: hyperion_types::JobView,
    /// Pre-formatted "Δ since started" string, e.g. "1m 47s".
    elapsed: String,
    /// True when state is `running` — drives the live-polling
    /// trigger in the template (we stop polling once terminal).
    is_running: bool,
    /// Session-wide CSRF token for the Retry button form. Wildcard
    /// scope so a single token works for /jobs/<id>/retry without
    /// having to mint one token per id.
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "_job_progress.html")]
struct JobProgressFragment {
    job: hyperion_types::JobView,
    elapsed: String,
    is_running: bool,
}

#[derive(Deserialize, Default)]
pub struct JobsListQuery {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub state: String,
}

/// Sidebar-badge endpoint. Returns `{"count": N}` for jobs in
/// state=`running`. Polled every 10s from `base.html` so the
/// operator sees the badge appear seconds after kicking off a
/// migration. Empty array is fine — the JS hides the badge then.
pub async fn get_running_count(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(axum::Json(serde_json::json!({"count": 0})).into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::JobList {
            kind: None,
            state: Some("running".to_string()),
            limit: 200,
        },
    )
    .await?;
    let n = match resp {
        RpcResponse::JobList(v) => v.len(),
        _ => 0,
    };
    Ok(axum::Json(serde_json::json!({"count": n})).into_response())
}

/// POST /jobs/<id>/retry — replay a failed/cancelled job by
/// reconstructing the spawn from the original `payload_json`.
/// Currently understands `migration` + `hosting_clone` (the two
/// kinds that ship with proper payload schemas). Other kinds
/// return a clean "no retry handler for kind X" flash so the
/// operator knows to redo the action from the source page
/// instead of staring at a disabled button.
pub async fn post_job_retry(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            axum::response::Redirect::to("/jobs?flash_error=admin+role+required").into_response(),
        );
    }
    let job = match fetch_job(&state, &id).await? {
        Some(j) => j,
        None => {
            return Ok(
                axum::response::Redirect::to("/jobs?flash_error=Job+id+not+found").into_response(),
            );
        }
    };
    if !job.is_terminal() {
        return Ok(axum::response::Redirect::to(&format!(
            "/jobs/{}?flash_error=Job+is+still+running",
            id
        ))
        .into_response());
    }
    // Parse the payload according to the job kind. Both supported
    // kinds were stored by the matching POST handler so the schema
    // is well-known here.
    let payload: serde_json::Value = serde_json::from_str(&job.payload_json).unwrap_or_default();
    match job.kind.as_str() {
        "migration" => {
            let form = crate::handlers::hostings::MigrationMoveForm {
                selector: payload
                    .get("selector")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                target_node: payload
                    .get("target_node")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                source_node: payload
                    .get("source_node")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            };
            crate::handlers::hostings::post_migration_move(
                State(state),
                ctx,
                headers,
                axum::Form(form),
            )
            .await
        }
        "hosting_clone" => {
            let form = crate::handlers::hostings::HostingCloneForm {
                selector: payload
                    .get("selector")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                new_domain: payload
                    .get("new_domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                target_node: payload
                    .get("target_node")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                source_node: payload
                    .get("source_node")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                issue_cert: payload
                    .get("issue_cert")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            };
            crate::handlers::hostings::post_hosting_clone(
                State(state),
                ctx,
                headers,
                axum::Form(form),
            )
            .await
        }
        "profile_apply" => {
            // Payload stored by profiles::post_apply — hosting ULID
            // + profile id are all the spawn needs. The handler
            // re-resolves the owning node itself, so a hosting that
            // migrated since the original run still applies to the
            // right box.
            let form = crate::handlers::profiles::ApplyForm {
                selector: payload
                    .get("hosting_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                profile_id: payload
                    .get("profile_id")
                    .and_then(|v| v.as_i64())
                    .unwrap_or_default(),
            };
            crate::handlers::profiles::post_apply(State(state), ctx, axum::Form(form)).await
        }
        other => Ok(axum::response::Redirect::to(&format!(
            "/jobs/{}?flash_error=No+retry+handler+for+kind+'{}'+%E2%80%94+please+re-run+from+the+source+page",
            id, other
        ))
        .into_response()),
    }
}

pub async fn get_jobs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<JobsListQuery>,
) -> Result<Response, AppError> {
    // Like /audit, jobs leak cross-tenant operational data —
    // operator-only.
    if !ctx.is_admin_or_higher() {
        return Ok(
            axum::response::Redirect::to("/?flash_error=admin+role+required").into_response(),
        );
    }
    let kind = if q.kind.trim().is_empty() {
        None
    } else {
        Some(q.kind.trim().to_string())
    };
    let st = if q.state.trim().is_empty() {
        None
    } else {
        Some(q.state.trim().to_string())
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::JobList {
            kind: kind.clone(),
            state: st.clone(),
            limit: 200,
        },
    )
    .await?;
    let jobs = match resp {
        RpcResponse::JobList(v) => v,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let tpl = JobsListTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "jobs",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        jobs,
        kind_filter: kind.unwrap_or_default(),
        state_filter: st.unwrap_or_default(),
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_job_detail(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    AxPath(id): AxPath<String>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            axum::response::Redirect::to("/?flash_error=admin+role+required").into_response(),
        );
    }
    let job = match fetch_job(&state, &id).await? {
        Some(j) => j,
        None => {
            return Ok(axum::response::Redirect::to(
                "/jobs?flash_error=Job+id+not+found+(rotated+out%3F)",
            )
            .into_response());
        }
    };
    let is_running = !job.is_terminal();
    let elapsed = format_elapsed(&job);
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let tpl = JobDetailTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "jobs",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        job,
        elapsed,
        is_running,
        csrf_token,
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_job_progress(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    AxPath(id): AxPath<String>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            Html("<div class=\"text-soft\">admin role required</div>".to_string()).into_response(),
        );
    }
    let job = match fetch_job(&state, &id).await? {
        Some(j) => j,
        None => {
            return Ok(
                Html("<div class=\"text-soft\">job no longer present</div>".to_string())
                    .into_response(),
            );
        }
    };
    let is_running = !job.is_terminal();
    let terminal = job.is_terminal();
    let elapsed = format_elapsed(&job);
    let frag = JobProgressFragment {
        job,
        elapsed,
        is_running,
    };
    let mut resp = Html(frag.render()?).into_response();
    if terminal {
        // HTTP 286 is htmx's "stop polling" signal: the body is still
        // swapped (the card shows its final done/failed state) but the
        // every-2s poller on the embedding div stops. Without it the
        // poll ran forever after the job finished — and if the agent
        // later restarted, every tick 502'd and fired a red error toast
        // every 2 seconds.
        *resp.status_mut() =
            axum::http::StatusCode::from_u16(286).unwrap_or(axum::http::StatusCode::OK);
    }
    Ok(resp)
}

async fn fetch_job(
    state: &SharedState,
    id: &str,
) -> Result<Option<hyperion_types::JobView>, AppError> {
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::JobGet { id: id.to_string() })
            .await?;
    match resp {
        RpcResponse::JobGet(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Render "1m 47s" or similar. Caps at hours since no current job
/// is expected to take days; if it does, "h m s" is still readable.
fn format_elapsed(j: &hyperion_types::JobView) -> String {
    let end = j.finished_at.unwrap_or(j.updated_at);
    let secs = (end - j.started_at).max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        format!("{m}m {s}s")
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        format!("{h}h {m}m {s}s")
    }
}

// ============================================================
//  Spawn primitive
// ============================================================

/// Reporter passed into the spawned closure — lets the work code
/// tick progress and report success/failure with the SAME
/// SharedState clone the handler already has.
#[derive(Clone)]
pub struct JobReporter {
    pub id: String,
    pub state: SharedState,
}

impl JobReporter {
    pub async fn step(&self, label: &str, pct: i64, log_append: &str) {
        let r = hyperion_rpc_client::call(
            &self.state.agent_socket,
            Request::JobProgress {
                id: self.id.clone(),
                step_label: label.to_string(),
                progress_pct: pct,
                log_append: log_append.to_string(),
            },
        )
        .await;
        if let Err(e) = r {
            tracing::warn!(error=%e, id=%self.id, "job_progress RPC failed");
        }
    }

    pub async fn finish(&self, ok: bool, error: Option<String>) {
        let r = hyperion_rpc_client::call(
            &self.state.agent_socket,
            Request::JobFinish {
                id: self.id.clone(),
                ok,
                error,
            },
        )
        .await;
        if let Err(e) = r {
            tracing::warn!(error=%e, id=%self.id, "job_finish RPC failed");
        }
    }
}

/// Open a job row, then tokio::spawn the supplied closure with a
/// fresh `JobReporter`. The closure must always call `.finish()` —
/// dropping the reporter without finishing leaves the row in
/// `running` until the reaper sweeps it (up to an hour).
///
/// The closure runs in a detached task; an unwind panics into the
/// tokio default handler and never reaches the operator. Callers
/// should `catch_unwind` if they want richer reporting.
pub async fn spawn_job<F, Fut>(
    state: SharedState,
    kind: &str,
    target: Option<&str>,
    payload_json: &str,
    actor_label: &str,
    actor_uid: i64,
    work: F,
) -> Result<String, AppError>
where
    F: FnOnce(JobReporter) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::JobStart {
            kind: kind.to_string(),
            target: target.map(String::from),
            payload_json: payload_json.to_string(),
            actor_label: actor_label.to_string(),
            actor_uid,
        },
    )
    .await?;
    let id = match resp {
        RpcResponse::JobStarted { job_id } => job_id,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected JobStart response".into())),
    };
    let reporter = JobReporter {
        id: id.clone(),
        state: state.clone(),
    };
    tokio::spawn(work(reporter));
    Ok(id)
}
