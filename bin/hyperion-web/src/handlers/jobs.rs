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

pub async fn get_jobs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<JobsListQuery>,
) -> Result<Response, AppError> {
    // Like /audit, jobs leak cross-tenant operational data —
    // operator-only.
    if !ctx.is_admin_or_higher() {
        return Ok(axum::response::Redirect::to("/?flash_error=admin+role+required").into_response());
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
        return Ok(axum::response::Redirect::to("/?flash_error=admin+role+required").into_response());
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
    let tpl = JobDetailTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "jobs",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        job,
        elapsed,
        is_running,
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_job_progress(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    AxPath(id): AxPath<String>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Html("<div class=\"text-soft\">admin role required</div>".to_string()).into_response());
    }
    let job = match fetch_job(&state, &id).await? {
        Some(j) => j,
        None => {
            return Ok(Html(
                "<div class=\"text-soft\">job no longer present</div>".to_string(),
            )
            .into_response());
        }
    };
    let is_running = !job.is_terminal();
    let elapsed = format_elapsed(&job);
    let frag = JobProgressFragment {
        job,
        elapsed,
        is_running,
    };
    Ok(Html(frag.render()?).into_response())
}

async fn fetch_job(state: &SharedState, id: &str) -> Result<Option<hyperion_types::JobView>, AppError> {
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::JobGet { id: id.to_string() },
    )
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
