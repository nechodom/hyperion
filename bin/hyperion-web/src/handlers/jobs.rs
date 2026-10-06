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
    /// Jobs still running, in the filtered view — their own group on top.
    running: Vec<JobRow>,
    /// Finished jobs in the filtered view, bucketed by local calendar day.
    days: Vec<DayGroup>,
    /// One line answering "is anything wrong / in flight right now?" —
    /// computed over the whole window, not the filtered view.
    verdict: String,
    verdict_tone: &'static str,
    /// Per-state counts for the segment strip (after kind + search filters).
    counts: StateCounts,
    /// `(kind, label)` for every kind present in the window, for the select.
    kinds: Vec<(String, String)>,
    kind_filter: String,
    state_filter: String,
    q: String,
    /// Pre-built segment hrefs, so the template never hand-assembles a query
    /// string out of user input.
    seg_hrefs: SegHrefs,
    /// True when the window filled up — older jobs exist but aren't listed.
    truncated: bool,
    /// The live region polls fast while something runs, slowly otherwise.
    refresh_secs: u32,
    /// Nothing in the window at all (as opposed to nothing matching).
    window_empty: bool,
}

/// One job as the list renders it — everything pre-formatted so the template
/// carries no arithmetic.
pub struct JobRow {
    pub id: String,
    pub title: String,
    pub target: Option<String>,
    pub state: String,
    pub tone: &'static str,
    pub state_label: &'static str,
    pub step_label: String,
    /// First line of the error, trimmed — the whole thing is on the job page.
    pub error_line: String,
    pub pct: i64,
    pub started_ago: String,
    pub started_abs: String,
    pub duration: String,
    pub actor: String,
}

pub struct DayGroup {
    pub label: String,
    pub rows: Vec<JobRow>,
}

#[derive(Default)]
pub struct StateCounts {
    pub all: usize,
    pub running: usize,
    pub failed: usize,
    pub done: usize,
    pub cancelled: usize,
}

pub struct SegHrefs {
    pub all: String,
    pub running: String,
    pub failed: String,
    pub done: String,
    pub cancelled: String,
}

/// How many jobs the list pulls before filtering. Filtering happens here
/// rather than in SQL so the segment counts and the kind list describe the
/// same window the rows come from.
const LIST_WINDOW: i64 = 500;
/// How many rows the list renders at most.
const LIST_SHOWN: usize = 200;

/// Kinds `/jobs/<id>/retry` knows how to replay. Keep in step with the match
/// in [`post_job_retry`].
pub const RETRYABLE_KINDS: &[&str] = &["migration", "hosting_clone", "profile_apply"];

/// What the operator calls a job kind. The stored kind is an identifier
/// (`acme_issue`, `post_create_setup`) and used to be shown raw; the page
/// now leads with this and keeps the identifier for the filter only.
pub fn job_kind_label(kind: &str) -> String {
    match kind {
        "migration" => "Move hosting",
        "hosting_clone" => "Copy hosting",
        "hosting_delete" => "Delete hosting",
        "hosting_restore" | "restore" => "Restore backup",
        "backup" | "hosting_backup" => "Backup",
        "install" => "Install service",
        "acme_issue" => "Issue certificate",
        "cert_renew" => "Renew certificate",
        "cert_renew_all" => "Renew all certificates",
        "node_update" => "Update node",
        "post_create_setup" => "Set up new hosting",
        "wp_install" => "Install WordPress",
        "wp_reinstall" => "Reinstall WordPress core",
        "wp_reinstall_all" => "Reinstall WordPress core everywhere",
        "profile_apply" => "Apply profile",
        "profile_reapply_all" => "Re-apply profile to all hostings",
        "rofs_fix" => "Fix read-only filesystem",
        "db_reset" => "Reset database",
        "panel_import" => "Import from another panel",
        "staging_push" => "Push staging to live",
        "snapshot_now" => "Take snapshot",
        "snapshot_delete" => "Delete snapshot",
        "site_check" => "Site check",
        "gitsync_deploy" => "Git deploy",
        "cwv_measure" => "Measure Core Web Vitals",
        "normalize_www" => "Normalize www redirect",
        "bulk" => "Bulk action",
        other => return crate::handlers::stats::fmt_action_label(other),
    }
    .to_string()
}

fn state_tone(state: &str) -> (&'static str, &'static str) {
    match state {
        "running" => ("warn", "Running"),
        "done" => ("ok", "Done"),
        "failed" => ("err", "Failed"),
        "cancelled" => ("muted", "Cancelled"),
        _ => ("muted", "Unknown"),
    }
}

fn fmt_local(ts: i64, fmt: &str) -> String {
    use chrono::{Local, TimeZone};
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.format(fmt).to_string())
        .unwrap_or_default()
}

/// "Today" / "Yesterday" / "Mon 5 Oct" for the day a job started, in the
/// panel host's local time.
fn day_label(ts: i64, now: i64) -> String {
    use chrono::{Local, TimeZone};
    let day = |t: i64| Local.timestamp_opt(t, 0).single().map(|d| d.date_naive());
    match (day(ts), day(now)) {
        (Some(d), Some(today)) if d == today => "Today".into(),
        (Some(d), Some(today)) if today.pred_opt() == Some(d) => "Yesterday".into(),
        _ => fmt_local(ts, "%a %-d %b %Y"),
    }
}

fn job_row(j: hyperion_types::JobView) -> JobRow {
    let (tone, state_label) = state_tone(&j.state);
    let duration = format_elapsed(&j);
    let error_line = j
        .error
        .as_deref()
        .and_then(|e| e.lines().map(str::trim).find(|l| !l.is_empty()))
        .map(|l| {
            if l.chars().count() > 160 {
                format!("{}…", l.chars().take(160).collect::<String>())
            } else {
                l.to_string()
            }
        })
        .unwrap_or_default();
    JobRow {
        title: job_kind_label(&j.kind),
        target: j.target,
        tone,
        state_label,
        // A finished job's last step is usually just "Done" — the pill says
        // that already.
        step_label: if j.state == "done" && j.step_label.trim().eq_ignore_ascii_case("done") {
            String::new()
        } else {
            j.step_label
        },
        error_line,
        pct: j.progress_pct.clamp(0, 100),
        started_ago: crate::handlers::stats::fmt_ago(&j.started_at),
        started_abs: fmt_local(j.started_at, "%Y-%m-%d %H:%M:%S"),
        duration,
        actor: j.actor_label,
        id: j.id,
        state: j.state,
    }
}

fn jobs_href(state: &str, kind: &str, q: &str) -> String {
    let mut parts = Vec::new();
    if !state.is_empty() {
        parts.push(format!("state={}", urlencode(state)));
    }
    if !kind.is_empty() {
        parts.push(format!("kind={}", urlencode(kind)));
    }
    if !q.is_empty() {
        parts.push(format!("q={}", urlencode(q)));
    }
    if parts.is_empty() {
        "/jobs".into()
    } else {
        format!("/jobs?{}", parts.join("&"))
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b' ' => "+".to_string(),
            b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b if b.is_ascii_alphanumeric() => (b as char).to_string(),
            b => format!("%{:02X}", b),
        })
        .collect()
}

/// Headline for the list. Failures in the last day outrank anything running:
/// a running job needs nothing from the operator, a failed one might.
fn verdict(jobs: &[hyperion_types::JobView], now: i64) -> (String, &'static str) {
    let running = jobs.iter().filter(|j| j.state == "running").count();
    let failed_24h = jobs
        .iter()
        .filter(|j| j.state == "failed" && now - j.finished_at.unwrap_or(j.updated_at) < 86_400)
        .count();
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    if failed_24h > 0 {
        let mut s = format!(
            "{} in the last 24 hours",
            plural(failed_24h, "job failed", "jobs failed")
        );
        if running > 0 {
            s.push_str(&format!(" · {} running", running));
        }
        (s, "err")
    } else if running > 0 {
        (
            format!("{} now", plural(running, "job running", "jobs running")),
            "warn",
        )
    } else if let Some(last) = jobs.iter().filter_map(|j| j.finished_at).max() {
        (
            format!(
                "Nothing running · last job finished {}",
                crate::handlers::stats::fmt_ago(&last)
            ),
            "ok",
        )
    } else {
        ("Nothing running".into(), "ok")
    }
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
    /// Human name of the job kind ("Move hosting").
    title: String,
    /// Whether `/jobs/<id>/retry` can replay this kind.
    retryable: bool,
    started_ago: String,
    started_abs: String,
}

#[derive(Template)]
#[template(path = "_job_progress.html")]
struct JobProgressFragment {
    job: hyperion_types::JobView,
    elapsed: String,
    is_running: bool,
    title: String,
    retryable: bool,
}

#[derive(Deserialize, Default)]
pub struct JobsListQuery {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub q: String,
}

/// Sidebar-badge endpoint. Returns `{"count": N}` for jobs in
/// state=`running`. Polled every 10s from `base.html` so the
/// operator sees the badge appear seconds after kicking off a
/// migration. Empty array is fine — the JS hides the badge then.
/// GET /api/nav-status — the counts the sidebar paints its status dots from.
///
/// One request for all of them: three separate pollers would triple the
/// traffic for numbers that are read at a glance, and would let the dots
/// disagree with each other mid-refresh.
///
/// Every failure answers zero rather than erroring. A sidebar dot is an
/// at-a-glance hint, and a hint that turns a page red because one RPC hiccuped
/// is worse than one that briefly says nothing.
pub async fn get_nav_status(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let zero = serde_json::json!({"monitors_down": 0, "wp_outdated": 0, "certs_expiring": 0});
    if !ctx.is_admin_or_higher() {
        return Ok(axum::Json(zero).into_response());
    }
    let (mon, vuln, certs) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::MonitorOverview),
        hyperion_rpc_client::call(&state.agent_socket, Request::VulnFindingsList),
        hyperion_rpc_client::call(&state.agent_socket, Request::CertOverview),
    );
    let monitors_down = match mon {
        Ok(RpcResponse::MonitorOverview(v)) => {
            v.iter().filter(|m| m.alert_state == "alerting").count()
        }
        _ => 0,
    };
    // Sites with at least one outdated component — not the total number of
    // findings. The badge answers "how many sites need me", and one site with
    // nine old plugins is still one site to open.
    let wp_outdated = match vuln {
        Ok(RpcResponse::VulnFindingsList(v)) => v.iter().filter(|s| !s.findings.is_empty()).count(),
        _ => 0,
    };
    let certs_expiring = match certs {
        Ok(RpcResponse::CertOverview(v)) => v
            .iter()
            .filter(|c| c.days_left < 14 && c.issuer.to_lowercase().contains("letsencrypt"))
            .count(),
        _ => 0,
    };
    Ok(axum::Json(serde_json::json!({
        "monitors_down": monitors_down,
        "wp_outdated": wp_outdated,
        "certs_expiring": certs_expiring,
    }))
    .into_response())
}

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

/// Feed for the global bottom progress-toast: every running job with its live
/// step + percent, so the operator always sees work in flight (import, backup,
/// cert issuance…) even after leaving the job page. Admins only; `[]` when idle.
pub async fn get_active_jobs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(axum::Json(serde_json::Value::Array(vec![])).into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::JobList {
            kind: None,
            state: Some("running".to_string()),
            limit: 50,
        },
    )
    .await?;
    let jobs = match resp {
        RpcResponse::JobList(v) => v,
        _ => Vec::new(),
    };
    let out: Vec<serde_json::Value> = jobs
        .into_iter()
        .map(|j| {
            serde_json::json!({
                "id": j.id,
                "label": job_kind_label(&j.kind),
                "kind": j.kind,
                "target": j.target,
                "step": j.step_label,
                "pct": j.progress_pct,
            })
        })
        .collect();
    Ok(axum::Json(serde_json::Value::Array(out)).into_response())
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
    let kind_filter = q.kind.trim().to_string();
    let state_filter = match q.state.trim() {
        s @ ("running" | "done" | "failed" | "cancelled") => s.to_string(),
        _ => String::new(),
    };
    let search = q.q.trim().to_string();
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::JobList {
            kind: None,
            state: None,
            limit: LIST_WINDOW,
        },
    )
    .await?;
    let mut jobs = match resp {
        RpcResponse::JobList(v) => v,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    humanize_targets(&state, &mut jobs).await;
    let now = hyperion_types::now_secs();
    let mut truncated = jobs.len() as i64 >= LIST_WINDOW;
    let window_empty = jobs.is_empty();
    let (verdict, verdict_tone) = verdict(&jobs, now);

    let mut kinds: Vec<(String, String)> = jobs
        .iter()
        .map(|j| j.kind.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|k| {
            let label = job_kind_label(&k);
            (k, label)
        })
        .collect();
    // A bookmarked filter for a kind that has rotated out keeps its option,
    // or the select would silently show "(all kinds)" while filtering.
    if !kind_filter.is_empty() && !kinds.iter().any(|(k, _)| *k == kind_filter) {
        kinds.push((kind_filter.clone(), job_kind_label(&kind_filter)));
    }
    kinds.sort_by(|a, b| a.1.cmp(&b.1));

    // Kind + search narrow everything; the state segments then count within
    // that, so "Failed 3" means three failed jobs of what you're looking at.
    let needle = search.to_lowercase();
    jobs.retain(|j| {
        (kind_filter.is_empty() || j.kind == kind_filter)
            && (needle.is_empty()
                || j.target
                    .as_deref()
                    .is_some_and(|t| t.to_lowercase().contains(&needle))
                || job_kind_label(&j.kind).to_lowercase().contains(&needle)
                || j.actor_label.to_lowercase().contains(&needle)
                || j.id.starts_with(&needle))
    });
    let mut counts = StateCounts {
        all: jobs.len(),
        ..Default::default()
    };
    for j in &jobs {
        match j.state.as_str() {
            "running" => counts.running += 1,
            "failed" => counts.failed += 1,
            "done" => counts.done += 1,
            "cancelled" => counts.cancelled += 1,
            _ => {}
        }
    }
    if !state_filter.is_empty() {
        jobs.retain(|j| j.state == state_filter);
    }
    truncated |= jobs.len() > LIST_SHOWN;
    jobs.truncate(LIST_SHOWN);

    let mut running = Vec::new();
    let mut days: Vec<DayGroup> = Vec::new();
    for j in jobs {
        if j.state == "running" {
            running.push(job_row(j));
            continue;
        }
        let label = day_label(j.started_at, now);
        let row = job_row(j);
        match days.last_mut() {
            Some(d) if d.label == label => d.rows.push(row),
            _ => days.push(DayGroup {
                label,
                rows: vec![row],
            }),
        }
    }
    let seg_hrefs = SegHrefs {
        all: jobs_href("", &kind_filter, &search),
        running: jobs_href("running", &kind_filter, &search),
        failed: jobs_href("failed", &kind_filter, &search),
        done: jobs_href("done", &kind_filter, &search),
        cancelled: jobs_href("cancelled", &kind_filter, &search),
    };
    let tpl = JobsListTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "jobs",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        refresh_secs: if counts.running > 0 || verdict_tone == "warn" {
            5
        } else {
            30
        },
        running,
        days,
        verdict,
        verdict_tone,
        counts,
        kinds,
        kind_filter,
        state_filter,
        q: search,
        seg_hrefs,
        truncated,
        window_empty,
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
    let mut job = match fetch_job(&state, &id).await? {
        Some(j) => j,
        None => {
            return Ok(axum::response::Redirect::to(
                "/jobs?flash_error=Job+id+not+found+(rotated+out%3F)",
            )
            .into_response());
        }
    };
    humanize_targets(&state, std::slice::from_mut(&mut job)).await;
    let is_running = !job.is_terminal();
    let elapsed = format_elapsed(&job);
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let title = job_kind_label(&job.kind);
    let retryable = RETRYABLE_KINDS.contains(&job.kind.as_str());
    let started_ago = crate::handlers::stats::fmt_ago(&job.started_at);
    let started_abs = fmt_local(job.started_at, "%Y-%m-%d %H:%M:%S");
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
        title,
        retryable,
        started_ago,
        started_abs,
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
    let mut job = match fetch_job(&state, &id).await? {
        Some(j) => j,
        None => {
            return Ok(
                Html("<div class=\"text-soft\">job no longer present</div>".to_string())
                    .into_response(),
            );
        }
    };
    humanize_targets(&state, std::slice::from_mut(&mut job)).await;
    let is_running = !job.is_terminal();
    let terminal = job.is_terminal();
    let elapsed = format_elapsed(&job);
    let frag = JobProgressFragment {
        title: job_kind_label(&job.kind),
        retryable: RETRYABLE_KINDS.contains(&job.kind.as_str()),
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

/// True for a hosting id (a UUID: 36 chars, hyphens at 8/13/18/23, hex
/// elsewhere). Domains always contain a dot; job labels never look like this.
fn looks_like_hosting_id(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// [`humanize_targets`] for a single subject, before it is stored.
async fn humanize_target(state: &SharedState, target: &mut Option<String>) {
    let mut probe = [hyperion_types::JobView {
        target: target.take(),
        ..Default::default()
    }];
    humanize_targets(state, &mut probe).await;
    *target = probe[0].target.take();
}

/// Show the hosting's domain instead of its id for jobs whose subject is
/// an id — rows written before `spawn_job` stored the domain. One cluster
/// listing for the whole batch, and none at all when no row needs it, so
/// the 2-second progress poll stays a single RPC for new jobs. A hosting
/// that has since been deleted keeps its id: nothing else names it.
async fn humanize_targets(state: &SharedState, jobs: &mut [hyperion_types::JobView]) {
    if !jobs
        .iter()
        .any(|j| j.target.as_deref().is_some_and(looks_like_hosting_id))
    {
        return;
    }
    let Ok(rows) = crate::handlers::hostings::list_hostings(state).await else {
        return;
    };
    for j in jobs.iter_mut() {
        if let Some(h) = j
            .target
            .as_deref()
            .and_then(|t| rows.iter().find(|h| h.id.as_str() == t))
        {
            j.target = Some(h.domain.clone());
        }
    }
}

/// Render "1m 47s" or similar. Caps at hours since no current job
/// is expected to take days; if it does, "h m s" is still readable.
fn format_elapsed(j: &hyperion_types::JobView) -> String {
    // A running job's clock is "now", not its last progress tick — a step
    // that sits quiet for a minute must not freeze the elapsed counter.
    let end = match j.finished_at {
        Some(t) => t,
        None if j.state == "running" => hyperion_types::now_secs(),
        None => j.updated_at,
    };
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

    /// Replace the job's sub-step list — the named subjobs the progress page
    /// renders. Best-effort: a failed mirror just means the card shows slightly
    /// stale sub-steps, never a failed job.
    pub async fn substeps(&self, subs: &[hyperion_types::JobSubstep]) {
        let json = match serde_json::to_string(subs) {
            Ok(j) => j,
            Err(_) => return,
        };
        let r = hyperion_rpc_client::call(
            &self.state.agent_socket,
            Request::JobSubsteps {
                id: self.id.clone(),
                substeps_json: json,
            },
        )
        .await;
        if let Err(e) = r {
            tracing::warn!(error=%e, id=%self.id, "job_substeps RPC failed");
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
    // Most per-hosting forms post the hosting's id as their selector, and
    // that id used to be stored as the job's subject — so the job pages
    // read "target 01a0f15b-…" where the operator expects "example.cz".
    // Store the domain instead. After a delete it is the only name left:
    // the id no longer resolves to anything.
    let mut target = target.map(String::from);
    humanize_target(&state, &mut target).await;
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::JobStart {
            kind: kind.to_string(),
            target,
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

#[cfg(test)]
mod tests {
    use super::looks_like_hosting_id;

    #[test]
    fn hosting_id_shape() {
        assert!(looks_like_hosting_id(
            "01a0f15b-b22e-750c-b871-6b348ee5ad1c"
        ));
        assert!(!looks_like_hosting_id("example.cz"));
        assert!(!looks_like_hosting_id("3 hostings"));
        assert!(!looks_like_hosting_id(
            "01a0f15b-b22e-750c-b871-6b348ee5ad1"
        ));
        assert!(!looks_like_hosting_id(
            "01a0f15bxb22e-750c-b871-6b348ee5ad1c"
        ));
    }
}
