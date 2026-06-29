//! /certs — cluster-wide certificate overview.
//!
//! Fans out CertOverview RPC across the master + every enrolled
//! node so the operator sees every cert on every node in one
//! sorted-by-expiry table. Without this view, "what's expiring in
//! the next 30 days?" required walking every hosting one at a
//! time.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::HostingSelector;
use hyperion_state::capabilities::Capability;
use hyperion_validate::Domain;
use serde::Deserialize;

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[derive(Template)]
#[template(path = "certs.html")]
struct CertsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    rows: Vec<hyperion_types::CertOverviewItem>,
    /// Aggregate counts for the summary card at the top.
    expired: usize,
    critical: usize,
    warning: usize,
    ok: usize,
    /// Master-hosted sites still on a bootstrap self-signed cert — drives the
    /// "Issue all via Cloudflare DNS" bulk button (hidden when zero).
    self_signed: usize,
    /// Flash banner state (set after redirect from /certs/renew-all).
    flash: Option<String>,
    flash_error: Option<String>,
    csrf_token: String,
}

#[derive(Deserialize, Default)]
pub struct CertsQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_error: Option<String>,
}

pub async fn get_certs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<CertsQuery>,
) -> Result<Response, AppError> {
    // Cluster-wide cert page: tenant roles also hold CertManage (for their own
    // hostings' certs), so require all-hostings scope to reach the cluster view.
    if !(ctx.can(Capability::CertManage) && ctx.scope_all()) {
        return Ok(
            axum::response::Redirect::to("/?flash_error=admin+role+required").into_response(),
        );
    }
    // Collect from master + every enrolled node. A worker that's
    // offline / rejects RPC contributes nothing — best-effort,
    // the page still renders.
    let mut all: Vec<hyperion_types::CertOverviewItem> = Vec::new();
    // Local agent first.
    if let Ok(RpcResponse::CertOverview(items)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::CertOverview).await
    {
        all.extend(items);
    }
    // Remote workers.
    if let Ok(RpcResponse::NodesList(nodes)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        for (n, resp) in crate::dispatcher::fan_out(&state, nodes, Request::CertOverview).await {
            if let RpcResponse::CertOverview(mut items) = resp {
                for item in items.iter_mut() {
                    item.node_id = n.label.clone();
                }
                all.extend(items);
            }
        }
    }
    // Already sorted ASC at agent level, but inter-node merge may
    // have produced an out-of-order interleave. Re-sort.
    all.sort_by_key(|i| i.not_after);

    let mut expired = 0;
    let mut critical = 0;
    let mut warning = 0;
    let mut ok = 0;
    for r in &all {
        match r.band.as_str() {
            "expired" => expired += 1,
            "critical" => critical += 1,
            "warning" => warning += 1,
            _ => ok += 1,
        }
    }
    // Master-hosted bootstrap certs we can bulk-issue via Cloudflare DNS-01.
    let self_signed = all
        .iter()
        .filter(|i| i.issuer == "self-signed" && i.node_id.is_empty())
        .count();

    let tpl = CertsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "certs",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows: all,
        expired,
        critical,
        warning,
        ok,
        self_signed,
        flash: q.flash.filter(|s| !s.is_empty()),
        flash_error: q.flash_error.filter(|s| !s.is_empty()),
        csrf_token: super::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

/// POST /certs/renew-all — sweep every node and run CertRenewAll.
/// The agent's renew logic only attempts certs within the renewal
/// window (default <30 days to expiry) and skips the rest, so this
/// is safe to mash whenever the operator wants to force a sweep
/// outside the scheduler's regular tick.
///
/// Fans out: master first, then every enrolled node. A node that's
/// offline / rejects RPC contributes a zero result — best-effort,
/// the flash message reports per-node totals.
pub async fn post_renew_all(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Cluster-wide cert page: tenant roles also hold CertManage (for their own
    // hostings' certs), so require all-hostings scope to reach the cluster view.
    if !(ctx.can(Capability::CertManage) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let mut total_renewed = 0u32;
    let mut total_skipped = 0u32;
    let mut total_failed = 0u32;
    let mut nodes_hit = 0u32;
    let mut nodes_failed = 0u32;
    // Master.
    nodes_hit += 1;
    match hyperion_rpc_client::call(&state.agent_socket, Request::CertRenewAll).await {
        Ok(RpcResponse::CertRenewAll(results)) => {
            for r in &results {
                match r.outcome {
                    hyperion_types::CertRenewOutcome::Renewed { .. } => total_renewed += 1,
                    hyperion_types::CertRenewOutcome::Skipped { .. } => total_skipped += 1,
                    hyperion_types::CertRenewOutcome::Failed { .. } => total_failed += 1,
                }
            }
        }
        _ => nodes_failed += 1,
    }
    // Workers.
    if let Ok(RpcResponse::NodesList(nodes)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        for n in nodes {
            nodes_hit += 1;
            match crate::dispatcher::dispatch_to_node(
                &state,
                Some(n.node_id.as_str()),
                Request::CertRenewAll,
            )
            .await
            {
                Ok(RpcResponse::CertRenewAll(results)) => {
                    for r in &results {
                        match r.outcome {
                            hyperion_types::CertRenewOutcome::Renewed { .. } => total_renewed += 1,
                            hyperion_types::CertRenewOutcome::Skipped { .. } => total_skipped += 1,
                            hyperion_types::CertRenewOutcome::Failed { .. } => total_failed += 1,
                        }
                    }
                }
                _ => nodes_failed += 1,
            }
        }
    }
    let msg = format!(
        "Cert renew sweep: {total_renewed} renewed, {total_skipped} skipped (still healthy), {total_failed} failed across {nodes_hit} nodes ({nodes_failed} unreachable)."
    );
    let key = if total_failed > 0 || nodes_failed > 0 {
        "flash_error"
    } else {
        "flash"
    };
    Ok(Redirect::to(&format!("/certs?{key}={}", urlencode(&msg))).into_response())
}

/// POST /certs/issue-all-cloudflare — background job that issues a real Let's
/// Encrypt cert via Cloudflare DNS-01 for every master-hosted site still on a
/// bootstrap self-signed cert. DNS-01 validates over DNS, so it works behind the
/// CloudFlare proxy (where HTTP-01 can't reach the origin). Each site issues
/// sequentially (~25s), so this runs detached and the operator watches the job.
///
/// Worker-hosted sites are left alone for now (issue them per-site from the
/// site's SSL tab); the job log notes this if any are skipped.
pub async fn post_issue_all_cloudflare(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !(ctx.can(Capability::CertManage) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "cert-issue-cloudflare",
        None,
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_issue_all_cf_job(reporter, job_state).await;
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

async fn run_issue_all_cf_job(reporter: crate::handlers::jobs::JobReporter, state: SharedState) {
    reporter.step("Checking the Cloudflare token…", 2, "").await;
    match hyperion_rpc_client::call(&state.agent_socket, Request::CloudflareTokenStatus).await {
        Ok(RpcResponse::CloudflareToken(i)) if i.valid == Some(true) => {}
        Ok(RpcResponse::CloudflareToken(i)) => {
            reporter
                .finish(
                    false,
                    Some(format!(
                        "Cloudflare token not usable ({}). Set it in Settings → Cloudflare certs first.",
                        i.message
                    )),
                )
                .await;
            return;
        }
        _ => {
            reporter
                .finish(false, Some("Could not check the Cloudflare token.".into()))
                .await;
            return;
        }
    }
    reporter
        .step("Listing sites still on a self-signed cert…", 5, "")
        .await;
    let items = match hyperion_rpc_client::call(&state.agent_socket, Request::CertOverview).await {
        Ok(RpcResponse::CertOverview(v)) => v,
        _ => {
            reporter
                .finish(false, Some("Could not list certificates.".into()))
                .await;
            return;
        }
    };
    // Master-hosted (node_id empty), still self-signed.
    let targets: Vec<String> = items
        .into_iter()
        .filter(|i| i.issuer == "self-signed" && i.node_id.is_empty())
        .map(|i| i.domain)
        .collect();
    if targets.is_empty() {
        reporter
            .step(
                "No master-hosted sites on a self-signed cert — nothing to do.",
                100,
                "",
            )
            .await;
        reporter.finish(true, None).await;
        return;
    }
    let total = targets.len();
    let mut ok = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for (idx, domain) in targets.iter().enumerate() {
        let pct = 5 + ((idx * 90) / total) as i64;
        reporter
            .step(
                &format!("[{}/{total}] Issuing {domain} via Cloudflare DNS…", idx + 1),
                pct,
                "",
            )
            .await;
        let sel = match Domain::parse(domain) {
            Ok(d) => HostingSelector::Domain(d),
            Err(e) => {
                failed.push(format!("{domain}: {e}"));
                continue;
            }
        };
        match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::CertDns01Begin {
                sel,
                staging: false,
                provider: "cloudflare".into(),
            },
        )
        .await
        {
            Ok(RpcResponse::CertDns01Begin {
                completed: true, ..
            }) => {
                ok += 1;
                reporter
                    .step(&format!("✓ {domain}"), pct, &format!("issued {domain}\n"))
                    .await;
            }
            Ok(RpcResponse::CertDns01Begin {
                completed: false, ..
            }) => {
                failed.push(format!("{domain}: DNS-01 did not complete"));
            }
            Ok(RpcResponse::Error(e)) => failed.push(format!("{domain}: {e}")),
            Ok(_) => failed.push(format!("{domain}: unexpected response")),
            Err(e) => failed.push(format!("{domain}: {e}")),
        }
    }
    let mut summary = format!("Issued {ok}/{total} certs via Cloudflare DNS.");
    if !failed.is_empty() {
        summary.push_str(&format!(" {} failed:\n{}", failed.len(), failed.join("\n")));
    }
    reporter.step(&summary, 100, &summary).await;
    reporter
        .finish(
            failed.is_empty(),
            (!failed.is_empty()).then(|| format!("{} site(s) failed — see log", failed.len())),
        )
        .await;
}
