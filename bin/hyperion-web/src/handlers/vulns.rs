//! /vulns — cluster-wide WordPress vulnerability dashboard.
//!
//! Fans `VulnFindingsList` out across the master + every enrolled node
//! and shows, in one severity-sorted table, every site that has a known
//! plugin/theme vulnerability from the last daily Wordfence scan. The
//! scan + storage happen in the agent's `wp_vuln_scan_tick`; this page
//! only reads the stored results, so it's cheap to render.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;

#[derive(Template)]
#[template(path = "vulns.html")]
struct VulnsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    rows: Vec<hyperion_types::HostingVulnSummary>,
    /// Total major updates available across the fleet (manual review).
    major: usize,
    /// Total outdated components (any severity) across the fleet.
    outdated: usize,
    sites: usize,
}

pub async fn get_vulns(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Cluster-wide WP-vuln overview: tenant roles hold WpVulnView for their own
    // sites, so require all-hostings scope for the cross-cluster view.
    if !(ctx.can(Capability::WpVulnView) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let mut all: Vec<hyperion_types::HostingVulnSummary> = Vec::new();
    // Master.
    if let Ok(RpcResponse::VulnFindingsList(items)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::VulnFindingsList).await
    {
        for mut it in items {
            it.node_id = "master".into();
            all.push(it);
        }
    }
    // Workers.
    if let Ok(RpcResponse::NodesList(nodes)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        for (n, resp) in crate::dispatcher::fan_out(&state, nodes, Request::VulnFindingsList).await
        {
            if let RpcResponse::VulnFindingsList(items) = resp {
                for mut it in items {
                    it.node_id = n.label.clone();
                    all.push(it);
                }
            }
        }
    }
    // Most major (high-severity) updates first, then most outdated.
    all.sort_by(|a, b| {
        b.count_severity("high")
            .cmp(&a.count_severity("high"))
            .then(b.findings.len().cmp(&a.findings.len()))
    });

    let major: usize = all.iter().map(|s| s.count_severity("high")).sum();
    let outdated: usize = all.iter().map(|s| s.findings.len()).sum();
    let sites = all.len();

    let tpl = VulnsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "vulns",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows: all,
        major,
        outdated,
        sites,
    };
    Ok(Html(tpl.render()?).into_response())
}
