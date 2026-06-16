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

#[derive(Template)]
#[template(path = "vulns.html")]
struct VulnsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    rows: Vec<hyperion_types::HostingVulnSummary>,
    critical: usize,
    high: usize,
    sites: usize,
}

pub async fn get_vulns(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
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
        for n in nodes {
            if let Ok(RpcResponse::VulnFindingsList(items)) = crate::dispatcher::dispatch_to_node(
                &state,
                Some(n.node_id.as_str()),
                Request::VulnFindingsList,
            )
            .await
            {
                for mut it in items {
                    it.node_id = n.label.clone();
                    all.push(it);
                }
            }
        }
    }
    // Worst (most criticals) first.
    all.sort_by(|a, b| {
        b.count_severity("critical")
            .cmp(&a.count_severity("critical"))
            .then(b.findings.len().cmp(&a.findings.len()))
    });

    let critical: usize = all.iter().map(|s| s.count_severity("critical")).sum();
    let high: usize = all.iter().map(|s| s.count_severity("high")).sum();
    let sites = all.len();

    let tpl = VulnsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "vulns",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows: all,
        critical,
        high,
        sites,
    };
    Ok(Html(tpl.render()?).into_response())
}
