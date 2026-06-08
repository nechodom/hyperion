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
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};

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
}

pub async fn get_certs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(axum::response::Redirect::to("/?flash_error=admin+role+required").into_response());
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
        for n in nodes {
            if let Ok(RpcResponse::CertOverview(mut items)) =
                crate::dispatcher::dispatch_to_node(
                    &state,
                    Some(n.node_id.as_str()),
                    Request::CertOverview,
                )
                .await
            {
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
    };
    Ok(Html(tpl.render()?).into_response())
}
