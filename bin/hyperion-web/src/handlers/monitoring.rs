//! /monitoring — cluster-wide list of every hosting with monitor
//! enabled, showing alert state, 24h success rate, avg latency,
//! and the node the hosting lives on. Fans out MonitorOverview
//! to the master + every enrolled worker and merges the rows.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::MonitorOverviewItem;

#[derive(Template)]
#[template(path = "monitoring.html")]
struct MonitoringTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    items: Vec<MonitorOverviewItem>,
    alerting_count: usize,
    healthy_count: usize,
    unknown_count: usize,
}

pub async fn get_monitoring(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Cluster-wide overview: it fans out across every node and lists EVERY
    // tenant's hostings (domain, node, health). The rows are not filtered by
    // per-hosting access, so a tenant-scoped role (operator/customer/viewer)
    // would enumerate other tenants' inventory here. Restrict to admin+;
    // tenant-scoped users still get per-hosting monitoring on each detail page.
    if !(ctx.can(Capability::MonitoringView) && ctx.scope_all()) {
        return Ok(axum::response::Redirect::to("/").into_response());
    }

    let mut items: Vec<MonitorOverviewItem> = Vec::new();

    // Master local.
    if let Ok(RpcResponse::MonitorOverview(rows)) =
        crate::dispatcher::dispatch_to_node(&state, None, Request::MonitorOverview).await
    {
        let mut rows = rows;
        for r in &mut rows {
            // Rows from the master local socket are local regardless of
            // the node_id they stored — master rows stamp the hostname
            // (e.g. "s4"), not empty. Tag them all with the LOCAL
            // sentinel unconditionally (the old is_empty() guard left
            // "s4" in place, which becomes the 400 "node s4 is not
            // enrolled" the moment a monitor action form reuses it).
            r.node_id = crate::dispatcher::LOCAL_NODE_SENTINEL.to_string();
        }
        items.extend(rows);
    }

    // Every enrolled worker.
    let workers = crate::handlers::hostings::fetch_remote_nodes(&state)
        .await
        .unwrap_or_default();
    for n in workers {
        if let Ok(RpcResponse::MonitorOverview(rows)) =
            crate::dispatcher::dispatch_to_node(&state, Some(&n.node_id), Request::MonitorOverview)
                .await
        {
            let mut rows = rows;
            for r in &mut rows {
                r.node_id = n.node_id.clone();
            }
            items.extend(rows);
        }
    }

    // Resort the merged list — agents already sort their own slice,
    // but the merge needs to re-apply the alerting-first rule globally.
    items.sort_by(|a, b| {
        let alert_rank = |s: &str| match s {
            "alerting" => 0,
            "unknown" => 1,
            _ => 2,
        };
        let ra = alert_rank(a.alert_state.as_str());
        let rb = alert_rank(b.alert_state.as_str());
        ra.cmp(&rb)
            .then(a.success_pct_24h.cmp(&b.success_pct_24h))
            .then(a.domain.cmp(&b.domain))
    });

    let alerting_count = items.iter().filter(|i| i.alert_state == "alerting").count();
    let unknown_count = items.iter().filter(|i| i.alert_state == "unknown").count();
    let healthy_count = items.len() - alerting_count - unknown_count;

    let tpl = MonitoringTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "monitoring",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        items,
        alerting_count,
        healthy_count,
        unknown_count,
    };
    Ok(Html(tpl.render()?).into_response())
}
