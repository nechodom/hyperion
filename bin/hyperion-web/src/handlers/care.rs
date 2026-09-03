//! The care overview: which sites are on a plan, and whether this month's
//! human check has actually been done.
//!
//! Everything else a care plan sells proves itself — a backup either ran or
//! it did not. The four items on the monthly checklist do not: they need a
//! person to look, and the only evidence they happened is that somebody said
//! so. A plan that promises them and records nothing is selling something
//! nobody delivers, and the first person to find out is the customer.
//!
//! So the dashboard carries a work list. Sites with something outstanding
//! sort to the top, and a month that closed unfinished is called out even
//! though it can no longer be fixed — that is exactly the state worth
//! learning about from your own panel rather than from an e-mail.

use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::care_check::CareOverviewRow;

use hyperion_state::capabilities::Capability;

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;

#[derive(Template)]
#[template(path = "_care_panel.html")]
pub struct CarePanelTpl {
    /// `"September 2026"` — the month the ticks below belong to.
    pub period_label: String,
    pub rows: Vec<CareRow>,
    /// Sites on a plan, and how many of them are fully checked this month.
    pub total: usize,
    pub complete: usize,
    /// Names of nodes whose sites are MISSING from the list. Rendered as a
    /// warning, because "no sites need attention" and "we could not ask the
    /// node that has them" must not look the same.
    pub unreachable: Vec<String>,
}

pub struct CareRow {
    pub hosting_id: String,
    pub domain: String,
    pub packages: String,
    pub done: usize,
    pub total: usize,
    pub outstanding: String,
    pub prev_outstanding: usize,
    pub complete: bool,
}

/// GET /dashboard/care-panel — lazily swapped into the dashboard.
///
/// Lazy because it asks every node: the activations and the checklist are
/// both co-located with the hosting, so this is one round-trip per node and
/// must not hold the dashboard behind the slowest one.
pub async fn get_care_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let now = hyperion_types::now_secs();
    let period = hyperion_types::care_check::period_key(now);
    let req = Request::CareOverview {
        period: period.clone(),
    };

    let mut rows: Vec<CareOverviewRow> = Vec::new();
    let mut unreachable: Vec<String> = Vec::new();

    // The master's own sites first — it is a node like any other for this
    // purpose, and on a single-server install it is the only one.
    match hyperion_rpc_client::call(&state.agent_socket, req.clone()).await {
        Ok(RpcResponse::CareOverview(v)) => rows.extend(v),
        // An older agent does not know the request. Say so rather than
        // rendering an empty card that reads as "nothing to do".
        _ => unreachable.push("this server".to_string()),
    }

    let nodes: Vec<hyperion_types::NodeSummary> =
        match hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await {
            Ok(RpcResponse::NodesList(v)) => v,
            _ => Vec::new(),
        };
    if !nodes.is_empty() {
        let (answered, failed) = crate::dispatcher::fan_out_reporting(&state, nodes, req).await;
        for (node, resp) in answered {
            match resp {
                RpcResponse::CareOverview(v) => rows.extend(v),
                _ => unreachable.push(node_label(&node)),
            }
        }
        for (node, _) in failed {
            unreachable.push(node_label(&node));
        }
    }

    // Tenant-scoped sessions see only their own sites. The care list is a
    // cluster-wide work list for the operator; a customer must not read it
    // as one.
    if ctx.is_tenant_scoped() {
        let mut kept: Vec<CareOverviewRow> = Vec::new();
        for r in rows {
            if crate::handlers::hostings::require_hosting_access(
                &state,
                &ctx,
                &r.hosting_id,
                false,
                Capability::HostingView,
            )
            .await
            .is_ok()
            {
                kept.push(r);
            }
        }
        rows = kept;
        // A tenant cannot act on another node's outage, and naming nodes to
        // them leaks the cluster's shape.
        unreachable.clear();
    }

    // Same order every node's answer already used, re-applied across the
    // merged list: work first, then alphabetical.
    rows.sort_by(|a, b| {
        b.outstanding
            .len()
            .cmp(&a.outstanding.len())
            .then_with(|| a.domain.cmp(&b.domain))
    });
    let total = rows.len();
    let complete = rows.iter().filter(|r| r.is_complete()).count();
    unreachable.sort();
    unreachable.dedup();

    let tpl = CarePanelTpl {
        period_label: month_label(&period),
        total,
        complete,
        unreachable,
        rows: rows
            .into_iter()
            .map(|r| CareRow {
                complete: r.is_complete(),
                outstanding: r.outstanding.join(", "),
                packages: r.packages.join(", "),
                done: r.checks_done,
                total: r.checks_total,
                prev_outstanding: r.prev_outstanding,
                hosting_id: r.hosting_id,
                domain: r.domain,
            })
            .collect(),
    };
    Ok(Html(tpl.render()?).into_response())
}

fn node_label(n: &hyperion_types::NodeSummary) -> String {
    if n.label.trim().is_empty() {
        n.node_id.clone()
    } else {
        n.label.clone()
    }
}

/// `"2026-09"` → `"September 2026"`.
fn month_label(period: &str) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let Some((y, m)) = period.split_once('-') else {
        return period.to_string();
    };
    match m.parse::<usize>() {
        Ok(n) if (1..=12).contains(&n) => format!("{} {y}", MONTHS[n - 1]),
        _ => period.to_string(),
    }
}
