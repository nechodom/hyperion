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
use hyperion_types::care_check::{CareNextReport, CareOverviewRow, CareReportHold};

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
    /// The countdown to the report e-mail. `None` = this site's plans send no
    /// report, or its node predates the field.
    pub report: Option<ReportCountdown>,
}

pub struct ReportCountdown {
    pub text: String,
    /// The exact date, for the hover.
    pub title: String,
    /// Pill tone: `muted` for plenty of time, `warn` for little,
    /// `err` for a report that will not leave.
    pub tone: &'static str,
}

/// With this little left, the countdown stops being background information.
const REPORT_SOON_SECS: i64 = 3 * 86_400;

fn report_countdown(next: &CareNextReport, now: i64) -> ReportCountdown {
    let date = chrono::DateTime::from_timestamp(next.at, 0)
        .map(|d| d.format("%-d %b %Y, %H:%M UTC").to_string())
        .unwrap_or_else(|| "unknown date".into());
    if let Some(hold) = next.hold {
        let (text, why) = match hold {
            CareReportHold::NoRecipient => (
                "e-mail: no recipient",
                "Set a care report e-mail on the site's care plan",
            ),
            CareReportHold::NoRelay => (
                "e-mail: no SMTP relay",
                "The node that owns this site has no SMTP relay configured",
            ),
            CareReportHold::SiteNotActive => (
                "e-mail: site not active",
                "No report leaves while the site is suspended or in the trash",
            ),
        };
        return ReportCountdown {
            text: text.into(),
            title: format!("{why}. Scheduled for {date}; it stays due until this is fixed."),
            tone: "err",
        };
    }
    let left = next.at - now;
    let text = if left <= 0 {
        "e-mail within the hour".to_string()
    } else if left < 3_600 {
        format!("e-mail in {} min", (left / 60).max(1))
    } else if left < 48 * 3_600 {
        format!("e-mail in {} h", left / 3_600)
    } else {
        format!("e-mail in {} days", left / 86_400)
    };
    ReportCountdown {
        text,
        title: format!("Care report to the customer: {date}"),
        tone: if left < REPORT_SOON_SECS {
            "warn"
        } else {
            "muted"
        },
    }
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
    let (rows, unreachable) = collect_overview(&state, &ctx, &period).await;
    let total = rows.len();
    let complete = rows.iter().filter(|r| r.is_complete()).count();

    let tpl = CarePanelTpl {
        period_label: month_label(&period),
        total,
        complete,
        unreachable,
        rows: rows
            .into_iter()
            .map(|r| CareRow {
                report: r.next_report.as_ref().map(|n| report_countdown(n, now)),
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

/// Every site on a care plan across the cluster, for `period`, plus the
/// names of nodes that did not answer. Shared by the dashboard work list and
/// the care packages page, so the two cannot count differently.
///
/// Rows come back work-first, then alphabetical; tenant-scoped sessions see
/// only their own sites and never a node name.
pub(crate) async fn collect_overview(
    state: &SharedState,
    ctx: &AuthCtx,
    period: &str,
) -> (Vec<CareOverviewRow>, Vec<String>) {
    let req = Request::CareOverview {
        period: period.to_string(),
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

    let nodes: Vec<hyperion_types::NodeSummary> = match crate::dispatcher::cached_nodes(state)
        .await
        .map(hyperion_rpc::codec::Response::NodesList)
    {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(),
    };
    if !nodes.is_empty() {
        let (answered, failed) = crate::dispatcher::fan_out_reporting(state, nodes, req).await;
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
                state,
                ctx,
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
        // them leaks the cluster's shape — but the FACT that the list is
        // incomplete is theirs to know. Clearing it outright turned "we
        // could not ask the node holding your sites" into "everything is
        // checked", which is the one direction this card must never fail in.
        if !unreachable.is_empty() {
            unreachable = vec!["a server that could not be reached".to_string()];
        }
    }

    // Same order every node's answer already used, re-applied across the
    // merged list.
    rows.sort_by(CareOverviewRow::work_order);
    unreachable.sort();
    unreachable.dedup();
    (rows, unreachable)
}

pub(crate) fn node_label(n: &hyperion_types::NodeSummary) -> String {
    if n.label.trim().is_empty() {
        n.node_id.clone()
    } else {
        n.label.clone()
    }
}

/// `"2026-09"` → `"September 2026"`.
pub(crate) fn month_label(period: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_793_750_400;

    fn countdown(left: i64) -> ReportCountdown {
        report_countdown(
            &CareNextReport {
                at: NOW + left,
                hold: None,
            },
            NOW,
        )
    }

    #[test]
    fn the_countdown_reads_in_the_largest_unit_that_still_helps() {
        assert_eq!(countdown(12 * 86_400).text, "e-mail in 12 days");
        assert_eq!(countdown(2 * 86_400).text, "e-mail in 2 days");
        assert_eq!(countdown(47 * 3_600).text, "e-mail in 47 h");
        assert_eq!(countdown(30).text, "e-mail in 1 min");
        // Due is not late: the hourly tick has not come round yet.
        assert_eq!(countdown(0).text, "e-mail within the hour");
        assert_eq!(countdown(-5 * 3_600).text, "e-mail within the hour");
    }

    #[test]
    fn little_time_left_is_a_warning() {
        assert_eq!(countdown(4 * 86_400).tone, "muted");
        assert_eq!(countdown(2 * 86_400).tone, "warn");
        assert_eq!(countdown(-60).tone, "warn");
    }

    /// A held report must not read as a time: nothing leaves at that time.
    #[test]
    fn a_held_report_says_why_instead_of_counting_down() {
        let held = report_countdown(
            &CareNextReport {
                at: NOW + 5 * 86_400,
                hold: Some(CareReportHold::NoRecipient),
            },
            NOW,
        );
        assert_eq!(held.text, "e-mail: no recipient");
        assert_eq!(held.tone, "err");
    }
}
