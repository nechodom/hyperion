//! Traffic by country card.

use super::*;

#[derive(Template)]
#[template(path = "_hosting_traffic_card.html")]
pub(super) struct TrafficCardTpl {
    pub(super) rows: Vec<hyperion_types::CountryTraffic>,
    pub(super) hours: i64,
    pub(super) error: Option<String>,
}

/// GET /hostings/:selector/traffic-panel — requests by country.
///
/// Lazy, like the other expensive cards: it parses the site's whole access
/// log, which is not something the detail page should wait on.
///
/// Every failure renders the card WITH the reason rather than a status
/// code — the placeholder it replaces is a spinner, and HTMX does not swap
/// on a non-2xx, so an error status would leave that spinner turning
/// forever.
pub async fn get_traffic_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<TrafficPanelQuery>,
) -> Result<Response, AppError> {
    let hours = q.hours.unwrap_or(24).clamp(1, 720);
    let card = |rows: Vec<hyperion_types::CountryTraffic>, error: Option<String>| {
        Html(
            TrafficCardTpl { rows, hours, error }
                .render()
                .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return Ok(card(
                vec![],
                Some(format!("could not read the selector: {e}")),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(card(
                vec![],
                Some(format!("could not look up this site: {e}")),
            ))
        }
    };
    if require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    .is_err()
    {
        return Ok(card(vec![], Some("not permitted".into())));
    }
    // The access log lives on the OWNING node, so the parse has to happen
    // there — shipping the log to the master would move gigabytes to answer
    // a page load.
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingCountryTraffic { sel, hours },
    )
    .await
    {
        Ok(RpcResponse::HostingCountryTraffic(rows)) => Ok(card(rows, None)),
        Ok(RpcResponse::Error(e)) => Ok(card(vec![], Some(e.to_string()))),
        Ok(_) => Ok(card(
            vec![],
            Some("unexpected response from the node".into()),
        )),
        Err(e) => Ok(card(vec![], Some(e.to_string()))),
    }
}

#[derive(serde::Deserialize)]
pub struct TrafficPanelQuery {
    pub hours: Option<i64>,
}
