//! WordPress integrity scan card.

use super::*;

/// Lazily-loaded file-integrity + malware panel — the tamper-detection
/// sibling of the vuln panel. Dispatched to the OWNING node: wp-cli's
/// checksum comparison and clamscan both have to read the site's files.
#[derive(Template)]
#[template(path = "_hosting_integrity_card.html")]
pub(super) struct IntegrityCardTpl {
    pub(super) scan: hyperion_types::WpIntegrityScanResult,
    pub(super) selector: String,
    pub(super) csrf_token: String,
}

/// A result meaning "nothing was checked", carrying why.
///
/// `Default` leaves `wp_cli_ok` and `clamav_available` false, which is
/// exactly what keeps `is_clean()` false — a hosting we couldn't reach
/// must render as "couldn't check", never as a pass. Same contract the
/// vuln panel gets from `feed_unavailable`.
pub(super) fn integrity_not_checked(why: String) -> hyperion_types::WpIntegrityScanResult {
    hyperion_types::WpIntegrityScanResult {
        error: Some(why),
        ..Default::default()
    }
}

/// Run the scan on the owning node, folding every failure mode into a
/// renderable "couldn't check" result rather than a 500 — a blank corner
/// of the page reads as "fine" to an operator, which is the one thing
/// this card must never imply.
pub(super) async fn integrity_scan_on_node(
    state: &SharedState,
    owner_node: Option<&str>,
    sel: HostingSelector,
) -> hyperion_types::WpIntegrityScanResult {
    match crate::dispatcher::dispatch_to_node(
        state,
        owner_node,
        Request::WpIntegrityScan { hosting: sel },
    )
    .await
    {
        Ok(RpcResponse::WpIntegrityScan(scan)) => scan,
        Ok(RpcResponse::Error(e)) => integrity_not_checked(e.to_string()),
        Ok(_) => integrity_not_checked("unexpected response from the node".into()),
        Err(e) => integrity_not_checked(e.to_string()),
    }
}

pub async fn get_integrity_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::WpVulnView,
    )
    .await
    {
        return Ok(r);
    }
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let scan = integrity_scan_on_node(&state, owner_node.as_deref(), sel).await;
    Ok(Html(
        IntegrityCardTpl {
            scan,
            selector,
            csrf_token,
        }
        .render()?,
    )
    .into_response())
}

#[derive(Deserialize)]
pub struct IntegrityScanForm {
    pub selector: String,
}

/// "Scan now". A POST rather than a repeat of the lazy GET because it
/// isn't a refresh: it re-hashes every core and plugin file against
/// WordPress.org and can walk the whole docroot with clamscan. Gated on
/// `WpManage` for the same reason — reading the verdict is a view,
/// spending the node's IO is not.
pub async fn post_integrity_scan(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityScanForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    // Resolve the owner EXPLICITLY: `.ok()`-to-None would retarget a
    // lookup failure at the master, which would then verify checksums for
    // files that aren't there and report the miss as a finding.
    let scan = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((_detail, owner_node)) => {
            integrity_scan_on_node(&state, owner_node.as_deref(), sel).await
        }
        Err(e) => integrity_not_checked(e.to_string()),
    };
    Ok(Html(
        IntegrityCardTpl {
            scan,
            selector: form.selector,
            csrf_token,
        }
        .render()?,
    )
    .into_response())
}
