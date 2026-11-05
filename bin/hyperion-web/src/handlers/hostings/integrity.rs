//! WordPress integrity scan card.

use super::*;

/// Lazily-loaded file-integrity + malware panel — the tamper-detection
/// sibling of the vuln panel. Dispatched to the OWNING node, where it reads
/// the last stored result; opening the page never starts a scan.
#[derive(Template)]
#[template(path = "_hosting_integrity_card.html")]
pub(super) struct IntegrityCardTpl {
    pub(super) scan: hyperion_types::WpIntegrityScanResult,
    pub(super) selector: String,
    pub(super) csrf_token: String,
    /// Outcome of a fix the operator just ran from this card, shown above
    /// the fresh scan. `(ok, text)`. Rendered inside the row because HTMX
    /// does not swap a non-2xx response — an error status would leave the
    /// operator watching a spinner.
    pub(super) notice: Option<(bool, String)>,
    /// When the pending scan was asked for (unix seconds); only read while
    /// `scan.scan_queued`. The polling card sends it back so the panel can
    /// tell whether the stored result is newer than the request.
    pub(super) queued_since: i64,
}

/// How long one page keeps polling for a scan it saw queued. The node says when
/// it's done; this is for a request nothing will ever answer, which would
/// otherwise poll for as long as the tab stays open.
const QUEUED_POLL_LIMIT_SECS: i64 = 2 * 3600;

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

/// The request that fills the card on page load. A read of the stored
/// result, never `WpIntegrityScan`: that one runs the scan worker and clamscan.
pub(super) fn integrity_panel_request(sel: HostingSelector) -> Request {
    Request::WpIntegrityStored { hosting: sel }
}

/// Phrase a node's refusal. A node from before `WpIntegrityStored` rejects
/// the request by name, which reads as gibberish to an operator.
pub(super) fn integrity_error_text(e: &str) -> String {
    if e.contains("unknown variant") {
        "this node needs updating to show scan results".into()
    } else {
        e.to_string()
    }
}

/// Read the stored scan from the owning node, folding every failure mode
/// into a renderable "couldn't check" result rather than a 500 — a blank
/// corner of the page reads as "fine" to an operator, which is the one
/// thing this card must never imply.
pub(super) async fn integrity_stored_on_node(
    state: &SharedState,
    owner_node: Option<&str>,
    sel: HostingSelector,
) -> hyperion_types::WpIntegrityScanResult {
    match crate::dispatcher::dispatch_to_node(state, owner_node, integrity_panel_request(sel)).await
    {
        Ok(RpcResponse::WpIntegrityScan(scan)) => scan,
        Ok(RpcResponse::Error(e)) => integrity_not_checked(integrity_error_text(&e.to_string())),
        Ok(_) => integrity_not_checked("unexpected response from the node".into()),
        Err(e) => integrity_not_checked(integrity_error_text(&e.to_string())),
    }
}

/// Ask the owning node for a scan. It answers at once, with the stored result
/// marked queued.
pub(super) fn integrity_scan_request(sel: HostingSelector) -> Request {
    Request::WpIntegrityScanRequest { hosting: sel }
}

async fn request_integrity_scan(
    state: &SharedState,
    owner_node: Option<&str>,
    sel: HostingSelector,
) -> Result<hyperion_types::WpIntegrityScanResult, String> {
    match crate::dispatcher::dispatch_to_node(state, owner_node, integrity_scan_request(sel)).await
    {
        Ok(RpcResponse::WpIntegrityScan(scan)) => Ok(scan),
        Ok(RpcResponse::Error(e)) => Err(integrity_error_text(&e.to_string())),
        Ok(_) => Err("unexpected response from the node".into()),
        Err(e) => Err(integrity_error_text(&e.to_string())),
    }
}

/// Should this card go on polling, and since when has this page been waiting?
/// `queued_at` is 0 on a page that has only just seen the request, say after a
/// reload.
pub(super) fn poll_state(queued: bool, queued_at: i64, now: i64) -> (bool, i64) {
    let since = if queued_at > 0 { queued_at } else { now };
    (queued && now - since < QUEUED_POLL_LIMIT_SECS, since)
}

#[derive(Deserialize)]
pub struct IntegrityPanelQuery {
    /// Set by a card that is waiting for a scan it queued.
    #[serde(default)]
    pub queued_at: i64,
}

pub async fn get_integrity_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<IntegrityPanelQuery>,
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
    let mut scan = integrity_stored_on_node(&state, owner_node.as_deref(), sel).await;
    // The node says whether the request still stands: it drops it when the scan
    // is stored, or when there's no longer a site to scan.
    let (queued, queued_since) = poll_state(scan.scan_queued, q.queued_at, now_secs_web());
    scan.scan_queued = queued;
    Ok(Html(
        IntegrityCardTpl {
            scan,
            selector,
            csrf_token,
            notice: None,
            queued_since,
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
/// spending the node's IO is not. Asks the owning node for a scan, which returns
/// at once, and answers with the card in its "queued" state, which polls until
/// the result is stored.
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
    let queued_since = now_secs_web();
    // Resolve the owner EXPLICITLY: `.ok()`-to-None would retarget a
    // lookup failure at the master, which would then verify checksums for
    // files that aren't there and report the miss as a finding.
    let (_detail, owner_node) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(found) => found,
        Err(e) => {
            return Ok(Html(
                IntegrityCardTpl {
                    scan: integrity_not_checked(e.to_string()),
                    selector: form.selector,
                    csrf_token,
                    notice: None,
                    queued_since: 0,
                }
                .render()?,
            )
            .into_response())
        }
    };
    let scan = request_integrity_scan(&state, owner_node.as_deref(), sel)
        .await
        .unwrap_or_else(integrity_not_checked);
    Ok(Html(
        IntegrityCardTpl {
            scan,
            selector: form.selector,
            csrf_token,
            notice: None,
            queued_since,
        }
        .render()?,
    )
    .into_response())
}

/// Run a fix on the owning node, then ask for a re-scan and render the card
/// with the fix's outcome on top. The re-scan is the proof: "repaired" is
/// only worth saying next to a scan that no longer lists the file — until
/// that lands, the card says it is waiting and shows the previous result.
///
/// The fix is idempotent (it re-downloads the release the site already
/// runs), so a dropped connection mid-way means "click it again", not a
/// half-done site — which is why it stays inline rather than a job.
async fn integrity_fix(
    state: SharedState,
    ctx: AuthCtx,
    selector: String,
    fix: impl FnOnce(HostingSelector) -> Request,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &selector, Capability::WpManage).await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let queued_since = now_secs_web();
    // Same explicit owner resolution as "Scan now": falling back to the
    // master would rewrite core on a box that doesn't hold the site.
    let (notice, scan, queued_since) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((_detail, owner_node)) => {
            let owner = owner_node.as_deref();
            let notice =
                match crate::dispatcher::dispatch_to_node(&state, owner, fix(sel.clone())).await {
                    Ok(RpcResponse::WpCoreRepair(m)) => (true, m),
                    Ok(RpcResponse::WpPluginAction(r)) => {
                        let ok = r.state == "ok" || r.state == "noop";
                        let text = if ok || r.output_tail.trim().is_empty() {
                            r.message
                        } else {
                            format!("{}\n\n{}", r.message, r.output_tail)
                        };
                        (ok, text)
                    }
                    Ok(RpcResponse::Error(e)) => (false, e.to_string()),
                    Ok(_) => (false, "unexpected response from the node".into()),
                    Err(e) => (false, e.to_string()),
                };
            // The fix already happened: failing to queue the re-scan must
            // not hide its outcome behind an error page.
            let mut notice = notice;
            let scan = match request_integrity_scan(&state, owner, sel.clone()).await {
                Ok(scan) => scan,
                Err(e) => {
                    notice.1 = format!("{}\n\nThe re-scan could not be queued: {e}", notice.1);
                    integrity_stored_on_node(&state, owner, sel).await
                }
            };
            (Some(notice), scan, queued_since)
        }
        Err(e) => (None, integrity_not_checked(e.to_string()), 0),
    };
    Ok(Html(
        IntegrityCardTpl {
            scan,
            selector,
            csrf_token,
            notice,
            queued_since,
        }
        .render()?,
    )
    .into_response())
}

/// POST /hostings/integrity/repair-core — put back the official core files
/// of the version the site already runs. Fixes "modified" and "missing";
/// a file that "shouldn't exist" is left where it is (see the card).
pub async fn post_integrity_repair_core(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityScanForm>,
) -> Result<Response, AppError> {
    integrity_fix(state, ctx, form.selector, |sel| Request::WpCoreRepair {
        sel,
    })
    .await
}

#[derive(Deserialize)]
pub struct IntegrityReinstallPluginForm {
    pub selector: String,
    pub slug: String,
}

/// POST /hostings/integrity/reinstall-plugin — replace one plugin that
/// failed verification with a clean copy of the same version from
/// wordpress.org. The slug is validated again in the adapter.
pub async fn post_integrity_reinstall_plugin(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityReinstallPluginForm>,
) -> Result<Response, AppError> {
    let slug = form.slug.trim().to_string();
    if slug.is_empty() {
        return Err(AppError::BadRequest("missing plugin slug".into()));
    }
    integrity_fix(state, ctx, form.selector, move |sel| {
        Request::WpPluginAction {
            hosting: sel,
            slug,
            action: hyperion_types::WpPluginAction::Reinstall,
        }
    })
    .await
}
