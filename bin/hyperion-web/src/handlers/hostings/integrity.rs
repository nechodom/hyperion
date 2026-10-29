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
    /// Outcome of a fix the operator just ran from this card, shown above
    /// the fresh scan. `(ok, text)`. Rendered inside the row because HTMX
    /// does not swap a non-2xx response — an error status would leave the
    /// operator watching a spinner.
    pub(super) notice: Option<(bool, String)>,
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
            notice: None,
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
            notice: None,
        }
        .render()?,
    )
    .into_response())
}

/// Run a fix on the owning node, then re-scan and render the card with the
/// fix's outcome on top. The re-scan is the proof: "repaired" is only worth
/// saying next to a scan that no longer lists the file.
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
    // Same explicit owner resolution as "Scan now": falling back to the
    // master would rewrite core on a box that doesn't hold the site.
    let (notice, scan) = match find_hosting_anywhere(&state, sel.clone()).await {
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
            (
                Some(notice),
                integrity_scan_on_node(&state, owner, sel).await,
            )
        }
        Err(e) => (None, integrity_not_checked(e.to_string())),
    };
    Ok(Html(
        IntegrityCardTpl {
            scan,
            selector,
            csrf_token,
            notice,
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
