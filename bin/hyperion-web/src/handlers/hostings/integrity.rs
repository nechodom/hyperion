//! WordPress integrity scan card.

use super::*;

/// Lazily-loaded file-integrity + malware panel — the tamper-detection
/// sibling of the vuln panel. Dispatched to the OWNING node, where it reads
/// the last stored result; opening the page never starts a scan.
#[derive(Template, Default)]
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
    /// Outcome of a file action just run from this card, in its own words: moving
    /// a file to quarantine isn't "fixing" anything.
    pub(super) action_notice: Option<(bool, String)>,
    /// May quarantine and restore here.
    pub(super) can_manage: bool,
    /// May trust files here. Without it the card says who is going to.
    pub(super) can_trust: bool,
    pub(super) quarantine: hyperion_types::QuarantineList,
    /// Why the list above can't be trusted to be whole.
    pub(super) quarantine_note: Option<String>,
}

/// What the card shows besides the scan: what this user may do, and what the
/// hosting holds in quarantine.
#[derive(Default)]
struct CardExtras {
    can_manage: bool,
    can_trust: bool,
    quarantine: hyperion_types::QuarantineList,
    quarantine_note: Option<String>,
}

/// How long one page keeps polling for a scan it saw queued. The node says when
/// it's done; this is for a request nothing will ever answer, which would
/// otherwise poll for as long as the tab stays open.
const QUEUED_POLL_LIMIT_SECS: i64 = 2 * 3600;

/// Does the overview tab carry the card? Sites with no WordPress and files to
/// scan do: WordPress has its row on the WordPress tab, a reverse proxy has no
/// site of its own and a redirect has nothing to scan.
pub(super) fn integrity_on_overview(kind: &str, has_wordpress: bool) -> bool {
    !has_wordpress && matches!(kind, "php" | "static")
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

/// A file action's refusal, in the words the node used. A node from before these
/// actions rejects the request by name.
pub(super) fn action_error_text(e: &str) -> String {
    if e.contains("unknown variant") {
        "this node needs updating".into()
    } else {
        e.strip_prefix("conflict: ").unwrap_or(e).to_string()
    }
}

/// The request that lists what a hosting holds in quarantine.
pub(super) fn quarantine_list_request(sel: HostingSelector) -> Request {
    Request::ScanQuarantineList { hosting: sel }
}

/// The reinstall the card's buttons send. The node checks the stored label: this
/// isn't `WpPluginAction`, which would take any slug it was given.
pub(super) fn integrity_reinstall_request(
    sel: HostingSelector,
    slug: String,
    theme: bool,
) -> Request {
    Request::ScanComponentReinstall {
        hosting: sel,
        slug,
        theme,
    }
}

async fn card_extras(
    state: &SharedState,
    ctx: &AuthCtx,
    hosting_id: &str,
    owner_node: Option<&str>,
    sel: HostingSelector,
) -> CardExtras {
    let allowed = |cap| require_hosting_access(state, ctx, hosting_id, true, cap);
    let can_manage = allowed(Capability::WpManage).await.is_ok();
    let can_trust = allowed(Capability::WpScanTrust).await.is_ok();
    let (quarantine, quarantine_note) =
        match crate::dispatcher::dispatch_to_node(state, owner_node, quarantine_list_request(sel))
            .await
        {
            Ok(RpcResponse::ScanQuarantineList(list)) => (list, None),
            Ok(RpcResponse::Error(e)) => {
                (Default::default(), Some(action_error_text(&e.to_string())))
            }
            Ok(_) => (
                Default::default(),
                Some("unexpected response from the node".to_string()),
            ),
            Err(e) => (Default::default(), Some(action_error_text(&e.to_string()))),
        };
    CardExtras {
        can_manage,
        can_trust,
        quarantine,
        quarantine_note,
    }
}

/// What a file action changes in the card: the node's answer, or why not with the
/// stored result beside it.
async fn run_file_action(
    state: &SharedState,
    owner_node: Option<&str>,
    sel: HostingSelector,
    request: Request,
    done: String,
) -> (hyperion_types::WpIntegrityScanResult, (bool, String)) {
    let refused = match crate::dispatcher::dispatch_to_node(state, owner_node, request).await {
        Ok(RpcResponse::WpIntegrityScan(scan)) => return (scan, (true, done)),
        Ok(RpcResponse::Error(e)) => action_error_text(&e.to_string()),
        Ok(_) => "unexpected response from the node".to_string(),
        Err(e) => action_error_text(&e.to_string()),
    };
    (
        integrity_stored_on_node(state, owner_node, sel).await,
        (false, refused),
    )
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
    let hosting_id = detail.id.as_str().to_string();
    if let Err(r) =
        require_hosting_access(&state, &ctx, &hosting_id, false, Capability::WpVulnView).await
    {
        return Ok(r);
    }
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let mut scan = integrity_stored_on_node(&state, owner_node.as_deref(), sel.clone()).await;
    // The node says whether the request still stands: it drops it when the scan
    // is stored, or when there's no longer a site to scan.
    let (queued, queued_since) = poll_state(scan.scan_queued, q.queued_at, now_secs_web());
    scan.scan_queued = queued;
    let extras = card_extras(&state, &ctx, &hosting_id, owner_node.as_deref(), sel).await;
    render_card(IntegrityCardTpl {
        scan,
        selector,
        csrf_token,
        queued_since,
        ..extras.into()
    })
}

impl From<CardExtras> for IntegrityCardTpl {
    fn from(e: CardExtras) -> Self {
        Self {
            can_manage: e.can_manage,
            can_trust: e.can_trust,
            quarantine: e.quarantine,
            quarantine_note: e.quarantine_note,
            ..Default::default()
        }
    }
}

fn render_card(tpl: IntegrityCardTpl) -> Result<Response, AppError> {
    Ok(Html(tpl.render()?).into_response())
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
    let (detail, owner_node) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(found) => found,
        Err(e) => {
            return render_card(IntegrityCardTpl {
                scan: integrity_not_checked(e.to_string()),
                selector: form.selector,
                csrf_token,
                ..Default::default()
            })
        }
    };
    let scan = request_integrity_scan(&state, owner_node.as_deref(), sel.clone())
        .await
        .unwrap_or_else(integrity_not_checked);
    let extras = card_extras(&state, &ctx, detail.id.as_str(), owner_node.as_deref(), sel).await;
    render_card(IntegrityCardTpl {
        scan,
        selector: form.selector,
        csrf_token,
        queued_since,
        ..extras.into()
    })
}

/// A file action from the card: the capability, then the node, which checks the
/// rest. The answer is the card again, since HTMX won't swap an error status.
async fn integrity_file_action(
    state: SharedState,
    ctx: AuthCtx,
    selector: String,
    cap: Capability,
    done: String,
    request: impl FnOnce(HostingSelector, String) -> Request,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &selector, cap).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let (detail, owner_node) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(found) => found,
        Err(e) => {
            return render_card(IntegrityCardTpl {
                scan: integrity_not_checked(e.to_string()),
                selector,
                csrf_token,
                ..Default::default()
            })
        }
    };
    let owner = owner_node.as_deref();
    let req = request(sel.clone(), ctx.username.clone());
    let (scan, action_notice) = run_file_action(&state, owner, sel.clone(), req, done).await;
    let extras = card_extras(&state, &ctx, detail.id.as_str(), owner, sel).await;
    render_card(IntegrityCardTpl {
        scan,
        selector,
        csrf_token,
        queued_since: now_secs_web(),
        action_notice: Some(action_notice),
        ..extras.into()
    })
}

#[derive(Deserialize)]
pub struct IntegrityFileForm {
    pub selector: String,
    pub rel: String,
    pub sha256: String,
}

/// POST /hostings/integrity/quarantine — move one reported file out of the site.
pub async fn post_integrity_quarantine(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityFileForm>,
) -> Result<Response, AppError> {
    let IntegrityFileForm {
        selector,
        rel,
        sha256,
    } = form;
    integrity_file_action(
        state,
        ctx,
        selector,
        Capability::WpManage,
        "Moved to quarantine. It can be put back from the list below for 90 days.".into(),
        move |hosting, actor| Request::ScanFileQuarantine {
            hosting,
            rel,
            sha256,
            actor,
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct IntegrityRestoreForm {
    pub selector: String,
    pub id: String,
}

/// POST /hostings/integrity/restore — put a quarantined file back.
pub async fn post_integrity_restore(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityRestoreForm>,
) -> Result<Response, AppError> {
    let IntegrityRestoreForm { selector, id } = form;
    integrity_file_action(
        state,
        ctx,
        selector,
        Capability::WpManage,
        "Put back where it was, with its owner and permissions. The site is scanned again.".into(),
        move |hosting, actor| Request::ScanFileRestore { hosting, id, actor },
    )
    .await
}

/// POST /hostings/integrity/trust — accept one reported file as it stands. Not
/// `WpManage`: a stolen customer login must not be able to approve a webshell.
pub async fn post_integrity_trust(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityFileForm>,
) -> Result<Response, AppError> {
    let IntegrityFileForm {
        selector,
        rel,
        sha256,
    } = form;
    integrity_file_action(
        state,
        ctx,
        selector,
        Capability::WpScanTrust,
        "Trusted as it stands. If its content changes it's flagged again.".into(),
        move |hosting, actor| Request::ScanFileTrust {
            hosting,
            rel,
            sha256,
            actor,
        },
    )
    .await
}

/// POST /hostings/integrity/trust-all — accept every change to review with no rule
/// hit, after a bulk edit. Same capability as one file.
pub async fn post_integrity_trust_all(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityScanForm>,
) -> Result<Response, AppError> {
    integrity_file_action(
        state,
        ctx,
        form.selector,
        Capability::WpScanTrust,
        "Trusted as they stand. Any of them whose content changes is flagged again.".into(),
        |hosting, actor| Request::ScanTrustAllReview { hosting, actor },
    )
    .await
}

#[derive(Deserialize)]
pub struct IntegrityVendorForgetForm {
    pub selector: String,
    pub slug: String,
    pub version: String,
    #[serde(default)]
    pub theme: bool,
}

/// POST /hostings/integrity/vendor-forget — stop believing this node's copy of one
/// vendor package version. Same capability as Trust: both decide what's taken as
/// good, and a customer's login must not be able to.
pub async fn post_integrity_vendor_forget(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityVendorForgetForm>,
) -> Result<Response, AppError> {
    let IntegrityVendorForgetForm {
        selector,
        slug,
        version,
        theme,
    } = form;
    integrity_file_action(
        state,
        ctx,
        selector,
        Capability::WpScanTrust,
        "Forgotten on this node. Sites on this version are scanned again.".into(),
        move |hosting, actor| Request::ScanVendorForget {
            hosting,
            theme,
            slug,
            version,
            actor,
        },
    )
    .await
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
    let mut extras = CardExtras::default();
    // Same explicit owner resolution as "Scan now": falling back to the
    // master would rewrite core on a box that doesn't hold the site.
    let (notice, scan, queued_since) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((detail, owner_node)) => {
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
                    Ok(RpcResponse::Error(e)) => (false, action_error_text(&e.to_string())),
                    Ok(_) => (false, "unexpected response from the node".into()),
                    Err(e) => (false, action_error_text(&e.to_string())),
                };
            // The fix already happened: failing to queue the re-scan must
            // not hide its outcome behind an error page.
            let mut notice = notice;
            let scan = match request_integrity_scan(&state, owner, sel.clone()).await {
                Ok(scan) => scan,
                Err(e) => {
                    notice.1 = format!("{}\n\nThe re-scan could not be queued: {e}", notice.1);
                    integrity_stored_on_node(&state, owner, sel.clone()).await
                }
            };
            extras = card_extras(&state, &ctx, detail.id.as_str(), owner, sel).await;
            (Some(notice), scan, queued_since)
        }
        Err(e) => (None, integrity_not_checked(e.to_string()), 0),
    };
    render_card(IntegrityCardTpl {
        scan,
        selector,
        csrf_token,
        notice,
        queued_since,
        ..extras.into()
    })
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
/// wordpress.org. The node refuses unless wordpress.org is what the scan compared
/// it with; the slug is validated again in the adapter.
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
        integrity_reinstall_request(sel, slug, false)
    })
    .await
}

/// POST /hostings/integrity/reinstall-theme — the same for a theme. Same form, and
/// the version comes from what the node stored, not from here.
pub async fn post_integrity_reinstall_theme(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<IntegrityReinstallPluginForm>,
) -> Result<Response, AppError> {
    let slug = form.slug.trim().to_string();
    if slug.is_empty() {
        return Err(AppError::BadRequest("missing theme slug".into()));
    }
    integrity_fix(state, ctx, form.selector, move |sel| {
        integrity_reinstall_request(sel, slug, true)
    })
    .await
}
