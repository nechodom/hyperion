//! WordPress updates (vulnerabilities) card.

use super::*;

/// Lazily-loaded WordPress vulnerability panel (Wordfence feed match).
/// Dispatched to the OWNING node — the feed cache + wp-cli both live
/// where the site's files are.
#[derive(Template)]
#[template(path = "_hosting_vuln_panel.html")]
pub(super) struct VulnPanelTpl {
    pub(super) scan: hyperion_types::WpVulnScanResult,
    /// Every outdated plugin, theme and core release with what happens to
    /// it — built by the cluster page's classifier so both say the same.
    pub(super) comps: Vec<crate::handlers::vulns::CompRow>,
    /// Of `comps`, how many wait for a person.
    pub(super) waiting: usize,
    pub(super) selector: String,
    /// The shared update button's selector (same as `selector`).
    pub(super) upd_sel: String,
    /// The update buttons return to the site, not to /vulns.
    pub(super) upd_back: &'static str,
    /// Whether the viewer may update — WpVulnView alone sees the rows but
    /// gets no buttons the POST would refuse.
    pub(super) can_manage: bool,
    pub(super) auto_update_enabled: bool,
    pub(super) csrf_token: String,
}

impl VulnPanelTpl {
    pub(super) fn new(
        scan: hyperion_types::WpVulnScanResult,
        selector: String,
        auto_update_enabled: bool,
        csrf_token: String,
        can_manage: bool,
    ) -> Self {
        let comps = crate::handlers::vulns::scan_comp_rows(
            &scan,
            auto_update_enabled,
            hyperion_types::now_secs(),
        );
        let waiting = comps.iter().filter(|c| c.state.needs_you()).count();
        Self {
            scan,
            comps,
            waiting,
            upd_sel: selector.clone(),
            upd_back: "",
            can_manage,
            selector,
            auto_update_enabled,
            csrf_token,
        }
    }
}

pub async fn get_vuln_panel(
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
    // Auto-update toggle state lives in the OWNING node's hosting_kv
    // ("wp_auto_update"); default ON when absent.
    let auto_update_enabled = match crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingKvList {
            hosting_id: detail.id.as_str().to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v
            .into_iter()
            .find(|(k, _)| k == "wp_auto_update")
            .map(|(_, val)| val.trim() != "off")
            .unwrap_or(true),
        _ => true,
    };
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let can_manage = ctx.can(Capability::WpManage) && !ctx.is_read_only();
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::WpVulnScan { hosting: sel },
    )
    .await;
    let html = match resp {
        Ok(RpcResponse::WpVulnScan(scan)) => VulnPanelTpl::new(
            scan,
            selector.clone(),
            auto_update_enabled,
            csrf_token,
            can_manage,
        )
        .render()?,
        // On any failure render the "couldn't check" state rather than
        // a blank corner — the operator should know the scan didn't run.
        _ => VulnPanelTpl::new(
            hyperion_types::WpVulnScanResult {
                feed_unavailable: true,
                ..Default::default()
            },
            selector.clone(),
            auto_update_enabled,
            csrf_token,
            can_manage,
        )
        .render()?,
    };
    Ok(Html(html).into_response())
}

#[derive(Deserialize)]
pub struct WpAutoUpdateForm {
    pub selector: String,
    /// "on" enables the defender's daily minor/patch auto-update; anything
    /// else disables it.
    pub enabled: String,
}

/// Toggle the keyless defender's daily minor/patch auto-update for a
/// hosting. Stored in the OWNING node's hosting_kv ("wp_auto_update",
/// keyed by the hosting ULID) where the daily tick reads it.
pub async fn post_wp_auto_update(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpAutoUpdateForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let (detail, target) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(_) => {
            return Ok(Redirect::to(&format!("/hostings/{}#wordpress", sel_url)).into_response());
        }
    };
    let value = if form.enabled == "on" { "on" } else { "off" };
    let saved = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::HostingKvSet {
            hosting_id: detail.id.as_str().to_string(),
            key: "wp_auto_update".into(),
            value: value.into(),
        },
    )
    .await;
    // Security updates hang on this switch: a write that did not land must not
    // come back as "saved".
    let (key, msg) = match saved {
        Ok(RpcResponse::HostingKvSet) => (
            "flash",
            if value == "on" {
                "Automatic updates switched on.".to_string()
            } else {
                "Automatic updates switched off.".to_string()
            },
        ),
        Ok(RpcResponse::Error(e)) => (
            "flash_error",
            format!("Automatic updates were not changed — the owning node refused it: {e}"),
        ),
        Ok(_) => (
            "flash_error",
            "Automatic updates were not changed — unexpected response.".to_string(),
        ),
        Err(e) => (
            "flash_error",
            format!(
                "Automatic updates were not changed — the owning node could not be reached: {e}"
            ),
        ),
    };
    Ok(Redirect::to(&format!(
        "/hostings/{}?{key}={}#wordpress",
        sel_url,
        urlencoding(&msg)
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct WpCoreUpdateForm {
    pub selector: String,
    /// The release the Updates row offered. The node accepts it only if
    /// wp-cli still offers it to this site.
    pub version: String,
}

/// POST /hostings/wp/core-update — update WordPress core to the release the
/// Updates row offered, major or minor. A background job: the node takes a
/// full pre-update backup first, which is minutes on a big site, and an
/// update cut off by a closed tab is exactly the half-done state the backup
/// exists for.
pub async fn post_wp_core_update(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpCoreUpdateForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let node = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((_d, n)) => n,
        Err(e) => {
            let token = stash_error(&state, &e.to_string()).await;
            return Ok(Redirect::to(&format!(
                "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
            ))
            .into_response());
        }
    };
    let version = form.version.trim().to_string();
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "wp_core_update",
        Some(&form.selector),
        &serde_json::json!({ "version": version }).to_string(),
        &ctx.username,
        actor_uid,
        move |reporter| run_wp_core_update_job(reporter, job_state, node, sel, version),
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

/// The `wp_core_update` job body — the web button and
/// `POST /api/v1/hostings/:id/wp/core-update` run the same thing.
pub(crate) async fn run_wp_core_update_job(
    reporter: crate::handlers::jobs::JobReporter,
    job_state: SharedState,
    node: Option<String>,
    sel: HostingSelector,
    version: String,
) {
    reporter
        .step(
            &format!("Backing up files + database, then updating WordPress to {version}…"),
            10,
            "",
        )
        .await;
    match crate::dispatcher::dispatch_to_node(
        &job_state,
        node.as_deref(),
        Request::WpCoreUpdate { sel, version },
    )
    .await
    {
        Ok(RpcResponse::WpCoreUpdate(m)) => {
            reporter.step(&m, 100, "").await;
            reporter.finish(true, None).await;
        }
        Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
        Ok(_) => {
            reporter
                .finish(false, Some("unexpected response from the node".into()))
                .await
        }
        Err(e) => reporter.finish(false, Some(e.to_string())).await,
    }
}
