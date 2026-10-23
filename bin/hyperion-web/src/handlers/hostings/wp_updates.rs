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
    pub(super) auto_update_enabled: bool,
    pub(super) csrf_token: String,
}

impl VulnPanelTpl {
    pub(super) fn new(
        scan: hyperion_types::WpVulnScanResult,
        selector: String,
        auto_update_enabled: bool,
        csrf_token: String,
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
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::WpVulnScan { hosting: sel },
    )
    .await;
    let html = match resp {
        Ok(RpcResponse::WpVulnScan(scan)) => {
            VulnPanelTpl::new(scan, selector.clone(), auto_update_enabled, csrf_token).render()?
        }
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
