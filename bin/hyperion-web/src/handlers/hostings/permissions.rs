//! Permission check, repair and autoheal.

use super::*;

#[derive(Template)]
#[template(path = "_hosting_perm_card.html")]
pub(super) struct PermCardTpl {
    pub(super) report: hyperion_types::FtpCheckReport,
    pub(super) selector: String,
    pub(super) system_user: String,
    pub(super) csrf_repair: String,
    /// Is the five-minute self-repair allowed to act on this site?
    ///
    /// Reported here rather than on its own card because it is the switch for
    /// exactly the check displayed beside it — a card that lists permission
    /// problems while something silently fixes them elsewhere is two halves of
    /// one story on different pages.
    pub(super) autoheal_enabled: bool,
    pub(super) csrf_autoheal: String,
    pub(super) error: Option<String>,
}

/// POST /hostings/perm-autoheal — turn this site's permission self-repair on
/// or off, re-rendering the permissions card in place.
///
/// The write goes to the OWNING node: that is where the five-minute tick reads
/// the key, so a master-local write would be a switch wired to nothing.
pub async fn post_perm_autoheal(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PermAutohealForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let enabled = form.enabled.trim() != "off";
    let _ = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingPermAutohealSet { sel, enabled },
    )
    .await?;
    // Re-render the whole card so the tile and the check agree.
    get_perm_panel(State(state), ctx, Path(form.selector)).await
}

#[derive(serde::Deserialize)]
pub struct PermAutohealForm {
    pub selector: String,
    /// "on" | "off"
    pub enabled: String,
}

/// GET /hostings/:selector/perm-panel — diagnose this site's file permissions.
pub async fn get_perm_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let card = |report, system_user: String, autoheal_enabled: bool, error: Option<String>| {
        Html(
            PermCardTpl {
                report,
                selector: selector.clone(),
                system_user,
                csrf_repair: csrf_token_for(&state, &ctx, "/hostings/wp/perm-repair"),
                autoheal_enabled,
                csrf_autoheal: csrf_token_for(&state, &ctx, "/hostings/perm-autoheal"),
                error,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return Ok(card(
                Default::default(),
                String::new(),
                true,
                Some(format!("could not read the selector: {e}")),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(card(
                Default::default(),
                String::new(),
                true,
                Some(e.to_string()),
            ))
        }
    };
    // A read probe, so HostingView is the right gate — the repair below is
    // what needs manage rights.
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
        return Ok(card(
            Default::default(),
            String::new(),
            true,
            Some("You do not have access to this hosting.".into()),
        ));
    }
    let user = detail.system_user.clone();
    // Read from the OWNING node's kv — that is where the tick reads it, so a
    // master-local read would show a switch wired to nothing. A failed read
    // renders as ON, which is what the tick itself answers when it cannot read
    // the key: the tile shows the state the site is actually in.
    let autoheal_enabled = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingKvList {
            hosting_id: detail.id.as_str().to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v
            .into_iter()
            .find(|(k, _)| k == "permissions_autoheal_enabled")
            .map(|(_, val)| val.trim() != "off")
            .unwrap_or(true),
        _ => true,
    };
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::WpPermCheck { sel },
    )
    .await
    {
        Ok(RpcResponse::WpPermCheck(r)) => Ok(card(r, user, autoheal_enabled, None)),
        Ok(RpcResponse::Error(e)) => Ok(card(
            Default::default(),
            user,
            autoheal_enabled,
            Some(e.to_string()),
        )),
        Ok(_) => Ok(card(
            Default::default(),
            user,
            autoheal_enabled,
            Some("unexpected response from the node".into()),
        )),
        Err(e) => Ok(card(
            Default::default(),
            user,
            autoheal_enabled,
            Some(e.to_string()),
        )),
    }
}

#[derive(serde::Deserialize)]
pub struct PermRepairForm {
    pub selector: String,
    pub scope: String,
}

/// POST /hostings/wp/perm-repair — apply one of the permission repairs.
pub async fn post_perm_repair(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PermRepairForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::WpPermRepair {
            sel,
            scope: form.scope.clone(),
        },
    )
    .await?;
    Ok(match resp {
        RpcResponse::WpPermRepair(m) => Redirect::to(&format!(
            "/hostings/{sel_url}?flash={}#wordpress",
            urlencoding(&m)
        ))
        .into_response(),
        RpcResponse::Error(e) => {
            let token = stash_error(&state, &e.to_string()).await;
            Redirect::to(&format!(
                "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
            ))
            .into_response()
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    })
}

#[derive(Deserialize)]
pub struct RepairPermsForm {
    pub selector: String,
    pub _csrf: String,
}

/// Reset ownership + modes across a hosting's tree.
///
/// Dispatched to the OWNING node explicitly, like the DKIM writes: the
/// files are there, and only that node knows the uid behind the system
/// user. Falling back to the master on a lookup failure would chown a
/// path that either does not exist there or belongs to a different site.
pub async fn post_repair_permissions(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RepairPermsForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let owner: Option<String> = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((_d, n)) => n,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{sel_url}?flash_error={}#settings",
                urlencoding(&e.to_string())
            ))
            .into_response())
        }
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingRepairPermissions { sel },
    )
    .await;
    let (key, msg) = match resp {
        Ok(RpcResponse::HostingRepairPermissions(m)) => ("flash", m),
        Ok(RpcResponse::Error(e)) => ("flash_error", e.to_string()),
        Ok(_) => ("flash_error", "unexpected response from node".to_string()),
        Err(e) => ("flash_error", e.to_string()),
    };
    Ok(Redirect::to(&format!(
        "/hostings/{sel_url}?{key}={}#settings",
        urlencoding(&msg)
    ))
    .into_response())
}
