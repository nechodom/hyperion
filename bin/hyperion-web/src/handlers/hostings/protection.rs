//! Brute-force scanning and IP bans for one hosting.

use super::*;

/// Brute-force tile on the Security card: whether the per-site HTTP
/// brute-force scan (the wp-login / xmlrpc access-log sweep) may look at
/// this hosting.
///
/// The switch is the OWNING node's `hosting_kv` key
/// `http_bruteforce_scan_enabled` (`FAIL2BAN_HTTP_KV_KEY` in
/// hyperion-core): `fail2ban_scan` reads it on the node that owns the
/// hosting, so both the state read and the toggle write must travel
/// there. The master's local kv — where the generic notes/tags writes
/// land — would be a switch wired to nothing on a multi-node cluster.
#[derive(Template)]
#[template(path = "_hosting_bruteforce_card.html")]
pub(super) struct BruteforceCardTpl {
    pub(super) enabled: bool,
    pub(super) selector: String,
    pub(super) csrf_token: String,
    /// Set only when a read or write failed — surfaced above the copy.
    pub(super) error: Option<String>,
}

/// Read the switch from the owning node's kv. Absent ⇒ ON, matching the
/// scanner's own default (`http_bruteforce_scan_enabled` in
/// hyperion-core); only a literal "off" opts the site out.
pub(super) async fn bruteforce_scan_enabled_on_node(
    state: &SharedState,
    owner_node: Option<&str>,
    hosting_id: &str,
) -> Result<bool, String> {
    match crate::dispatcher::dispatch_to_node(
        state,
        owner_node,
        Request::HostingKvList {
            hosting_id: hosting_id.to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => Ok(v
            .into_iter()
            .find(|(k, _)| k == "http_bruteforce_scan_enabled")
            .map(|(_, val)| val.trim() != "off")
            .unwrap_or(true)),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected response from the owning node".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn get_bruteforce_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    {
        return Ok(r);
    }
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    // A failed read renders as ON plus the error — ON is what the scanner
    // itself answers when it cannot read the key, so the tile shows the
    // state the site is actually in rather than collapsing.
    let (enabled, error) =
        match bruteforce_scan_enabled_on_node(&state, owner_node.as_deref(), detail.id.as_str())
            .await
        {
            Ok(on) => (on, None),
            Err(e) => (true, Some(e)),
        };
    Ok(Html(
        BruteforceCardTpl {
            enabled,
            selector,
            csrf_token,
            error,
        }
        .render()?,
    )
    .into_response())
}

#[derive(Deserialize)]
pub struct BruteforceScanForm {
    pub selector: String,
    /// "on" resumes the access-log scan; anything else pauses it.
    pub enabled: String,
}

pub async fn post_bruteforce_scan(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BruteforceScanForm>,
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
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let render = |enabled: bool, error: Option<String>| -> Result<Response, AppError> {
        Ok(Html(
            BruteforceCardTpl {
                enabled,
                selector: form.selector.clone(),
                csrf_token: csrf_token.clone(),
                error,
            }
            .render()?,
        )
        .into_response())
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        // Unknown state — show the scanner's fail-open default plus why.
        Err(e) => return render(true, Some(e.to_string())),
    };
    let value = if form.enabled.trim() == "on" {
        "on"
    } else {
        "off"
    };
    let saved = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingKvSet {
            hosting_id: detail.id.as_str().to_string(),
            key: "http_bruteforce_scan_enabled".into(),
            value: value.into(),
        },
    )
    .await;
    let (enabled, error) = match saved {
        Ok(RpcResponse::HostingKvSet) => (value == "on", None),
        Ok(RpcResponse::Error(e)) => (
            // The write was refused — re-read so the tile shows reality.
            bruteforce_scan_enabled_on_node(&state, owner.as_deref(), detail.id.as_str())
                .await
                .unwrap_or(true),
            Some(format!("the owning node refused the change: {e}")),
        ),
        Ok(_) => (
            true,
            Some("unexpected response from the owning node".into()),
        ),
        Err(e) => (
            bruteforce_scan_enabled_on_node(&state, owner.as_deref(), detail.id.as_str())
                .await
                .unwrap_or(true),
            Some(e.to_string()),
        ),
    };
    render(enabled, error)
}

/// Lazily-loaded "Banned IPs" panel (Settings tab). Dispatched to the
/// OWNING node — bans are enforced node-wide by nftables there.
#[derive(Template)]
#[template(path = "_hosting_bans_panel.html")]
pub(super) struct BansPanelTpl {
    pub(super) bans: Vec<hyperion_types::IpBanWire>,
    pub(super) selector: String,
    pub(super) csrf_ban: String,
    pub(super) error: String,
}

pub async fn get_bans_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    {
        return Ok(r);
    }
    let csrf_ban = csrf_token_for(&state, &ctx, "/hostings/ban");
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::BanList {
            hosting_id: Some(detail.id.as_str().to_string()),
        },
    )
    .await;
    let (bans, error) = match resp {
        Ok(RpcResponse::BanList(b)) => (b, String::new()),
        Ok(RpcResponse::Error(e)) => (vec![], e.to_string()),
        _ => (vec![], "could not reach the owning node".into()),
    };
    let tpl = BansPanelTpl {
        bans,
        selector: detail.id.as_str().to_string(),
        csrf_ban,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct BanForm {
    pub selector: String,
    /// "add" | "remove".
    pub op: String,
    pub ip: String,
    #[serde(default)]
    pub reason: String,
}

pub async fn post_ban(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BanForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::SecurityManage)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let hosting_id = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((d, _)) => Some(d.id.as_str().to_string()),
        Err(_) => None,
    };
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let req = if form.op == "remove" {
        Request::BanRemove {
            ip: form.ip.trim().to_string(),
            // Scoped unless the caller is an admin. The nftables set is one
            // global set on the input hook, so an unban naming only an IP
            // lifts whatever protection that IP had — including a
            // brute-force ban raised for a different tenant. Both Customer
            // and Operator hold SecurityManage here.
            sel: if ctx.is_admin_or_higher() {
                None
            } else {
                Some(sel)
            },
        }
    } else {
        let reason = if form.reason.trim().is_empty() {
            "manual ban".to_string()
        } else {
            form.reason.trim().chars().take(200).collect()
        };
        Request::BanAdd {
            ip: form.ip.trim().to_string(),
            hosting_id,
            reason,
            ttl_secs: 0, // manual bans are permanent until lifted
            source: "manual".into(),
        }
    };
    let resp = crate::dispatcher::dispatch_to_node(&state, target_owned.as_deref(), req).await?;
    match resp {
        RpcResponse::BanAdd | RpcResponse::BanRemove => {
            Ok(Redirect::to(&format!("/hostings/{}?ban=ok#settings", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?ban_error={}#settings", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
