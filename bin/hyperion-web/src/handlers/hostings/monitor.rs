//! Uptime monitor settings.

use super::*;

#[derive(Deserialize)]
pub struct MonitorSetForm {
    pub selector: String,
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub url_path: String,
    #[serde(default)]
    pub interval_secs: String,
    #[serde(default)]
    pub alert_after_fails: String,
    #[serde(default)]
    pub alert_email: String,
    #[serde(default)]
    pub alert_slack_webhook: String,
    #[serde(default)]
    pub alert_webhook_url: String,
    /// "1" from the Remove button. The webhook input is not rendered while
    /// one is configured, so this is the only way to clear it — and it cannot
    /// happen by accident on an unrelated save.
    #[serde(default)]
    pub remove_slack: Option<String>,
}

pub async fn post_monitor_set(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<MonitorSetForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
    // Cross-node aware: the form selector is now a ULID (after the
    // duplicate-domain fix), so the master agent may not own the
    // row at all. `find_hosting_anywhere` checks master first, then
    // fans out to every enrolled worker. The returned `owner_node`
    // is what we dispatch the MonitorSet RPC to so the config
    // lands on the agent that actually serves the hosting.
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    let target = owner_node.as_deref();
    // Guard with manage-level access. super_admin / admin bypass.
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        true,
        Capability::MonitoringManage,
    )
    .await
    {
        return Ok(r);
    }
    let enabled = form.enabled == "on" || form.enabled == "true" || form.enabled == "1";
    let path = if form.url_path.trim().is_empty() {
        None
    } else {
        Some(form.url_path.trim().to_string())
    };
    let interval = form
        .interval_secs
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0);
    let after = form
        .alert_after_fails
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0);
    let email = if form.alert_email.trim().is_empty() {
        None
    } else {
        Some(form.alert_email.trim().to_string())
    };
    // Empty is "leave it alone", NOT "delete it". The webhook is a bearer
    // credential, so it is never rendered back into the form — an empty field
    // means the operator was not shown it. Removing is its own explicit
    // button, which posts remove_slack=1.
    let slack = if form.alert_slack_webhook.trim().is_empty() {
        None
    } else {
        Some(form.alert_slack_webhook.trim().to_string())
    };
    let clear_slack_webhook = form.remove_slack.as_deref() == Some("1");
    let webhook = if form.alert_webhook_url.trim().is_empty() {
        None
    } else {
        Some(form.alert_webhook_url.trim().to_string())
    };
    // The node POSTs to this URL when the monitor fires. Below cluster scope,
    // refuse an internal target so a customer cannot turn their own site's
    // uptime check into a read of the metadata endpoint or an internal service.
    if !ctx.scope_all() {
        if let Some(u) = webhook.as_deref() {
            if let Err(msg) = super::reject_internal_url(u).await {
                return Ok(Redirect::to(&format!(
                    "/hostings/{}?error={}#monitor",
                    urlencoding(&form.selector),
                    urlencoding(&msg)
                ))
                .into_response());
            }
        }
    }
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::MonitorSet {
            clear_slack_webhook,
            sel: sel.clone(),
            enabled,
            url_path: path,
            interval_secs: interval,
            alert_after_fails: after,
            alert_email: email,
            alert_slack_webhook: slack,
            alert_webhook_url: webhook,
        },
    )
    .await?;
    match resp {
        RpcResponse::MonitorSet => Ok(Redirect::to(&format!(
            "/hostings/{}#monitor",
            urlencoding(&form.selector)
        ))
        .into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct MonitorProbeForm {
    pub selector: String,
}

pub async fn post_monitor_probe(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<MonitorProbeForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    let target = owner_node.as_deref();
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        true,
        Capability::MonitoringManage,
    )
    .await
    {
        return Ok(r);
    }
    let _ = crate::dispatcher::dispatch_to_node(&state, target, Request::MonitorProbeNow { sel })
        .await?;
    Ok(Redirect::to(&format!(
        "/hostings/{}#monitor",
        urlencoding(&form.selector)
    ))
    .into_response())
}
