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
                    "/hostings/{}?monitor_error={}#monitor",
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
pub struct MonitorFromProfileForm {
    pub selector: String,
    pub profile_id: i64,
}

/// Copy a profile's alert channels — its Slack webhook and its "also e-mail
/// alerts to" list — onto this site's uptime monitor.
///
/// Server-side on purpose: the profile's webhook is a bearer credential and
/// never reaches the browser, so the form cannot simply prefill it. Everything
/// else on the monitor (on/off, path, interval, threshold, JSON webhook) is
/// re-sent unchanged, because `MonitorSet` writes every column it is given.
/// E-mail addresses are merged into the ones already there rather than
/// replacing them: an import must not quietly stop someone getting alerts.
pub async fn post_monitor_from_profile(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<MonitorFromProfileForm>,
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
    let back = |key: &str, val: &str| -> Response {
        Redirect::to(&format!(
            "/hostings/{}?{key}={}#monitor",
            urlencoding(&form.selector),
            urlencoding(val)
        ))
        .into_response()
    };
    // Profiles are cluster-wide and carry other clients' webhooks; reading one
    // is the profiles permission, same as applying one.
    if !ctx.can(Capability::ProfilesManage) {
        return Ok(back(
            "monitor_error",
            "Importing from a profile needs the profiles permission.",
        ));
    }
    let profiles = fetch_all_profiles(&state).await?;
    let Some(profile) = profiles.into_iter().find(|p| p.id == form.profile_id) else {
        return Ok(back("monitor_error", "That profile no longer exists."));
    };
    let profile_slack = profile
        .slack_webhook
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let profile_emails = recipient_list(&profile.alert_emails);
    if profile_slack.is_none() && profile_emails.is_empty() {
        return Ok(back(
            "monitor_error",
            &format!(
                "The {} profile has no Slack webhook or alert e-mails to import.",
                profile.name
            ),
        ));
    }
    // The current config, read from the owning node. A failed read must not
    // fall back to defaults — saving those would wipe the monitor.
    let current = match crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::MonitorGet { sel: sel.clone() },
    )
    .await?
    {
        RpcResponse::MonitorGet { config, .. } => config,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let mut emails = recipient_list(current.alert_email.as_deref().unwrap_or(""));
    for e in profile_emails {
        if !emails.iter().any(|x| x.eq_ignore_ascii_case(&e)) {
            emails.push(e);
        }
    }
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::MonitorSet {
            sel,
            enabled: current.enabled,
            url_path: Some(current.url_path),
            interval_secs: Some(current.interval_secs),
            alert_after_fails: Some(current.alert_after_fails),
            alert_email: (!emails.is_empty()).then(|| emails.join(",")),
            // None = keep whatever webhook the monitor already has.
            alert_slack_webhook: profile_slack,
            clear_slack_webhook: false,
            alert_webhook_url: current.alert_webhook_url,
        },
    )
    .await?;
    match resp {
        RpcResponse::MonitorSet => Ok(back("monitor_imported", &profile.name)),
        RpcResponse::Error(e) => Ok(back("monitor_error", &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Split a comma/semicolon/newline-separated address list, dropping blanks
/// and case-insensitive duplicates while keeping the order.
fn recipient_list(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split([',', ';', '\n', '\r']) {
        let a = part.trim();
        if a.is_empty() || out.iter().any(|x| x.eq_ignore_ascii_case(a)) {
            continue;
        }
        out.push(a.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::recipient_list;

    #[test]
    fn recipient_list_splits_trims_and_dedupes() {
        assert_eq!(
            recipient_list(" ops@a.cz, OPS@a.cz;\nsre@a.cz ,, "),
            vec!["ops@a.cz".to_string(), "sre@a.cz".to_string()]
        );
        assert!(recipient_list("  ").is_empty());
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
