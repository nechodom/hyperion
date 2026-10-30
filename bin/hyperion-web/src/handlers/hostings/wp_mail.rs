//! WordPress mail card.

use super::*;

// ============================================================
// WordPress mail
// ============================================================

#[derive(Template)]
#[template(path = "_hosting_wpmail_card.html")]
pub(super) struct WpMailCardTpl {
    pub(super) report: hyperion_types::FtpCheckReport,
    pub(super) selector: String,
    /// The per-site switches, read from the OWNING node, because that is
    /// where the tick reads them — a master-local read would show a switch
    /// wired to nothing.
    pub(super) switches: WpMailSwitches,
    pub(super) csrf_repair: String,
    pub(super) csrf_autofix: String,
    pub(super) csrf_override: String,
    pub(super) error: Option<String>,
    /// Settings → Mail → Largest message on the site's node, when a finding
    /// is fixed there and the viewer may change settings.
    pub(super) size_href: Option<String>,
}

/// The mail card's switches. Absent keys read as the node's own defaults.
#[derive(Clone, Copy)]
pub(super) struct WpMailSwitches {
    /// May the five-minute tick configure this site on its own?
    pub(super) autofix: bool,
    /// May Hyperion change the site's mail at all (sender rewrite, SMTP
    /// takeover)? Off for a site on its own SMTP server.
    pub(super) rewrite: bool,
    /// Is Hyperion currently sending instead of the site's SMTP plugin?
    pub(super) forced: bool,
}

impl Default for WpMailSwitches {
    fn default() -> Self {
        Self {
            autofix: true,
            rewrite: true,
            forced: false,
        }
    }
}

impl WpMailSwitches {
    pub(super) fn from_kv(kv: &[(String, String)]) -> Self {
        let get = |key: &str| kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.trim());
        let rewrite = get("wp_mail_override") != Some("off");
        Self {
            autofix: get("wp_mail_autofix_enabled") != Some("off"),
            rewrite,
            // Only while rewriting is allowed: the node ignores a takeover
            // stamp on a site that is switched off.
            forced: rewrite && get("wp_mail_force_local_at").is_some_and(|v| !v.is_empty()),
        }
    }
}

/// GET /hostings/:selector/wpmail-panel — how this site's WordPress mail is
/// set up, and whether anything has been failing.
pub async fn get_wpmail_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    // The node the site lives on, once known: the size limit is that
    // node's setting, not the master's.
    let site_node = std::sync::OnceLock::<String>::new();
    let card = |mut report: hyperion_types::FtpCheckReport,
                switches: WpMailSwitches,
                error: Option<String>| {
        // The server's mail path is the node's, not the site's: the repair
        // only puts it back for somebody who may change the node's settings
        // (see `post_wpmail_repair`), so nobody else is offered a button
        // that would write the site's half and leave the error standing.
        if !ctx.can(Capability::SettingsManage) {
            for item in report.items.iter_mut() {
                if item.id == "wp_mail_transport" {
                    item.fix.clear();
                }
            }
        }
        let size_href = match site_node.get() {
            Some(node) if report.has_mail_size_fix() && ctx.can(Capability::SettingsManage) => {
                Some(format!(
                    "/settings/mail?node={}#mail-size",
                    urlencoding(node)
                ))
            }
            _ => None,
        };
        Html(
            WpMailCardTpl {
                report,
                selector: selector.clone(),
                switches,
                csrf_repair: csrf_token_for(&state, &ctx, "/hostings/wp/mail-repair"),
                csrf_autofix: csrf_token_for(&state, &ctx, "/hostings/wp/mail-autofix"),
                csrf_override: csrf_token_for(&state, &ctx, "/hostings/wp/mail-override"),
                error,
                size_href,
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
                Default::default(),
                Some(format!("could not read the selector: {e}")),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(card(
                Default::default(),
                Default::default(),
                Some(e.to_string()),
            ))
        }
    };
    // A read probe, so HostingView is the right gate; the repair below is
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
            Default::default(),
            Some("You do not have access to this hosting.".into()),
        ));
    }
    let _ = site_node.set(
        owner
            .clone()
            .unwrap_or_else(|| crate::dispatcher::LOCAL_NODE_SENTINEL.to_string()),
    );
    // Absent or unreadable ⇒ the defaults, matching what the node answers.
    let switches = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingKvList {
            hosting_id: detail.id.as_str().to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => WpMailSwitches::from_kv(&v),
        _ => WpMailSwitches::default(),
    };
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::WpMailSelfCheck { sel },
    )
    .await
    {
        Ok(RpcResponse::WpMailSelfCheck(r)) => Ok(card(r, switches, None)),
        Ok(RpcResponse::Error(e)) => Ok(card(Default::default(), switches, Some(e.to_string()))),
        Ok(_) => Ok(card(
            Default::default(),
            switches,
            Some("unexpected response from the node".into()),
        )),
        Err(e) => Ok(card(Default::default(), switches, Some(e.to_string()))),
    }
}

#[derive(serde::Deserialize)]
pub struct WpMailRepairForm {
    pub selector: String,
}

/// POST /hostings/wp/mail-repair — write the configuration now.
pub async fn post_wpmail_repair(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpMailRepairForm>,
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
    let _ = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::WpMailRepair {
            sel,
            // Starting postfix / fixing postdrop is node-wide: a tenant's
            // "Configure now" gets its own site's half only.
            heal_transport: ctx.can(Capability::SettingsManage),
        },
    )
    .await;
    // Re-render from the node rather than reporting success: a repair the
    // node refused then shows the state the site is actually in, not the
    // state the click implied.
    get_wpmail_panel(State(state), ctx, Path(form.selector)).await
}

#[derive(serde::Deserialize)]
pub struct WpMailAutofixForm {
    pub selector: String,
    pub enabled: String,
}

/// POST /hostings/wp/mail-autofix — per-site switch for the automatic repair.
///
/// Turning it OFF leaves whatever is already on disk exactly as it is: the
/// switch means "stop deciding for me", not "undo what you did", and pulling
/// a working mu-plugin would break the site's mail at the moment somebody
/// asked for less interference.
pub async fn post_wpmail_autofix(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpMailAutofixForm>,
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
        Request::WpMailAutofixSet { sel, enabled },
    )
    .await?;
    // Re-render the whole card so the switch and the findings agree.
    get_wpmail_panel(State(state), ctx, Path(form.selector)).await
}

#[derive(serde::Deserialize)]
pub struct WpMailOverrideForm {
    pub selector: String,
    /// `on`, `off` or `hand_back` — validated by the node.
    pub mode: String,
}

/// POST /hostings/wp/mail-override — may Hyperion change this site's mail?
///
/// `off` is for a site that sends through its own SMTP server and needs its
/// own From address; `hand_back` returns sending to an SMTP plugin Hyperion
/// took it from. The node rewrites the mail plugin straight away.
pub async fn post_wpmail_override(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpMailOverrideForm>,
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
    let _ = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::WpMailOverrideSet {
            sel,
            mode: form.mode.trim().to_string(),
        },
    )
    .await?;
    // Re-render from the node, so the card shows what it actually did.
    get_wpmail_panel(State(state), ctx, Path(form.selector)).await
}

#[cfg(test)]
mod wpmail_card_tests {
    use super::*;

    fn render(kv: &[(&str, &str)]) -> String {
        let kv: Vec<(String, String)> = kv
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        WpMailCardTpl {
            report: Default::default(),
            selector: "mail.cz".into(),
            switches: WpMailSwitches::from_kv(&kv),
            csrf_repair: "r".into(),
            csrf_autofix: "a".into(),
            csrf_override: "o".into(),
            error: None,
            size_href: None,
        }
        .render()
        .expect("render")
    }

    /// A size refusal sends the operator to the node's Largest message
    /// setting — never to the repair, which cannot change the limit.
    #[test]
    fn size_refusal_links_to_the_nodes_limit_not_the_repair() {
        let report = hyperion_types::FtpCheckReport {
            items: vec![hyperion_types::FtpCheckItem {
                id: "wp_mail_transport".into(),
                label: "A message was over this server's size limit".into(),
                severity: "error".into(),
                detail: String::new(),
                fix: "mail_size".into(),
            }],
            ..Default::default()
        };
        let html = WpMailCardTpl {
            report,
            selector: "mail.cz".into(),
            switches: WpMailSwitches::default(),
            csrf_repair: "r".into(),
            csrf_autofix: "a".into(),
            csrf_override: "o".into(),
            error: None,
            size_href: Some("/settings/mail?node=node_a#mail-size".into()),
        }
        .render()
        .expect("render");
        assert!(html.contains(r#"href="/settings/mail?node=node_a#mail-size""#));
        assert!(
            !html.contains("/hostings/wp/mail-repair\""),
            "no repair button"
        );
    }

    /// The default says out loud that Hyperion rewrites the sender, and
    /// offers the switch for a site on its own SMTP server — behind a
    /// confirm, since it changes what every mail of the site looks like.
    #[test]
    fn default_card_says_the_sender_is_rewritten_and_offers_the_switch() {
        let html = render(&[]);
        assert!(html.contains("Hyperion rewrites the sender"));
        assert!(html.contains(r#"name="mode" value="off""#));
        assert!(html.contains("Turn off (own SMTP server)"));
        assert!(html.contains(r#"data-confirm-title="Stop rewriting this site's mail""#));
        assert!(!html.contains("Hand back to the plugin"));
    }

    #[test]
    fn switched_off_card_says_mail_is_left_alone() {
        let html = render(&[
            ("wp_mail_override", "off"),
            // A stale takeover stamp means nothing while rewriting is off.
            ("wp_mail_force_local_at", "123"),
        ]);
        assert!(html.contains("Hyperion leaves mail alone"));
        assert!(html.contains(r#"name="mode" value="on""#));
        assert!(!html.contains("Hand back to the plugin"));
    }

    #[test]
    fn a_takeover_offers_the_hand_back() {
        let html = render(&[("wp_mail_force_local_at", "123")]);
        assert!(html.contains("Hyperion is sending instead of the SMTP plugin"));
        assert!(html.contains(r#"name="mode" value="hand_back""#));
    }
}
