//! WAF levels, rule pins and ModSecurity/CRS.

use super::*;

/// The bot families offered in the UI, with whichever are currently on.
/// One WAF rule on the Protection card.
pub struct WafRuleRow {
    pub id: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    /// "Strict" for rules only the Strict level turns on.
    pub strict_only: bool,
    /// `""` (follow the level), `"on"` or `"off"`.
    pub pin: &'static str,
    /// What nginx actually renders for this site.
    pub effective: bool,
    pub counts_for_ban: bool,
}

/// The Core Rule Set block of the Protection card.
pub struct CrsView {
    pub mode: &'static str,
    pub paranoia: i64,
    pub threshold: i64,
    pub wordpress: bool,
    pub exclusions: Vec<CrsExclusionRow>,
}

pub struct CrsExclusionRow {
    /// Position in the stored list — what the remove form names.
    pub index: usize,
    pub rules: String,
    /// Empty = the whole site.
    pub path: String,
}

pub(super) fn crs_view(opts: &hyperion_types::VhostOptions) -> CrsView {
    let s = opts.crs_settings();
    CrsView {
        mode: s.mode.as_str(),
        paranoia: s.paranoia,
        threshold: s.threshold,
        // First switch-on: suggest the WordPress exclusions (the column
        // defaults to on; a never-saved site reads false here).
        wordpress: s.wordpress || s.mode == hyperion_types::crs::CrsMode::Off,
        exclusions: s
            .exclusions
            .iter()
            .enumerate()
            .map(|(index, e)| CrsExclusionRow {
                index,
                rules: e
                    .rules
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(" "),
                path: e.path.clone(),
            })
            .collect(),
    }
}

/// Ask the owning node about its ModSecurity engine. `None` when it cannot
/// say (an older node does not know the request).
pub(crate) async fn fetch_modsec_status(
    state: &SharedState,
    node: Option<&str>,
) -> Option<hyperion_types::crs::ModsecStatus> {
    match crate::dispatcher::dispatch_to_node(state, node, Request::ModsecStatus).await {
        Ok(RpcResponse::ModsecStatus(s)) => Some(s),
        _ => None,
    }
}

/// Hosting kinds whose vhost carries the Protection card's rules. The
/// reverse-proxy and redirect templates have none of them.
pub(super) fn protection_applies(kind: &str) -> bool {
    !matches!(kind, "reverse_proxy" | "redirect")
}

/// One phrase for what the WAF does on this site. A level of Off with rules
/// pinned on still refuses requests, and saying "off" there would hide it.
pub(super) fn waf_summary(level: &str, rows: &[WafRuleRow]) -> String {
    let on = rows.iter().filter(|r| r.effective).count();
    match level {
        "off" if on > 0 => format!(
            "WAF off · {on} rule{} pinned on",
            if on == 1 { "" } else { "s" }
        ),
        "off" => "WAF off".to_string(),
        other => format!("WAF {other}"),
    }
}

pub(super) fn waf_rule_rows(opts: &hyperion_types::VhostOptions, has_php: bool) -> Vec<WafRuleRow> {
    use hyperion_types::waf;
    let level = opts.effective_waf_level();
    let pins = waf::parse_overrides(&opts.waf_overrides);
    let eff = waf::effective_rules(level, &pins, has_php);
    waf::RULES
        .iter()
        .filter(|r| has_php || !r.php_only)
        .map(|r| WafRuleRow {
            id: r.id,
            label: r.label,
            help: r.help,
            strict_only: r.tier == waf::Tier::Strict,
            pin: match pins.get(r.id) {
                Some(true) => "on",
                Some(false) => "off",
                None => "",
            },
            effective: eff.get(r.id),
            counts_for_ban: r.counts_for_ban,
        })
        .collect()
}

pub(super) fn bot_family_rows(
    selected: &str,
) -> Vec<(&'static str, &'static str, &'static str, bool)> {
    let on: Vec<&str> = selected.split(',').map(|s| s.trim()).collect();
    [
        ("ai", "AI scrapers", "GPTBot, ClaudeBot, CCBot, PerplexityBot, Bytespider, Google-Extended and friends — the crawlers that train models on the site", ),
        ("social", "Social previews", "facebookexternalhit, Twitterbot, Instagram, Discord, WhatsApp — blocking these stops link previews from rendering"),
        ("seo", "SEO crawlers", "AhrefsBot, SemrushBot, MJ12bot, DotBot — third-party backlink and audit tools, usually the bulk of nuisance traffic"),
        ("shopping", "Price comparison", "Heureka, Zboží, Google Shopping — block only if the site is not selling through them"),
    ]
    .into_iter()
    .map(|(v, label, desc)| (v, label, desc, on.contains(&v)))
    .collect()
}

/// One row of the WAF activity totals.
pub struct WafTotalRow {
    pub label: &'static str,
    pub rule: String,
    pub day: i64,
    pub week: i64,
}

/// One refused request in the WAF activity list. Everything but the time
/// and address is attacker-controlled; askama escapes it on render.
pub struct WafHitRow {
    pub ago: String,
    pub ip: String,
    pub rule: String,
    pub label: &'static str,
    /// Whether "Allow this" can pin the rule off (catalogue rules only —
    /// a country or bot refusal is changed in its own field).
    pub pinnable: bool,
    pub request: String,
    pub ua: String,
    /// For a Core Rule Set decision: matched rules + score.
    pub detail: String,
    /// Recorded in detection-only mode — not refused.
    pub detected: bool,
    /// "Allow this" for a CRS row: the rules to exclude ("942100 942130")
    /// and the path prefix to exclude them on. Empty for other rows.
    pub crs_rules: String,
    pub crs_path: String,
}

/// WAF activity panel under the Protection card: what was refused, by
/// which rule, and the per-site auto-ban switch.
///
/// The records live on the OWNING node (it reads its own root-owned hit
/// logs), so both the read and the auto-ban switch travel there — the
/// master's local tables would be an empty panel on a multi-node cluster.
#[derive(Template)]
#[template(path = "_hosting_waf_panel.html")]
pub(super) struct WafPanelTpl {
    pub(super) selector: String,
    pub(super) csrf_token: String,
    pub(super) can_edit: bool,
    pub(super) totals: Vec<WafTotalRow>,
    pub(super) day_total: i64,
    /// Requests the Core Rule Set would have refused in detection mode.
    pub(super) day_detected: i64,
    pub(super) hits: Vec<WafHitRow>,
    pub(super) autoban_enabled: bool,
    pub(super) fail2ban_enabled: bool,
    pub(super) threshold: u32,
    pub(super) window_min: i64,
    /// Labels of the rules whose refusals count towards a ban, from the
    /// catalogue — so the copy cannot drift from what the ingest counts.
    pub(super) ban_rules: String,
    pub(super) error: Option<String>,
    pub(super) notice: Option<String>,
}

pub(super) fn waf_ban_rule_labels() -> String {
    hyperion_types::waf::RULES
        .iter()
        .filter(|r| r.counts_for_ban)
        .map(|r| r.label.to_lowercase())
        .collect::<Vec<_>>()
        .join(", ")
}

impl WafPanelTpl {
    pub(super) fn from_activity(
        selector: String,
        csrf_token: String,
        can_edit: bool,
        a: hyperion_types::waf::WafActivity,
    ) -> Self {
        use hyperion_types::waf;
        let mut totals: Vec<WafTotalRow> = a
            .totals_7d
            .iter()
            .map(|w| WafTotalRow {
                label: waf::label_for(&w.rule),
                rule: w.rule.clone(),
                day: a
                    .totals_24h
                    .iter()
                    .find(|d| d.rule == w.rule)
                    .map(|d| d.hits)
                    .unwrap_or(0),
                week: w.hits,
            })
            .collect();
        totals.sort_by(|x, y| y.day.cmp(&x.day).then(y.week.cmp(&x.week)));
        let hits = a
            .recent
            .into_iter()
            .map(|h| {
                let mut request = format!("{} {}", h.method, h.uri);
                if request.len() > 120 {
                    let mut end = 117;
                    while !request.is_char_boundary(end) {
                        end -= 1;
                    }
                    request.truncate(end);
                    request.push('…');
                }
                let crs_rules = if h.rule.starts_with("crs_") {
                    hyperion_types::crs::detail_rule_ids(&h.detail)
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    String::new()
                };
                WafHitRow {
                    ago: crate::handlers::stats::fmt_ago(&h.ts),
                    label: waf::label_for(&h.rule),
                    pinnable: waf::rule(&h.rule).is_some(),
                    detected: hyperion_types::crs::tag_is_detection(&h.rule),
                    crs_path: if crs_rules.is_empty() {
                        String::new()
                    } else {
                        hyperion_types::crs::exclusion_path_for(&h.uri)
                    },
                    crs_rules,
                    rule: h.rule,
                    ip: h.ip,
                    request,
                    ua: h.ua,
                    detail: h.detail,
                }
            })
            .collect();
        Self {
            selector,
            csrf_token,
            can_edit,
            day_total: a
                .totals_24h
                .iter()
                .filter(|c| !hyperion_types::crs::tag_is_detection(&c.rule))
                .map(|c| c.hits)
                .sum(),
            day_detected: a
                .totals_24h
                .iter()
                .filter(|c| hyperion_types::crs::tag_is_detection(&c.rule))
                .map(|c| c.hits)
                .sum(),
            totals,
            hits,
            autoban_enabled: a.autoban_enabled,
            fail2ban_enabled: a.fail2ban_enabled,
            threshold: a.threshold,
            window_min: (a.window_secs / 60).max(1),
            ban_rules: waf_ban_rule_labels(),
            error: None,
            notice: None,
        }
    }

    pub(super) fn failed(selector: String, csrf_token: String, error: String) -> Self {
        Self {
            selector,
            csrf_token,
            can_edit: false,
            totals: vec![],
            day_total: 0,
            day_detected: 0,
            hits: vec![],
            autoban_enabled: true,
            fail2ban_enabled: true,
            threshold: 0,
            window_min: 0,
            ban_rules: waf_ban_rule_labels(),
            error: Some(error),
            notice: None,
        }
    }
}

pub(super) fn waf_panel_error(cause: &str) -> String {
    format!(
        "Could not read WAF activity from this site's node ({cause}). A node that runs an \
         older Hyperion does not record it — update the node if that is the case."
    )
}

/// Fetch the activity from the owning node and render the panel. An older
/// node does not know the request; say so instead of an error page.
pub(super) async fn render_waf_panel(
    state: &SharedState,
    ctx: &AuthCtx,
    selector: String,
    hosting_id: &str,
    owner: Option<&str>,
    notice: Option<String>,
) -> Result<Response, AppError> {
    let csrf_token = crate::handlers::session_csrf_token(state, ctx);
    let can_edit = ctx.can(Capability::HostingEditConfig);
    let resp = crate::dispatcher::dispatch_to_node(
        state,
        owner,
        Request::HostingWafActivity {
            hosting_id: hosting_id.to_string(),
        },
    )
    .await;
    let mut tpl = match resp {
        Ok(RpcResponse::HostingWafActivity(a)) => {
            WafPanelTpl::from_activity(selector, csrf_token, can_edit, a)
        }
        // An older node cannot even decode the request — it drops the
        // connection, so there is no message to recognise. Name the likely
        // cause next to whatever did come back.
        Ok(RpcResponse::Error(e)) => {
            WafPanelTpl::failed(selector, csrf_token, waf_panel_error(&e.to_string()))
        }
        Ok(_) => WafPanelTpl::failed(selector, csrf_token, waf_panel_error("unexpected response")),
        Err(e) => WafPanelTpl::failed(selector, csrf_token, waf_panel_error(&e.to_string())),
    };
    tpl.notice = notice;
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_waf_panel(
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
    render_waf_panel(
        &state,
        &ctx,
        selector,
        detail.id.as_str(),
        owner_node.as_deref(),
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct WafAutobanForm {
    pub selector: String,
    /// "on" lets WAF refusals earn a firewall ban; anything else stops it.
    pub enabled: String,
}

/// Switch WAF auto-ban for one hosting. Writes the OWNING node's kv (that
/// is where the ingest reads it), resolved explicitly — see
/// `post_bruteforce_scan` for why a fallback to the master would lie.
pub async fn post_waf_autoban(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WafAutobanForm>,
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
    let (detail, owner) = find_hosting_anywhere(&state, sel).await?;
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
            key: "waf_autoban_enabled".into(),
            value: value.into(),
        },
    )
    .await;
    let notice = match saved {
        Ok(RpcResponse::HostingKvSet) => None,
        Ok(RpcResponse::Error(e)) => Some(format!("the owning node refused the change: {e}")),
        Ok(_) => Some("unexpected response from the owning node".into()),
        Err(e) => Some(e.to_string()),
    };
    render_waf_panel(
        &state,
        &ctx,
        form.selector.clone(),
        detail.id.as_str(),
        owner.as_deref(),
        notice,
    )
    .await
}

#[derive(Deserialize)]
pub struct WafRuleForm {
    pub selector: String,
    /// Catalogue rule id.
    pub rule: String,
    /// "on", "off", or "" to follow the level again.
    #[serde(default)]
    pub pin: String,
    /// "protection" when posted from the cluster Protection page: a plain
    /// form there, so the outcome is a redirect back with a flash rather
    /// than a re-rendered panel.
    #[serde(default)]
    pub from: String,
}

/// Pin one WAF rule from the activity list ("Allow this" = pin off). Goes
/// through the normal vhost-options save, so it is validated with
/// `nginx -t` like any other change, then re-renders the panel.
pub async fn post_waf_rule(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WafRuleForm>,
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
    if hyperion_types::waf::rule(&form.rule).is_none() {
        return Err(AppError::BadRequest("unknown WAF rule".into()));
    }
    let (detail, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let mut options = detail.vhost_options.clone();
    options.basic_auth_set = false;
    let mut pins = hyperion_types::waf::parse_overrides(&options.waf_overrides);
    match form.pin.trim() {
        "on" => {
            pins.insert(form.rule.clone(), true);
        }
        "off" => {
            pins.insert(form.rule.clone(), false);
        }
        _ => {
            pins.remove(&form.rule);
        }
    }
    options.waf_overrides = hyperion_types::waf::overrides_to_string(&pins);
    let level = options.effective_waf_level();
    options.set_waf_level(level);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingSetVhostOptions {
            sel,
            options,
            basic_auth_password: None,
        },
    )
    .await;
    let label = hyperion_types::waf::label_for(&form.rule);
    if form.from == "protection" {
        let q = match &resp {
            Ok(RpcResponse::HostingSetVhostOptions(_)) => {
                let text = match form.pin.trim() {
                    "off" => format!("\u{201c}{label}\u{201d} is now off for {}.", detail.domain),
                    "on" => format!(
                        "\u{201c}{label}\u{201d} is now always on for {}.",
                        detail.domain
                    ),
                    _ => format!(
                        "\u{201c}{label}\u{201d} follows the level again on {}.",
                        detail.domain
                    ),
                };
                format!("flash={}", urlencoding(&text))
            }
            Ok(RpcResponse::Error(e)) => {
                format!("flash_error={}", urlencoding(&format!("not saved: {e}")))
            }
            Ok(_) => "flash_error=unexpected+response+from+the+owning+node".to_string(),
            Err(e) => format!("flash_error={}", urlencoding(&format!("not saved: {e}"))),
        };
        return Ok(Redirect::to(&format!("/protection?{q}")).into_response());
    }
    let notice = match resp {
        // Reload the whole page, not just this panel: the Protection card's
        // rule selects still hold the old pin, and its next save would put
        // the rule straight back.
        Ok(RpcResponse::HostingSetVhostOptions(_)) => {
            let text = match form.pin.trim() {
                "off" => format!("\u{201c}{label}\u{201d} is now off for this site."),
                "on" => format!("\u{201c}{label}\u{201d} is now always on for this site."),
                _ => format!("\u{201c}{label}\u{201d} follows the level again."),
            };
            return Ok((
                axum::http::StatusCode::NO_CONTENT,
                [
                    ("HX-Refresh", "true".to_string()),
                    (
                        "HX-Trigger",
                        format!(
                            "{{\"toast\":{{\"level\":\"ok\",\"text\":{}}}}}",
                            json_string(&text)
                        ),
                    ),
                ],
            )
                .into_response());
        }
        Ok(RpcResponse::Error(e)) => Some(format!("not saved: {e}")),
        Ok(_) => Some("unexpected response from the owning node".into()),
        Err(e) => Some(format!("not saved: {e}")),
    };
    render_waf_panel(
        &state,
        &ctx,
        form.selector.clone(),
        detail.id.as_str(),
        owner.as_deref(),
        notice,
    )
    .await
}

/// After a change that alters what the page shows in several places: an
/// HTMX caller reloads the page (with a toast), anything else is redirected.
pub(super) fn refresh_with_toast(
    headers: &axum::http::HeaderMap,
    text: &str,
    redirect_to: String,
) -> Response {
    let is_htmx = headers
        .get("HX-Request")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !is_htmx {
        return Redirect::to(&redirect_to).into_response();
    }
    (
        axum::http::StatusCode::NO_CONTENT,
        [
            ("HX-Refresh", "true".to_string()),
            (
                "HX-Trigger",
                format!(
                    "{{\"toast\":{{\"level\":\"ok\",\"text\":{}}}}}",
                    json_string(text)
                ),
            ),
        ],
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CrsExclusionForm {
    pub selector: String,
    /// `add` or `remove`.
    pub op: String,
    /// add: rule ids, separated by spaces or commas.
    #[serde(default)]
    pub rules: String,
    /// add: request-path prefix; empty = the whole site.
    #[serde(default)]
    pub path: String,
    /// remove: the entry's position in the list.
    #[serde(default)]
    pub index: Option<usize>,
}

/// Add or remove one Core Rule Set exclusion — from the Protection card, or
/// as "Allow this" on a CRS row of the activity panel (a path-scoped
/// exclusion of exactly the rules that request matched). Goes through the
/// normal vhost save, so it is validated and `nginx -t`ed like any other.
pub async fn post_crs_exclusion(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<CrsExclusionForm>,
) -> Result<Response, AppError> {
    use hyperion_types::crs;
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
    let back = format!("/hostings/{}#protection", urlencoding(&form.selector));
    let (detail, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let mut options = detail.vhost_options.clone();
    options.basic_auth_set = false;
    let mut list = crs::parse_exclusions(&options.crs_exclusions);
    let done = match form.op.trim() {
        "add" => {
            let mut rules = Vec::new();
            for t in form
                .rules
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|t| !t.is_empty())
            {
                match t.parse::<u32>() {
                    Ok(id) => rules.push(id),
                    Err(_) => {
                        return Ok(save_result(
                            &headers,
                            false,
                            &format!("{t:?} is not a rule id"),
                            back,
                        ))
                    }
                }
            }
            list.push(crs::CrsExclusion {
                rules,
                path: form.path.trim().to_string(),
            });
            if let Err(m) = crs::validate_exclusions(&list) {
                return Ok(save_result(&headers, false, &m, back));
            }
            "CRS exclusion added."
        }
        "remove" => {
            let Some(i) = form.index.filter(|i| *i < list.len()) else {
                return Err(AppError::BadRequest("no such exclusion".into()));
            };
            list.remove(i);
            "CRS exclusion removed."
        }
        _ => return Err(AppError::BadRequest("op must be add or remove".into())),
    };
    options.crs_exclusions = crs::exclusions_to_string(&list);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingSetVhostOptions {
            sel,
            options,
            basic_auth_password: None,
        },
    )
    .await;
    match resp {
        Ok(RpcResponse::HostingSetVhostOptions(_)) => Ok(refresh_with_toast(&headers, done, back)),
        Ok(RpcResponse::Error(e)) => Ok(save_result(&headers, false, &e.to_string(), back)),
        Ok(_) => Err(AppError::Internal("unexpected response".into())),
        Err(e) => Ok(save_result(&headers, false, &e.to_string(), back)),
    }
}

#[derive(Deserialize)]
pub struct ModsecInstallForm {
    pub selector: String,
}

/// Install ModSecurity + the OWASP Core Rule Set on the node that owns this
/// hosting. A package install on a node is an administrator's call; it is
/// slow (apt), so it runs as a background job.
pub async fn post_modsec_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ModsecInstallForm>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let sel = parse_selector(&form.selector)?;
    let (_detail, owner) = find_hosting_anywhere(&state, sel).await?;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "modsec_install",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            reporter
                .step(
                    "Installing ModSecurity and the OWASP Core Rule Set on the node…",
                    10,
                    "",
                )
                .await;
            match crate::dispatcher::dispatch_to_node(
                &job_state,
                owner.as_deref(),
                Request::ModsecInstall,
            )
            .await
            {
                Ok(RpcResponse::ModsecInstall(st)) => {
                    let log = format!(
                        "OWASP Core Rule Set {} installed. Turn it on per site on the \
                         Protection card — start with Detection only.\n",
                        if st.crs_version.is_empty() {
                            "?"
                        } else {
                            st.crs_version.as_str()
                        }
                    );
                    // Sites whose care plan sells the rule set were waiting
                    // for exactly this; switch them on now rather than at the
                    // next hourly pass.
                    reporter
                        .step("Switching on what care plans include…", 90, &log)
                        .await;
                    let plans = match crate::dispatcher::dispatch_to_node(
                        &job_state,
                        owner.as_deref(),
                        Request::PackageEnforceTick,
                    )
                    .await
                    {
                        Ok(RpcResponse::PackageEnforceTick { corrected }) if corrected > 0 => {
                            format!(
                                "Care plans: {corrected} setting{} switched on.\n",
                                if corrected == 1 { "" } else { "s" }
                            )
                        }
                        _ => String::new(),
                    };
                    reporter.step("Installed.", 100, &plans).await;
                    reporter.finish(true, None).await;
                }
                Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
                Ok(_) => {
                    reporter
                        .finish(false, Some("unexpected agent response".into()))
                        .await
                }
                Err(e) => reporter.finish(false, Some(e.to_string())).await,
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

#[cfg(test)]
mod waf_form_tests {
    use super::{waf_rule_rows, VhostOptionsForm};

    fn parse(body: &str) -> VhostOptionsForm {
        // Through axum's own Form extractor — the thing that 422'd.
        use axum::extract::FromRequest;
        let req = axum::http::Request::builder()
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        let axum::Form(f) = rt
            .block_on(axum::Form::<VhostOptionsForm>::from_request(req, &()))
            .expect("form parses");
        f
    }

    /// Several bot families ticked at once used to be a repeated
    /// `blocked_bots` key, which axum's Form answers with a 422.
    #[test]
    fn several_bot_families_parse() {
        let f = parse("selector=x&section=protection&bot_ai=on&bot_seo=on&waf_level=strict");
        assert_eq!(f.blocked_bots(), "ai,seo");
        assert_eq!(f.section, "protection");
    }

    /// The raw snippet textarea is not on the page for users without the
    /// capability; its absence must read as "unchanged", not as "".
    #[test]
    fn a_missing_snippet_field_is_not_an_empty_snippet() {
        assert_eq!(parse("selector=x&section=vhost").custom_nginx_snippet, None);
        assert_eq!(
            parse("selector=x&section=vhost&custom_nginx_snippet=").custom_nginx_snippet,
            Some(String::new())
        );
    }

    #[test]
    fn crs_sub_form_carries_only_its_own_fields() {
        let f = parse("selector=x&section=crs&crs_mode=block&crs_paranoia=2&crs_threshold=10");
        let mut o = hyperion_types::VhostOptions {
            crs_exclusions: r#"[{"rules":[942100]}]"#.into(),
            waf_level: "strict".into(),
            ..Default::default()
        };
        f.apply_crs(&mut o);
        assert_eq!(o.crs_mode, "block");
        assert_eq!(o.crs_paranoia, 2);
        assert_eq!(o.crs_threshold, 10);
        assert!(!o.crs_wordpress, "unticked checkbox");
        assert_eq!(
            o.crs_exclusions, r#"[{"rules":[942100]}]"#,
            "exclusions untouched"
        );
        assert_eq!(o.waf_level, "strict", "WAF untouched");
    }

    #[test]
    fn crs_view_suggests_wordpress_exclusions_before_first_use() {
        let off = super::crs_view(&hyperion_types::VhostOptions::default());
        assert_eq!(off.mode, "off");
        assert!(off.wordpress);
        let on = super::crs_view(&hyperion_types::VhostOptions {
            crs_mode: "detect".into(),
            crs_exclusions: r#"[{"rules":[942100,941160],"path":"/x"}]"#.into(),
            ..Default::default()
        });
        assert!(!on.wordpress, "an explicit choice is kept");
        assert_eq!(on.exclusions[0].rules, "941160 942100");
        assert_eq!(on.exclusions[0].path, "/x");
        assert_eq!(on.exclusions[0].index, 0);
    }

    #[test]
    fn rule_selects_become_pins() {
        let f = parse("selector=x&waf_level=standard&waf_rule_xmlrpc=off&waf_rule_dotfiles=on&waf_rule_probe_args=");
        assert_eq!(f.waf_overrides(), r#"{"dotfiles":true,"xmlrpc":false}"#);
        assert_eq!(parse("selector=x").waf_overrides(), "");
    }

    /// The legacy bool travels with the level: an older node reads only it.
    #[test]
    fn a_chosen_level_carries_the_legacy_bool() {
        let mut o = hyperion_types::VhostOptions::default();
        parse("selector=x&section=protection&waf_level=strict").apply_protection(&mut o);
        assert_eq!(o.waf_level, "strict");
        assert!(o.waf_enabled);
        parse("selector=x&section=protection&waf_level=off").apply_protection(&mut o);
        assert!(!o.waf_enabled);
        // The old single switch: level left for the service to keep.
        parse("selector=x&waf_enabled=on").apply_protection(&mut o);
        assert_eq!(o.waf_level, "");
        assert!(o.waf_enabled);
        // An unknown level is passed through for the service to refuse.
        parse("selector=x&waf_level=paranoid").apply_protection(&mut o);
        assert_eq!(o.waf_level, "paranoid");
    }

    /// Toast text rides in a header that browsers decode as Latin-1: it
    /// must be ASCII, and still decode back to the original text.
    #[test]
    fn toast_json_is_ascii_and_round_trips() {
        let text = "rule 949110 cannot be excluded — “quoted” 😀\n";
        let json = super::json_string(text);
        assert!(json.is_ascii(), "{json}");
        let back: String = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(back, text);
    }

    #[test]
    fn summary_does_not_say_off_while_pinned_rules_refuse() {
        let mut o = hyperion_types::VhostOptions::default();
        assert_eq!(
            super::waf_summary("off", &waf_rule_rows(&o, true)),
            "WAF off"
        );
        o.waf_overrides = r#"{"dotfiles":true}"#.into();
        assert_eq!(
            super::waf_summary("off", &waf_rule_rows(&o, true)),
            "WAF off · 1 rule pinned on"
        );
        assert_eq!(
            super::waf_summary("strict", &waf_rule_rows(&o, true)),
            "WAF strict"
        );
        assert!(!super::protection_applies("reverse_proxy"));
        assert!(!super::protection_applies("redirect"));
        assert!(super::protection_applies("php"));
    }

    #[test]
    fn rule_rows_hide_php_rules_for_static_sites_and_show_pins() {
        let mut o = hyperion_types::VhostOptions::default();
        o.set_waf_level(hyperion_types::waf::WafLevel::Standard);
        o.waf_overrides = r#"{"xmlrpc":false}"#.into();
        let php = waf_rule_rows(&o, true);
        let x = php.iter().find(|r| r.id == "xmlrpc").expect("xmlrpc");
        assert_eq!(x.pin, "off");
        assert!(!x.effective);
        assert!(php.iter().any(|r| r.id == "php_in_uploads" && r.effective));
        assert!(!waf_rule_rows(&o, false)
            .iter()
            .any(|r| r.id == "php_in_uploads"));
    }
}
