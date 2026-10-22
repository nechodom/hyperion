//! nginx vhost options, upstream, aliases and www normalisation.

use super::*;

#[derive(Deserialize)]
pub struct ProxyUpstreamForm {
    pub selector: String,
    /// New upstream origin, e.g. `http://127.0.0.1:8080`. Validated and
    /// re-serialized service-side by `nginx::validate_upstream_url`.
    pub upstream_url: String,
}

/// Change a reverse-proxy hosting's upstream URL, then re-render its vhost.
/// Owner-dispatched: the vhost lives on the node that owns the hosting, so
/// this must reach that node (mirrors `post_set_expiry`), not master-local.
pub async fn post_proxy_upstream(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ProxyUpstreamForm>,
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
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::HostingSetProxyUpstream {
            sel,
            upstream_url: form.upstream_url.trim().to_string(),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetProxyUpstream(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?proxy_saved=1", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?proxy_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct VhostOptionsForm {
    pub(super) selector: String,
    #[serde(default)]
    pub(super) target_node: String,
    // Use stringly "on" semantics — HTML checkboxes don't send
    // false values, so #[serde(default)] + presence check.
    #[serde(default)]
    pub(super) basic_auth_enabled: Option<String>,
    #[serde(default)]
    pub(super) basic_auth_user: String,
    /// Operator-typed new password. Empty string = leave hash alone.
    #[serde(default)]
    pub(super) basic_auth_password: String,
    #[serde(default)]
    pub(super) force_https: Option<String>,
    #[serde(default)]
    pub(super) hsts_max_age: i64,
    /// Absent when the card was rendered for someone without the raw-nginx
    /// capability (the textarea is not on the page at all) — that means
    /// "leave it", not "set it to empty".
    #[serde(default)]
    pub(super) custom_nginx_snippet: Option<String>,
    #[serde(default)]
    pub(super) maintenance_mode: Option<String>,
    #[serde(default)]
    pub(super) fastcgi_cache_enabled: Option<String>,
    #[serde(default)]
    pub(super) fastcgi_cache_ttl: i64,
    #[serde(default)]
    pub(super) redirect_url: String,
    #[serde(default)]
    pub(super) redirect_code: i64,
    #[serde(default)]
    pub(super) redirect_preserve_path: Option<String>,
    /// Which card posted: `protection`, `vhost`, or empty for a caller that
    /// sends every field at once. A card's save only changes that card's
    /// fields — the rest come from what is stored, so saving HTTPS never
    /// resets the WAF and the reverse.
    #[serde(default)]
    pub(super) section: String,
    /// Legacy single switch; only read when `waf_level` is absent.
    #[serde(default)]
    pub(super) waf_enabled: Option<String>,
    #[serde(default)]
    pub(super) waf_level: String,
    // One select per catalogue rule: "" (follow the level), "on", "off".
    // Fixed fields, not a map: they are the whole catalogue, and a fixed
    // field cannot smuggle an unknown rule id into the stored JSON.
    #[serde(default)]
    pub(super) waf_rule_probe_args: String,
    #[serde(default)]
    pub(super) waf_rule_scanner_ua: String,
    #[serde(default)]
    pub(super) waf_rule_xmlrpc: String,
    #[serde(default)]
    pub(super) waf_rule_sensitive_files: String,
    #[serde(default)]
    pub(super) waf_rule_dump_files: String,
    #[serde(default)]
    pub(super) waf_rule_php_in_uploads: String,
    #[serde(default)]
    pub(super) waf_rule_dotfiles: String,
    #[serde(default)]
    pub(super) waf_rule_author_enum: String,
    #[serde(default)]
    pub(super) waf_rule_rest_user_enum: String,
    #[serde(default)]
    pub(super) waf_rule_bad_methods: String,
    #[serde(default)]
    pub(super) waf_rule_empty_ua: String,
    #[serde(default)]
    pub(super) signup_limit_enabled: Option<String>,
    // One checkbox per bot family. NOT a repeated `blocked_bots` key:
    // axum's urlencoded Form cannot collect repeated keys into a Vec and
    // answered every save with a ticked family with a 422.
    #[serde(default)]
    pub(super) bot_ai: Option<String>,
    #[serde(default)]
    pub(super) bot_social: Option<String>,
    #[serde(default)]
    pub(super) bot_seo: Option<String>,
    #[serde(default)]
    pub(super) bot_shopping: Option<String>,
    // OWASP Core Rule Set sub-form (`section=crs`). The service validates.
    #[serde(default)]
    pub(super) crs_mode: String,
    #[serde(default)]
    pub(super) crs_paranoia: i64,
    #[serde(default)]
    pub(super) crs_threshold: i64,
    #[serde(default)]
    pub(super) crs_wordpress: Option<String>,
    /// Comma-separated ISO codes from the text field.
    #[serde(default)]
    pub(super) blocked_countries: Option<String>,
    #[serde(default)]
    pub(super) wp_admin_allowlist: String,
    #[serde(default)]
    pub(super) canonical_host: String,
    #[serde(default)]
    pub(super) noindex: Option<String>,
}

impl VhostOptionsForm {
    /// The rule pins the form asks for, as stored JSON.
    pub(super) fn waf_overrides(&self) -> String {
        let mut map = std::collections::BTreeMap::new();
        for (id, v) in [
            ("probe_args", &self.waf_rule_probe_args),
            ("scanner_ua", &self.waf_rule_scanner_ua),
            ("xmlrpc", &self.waf_rule_xmlrpc),
            ("sensitive_files", &self.waf_rule_sensitive_files),
            ("dump_files", &self.waf_rule_dump_files),
            ("php_in_uploads", &self.waf_rule_php_in_uploads),
            ("dotfiles", &self.waf_rule_dotfiles),
            ("author_enum", &self.waf_rule_author_enum),
            ("rest_user_enum", &self.waf_rule_rest_user_enum),
            ("bad_methods", &self.waf_rule_bad_methods),
            ("empty_ua", &self.waf_rule_empty_ua),
        ] {
            match v.trim() {
                "on" => {
                    map.insert(id.to_string(), true);
                }
                "off" => {
                    map.insert(id.to_string(), false);
                }
                _ => {}
            }
        }
        hyperion_types::waf::overrides_to_string(&map)
    }

    /// Copy the Protection card's fields onto `options`.
    pub(super) fn apply_protection(&self, options: &mut hyperion_types::VhostOptions) {
        match hyperion_types::waf::WafLevel::parse(&self.waf_level) {
            // Through `set_waf_level`, so the legacy bool moves with the
            // level: a node that predates the rework reads only the bool.
            Some(level) => {
                options.set_waf_level(level);
                options.waf_overrides = self.waf_overrides();
            }
            None if self.waf_level.trim().is_empty() => {
                // A caller that only knows the old switch: the service keeps
                // the stored level and pins while the switch agrees with them.
                options.waf_level = String::new();
                options.waf_enabled = checkbox_on(&self.waf_enabled);
                options.waf_overrides = String::new();
            }
            // Unknown value: passed on for the service to refuse by name.
            None => options.waf_level = self.waf_level.trim().to_string(),
        }
        options.signup_limit_enabled = checkbox_on(&self.signup_limit_enabled);
        options.blocked_bots = self.blocked_bots();
        // Sanitized again in the renderer, but rejecting non-codes here too
        // means the DB never stores something the vhost would drop — the
        // saved value and the applied value stay the same thing.
        options.blocked_countries = self
            .blocked_countries
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(|c| c.trim().to_ascii_uppercase())
            .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
            .collect::<Vec<_>>()
            .join(",");
        options.wp_admin_allowlist = self.wp_admin_allowlist.trim().to_string();
    }

    /// Copy the Core Rule Set sub-form onto `options`. Exclusions are not
    /// part of it — they have their own add/remove forms.
    pub(super) fn apply_crs(&self, options: &mut hyperion_types::VhostOptions) {
        options.crs_mode = self.crs_mode.trim().to_string();
        options.crs_paranoia = self.crs_paranoia;
        options.crs_threshold = self.crs_threshold;
        options.crs_wordpress = checkbox_on(&self.crs_wordpress);
    }

    pub(super) fn blocked_bots(&self) -> String {
        [
            ("ai", &self.bot_ai),
            ("social", &self.bot_social),
            ("seo", &self.bot_seo),
            ("shopping", &self.bot_shopping),
        ]
        .into_iter()
        .filter(|(_, v)| checkbox_on(v))
        .map(|(f, _)| f)
        .collect::<Vec<_>>()
        .join(",")
    }
}

pub(super) fn checkbox_on(v: &Option<String>) -> bool {
    v.as_deref()
        .map(|s| matches!(s, "on" | "true" | "1" | "yes"))
        .unwrap_or(false)
}

pub async fn post_vhost_options(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<VhostOptionsForm>,
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
    // The raw nginx snippet is spliced verbatim into a config that root
    // loads, so it is gated on its OWN capability rather than travelling
    // with the rest of the hosting settings — see HostingEditNginxRaw.
    //
    // A caller without it keeps whatever is stored instead of being
    // refused outright: the field ships inside the same form as every
    // other vhost setting, so dropping the submitted value would let a
    // tenant WIPE an admin's snippet by saving an unrelated checkbox.
    // Only an actual attempt to CHANGE it is an error.
    let section = form.section.trim();
    let (save_vhost, save_protection, save_crs) = match section {
        "vhost" => (true, false, false),
        "protection" => (false, true, false),
        "crs" => (false, false, true),
        _ => (true, true, false),
    };
    // Every save starts from what is stored, and a card's save only
    // overwrites its own fields. A per-card save therefore NEEDS the stored
    // options: falling back to defaults would reset the other card.
    let stored = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((d, _)) => d.vhost_options,
        Err(e) if section.is_empty() => {
            tracing::debug!(error = %e, "vhost-options: stored lookup failed; full-form save");
            hyperion_types::VhostOptions::default()
        }
        Err(e) => return Err(e),
    };
    let mut options = stored.clone();
    // The service decides from the password + what exists.
    options.basic_auth_set = false;
    if save_vhost {
        // The raw nginx snippet is spliced verbatim into a config that root
        // loads, so it is gated on its OWN capability rather than travelling
        // with the rest of the hosting settings — see HostingEditNginxRaw.
        //
        // A caller without it keeps whatever is stored instead of being
        // refused outright: the field ships inside the same form as every
        // other vhost setting, so dropping the submitted value would let a
        // tenant WIPE an admin's snippet by saving an unrelated checkbox.
        // Only an actual attempt to CHANGE it is an error.
        // A form without the field at all — the card hides the textarea
        // from anyone without the capability — changes nothing either:
        // treating the missing field as "" refused every save such a user
        // made on a site whose admin had written a snippet.
        let submitted_snippet = form.custom_nginx_snippet.as_deref();
        if !ctx.can(Capability::HostingEditNginxRaw)
            && submitted_snippet.is_some_and(|v| v.trim() != stored.custom_nginx_snippet.trim())
        {
            return Ok((
                axum::http::StatusCode::FORBIDDEN,
                [("content-type", "text/html; charset=utf-8")],
                "<h1>403 Forbidden</h1><p>Editing the raw nginx snippet needs the \
                 \"Write raw nginx config\" capability — nginx runs as root, so that \
                 field is admin-level.</p>"
                    .to_string(),
            )
                .into_response());
        }
        if let (true, Some(v)) = (ctx.can(Capability::HostingEditNginxRaw), submitted_snippet) {
            options.custom_nginx_snippet = v.to_string();
        }
        options.basic_auth_enabled = checkbox_on(&form.basic_auth_enabled);
        options.basic_auth_user = form.basic_auth_user.trim().to_string();
        options.force_https = checkbox_on(&form.force_https);
        options.hsts_max_age = form.hsts_max_age;
        options.maintenance_mode = checkbox_on(&form.maintenance_mode);
        options.fastcgi_cache_enabled = checkbox_on(&form.fastcgi_cache_enabled);
        options.fastcgi_cache_ttl = form.fastcgi_cache_ttl;
        options.redirect_url = form.redirect_url.trim().to_string();
        options.redirect_code = form.redirect_code;
        options.redirect_preserve_path = checkbox_on(&form.redirect_preserve_path);
        options.canonical_host = form.canonical_host.trim().to_string();
        options.noindex = checkbox_on(&form.noindex);
    }
    if save_protection {
        form.apply_protection(&mut options);
    }
    if save_crs {
        form.apply_crs(&mut options);
    }
    let pw_opt = if form.basic_auth_password.is_empty() || !save_vhost {
        None
    } else {
        Some(form.basic_auth_password)
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetVhostOptions {
            sel,
            options,
            basic_auth_password: pw_opt,
        },
    )
    .await?;
    let sel_url = urlencoding(&form.selector);
    match resp {
        RpcResponse::HostingSetVhostOptions(_) => Ok(save_result(
            &headers,
            true,
            if save_vhost {
                "HTTP & access settings saved."
            } else if save_crs {
                "Core Rule Set settings saved."
            } else {
                "Protection settings saved."
            },
            format!("/hostings/{sel_url}?vhost_saved=1"),
        )),
        RpcResponse::Error(e) => {
            // The verbatim nginx -t output (or validation error) reaches the
            // operator either way: as a toast under HTMX, or in the banner
            // the query string drives on a full navigation.
            Ok(save_result(
                &headers,
                false,
                &e.to_string(),
                format!(
                    "/hostings/{sel_url}?vhost_error={}",
                    urlencoding(&e.to_string())
                ),
            ))
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct NormalizeWwwForm {
    pub selector: String,
    #[serde(default)]
    pub target_node: String,
}

/// POST /hostings/normalize-www — move a hosting whose primary name is
/// `www.<name>` onto the bare `<name>`.
///
/// This is deliberately NOT an on-disk rename: the home directory, certificate
/// directory, vhost file, DKIM keys, FTP logins and log paths are all derived
/// from the primary name, and moving them under a live site is how outages
/// happen. The visitor-facing result is the same, though: the bare name is
/// added as an alias (so it is served and put into the certificate), the
/// certificate is re-issued, and only THEN is the canonical hostname switched
/// so `www.<name>` 301s to `<name>` (WordPress's Site Address follows, and the
/// redirect-loop probe rolls it back if it cycles). Every step that could
/// leave visitors on a dead address is checked first, and a failed step puts
/// the aliases back.
pub async fn post_normalize_www(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NormalizeWwwForm>,
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
    if !ctx.can(Capability::CertManage) {
        return Err(AppError::Forbidden);
    }
    let (detail, node) = find_hosting_anywhere(&state, sel).await?;
    let sel_url = urlencoding(&form.selector);
    let Some(bare) = bare_name_of(&detail.domain) else {
        return Ok(Redirect::to(&format!(
            "/hostings/{sel_url}?flash_error={}",
            urlencoding("This hosting's name does not start with www. — nothing to move.")
        ))
        .into_response());
    };

    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "normalize_www",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_normalize_www_job(reporter, job_state, node, detail, bare).await;
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

/// `www.example.cz` → `Some("example.cz")`; `None` when there is no `www.`
/// prefix to drop or dropping it would leave a single label.
pub(super) fn bare_name_of(domain: &str) -> Option<String> {
    domain
        .strip_prefix("www.")
        .filter(|rest| rest.contains('.'))
        .map(str::to_string)
}

pub(super) async fn run_normalize_www_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    detail: HostingDetail,
    bare: String,
) {
    match normalize_www_steps(&reporter, &state, node.as_deref(), &detail, &bare).await {
        Ok(()) => {
            reporter
                .step(
                    &format!(
                        "Done: {bare} is the canonical address, {} redirects to it.",
                        detail.domain
                    ),
                    100,
                    "",
                )
                .await;
            reporter.finish(true, None).await;
        }
        Err(e) => reporter.finish(false, Some(e)).await,
    }
}

pub(super) async fn normalize_www_steps(
    reporter: &crate::handlers::jobs::JobReporter,
    state: &SharedState,
    node: Option<&str>,
    detail: &HostingDetail,
    bare: &str,
) -> Result<(), String> {
    use crate::dispatcher::dispatch_to_node;
    let bare_dom = Domain::parse(bare).map_err(|e| e.to_string())?;
    let sel = HostingSelector::Id(detail.id.clone());

    reporter
        .step(&format!("Checking that {bare} is free…"), 5, "")
        .await;
    if let Ok(rows) = list_hostings(state).await {
        if rows
            .iter()
            .any(|h| h.id != detail.id && h.domain.eq_ignore_ascii_case(bare))
        {
            return Err(format!(
                "{bare} is already a separate hosting in this cluster."
            ));
        }
    }

    // Never redirect visitors to an address that does not reach this node.
    reporter
        .step(&format!("Checking DNS for {bare}…"), 15, "")
        .await;
    match dispatch_to_node(state, node, Request::DnsCheck { domain: bare_dom.clone() }).await {
        Ok(RpcResponse::DnsCheck(r)) if r.matches => {}
        Ok(RpcResponse::DnsCheck(r)) => {
            return Err(format!(
                "DNS for {bare} does not point at this server yet ({}). Point it here, then run this again — nothing was changed.",
                r.note
            ))
        }
        Ok(RpcResponse::Error(e)) => return Err(e.to_string()),
        Ok(_) => return Err("unexpected agent response".into()),
        Err(e) => return Err(e.to_string()),
    }

    reporter
        .step(&format!("Adding {bare} as an alias…"), 30, "")
        .await;
    let old_aliases = detail.aliases.clone();
    let mut with_bare: Vec<Domain> = old_aliases
        .iter()
        .filter_map(|a| Domain::parse(a).ok())
        .collect();
    if !old_aliases.iter().any(|a| a == bare) {
        with_bare.push(bare_dom);
    }
    match dispatch_to_node(
        state,
        node,
        Request::HostingSetAliases {
            sel: sel.clone(),
            aliases: with_bare,
        },
    )
    .await
    {
        Ok(RpcResponse::HostingSetAliases(_)) => {}
        Ok(RpcResponse::Error(e)) => return Err(format!("could not add the alias: {e}")),
        Ok(_) => return Err("unexpected agent response".into()),
        Err(e) => return Err(e.to_string()),
    }

    let revert = || async {
        let restore: Vec<Domain> = old_aliases
            .iter()
            .filter_map(|a| Domain::parse(a).ok())
            .collect();
        let _ = dispatch_to_node(
            state,
            node,
            Request::HostingSetAliases {
                sel: sel.clone(),
                aliases: restore,
            },
        )
        .await;
    };

    reporter
        .step("Issuing a certificate that covers both names…", 45, "")
        .await;
    let cert_req = CertIssueRequest {
        staging: false,
        require_dns_match: true,
        extra_sans: vec![],
    };
    match dispatch_to_node(
        state,
        node,
        Request::CertIssueAcme {
            sel: sel.clone(),
            req: cert_req,
        },
    )
    .await
    {
        Ok(RpcResponse::CertIssueAcme(_)) => {}
        Ok(RpcResponse::Error(e)) => {
            revert().await;
            return Err(format!("certificate not issued, aliases put back: {e}"));
        }
        Ok(_) => {
            revert().await;
            return Err("unexpected agent response".into());
        }
        Err(e) => {
            revert().await;
            return Err(e.to_string());
        }
    }

    reporter
        .step(&format!("Redirecting {} to {bare}…", detail.domain), 75, "")
        .await;
    let mut options = detail.vhost_options.clone();
    options.canonical_host = "non-www".into();
    match dispatch_to_node(
        state,
        node,
        Request::HostingSetVhostOptions { sel, options, basic_auth_password: None },
    )
    .await
    {
        Ok(RpcResponse::HostingSetVhostOptions(_)) => Ok(()),
        // The alias and certificate stay: both names work, nothing redirects.
        Ok(RpcResponse::Error(e)) => Err(format!(
            "both names are served and covered by the certificate, but the redirect was not applied: {e}"
        )),
        Ok(_) => Err("unexpected agent response".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct AliasesForm {
    pub selector: String,
    /// Comma / space / newline separated alias domains. Empty clears all.
    #[serde(default)]
    pub aliases: String,
    #[serde(default)]
    pub target_node: String,
}

/// POST /hostings/aliases — replace a hosting's alias domains (SANs) after
/// creation. Rewrites the nginx vhost server_name + reloads on the owning node.
/// Newly-added aliases need a cert re-issue (SSL tab) to be covered by HTTPS.
pub async fn post_set_aliases(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<AliasesForm>,
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
    let aliases = match parse_aliases(&form.aliases) {
        Ok(a) => a,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?flash_error={}#access",
                sel_url,
                urlencoding(&format!("Invalid alias: {e}"))
            ))
            .into_response());
        }
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetAliases { sel, aliases },
    )
    .await?;
    let flash = match resp {
        RpcResponse::HostingSetAliases(_) => {
            "Aliases updated. Re-issue the certificate (SSL tab) to cover any new names."
                .to_string()
        }
        RpcResponse::Error(e) => format!("Couldn't update aliases: {e}"),
        _ => "Aliases: unexpected response".into(),
    };
    Ok(Redirect::to(&format!(
        "/hostings/{}?flash={}#access",
        sel_url,
        urlencoding(&flash)
    ))
    .into_response())
}

pub(super) fn parse_aliases(input: &str) -> Result<Vec<Domain>, String> {
    let mut out = Vec::new();
    for piece in input.split(|c: char| c == ',' || c.is_whitespace()) {
        let p = piece.trim();
        if p.is_empty() {
            continue;
        }
        match Domain::parse(p) {
            Ok(d) => out.push(d),
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(out)
}
