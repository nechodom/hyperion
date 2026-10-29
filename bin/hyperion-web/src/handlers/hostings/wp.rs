//! WordPress tab: install, debug, Redis, plugins, themes, repair and rescue.

use super::*;

#[derive(Deserialize)]
pub struct WpInstallForm {
    pub selector: String,
    pub site_url: String,
    pub title: String,
    pub admin_user: String,
    pub admin_email: String,
    pub admin_password: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub version: String,
}

pub async fn post_wp_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpInstallForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let locale = if form.locale.trim().is_empty() {
        "en_US".to_string()
    } else {
        form.locale.trim().to_string()
    };
    let version = if form.version.trim().is_empty() {
        "latest".to_string()
    } else {
        form.version.trim().to_string()
    };
    let req = WpInstallRequest {
        site_url: form.site_url.trim().to_string(),
        title: form.title.trim().to_string(),
        admin_user: form.admin_user.trim().to_string(),
        admin_email: form.admin_email.trim().to_string(),
        admin_password: form.admin_password,
        locale,
        version,
        // Stand-alone WP install (existing hosting, not part of
        // create flow) — leave no_index off; operator can flip
        // it later in WP admin.
        no_index: false,
    };
    // ── Synchronous pre-flight (authz, form parse, owner-node lookup
    // above) stays on the request thread. Only the WpInstall dispatch —
    // download core, scaffold DB, run wp-cli, which is tens of seconds —
    // detaches into the worker so a dropped browser doesn't abort it.
    //
    // Find owner node so WpInstall lands on the right agent
    // (post-migration the master may not own the row anymore).
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);

    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    // payload_json carries no secrets — admin_password lives only in
    // `req`, in memory, never persisted to the job row.
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "install",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_wp_install_job(reporter, job_state, node, sel, req).await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker: run the WordPress install on the owning node and
/// fold the installed version into the job log.
pub(crate) async fn run_wp_install_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    sel: HostingSelector,
    req: WpInstallRequest,
) {
    reporter
        .step("Installing WordPress — core + database…", 10, "")
        .await;
    match crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::WpInstall { sel, req },
    )
    .await
    {
        Ok(RpcResponse::WpInstall(st)) => {
            let log = format!("WordPress {} installed at {}\n", st.wp_version, st.site_url);
            reporter.step("WordPress installed.", 100, &log).await;
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
}

// ──────────── WP debug + Redis handlers ────────────

#[derive(Deserialize)]
pub struct WpDebugForm {
    pub(super) selector: String,
    #[serde(default)]
    pub(super) target_node: String,
    #[serde(default)]
    pub(super) enabled: Option<String>,
    #[serde(default)]
    pub(super) log: Option<String>,
    #[serde(default)]
    pub(super) display: Option<String>,
}

pub(super) fn redirect_after_wp_extras(form_selector: &str, error: Option<String>) -> Response {
    match error {
        Some(e) => {
            // Two parallel channels so the error is visible no matter
            // where the operator is on the page:
            //   - `flash_error` triggers the top-of-page red toast via
            //     base.html's onload shim. Visible regardless of which
            //     tab is currently active or how far the page is
            //     scrolled — perfect for the post-redirect case where
            //     the form lived inside a deeply-nested card.
            //   - `wp_extras_error` populates the in-card banner so
            //     the message is still there after the toast fades
            //     (7s). Until we wire this banner into every
            //     WP-extras card, it lives inside Debug + Redis only.
            Redirect::to(&format!(
                "/hostings/{}?wp_extras_error={}&flash_error={}#wordpress",
                urlencoding(form_selector),
                urlencoding(&e),
                urlencoding(&e),
            ))
            .into_response()
        }
        None => Redirect::to(&format!(
            "/hostings/{}?wp_extras_saved=1&flash=Settings+saved#wordpress",
            urlencoding(form_selector)
        ))
        .into_response(),
    }
}

pub async fn post_wp_debug(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpDebugForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetWpDebug {
            sel,
            enabled: checkbox_on(&form.enabled),
            log: checkbox_on(&form.log),
            display: checkbox_on(&form.display),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetWpDebug(_) => Ok(redirect_after_wp_extras(&form.selector, None)),
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpRotateForm {
    pub(super) selector: String,
    #[serde(default)]
    pub(super) target_node: String,
}

pub async fn post_wp_debug_log_rotate(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpRotateForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingRotateWpDebugLog { sel },
    )
    .await?;
    match resp {
        RpcResponse::HostingRotateWpDebugLog => Ok(redirect_after_wp_extras(&form.selector, None)),
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpRedisForm {
    pub(super) selector: String,
    #[serde(default)]
    pub(super) target_node: String,
    /// "on" = enable; anything else = disable.
    #[serde(default)]
    pub(super) enabled: String,
}

pub async fn post_wp_redis(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpRedisForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetRedis {
            sel,
            enabled: form.enabled == "on",
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetRedis(_) => Ok(redirect_after_wp_extras(&form.selector, None)),
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_wp_redis_rotate(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpRotateForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingRotateRedisPassword { sel },
    )
    .await?;
    match resp {
        RpcResponse::HostingRotateRedisPassword(_) => {
            Ok(redirect_after_wp_extras(&form.selector, None))
        }
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Template)]
#[template(path = "_hosting_fatal_card.html")]
pub(super) struct FatalCardTpl {
    pub(super) report: hyperion_types::WpFatalReport,
    pub(super) selector: String,
    pub(super) csrf_token: String,
    pub(super) csrf_wp_debug: String,
    pub(super) csrf_dropin: String,
    pub(super) target_node: String,
    pub(super) wp_debug_enabled: bool,
    pub(super) error: Option<String>,
}

/// GET /hostings/:selector/health-panel — is the site throwing a fatal?
///
/// Runs on the OWNING node (the probe goes over that box's loopback, and
/// the wp-cli reproduction needs the site's files). Failures render in the
/// card — the placeholder is a spinner and HTMX discards a non-2xx.
#[derive(serde::Deserialize)]
pub struct EmergencyPluginForm {
    pub selector: String,
    pub slug: String,
}

/// Shared body of the two emergency-plugin actions: authorize, dispatch to
/// the owning node, land back on the WordPress tab with the outcome.
pub(super) async fn emergency_plugin_action(
    state: SharedState,
    ctx: AuthCtx,
    form: EmergencyPluginForm,
    build: impl FnOnce(HostingSelector, String) -> Request,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
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
    let resp =
        crate::dispatcher::dispatch_to_node(&state, node.as_deref(), build(sel, form.slug.clone()))
            .await?;
    match resp {
        RpcResponse::WpEmergencyDisable | RpcResponse::WpEmergencyRestore => {
            Ok(Redirect::to(&format!("/hostings/{sel_url}#wordpress")).into_response())
        }
        RpcResponse::Error(e) => {
            let token = stash_error(&state, &e.to_string()).await;
            Ok(Redirect::to(&format!(
                "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(serde::Deserialize)]
pub struct DropinForm {
    pub selector: String,
    #[serde(default)]
    pub enabled: Option<String>,
}

/// POST /hostings/wp/dropin — park or restore `wp-content/object-cache.php`.
///
/// Deliberately does NOT go through wp-cli: the whole point is that the
/// drop-in stops WordPress booting, so every wp-cli remedy fails too.
pub async fn post_wp_dropin(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DropinForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
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
        Request::WpDropinSet {
            sel,
            enabled: checkbox_on(&form.enabled),
        },
    )
    .await?;
    Ok(match resp {
        RpcResponse::WpDropinSet(m) => Redirect::to(&format!(
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

/// POST /hostings/wp/emergency-disable — park the plugin folder.
pub async fn post_wp_emergency_disable(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<EmergencyPluginForm>,
) -> Result<Response, AppError> {
    emergency_plugin_action(state, ctx, form, |sel, slug| Request::WpEmergencyDisable {
        sel,
        slug,
    })
    .await
}

/// POST /hostings/wp/emergency-restore — folder back, plugin left inactive.
pub async fn post_wp_emergency_restore(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<EmergencyPluginForm>,
) -> Result<Response, AppError> {
    emergency_plugin_action(state, ctx, form, |sel, slug| Request::WpEmergencyRestore {
        sel,
        slug,
    })
    .await
}

#[derive(serde::Deserialize)]
pub struct WpCoreRepairForm {
    pub selector: String,
}

/// POST /hostings/wp/core-repair — replace core files, keep everything else.
pub async fn post_wp_core_repair(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpCoreRepairForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
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
    let resp =
        crate::dispatcher::dispatch_to_node(&state, node.as_deref(), Request::WpCoreRepair { sel })
            .await?;
    Ok(match resp {
        RpcResponse::WpCoreRepair(m) => Redirect::to(&format!(
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

#[derive(serde::Deserialize)]
pub struct WpReinstallForm {
    pub selector: String,
    /// The operator must type the domain. Checked here AND on the node.
    pub confirm_domain: String,
    #[serde(default)]
    pub backup_first: Option<String>,
    pub title: String,
    pub admin_user: String,
    pub admin_email: String,
    #[serde(default)]
    pub locale: String,
    /// Blank (or under 6 chars) means "generate one for me" — same rule the
    /// first install uses. Taken from the operator rather than generated
    /// unconditionally, because a generated password would have to travel
    /// back through the job log, and job logs are persisted.
    #[serde(default)]
    pub admin_password: String,
}

/// POST /hostings/wp/reinstall — wipe the site and install WordPress fresh.
///
/// Gated on `HostingDelete`, not `WpManage`: the outcome is the same class
/// of loss as deleting the hosting, and anyone who can delete can already
/// achieve something worse. Runs as a background job because it is minutes
/// of work and must survive the operator closing the tab.
pub async fn post_wp_reinstall(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpReinstallForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingDelete)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let (detail, node) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            let token = stash_error(&state, &e.to_string()).await;
            return Ok(Redirect::to(&format!(
                "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
            ))
            .into_response());
        }
    };
    // The typed confirmation is checked here as well as on the node. The
    // browser dialog only guards against a misclick — a POST skips it.
    if !form
        .confirm_domain
        .trim()
        .eq_ignore_ascii_case(&detail.domain)
    {
        let token = stash_error(
            &state,
            &format!(
                "Reinstall refused: the confirmation did not match. Type {} exactly.",
                detail.domain
            ),
        )
        .await;
        return Ok(Redirect::to(&format!(
            "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
        ))
        .into_response());
    }

    let generated = form.admin_password.trim().len() < 6;
    let admin_password = if generated {
        generate_wp_admin_password()
    } else {
        form.admin_password.trim().to_string()
    };
    if !is_valid_wp_username(form.admin_user.trim()) {
        let token = stash_error(
            &state,
            &format!(
                "`{}` is not a valid WordPress username (letters, numbers, _, -, @, . only).",
                form.admin_user.trim()
            ),
        )
        .await;
        return Ok(Redirect::to(&format!(
            "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
        ))
        .into_response());
    }
    let req = hyperion_types::WpInstallRequest {
        site_url: format!("https://{}", detail.domain),
        title: if form.title.trim().is_empty() {
            detail.domain.clone()
        } else {
            form.title.trim().to_string()
        },
        admin_user: form.admin_user.trim().to_string(),
        admin_email: form.admin_email.trim().to_string(),
        admin_password: admin_password.clone(),
        locale: if form.locale.trim().is_empty() {
            "en_US".into()
        } else {
            form.locale.trim().to_string()
        },
        version: "latest".into(),
        no_index: false,
    };

    let backup_first = checkbox_on(&form.backup_first);
    let s3_targets = resolve_s3_targets(&state).await;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let confirm = form.confirm_domain.trim().to_string();
    let domain = detail.domain.clone();

    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "wp_reinstall",
        Some(&form.selector),
        // No password in the payload — job payloads are persisted.
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            if backup_first {
                reporter
                    .step("Backing up before the wipe — files + database…", 5, "")
                    .await;
                let backed_up = matches!(
                    crate::dispatcher::dispatch_to_node(
                        &job_state,
                        node.as_deref(),
                        Request::BackupNow {
                            sel: sel.clone(),
                            s3_targets,
                            // "Back up first" before a destructive op runs
                            // inline in this job; no separate sub-step card.
                            progress_job_id: None,
                        },
                    )
                    .await,
                    Ok(RpcResponse::BackupNow(_))
                );
                if !backed_up {
                    // The whole point of the checkbox. A failed backup
                    // followed by a wipe is the worst outcome this feature
                    // can produce, so it stops here with the site intact.
                    reporter
                        .finish(
                            false,
                            Some(
                                "The backup FAILED, so NOTHING was deleted — the site is \
                                 exactly as it was. Fix the backup (Backups tab) and try \
                                 again, or untick \"Back up first\" if you genuinely do \
                                 not want one."
                                    .into(),
                            ),
                        )
                        .await;
                    return;
                }
                reporter.step("Backup complete.", 35, "").await;
            }
            reporter
                .step("Resetting the database and wiping the files…", 45, "")
                .await;
            match crate::dispatcher::dispatch_to_node(
                &job_state,
                node.as_deref(),
                Request::WpReinstall {
                    sel,
                    req,
                    confirm_domain: confirm,
                },
            )
            .await
            {
                Ok(RpcResponse::WpReinstall(m)) => {
                    // The admin password deliberately does not appear here:
                    // job rows are persisted, so anything written to one
                    // outlives the page that showed it.
                    reporter
                        .step(
                            &format!("{m} Sign in at https://{domain}/wp-admin/."),
                            100,
                            "",
                        )
                        .await;
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
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

/// POST /hostings/page-cache/purge — empty the site's FastCGI page cache on
/// its owning node. htmx-driven: answers with the one-line result that
/// replaces the note next to the button.
pub async fn post_page_cache_purge(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PageCachePurgeForm>,
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
    let html = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingPageCachePurge { sel },
    )
    .await
    {
        Ok(RpcResponse::HostingPageCachePurged(0)) => {
            "<span class=\"note\">Nothing was cached.</span>".to_string()
        }
        Ok(RpcResponse::HostingPageCachePurged(n)) => format!(
            "<span class=\"pill ok\">Purged {n} cached page{}</span>",
            if n == 1 { "" } else { "s" }
        ),
        Ok(RpcResponse::Error(e)) => format!(
            "<span class=\"pill err\">Purge failed: {}</span>",
            askama_escape::escape(&e.to_string(), askama_escape::Html)
        ),
        Ok(_) => {
            "<span class=\"pill err\">Purge failed: unexpected agent response</span>".to_string()
        }
        Err(e) => format!(
            "<span class=\"pill err\">Purge failed: {}</span>",
            askama_escape::escape(&e.to_string(), askama_escape::Html)
        ),
    };
    Ok(Html(html).into_response())
}

#[derive(serde::Deserialize)]
pub struct PageCachePurgeForm {
    pub selector: String,
}

#[derive(Deserialize)]
pub struct WpResetForm {
    pub selector: String,
    pub wp_user: String,
    pub new_password: String,
}

/// POST /hostings/:sel/wp/plugins/action
///
/// Single endpoint that dispatches every plugin operation by reading
/// the `action` form field. Keeps the WP plugin tab from sprouting
/// six separate routes (one per verb), and lets the audit log carry
/// the same `wp.plugin.action` event for all of them — the operator
/// only needs to grep for one prefix.
///
/// Form fields:
///   - selector: hosting selector (domain or id)
///   - slug: plugin slug; empty for "update_all"
///   - action: "install" | "activate" | "deactivate" | "update"
///             | "update_all" | "delete" | "auto_update_enable"
///             | "auto_update_disable"
///   - source: only required when action="install" — wp.org slug or URL
#[derive(Deserialize)]
pub struct WpPluginActionForm {
    pub selector: String,
    /// Install without activating. Off by default.
    #[serde(default)]
    pub install_only: Option<String>,
    #[serde(default)]
    pub slug: String,
    pub action: String,
    #[serde(default)]
    pub source: String,
    /// "vulns" when the update button on /vulns sent it — a successful
    /// update goes back there. Anything else returns to the site.
    #[serde(default)]
    pub back: String,
}

#[derive(Deserialize)]
pub struct WpThemeActionForm {
    pub selector: String,
    #[serde(default)]
    pub slug: String,
    pub action: String,
    #[serde(default)]
    pub source: String,
    /// Carries the hosting's node id (injected by the detail
    /// page's JS shim) so the dispatch lands on the right agent.
    #[serde(default)]
    pub target_node: String,
    /// Same as [`WpPluginActionForm::back`].
    #[serde(default)]
    pub back: String,
}

/// A plugin/theme update started from /vulns goes back there. That page
/// reads the STORED scans, so re-scan the site first (the scan saves itself)
/// — otherwise the row would still list the update just applied.
async fn back_to_vulns(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
    flash: &str,
) -> Response {
    let _ =
        crate::dispatcher::dispatch_to_node(state, target, Request::WpVulnScan { hosting: sel })
            .await;
    Redirect::to(&format!("/vulns?flash={}", urlencoding(flash))).into_response()
}

/// POST /hostings/wp/theme-action — single endpoint for every
/// whitelisted theme verb. Mirrors post_wp_plugin_action but
/// follows the hosting via target_node.
pub async fn post_wp_theme_action(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpThemeActionForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let action = match form.action.as_str() {
        "install" => {
            let source = form.source.trim().to_string();
            if source.is_empty() {
                return Err(AppError::BadRequest(
                    "theme install requires a source (slug or https URL)".into(),
                ));
            }
            hyperion_types::WpThemeAction::Install { source }
        }
        "activate" => hyperion_types::WpThemeAction::Activate,
        "update" => hyperion_types::WpThemeAction::Update,
        "update_all" => hyperion_types::WpThemeAction::UpdateAll,
        "delete" => hyperion_types::WpThemeAction::Delete,
        other => {
            return Err(AppError::BadRequest(format!(
                "unknown wp theme action: {}",
                askama_escape::escape(other, askama_escape::Html)
            )));
        }
    };
    let slug = match &action {
        hyperion_types::WpThemeAction::UpdateAll => String::new(),
        hyperion_types::WpThemeAction::Install { source } => source.clone(),
        _ => {
            let s = form.slug.trim().to_string();
            if s.is_empty() {
                return Err(AppError::BadRequest("missing theme slug".into()));
            }
            s
        }
    };
    // The detail page's shim names the node; a form without it (the /vulns
    // update button) is routed to the hosting's owner like the plugin path.
    let target: Option<String> = if form.target_node == crate::dispatcher::LOCAL_NODE_SENTINEL {
        None
    } else if form.target_node.is_empty() {
        find_hosting_anywhere(&state, sel.clone())
            .await
            .ok()
            .and_then(|(_d, n)| n)
    } else {
        Some(form.target_node.clone())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::WpThemeAction {
            sel: sel.clone(),
            slug,
            action,
        },
    )
    .await?;
    match resp {
        RpcResponse::WpThemeAction(r) => {
            if r.state == "failed" {
                // Full text through the hand-off, including wp-cli's own
                // output — same reasoning as the plugin path.
                let detail_text = if r.output_tail.trim().is_empty() {
                    r.message.clone()
                } else {
                    format!("{}\n\n{}", r.message, r.output_tail)
                };
                let token = stash_error(&state, &format!("Theme failed: {detail_text}")).await;
                return Ok(Redirect::to(&format!(
                    "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
                ))
                .into_response());
            }
            if form.back == "vulns" {
                let msg = format!("Theme {}: {}", r.state, r.message);
                return Ok(back_to_vulns(&state, target.as_deref(), sel, &msg).await);
            }
            let msg = urlencoding(&format!("Theme {}: {}", r.state, r.message));
            Ok(
                Redirect::to(&format!("/hostings/{sel_url}?wp_flash={msg}#wordpress"))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/{}?wp_error_ref={}#wordpress",
            sel_url,
            stash_error(&state, &e.to_string()).await
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// derive_master_url is the shared helper in handlers::mod — see
// there for the loopback-detection + public-IP fallback rationale.
// Hostings caller imports via the crate::handlers:: path below.

pub async fn post_wp_plugin_action(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpPluginActionForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // Map the form's `action` string into the typed enum. Anything not
    // on the whitelist gets a 400 — the UI shouldn't be able to send it.
    let action = match form.action.as_str() {
        "install" => {
            let source = form.source.trim().to_string();
            if source.is_empty() {
                return Err(AppError::BadRequest(
                    "plugin install requires a source (slug or https URL)".into(),
                ));
            }
            // Activate by default — the buttons that reach here all say
            // "install & activate". `install_only=1` opts out, for putting a
            // plugin in place without loading its code.
            hyperion_types::WpPluginAction::Install {
                source,
                activate: !checkbox_on(&form.install_only),
            }
        }
        "activate" => hyperion_types::WpPluginAction::Activate,
        "deactivate" => hyperion_types::WpPluginAction::Deactivate,
        "update" => hyperion_types::WpPluginAction::Update,
        "update_all" => hyperion_types::WpPluginAction::UpdateAll,
        "delete" => hyperion_types::WpPluginAction::Delete,
        "auto_update_enable" => hyperion_types::WpPluginAction::SetAutoUpdate { enabled: true },
        "auto_update_disable" => hyperion_types::WpPluginAction::SetAutoUpdate { enabled: false },
        "resume_auto_update" => hyperion_types::WpPluginAction::ResumeAutoUpdate,
        other => {
            return Err(AppError::BadRequest(format!(
                "unknown wp plugin action: {}",
                askama_escape::escape(other, askama_escape::Html)
            )));
        }
    };
    // slug is meaningless for `update_all` and `install` (the latter
    // gets the slug from `source`). For everything else it MUST validate.
    let slug = match &action {
        hyperion_types::WpPluginAction::UpdateAll => String::new(),
        hyperion_types::WpPluginAction::Install { source, .. } => source.clone(),
        _ => {
            let s = form.slug.trim().to_string();
            if s.is_empty() {
                return Err(AppError::BadRequest("missing plugin slug".into()));
            }
            s
        }
    };
    // WordPress lives on the owning node — dispatch there (the plugin
    // LIST is already read from the owner). Master-local made every
    // plugin install/activate/update fail on worker-hosted sites, while
    // the sibling theme action worked.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::WpPluginAction {
            hosting: sel.clone(),
            slug,
            action,
        },
    )
    .await?;
    match resp {
        RpcResponse::WpPluginAction(r) => {
            let ok = r.state == "ok" || r.state == "noop";
            if ok && form.back == "vulns" {
                let msg = format!("Plugin {}: {}", r.state, r.message);
                return Ok(back_to_vulns(&state, target_owned.as_deref(), sel, &msg).await);
            }
            if ok {
                // Success stays a short query-string flash — there is nothing
                // to read.
                let q = urlencoding(&format!("Plugin {}: {}", r.state, r.message));
                return Ok(
                    Redirect::to(&format!("/hostings/{sel_url}?flash={q}#wordpress"))
                        .into_response(),
                );
            }
            // Failure goes through the server-side hand-off with the FULL
            // text. This path used to `take(140)` and put the result in the
            // query string, which is what cut an operator's error off
            // mid-command and told them nothing. `output_tail` is the real
            // wp-cli output — up to 4 KiB of it — and it was produced,
            // typed, carried over RPC, and then thrown away here.
            let detail_text = if r.output_tail.trim().is_empty() {
                r.message.clone()
            } else {
                format!("{}\n\n{}", r.message, r.output_tail)
            };
            let token = stash_error(&state, &format!("Plugin {}: {detail_text}", r.state)).await;
            Ok(Redirect::to(&format!(
                "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
            ))
            .into_response())
        }
        RpcResponse::Error(e) => {
            let token = stash_error(&state, &format!("Plugin action failed: {e}")).await;
            Ok(Redirect::to(&format!(
                "/hostings/{sel_url}?wp_error_ref={token}#wordpress"
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_wp_reset(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpResetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector, Capability::WpManage)
        .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // WordPress lives on the owning node — dispatch there, not the
    // master local socket (NotFound for a worker-hosted site).
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::WpResetPassword {
            sel,
            wp_user: form.wp_user.trim().to_string(),
            new_password: form.new_password,
        },
    )
    .await?;
    match resp {
        RpcResponse::WpResetPassword => {
            Ok(Redirect::to(&format!("/hostings/{}?wp=reset", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let token = stash_error(&state, &e.to_string()).await;
            Ok(
                Redirect::to(&format!("/hostings/{}?wp_error_ref={}", sel_url, token))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
