use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::{DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector};
use hyperion_types::{
    CertIssueRequest, DbProvision, DnsCheckResult, HostingDetail, HostingProfile, HostingStats,
    HostingSummary, PhpVersion, ProfileApply, SpfCheckResult, WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::{Domain, SystemUserName};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Template)]
#[template(path = "hostings_list.html")]
struct ListTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    rows: Vec<HostingSummary>,
    total_count: usize,
    q: String,
    state_filter: String,
    csrf_token: String,
    csrf_bulk: String,
    error: Option<String>,
    flash: Option<String>,
    /// WP asset library — drives the "Bulk install asset" dropdown.
    /// Empty list = the dropdown hides itself.
    wp_assets: Vec<hyperion_types::WpAssetSummary>,
}

#[derive(Template)]
#[template(path = "hostings_new.html")]
struct NewTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    error: Option<&'a str>,
    domain_in: &'a str,
    aliases_in: &'a str,
    /// "" = none/static, otherwise "8.1".."8.4"
    php_in: String,
    /// "" = none, otherwise "mariadb"/"postgres"
    db_in: String,
    /// "" = default php, otherwise echoes back kind selector
    #[allow(dead_code)]
    kind_in: String,
    /// Echoed-back upstream URL when create failed and kind=reverse_proxy
    proxy_upstream_url_in: String,
    /// Enrolled remote nodes (master excluded). When empty, the
    /// template hides the "Target node" dropdown and the hosting is
    /// provisioned on the master itself.
    nodes: Vec<hyperion_types::NodeSummary>,
    /// Pre-selected target node when re-rendering after a validation
    /// error. Empty / "local" → master.
    target_node_in: String,
    /// Echoes the [cluster] master_accepts_hostings setting from
    /// agent.toml. When false the template hides the master from
    /// the Target-node dropdown — operator turned the master into
    /// a control-plane-only node via Settings → Cluster.
    master_accepts_hostings: bool,
}

/// Per-field append to `CreateForm` for the optional WP install
/// checkbox + its admin fields. Standalone struct so older code that
/// only uses the basic fields keeps compiling — Form picks both
/// because axum Form derives Deserialize on the whole body.

#[derive(Template)]
#[template(path = "hostings_detail.html")]
struct DetailTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    detail: HostingDetail,
    limits: hyperion_types::HostingLimits,
    wp_status: Option<WpInstallStatus>,
    expiry: hyperion_types::HostingExpiry,
    backups: Vec<hyperion_types::BackupRunWire>,
    stats: Option<HostingStats>,
    csrf_delete: String,
    csrf_suspend: String,
    csrf_resume: String,
    csrf_limits: String,
    csrf_wp_install: String,
    csrf_backup_now: String,
    csrf_expiry_set: String,
    csrf_expiry_clear: String,
    csrf_dns_check: String,
    csrf_cert_issue: String,
    csrf_restore: String,
    csrf_logs: String,
    csrf_cron: String,
    cron_body: String,
    csrf_wp_reset: String,
    csrf_db_reset: String,
    csrf_profile_apply: String,
    profile_apply: Option<ProfileApply>,
    applied_profile_name: Option<String>,
    profiles: Vec<HostingProfile>,
    spf: Option<SpfCheckResult>,
    csrf_ftp_set: String,
    csrf_ftp_disable: String,
    ftp_new_password: Option<String>,
    error: Option<&'a str>,
    wp_error: Option<String>,
    wp_flash: Option<String>,
    backup_error: Option<String>,
    backup_flash: Option<String>,
    expiry_error: Option<String>,
    expiry_flash: Option<String>,
    cert_error: Option<String>,
    cert_flash: Option<String>,
    restore_error: Option<String>,
    restore_flash: Option<String>,
    cron_error: Option<String>,
    cron_flash: Option<String>,
    db_error: Option<String>,
    db_flash: Option<String>,
    profile_error: Option<String>,
    profile_flash: Option<String>,
    ftp_error: Option<String>,
    ftp_flash: Option<String>,
    just_created: Option<HostingCreated>,
    /// Drives the per-user Access tab — super_admin only.
    is_super_admin: bool,
    /// Existing access grants for this hosting (populated for super_admin).
    access_grants: Vec<hyperion_types::WebHostingAccess>,
    /// Users available to grant to (operator/viewer roles; super_admin
    /// and admin are excluded since they already see everything).
    users_for_access: Vec<hyperion_types::WebUserSummary>,
    /// Per-hosting monitor config + sample history (for the Monitor tab).
    monitor_config: hyperion_types::MonitorConfigView,
    monitor_history: hyperion_types::MonitorHistory,
    /// WordPress plugin list — populated only when wp_status is Some.
    /// Empty otherwise; the template's WP tab shows an "install WP first"
    /// state instead of an empty table.
    wp_plugins: hyperion_types::WpPluginListResponse,
    /// Per-hosting email log — last 50 emails the agent sent on
    /// behalf of this hosting (alerts, cert reminders, monitor
    /// down/up, billing). Drives the new Emails tab.
    email_log: Vec<hyperion_types::EmailLogEntry>,
    /// Session-wide CSRF token used by the newer forms that don't have
    /// dedicated csrf_* fields plumbed (access, acme-email, monitor,
    /// backup delete). Middleware accepts both.
    csrf_token: String,
    /// Which node owns this hosting — "" (master) or the enrolled
    /// `node_id`. Per-hosting action forms render this as a hidden
    /// input so post_suspend / post_delete / post_set_limits / etc.
    /// dispatch the RPC to the correct agent. Empty string is the
    /// safe default for backwards compatibility with single-node
    /// setups.
    target_node: String,
    /// Enrolled remote nodes — drives the one-click "Migrate to…"
    /// dropdown on the Migration tab. Empty on single-node setups
    /// (the dropdown hides itself in that case).
    all_nodes: Vec<hyperion_types::NodeSummary>,
    /// Uploaded plugin/theme ZIPs from the master's library —
    /// drives the "Install from library" dropdown on the WP tab.
    /// Library lives on the MASTER (the master web is what
    /// operators upload to), so we always fetch via the local
    /// agent socket regardless of where this hosting lives.
    wp_assets: Vec<hyperion_types::WpAssetSummary>,
    /// Installed WP themes for the new Themes tab. Same shape as
    /// wp_plugins above, mirrored across the wp_theme adapter.
    /// Empty when wp_status is None (no WP install).
    wp_themes: hyperion_types::WpThemeListResponse,
    /// CSRF token for the vhost options form (basic auth, HSTS,
    /// FastCGI cache, custom snippet, maintenance mode, redirect).
    csrf_vhost_options: String,
    /// Set by the post handler on success — banner in the UI.
    vhost_saved: bool,
    /// Set when set_vhost_options returned an error — banner in UI.
    vhost_error: Option<String>,
    /// WP debug toggle form CSRF.
    /// Up to 48 hourly buckets of (disk, bw_in, bw_out, php_requests)
    /// for the Stats card sparklines. Newest last, may be shorter
    /// than 48 if the agent is freshly installed.
    usage_buckets: Vec<hyperion_types::HostingUsageBucket>,
    csrf_wp_debug: String,
    /// WP debug.log rotate button CSRF.
    csrf_wp_debug_rotate: String,
    /// WP Redis enable/disable form CSRF.
    csrf_wp_redis: String,
    /// WP Redis password rotate button CSRF.
    csrf_wp_redis_rotate: String,
    /// Set after a successful WP debug/Redis POST — banner in UI.
    wp_extras_flash: bool,
    /// Set when set_wp_debug / set_redis returned an error — banner.
    wp_extras_error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub bulk_flash: Option<String>,
}

pub async fn get_list(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<ListQuery>,
) -> Result<Response, AppError> {
    let rows = list_hostings(&state).await.map_err(AppError::Rpc)?;
    let total_count = rows.len();
    // Role-based filter: operators + viewers only see hostings they
    // have an explicit access grant for. super_admin + admin see all.
    let rows = filter_by_access(&state, &ctx, rows).await;
    let needle = q.q.trim().to_lowercase();
    let state_filter = q.state.trim().to_lowercase();
    let rows: Vec<HostingSummary> = rows
        .into_iter()
        .filter(|r| needle.is_empty() || r.domain.to_lowercase().contains(&needle))
        .filter(|r| state_filter.is_empty() || r.state.as_str() == state_filter)
        .collect();
    let csrf_token = csrf_token_for(&state, &ctx, "/hostings/delete");
    let csrf_bulk = csrf_token_for(&state, &ctx, "/hostings/bulk");
    let tpl = ListTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows,
        total_count,
        q: q.q,
        state_filter,
        csrf_token,
        csrf_bulk,
        error: None,
        flash: q.bulk_flash,
        wp_assets: fetch_wp_assets(&state).await.unwrap_or_default(),
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_new(State(state): State<SharedState>, ctx: AuthCtx) -> Result<Response, AppError> {
    // Creating a new hosting is a cluster-scoped action. Tenant-
    // scoped roles (operator / customer / viewer) get bounced —
    // the post_create handler enforces this server-side anyway,
    // bouncing on GET avoids rendering the entire form just to
    // refuse the submit.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    // Wildcard CSRF token so it also covers the DNS-preflight HTMX
    // button (form_id /hostings/dns-check-domain) in addition to the
    // main /hostings POST.
    let csrf_token = super::session_csrf_token(&state, &ctx);
    // Fetch enrolled remote nodes so the "Target node" dropdown can
    // offer them. Failure here just leaves the dropdown empty — the
    // form still works for the default-master case.
    let nodes = match fetch_remote_nodes(&state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error=%e,
                "fetch_remote_nodes failed — Target node dropdown will be empty"
            );
            Vec::new()
        }
    };
    // Check the [cluster] section from agent.toml — master might be
    // set to control-plane-only, in which case we hide the master
    // option from the Target-node dropdown.
    let master_accepts_hostings = fetch_master_accepts_hostings(&state).await;
    let tpl = NewTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token,
        error: None,
        domain_in: "",
        aliases_in: "",
        php_in: "8.3".to_string(),
        db_in: "mariadb".to_string(),
        kind_in: "php".to_string(),
        proxy_upstream_url_in: String::new(),
        nodes,
        target_node_in: String::new(),
        master_accepts_hostings,
    };
    // Browsers (and reverse proxies in front) can cache /hostings/new
    // by default. After an enrollment the dropdown should refresh on
    // the next visit, NOT show the previous stale rendering. The
    // form also carries a one-time CSRF token, so a cached page
    // would be useless on submit anyway.
    let mut response = Html(tpl.render()?).into_response();
    let h = response.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    h.insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    h.insert("vary", axum::http::HeaderValue::from_static("Cookie"));
    Ok(response)
}

/// Look up enrolled nodes via NodesList. The master itself isn't a
/// row in the `nodes` table (it's the orchestrator, not an enrollee),
/// so whatever this returns IS the set of remote targets the
/// operator can pick from.
pub(crate) async fn fetch_remote_nodes(
    state: &SharedState,
) -> Result<Vec<hyperion_types::NodeSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await?;
    match resp {
        RpcResponse::NodesList(v) => Ok(v),
        _ => Err(AppError::Internal("unexpected NodesList response".into())),
    }
}

#[derive(Deserialize)]
pub struct CreateForm {
    domain: String,
    #[serde(default)]
    aliases: String,
    #[serde(default)]
    php: String,
    #[serde(default)]
    db: String,
    #[serde(default)]
    system_user: String,
    /// "php" | "static" | "reverse_proxy" — defaults to "php".
    #[serde(default)]
    pub kind: String,
    /// Upstream URL when kind=reverse_proxy.
    #[serde(default)]
    pub proxy_upstream_url: String,
    /// Target node for provisioning. "" / "local" → master itself;
    /// anything else is a node_id from /install / NodesList.
    #[serde(default)]
    pub target_node: String,
    /// "on" if the user checked the "install WordPress" checkbox.
    #[serde(default)]
    pub install_wp: String,
    /// WP admin login (the username typed into wp-login.php).
    /// Defaults to "admin" when blank. Operators should pick
    /// something non-obvious — "admin" is the first username every
    /// drive-by brute-forcer tries.
    #[serde(default)]
    pub wp_admin_user: String,
    /// WP admin email (also gets the install confirmation email).
    #[serde(default)]
    pub wp_admin_email: String,
    /// WP admin password — what the operator types.
    #[serde(default)]
    pub wp_admin_password: String,
    /// `wp_options.blogname` — default to the domain if blank.
    #[serde(default)]
    pub wp_title: String,
    /// Locale; defaults to en_US if blank.
    #[serde(default)]
    pub wp_locale: String,
}

pub async fn post_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    // Creating a new hosting is a cluster-scoped action — operators
    // with per-hosting grants can't conjure new sites into existence.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let csrf_token = super::session_csrf_token(&state, &ctx);
    // Parse inputs; render the form with an error if anything is malformed.
    let domain = match Domain::parse(form.domain.trim()) {
        Ok(d) => d,
        Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e.to_string())),
    };
    let aliases = match parse_aliases(&form.aliases) {
        Ok(v) => v,
        Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e)),
    };
    let php_version = if form.php.is_empty() || form.php == "none" {
        None
    } else {
        match PhpVersion::from_str(&form.php) {
            Ok(v) => Some(v),
            Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e)),
        }
    };
    let database = if form.db.is_empty() || form.db == "none" {
        None
    } else {
        match DbProvision::from_str(&form.db) {
            Ok(v) => Some(v),
            Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e)),
        }
    };
    let system_user = if form.system_user.trim().is_empty() {
        None
    } else {
        match SystemUserName::parse(form.system_user.trim()) {
            Ok(v) => Some(v),
            Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e.to_string())),
        }
    };
    let kind = if form.kind == "reverse_proxy" {
        "reverse_proxy".to_string()
    } else if form.kind == "static" {
        "static".to_string()
    } else {
        "php".to_string()
    };
    let proxy_upstream_url = if kind == "reverse_proxy" {
        let u = form.proxy_upstream_url.trim().to_string();
        if u.is_empty() {
            return Ok(render_new_error(
                &ctx,
                &csrf_token,
                &form,
                "Reverse proxy requires an upstream URL.",
            ));
        }
        Some(u)
    } else {
        None
    };
    let req = HostingCreateReq {
        domain,
        aliases,
        php_version,
        database,
        system_user,
        kind,
        proxy_upstream_url,
    };
    // Cache target_node — every downstream RPC in this handler
    // (HostingCreate, optional WpInstall, HostingGet, fetch_limits)
    // must hit the SAME node, otherwise the WP install would land on
    // the master while the hosting itself lives on stav.
    //
    // "auto" is the auto-placement sentinel — pick the best-fit
    // worker by available capacity + load. Falls back to master if
    // no online workers are available + master_accepts_hostings is on.
    let mut target_node = form.target_node.clone();
    if target_node == "auto" {
        match pick_auto_placement_target(&state).await {
            Some(picked) => {
                tracing::info!(picked = %picked, "auto-placement chose node");
                target_node = picked;
            }
            None => {
                // Fall back to master if it accepts hostings;
                // otherwise surface a clean error.
                if fetch_master_accepts_hostings(&state).await {
                    target_node = crate::dispatcher::LOCAL_NODE_SENTINEL.to_string();
                    tracing::info!("auto-placement: no workers, falling back to master");
                } else {
                    return Ok(render_new_error(
                        &ctx,
                        &csrf_token,
                        &form,
                        "Auto-placement found no online workers and master is \
                         in control-plane-only mode. Enrol a worker or enable \
                         master hosting in Settings → Cluster.",
                    ));
                }
            }
        }
    }
    let target = if target_node.is_empty()
        || target_node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(target_node.as_str())
    };
    // Server-side enforcement of the cluster.master_accepts_hostings
    // toggle. UI hides the master option already (defense in depth)
    // but a hand-crafted POST with target_node=local would otherwise
    // bypass it.
    if target.is_none() && !fetch_master_accepts_hostings(&state).await {
        return Ok(render_new_error(
            &ctx,
            &csrf_token,
            &form,
            "Master is in control-plane-only mode (Settings → Cluster). Pick a worker node from the dropdown.",
        ));
    }
    // Loud breadcrumb so the operator can verify in journalctl which
    // node a create attempt was actually dispatched to. The dispatcher
    // also logs, but having both lets us tell apart "form submitted
    // local because dropdown wasn't rendered" (no log here with the
    // real intent) from "dispatcher overrode the choice" (logs differ).
    tracing::info!(
        operator = %ctx.username,
        domain = %req.domain.as_str(),
        target_node_form_value = %target_node,
        target_after_normalize = ?target,
        "post_create dispatch decision"
    );
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingCreate(req.clone()),
    )
    .await?;
    match resp {
        RpcResponse::HostingCreate(mut created) => {
            // Optional WordPress install — only when checkbox ticked,
            // database is provisioned, and kind is php (no point
            // installing WP on a static or reverse_proxy hosting).
            let wp_was_requested = form.install_wp.eq_ignore_ascii_case("on") ||
                                   form.install_wp == "true" || form.install_wp == "1";
            if wp_was_requested && created.db.is_some() && req.kind == "php" {
                let admin_email = form.wp_admin_email.trim();
                let admin_password = form.wp_admin_password.clone();
                // Default "admin" preserves the previous behaviour
                // for operators who leave the field blank, but
                // explicit non-empty input wins.
                let admin_user_raw = form.wp_admin_user.trim();
                let admin_user = if admin_user_raw.is_empty() {
                    "admin".to_string()
                } else {
                    admin_user_raw.to_string()
                };
                if admin_email.is_empty() || admin_password.len() < 6 {
                    // Don't fail the whole create — the hosting is
                    // alive. Just leave WP uninstalled.
                    tracing::warn!(
                        "WP install requested but missing/short credentials; skipping"
                    );
                } else if !is_valid_wp_username(&admin_user) {
                    // Same fail-soft as above: keep the hosting,
                    // skip WP, log so the operator sees the reason
                    // in journalctl.
                    tracing::warn!(
                        admin_user = %admin_user,
                        "WP install requested but admin username is invalid; skipping"
                    );
                } else {
                    let title = if form.wp_title.trim().is_empty() {
                        req.domain.as_str().to_string()
                    } else {
                        form.wp_title.trim().to_string()
                    };
                    let locale = if form.wp_locale.trim().is_empty() {
                        "en_US".to_string()
                    } else {
                        form.wp_locale.trim().to_string()
                    };
                    let site_url = format!("https://{}", req.domain.as_str());
                    let wp_req = hyperion_types::WpInstallRequest {
                        site_url: site_url.clone(),
                        title,
                        admin_user: admin_user.clone(),
                        admin_email: admin_email.to_string(),
                        admin_password: admin_password.clone(),
                        locale,
                        version: "latest".to_string(),
                    };
                    let install_resp = crate::dispatcher::dispatch_to_node(
                        &state,
                        target,
                        Request::WpInstall {
                            sel: HostingSelector::Id(created.id.clone()),
                            req: wp_req,
                        },
                    )
                    .await;
                    match install_resp {
                        Ok(RpcResponse::WpInstall(_status)) => {
                            // Tuck the WP creds into the response so
                            // the credential panel renders them.
                            created.wp = Some(hyperion_rpc::wire::WpCreatedInfo {
                                admin_user: admin_user.clone(),
                                admin_email: admin_email.to_string(),
                                admin_password,
                                admin_login_url: format!("{}/wp-login.php", site_url),
                            });
                        }
                        Ok(RpcResponse::Error(e)) => {
                            tracing::warn!(error=%e, "WP install failed");
                        }
                        _ => {}
                    }
                }
            }

            // Re-fetch detail for nice display. Must go to the SAME
            // node we just provisioned on — otherwise the master
            // would return "no such hosting" because the row lives
            // on the remote node's state DB.
            let detail_resp = crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::HostingGet(HostingSelector::Id(created.id.clone())),
            )
            .await?;
            let detail = match detail_resp {
                RpcResponse::HostingGet(d) => d,
                _ => return Err(AppError::Internal("expected HostingGet".into())),
            };
            let limits = fetch_limits(&state, target, HostingSelector::Id(created.id.clone()))
                .await
                .unwrap_or_else(|_| hyperion_types::HostingLimits::defaults());
            let tpl = DetailTpl {
                username: &ctx.username,
                user_initial: super::user_initial(&ctx.username),
                active: "hostings",
                css_version: super::css_version(),
                htmx_version: super::htmx_version(),
                detail,
                limits,
                wp_status: None,
                expiry: hyperion_types::HostingExpiry::defaults(),
                backups: vec![],
                stats: None,
                csrf_delete: csrf_token_for(&state, &ctx, "/hostings/delete"),
                csrf_suspend: csrf_token_for(&state, &ctx, "/hostings/suspend"),
                csrf_resume: csrf_token_for(&state, &ctx, "/hostings/resume"),
                csrf_limits: csrf_token_for(&state, &ctx, "/hostings/set-limits"),
                csrf_wp_install: csrf_token_for(&state, &ctx, "/hostings/wp/install"),
                csrf_backup_now: csrf_token_for(&state, &ctx, "/hostings/backup-now"),
                csrf_expiry_set: csrf_token_for(&state, &ctx, "/hostings/expiry/set"),
                csrf_expiry_clear: csrf_token_for(&state, &ctx, "/hostings/expiry/clear"),
                csrf_dns_check: csrf_token_for(&state, &ctx, "/hostings/dns-check"),
                csrf_cert_issue: csrf_token_for(&state, &ctx, "/hostings/cert/issue"),
                csrf_restore: csrf_token_for(&state, &ctx, "/hostings/restore"),
                csrf_logs: csrf_token_for(&state, &ctx, "/hostings/logs"),
                csrf_cron: csrf_token_for(&state, &ctx, "/hostings/cron"),
                cron_body: String::new(),
                csrf_wp_reset: csrf_token_for(&state, &ctx, "/hostings/wp/reset-password"),
                csrf_db_reset: csrf_token_for(&state, &ctx, "/hostings/db/reset-password"),
                csrf_profile_apply: csrf_token_for(&state, &ctx, "/profiles/apply"),
                profile_apply: None,
                applied_profile_name: None,
                profiles: vec![],
                spf: None,
                csrf_ftp_set: csrf_token_for(&state, &ctx, "/hostings/ftp/set"),
                csrf_ftp_disable: csrf_token_for(&state, &ctx, "/hostings/ftp/disable"),
                ftp_new_password: None,
                error: None,
                wp_error: None,
                wp_flash: None,
                backup_error: None,
                backup_flash: None,
                expiry_error: None,
                expiry_flash: None,
                cert_error: None,
                cert_flash: None,
                restore_error: None,
                restore_flash: None,
                cron_error: None,
                cron_flash: None,
                db_error: None,
                db_flash: None,
                profile_error: None,
                profile_flash: None,
                ftp_error: None,
                ftp_flash: None,
                just_created: Some(created),
                is_super_admin: ctx.is_super_admin(),
                access_grants: vec![],
                users_for_access: vec![],
                monitor_config: hyperion_types::MonitorConfigView::default(),
                monitor_history: hyperion_types::MonitorHistory::default(),
                wp_plugins: hyperion_types::WpPluginListResponse::default(),
                email_log: vec![],
                csrf_token: super::session_csrf_token(&state, &ctx),
                target_node: target.unwrap_or("").to_string(),
                all_nodes: fetch_remote_nodes(&state).await.unwrap_or_default(),
                wp_assets: fetch_wp_assets(&state).await.unwrap_or_default(),
                wp_themes: hyperion_types::WpThemeListResponse::default(),
                csrf_vhost_options: csrf_token_for(&state, &ctx, "/hostings/vhost-options"),
                vhost_saved: false,
                vhost_error: None,
                usage_buckets: vec![],
                csrf_wp_debug: csrf_token_for(&state, &ctx, "/hostings/wp/debug"),
                csrf_wp_debug_rotate: csrf_token_for(
                    &state,
                    &ctx,
                    "/hostings/wp/debug-log/rotate",
                ),
                csrf_wp_redis: csrf_token_for(&state, &ctx, "/hostings/wp/redis"),
                csrf_wp_redis_rotate: csrf_token_for(&state, &ctx, "/hostings/wp/redis/rotate"),
                wp_extras_flash: false,
                wp_extras_error: None,
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => Ok(render_new_error(
            &ctx,
            &csrf_token,
            &form,
            &format!("agent: {e}"),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn get_detail(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DetailQuery>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    // Multi-node detail lookup: try master first, then fan out across
    // enrolled workers. Returns the detail PLUS the node id where it
    // was found so every subsequent per-hosting RPC on this page
    // (limits, stats, backups, …) goes to the SAME node. Without
    // this, the detail page would show 404 for any hosting that
    // lives on a worker.
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    let target = owner_node.as_deref();
    // RBAC guard: operator + viewer must have an access grant.
    // super_admin + admin pass through. Unauthenticated redirects to
    // /login earlier (require_auth middleware), so unwrap to /hostings
    // for the no-access case.
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    let sel_id = HostingSelector::Id(detail.id.clone());

    // === Parallel RPC fan-out ===
    // The hosting detail page used to do ~12 serial RPCs (limits,
    // wp_status, plugins, themes, expiry, backups, stats, cron,
    // profile_apply, profiles, spf, monitor, email_log). On a
    // multi-node setup with 100ms+ per RPC that added up to >1s
    // of page-render latency. tokio::join! buckets them so the
    // whole page is bounded by the SLOWEST single RPC.
    //
    // wp_plugins + wp_themes still depend on wp_status (only
    // probe wp-cli if WP is installed). We get wp_status in the
    // first wave + conditionally fire plugins/themes in a tiny
    // second wave.
    let usage_fut = async {
        match crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::HostingUsage { sel: sel_id.clone(), limit: 48 },
        )
        .await
        {
            Ok(RpcResponse::HostingUsage(rows)) => rows,
            _ => vec![],
        }
    };
    let (
        limits_res,
        wp_status_res,
        expiry_res,
        backups_res,
        stats_res,
        cron_res,
        profile_apply_res,
        profiles_res,
        usage_buckets,
    ) = tokio::join!(
        fetch_limits(&state, target, sel_id.clone()),
        fetch_wp_status(&state, target, sel_id.clone()),
        fetch_expiry(&state, target, sel_id.clone()),
        fetch_backup_list(&state, target, sel_id.clone(), 10),
        fetch_stats(&state, target, sel_id.clone()),
        fetch_cron(&state, target, sel_id.clone()),
        fetch_profile_apply(&state, target, sel_id.clone()),
        fetch_all_profiles(&state),
        usage_fut,
    );
    let limits = limits_res.unwrap_or_else(|_| hyperion_types::HostingLimits::defaults());
    let wp_status = wp_status_res.unwrap_or(None);
    let expiry = expiry_res.unwrap_or_else(|_| hyperion_types::HostingExpiry::defaults());
    let backups = backups_res.unwrap_or_default();
    let stats = stats_res.ok();
    let cron_body = cron_res.unwrap_or_default();
    let profile_apply = profile_apply_res.unwrap_or(None);
    let profiles = profiles_res.unwrap_or_default();

    let domain_for_spf = Domain::parse(&detail.domain).ok();

    // Wave 2 — independent of wp_status, and WP plugins/themes
    // only when WP is installed. Wave 1 already finished so we
    // know wp_status now.
    let wp_plugins_fut = async {
        if wp_status.is_some() {
            match crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::WpPluginList { hosting: sel_id.clone() },
            )
            .await
            {
                Ok(RpcResponse::WpPluginList(r)) => r,
                _ => hyperion_types::WpPluginListResponse::default(),
            }
        } else {
            hyperion_types::WpPluginListResponse::default()
        }
    };
    let wp_themes_fut = async {
        if wp_status.is_some() {
            match crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::WpThemeList { hosting: sel_id.clone() },
            )
            .await
            {
                Ok(RpcResponse::WpThemeList(r)) => r,
                _ => hyperion_types::WpThemeListResponse::default(),
            }
        } else {
            hyperion_types::WpThemeListResponse::default()
        }
    };
    let spf_fut = async {
        match domain_for_spf {
            Some(d) => match hyperion_rpc_client::call(
                &state.agent_socket,
                Request::DnsSpfCheck { domain: d },
            )
            .await
            {
                Ok(RpcResponse::DnsSpfCheck(r)) => Some(r),
                _ => None,
            },
            None => None,
        }
    };
    let monitor_fut = async {
        match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::MonitorGet { sel: sel_id.clone() },
        )
        .await
        {
            Ok(RpcResponse::MonitorGet { config, history }) => (config, history),
            _ => (
                hyperion_types::MonitorConfigView::default(),
                hyperion_types::MonitorHistory::default(),
            ),
        }
    };
    let email_log_fut = async {
        match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::EmailLogList {
                hosting_id: Some(detail.id.as_str().to_string()),
                limit: 50,
            },
        )
        .await
        {
            Ok(RpcResponse::EmailLogList(r)) => r,
            _ => vec![],
        }
    };
    let (wp_plugins, wp_themes, spf, monitor_pair, email_log) = tokio::join!(
        wp_plugins_fut,
        wp_themes_fut,
        spf_fut,
        monitor_fut,
        email_log_fut,
    );
    let (monitor_config, monitor_history) = monitor_pair;

    let applied_profile_name = profile_apply
        .as_ref()
        .and_then(|a| a.profile_id)
        .and_then(|pid| profiles.iter().find(|p| p.id == pid).map(|p| p.name.clone()));
    // Access tab data — fetched only for super_admin since they're the
    // only ones who see the tab. Empty vec for everyone else is cheap
    // and keeps the template happy.
    let (access_grants_for_detail, users_for_access_for_detail) = if ctx.is_super_admin() {
        let grants = match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::WebListHostingAccess {
                hosting_id: detail.id.as_str().to_string(),
            },
        )
        .await
        {
            Ok(RpcResponse::WebListHostingAccess(g)) => g,
            _ => vec![],
        };
        let users = match hyperion_rpc_client::call(&state.agent_socket, Request::WebUserList)
            .await
        {
            Ok(RpcResponse::WebUserList(u)) => u
                .into_iter()
                // Only operators + viewers can be granted per-web access;
                // super_admin and admin already see everything.
                .filter(|u| u.role == "operator" || u.role == "viewer")
                .collect(),
            _ => vec![],
        };
        (grants, users)
    } else {
        (vec![], vec![])
    };
    let tpl = DetailTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        detail,
        limits,
        wp_status,
        expiry,
        backups,
        stats,
        csrf_delete: csrf_token_for(&state, &ctx, "/hostings/delete"),
        csrf_suspend: csrf_token_for(&state, &ctx, "/hostings/suspend"),
        csrf_resume: csrf_token_for(&state, &ctx, "/hostings/resume"),
        csrf_limits: csrf_token_for(&state, &ctx, "/hostings/set-limits"),
        csrf_wp_install: csrf_token_for(&state, &ctx, "/hostings/wp/install"),
        csrf_backup_now: csrf_token_for(&state, &ctx, "/hostings/backup-now"),
        csrf_expiry_set: csrf_token_for(&state, &ctx, "/hostings/expiry/set"),
        csrf_expiry_clear: csrf_token_for(&state, &ctx, "/hostings/expiry/clear"),
        csrf_dns_check: csrf_token_for(&state, &ctx, "/hostings/dns-check"),
        csrf_cert_issue: csrf_token_for(&state, &ctx, "/hostings/cert/issue"),
        csrf_restore: csrf_token_for(&state, &ctx, "/hostings/restore"),
        csrf_logs: csrf_token_for(&state, &ctx, "/hostings/logs"),
        csrf_cron: csrf_token_for(&state, &ctx, "/hostings/cron"),
        cron_body,
        csrf_wp_reset: csrf_token_for(&state, &ctx, "/hostings/wp/reset-password"),
        csrf_db_reset: csrf_token_for(&state, &ctx, "/hostings/db/reset-password"),
        csrf_profile_apply: csrf_token_for(&state, &ctx, "/profiles/apply"),
        profile_apply,
        applied_profile_name,
        profiles,
        spf,
        csrf_ftp_set: csrf_token_for(&state, &ctx, "/hostings/ftp/set"),
        csrf_ftp_disable: csrf_token_for(&state, &ctx, "/hostings/ftp/disable"),
        ftp_new_password: q.ftp_pw,
        error: None,
        wp_error: q.wp_error,
        wp_flash: q.wp.map(|s| {
            if s == "reset" {
                "WordPress admin password reset.".to_string()
            } else {
                "WordPress install succeeded.".into()
            }
        }),
        backup_error: q.backup_error,
        backup_flash: q.backup.map(|_| "Backup started — see list below.".into()),
        expiry_error: q.expiry_error,
        expiry_flash: q.expiry.map(|s| {
            if s == "cleared" {
                "Expiry cleared.".to_string()
            } else {
                "Expiry updated.".to_string()
            }
        }),
        cert_error: q.cert_error,
        cert_flash: q.cert.map(|s| {
            if s == "staging" {
                "Staging certificate issued — issuer 'letsencrypt-staging'.".into()
            } else {
                "Production HTTPS certificate issued.".into()
            }
        }),
        restore_error: q.restore_error,
        restore_flash: q.restore.map(|_| "Backup restored.".into()),
        cron_error: q.cron_error,
        cron_flash: q.cron.map(|_| "Crontab saved.".into()),
        db_error: q.db_error,
        db_flash: q.db.map(|_| "Database password reset.".into()),
        profile_error: q.profile_error,
        profile_flash: q.profile.map(|_| "Profile applied.".into()),
        ftp_error: q.ftp_error,
        ftp_flash: q.ftp.map(|s| {
            if s == "disabled" {
                "FTP disabled — password cleared.".into()
            } else {
                "FTP password set.".into()
            }
        }),
        just_created: None,
        is_super_admin: ctx.is_super_admin(),
        access_grants: access_grants_for_detail,
        users_for_access: users_for_access_for_detail,
        monitor_config,
        monitor_history,
        wp_plugins,
        email_log,
        csrf_token: super::session_csrf_token(&state, &ctx),
        target_node: owner_node.clone().unwrap_or_default(),
        all_nodes: fetch_remote_nodes(&state).await.unwrap_or_default(),
        wp_assets: fetch_wp_assets(&state).await.unwrap_or_default(),
        wp_themes,
        csrf_vhost_options: csrf_token_for(&state, &ctx, "/hostings/vhost-options"),
        vhost_saved: q.vhost_saved.as_deref() == Some("1"),
        vhost_error: q.vhost_error,
        usage_buckets,
        csrf_wp_debug: csrf_token_for(&state, &ctx, "/hostings/wp/debug"),
        csrf_wp_debug_rotate: csrf_token_for(&state, &ctx, "/hostings/wp/debug-log/rotate"),
        csrf_wp_redis: csrf_token_for(&state, &ctx, "/hostings/wp/redis"),
        csrf_wp_redis_rotate: csrf_token_for(&state, &ctx, "/hostings/wp/redis/rotate"),
        wp_extras_flash: q.wp_extras_saved.as_deref() == Some("1"),
        wp_extras_error: q.wp_extras_error,
    };
    Ok(Html(tpl.render()?).into_response())
}

async fn fetch_profile_apply(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<Option<ProfileApply>, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::ProfileGetApply { sel }).await?;
    match resp {
        RpcResponse::ProfileGetApply(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_all_profiles(state: &SharedState) -> Result<Vec<HostingProfile>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::ProfileList).await?;
    match resp {
        RpcResponse::ProfileList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_cron(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<String, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::CronList { sel }).await?;
    match resp {
        RpcResponse::CronList(s) => Ok(s),
        RpcResponse::Error(_) => Ok(String::new()),
        _ => Ok(String::new()),
    }
}

async fn fetch_stats(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<HostingStats, AppError> {
    let resp = crate::dispatcher::dispatch_to_node(state, target, Request::HostingStats { sel })
        .await?;
    match resp {
        RpcResponse::HostingStats(s) => Ok(s),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize, Default)]
pub struct DetailQuery {
    /// Set to "installed" via the redirect after a successful WP install.
    #[serde(default)]
    pub wp: Option<String>,
    /// Surface WP install failures back into the detail page.
    #[serde(default)]
    pub wp_error: Option<String>,
    #[serde(default)]
    pub backup: Option<String>,
    #[serde(default)]
    pub backup_error: Option<String>,
    #[serde(default)]
    pub expiry: Option<String>,
    #[serde(default)]
    pub expiry_error: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub cert_error: Option<String>,
    #[serde(default)]
    pub restore: Option<String>,
    #[serde(default)]
    pub restore_error: Option<String>,
    #[serde(default)]
    pub cron: Option<String>,
    #[serde(default)]
    pub cron_error: Option<String>,
    #[serde(default)]
    pub db: Option<String>,
    #[serde(default)]
    pub db_error: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub profile_error: Option<String>,
    #[serde(default)]
    pub ftp: Option<String>,
    #[serde(default)]
    pub ftp_error: Option<String>,
    /// Newly-set FTP password — shown ONCE then dropped. Carried in
    /// the query string after a successful POST so the redirect lands
    /// the operator on the page WITH the password visible.
    #[serde(default)]
    pub ftp_pw: Option<String>,
    /// "1" after a successful vhost-options POST → green banner.
    #[serde(default)]
    pub vhost_saved: Option<String>,
    /// nginx -t error / validation error from the vhost-options POST,
    /// surfaced back through the redirect.
    #[serde(default)]
    pub vhost_error: Option<String>,
    /// "1" after WP debug / Redis form was applied successfully.
    #[serde(default)]
    pub wp_extras_saved: Option<String>,
    /// Error from WP debug / Redis form, surfaced via redirect.
    #[serde(default)]
    pub wp_extras_error: Option<String>,
}

async fn fetch_expiry(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<hyperion_types::HostingExpiry, AppError> {
    let resp = crate::dispatcher::dispatch_to_node(state, target, Request::HostingGetExpiry(sel))
        .await?;
    match resp {
        RpcResponse::HostingGetExpiry(e) => Ok(e),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_backup_list(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
    limit: i64,
) -> Result<Vec<hyperion_types::BackupRunWire>, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::BackupList { sel, limit })
            .await?;
    match resp {
        RpcResponse::BackupList(rows) => Ok(rows),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_wp_status(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<Option<WpInstallStatus>, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::WpStatus { sel }).await?;
    match resp {
        RpcResponse::WpStatus(s) => Ok(s),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

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

#[derive(Deserialize)]
pub struct BackupNowForm {
    pub selector: String,
    #[serde(default)]
    pub target_node: String,
}

pub async fn post_backup_now(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupNowForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::BackupNow { sel },
    )
    .await?;
    let sel_url = urlencoding(&form.selector);
    match resp {
        RpcResponse::BackupNow(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?backup=started", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?backup_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SetExpiryForm {
    pub selector: String,
    /// `YYYY-MM-DD` from <input type="date">, or empty to clear.
    pub expires_on: String,
    #[serde(default)]
    pub owner_email: String,
    #[serde(default)]
    pub grace_days: Option<i64>,
    #[serde(default)]
    pub warning_offsets: Option<String>,
}

pub async fn post_set_expiry(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetExpiryForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let expires_at = match parse_yyyymmdd_to_epoch(form.expires_on.trim()) {
        Ok(t) => t,
        Err(msg) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?expiry_error={}",
                sel_url,
                urlencoding(&msg)
            ))
            .into_response());
        }
    };
    let expiry = hyperion_types::HostingExpiry {
        expires_at,
        owner_email: if form.owner_email.trim().is_empty() {
            None
        } else {
            Some(form.owner_email.trim().to_string())
        },
        grace_days: form.grace_days.unwrap_or(30).max(0),
        warning_offsets_days: form
            .warning_offsets
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("30,7,1")
            .to_string(),
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingSetExpiry { sel, expiry },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetExpiry(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?expiry=set", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?expiry_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ClearExpiryForm {
    pub selector: String,
}

pub async fn post_clear_expiry(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ClearExpiryForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingClearExpiry(sel)).await?;
    match resp {
        RpcResponse::HostingClearExpiry => {
            Ok(Redirect::to(&format!("/hostings/{}?expiry=cleared", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?expiry_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Parse YYYY-MM-DD into a Unix epoch (UTC midnight). Empty input → None.
fn parse_yyyymmdd_to_epoch(s: &str) -> Result<Option<i64>, String> {
    if s.is_empty() {
        return Ok(None);
    }
    let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| format!("Date must be YYYY-MM-DD, got: {s}"))?;
    let dt = d
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| "Invalid date".to_string())?
        .and_utc();
    Ok(Some(dt.timestamp()))
}

pub async fn post_wp_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpInstallForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
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
    };
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::WpInstall { sel, req }).await?;
    let sel_url = urlencoding(&form.selector);
    match resp {
        RpcResponse::WpInstall(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?wp=installed", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?wp_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_limits(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<hyperion_types::HostingLimits, AppError> {
    let resp = crate::dispatcher::dispatch_to_node(state, target, Request::HostingGetLimits(sel))
        .await?;
    match resp {
        RpcResponse::HostingGetLimits(l) => Ok(l),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    selector: String,
    #[serde(default)]
    keep_user: Option<String>,
    #[serde(default)]
    keep_db: Option<String>,
    /// Which node owns this hosting. Filled by the listing template
    /// from the aggregated HostingSummary.node_id field. Empty /
    /// "local" → master itself. Missing field defaults to master
    /// for backwards compatibility with the pre-multi-node form.
    #[serde(default)]
    target_node: String,
}

pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let opts = DeleteOpts {
        keep_user: form.keep_user.as_deref() == Some("on"),
        keep_database: form.keep_db.as_deref() == Some("on"),
    };
    // Dispatch to the node that actually owns the hosting. Without
    // this, deletes always hit the master and silently do nothing
    // for hostings provisioned on a worker (the very bug that left
    // orphan rows blocking the UNIQUE(domain) constraint on retry).
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingDelete { sel, opts },
    )
    .await?;
    match resp {
        RpcResponse::HostingDelete => Ok(Redirect::to("/hostings?deleted=1").into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Resolve a per-form `target_node` field to the Option<&str>
/// shape that dispatch_to_node accepts. Empty / "local" / "" →
/// master itself; anything else is a remote node_id.
fn node_target(raw: &str) -> Option<&str> {
    let s = raw.trim();
    if s.is_empty() || s == crate::dispatcher::LOCAL_NODE_SENTINEL {
        None
    } else {
        Some(s)
    }
}

#[derive(Deserialize)]
pub struct SuspendForm {
    selector: String,
    #[serde(default)]
    reason: String,
    /// Node where the hosting lives — populated by the detail
    /// page's target_node injector. Empty / "local" → master.
    #[serde(default)]
    target_node: String,
}

pub async fn post_suspend(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SuspendForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let reason = hyperion_types::SuspendReason::Manual {
        message: if form.reason.trim().is_empty() {
            None
        } else {
            Some(form.reason.trim().to_string())
        },
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSuspend { sel, reason },
    )
    .await?;
    match resp {
        RpcResponse::HostingSuspend => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ResumeForm {
    selector: String,
    #[serde(default)]
    target_node: String,
}

pub async fn post_resume(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ResumeForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingResume(sel),
    )
    .await?;
    match resp {
        RpcResponse::HostingResume => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct VhostOptionsForm {
    selector: String,
    #[serde(default)]
    target_node: String,
    // Use stringly "on" semantics — HTML checkboxes don't send
    // false values, so #[serde(default)] + presence check.
    #[serde(default)]
    basic_auth_enabled: Option<String>,
    #[serde(default)]
    basic_auth_user: String,
    /// Operator-typed new password. Empty string = leave hash alone.
    #[serde(default)]
    basic_auth_password: String,
    #[serde(default)]
    force_https: Option<String>,
    #[serde(default)]
    hsts_max_age: i64,
    #[serde(default)]
    custom_nginx_snippet: String,
    #[serde(default)]
    maintenance_mode: Option<String>,
    #[serde(default)]
    fastcgi_cache_enabled: Option<String>,
    #[serde(default)]
    fastcgi_cache_ttl: i64,
    #[serde(default)]
    redirect_url: String,
    #[serde(default)]
    redirect_code: i64,
    #[serde(default)]
    redirect_preserve_path: Option<String>,
}

fn checkbox_on(v: &Option<String>) -> bool {
    v.as_deref()
        .map(|s| matches!(s, "on" | "true" | "1" | "yes"))
        .unwrap_or(false)
}

pub async fn post_vhost_options(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<VhostOptionsForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let options = hyperion_types::VhostOptions {
        basic_auth_enabled: checkbox_on(&form.basic_auth_enabled),
        basic_auth_user: form.basic_auth_user.trim().to_string(),
        basic_auth_set: false, // service decides — based on pw + existing
        force_https: checkbox_on(&form.force_https),
        hsts_max_age: form.hsts_max_age,
        custom_nginx_snippet: form.custom_nginx_snippet,
        maintenance_mode: checkbox_on(&form.maintenance_mode),
        fastcgi_cache_enabled: checkbox_on(&form.fastcgi_cache_enabled),
        fastcgi_cache_ttl: form.fastcgi_cache_ttl,
        redirect_url: form.redirect_url.trim().to_string(),
        redirect_code: form.redirect_code,
        redirect_preserve_path: checkbox_on(&form.redirect_preserve_path),
    };
    let pw_opt = if form.basic_auth_password.is_empty() {
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
    match resp {
        RpcResponse::HostingSetVhostOptions(_) => Ok(Redirect::to(&format!(
            "/hostings/{}?vhost_saved=1",
            urlencoding(&form.selector)
        ))
        .into_response()),
        RpcResponse::Error(e) => {
            // Bounce back to the detail page with the error in the query
            // string so the operator sees the verbatim nginx -t output
            // (or validation error) in a banner instead of a bare 500.
            Ok(Redirect::to(&format!(
                "/hostings/{}?vhost_error={}",
                urlencoding(&form.selector),
                urlencoding(&e.to_string())
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// ──────────── WP debug + Redis handlers ────────────

#[derive(Deserialize)]
pub struct WpDebugForm {
    selector: String,
    #[serde(default)]
    target_node: String,
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    log: Option<String>,
    #[serde(default)]
    display: Option<String>,
}

fn redirect_after_wp_extras(form_selector: &str, error: Option<String>) -> Response {
    match error {
        Some(e) => Redirect::to(&format!(
            "/hostings/{}?wp_extras_error={}",
            urlencoding(form_selector),
            urlencoding(&e)
        ))
        .into_response(),
        None => Redirect::to(&format!(
            "/hostings/{}?wp_extras_saved=1",
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
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
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
    selector: String,
    #[serde(default)]
    target_node: String,
}

pub async fn post_wp_debug_log_rotate(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpRotateForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
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
        RpcResponse::HostingRotateWpDebugLog => {
            Ok(redirect_after_wp_extras(&form.selector, None))
        }
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpRedisForm {
    selector: String,
    #[serde(default)]
    target_node: String,
    /// "on" = enable; anything else = disable.
    #[serde(default)]
    enabled: String,
}

pub async fn post_wp_redis(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpRedisForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
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
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
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

#[derive(Deserialize)]
pub struct SetLimitsForm {
    selector: String,
    php_memory_mb: i64,
    php_max_exec_secs: i64,
    php_max_children: i64,
    php_max_requests: i64,
    db_max_connections: i64,
    #[serde(default)]
    disk_hard_mb: String,
    #[serde(default)]
    bw_monthly_mb: String,
    #[serde(default)]
    target_node: String,
}

#[derive(Deserialize)]
pub struct BackupDeleteForm {
    selector: String,
    backup_id: i64,
}

/// POST /hostings/backups/delete — remove a single backup run + its
/// archive file. Refuses if the backup is still running.
pub async fn post_backup_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupDeleteForm>,
) -> Result<Response, AppError> {
    // form.selector controls the redirect target, not the action — the
    // RPC operates on backup_id directly. We still gate via the
    // selector because non-admins can only see the backup list for
    // hostings they have access to; a viewer probing arbitrary
    // backup_ids without a matching access grant gets 403 here.
    if let Err(r) = require_manage_for_selector(&state, &ctx, &form.selector).await {
        return Ok(r);
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupDelete {
            backup_id: form.backup_id,
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupDelete => {
            Ok(Redirect::to(&format!("/hostings/{}#backups", urlencoding(&form.selector)))
                .into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SetAcmeEmailForm {
    selector: String,
    #[serde(default)]
    acme_email: String,
}

/// POST /hostings/acme-email — set or clear the per-hosting ACME
/// contact email override. An empty `acme_email` field clears the
/// override, falling back to `[acme] contact_email` from agent.toml.
pub async fn post_set_acme_email(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetAcmeEmailForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let trimmed = form.acme_email.trim();
    let email = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::SetHostingAcmeEmail { sel, email },
    )
    .await?;
    match resp {
        RpcResponse::SetHostingAcmeEmail => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_set_limits(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetLimitsForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let mut l = hyperion_types::HostingLimits::defaults();
    l.php_memory_mb = form.php_memory_mb;
    l.php_max_exec_secs = form.php_max_exec_secs;
    l.php_max_children = form.php_max_children;
    l.php_max_requests = form.php_max_requests;
    l.db_max_connections = form.db_max_connections;
    if let Ok(mb) = form.disk_hard_mb.trim().parse::<i64>() {
        if mb > 0 {
            l.disk_hard_bytes = Some(mb * 1024 * 1024);
        }
    }
    if let Ok(mb) = form.bw_monthly_mb.trim().parse::<i64>() {
        if mb > 0 {
            l.bw_monthly_bytes = Some(mb * 1024 * 1024);
        }
    }
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetLimits { sel, limits: l },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetLimits(_) => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct AccessGrantForm {
    pub hosting_id: String,
    pub user_id: i64,
    #[serde(default)]
    pub level: String,
}

#[derive(Deserialize)]
pub struct AccessRevokeForm {
    pub hosting_id: String,
    pub user_id: i64,
}

/// POST /hostings/access/grant — super_admin only. Grants a non-admin
/// user `read` or `manage` access to one hosting.
pub async fn post_access_grant(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<AccessGrantForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let level = if form.level == "read" { "read" } else { "manage" };
    let granted_by = ctx.session.as_ref().map(|s| s.user_id);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebGrantHostingAccess {
            user_id: form.user_id,
            hosting_id: form.hosting_id.clone(),
            level: level.to_string(),
            granted_by,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::WebGrantHostingAccess => {
            Ok(Redirect::to(&format!("/hostings/{}#access", urlencoding(&form.hosting_id)))
                .into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /hostings/access/revoke — super_admin only.
pub async fn post_access_revoke(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<AccessRevokeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebRevokeHostingAccess {
            user_id: form.user_id,
            hosting_id: form.hosting_id.clone(),
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::WebRevokeHostingAccess => {
            Ok(Redirect::to(&format!("/hostings/{}#access", urlencoding(&form.hosting_id)))
                .into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

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
}

pub async fn post_monitor_set(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<MonitorSetForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
    // Guard with manage-level access. super_admin / admin bypass.
    let detail_resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingGet(sel.clone())).await?;
    let detail = match detail_resp {
        RpcResponse::HostingGet(d) => d,
        _ => return Err(AppError::Internal("expected HostingGet".into())),
    };
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), true).await {
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
    let slack = if form.alert_slack_webhook.trim().is_empty() {
        None
    } else {
        Some(form.alert_slack_webhook.trim().to_string())
    };
    let webhook = if form.alert_webhook_url.trim().is_empty() {
        None
    } else {
        Some(form.alert_webhook_url.trim().to_string())
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::MonitorSet {
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
        RpcResponse::MonitorSet => {
            Ok(Redirect::to(&format!("/hostings/{}#monitor", urlencoding(&form.selector)))
                .into_response())
        }
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
    let detail_resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingGet(sel.clone())).await?;
    let detail = match detail_resp {
        RpcResponse::HostingGet(d) => d,
        _ => return Err(AppError::Internal("expected HostingGet".into())),
    };
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), true).await {
        return Ok(r);
    }
    let _ =
        hyperion_rpc_client::call(&state.agent_socket, Request::MonitorProbeNow { sel }).await?;
    Ok(Redirect::to(&format!("/hostings/{}#monitor", urlencoding(&form.selector)))
        .into_response())
}

/// Drop hosting summaries the caller doesn't have access to.
/// super_admin + admin pass through everything; operator + viewer get
/// filtered down to the set of hostings their `web_user_hosting_access`
/// rows mention. Unauthenticated callers see nothing.
///
/// Failures (RPC error, missing user_id) are conservative: we filter
/// to empty rather than risk over-disclosure.
async fn filter_by_access(
    state: &SharedState,
    ctx: &AuthCtx,
    rows: Vec<HostingSummary>,
) -> Vec<HostingSummary> {
    if ctx.is_admin_or_higher() {
        return rows;
    }
    let Some(sess) = ctx.session.as_ref() else {
        return Vec::new();
    };
    // Fetch the access set once and filter in memory.
    let mut allowed: std::collections::HashSet<String> = std::collections::HashSet::new();
    // We don't have a dedicated "list my hostings" RPC; iterate over
    // the visible rows and ask the agent per-id. For the typical
    // operator-with-a-few-hostings case this is cheap; for a 1000-
    // hosting cluster it's wasteful but acceptable for v1.
    for r in &rows {
        let access_resp = hyperion_rpc_client::call(
            &state.agent_socket,
            Request::WebListHostingAccess {
                hosting_id: r.id.as_str().to_string(),
            },
        )
        .await;
        if let Ok(RpcResponse::WebListHostingAccess(grants)) = access_resp {
            if grants.iter().any(|g| g.user_id == sess.user_id) {
                allowed.insert(r.id.as_str().to_string());
            }
        }
    }
    rows.into_iter()
        .filter(|r| allowed.contains(r.id.as_str()))
        .collect()
}

/// Block detail / write access for callers without the required level.
/// "read" → viewer-style (any access entry suffices). "manage" →
/// operator-style (level=manage). super_admin + admin always allowed.
///
/// Returns a `403 Forbidden` response on rejection. POST handlers must
/// propagate this with `Ok(r)` — a redirect would silently steer the
/// caller back to /hostings and obscure the access failure.
pub async fn require_hosting_access(
    state: &SharedState,
    ctx: &AuthCtx,
    hosting_id: &str,
    require_manage: bool,
) -> Result<(), Response> {
    if ctx.is_admin_or_higher() {
        return Ok(());
    }
    let forbidden = || {
        (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<h1>403 Forbidden</h1>".to_string(),
        )
            .into_response()
    };
    let Some(sess) = ctx.session.as_ref() else {
        return Err(forbidden());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebListHostingAccess {
            hosting_id: hosting_id.to_string(),
        },
    )
    .await;
    let grants = match resp {
        Ok(RpcResponse::WebListHostingAccess(g)) => g,
        _ => return Err(forbidden()),
    };
    let mine = grants.into_iter().find(|g| g.user_id == sess.user_id);
    match mine {
        None => Err(forbidden()),
        Some(g) if require_manage && g.level != "manage" => Err(forbidden()),
        Some(_) => Ok(()),
    }
}

/// Convenience wrapper for mutating POST handlers: parse the selector,
/// resolve the hosting id (looking it up by domain if needed), and
/// require manage-level access. Returns the resolved `HostingSelector`
/// on success so the caller can pass it straight to its RPC request.
///
/// Failure conditions all collapse to a 403 response — the caller
/// propagates it via `Ok(r)`. Surfacing the precise reason (no such
/// hosting vs. no access) would help account-enumeration; viewers
/// shouldn't be able to probe which ids exist.
pub async fn require_manage_for_selector(
    state: &SharedState,
    ctx: &AuthCtx,
    sel_str: &str,
) -> Result<HostingSelector, Response> {
    let forbidden = || {
        (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<h1>403 Forbidden</h1>".to_string(),
        )
            .into_response()
    };
    let sel = parse_selector(sel_str).map_err(|_| forbidden())?;
    if ctx.is_admin_or_higher() {
        return Ok(sel);
    }
    let hosting_id = match &sel {
        HostingSelector::Id(id) => id.as_str().to_string(),
        _ => {
            let resp = hyperion_rpc_client::call(
                &state.agent_socket,
                Request::HostingGet(sel.clone()),
            )
            .await;
            match resp {
                Ok(RpcResponse::HostingGet(d)) => d.id.as_str().to_string(),
                _ => return Err(forbidden()),
            }
        }
    };
    require_hosting_access(state, ctx, &hosting_id, true).await?;
    Ok(sel)
}

pub(crate) fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn parse_aliases(input: &str) -> Result<Vec<Domain>, String> {
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

/// Re-export of parse_selector for sibling handler modules.
pub fn parse_selector_public(s: &str) -> Result<HostingSelector, AppError> {
    parse_selector(s)
}

/// Conservative validator for the WordPress admin username the
/// operator types in the New Hosting form. WP itself accepts a
/// fairly wide range (including spaces, periods, `@`), but we
/// bound it to the safe subset to avoid:
///   - shell quoting bugs if it gets passed to wp-cli unescaped,
///   - URL-encoding surprises in wp-login.php links,
///   - operator typos that yield a username they then can't type
///     reliably (zero-width space, RTL marks, etc.).
///
/// Rules: 1..=60 chars, ASCII alphanumeric + `._@-`. No leading
/// dash (looks like a CLI flag), no leading dot (hidden), no
/// embedded whitespace.
fn is_valid_wp_username(s: &str) -> bool {
    if s.is_empty() || s.len() > 60 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'-' || bytes[0] == b'.' {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '@' || c == '-'
    })
}

#[cfg(test)]
mod wp_username_tests {
    use super::is_valid_wp_username;

    #[test]
    fn accepts_typical_usernames() {
        assert!(is_valid_wp_username("admin"));
        assert!(is_valid_wp_username("kevin"));
        assert!(is_valid_wp_username("kevin.nechodom"));
        assert!(is_valid_wp_username("kevin_99"));
        assert!(is_valid_wp_username("k@example.cz"));
        assert!(is_valid_wp_username("a"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_valid_wp_username(""));
    }

    #[test]
    fn rejects_too_long() {
        assert!(!is_valid_wp_username(&"a".repeat(61)));
        assert!(is_valid_wp_username(&"a".repeat(60)));
    }

    #[test]
    fn rejects_leading_dash_or_dot() {
        assert!(!is_valid_wp_username("-admin"));
        assert!(!is_valid_wp_username(".hidden"));
    }

    #[test]
    fn rejects_whitespace_and_shell_metacharacters() {
        assert!(!is_valid_wp_username("admin user"));
        assert!(!is_valid_wp_username("admin\nuser"));
        assert!(!is_valid_wp_username("admin;rm"));
        assert!(!is_valid_wp_username("$(whoami)"));
        assert!(!is_valid_wp_username("admin`whoami`"));
        assert!(!is_valid_wp_username("admin/test"));
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(!is_valid_wp_username("admín"));
        assert!(!is_valid_wp_username("админ"));
    }
}

fn parse_selector(s: &str) -> Result<HostingSelector, AppError> {
    if s.contains('.') {
        Ok(HostingSelector::Domain(Domain::parse(s)?))
    } else {
        Ok(HostingSelector::Id(hyperion_types::HostingId(
            s.to_string(),
        )))
    }
}

fn csrf_token_for(state: &SharedState, ctx: &AuthCtx, form_id: &str) -> String {
    let sid = ctx
        .session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default();
    hyperion_auth::csrf::mint(
        state.csrf_key.as_ref(),
        &sid,
        form_id,
        hyperion_types::now_secs(),
    )
}

fn render_new_error<'a>(
    ctx: &'a AuthCtx,
    csrf_token: &'a str,
    form: &'a CreateForm,
    error: &'a str,
) -> Response {
    let tpl = NewTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: csrf_token.to_string(),
        error: Some(error),
        domain_in: &form.domain,
        aliases_in: &form.aliases,
        php_in: form.php.clone(),
        db_in: form.db.clone(),
        kind_in: form.kind.clone(),
        proxy_upstream_url_in: form.proxy_upstream_url.clone(),
        // Re-rendering on validation error doesn't need a fresh
        // NodesList — we'd repeat the agent RPC for no UX gain.
        // The dropdown silently empties, which is acceptable since
        // the operator is fixing a field, not switching nodes.
        nodes: Vec::new(),
        target_node_in: form.target_node.clone(),
        // Same reasoning — preserve the operator-set value on
        // re-render. Defaulting to true keeps backward-compat.
        master_accepts_hostings: true,
    };
    Html(
        tpl.render()
            .unwrap_or_else(|_| "<h1>render error</h1>".into()),
    )
    .into_response()
}

/// Best-effort fetch of the WP asset library from the master.
/// Used by the hosting detail page to render the "Install from
/// library" dropdown on the WP tab. Failure → empty list (the
/// dropdown hides itself in the template).
async fn fetch_wp_assets(
    state: &SharedState,
) -> Result<Vec<hyperion_types::WpAssetSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::WpAssetList).await?;
    match resp {
        RpcResponse::WpAssetList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Check the master's [cluster] section: should the master itself
/// accept new hostings, or is it a control-plane-only node? Used
/// by /hostings/new to gate the master option in the Target-node
/// dropdown. Defaults to true (permissive) on any RPC failure or
/// missing config field — least-surprise.
async fn fetch_master_accepts_hostings(state: &SharedState) -> bool {
    match hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView).await {
        Ok(RpcResponse::AgentConfigView(c)) => c.cluster.master_accepts_hostings,
        _ => true,
    }
}

/// Pull the two bundle files (manifest.json + archive.tar.gz) off
/// a worker source via signed RPC and write them under the master's
/// own /var/lib/hyperion/migration/<bundle_id>/. After this the
/// master's existing /api/migration/bundle/<id>/<filename> route
/// serves the right bytes to the target node — the target doesn't
/// need to know the bundle started life on a worker.
///
/// Returns the local bundle directory on the master on success.
async fn pull_bundle_from_worker(
    state: &SharedState,
    source_node: &str,
    bundle_id: &str,
) -> Result<std::path::PathBuf, String> {
    use base64::Engine;
    let local_dir = std::path::PathBuf::from("/var/lib/hyperion/migration").join(bundle_id);
    tokio::fs::create_dir_all(&local_dir)
        .await
        .map_err(|e| format!("create local bundle dir: {e}"))?;
    for filename in ["manifest.json", "archive.tar.gz"] {
        let resp = crate::dispatcher::dispatch_to_node(
            state,
            Some(source_node),
            Request::HostingMigrationFetchBundleFile {
                bundle_id: bundle_id.to_string(),
                filename: filename.to_string(),
            },
        )
        .await
        .map_err(|e| format!("rpc {filename}: {e}"))?;
        let bytes_b64 = match resp {
            RpcResponse::HostingMigrationFetchBundleFile { bytes_b64 } => bytes_b64,
            RpcResponse::Error(e) => return Err(format!("source rejected {filename}: {e}")),
            _ => return Err(format!("unexpected response for {filename}")),
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(bytes_b64.as_bytes())
            .map_err(|e| format!("b64 {filename}: {e}"))?;
        tokio::fs::write(local_dir.join(filename), &bytes)
            .await
            .map_err(|e| format!("write {filename}: {e}"))?;
    }
    Ok(local_dir)
}

/// Auto-placement: pick the best-fit node for a new hosting when
/// the operator chose the "auto" sentinel in the create form.
///
/// Strategy (lower is better):
///   - Disqualify offline workers entirely.
///   - Score = 0.45·hostings + 0.35·loadavg + 0.20·mem_pct
///     normalised across the candidate set so a single node never
///     dominates by virtue of having the largest absolute numbers.
///   - Tiebreak by lexicographically smaller node_id (stable).
///   - Master is INCLUDED as a candidate iff
///     `cluster.master_accepts_hostings = true`.
///
/// Returns the chosen target string ready for the existing
/// dispatcher contract:
///   - `Some("worker-id")` to dispatch to a worker
///   - `Some(LOCAL_NODE_SENTINEL)` to dispatch locally
///   - `None` when no candidate qualifies (caller falls back to
///     master / error).
async fn pick_auto_placement_target(state: &SharedState) -> Option<String> {
    use hyperion_types::NodeStats;

    let nodes = fetch_remote_nodes(state).await.unwrap_or_default();
    let master_accepts = fetch_master_accepts_hostings(state).await;

    // Collect candidate NodeStats. Each entry is (target_string, NodeStats).
    let mut candidates: Vec<(String, NodeStats)> = Vec::with_capacity(nodes.len() + 1);

    if master_accepts {
        if let Ok(RpcResponse::ClusterStats(c)) =
            hyperion_rpc_client::call(&state.agent_socket, Request::ClusterStats).await
        {
            if let Some(mut n) = c.nodes.into_iter().next() {
                if n.label.is_empty() {
                    n.label = "master".into();
                }
                if n.agent_online {
                    candidates.push((crate::dispatcher::LOCAL_NODE_SENTINEL.to_string(), n));
                }
            }
        }
    }

    for ns in nodes {
        match crate::dispatcher::dispatch_to_node(state, Some(&ns.node_id), Request::ClusterStats)
            .await
        {
            Ok(RpcResponse::ClusterStats(c)) => {
                if let Some(stat) = c.nodes.into_iter().next() {
                    if stat.agent_online {
                        candidates.push((ns.node_id.clone(), stat));
                    }
                }
            }
            _ => {
                tracing::warn!(node = %ns.node_id, "auto-placement: stats unavailable; skipping");
            }
        }
    }

    if candidates.is_empty() {
        return None;
    }

    // Normalise each axis to [0, 1]. Lower = better. A zero-range
    // axis collapses to 0 contribution (every candidate is equal on
    // that axis).
    let max_host = candidates.iter().map(|(_, s)| s.hostings_count).max().unwrap_or(0);
    let max_load = candidates.iter().map(|(_, s)| s.loadavg_1m_x100).max().unwrap_or(0);
    let max_mem_pct: f64 = candidates
        .iter()
        .map(|(_, s)| mem_pct(s))
        .fold(0.0_f64, f64::max);

    let mut scored: Vec<(String, f64)> = candidates
        .iter()
        .map(|(id, s)| {
            let h = if max_host > 0 {
                s.hostings_count as f64 / max_host as f64
            } else {
                0.0
            };
            let l = if max_load > 0 {
                s.loadavg_1m_x100 as f64 / max_load as f64
            } else {
                0.0
            };
            let m_pct = mem_pct(s);
            let m = if max_mem_pct > 0.0 { m_pct / max_mem_pct } else { 0.0 };
            let score = 0.45 * h + 0.35 * l + 0.20 * m;
            (id.clone(), score)
        })
        .collect();
    // Stable tiebreak: lexicographically smaller node_id wins.
    scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));
    scored.into_iter().next().map(|(id, _)| id)
}

fn mem_pct(s: &hyperion_types::NodeStats) -> f64 {
    if s.mem_total_kib <= 0 {
        return 0.0;
    }
    (s.mem_used_kib as f64 / s.mem_total_kib as f64).clamp(0.0, 1.0)
}

/// Locate which node a hosting lives on, so per-hosting actions
/// (suspend, resume, set-limits, backup, cert, …) dispatched from
/// the detail page land on the right agent.
///
/// Strategy: try the master's local socket first (the common case).
/// On NotFound, fan out across enrolled nodes. The first one that
/// returns the hosting wins; its `node_id` is returned so the
/// handler can pass it to `dispatch_to_node`.
///
/// Returns `(HostingDetail, node_id_or_None)`. `None` means master.
pub async fn find_hosting_anywhere(
    state: &SharedState,
    sel: HostingSelector,
) -> Result<(hyperion_types::HostingDetail, Option<String>), AppError> {
    // 1. Master local.
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingGet(sel.clone()),
    )
    .await
    {
        Ok(RpcResponse::HostingGet(d)) => return Ok((d, None)),
        Ok(RpcResponse::Error(e)) if !is_not_found_error(&e) => {
            return Err(AppError::Rpc(e.to_string()));
        }
        Ok(_) => {}
        Err(e) => return Err(AppError::from(e)),
    }
    // 2. Fan out to enrolled nodes.
    let nodes_resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await;
    let nodes: Vec<hyperion_types::NodeSummary> = match nodes_resp {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(),
    };
    for n in nodes {
        let r = crate::dispatcher::dispatch_to_node(
            state,
            Some(&n.node_id),
            Request::HostingGet(sel.clone()),
        )
        .await;
        match r {
            Ok(RpcResponse::HostingGet(d)) => return Ok((d, Some(n.node_id))),
            Ok(RpcResponse::Error(_)) => continue, // not on this node
            _ => continue,
        }
    }
    Err(AppError::NotFound)
}

fn is_not_found_error(e: &hyperion_rpc::error::RpcError) -> bool {
    matches!(e, hyperion_rpc::error::RpcError::NotFound { .. })
}

/// Aggregate hostings from the master + every enrolled remote node.
/// Each row gets its `node_id` field REWRITTEN to the master's
/// identifier for that node ("local" sentinel for master, the
/// enrolled `node_id` for each worker) so the templates can show
/// + the action forms can dispatch correctly without translating
/// hostname↔enrolled-id (which differs because workers' hostings
/// rows tag node_id with their hostname, while the master's view
/// of "which node is this" uses the enrolled id).
///
/// Failure to reach a remote node is logged and that node's
/// hostings are simply omitted — the local list still renders.
async fn list_hostings(state: &SharedState) -> Result<Vec<HostingSummary>, String> {
    // 1. Master's own hostings (always included).
    let local_resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingList)
        .await
        .map_err(|e| e.to_string())?;
    let mut local: Vec<HostingSummary> = match local_resp {
        RpcResponse::HostingList(v) => v,
        RpcResponse::Error(e) => return Err(e.to_string()),
        _ => return Err("unexpected response".into()),
    };
    for r in &mut local {
        r.node_id = Some(crate::dispatcher::LOCAL_NODE_SENTINEL.to_string());
    }

    // 2. Enrolled remote nodes — best-effort fan-out.
    let nodes_resp = hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await;
    let nodes: Vec<hyperion_types::NodeSummary> = match nodes_resp {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(), // failed lookup — fall back to master-only
    };
    let mut all = local;
    for n in nodes {
        match crate::dispatcher::dispatch_to_node(
            state,
            Some(&n.node_id),
            Request::HostingList,
        )
        .await
        {
            Ok(RpcResponse::HostingList(mut remote)) => {
                for r in &mut remote {
                    r.node_id = Some(n.node_id.clone());
                }
                all.extend(remote);
            }
            Ok(RpcResponse::Error(e)) => {
                tracing::warn!(node=%n.node_id, error=%e, "remote hosting list refused");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(node=%n.node_id, error=%e, "remote hosting list unreachable");
            }
        }
    }
    Ok(all)
}

// ==================================================================
//  DNS check + real ACME issue + restore
// ==================================================================

#[derive(Deserialize)]
pub struct DnsCheckForm {
    pub selector: String,
}

/// HTMX-style endpoint: returns just the result fragment (not a full page)
/// so the operator can poll without losing the rest of the screen.
/// HTMX endpoint for the **create form**: DNS preflight against a
/// raw domain string (no existing hosting yet). Returns the same
/// HTML fragment as `post_dns_check` so the visual feedback is
/// identical to the post-create flow.
#[derive(Deserialize)]
pub struct DnsCheckDomainForm {
    domain: String,
}

pub async fn post_dns_check_domain(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DnsCheckDomainForm>,
) -> Result<Response, AppError> {
    // Used by the new-hosting form. Match post_create's gating —
    // operators can't be on this page anyway.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let trimmed = form.domain.trim();
    let parsed = match Domain::parse(trimmed) {
        Ok(d) => d,
        Err(e) => {
            return Ok(Html(format!(
                "<div class=\"flash error\"><div class=\"flash-body\">Invalid domain: {}</div></div>",
                askama_escape::escape(&e.to_string(), askama_escape::Html)
            ))
            .into_response());
        }
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::DnsCheck { domain: parsed },
    )
    .await?;
    let html = match resp {
        RpcResponse::DnsCheck(r) => render_dns_fragment(&r),
        RpcResponse::Error(e) => format!(
            "<div class=\"flash error\"><div class=\"flash-body\">DNS check failed: {}</div></div>",
            askama_escape::escape(&e.to_string(), askama_escape::Html)
        ),
        _ => "<div class=\"flash error\"><div class=\"flash-body\">Unexpected response.</div></div>"
            .into(),
    };
    Ok(Html(html).into_response())
}

pub async fn post_dns_check(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DnsCheckForm>,
) -> Result<Response, AppError> {
    // DNS check is non-mutating but ties to a specific hosting; gate
    // at manage so a viewer can't probe via this endpoint.
    let detail_sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let detail_resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingGet(detail_sel)).await?;
    let domain = match detail_resp {
        RpcResponse::HostingGet(d) => Domain::parse(&d.domain)?,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::DnsCheck { domain }).await?;
    let html = match resp {
        RpcResponse::DnsCheck(r) => render_dns_fragment(&r),
        RpcResponse::Error(e) => {
            format!(
                "<div class=\"flash error\"><div class=\"flash-body\">DNS check failed: {}</div></div>",
                askama_escape::escape(&e.to_string(), askama_escape::Html)
            )
        }
        _ => "<div class=\"flash error\"><div class=\"flash-body\">Unexpected response.</div></div>"
            .into(),
    };
    Ok(Html(html).into_response())
}

fn render_dns_fragment(r: &DnsCheckResult) -> String {
    let esc = |s: &str| askama_escape::escape(s, askama_escape::Html).to_string();
    let badge = if r.matches {
        "<span class=\"pill ok\">matches ✓</span>"
    } else {
        "<span class=\"pill err\">no match ✗</span>"
    };
    let a_list = if r.resolved_a.is_empty() {
        "<span class=\"text-soft\">none</span>".to_string()
    } else {
        r.resolved_a
            .iter()
            .map(|ip| format!("<code>{}</code>", esc(ip)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let aaaa_list = if r.resolved_aaaa.is_empty() {
        "<span class=\"text-soft\">none</span>".to_string()
    } else {
        r.resolved_aaaa
            .iter()
            .map(|ip| format!("<code>{}</code>", esc(ip)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let our_v4 = r.our_public_ipv4.as_deref().unwrap_or("?");
    let our_v6 = r.our_public_ipv6.as_deref().unwrap_or("?");
    format!(
        r#"<div class="kv" style="margin-top:0.5rem">
            <dt>Status</dt><dd>{badge}</dd>
            <dt>A records</dt><dd>{a_list}</dd>
            <dt>AAAA records</dt><dd>{aaaa_list}</dd>
            <dt>Our IPv4</dt><dd><code>{ipv4}</code></dd>
            <dt>Our IPv6</dt><dd><code>{ipv6}</code></dd>
        </div>
        <p class="muted" style="font-size:0.85rem;margin-top:0.7rem;margin-bottom:0">{note}</p>"#,
        badge = badge,
        a_list = a_list,
        aaaa_list = aaaa_list,
        ipv4 = esc(our_v4),
        ipv6 = esc(our_v6),
        note = esc(&r.note),
    )
}

#[derive(Deserialize)]
pub struct CertIssueForm {
    pub selector: String,
    #[serde(default)]
    pub staging: Option<String>,
    #[serde(default)]
    pub require_dns_match: Option<String>,
}

pub async fn post_cert_issue(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CertIssueForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let req = CertIssueRequest {
        staging: form.staging.as_deref() == Some("on"),
        require_dns_match: form.require_dns_match.as_deref() != Some("off"),
        extra_sans: vec![],
    };
    let staging = req.staging;
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::CertIssueAcme { sel, req }).await?;
    match resp {
        RpcResponse::CertIssueAcme(_) => {
            let kind = if staging { "staging" } else { "prod" };
            Ok(Redirect::to(&format!("/hostings/{}?cert={}", sel_url, kind)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cert_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct RestoreForm {
    pub selector: String,
    pub archive_path: String,
}

#[derive(Deserialize)]
pub struct LogsForm {
    pub selector: String,
    pub kind: String,
    #[serde(default = "default_log_lines")]
    pub lines: i64,
}
fn default_log_lines() -> i64 {
    200
}

pub async fn post_logs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<LogsForm>,
) -> Result<Response, AppError> {
    // Logs can carry sensitive request data and stack traces — gate
    // them at manage level just like the other per-hosting writes.
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingLogs {
            sel,
            log_kind: form.kind.clone(),
            lines: form.lines,
        },
    )
    .await?;
    let body = match resp {
        RpcResponse::HostingLogs(s) => s,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let kind = askama_escape::escape(&form.kind, askama_escape::Html).to_string();
    let lines_label = form.lines;
    let pre = if body.trim().is_empty() {
        format!(
            r#"<div class="muted" style="padding:0.5rem 0">No {kind} log entries.</div>"#,
            kind = kind
        )
    } else {
        let esc = askama_escape::escape(&body, askama_escape::Html).to_string();
        format!(
            r#"<div class="muted" style="font-size:0.8rem;margin-bottom:0.4rem">Last {lines} lines · {kind}.log</div>
<pre style="max-height:36rem;overflow:auto;font-size:11.5px;line-height:1.5">{esc}</pre>"#,
            lines = lines_label,
            kind = kind,
            esc = esc
        )
    };
    Ok(Html(pre).into_response())
}

#[derive(Deserialize)]
pub struct CronForm {
    pub selector: String,
    pub body: String,
}

pub async fn post_cron_save(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CronForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::CronReplace {
            sel,
            body: form.body,
        },
    )
    .await?;
    match resp {
        RpcResponse::CronReplace => {
            Ok(Redirect::to(&format!("/hostings/{}?cron=saved", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cron_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpResetForm {
    pub selector: String,
    pub wp_user: String,
    pub new_password: String,
}

/// Multipart upload of a tar.gz backup archive. Saved to
/// /var/lib/hyperion/backups/incoming/<sanitized-filename> then handed
/// off to the existing BackupRestore RPC.
pub async fn post_restore_upload(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    mut multipart: axum::extract::Multipart,
) -> Result<Response, AppError> {
    let mut selector: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        match field.name() {
            Some("selector") => {
                selector = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("selector: {e}")))?,
                );
            }
            Some("archive") => {
                filename = field.file_name().map(|s| {
                    s.chars()
                        .filter(|c| c.is_ascii_alphanumeric() || ['.', '-', '_'].contains(c))
                        .collect()
                });
                bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("read archive: {e}")))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }
    let selector = selector.ok_or_else(|| AppError::BadRequest("missing selector".into()))?;
    // Authorize BEFORE touching the filesystem — a viewer must not be
    // able to dump arbitrary tarballs into /var/lib/hyperion/backups
    // even if they can't ultimately trigger the restore.
    let sel = match require_manage_for_selector(&state, &ctx, &selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let bytes = bytes.ok_or_else(|| AppError::BadRequest("missing archive file".into()))?;
    let filename = filename
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("upload-{}.tar.gz", hyperion_types::now_secs()));
    if !filename.ends_with(".tar.gz") {
        return Err(AppError::BadRequest(
            "archive must be a .tar.gz file".into(),
        ));
    }

    let incoming_dir = std::path::PathBuf::from("/var/lib/hyperion/backups/incoming");
    tokio::fs::create_dir_all(&incoming_dir)
        .await
        .map_err(|e| AppError::Internal(format!("mkdir incoming: {e}")))?;
    let dest = incoming_dir.join(&filename);
    tokio::fs::write(&dest, &bytes)
        .await
        .map_err(|e| AppError::Internal(format!("write upload: {e}")))?;

    let sel_url = urlencoding(&selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupRestore {
            sel,
            archive_path: dest.display().to_string(),
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupRestore => {
            Ok(Redirect::to(&format!("/hostings/{}?restore=ok", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?restore_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct BulkForm {
    pub action: String,
    /// Comma-separated list of selectors (domains). Browsers POST checkboxes
    /// one per name, so we use serde to gather them into a Vec. Axum's Form
    /// extractor surfaces repeated fields as comma-separated when the form
    /// type expects a String — use the manual deserializer instead.
    #[serde(default)]
    pub selected: Vec<String>,
    /// Asset id for the `install_asset` bulk action. 0 / unset for
    /// every other action.
    #[serde(default)]
    pub asset_id: i64,
    /// Whether to also activate the asset after install. Plain
    /// HTML checkbox → "on" when ticked, missing when not.
    #[serde(default)]
    pub activate: Option<String>,
}

pub async fn post_bulk(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BulkForm>,
) -> Result<Response, AppError> {
    // Bulk ops span arbitrary hostings (admin can pick anything in the
    // list). Operators with per-hosting grants don't get to run bulk
    // delete across the cluster — that's an admin-level lever.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    if form.selected.is_empty() {
        return Ok(Redirect::to("/hostings?q=&state=").into_response());
    }
    // Pre-flight validation for install_asset — surface a single
    // clean error rather than echoing it per-selected hosting.
    if form.action == "install_asset" && form.asset_id <= 0 {
        return Ok(Redirect::to(
            "/hostings?bulk_flash=Pick+an+asset+from+the+library+before+running+the+bulk+install",
        )
        .into_response());
    }
    let activate = matches!(form.activate.as_deref(), Some("on" | "true" | "1"));
    let mut ok = 0;
    let mut errs: Vec<String> = vec![];
    for sel_str in &form.selected {
        let sel = match parse_selector(sel_str) {
            Ok(s) => s,
            Err(e) => {
                errs.push(format!("{sel_str}: {e}"));
                continue;
            }
        };
        // For multi-node correctness: actions like suspend/resume/
        // delete/install_asset have to land on the node that
        // actually owns the hosting. Look it up first (best-effort —
        // single-node setups treat all hostings as local). The
        // backup action stays master-local because backups are
        // currently a master-side operation only.
        let target_owned: Option<String> = match form.action.as_str() {
            "backup" => None,
            _ => find_hosting_anywhere(&state, sel.clone())
                .await
                .ok()
                .and_then(|(_d, n)| n),
        };
        let target = target_owned.as_deref();
        let req = match form.action.as_str() {
            "suspend" => Request::HostingSuspend {
                sel,
                reason: hyperion_types::SuspendReason::Manual {
                    message: Some("bulk suspend".into()),
                },
            },
            "resume" => Request::HostingResume(sel),
            "backup" => Request::BackupNow { sel },
            "delete" => Request::HostingDelete {
                sel,
                opts: hyperion_rpc::wire::DeleteOpts {
                    keep_user: false,
                    keep_database: false,
                },
            },
            "install_asset" => Request::WpInstallFromAsset {
                sel,
                asset_id: form.asset_id,
                activate,
            },
            other => {
                return Err(AppError::BadRequest(format!(
                    "unknown bulk action: {other}"
                )));
            }
        };
        let result = crate::dispatcher::dispatch_to_node(&state, target, req).await;
        match result {
            Ok(RpcResponse::Error(e)) => errs.push(format!("{sel_str}: {e}")),
            Ok(_) => ok += 1,
            Err(e) => errs.push(format!("{sel_str}: {e}")),
        }
    }
    let flash = if errs.is_empty() {
        format!("{} {} {}", ok, form.action, if ok == 1 { "ok" } else { "ok" })
    } else {
        format!(
            "{} succeeded, {} failed: {}",
            ok,
            errs.len(),
            errs.into_iter().take(3).collect::<Vec<_>>().join("; ")
        )
    };
    let q = urlencoding(&flash);
    Ok(Redirect::to(&format!("/hostings?bulk_flash={}", q)).into_response())
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
    #[serde(default)]
    pub slug: String,
    pub action: String,
    #[serde(default)]
    pub source: String,
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
}

/// POST /hostings/wp/theme-action — single endpoint for every
/// whitelisted theme verb. Mirrors post_wp_plugin_action but
/// follows the hosting via target_node.
pub async fn post_wp_theme_action(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpThemeActionForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
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
    let target = if form.target_node.is_empty()
        || form.target_node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(form.target_node.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::WpThemeAction { sel, slug, action },
    )
    .await?;
    match resp {
        RpcResponse::WpThemeAction(r) => {
            let msg = format!("Theme {}: {}", r.state, r.message);
            Ok(Redirect::to(&format!(
                "/hostings/{}?{}={}#themes",
                sel_url,
                if r.state == "failed" { "wp_error" } else { "wp_flash" },
                urlencoding(&msg)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/{}?wp_error={}#themes",
            sel_url,
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /hostings/migration/export
///
/// Trigger a migration-bundle export on the source node. Returns a
/// redirect to the detail page with the bundle paths flashed —
/// operator copies the scp one-liner from there. The bundle stays on
/// disk until the operator deletes it (no auto-prune for now).
#[derive(Deserialize)]
pub struct MigrationExportForm {
    pub selector: String,
}

/// Template for the one-shot "export result" page rendered inline as
/// the POST response (NOT a redirect — the URL would otherwise carry
/// the signed token through browser history and the Referer header).
#[derive(Template)]
#[template(path = "migration_export_result.html")]
struct MigrationExportResultTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    selector: &'a str,
    bundle: hyperion_types::HostingMigrationBundle,
    /// Session-wide CSRF token. Currently unread by the template
    /// itself (no forms on the result page), but populated so a
    /// future "delete bundle now" or "regenerate token" button can
    /// drop in without re-plumbing the handler.
    #[allow(dead_code)]
    csrf_token: String,
}

/// One-click migration: export the hosting from its current node,
/// hand the signed download URL to the target node, wait for the
/// import to finish. After success, the OLD hosting is suspended
/// (NOT deleted — operator should verify the new one before
/// pulling the trigger).
///
/// Current limitation: only works when the SOURCE is the master.
/// Worker-to-worker / worker-to-master needs the master to proxy
/// the bundle bytes (each worker holds its own /var/lib/hyperion/
/// migration/<id>/ — only master serves the /api/migration/bundle/
/// route). That's a follow-up.
#[derive(Deserialize)]
pub struct MigrationMoveForm {
    pub selector: String,
    pub target_node: String,
    /// Hidden — populated by the JS-injected hidden input. Identifies
    /// which node the hosting currently LIVES on (source).
    #[serde(default)]
    pub source_node: String,
}

pub async fn post_migration_move(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<MigrationMoveForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);

    // 0. Sanity gates.
    let target = form.target_node.trim();
    if target.is_empty() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error=Pick+a+target+node+for+migration#migration",
            sel_url
        ))
        .into_response());
    }
    let source_local = form.source_node.is_empty()
        || form.source_node == crate::dispatcher::LOCAL_NODE_SENTINEL;
    let source_node_str = if source_local {
        crate::dispatcher::LOCAL_NODE_SENTINEL.to_string()
    } else {
        form.source_node.clone()
    };
    let target_owned = target.to_string();
    if target_owned == source_node_str {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#migration",
            sel_url,
            urlencoding("Target node must be different from the source.")
        ))
        .into_response());
    }

    // 1. Export the bundle on the source. Dispatches to the source
    // node (master OR worker) so the archive lands on the source's
    // local /var/lib/hyperion/migration/<id>/.
    let source_dispatch = if source_local {
        None
    } else {
        Some(form.source_node.as_str())
    };
    let export = crate::dispatcher::dispatch_to_node(
        &state,
        source_dispatch,
        Request::HostingExport { hosting: sel.clone() },
    )
    .await?;
    let bundle = match export {
        RpcResponse::HostingExport(b) => b,
        RpcResponse::Error(e) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?flash_error={}#migration",
                sel_url,
                urlencoding(&format!("Export failed: {e}"))
            ))
            .into_response());
        }
        _ => return Err(AppError::Internal("expected HostingExport".into())),
    };

    // 1b. When the source was a worker the bundle files live on
    // its disk — pull them to the master so the existing
    // /api/migration/bundle/ download URL serves the right bytes.
    if !source_local {
        if let Err(e) = pull_bundle_from_worker(
            &state,
            &form.source_node,
            &bundle.bundle_id,
        )
        .await
        {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?flash_error={}#migration",
                sel_url,
                urlencoding(&format!("Bundle proxy failed: {e}"))
            ))
            .into_response());
        }
    }

    // 2. Mint a signed download URL so the target node can fetch
    //    archive.tar.gz + manifest.json from the master's
    //    /api/migration/bundle/<id>/ route. Reuse the same TTL +
    //    signing-key path the standalone export already uses.
    let master_url = super::derive_master_url(&state, &headers).await;
    let exp = hyperion_types::now_secs()
        + crate::handlers::migration::BUNDLE_DOWNLOAD_TTL_SECS;
    let token =
        hyperion_auth::bundle_sig::mint(state.csrf_key.as_ref(), &bundle.bundle_id, exp);
    let base_url = format!("{master_url}/api/migration/bundle/{}", bundle.bundle_id);
    // 3. Tell the TARGET node to fetch + import. Importer
    // appends `?t=<token>` to both manifest.json + archive.tar.gz.
    let import = crate::dispatcher::dispatch_to_node(
        &state,
        Some(&target_owned),
        Request::HostingImportFromUrl {
            base_url: base_url.clone(),
            token: token.clone(),
        },
    )
    .await?;
    let new_id = match import {
        RpcResponse::HostingImportFromUrl(r) => r.new_hosting_id,
        RpcResponse::Error(e) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?flash_error={}#migration",
                sel_url,
                urlencoding(&format!("Target import failed: {e}"))
            ))
            .into_response());
        }
        _ => return Err(AppError::Internal("expected HostingImportFromUrl".into())),
    };

    // 4. Suspend the source — leaves it offline-but-recoverable so
    //    the operator can verify the new hosting works before
    //    pulling the trigger on delete. Best-effort. Dispatched to
    //    the SOURCE node (master OR worker) so we suspend the right
    //    copy when the source isn't the master.
    let _ = crate::dispatcher::dispatch_to_node(
        &state,
        source_dispatch,
        Request::HostingSuspend {
            sel: sel.clone(),
            reason: hyperion_types::SuspendReason::Manual {
                message: Some(format!(
                    "Migrated to node {target_owned} as {} — verify and delete here when ready.",
                    new_id.as_str()
                )),
            },
        },
    )
    .await;

    self::audit_migration_move(&state, &ctx, &form.selector, &target_owned, &new_id).await;

    // 5. Land the operator on the NEW hosting's detail page.
    Ok(Redirect::to(&format!(
        "/hostings/{}?flash={}",
        urlencoding(&form.selector),
        urlencoding(&format!(
            "Migrated to node {target_owned}. New hosting id: {}. Source is suspended — delete it from the Danger tab once you've verified the new one is live.",
            new_id.as_str()
        ))
    ))
    .into_response())
}

/// Write an audit-log entry on the master for the migration move.
/// Best-effort — failure here doesn't block the operator.
async fn audit_migration_move(
    state: &SharedState,
    _ctx: &AuthCtx,
    selector: &str,
    target_node: &str,
    new_id: &hyperion_types::HostingId,
) {
    // The audit RPC is server-side under hosting actions; reusing
    // it here would require a dedicated RPC. For now just log.
    tracing::info!(
        selector = selector,
        target_node = target_node,
        new_hosting_id = new_id.as_str(),
        operator = %_ctx.username,
        "hosting migrated via one-click UI"
    );
    let _ = state;
}

pub async fn post_migration_export(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<MigrationExportForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingExport { hosting: sel },
    )
    .await?;
    match resp {
        RpcResponse::HostingExport(mut b) => {
            // Mint the signed download URL — agent has no idea what
            // master URL the operator's browser used to reach us, so
            // the web layer is the only thing that can derive it.
            let master_url = super::derive_master_url(&state, &headers).await;
            let exp = hyperion_types::now_secs()
                + crate::handlers::migration::BUNDLE_DOWNLOAD_TTL_SECS;
            let token = hyperion_auth::bundle_sig::mint(
                state.csrf_key.as_ref(),
                &b.bundle_id,
                exp,
            );
            b.download_base_url = format!(
                "{master_url}/api/migration/bundle/{}",
                b.bundle_id
            );
            b.bundle_token = token;
            b.token_expires_at = exp;

            let tpl = MigrationExportResultTpl {
                username: &ctx.username,
                user_initial: super::user_initial(&ctx.username),
                active: "hostings",
                css_version: super::css_version(),
                htmx_version: super::htmx_version(),
                selector: &form.selector,
                bundle: b,
                csrf_token: super::session_csrf_token(&state, &ctx),
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&format!("Migration export failed: {}", e));
            Ok(Redirect::to(&format!("/hostings/{}?flash_error={}#migration", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// derive_master_url is the shared helper in handlers::mod — see
// there for the loopback-detection + public-IP fallback rationale.
// Hostings caller imports via the super:: path below.

pub async fn post_wp_plugin_action(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpPluginActionForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
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
            hyperion_types::WpPluginAction::Install { source }
        }
        "activate" => hyperion_types::WpPluginAction::Activate,
        "deactivate" => hyperion_types::WpPluginAction::Deactivate,
        "update" => hyperion_types::WpPluginAction::Update,
        "update_all" => hyperion_types::WpPluginAction::UpdateAll,
        "delete" => hyperion_types::WpPluginAction::Delete,
        "auto_update_enable" => hyperion_types::WpPluginAction::SetAutoUpdate { enabled: true },
        "auto_update_disable" => hyperion_types::WpPluginAction::SetAutoUpdate { enabled: false },
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
        hyperion_types::WpPluginAction::Install { source } => source.clone(),
        _ => {
            let s = form.slug.trim().to_string();
            if s.is_empty() {
                return Err(AppError::BadRequest("missing plugin slug".into()));
            }
            s
        }
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WpPluginAction { hosting: sel, slug, action },
    )
    .await?;
    match resp {
        RpcResponse::WpPluginAction(r) => {
            // Encode the state + a short message into the redirect so the
            // detail page can pop a toast on next render.
            let flash = format!(
                "Plugin {}: {}",
                r.state,
                r.message.chars().take(140).collect::<String>(),
            );
            let q = urlencoding(&flash);
            let key = if r.state == "ok" || r.state == "noop" {
                "flash"
            } else {
                "flash_error"
            };
            Ok(Redirect::to(&format!("/hostings/{}?{}={}#wp", sel_url, key, q)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&format!("Plugin action failed: {}", e));
            Ok(
                Redirect::to(&format!("/hostings/{}?flash_error={}#wp", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_wp_reset(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpResetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
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
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?wp_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DbResetForm {
    pub selector: String,
    pub new_password: String,
}

pub async fn post_db_reset(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DbResetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::DbResetPassword {
            sel,
            new_password: form.new_password,
        },
    )
    .await?;
    match resp {
        RpcResponse::DbResetPassword => {
            Ok(Redirect::to(&format!("/hostings/{}?db=reset", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?db_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct FtpSetForm {
    pub selector: String,
    /// Empty → server generates one.
    #[serde(default)]
    pub new_password: String,
}

pub async fn post_ftp_set(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpSetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::FtpSetPassword {
            sel,
            new_password: form.new_password,
        },
    )
    .await?;
    match resp {
        RpcResponse::FtpSetPassword { password } => {
            Ok(Redirect::to(&format!(
                "/hostings/{}?ftp=set&ftp_pw={}#settings",
                sel_url,
                urlencoding(&password)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?ftp_error={}#settings", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct FtpDisableForm {
    pub selector: String,
}

pub async fn post_ftp_disable(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpDisableForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::FtpDisable { sel }).await?;
    match resp {
        RpcResponse::FtpDisable => {
            Ok(Redirect::to(&format!("/hostings/{}?ftp=disabled#settings", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?ftp_error={}#settings", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_restore(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RestoreForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupRestore {
            sel,
            archive_path: form.archive_path.trim().to_string(),
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupRestore => {
            Ok(Redirect::to(&format!("/hostings/{}?restore=ok", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?restore_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
