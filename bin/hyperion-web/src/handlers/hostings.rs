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
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_new(State(state): State<SharedState>, ctx: AuthCtx) -> Result<Response, AppError> {
    // Wildcard CSRF token so it also covers the DNS-preflight HTMX
    // button (form_id /hostings/dns-check-domain) in addition to the
    // main /hostings POST.
    let csrf_token = super::session_csrf_token(&state, &ctx);
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
    };
    Ok(Html(tpl.render()?).into_response())
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
    /// "on" if the user checked the "install WordPress" checkbox.
    #[serde(default)]
    pub install_wp: String,
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
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingCreate(req.clone()))
        .await
        .map_err(AppError::from)?;
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
                if admin_email.is_empty() || admin_password.len() < 6 {
                    // Don't fail the whole create — the hosting is
                    // alive. Just leave WP uninstalled.
                    tracing::warn!(
                        "WP install requested but missing/short credentials; skipping"
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
                        admin_user: "admin".to_string(),
                        admin_email: admin_email.to_string(),
                        admin_password: admin_password.clone(),
                        locale,
                        version: "latest".to_string(),
                    };
                    let install_resp = hyperion_rpc_client::call(
                        &state.agent_socket,
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
                                admin_user: "admin".into(),
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

            // Re-fetch detail for nice display.
            let detail_resp = hyperion_rpc_client::call(
                &state.agent_socket,
                Request::HostingGet(HostingSelector::Id(created.id.clone())),
            )
            .await
            .map_err(AppError::from)?;
            let detail = match detail_resp {
                RpcResponse::HostingGet(d) => d,
                _ => return Err(AppError::Internal("expected HostingGet".into())),
            };
            let limits = fetch_limits(&state, HostingSelector::Id(created.id.clone()))
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
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingGet(sel)).await?;
    let detail = match resp {
        RpcResponse::HostingGet(d) => d,
        RpcResponse::Error(hyperion_rpc::RpcError::NotFound { .. }) => {
            return Err(AppError::NotFound)
        }
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    // RBAC guard: operator + viewer must have an access grant.
    // super_admin + admin pass through. Unauthenticated redirects to
    // /login earlier (require_auth middleware), so unwrap to /hostings
    // for the no-access case.
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    let sel_id = HostingSelector::Id(detail.id.clone());
    let limits = fetch_limits(&state, sel_id.clone())
        .await
        .unwrap_or_else(|_| hyperion_types::HostingLimits::defaults());
    let wp_status = fetch_wp_status(&state, sel_id.clone())
        .await
        .unwrap_or(None);
    // Only ask the agent for the plugin list when WP is actually
    // installed — otherwise wp-cli fails with "Error: This does not
    // seem to be a WordPress installation." and we'd render a flash.
    let wp_plugins = if wp_status.is_some() {
        match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::WpPluginList { hosting: sel_id.clone() },
        )
        .await
        {
            Ok(RpcResponse::WpPluginList(r)) => r,
            _ => hyperion_types::WpPluginListResponse::default(),
        }
    } else {
        hyperion_types::WpPluginListResponse::default()
    };
    let expiry = fetch_expiry(&state, sel_id.clone())
        .await
        .unwrap_or_else(|_| hyperion_types::HostingExpiry::defaults());
    let backups = fetch_backup_list(&state, sel_id.clone(), 10)
        .await
        .unwrap_or_default();
    let stats = fetch_stats(&state, sel_id.clone()).await.ok();
    let cron_body = fetch_cron(&state, sel_id.clone()).await.unwrap_or_default();
    let profile_apply = fetch_profile_apply(&state, sel_id.clone()).await.unwrap_or(None);
    let profiles = fetch_all_profiles(&state).await.unwrap_or_default();
    let applied_profile_name = profile_apply
        .as_ref()
        .and_then(|a| a.profile_id)
        .and_then(|pid| profiles.iter().find(|p| p.id == pid).map(|p| p.name.clone()));
    let spf = match Domain::parse(&detail.domain) {
        Ok(d) => match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::DnsSpfCheck { domain: d },
        )
        .await
        {
            Ok(RpcResponse::DnsSpfCheck(r)) => Some(r),
            _ => None,
        },
        Err(_) => None,
    };
    // Per-hosting monitor config + history for the Monitor tab.
    let (monitor_config, monitor_history) = match hyperion_rpc_client::call(
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
    };
    // Per-hosting email log for the Emails tab.
    let email_log: Vec<hyperion_types::EmailLogEntry> = match hyperion_rpc_client::call(
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
    };
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
    };
    Ok(Html(tpl.render()?).into_response())
}

async fn fetch_profile_apply(
    state: &SharedState,
    sel: HostingSelector,
) -> Result<Option<ProfileApply>, AppError> {
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileGetApply { sel }).await?;
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

async fn fetch_cron(state: &SharedState, sel: HostingSelector) -> Result<String, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::CronList { sel }).await?;
    match resp {
        RpcResponse::CronList(s) => Ok(s),
        RpcResponse::Error(_) => Ok(String::new()),
        _ => Ok(String::new()),
    }
}

async fn fetch_stats(
    state: &SharedState,
    sel: HostingSelector,
) -> Result<HostingStats, AppError> {
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingStats { sel }).await?;
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
}

async fn fetch_expiry(
    state: &SharedState,
    sel: HostingSelector,
) -> Result<hyperion_types::HostingExpiry, AppError> {
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingGetExpiry(sel)).await?;
    match resp {
        RpcResponse::HostingGetExpiry(e) => Ok(e),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_backup_list(
    state: &SharedState,
    sel: HostingSelector,
    limit: i64,
) -> Result<Vec<hyperion_types::BackupRunWire>, AppError> {
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupList { sel, limit },
    )
    .await?;
    match resp {
        RpcResponse::BackupList(rows) => Ok(rows),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_wp_status(
    state: &SharedState,
    sel: HostingSelector,
) -> Result<Option<WpInstallStatus>, AppError> {
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::WpStatus { sel }).await?;
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
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::BackupNow { sel }).await?;
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
    sel: HostingSelector,
) -> Result<hyperion_types::HostingLimits, AppError> {
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingGetLimits(sel)).await?;
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
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingDelete { sel, opts })
        .await?;
    match resp {
        RpcResponse::HostingDelete => Ok(Redirect::to("/hostings?deleted=1").into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SuspendForm {
    selector: String,
    #[serde(default)]
    reason: String,
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
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingSuspend { sel, reason })
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
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingResume(sel)).await?;
    match resp {
        RpcResponse::HostingResume => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
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
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
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

fn urlencoding(s: &str) -> String {
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
    };
    Html(
        tpl.render()
            .unwrap_or_else(|_| "<h1>render error</h1>".into()),
    )
    .into_response()
}

async fn list_hostings(state: &SharedState) -> Result<Vec<HostingSummary>, String> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingList)
        .await
        .map_err(|e| e.to_string())?;
    match resp {
        RpcResponse::HostingList(v) => Ok(v),
        RpcResponse::Error(e) => Err(e.to_string()),
        _ => Err("unexpected response".into()),
    }
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
            other => {
                return Err(AppError::BadRequest(format!(
                    "unknown bulk action: {other}"
                )));
            }
        };
        match hyperion_rpc_client::call(&state.agent_socket, req).await {
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
            let master_url = derive_master_url(&state, &headers);
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

/// Mirror of `install::derive_master_url` — picks the externally
/// reachable URL from the request the operator made. Duplicated
/// here to keep the install handler's helper private; once we have
/// more callers we can pull this into a shared module.
fn derive_master_url(state: &SharedState, headers: &axum::http::HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| {
            if state.cfg.web.secure_cookies {
                "https".to_string()
            } else {
                "http".to_string()
            }
        });
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| state.cfg.web.listen.clone());
    format!("{scheme}://{host}")
}

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
