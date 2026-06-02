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
}

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
    just_created: Option<HostingCreated>,
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
    let csrf_token = csrf_token_for(&state, &ctx, "/hostings");
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
}

pub async fn post_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    let csrf_token = csrf_token_for(&state, &ctx, "/hostings");
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
    let req = HostingCreateReq {
        domain,
        aliases,
        php_version,
        database,
        system_user,
    };
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingCreate(req.clone()))
        .await
        .map_err(AppError::from)?;
    match resp {
        RpcResponse::HostingCreate(created) => {
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
                just_created: Some(created),
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
    let sel_id = HostingSelector::Id(detail.id.clone());
    let limits = fetch_limits(&state, sel_id.clone())
        .await
        .unwrap_or_else(|_| hyperion_types::HostingLimits::defaults());
    let wp_status = fetch_wp_status(&state, sel_id.clone())
        .await
        .unwrap_or(None);
    let expiry = fetch_expiry(&state, sel_id.clone())
        .await
        .unwrap_or_else(|_| hyperion_types::HostingExpiry::defaults());
    let backups = fetch_backup_list(&state, sel_id.clone(), 10)
        .await
        .unwrap_or_default();
    let stats = fetch_stats(&state, sel_id.clone()).await.ok();
    let cron_body = fetch_cron(&state, sel_id.clone()).await.unwrap_or_default();
    let profile_apply = fetch_profile_apply(&state, sel_id).await.unwrap_or(None);
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
        just_created: None,
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
    Form(form): Form<BackupNowForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<SetExpiryForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<ClearExpiryForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<WpInstallForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<SuspendForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<ResumeForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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

pub async fn post_set_limits(
    State(state): State<SharedState>,
    Form(form): Form<SetLimitsForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
pub async fn post_dns_check(
    State(state): State<SharedState>,
    Form(form): Form<DnsCheckForm>,
) -> Result<Response, AppError> {
    let detail_sel = parse_selector(&form.selector)?;
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
    Form(form): Form<CertIssueForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<LogsForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<CronForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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

    let sel = parse_selector(&selector)?;
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
    Form(form): Form<BulkForm>,
) -> Result<Response, AppError> {
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

pub async fn post_wp_reset(
    State(state): State<SharedState>,
    Form(form): Form<WpResetForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
    Form(form): Form<DbResetForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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

pub async fn post_restore(
    State(state): State<SharedState>,
    Form(form): Form<RestoreForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
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
