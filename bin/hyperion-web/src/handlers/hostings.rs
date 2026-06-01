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
    DbProvision, HostingDetail, HostingSummary, PhpVersion, WpInstallRequest, WpInstallStatus,
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
    rows: Vec<HostingSummary>,
    csrf_token: String,
    error: Option<String>,
    flash: Option<String>,
}

#[derive(Template)]
#[template(path = "hostings_new.html")]
struct NewTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
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
    detail: HostingDetail,
    limits: hyperion_types::HostingLimits,
    wp_status: Option<WpInstallStatus>,
    expiry: hyperion_types::HostingExpiry,
    backups: Vec<hyperion_types::BackupRunWire>,
    csrf_delete: String,
    csrf_suspend: String,
    csrf_resume: String,
    csrf_limits: String,
    csrf_wp_install: String,
    csrf_backup_now: String,
    csrf_expiry_set: String,
    csrf_expiry_clear: String,
    error: Option<&'a str>,
    wp_error: Option<String>,
    wp_flash: Option<String>,
    backup_error: Option<String>,
    backup_flash: Option<String>,
    expiry_error: Option<String>,
    expiry_flash: Option<String>,
    just_created: Option<HostingCreated>,
}

pub async fn get_list(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let rows = list_hostings(&state).await.map_err(AppError::Rpc)?;
    let csrf_token = csrf_token_for(&state, &ctx, "/hostings/delete");
    let tpl = ListTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        rows,
        csrf_token,
        error: None,
        flash: None,
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_new(State(state): State<SharedState>, ctx: AuthCtx) -> Result<Response, AppError> {
    let csrf_token = csrf_token_for(&state, &ctx, "/hostings");
    let tpl = NewTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
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
                detail,
                limits,
                wp_status: None,
                expiry: hyperion_types::HostingExpiry::defaults(),
                backups: vec![],
                csrf_delete: csrf_token_for(&state, &ctx, "/hostings/delete"),
                csrf_suspend: csrf_token_for(&state, &ctx, "/hostings/suspend"),
                csrf_resume: csrf_token_for(&state, &ctx, "/hostings/resume"),
                csrf_limits: csrf_token_for(&state, &ctx, "/hostings/set-limits"),
                csrf_wp_install: csrf_token_for(&state, &ctx, "/hostings/wp/install"),
                csrf_backup_now: csrf_token_for(&state, &ctx, "/hostings/backup-now"),
                csrf_expiry_set: csrf_token_for(&state, &ctx, "/hostings/expiry/set"),
                csrf_expiry_clear: csrf_token_for(&state, &ctx, "/hostings/expiry/clear"),
                error: None,
                wp_error: None,
                wp_flash: None,
                backup_error: None,
                backup_flash: None,
                expiry_error: None,
                expiry_flash: None,
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
    let backups = fetch_backup_list(&state, sel_id, 10)
        .await
        .unwrap_or_default();
    let tpl = DetailTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        detail,
        limits,
        wp_status,
        expiry,
        backups,
        csrf_delete: csrf_token_for(&state, &ctx, "/hostings/delete"),
        csrf_suspend: csrf_token_for(&state, &ctx, "/hostings/suspend"),
        csrf_resume: csrf_token_for(&state, &ctx, "/hostings/resume"),
        csrf_limits: csrf_token_for(&state, &ctx, "/hostings/set-limits"),
        csrf_wp_install: csrf_token_for(&state, &ctx, "/hostings/wp/install"),
        csrf_backup_now: csrf_token_for(&state, &ctx, "/hostings/backup-now"),
        csrf_expiry_set: csrf_token_for(&state, &ctx, "/hostings/expiry/set"),
        csrf_expiry_clear: csrf_token_for(&state, &ctx, "/hostings/expiry/clear"),
        error: None,
        wp_error: q.wp_error,
        wp_flash: q.wp.map(|_| "WordPress install succeeded.".into()),
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
        just_created: None,
    };
    Ok(Html(tpl.render()?).into_response())
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
