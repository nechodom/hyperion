//! `/profiles` — operator-defined hosting templates (limits + expiry
//! policy + pricing + optional Slack webhook).

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{HostingProfile, ProfileInput};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "profiles.html")]
struct ProfilesTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    profiles: Vec<HostingProfile>,
    csrf_create: String,
    csrf_delete: String,
    flash: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct ProfilesQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn get_profiles(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<ProfilesQuery>,
) -> Result<Response, AppError> {
    let profiles = fetch_profiles(&state).await.unwrap_or_default();
    let tpl = ProfilesTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profiles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        profiles,
        csrf_create: csrf_token(&state, &ctx, "/profiles/create"),
        csrf_delete: csrf_token(&state, &ctx, "/profiles/delete"),
        flash: q.flash,
        error: q.error,
    };
    Ok(Html(tpl.render()?).into_response())
}

async fn fetch_profiles(state: &SharedState) -> Result<Vec<HostingProfile>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::ProfileList).await?;
    match resp {
        RpcResponse::ProfileList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct CreateForm {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_256")]
    pub php_memory_mb: i64,
    #[serde(default = "default_60")]
    pub php_max_exec_secs: i64,
    #[serde(default = "default_10")]
    pub php_max_children: i64,
    #[serde(default = "default_1000")]
    pub php_max_requests: i64,
    #[serde(default = "default_50")]
    pub db_max_connections: i64,
    #[serde(default)]
    pub disk_hard_mb: String,
    #[serde(default)]
    pub bw_monthly_mb: String,
    #[serde(default = "default_30")]
    pub expiry_grace_days: i64,
    #[serde(default = "default_offsets")]
    pub expiry_warning_offsets: String,
    /// Price in major units (e.g. 199.00) — converted to minor for storage.
    #[serde(default)]
    pub price_major: String,
    #[serde(default)]
    pub price_currency: String,
    #[serde(default)]
    pub price_interval: String,
    #[serde(default)]
    pub slack_webhook: String,
}

fn default_256() -> i64 {
    256
}
fn default_60() -> i64 {
    60
}
fn default_10() -> i64 {
    10
}
fn default_1000() -> i64 {
    1000
}
fn default_50() -> i64 {
    50
}
fn default_30() -> i64 {
    30
}
fn default_offsets() -> String {
    "30,7,1".into()
}

pub async fn post_create(
    State(state): State<SharedState>,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    let price_minor = parse_price_major(&form.price_major)?;
    let currency = form.price_currency.trim().to_string();
    let interval = form.price_interval.trim().to_string();
    let input = ProfileInput {
        name: form.name,
        description: form.description,
        php_memory_mb: form.php_memory_mb,
        php_max_exec_secs: form.php_max_exec_secs,
        php_max_children: form.php_max_children,
        php_max_requests: form.php_max_requests,
        db_max_connections: form.db_max_connections,
        disk_hard_mb: parse_opt_i64(&form.disk_hard_mb),
        bw_monthly_mb: parse_opt_i64(&form.bw_monthly_mb),
        expiry_grace_days: form.expiry_grace_days,
        expiry_warning_offsets: form.expiry_warning_offsets,
        price_minor,
        price_currency: if currency.is_empty() {
            None
        } else {
            Some(currency)
        },
        price_interval: if interval.is_empty() {
            None
        } else {
            Some(interval)
        },
        slack_webhook: if form.slack_webhook.trim().is_empty() {
            None
        } else {
            Some(form.slack_webhook.trim().to_string())
        },
    };
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileCreate(input)).await?;
    match resp {
        RpcResponse::ProfileCreate(p) => Ok(Redirect::to(&format!(
            "/profiles?flash={}",
            urlencoding(&format!("Profile \"{}\" created.", p.name))
        ))
        .into_response()),
        RpcResponse::Error(e) => {
            Ok(Redirect::to(&format!("/profiles?error={}", urlencoding(&e.to_string())))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub id: i64,
}

pub async fn post_delete(
    State(state): State<SharedState>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileDelete { id: form.id })
            .await?;
    match resp {
        RpcResponse::ProfileDelete => Ok(Redirect::to("/profiles?flash=Profile+deleted").into_response()),
        RpcResponse::Error(e) => {
            Ok(Redirect::to(&format!("/profiles?error={}", urlencoding(&e.to_string())))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ApplyForm {
    pub selector: String,
    pub profile_id: i64,
}

pub async fn post_apply(
    State(state): State<SharedState>,
    Form(form): Form<ApplyForm>,
) -> Result<Response, AppError> {
    let sel = super::hostings::parse_selector_public(&form.selector)?;
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ProfileApply {
            sel,
            profile_id: form.profile_id,
        },
    )
    .await?;
    match resp {
        RpcResponse::ProfileApply(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?profile=applied", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?profile_error={}", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

fn parse_opt_i64(s: &str) -> Option<i64> {
    s.trim().parse().ok().filter(|n: &i64| *n > 0)
}

/// Parse "199.00" / "199,00" / "199" → 19900 (minor units).
fn parse_price_major(s: &str) -> Result<Option<i64>, AppError> {
    let s = s.trim().replace(',', ".");
    if s.is_empty() {
        return Ok(None);
    }
    let n: f64 = s
        .parse()
        .map_err(|_| AppError::BadRequest(format!("price not numeric: {s}")))?;
    if n < 0.0 {
        return Err(AppError::BadRequest("price must be ≥ 0".into()));
    }
    Ok(Some((n * 100.0).round() as i64))
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn csrf_token(state: &SharedState, ctx: &AuthCtx, form_id: &str) -> String {
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
