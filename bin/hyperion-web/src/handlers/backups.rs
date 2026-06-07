//! `/settings/backups` — off-site backup target config + probe.
//!
//! Operators add one or more S3-compatible destinations (Wasabi,
//! Backblaze B2, Minio, AWS S3). The agent stores the access
//! credentials, an age public key for client-side encryption, and
//! a per-target retention policy.
//!
//! This commit ships the CONFIG layer + a curl-based reachability
//! probe. The scheduled-upload runner (with age encryption +
//! aws-cli upload + retention pruning) lands in a follow-up so
//! the diff stays readable.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path as AxPath, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "settings_backups.html")]
struct BackupsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    targets: Vec<hyperion_types::BackupTargetView>,
    csrf_token: String,
}

pub async fn get_backups(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetList).await?;
    let targets = match resp {
        RpcResponse::BackupTargetList(v) => v,
        _ => Vec::new(),
    };
    let tpl = BackupsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "settings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        targets,
        csrf_token: super::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct BackupTargetForm {
    #[serde(default)]
    pub id: Option<i64>,
    pub name: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub endpoint: String,
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    pub access_key_id: String,
    /// Optional: only sent when the operator wants to set/rotate
    /// the secret. Empty = preserve the existing on-disk path.
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub age_recipient: String,
    #[serde(default = "default_daily")]
    pub retention_daily: i64,
    #[serde(default = "default_weekly")]
    pub retention_weekly: i64,
    #[serde(default = "default_monthly")]
    pub retention_monthly: i64,
    #[serde(default)]
    pub enabled: Option<String>,
}

fn default_kind() -> String { "s3".into() }
fn default_region() -> String { "us-east-1".into() }
fn default_daily() -> i64 { 7 }
fn default_weekly() -> i64 { 4 }
fn default_monthly() -> i64 { 12 }

pub async fn post_upsert(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupTargetForm>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let secret_key = if form.secret_key.trim().is_empty() {
        None
    } else {
        Some(form.secret_key.clone())
    };
    let age_recipient = if form.age_recipient.trim().is_empty() {
        None
    } else {
        Some(form.age_recipient.clone())
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupTargetUpsert {
            id: form.id,
            name: form.name,
            kind: form.kind,
            endpoint: form.endpoint,
            bucket: form.bucket,
            region: form.region,
            access_key_id: form.access_key_id,
            secret_key,
            age_recipient,
            retention_daily: form.retention_daily,
            retention_weekly: form.retention_weekly,
            retention_monthly: form.retention_monthly,
            enabled: form.enabled.as_deref() == Some("on"),
        },
    )
    .await?;
    let flash = match resp {
        RpcResponse::BackupTargetUpserted { id } => format!("Saved target #{id}"),
        RpcResponse::Error(e) => format!("Save failed: {e}"),
        _ => "Save: unexpected response".into(),
    };
    Ok(Redirect::to(&format!("/settings/backups?flash={}", urlencode(&flash))).into_response())
}

pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    AxPath(id): AxPath<i64>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupTargetDelete { id },
    )
    .await?;
    Ok(Redirect::to("/settings/backups?flash=Target+deleted").into_response())
}

pub async fn post_probe(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    AxPath(id): AxPath<i64>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Html(
            "<div class=\"pill err\">admin role required</div>".to_string(),
        )
        .into_response());
    }
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetProbe { id })
            .await?;
    let html = match resp {
        RpcResponse::BackupTargetProbe(p) => {
            let cls = if p.ok { "pill ok" } else { "pill err" };
            format!(
                "<span class=\"{cls}\" title=\"{}\">{} · {}ms</span>",
                askama_escape::escape(&p.message, askama_escape::Html),
                if p.ok { "reachable" } else { "unreachable" },
                p.put_latency_ms,
            )
        }
        RpcResponse::Error(e) => format!(
            "<span class=\"pill err\">probe failed: {}</span>",
            askama_escape::escape(&e.to_string(), askama_escape::Html)
        ),
        _ => "<span class=\"pill err\">unexpected response</span>".into(),
    };
    Ok(Html(html).into_response())
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
