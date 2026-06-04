//! `/settings` — agent-wide configuration view + email test trigger.
//!
//! READ-ONLY for now; agent.toml editing is the next iteration. The
//! page reads `AgentConfigView` from the RPC (sanitised — no secrets)
//! and renders it with clear "set / not set" indicators.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::ratelimit::Bucket;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::response::Json;
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{AgentConfigView, EmailLogEntry, SmtpAutodetect, UpdateStatus};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    config: AgentConfigView,
    update_status: UpdateStatus,
    update_current_short: String,
    update_latest_short: String,
    /// Last 5 emails the agent sent (any kind, any state). Rendered
    /// inline under the Send test button so the operator sees their
    /// test send immediately without navigating to /emails.
    recent_emails: Vec<EmailLogEntry>,
    error: Option<String>,
    flash: Option<String>,
    flash_error: Option<String>,
    csrf_token: String,
}

fn short_sha(s: &str) -> String {
    s.chars().take(12).collect()
}

#[derive(Deserialize, Default)]
pub struct SettingsQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    flash_error: Option<String>,
}

pub async fn get_settings(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<SettingsQuery>,
) -> Result<Response, AppError> {
    let (config_res, update_res, emails_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::UpdateCheck { force_refresh: false },
        ),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::EmailLogList { hosting_id: None, limit: 5 },
        ),
    );
    let (config, error) = match config_res {
        Ok(RpcResponse::AgentConfigView(c)) => (c, None),
        Ok(RpcResponse::Error(e)) => (AgentConfigView::default(), Some(e.to_string())),
        Ok(_) => (
            AgentConfigView::default(),
            Some("unexpected agent response".into()),
        ),
        Err(e) => (AgentConfigView::default(), Some(format!("rpc: {e}"))),
    };
    let update_status: UpdateStatus = match update_res {
        Ok(RpcResponse::UpdateCheck(u)) => u,
        _ => UpdateStatus::default(),
    };
    let recent_emails: Vec<EmailLogEntry> = match emails_res {
        Ok(RpcResponse::EmailLogList(rows)) => rows,
        _ => vec![],
    };
    let update_current_short = short_sha(&update_status.current_sha);
    let update_latest_short = short_sha(&update_status.latest_sha);
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let tpl = SettingsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "settings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        config,
        update_status,
        update_current_short,
        update_latest_short,
        recent_emails,
        error,
        flash: q.flash,
        flash_error: q.flash_error,
        csrf_token,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct EmailTestForm {
    to: String,
}

/// POST /settings/email-test — fires a one-off SMTP send + redirects
/// back to /settings with a flash message.
pub async fn post_email_test(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<EmailTestForm>,
) -> Result<Response, AppError> {
    // Without this gate any authenticated viewer can use Hyperion's
    // SMTP relay as a free spam vector — the relay's daily quota
    // would also get blown out, breaking real cluster notifications.
    if !ctx.is_admin_or_higher() {
        return Ok(
            Redirect::to("/settings?flash_error=admin+role+required+to+send+test+emails")
                .into_response(),
        );
    }
    // Per-IP rate limit so a compromised admin cookie / leaked
    // session can't be used as an open relay or address enumerator.
    // 3/min is comfortable for an operator clicking Test a few times
    // and absurdly low for automated abuse.
    let ip = email_test_ip(&headers, peer);
    if !state.ratelimit.check("email-test", ip, Bucket::per_minute(3)) {
        return Ok(Redirect::to(
            "/settings?flash_error=test+email+rate+limit+exceeded+%E2%80%94+wait+a+minute",
        )
        .into_response());
    }
    let to = form.to.trim().to_string();
    // Bound the address at the RFC5321 max so a 50 KB pathological
    // 'to' field can't blow out the Location header on the redirect.
    if to.len() > 254 {
        return Ok(
            Redirect::to("/settings?flash_error=address+too+long+%28max+254+chars%29")
                .into_response(),
        );
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EmailSendTest { to: to.clone() },
    )
    .await?;
    match resp {
        RpcResponse::EmailSendTest { smtp_code } => {
            // Surface the SMTP server's response code in the flash —
            // "250 OK" means the relay accepted the message into its
            // queue (whether it'll be delivered is between the relay
            // and the recipient's MX). Operator can tell "queued"
            // from "rejected by relay before our test even left".
            let msg = format!("Test email sent to {to} · SMTP response: {smtp_code} · see /emails for delivery log");
            Ok(
                Redirect::to(&format!("/settings?flash={}", urlencode(&msg)))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => {
            // Include a pointer to /emails so the operator can see the
            // failed-row in context (it's already logged there).
            let msg = format!("{e} — see /emails for the failed row");
            Ok(Redirect::to(&format!(
                "/settings?flash_error={}",
                urlencode(&msg)
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ConfigEditForm {
    /// "acme" | "email" | "slack" | "backup_remote" | "backup_retention"
    pub section: String,
    /// Field name -> string-encoded value. Service does the typing.
    /// Empty string clears (or sets the field to "" depending on
    /// type — int parsing rejects empty).
    #[serde(flatten)]
    pub fields: std::collections::BTreeMap<String, String>,
}

/// POST /settings/config — super_admin only. Updates one section of
/// agent.toml in place, preserving comments. Operator must restart the
/// agent to apply.
pub async fn post_config(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ConfigEditForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    // Strip the `section` field from the bag — it's not a TOML field
    // itself, it's the routing key. axum's `#[serde(flatten)]` collects
    // every form field including `section`, so filter it out.
    let mut fields = form.fields;
    fields.remove("section");
    fields.remove("_csrf");
    // "Leave blank to keep" for sensitive fields — empty string would
    // overwrite a real password / webhook URL with "".
    let drop_if_empty: &[&str] = match form.section.as_str() {
        "email" => &["smtp_password"],
        "slack" => &["default_webhook"],
        "backup_remote" => &["password"],
        _ => &[],
    };
    for k in drop_if_empty {
        if fields.get(*k).map(|v| v.trim().is_empty()).unwrap_or(false) {
            fields.remove(*k);
        }
    }
    // Unchecked checkboxes don't show up in the form at all — but our
    // service knows the field is required. Synthesise `enabled=false`
    // when the checkbox is absent in sections that use it.
    if matches!(form.section.as_str(), "email" | "backup_remote")
        && !fields.contains_key("enabled")
    {
        fields.insert("enabled".to_string(), "false".to_string());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AgentConfigUpdate {
            section: form.section.clone(),
            fields,
        },
    )
    .await
    .map_err(AppError::from)?;
    let dest = match resp {
        RpcResponse::AgentConfigUpdate => format!(
            "/settings?flash=Section+%5B{}%5D+saved+%E2%80%94+restart+hyperion-agent+to+apply",
            urlencode(&form.section)
        ),
        RpcResponse::Error(e) => format!("/settings?flash_error={}", urlencode(&e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}

/// POST /api/email-autodetect
///
/// Probes the local box for a usable SMTP relay so the operator can
/// click "Auto-detect" on the Settings page instead of guessing
/// host/port/security. Behind require_auth (the protected router)
/// — viewers can run it too since it's read-only.
pub async fn post_email_autodetect(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Viewers shouldn't be able to fingerprint local SMTP via this
    // endpoint — the probe is operator-config only.
    if !ctx.is_admin_or_higher() {
        return Ok(Json(SmtpAutodetect {
            found: false,
            smtp_host: String::new(),
            smtp_port: 0,
            security: String::new(),
            suggested_from: String::new(),
            notes: "admin role required to probe SMTP".into(),
        })
        .into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EmailSmtpAutodetect,
    )
    .await?;
    let a = match resp {
        RpcResponse::EmailSmtpAutodetect(a) => a,
        RpcResponse::Error(e) => {
            return Ok(Json(SmtpAutodetect {
                found: false,
                smtp_host: String::new(),
                smtp_port: 0,
                security: String::new(),
                suggested_from: String::new(),
                notes: format!("agent error: {e}"),
            })
            .into_response());
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Json(a).into_response())
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b' ' => "+".to_string(),
            b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b if b.is_ascii_alphanumeric() => (b as char).to_string(),
            b => format!("%{:02X}", b),
        })
        .collect()
}

/// Resolve the effective source IP for the email-test rate limit
/// bucket. Same precedence as the /api/enroll handler: forwarded-for
/// → real-ip → peer socket.
fn email_test_ip(headers: &HeaderMap, peer: SocketAddr) -> std::net::IpAddr {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            if let Ok(ip) = first.trim().parse() {
                return ip;
            }
        }
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = v.trim().parse() {
            return ip;
        }
    }
    peer.ip()
}
