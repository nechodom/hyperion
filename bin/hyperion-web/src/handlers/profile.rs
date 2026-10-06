//! `/profile` — self-service for the currently signed-in user: picture,
//! 2FA, password, email change, and the devices signed in to the account.
//!
//! One page, read top to bottom as "is my account safe?": a verdict line,
//! then the account itself, sign-in security, email, devices. `/settings/
//! sessions` used to be a second list of the same sessions; it now
//! redirects here.

use crate::auth::AuthCtx;
use crate::error::AppError;
#[allow(unused_imports)] // askama resolves {{ x|datetime }} through this
use crate::filters;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{WebSessionView, WebUserSummary};
use qrcode::render::svg;
use qrcode::QrCode;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "profile.html")]
struct ProfileTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    user: Option<WebUserSummary>,
    /// Set while 2FA enrolment is in progress: the page renders only the
    /// enrolment steps, nothing else competes with "scan, save, confirm".
    enrollment: Option<Web2faEnrollmentView>,
    error: Option<String>,
    flash: Option<String>,
    /// True when the session is gated into 2FA enrolment (admin+ without
    /// 2FA) — renders a blocking banner above the enrolment card.
    require_2fa: bool,
    csrf_token: String,
    verdict: Verdict,
    /// Sessions that can still authenticate, this device first. A stolen
    /// cookie is invisible without this list, and the only way to act on
    /// one is to be able to see it first.
    devices: Vec<DeviceRow>,
    /// Signed-out and expired sessions, newest first — history only.
    ended: Vec<DeviceRow>,
    /// "expires in 12 min" for a pending email change.
    pending_expires_in: String,
    /// Unused 2FA backup codes; -1 when unknown (2FA off, or an agent too
    /// old to report it). Askama can't compare through an `Option<&i64>`.
    codes_left: i64,
}

/// View-shape — the SVG is rendered server-side.
#[derive(Debug, Clone)]
pub struct Web2faEnrollmentView {
    pub secret_base32: String,
    pub otpauth_url: String,
    pub qr_svg: String,
    pub backup_codes: Vec<String>,
}

/// The one-line answer at the top of the page.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    /// `ok` | `warn` | `err` — the `.svc-verdict` tone classes.
    tone: &'static str,
    text: String,
}

/// Backup codes at or below this count get a warning: two lost phones
/// from locked out is too close.
const LOW_BACKUP_CODES: i64 = 2;

/// `gated` is the session-level 2FA gate (admin+ under enforce_admin_2fa):
/// it requires 2FA even when the user row's `totp_required` is false.
fn build_verdict(user: Option<&WebUserSummary>, gated: bool, live_devices: usize) -> Verdict {
    let Some(u) = user else {
        return Verdict {
            tone: "warn",
            text: "Your account details could not be loaded.".into(),
        };
    };
    if !u.totp_enrolled {
        return if u.totp_required || gated {
            Verdict {
                tone: "err",
                text: "Two-factor authentication is required for your role and is not set up."
                    .into(),
            }
        } else {
            Verdict {
                tone: "warn",
                text: "Two-factor authentication is off \u{2014} a password alone protects this account."
                    .into(),
            }
        };
    }
    match u.backup_codes_left {
        Some(0) => {
            return Verdict {
                tone: "warn",
                text:
                    "No backup codes left \u{2014} lose your authenticator and you cannot sign in."
                        .into(),
            }
        }
        Some(n) if n <= LOW_BACKUP_CODES => {
            return Verdict {
                tone: "warn",
                text: format!(
                    "Only {n} backup code{} left.",
                    if n == 1 { "" } else { "s" }
                ),
            }
        }
        _ => {}
    }
    Verdict {
        tone: "ok",
        text: format!(
            "Account protected \u{2014} two-factor on, signed in on {live_devices} device{}.",
            if live_devices == 1 { "" } else { "s" }
        ),
    }
}

/// One session, shaped for the devices list.
#[derive(Debug, Clone)]
struct DeviceRow {
    sid: String,
    /// "Firefox on macOS" — the raw user agent goes in a tooltip.
    label: String,
    user_agent: String,
    ip: String,
    created_at: i64,
    last_seen_ago: String,
    is_current: bool,
    /// Why an ended session ended: "signed out" | "expired".
    ended: Option<&'static str>,
}

/// Grace past the nominal cookie lifetime before a session counts as
/// expired. The row's `created_at` is the FIRST sign-in; a session that
/// finished 2FA enrolment got a fresh cookie later, so its real expiry runs
/// a little past `created_at + ttl`. Calling a live session "expired" would
/// hide its sign-out button, so err towards live.
const EXPIRY_GRACE_SECS: i64 = 3600;

/// Split sessions into still-live (this device first, then most recently
/// seen) and ended (newest first).
fn split_devices(
    list: Vec<WebSessionView>,
    current_sid: &str,
    ttl: i64,
    now: i64,
) -> (Vec<DeviceRow>, Vec<DeviceRow>) {
    let mut live = Vec::new();
    let mut ended = Vec::new();
    for s in list {
        let is_current = s.sid == current_sid;
        let reason = if s.is_revoked() {
            Some("signed out")
        } else if !is_current && s.created_at + ttl + EXPIRY_GRACE_SECS < now {
            Some("expired")
        } else {
            None
        };
        let ua = s.user_agent.unwrap_or_default();
        let row = DeviceRow {
            label: device_label(&ua),
            user_agent: ua,
            ip: s.ip.unwrap_or_else(|| "\u{2014}".into()),
            created_at: s.created_at,
            last_seen_ago: format_ago(now - s.last_seen_at),
            is_current,
            ended: reason,
            sid: s.sid,
        };
        if reason.is_some() {
            ended.push((s.last_seen_at, row));
        } else {
            live.push((s.last_seen_at, row));
        }
    }
    live.sort_by(|a, b| b.1.is_current.cmp(&a.1.is_current).then(b.0.cmp(&a.0)));
    ended.sort_by(|a, b| b.0.cmp(&a.0));
    (
        live.into_iter().map(|(_, r)| r).collect(),
        ended.into_iter().map(|(_, r)| r).collect(),
    )
}

/// "Firefox on macOS" from a user-agent string. Order matters: Edge and
/// Opera carry "Chrome/", Chrome carries "Safari/", Android carries
/// "Linux", iOS carries "Mac OS X".
fn device_label(ua: &str) -> String {
    if ua.is_empty() {
        return "Unknown device".into();
    }
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("OPR/") {
        "Opera"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else if ua.starts_with("curl/") {
        "curl"
    } else {
        "Browser"
    };
    let os = if ua.contains("iPhone") || ua.contains("iPad") {
        Some("iOS")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("CrOS") {
        Some("ChromeOS")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    match os {
        Some(os) => format!("{browser} on {os}"),
        None => browser.to_string(),
    }
}

/// "just now" / "5 min ago" / "3 h ago" / "2 days ago".
fn format_ago(delta_secs: i64) -> String {
    let s = delta_secs.max(0);
    if s < 60 {
        "just now".into()
    } else if s < 3600 {
        format!("{} min ago", s / 60)
    } else if s < 86400 {
        format!("{} h ago", s / 3600)
    } else {
        let d = s / 86400;
        format!("{d} day{} ago", if d == 1 { "" } else { "s" })
    }
}

/// "in 12 min" for a pending code; "in under a minute" at the tail end.
fn format_expires_in(expires_at: i64, now: i64) -> String {
    let left = expires_at - now;
    if left < 60 {
        "in under a minute".into()
    } else {
        format!("in {} min", left / 60)
    }
}

#[derive(Deserialize, Default)]
pub struct ProfileQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

async fn load_user(state: &SharedState, user_id: i64) -> Result<Option<WebUserSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::WebUserGet { id: user_id })
        .await
        .map_err(AppError::from)?;
    Ok(match resp {
        RpcResponse::WebUserGet(u) => u,
        _ => None,
    })
}

pub async fn get_profile(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<ProfileQuery>,
) -> Result<Response, AppError> {
    let Some(session) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let user = load_user(&state, session.user_id).await?;
    let csrf_token = super::session_csrf_token(&state, &ctx);
    // Sessions for this account. Failure renders an empty list rather than
    // a 500: the rest of the profile page is still useful, and a missing
    // list is obvious on its own.
    let sessions = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebSessionList {
            user_id: session.user_id,
        },
    )
    .await
    {
        Ok(RpcResponse::WebSessionList(v)) => v,
        _ => Vec::new(),
    };
    let now = hyperion_types::now_secs();
    let (devices, ended) = split_devices(sessions, &session.sid, state.session_ttl(), now);
    let require_2fa = session.needs_2fa_enrollment();
    let verdict = build_verdict(user.as_ref(), require_2fa, devices.len().max(1));
    let pending_expires_in = user
        .as_ref()
        .and_then(|u| u.pending_email.as_ref())
        .map(|p| format_expires_in(p.expires_at, now))
        .unwrap_or_default();
    let codes_left = user
        .as_ref()
        .and_then(|u| u.backup_codes_left)
        .unwrap_or(-1);

    let tpl = ProfileTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profile",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        user,
        enrollment: None,
        error: q.error,
        flash: q.flash,
        require_2fa,
        csrf_token,
        verdict,
        devices,
        ended,
        codes_left,
        pending_expires_in,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(serde::Deserialize)]
pub struct RevokeSessionForm {
    pub sid: String,
}

/// POST /profile/sessions/revoke — end ONE other session.
pub async fn post_revoke_session(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Form(form): axum::extract::Form<RevokeSessionForm>,
) -> Result<Response, AppError> {
    let Some(session) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    // Revoking is scoped to sessions this user OWNS. Without the ownership
    // check a sid from anywhere would do, which turns a profile page into a
    // way to sign out any other account.
    let owned = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebSessionList {
            user_id: session.user_id,
        },
    )
    .await
    {
        Ok(RpcResponse::WebSessionList(v)) => v.iter().any(|s| s.sid == form.sid),
        _ => false,
    };
    if !owned {
        return Ok(Redirect::to("/profile?error=unknown+session").into_response());
    }
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebSessionRevoke {
            sid: form.sid,
            revoked_by: session.user_id,
        },
    )
    .await?;
    Ok(Redirect::to("/profile?flash=device+signed+out").into_response())
}

/// POST /profile/sessions/revoke-all — end every session, including this one.
///
/// Deliberately including this one: the reason to press it is "someone else
/// may have my cookie", and sparing the browser you are holding is exactly
/// wrong if that browser is theirs.
pub async fn post_revoke_all_sessions(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let Some(session) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebSessionRevokeAll {
            user_id: session.user_id,
            revoked_by: session.user_id,
        },
    )
    .await?;
    Ok(Redirect::to("/login?error=expired").into_response())
}

/// POST /profile/2fa/start — generate a fresh TOTP secret + 10 backup
/// codes for the current user. Renders the QR + codes in-place so the
/// operator can scan + save before confirming.
pub async fn post_2fa_start(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let Some(session) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::Web2faEnrollStart {
            user_id: session.user_id,
        },
    )
    .await
    .map_err(AppError::from)?;
    let enrollment = match resp {
        RpcResponse::Web2faEnrollStart(e) => e,
        RpcResponse::Error(e) => {
            return Ok(
                Redirect::to(&format!("/profile?error={}", urlencode(&e.to_string())))
                    .into_response(),
            );
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    // Render QR as SVG server-side.
    let qr_svg = match QrCode::new(enrollment.otpauth_url.as_bytes()) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(220, 220)
            .max_dimensions(260, 260)
            .light_color(svg::Color("#ffffff"))
            .dark_color(svg::Color("#111111"))
            .build(),
        Err(_) => "<p>QR generation failed — use the secret to enter manually.</p>".to_string(),
    };
    let user = load_user(&state, session.user_id).await?;
    let view = Web2faEnrollmentView {
        secret_base32: enrollment.secret_base32,
        otpauth_url: enrollment.otpauth_url,
        qr_svg,
        backup_codes: enrollment.backup_codes,
    };
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let tpl = ProfileTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profile",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        user,
        enrollment: Some(view),
        error: None,
        flash: None,
        require_2fa: session.needs_2fa_enrollment(),
        csrf_token,
        // The enrolment render is a focused, blocking screen: only the
        // steps show, so the verdict and device list stay empty.
        verdict: Verdict {
            tone: "warn",
            text: String::new(),
        },
        devices: Vec::new(),
        ended: Vec::new(),
        pending_expires_in: String::new(),
        codes_left: -1,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    code: String,
}

/// POST /profile/2fa/confirm — verify the first TOTP code. Flips
/// `totp_enrolled_at` on success.
pub async fn post_2fa_confirm(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, AppError> {
    let Some(session) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::Web2faConfirmEnroll {
            user_id: session.user_id,
            code: form.code,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::Web2faConfirmEnroll { ok: true } => {
            // If this session was gated into 2FA enrolment, upgrade it to
            // a full session now that they've enrolled so the gate lifts.
            if session.needs_2fa_enrollment() {
                let now = hyperion_types::now_secs();
                let (caps, scope_all, caps_present) =
                    crate::auth::resolve_caps(&state, session.user_id).await;
                let full = hyperion_auth::Session {
                    sid: session.sid.clone(),
                    user_id: session.user_id,
                    created_at: now,
                    expires_at: now + state.session_ttl(),
                    username: session.username.clone(),
                    role: session.role.clone(),
                    purpose: hyperion_auth::PURPOSE_SESSION.to_string(),
                    caps,
                    scope_all,
                    caps_present,
                };
                if let Ok(token) = state.session.sign(&full) {
                    let mut resp =
                        Redirect::to("/profile?flash=2FA+enrolled+successfully").into_response();
                    resp.headers_mut().insert(
                        axum::http::header::SET_COOKIE,
                        crate::auth::set_cookie(&state, &token),
                    );
                    return Ok(resp);
                }
            }
            Ok(Redirect::to("/profile?flash=2FA+enrolled+successfully").into_response())
        }
        RpcResponse::Web2faConfirmEnroll { ok: false } => Ok(Redirect::to(
            "/profile?error=Code+rejected+%E2%80%94+make+sure+your+device+clock+is+correct+and+the+code+is+fresh",
        )
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profile?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /profile/2fa/disable — clears the secret + backup codes after
/// the user explicitly confirms.
pub async fn post_2fa_disable(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let Some(session) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::Web2faDisable {
            user_id: session.user_id,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::Web2faDisable => {
            Ok(Redirect::to("/profile?flash=2FA+disabled").into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profile?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ChangePwForm {
    current_password: String,
    new_password: String,
    new_password_confirm: String,
}

/// POST /profile/password — self-service password change.
pub async fn post_change_password(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ChangePwForm>,
) -> Result<Response, AppError> {
    let Some(session) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    if form.new_password != form.new_password_confirm {
        return Ok(Redirect::to("/profile?error=passwords+do+not+match").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebUserSetPassword {
            user_id: session.user_id,
            new_password: form.new_password,
            // Re-authenticate: the service verifies this before changing the
            // password, so a stolen session alone can't take over the account.
            current_password: Some(form.current_password),
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::WebUserSetPassword => {
            // Boot any attacker: a changed password invalidates every OTHER
            // session (a stolen cookie must not survive). Keep the caller's
            // current session so they aren't bounced to /login.
            revoke_other_sessions(&state, session.user_id, &session.sid).await;
            Ok(
                Redirect::to("/profile?flash=password+changed+%E2%80%94+other+sessions+signed+out")
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profile?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Revoke all of a user's sessions except `keep_sid`. Best-effort — used after
/// a password change so a stolen cookie can't outlive the reset, while the
/// caller's own session stays alive.
async fn revoke_other_sessions(state: &SharedState, user_id: i64, keep_sid: &str) {
    let Ok(RpcResponse::WebSessionList(list)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::WebSessionList { user_id }).await
    else {
        return;
    };
    for s in list {
        if s.sid != keep_sid && !s.is_revoked() {
            let _ = hyperion_rpc_client::call(
                &state.agent_socket,
                Request::WebSessionRevoke {
                    sid: s.sid,
                    revoked_by: user_id,
                },
            )
            .await;
        }
    }
}

// ─────────── Email change with verification ───────────

#[derive(serde::Deserialize)]
pub struct EmailChangeRequestForm {
    pub new_email: String,
    pub current_password: String,
}

pub async fn post_email_change_request(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<EmailChangeRequestForm>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EmailChangeRequest {
            user_id: sess.user_id,
            new_email: form.new_email,
            current_password: form.current_password,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::EmailChangeRequest { masked_to } => Ok(Redirect::to(&format!(
            "/profile?flash=Code+sent+to+{}",
            urlencode(&masked_to)
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profile?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(serde::Deserialize)]
pub struct EmailChangeConfirmForm {
    pub code: String,
}

pub async fn post_email_change_confirm(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<EmailChangeConfirmForm>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EmailChangeConfirm {
            user_id: sess.user_id,
            code: form.code.trim().to_string(),
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::EmailChangeConfirm => {
            Ok(Redirect::to("/profile?flash=Email+changed").into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profile?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_email_change_cancel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EmailChangeCancel {
            user_id: sess.user_id,
        },
    )
    .await;
    Ok(Redirect::to("/profile?flash=Cancelled").into_response())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn user(enrolled: bool, required: bool, codes: Option<i64>) -> WebUserSummary {
        WebUserSummary {
            id: 1,
            username: "kevin".into(),
            email: "k@example.com".into(),
            role: "admin".into(),
            totp_enrolled: enrolled,
            totp_required: required,
            locked: false,
            locked_reason: None,
            last_login_at: None,
            created_at: 0,
            custom_role_id: None,
            pending_email: None,
            backup_codes_left: codes,
        }
    }

    fn session(sid: &str, created: i64, seen: i64, revoked: bool) -> WebSessionView {
        WebSessionView {
            sid: sid.into(),
            user_id: 1,
            ip: Some("203.0.113.9".into()),
            user_agent: None,
            created_at: created,
            last_seen_at: seen,
            revoked_at: revoked.then_some(seen),
            revoked_by: None,
        }
    }

    #[test]
    fn verdict_ranks_missing_2fa_over_backup_codes() {
        assert_eq!(
            build_verdict(Some(&user(false, true, None)), false, 1).tone,
            "err"
        );
        // The session gate requires 2FA even when the row doesn't say so.
        assert_eq!(
            build_verdict(Some(&user(false, false, None)), true, 1).tone,
            "err"
        );
        assert_eq!(
            build_verdict(Some(&user(false, false, None)), false, 1).tone,
            "warn"
        );
        let none_left = build_verdict(Some(&user(true, false, Some(0))), false, 1);
        assert_eq!(none_left.tone, "warn");
        assert!(none_left.text.starts_with("No backup codes"));
        assert_eq!(
            build_verdict(Some(&user(true, false, Some(1))), false, 1).text,
            "Only 1 backup code left."
        );
        let ok = build_verdict(Some(&user(true, false, Some(8))), false, 3);
        assert_eq!(ok.tone, "ok");
        assert!(ok.text.contains("3 devices"));
        // An agent too old to report the count is not a warning.
        assert_eq!(
            build_verdict(Some(&user(true, false, None)), false, 1).tone,
            "ok"
        );
    }

    #[test]
    fn devices_split_live_from_ended_with_this_device_first() {
        let ttl = 86_400;
        let now = 10 * 86_400;
        let list = vec![
            session("other", now - 100, now - 10, false),
            session("me", now - 500, now - 400, false),
            session("gone", now - 300, now - 200, true),
            // Past ttl + grace: expired even though never revoked.
            session("old", now - ttl - EXPIRY_GRACE_SECS - 1, now - ttl, false),
        ];
        let (live, ended) = split_devices(list, "me", ttl, now);
        let live: Vec<_> = live.iter().map(|d| d.sid.as_str()).collect();
        assert_eq!(live, ["me", "other"]);
        let ended: Vec<_> = ended.iter().map(|d| (d.sid.as_str(), d.ended)).collect();
        assert_eq!(
            ended,
            [("gone", Some("signed out")), ("old", Some("expired"))]
        );
    }

    #[test]
    fn current_session_never_counts_as_expired() {
        let (live, ended) = split_devices(vec![session("me", 0, 0, false)], "me", 60, 1_000_000);
        assert_eq!(live.len(), 1);
        assert!(ended.is_empty());
    }

    #[test]
    fn device_label_picks_browser_and_os() {
        let cases = [
            ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:131.0) Gecko/20100101 Firefox/131.0", "Firefox on macOS"),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 Edg/129.0", "Edge on Windows"),
            ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36", "Chrome on Android"),
            ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1", "Safari on iOS"),
            ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 OPR/114.0", "Opera on Linux"),
            ("curl/8.5.0", "curl"),
            ("", "Unknown device"),
        ];
        for (ua, want) in cases {
            assert_eq!(device_label(ua), want, "{ua}");
        }
    }

    #[test]
    fn ago_and_expiry_wording() {
        assert_eq!(format_ago(-5), "just now");
        assert_eq!(format_ago(59), "just now");
        assert_eq!(format_ago(60), "1 min ago");
        assert_eq!(format_ago(7200), "2 h ago");
        assert_eq!(format_ago(86_400), "1 day ago");
        assert_eq!(format_ago(3 * 86_400), "3 days ago");
        assert_eq!(format_expires_in(130, 100), "in under a minute");
        assert_eq!(format_expires_in(100 + 12 * 60 + 5, 100), "in 12 min");
    }
}
