//! `/profile` — self-service for the currently signed-in user.
//!
//! Right now: 2FA enrollment + disable + change own password. Future:
//! email change, session list, recent activity.

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
use hyperion_types::WebUserSummary;
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
    enrollment: Option<Web2faEnrollmentView>,
    error: Option<String>,
    flash: Option<String>,
    /// True when the session is gated into 2FA enrolment (admin+ without
    /// 2FA) — renders a blocking banner above the enrolment card.
    require_2fa: bool,
    csrf_token: String,
    /// Every live session this account holds — "where am I signed in".
    /// A stolen cookie is invisible without this list, and the only way to
    /// act on one is to be able to see it first.
    sessions: Vec<hyperion_types::WebSessionView>,
    /// The sid of the session viewing the page, so it can be labelled
    /// rather than looking like just another device.
    current_sid: String,
}

/// View-shape — the SVG is rendered server-side.
#[derive(Debug, Clone)]
pub struct Web2faEnrollmentView {
    pub secret_base32: String,
    pub otpauth_url: String,
    pub qr_svg: String,
    pub backup_codes: Vec<String>,
}

#[derive(Deserialize, Default)]
pub struct ProfileQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

pub async fn get_profile(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<ProfileQuery>,
) -> Result<Response, AppError> {
    let Some(session) = ctx.session.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let user_resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebUserGet {
            id: session.user_id,
        },
    )
    .await
    .map_err(AppError::from)?;
    let user = match user_resp {
        RpcResponse::WebUserGet(u) => u,
        _ => None,
    };
    let csrf_token = super::session_csrf_token(&state, &ctx);
    // Live sessions for this account. Failure renders an empty list rather
    // than a 500: the rest of the profile page is still useful, and a
    // missing list is obvious on its own.
    let sessions = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebSessionList {
            user_id: session.user_id,
        },
    )
    .await
    {
        Ok(RpcResponse::WebSessionList(v)) => {
            v.into_iter().filter(|s| s.revoked_at.is_none()).collect()
        }
        _ => Vec::new(),
    };
    let current_sid = session.sid.clone();

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
        require_2fa: session.needs_2fa_enrollment(),
        csrf_token,
        sessions,
        current_sid,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// POST /profile/2fa/start — generate a fresh TOTP secret + 10 backup
/// codes for the current user. Renders the QR + codes in-place so the
/// operator can scan + save before confirming.
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
    let user_resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebUserGet {
            id: session.user_id,
        },
    )
    .await
    .map_err(AppError::from)?;
    let user = match user_resp {
        RpcResponse::WebUserGet(u) => u,
        _ => None,
    };
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
        // The 2FA-enrolment render is a focused, blocking screen — the
        // session list would be noise there.
        sessions: Vec::new(),
        current_sid: String::new(),
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
