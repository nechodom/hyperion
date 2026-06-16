//! `/profile` — self-service for the currently signed-in user.
//!
//! Right now: 2FA enrollment + disable + change own password. Future:
//! email change, session list, recent activity.

use crate::auth::AuthCtx;
use crate::error::AppError;
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
        Request::WebUserGet { id: session.user_id },
    )
    .await
    .map_err(AppError::from)?;
    let user = match user_resp {
        RpcResponse::WebUserGet(u) => u,
        _ => None,
    };
    let csrf_token = super::session_csrf_token(&state, &ctx);
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
    };
    Ok(Html(tpl.render()?).into_response())
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
            return Ok(Redirect::to(&format!(
                "/profile?error={}",
                urlencode(&e.to_string())
            ))
            .into_response());
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
        Request::WebUserGet { id: session.user_id },
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
                let full = hyperion_auth::Session {
                    sid: session.sid.clone(),
                    user_id: session.user_id,
                    created_at: now,
                    expires_at: now + state.session_ttl(),
                    username: session.username.clone(),
                    role: session.role.clone(),
                    purpose: hyperion_auth::PURPOSE_SESSION.to_string(),
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
        RpcResponse::Web2faDisable => Ok(Redirect::to("/profile?flash=2FA+disabled").into_response()),
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
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::WebUserSetPassword => {
            Ok(Redirect::to("/profile?flash=password+changed").into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profile?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
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
