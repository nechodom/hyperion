use crate::admin_user;
use crate::auth::{clear_cookie, set_cookie, AuthCtx};
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_auth::{Session, PURPOSE_PENDING_2FA, PURPOSE_SESSION};
use serde::Deserialize;
use std::sync::Mutex;

/// Per-IP failed-login tracker. Token bucket with a 5-attempt cap over
/// a 5-minute window. Resets on successful login.
struct ThrottleState {
    by_ip: std::collections::HashMap<String, (u32, i64)>,
}
static THROTTLE: once_cell::sync::Lazy<Mutex<ThrottleState>> =
    once_cell::sync::Lazy::new(|| {
        Mutex::new(ThrottleState {
            by_ip: std::collections::HashMap::new(),
        })
    });

// Sliding window — 5 failed attempts per IP within 15 minutes. Bumped
// from 5min to 15min after staging-env brute-force tests showed an
// attacker could still rotate through ~12 password guesses per hour
// per IP with the old 5min reset. 15min trades 3× window depth for
// the same legitimate-user friction (one fat-finger password recovers
// in ~3 minutes — well under the window).
const THROTTLE_WINDOW_SECS: i64 = 15 * 60;
const THROTTLE_LIMIT: u32 = 5;

fn caller_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn check_throttle(ip: &str) -> bool {
    let now = hyperion_types::now_secs();
    let mut s = THROTTLE.lock().expect("login throttle mutex poisoned");
    // Garbage-collect stale entries opportunistically.
    s.by_ip
        .retain(|_, (_, ts)| now - *ts < THROTTLE_WINDOW_SECS);
    let entry = s.by_ip.entry(ip.to_string()).or_insert((0, now));
    if now - entry.1 >= THROTTLE_WINDOW_SECS {
        *entry = (0, now);
    }
    entry.0 < THROTTLE_LIMIT
}

fn record_failure(ip: &str) {
    let now = hyperion_types::now_secs();
    let mut s = THROTTLE.lock().expect("login throttle mutex poisoned");
    let entry = s.by_ip.entry(ip.to_string()).or_insert((0, now));
    if now - entry.1 >= THROTTLE_WINDOW_SECS {
        *entry = (1, now);
    } else {
        entry.0 += 1;
    }
}

fn clear_throttle(ip: &str) {
    let mut s = THROTTLE.lock().expect("login throttle mutex poisoned");
    s.by_ip.remove(ip);
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTpl<'a> {
    /// Error code from `?error=…` query param — `"invalid"`, `"expired"`,
    /// `"locked"`, `"csrf"`, or any custom message. Template branches
    /// on the known codes and falls through to literal rendering for
    /// anything else. Owned because askama's `==` comparison on `&str`
    /// vs string literal trips up its derive macro.
    error: Option<String>,
    next: &'a str,
    css_version: &'static str,
}

#[derive(Deserialize, Default)]
pub struct LoginQuery {
    #[serde(default)]
    next: String,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    next: String,
}

pub async fn get_login(
    State(state): State<SharedState>,
    Query(q): Query<LoginQuery>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if ctx.is_authenticated() {
        return Ok(Redirect::to(redirect_target(&q.next)).into_response());
    }
    let tpl = LoginTpl {
        error: q.error.clone(),
        next: &q.next,
        css_version: crate::handlers::css_version(),
    };
    let _ = state;
    Ok(Html(tpl.render()?).into_response())
}

pub async fn post_login(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let ip = caller_ip(&headers);
    if !check_throttle(&ip) {
        tracing::warn!(ip = %ip, "login throttled");
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "300")],
            "Too many failed login attempts. Wait 5 minutes and try again.",
        )
            .into_response());
    }

    // Try the agent's web_users table first via RPC. On a fresh install
    // it's empty — in that case we fall back to the bootstrap
    // /etc/hyperion/web-admin.json user AND seed it into the DB so
    // subsequent logins use the multi-user path.
    let users_list = hyperion_rpc_client::call(
        &state.agent_socket,
        hyperion_rpc::codec::Request::WebUserList,
    )
    .await;
    let db_has_users = matches!(
        &users_list,
        Ok(hyperion_rpc::codec::Response::WebUserList(v)) if !v.is_empty()
    );

    if db_has_users {
        return post_login_via_rpc(state, &ip, form, headers).await;
    }
    // Bootstrap path: verify against the JSON file, then seed.
    post_login_bootstrap(state, &ip, form, headers).await
}

async fn post_login_via_rpc(
    state: SharedState,
    ip: &str,
    form: LoginForm,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        hyperion_rpc::codec::Request::WebLogin {
            username: form.username.clone(),
            password: form.password.clone(),
            client_ip: Some(ip.to_string()),
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        hyperion_rpc::codec::Response::WebLogin(result) => match result {
            hyperion_types::WebLoginResult::Ok { user_id, username, role, .. } => {
                clear_throttle(ip);
                mint_session_redirect(&state, user_id, username, role, &form.next, &headers).await
            }
            hyperion_types::WebLoginResult::NeedsTotp { user_id, .. } => {
                // Stash user_id in a short-lived signed pending cookie
                // (reuses the session signer but with a 5-minute TTL).
                // Redirect to /login/2fa to enter the code.
                clear_throttle(ip);
                mint_pending_2fa_cookie(&state, user_id, &form.next)
            }
            hyperion_types::WebLoginResult::Locked { reason: _ } => {
                Ok(Redirect::to("/login?error=locked").into_response())
            }
            hyperion_types::WebLoginResult::Invalid => {
                record_failure(ip);
                Ok(login_failed(&form.next))
            }
        },
        hyperion_rpc::codec::Response::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn post_login_bootstrap(
    state: SharedState,
    ip: &str,
    form: LoginForm,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Verify against the on-disk single-admin JSON file.
    let user = state.admin_user.clone();
    if !subtle_eq(&form.username, &user.username) {
        record_failure(ip);
        return Ok(login_failed(&form.next));
    }
    let ok =
        admin_user::verify(&user, &form.password).map_err(|e| AppError::Internal(e.to_string()))?;
    if !ok {
        record_failure(ip);
        return Ok(login_failed(&form.next));
    }
    clear_throttle(ip);
    // Seed the DB with this bootstrap user as super_admin. If the seed
    // fails we still let them log in (so they're not locked out) — the
    // next login attempt will try again.
    let seed = hyperion_rpc_client::call(
        &state.agent_socket,
        hyperion_rpc::codec::Request::WebUserCreate {
            username: form.username.clone(),
            email: format!("{}@bootstrap.local", form.username),
            password: form.password.clone(),
            role: "super_admin".into(),
        },
    )
    .await;
    if let Ok(hyperion_rpc::codec::Response::WebUserCreate { id }) = seed {
        return mint_session_redirect(
            &state,
            id,
            form.username.clone(),
            "super_admin".into(),
            &form.next,
            &headers,
        )
        .await;
    }
    // Couldn't seed — issue a session under the legacy id anyway.
    mint_session_redirect(
        &state,
        user.id,
        user.username.clone(),
        "super_admin".into(),
        &form.next,
        &headers,
    )
    .await
}

/// Mint a 5-minute "pending 2FA" cookie carrying `user_id`. Same
/// signer as full sessions but expires fast — operator must enter
/// the TOTP code within that window or restart the login.
fn mint_pending_2fa_cookie(
    state: &SharedState,
    user_id: i64,
    next: &str,
) -> Result<Response, AppError> {
    let now = hyperion_types::now_secs();
    let pending = Session {
        sid: format!("p2fa-{}", ulid::Ulid::new()),
        user_id,
        created_at: now,
        expires_at: now + 300, // 5 minutes
        username: String::new(),
        role: "pending_2fa".to_string(),
        purpose: PURPOSE_PENDING_2FA.to_string(),
    };
    let token = state
        .session
        .sign(&pending)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let cookie = format!(
        "{}_pending2fa={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300{}",
        state.cookie_name(),
        token,
        if state.secure_cookies() {
            "; Secure"
        } else {
            ""
        }
    );
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        headers.insert(header::SET_COOKIE, v);
    }
    let next_enc: String = url::form_urlencoded::byte_serialize(next.as_bytes()).collect();
    let mut resp = Redirect::to(&format!("/login/2fa?next={next_enc}")).into_response();
    resp.headers_mut().extend(headers);
    Ok(resp)
}

#[derive(Deserialize, Default)]
pub struct Login2faQuery {
    #[serde(default)]
    pub next: String,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct Login2faForm {
    code: String,
    #[serde(default)]
    next: String,
}

#[derive(askama::Template)]
#[template(path = "login_2fa.html")]
struct Login2faTpl<'a> {
    /// Raw error code from `?error=…`. Template branches on the known
    /// codes ("invalid" / "expired") and falls through to literal
    /// rendering for anything custom — same pattern as login.html.
    /// Owned (not &str) because askama's `==` comparison on &str vs
    /// string literal trips the derive macro.
    error: Option<String>,
    next: &'a str,
    css_version: &'static str,
}

pub async fn get_login_2fa(
    State(state): State<SharedState>,
    Query(q): Query<Login2faQuery>,
) -> Result<Response, AppError> {
    let _ = state;
    let tpl = Login2faTpl {
        error: q.error.clone(),
        next: &q.next,
        css_version: crate::handlers::css_version(),
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn post_login_2fa(
    State(state): State<SharedState>,
    headers_in: HeaderMap,
    Form(form): Form<Login2faForm>,
) -> Result<Response, AppError> {
    // Throttle the second factor too — without this, an attacker who
    // captured the password could brute-force the 6-digit TOTP from
    // the pending-2fa cookie (~1M attempts to enumerate). Reuses the
    // same per-IP bucket as the password step, so a failed-password
    // burst also blocks 2FA tries from that IP and vice-versa.
    let ip = caller_ip(&headers_in);
    if !check_throttle(&ip) {
        tracing::warn!(ip = %ip, "2fa verify throttled");
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "900")],
            "Too many failed login attempts. Wait 15 minutes and try again.",
        )
            .into_response());
    }

    // Recover the pending-2fa cookie.
    let cookie_name = format!("{}_pending2fa", state.cookie_name());
    let token = headers_in
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == cookie_name {
                Some(v.to_string())
            } else {
                None
            }
        });
    let Some(t) = token else {
        return Ok(Redirect::to("/login?error=expired").into_response());
    };
    let now = hyperion_types::now_secs();
    let pending = match state.session.verify(&t, now) {
        // Reject anything other than a pending-2FA token here — a
        // real-session token planted in the pending cookie slot
        // would otherwise let a stolen full session masquerade as a
        // half-authenticated one.
        Ok(s) if s.is_pending_2fa() => s,
        _ => return Ok(Redirect::to("/login?error=expired").into_response()),
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        hyperion_rpc::codec::Request::WebVerify2fa {
            user_id: pending.user_id,
            code: form.code,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        hyperion_rpc::codec::Response::WebVerify2fa(hyperion_types::WebVerify2faResult::Ok {
            user_id,
            username,
            role,
            ..
        }) => {
            // Clear the pending cookie + mint the real session.
            let mut headers = HeaderMap::new();
            let clear = format!(
                "{}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax",
                cookie_name
            );
            if let Ok(v) = HeaderValue::from_str(&clear) {
                headers.insert(header::SET_COOKIE, v);
            }
            let r = mint_session_redirect(&state, user_id, username, role, &form.next, &headers_in).await?;
            let mut combined = r;
            // Append the cookie-clear header.
            if let Some(v) = HeaderValue::from_str(&format!(
                "{}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax",
                cookie_name
            ))
            .ok()
            {
                combined.headers_mut().append(header::SET_COOKIE, v);
            }
            Ok(combined)
        }
        hyperion_rpc::codec::Response::WebVerify2fa(hyperion_types::WebVerify2faResult::Invalid) => {
            // Record the failure in the IP bucket so a wrong-code burst
            // contributes to the same throttle as wrong-password tries.
            // Without this, an attacker could try unlimited 6-digit
            // codes per session-cookie issuance.
            record_failure(&ip);
            Ok(Redirect::to("/login/2fa?error=invalid").into_response())
        }
        hyperion_rpc::codec::Response::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn mint_session_redirect(
    state: &SharedState,
    user_id: i64,
    username: String,
    role: String,
    next: &str,
    req_headers: &HeaderMap,
) -> Result<Response, AppError> {
    let now = hyperion_types::now_secs();
    let sid = ulid::Ulid::new().to_string();
    let session = Session {
        sid: sid.clone(),
        user_id,
        created_at: now,
        expires_at: now + state.session_ttl(),
        username,
        role,
        purpose: PURPOSE_SESSION.to_string(),
    };
    let token = state
        .session
        .sign(&session)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Track the session in the agent's `web_sessions` ledger so the
    // /settings/sessions revoke flow can kill it later. Best-effort:
    // if the RPC fails (agent socket down), the user still gets
    // their cookie — they just won't show up in the active-sessions
    // list. Auth middleware treats "missing row" as anonymous, so
    // a missed insert here means the user has to log in again,
    // not silent privilege escalation.
    let ip = caller_ip(req_headers);
    let ua = req_headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(255).collect::<String>());
    let r = hyperion_rpc_client::call(
        &state.agent_socket,
        hyperion_rpc::codec::Request::WebSessionInsert {
            sid: sid.clone(),
            user_id,
            ip: Some(ip),
            user_agent: ua,
        },
    )
    .await;
    if let Err(e) = r {
        tracing::warn!(error=%e, sid=%sid, "web_session_insert RPC failed — cookie minted anyway");
    }

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, set_cookie(state, &token));
    let dest = redirect_target(next);
    let mut resp = Redirect::to(dest).into_response();
    resp.headers_mut().extend(headers);
    Ok(resp)
}

pub async fn post_logout(
    State(state): State<SharedState>,
    ctx: crate::auth::AuthCtx,
) -> Response {
    // Revoke the row backing this session so a stolen cookie can't
    // outlive logout. Best-effort — the cookie is cleared either
    // way; failing to revoke leaves the row in the table but the
    // operator already lost their handle on it. Audit log gets a
    // row from Service::web_session_revoke either way.
    if let Some(s) = ctx.session.as_ref() {
        let _ = hyperion_rpc_client::call(
            &state.agent_socket,
            hyperion_rpc::codec::Request::WebSessionRevoke {
                sid: s.sid.clone(),
                revoked_by: s.user_id,
            },
        )
        .await;
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, clear_cookie(&state));
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut().extend(headers);
    resp
}

fn login_failed(next: &str) -> Response {
    let encoded_next: String = url::form_urlencoded::byte_serialize(next.as_bytes()).collect();
    let dest = format!("/login?error=invalid&next={encoded_next}");
    Redirect::to(&dest).into_response()
}

fn redirect_target(next: &str) -> &str {
    // Refuse open redirects: must start with '/'
    if next.starts_with('/') && !next.starts_with("//") {
        next
    } else {
        "/"
    }
}

fn subtle_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

#[allow(dead_code)] // used by status-line in 401 responses; reserved
pub fn unauthorized_html() -> (StatusCode, &'static str) {
    (StatusCode::UNAUTHORIZED, "unauthorized")
}
