//! Login + session middleware + extractors.

use crate::error::AppError;
use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::{header, request::Parts, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use lm_auth::Session;

/// Cookie-extracted session, available in handlers via the State extractor
/// chain. Absence is represented by `None`.
#[derive(Clone)]
pub struct AuthCtx {
    pub session: Option<Session>,
    pub username: String,
}

impl AuthCtx {
    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }
}

#[async_trait::async_trait]
impl FromRequestParts<SharedState> for AuthCtx {
    type Rejection = AppError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        Ok(extract_auth(parts, state))
    }
}

/// Middleware: redirect unauthenticated requests to `/login` (preserving
/// the original target via `?next=`).
pub async fn require_auth(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let ctx = extract_auth(&mut parts, &state);
    if !ctx.is_authenticated() {
        let uri = parts.uri.to_string();
        let next_param = url::form_urlencoded::byte_serialize(uri.as_bytes()).collect::<String>();
        return Redirect::to(&format!("/login?next={next_param}")).into_response();
    }
    let req = Request::from_parts(parts, body);
    next.run(req).await
}

fn extract_auth(parts: &mut Parts, state: &SharedState) -> AuthCtx {
    let cookie_name = state.cookie_name();
    let token = parts
        .headers
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
    let username = state.admin_user.username.clone();
    match token {
        Some(t) => {
            let now = lm_types::now_secs();
            match state.session.verify(&t, now) {
                Ok(s) => AuthCtx {
                    session: Some(s),
                    username,
                },
                Err(_) => AuthCtx {
                    session: None,
                    username,
                },
            }
        }
        None => AuthCtx {
            session: None,
            username,
        },
    }
}

/// Build a Set-Cookie value for the given session token.
pub fn set_cookie(state: &SharedState, token: &str) -> HeaderValue {
    let mut s = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax",
        state.cookie_name(),
        token
    );
    if state.secure_cookies() {
        s.push_str("; Secure");
    }
    s.push_str(&format!("; Max-Age={}", state.session_ttl()));
    HeaderValue::from_str(&s).unwrap_or(HeaderValue::from_static(""))
}

pub fn clear_cookie(state: &SharedState) -> HeaderValue {
    let mut s = format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        state.cookie_name()
    );
    if state.secure_cookies() {
        s.push_str("; Secure");
    }
    HeaderValue::from_str(&s).unwrap_or(HeaderValue::from_static(""))
}

/// CSRF guard for POST requests. Returns 403 if missing/invalid token.
/// The token is read from a form field named `_csrf` (sent by every form).
pub async fn check_csrf(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if req.method() != axum::http::Method::POST {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "bad body").into_response();
        }
    };
    let mut token: Option<String> = None;
    for (k, v) in url::form_urlencoded::parse(&bytes) {
        if k == "_csrf" {
            token = Some(v.into_owned());
            break;
        }
    }
    let ctx = {
        let mut p = parts.clone();
        extract_auth(&mut p, &state)
    };
    let sid = ctx
        .session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default();
    let form_id = parts.uri.path().to_string();
    let now = lm_types::now_secs();
    let ok = token
        .as_deref()
        .map(|t| lm_auth::csrf::verify(state.csrf_key.as_ref(), &sid, &form_id, t, now))
        .unwrap_or(false);
    if !ok {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let req = Request::from_parts(parts, Body::from(bytes));
    next.run(req).await
}
