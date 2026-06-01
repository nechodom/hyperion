use crate::admin_user;
use crate::auth::{clear_cookie, set_cookie, AuthCtx};
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_auth::Session;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTpl<'a> {
    error: Option<&'a str>,
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
        error: q.error.as_deref(),
        next: &q.next,
        css_version: crate::handlers::css_version(),
    };
    let _ = state;
    Ok(Html(tpl.render()?).into_response())
}

pub async fn post_login(
    State(state): State<SharedState>,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let user = state.admin_user.clone();
    if !subtle_eq(&form.username, &user.username) {
        return Ok(login_failed(&form.next));
    }
    let ok =
        admin_user::verify(&user, &form.password).map_err(|e| AppError::Internal(e.to_string()))?;
    if !ok {
        return Ok(login_failed(&form.next));
    }
    // Mint a session.
    let now = hyperion_types::now_secs();
    let sid = ulid::Ulid::new().to_string();
    let session = Session {
        sid,
        user_id: user.id,
        created_at: now,
        expires_at: now + state.session_ttl(),
    };
    let token = state
        .session
        .sign(&session)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, set_cookie(&state, &token));
    let dest = redirect_target(&form.next);
    let mut resp = Redirect::to(dest).into_response();
    resp.headers_mut().extend(headers);
    Ok(resp)
}

pub async fn post_logout(State(state): State<SharedState>) -> Response {
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
