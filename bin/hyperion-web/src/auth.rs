//! Login + session middleware + extractors.

use crate::error::AppError;
use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::{header, request::Parts, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use hyperion_auth::Session;

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

    /// Role string from the session, or "viewer" if unauthenticated.
    /// Used by handlers to short-circuit write operations.
    pub fn role(&self) -> &str {
        self.session.as_ref().map(|s| s.role.as_str()).unwrap_or("viewer")
    }

    pub fn is_super_admin(&self) -> bool {
        self.session.as_ref().map(|s| s.is_super_admin()).unwrap_or(false)
    }

    pub fn is_admin_or_higher(&self) -> bool {
        self.session.as_ref().map(|s| s.is_admin_or_higher()).unwrap_or(false)
    }

    pub fn is_read_only(&self) -> bool {
        self.session.as_ref().map(|s| s.is_read_only()).unwrap_or(true)
    }

    /// Tenant-scoped: operator/customer/viewer — sees only granted
    /// hostings, can't touch cluster-wide endpoints.
    pub fn is_tenant_scoped(&self) -> bool {
        self.session
            .as_ref()
            .map(|s| s.is_tenant_scoped())
            .unwrap_or(true)
    }

    /// Customer role — slim navigation in base.html.
    pub fn is_customer(&self) -> bool {
        self.session.as_ref().map(|s| s.is_customer()).unwrap_or(false)
    }
}

#[async_trait::async_trait]
impl FromRequestParts<SharedState> for AuthCtx {
    type Rejection = AppError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        Ok(extract_auth(parts, state).await)
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
    let ctx = extract_auth(&mut parts, &state).await;
    if !ctx.is_authenticated() {
        let uri = parts.uri.to_string();
        let next_param = url::form_urlencoded::byte_serialize(uri.as_bytes()).collect::<String>();
        return Redirect::to(&format!("/login?next={next_param}")).into_response();
    }
    // 2FA enforcement gate: an admin+ session that hasn't enrolled in 2FA
    // is authenticated but corralled to the enrolment card. Exempt the
    // profile pages (where enrolment lives), logout, static assets and
    // the role-echo shim so they can actually complete it. The session
    // upgrades to a full one the moment they confirm enrolment.
    if ctx
        .session
        .as_ref()
        .map(|s| s.needs_2fa_enrollment())
        .unwrap_or(false)
    {
        let path = parts.uri.path();
        let exempt = path.starts_with("/profile")
            || path == "/logout"
            || path.starts_with("/static")
            || path.starts_with("/assets")
            || path.starts_with("/api/")
            || path == "/healthz"
            || path == "/readyz";
        if !exempt {
            return Redirect::to("/profile?require_2fa=1").into_response();
        }
    }
    let req = Request::from_parts(parts, body);
    next.run(req).await
}

async fn extract_auth(parts: &mut Parts, state: &SharedState) -> AuthCtx {
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
    let fallback_username = state.admin_user.username.clone();
    match token {
        Some(t) => {
            let now = hyperion_types::now_secs();
            match state.session.verify(&t, now) {
                // Only real-session tokens authenticate. A pending-2FA
                // token planted in the session cookie slot must NOT
                // authenticate — otherwise password-only knowledge
                // bypasses the TOTP second factor.
                Ok(s) if s.is_real_session() => {
                    // Liveness probe against the agent's `web_sessions`
                    // ledger: a revoked or evicted sid is treated as
                    // anonymous EVEN IF the cookie signature is still
                    // valid. Without this the panel can't kill a
                    // stolen cookie before its TTL expires.
                    //
                    // Special case: sessions minted before this RPC
                    // existed have no row → touch returns false →
                    // they'd be locked out. Accept "unknown sid" as
                    // valid for now; the next revoke-all sweep
                    // (planned with the operator-facing kill button)
                    // will purge them all at once. Once that sweep
                    // happens the fall-through can tighten to
                    // "unknown sid ⇒ anonymous".
                    let live = match hyperion_rpc_client::call(
                        &state.agent_socket,
                        hyperion_rpc::codec::Request::WebSessionTouch {
                            sid: s.sid.clone(),
                        },
                    )
                    .await
                    {
                        Ok(hyperion_rpc::codec::Response::WebSessionTouch(b)) => b,
                        // Unknown sid (legacy cookie) or RPC failure —
                        // do NOT fail-closed: a transient socket blip
                        // would log everyone out.
                        _ => true,
                    };
                    if !live {
                        // Row present + revoked. Treat as anonymous.
                        AuthCtx {
                            session: None,
                            username: fallback_username,
                        }
                    } else {
                        // Prefer the username embedded in the session
                        // (multi-user era). Old sessions from before
                        // multi-user have an empty string here — fall
                        // back to the bootstrap admin user.
                        let username = if s.username.is_empty() {
                            fallback_username
                        } else {
                            s.username.clone()
                        };
                        AuthCtx {
                            session: Some(s),
                            username,
                        }
                    }
                }
                _ => AuthCtx {
                    session: None,
                    username: fallback_username,
                },
            }
        }
        None => AuthCtx {
            session: None,
            username: fallback_username,
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
///
/// The token is accepted from THREE places, in this priority order:
///   1. `X-CSRF-Token` request header — for fetch/XHR/HTMX flows
///      that don't want to embed the token in the body.
///   2. `?_csrf=…` query string — for `multipart/form-data` uploads
///      where parsing the body in middleware would mean buffering
///      potentially gigabytes of file content just to find one
///      hidden field. The form template appends the token to the
///      action URL instead.
///   3. `_csrf` body field — the original path, used by every
///      `application/x-www-form-urlencoded` form.
///
/// Multipart bodies are NEVER buffered by the middleware — they
/// stream straight to the handler. Urlencoded bodies are buffered
/// (small, bounded by tower-http body limits) and re-injected.
pub async fn check_csrf(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if req.method() != axum::http::Method::POST {
        return next.run(req).await;
    }
    // Routes whose POST is idempotent + has no destructive side
    // effect beyond the caller's own session. Skipping CSRF here is
    // defensible (a forced logout is annoying, not a vulnerability)
    // and avoids plumbing csrf tokens into base.html on every page.
    //
    // Bell notification endpoints are scoped to session.user_id at
    // both the handler and the RPC/DB layer — a CSRF-forged request
    // could only mark the user's OWN notifications as read, which
    // is on the same "annoying, not exploitable" tier as logout.
    let p = req.uri().path();
    if p == "/logout"
        || p == "/api/notifications/mark-read"
        || p == "/api/notifications/mark-all-read"
    {
        return next.run(req).await;
    }

    // 1. Header — works for any content type, doesn't touch body.
    let header_token: Option<String> = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // 2. Query string — for multipart uploads. Also a no-cost fallback
    //    for any form that wants to put the token in the action URL.
    let query_token: Option<String> = req
        .uri()
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "_csrf")
                .map(|(_, v)| v.into_owned())
        });

    // Decide whether we need to read the body. Skip it entirely for
    // multipart — a 2 GB upload would otherwise sit in memory just to
    // find a 100-byte hidden field that the template should have put
    // in the URL anyway.
    let is_multipart = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().starts_with("multipart/"))
        .unwrap_or(false);

    let (parts, body, body_bytes_opt) = if is_multipart || header_token.is_some()
        || query_token.is_some()
    {
        // Don't buffer — re-attach the body unread.
        let (p, b) = req.into_parts();
        (p, b, None)
    } else {
        // Urlencoded path: buffer + parse for `_csrf`.
        let (p, b) = req.into_parts();
        match http_body_util::BodyExt::collect(b).await {
            Ok(c) => {
                let bytes = c.to_bytes();
                (p, Body::from(bytes.clone()), Some(bytes))
            }
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "bad body").into_response();
            }
        }
    };

    let body_token: Option<String> = body_bytes_opt
        .as_ref()
        .and_then(|bytes| {
            url::form_urlencoded::parse(bytes)
                .find(|(k, _)| k == "_csrf")
                .map(|(_, v)| v.into_owned())
        });

    // Pick the first non-empty token, in priority order.
    let token: Option<String> = header_token
        .filter(|s| !s.is_empty())
        .or(query_token.filter(|s| !s.is_empty()))
        .or(body_token.filter(|s| !s.is_empty()));

    let ctx = {
        let mut p = parts.clone();
        extract_auth(&mut p, &state).await
    };
    let sid = ctx
        .session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default();
    let form_id = parts.uri.path().to_string();
    let now = hyperion_types::now_secs();
    // Accept either the legacy path-scoped token OR a session-wide
    // wildcard token. New forms can use the simpler wildcard via the
    // global `csrf_token` template variable; older forms continue to
    // work with their per-route scoped tokens.
    let ok = token
        .as_deref()
        .map(|t| {
            hyperion_auth::csrf::verify(state.csrf_key.as_ref(), &sid, &form_id, t, now)
                || hyperion_auth::csrf::verify(
                    state.csrf_key.as_ref(),
                    &sid,
                    hyperion_auth::csrf::SESSION_WIDE_FORM_ID,
                    t,
                    now,
                )
        })
        .unwrap_or(false);
    if !ok {
        // Print enough info for the operator to grep journalctl
        // and figure out WHICH check failed (missing token vs.
        // expired vs. wrong key). Token value itself is logged at
        // 8-char prefix only — full value is sensitive enough that
        // we don't want it in plaintext logs.
        let token_prefix: String = token
            .as_deref()
            .map(|t| t.chars().take(8).collect())
            .unwrap_or_else(|| "(none)".into());
        let content_type = parts
            .headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("(missing)")
            .to_string();
        tracing::warn!(
            path = %form_id,
            had_session = %ctx.is_authenticated(),
            token_source = ?token_source(token.as_deref(), &parts),
            token_prefix = %token_prefix,
            content_type = %content_type,
            is_multipart = %is_multipart,
            "CSRF check failed",
        );
        // Friendly HTML page so the operator who lands on this
        // after a stale-form submit gets a clear next step rather
        // than a bare "CSRF check failed" plain-text wall. The
        // back-button hint is the most common fix (browsers
        // sometimes carry an expired session into the new
        // submit). The journalctl breadcrumb makes operator
        // self-service possible without source-diving.
        let html = format!(
            "<!doctype html><html><head><meta charset=utf-8><title>CSRF check failed · hyperion</title>\
             <style>body{{font-family:system-ui,-apple-system,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1.5rem;line-height:1.55;color:#1a1a1a}}\
             h1{{margin:0 0 1rem;font-size:1.5rem}} code{{background:#f0f0f0;padding:0.1rem 0.3rem;border-radius:3px;font-size:0.85em}}\
             .meta{{color:#666;font-size:0.85rem;margin-top:1.5rem;border-top:1px solid #ddd;padding-top:1rem}}</style></head>\
             <body><h1>CSRF check failed</h1>\
             <p>The token attached to your form submission didn't validate. This usually means one of:</p>\
             <ul><li>You loaded the page in another tab a long time ago and your session has changed since.</li>\
             <li>You went back via browser history and re-submitted a cached form.</li>\
             <li>An admin restarted hyperion-web and the session keys rotated.</li></ul>\
             <p><strong>Fix:</strong> go back, refresh the page (Cmd/Ctrl + Shift + R) and try the action again.</p>\
             <p class=meta>Path: <code>{path}</code> · Source: <code>{source}</code> · Operator can grep journalctl with <code>journalctl -u hyperion-web -g 'CSRF check failed' --since '5 min ago'</code></p>\
             </body></html>",
            path = askama_escape::escape(&form_id, askama_escape::Html),
            source = token_source(token.as_deref(), &parts),
        );
        return (
            StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            html,
        )
            .into_response();
    }
    let req = Request::from_parts(parts, body);
    next.run(req).await
}

/// Diagnostic label for the source we picked the CSRF token from.
/// Used only for log lines on a failed check — helps debug "the form
/// definitely has a token, why is the middleware rejecting it".
fn token_source(token: Option<&str>, parts: &Parts) -> &'static str {
    if token.is_none() {
        return "none";
    }
    if parts.headers.contains_key("x-csrf-token") {
        return "header";
    }
    if parts
        .uri
        .query()
        .map(|q| q.contains("_csrf="))
        .unwrap_or(false)
    {
        return "query";
    }
    "body"
}
