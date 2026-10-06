//! "Open phpMyAdmin" — the panel side of the phpMyAdmin pass-through.
//!
//! Served ONLY by the separate `pma_listen` listener (its own port, so its
//! own browser origin), never by the panel's router. That separation is the
//! point: phpMyAdmin renders data tenants control, and an XSS in phpMyAdmin
//! that ran in the panel's origin could read every panel page and act as the
//! signed-in admin across the whole cluster. On its own origin it can reach
//! nothing but phpMyAdmin.
//!
//! Every request is authenticated with the panel's session cookie (cookies
//! are per host, not per port, so the browser sends it here too), authorised
//! per hosting exactly like the Database card's own actions, and relayed to
//! the owning node, whose agent attaches the database credentials. See
//! `hyperion_types::pma` for the whole model.

use crate::auth::AuthCtx;
use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine as _;
use hyperion_rpc::codec::{Request as RpcRequest, Response as RpcResponse};
use hyperion_rpc::wire::HostingSelector;
use hyperion_state::capabilities::Capability;
use hyperion_types::pma::{self as wire, PmaHttpRequest};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The CSP phpMyAdmin pages run under. phpMyAdmin needs inline scripts and
/// `eval` (its own header asks for both); everything else stays on 'self',
/// which on this listener means phpMyAdmin and nothing else. No framing, no
/// plugins, forms only back to itself.
const PMA_CSP: &str = "default-src 'self'; \
     script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data: blob:; \
     font-src 'self' data:; \
     connect-src 'self'; \
     form-action 'self'; \
     base-uri 'self'; \
     object-src 'none'; \
     frame-src 'self'; \
     frame-ancestors 'none'";

/// How long a hosting → node lookup is reused. phpMyAdmin pulls dozens of
/// assets per page and `find_hosting_anywhere` may ask every node; a minute
/// is far shorter than any move between nodes takes. Authorisation is NOT
/// cached — it runs on every request.
const NODE_CACHE_TTL: Duration = Duration::from_secs(60);

fn node_cache() -> &'static Mutex<HashMap<String, (Option<String>, Instant)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Option<String>, Instant)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_node(id: &str) -> Option<Option<String>> {
    let guard = node_cache().lock().ok()?;
    guard
        .get(id)
        .filter(|(_, at)| at.elapsed() < NODE_CACHE_TTL)
        .map(|(n, _)| n.clone())
}

fn remember_node(id: &str, node: Option<String>) {
    if let Ok(mut g) = node_cache().lock() {
        g.retain(|_, (_, at)| at.elapsed() < NODE_CACHE_TTL);
        g.insert(id.to_string(), (node, Instant::now()));
    }
}

fn forget_node(id: &str) {
    if let Ok(mut g) = node_cache().lock() {
        g.remove(id);
    }
}

/// The router for the phpMyAdmin listener. Nothing of the panel is mounted
/// here — not even its static assets — so this origin holds no panel page.
pub fn router(state: SharedState) -> axum::Router {
    use axum::routing::any;
    axum::Router::new()
        .route("/pma/:id", any(get_bare))
        .route("/pma/:id/", any(relay))
        .route("/pma/:id/*rest", any(relay))
        .fallback(|| async { page(StatusCode::NOT_FOUND, "Not found", "Nothing here.") })
        .layer(axum::middleware::from_fn(pma_headers))
        .with_state(state)
}

/// The URL the hosting's Database card links to, or `None` when the
/// phpMyAdmin listener is switched off. Built from the host the operator is
/// using right now, so it works the same on a raw IP and on the panel's
/// hostname — only the port differs, which is exactly what gives phpMyAdmin
/// an origin of its own.
pub fn pma_url(state: &SharedState, panel_host: &str, hosting_id: &str) -> Option<String> {
    // The listener only exists in TLS mode (see main.rs).
    if !state.cfg.web.tls_enabled {
        return None;
    }
    let port = super::listen_port(&state.cfg.web.pma_listen)?;
    Some(format!("https://{panel_host}:{port}/pma/{hosting_id}/"))
}

/// `/pma/<id>` → `/pma/<id>/`, so phpMyAdmin's relative links resolve.
async fn get_bare(axum::extract::Path(id): axum::extract::Path<String>) -> Response {
    if !wire::hosting_id_ok(&id) {
        return page(StatusCode::NOT_FOUND, "Not found", "Nothing here.");
    }
    Redirect::to(&format!("/pma/{id}/")).into_response()
}

async fn relay(State(state): State<SharedState>, ctx: AuthCtx, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();
    let Some(after) = path.strip_prefix(wire::PATH_PREFIX) else {
        return page(StatusCode::NOT_FOUND, "Not found", "Nothing here.");
    };
    let (id, rest) = after.split_at(after.find('/').unwrap_or(after.len()));
    if !wire::hosting_id_ok(id) {
        return page(StatusCode::NOT_FOUND, "Not found", "Nothing here.");
    }
    let id = id.to_string();

    // 1. A real, fully signed-in panel session. API keys never open
    //    phpMyAdmin, and an admin still owing their 2FA enrolment is not
    //    signed in yet as far as anything outside /profile is concerned.
    let signed_in = ctx.is_authenticated()
        && !ctx
            .session
            .as_ref()
            .map(|s| s.needs_2fa_enrollment())
            .unwrap_or(false);
    if !signed_in {
        return page(
            StatusCode::UNAUTHORIZED,
            "Sign in to the panel first",
            "Your panel session has ended. Sign in to the panel again, then open \
             phpMyAdmin from the hosting's Database card.",
        );
    }

    // 2. Same gate as the Database card's own write actions.
    if let Err(_denied) = super::hostings::require_hosting_access(
        &state,
        &ctx,
        &id,
        true,
        Capability::HostingDatabases,
    )
    .await
    {
        return page(
            StatusCode::FORBIDDEN,
            "No access",
            "Your account cannot manage this hosting's database.",
        );
    }

    // 3. The request itself.
    let method = parts.method.as_str().to_string();
    if !wire::method_allowed(&method) {
        return page(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed",
            "phpMyAdmin does not use this method.",
        );
    }
    let rest_and_query = match parts.uri.query() {
        Some(q) => format!("{rest}?{q}"),
        None => rest.to_string(),
    };
    if !wire::rest_path_ok(&rest_and_query) {
        return page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "That address is not valid.",
        );
    }
    let authority = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.authority().map(|a| a.to_string()))
        .unwrap_or_default();
    let base_url = format!("https://{authority}/pma/{id}/");
    if !wire::base_url_ok(&base_url, &id) {
        return page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "Unrecognised host name.",
        );
    }
    let body = match axum::body::to_bytes(body, wire::MAX_REQUEST_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return page(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Too large",
                "phpMyAdmin through the panel accepts at most 1 MiB per request. \
                 Import bigger SQL files over SSH or by restoring a backup.",
            )
        }
    };
    let mut headers = wire::filter_request_headers(
        parts
            .headers
            .iter()
            .filter_map(|(k, v)| Some((k.as_str(), v.to_str().ok()?))),
    );
    if let Some(c) = wire::filter_cookie_header(
        parts
            .headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok()),
    ) {
        headers.push(("cookie".into(), c));
    }
    let pma_req = PmaHttpRequest {
        method,
        path: rest_and_query,
        headers,
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
        base_url,
    };

    // 4. To the node that owns the database. hosting_id_ok() vetted the id,
    //    so it is always an Id selector, never a domain lookup.
    let sel = HostingSelector::Id(hyperion_types::HostingId::from(id.clone()));
    let node = match cached_node(&id) {
        Some(n) => n,
        None => match super::hostings::find_hosting_anywhere(&state, sel.clone()).await {
            Ok((_, n)) => {
                remember_node(&id, n.clone());
                n
            }
            Err(_) => {
                return page(
                    StatusCode::NOT_FOUND,
                    "Hosting not found",
                    "This hosting does not exist, or the node it lives on is not answering.",
                )
            }
        },
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        RpcRequest::PmaHttp { sel, req: pma_req },
    )
    .await;
    match resp {
        Ok(RpcResponse::PmaHttp(r)) => build_response(r),
        Ok(RpcResponse::Error(e)) => {
            forget_node(&id);
            page(
                StatusCode::BAD_GATEWAY,
                "phpMyAdmin is not available",
                &e.to_string(),
            )
        }
        Ok(_) => {
            forget_node(&id);
            page(
                StatusCode::BAD_GATEWAY,
                "phpMyAdmin is not available",
                "The node runs an older Hyperion that has no phpMyAdmin yet — update it \
                 from the Nodes page.",
            )
        }
        Err(e) => {
            forget_node(&id);
            page(
                StatusCode::BAD_GATEWAY,
                "phpMyAdmin is not available",
                &format!("The node that hosts this database did not answer: {e}"),
            )
        }
    }
}

fn build_response(r: wire::PmaHttpResponse) -> Response {
    let body = match base64::engine::general_purpose::STANDARD.decode(r.body_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => {
            return page(
                StatusCode::BAD_GATEWAY,
                "phpMyAdmin is not available",
                "The node sent an unreadable answer.",
            )
        }
    };
    let mut out = Response::new(Body::from(body));
    *out.status_mut() = StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_GATEWAY);
    // Filter again: the node is trusted to sign, not to pick our headers.
    for (k, v) in
        wire::filter_response_headers(r.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    {
        if let (Ok(name), Ok(val)) = (
            header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(&v),
        ) {
            out.headers_mut().append(name, val);
        }
    }
    out
}

/// Security headers for every response on this listener, phpMyAdmin's or
/// ours. Unconditional `insert`: whatever came from upstream is replaced.
async fn pma_headers(req: Request, next: axum::middleware::Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(PMA_CSP));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    // phpMyAdmin URLs carry SQL in the query string; never hand them to
    // another site in a Referer.
    h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    h.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
    resp
}

/// Minimal self-contained page — this origin serves no panel stylesheet.
fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\">\
         <title>{t} · phpMyAdmin · Hyperion</title>\
         <style>body{{font:15px/1.5 system-ui,sans-serif;max-width:34rem;margin:4rem auto;\
         padding:0 1rem}}h1{{font-size:1.25rem}}p{{opacity:.8}}</style></head>\
         <body><h1>{t}</h1><p>{b}</p></body></html>",
        t = esc(title),
        b = esc(body),
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_headers_are_refiltered_and_cookies_kept_apart() {
        let r = wire::PmaHttpResponse {
            status: 302,
            headers: vec![
                (
                    "set-cookie".into(),
                    "phpMyAdmin_https=a; path=/pma/x/".into(),
                ),
                ("set-cookie".into(), "pma_lang=cs".into()),
                ("x-powered-by".into(), "PHP".into()),
                ("location".into(), "https://h:8447/pma/x/index.php".into()),
            ],
            body_b64: base64::engine::general_purpose::STANDARD.encode("hi"),
        };
        let resp = build_response(r);
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get_all("set-cookie").iter().count(), 2);
        assert!(resp.headers().get("x-powered-by").is_none());
        assert!(resp.headers().get("location").is_some());
    }

    #[test]
    fn page_escapes() {
        let resp = page(StatusCode::BAD_GATEWAY, "<x>", "a & b");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
