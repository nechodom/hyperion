//! Unified error type for handlers.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not authenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("agent rpc: {0}")]
    Rpc(String),
    #[error("internal: {0}")]
    Internal(String),
    /// A specific node is unreachable — the master tried to reach
    /// it over signed RPC (port 9443) and the TCP connect failed.
    /// We surface this as a themed page with actionable hints
    /// rather than dumping the raw curl error (which leaks IPs).
    #[error("node {node_id} unreachable: {hint}")]
    NodeUnreachable {
        node_id: String,
        /// Short human-readable hint shown on the error page.
        /// Examples: "TCP connect refused (port 9443)",
        /// "TLS handshake timeout", "DNS lookup failed".
        hint: String,
    },
    /// 429 — returned by per-IP rate-limited handlers (enroll,
    /// heartbeat, email-test). Body is the reason shown to the
    /// caller. JSON-shaped because the limited endpoints are
    /// JSON-API (called by curl from nodes, not via the browser).
    #[error("too many requests: {0}")]
    TooManyRequests(String),
}

/// Themed full-page error template. Falls back to a plain
/// minimal-HTML string if the template render itself fails
/// (would be an askama bug — never expected in practice).
#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPageTpl<'a> {
    css_version: &'static str,
    code: u16,
    title: &'a str,
    headline: &'a str,
    body: &'a str,
    hints: &'a [&'a str],
    /// Optional "Retry" / "Open settings" action link rendered as
    /// a button below the body. (label, href).
    action: Option<(&'a str, &'a str)>,
}

/// Strip IPv4 / IPv6 / port:port leaks from an arbitrary error
/// message so we can safely surface it. Replaces every match
/// with `<node>` so the operator gets the structure of the
/// failure without the literal address.
fn redact_addresses(s: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;
    // IPv4 dotted quad. We don't bother validating ranges — the
    // false-positive cost (replacing "1.2.3.4" in a log tail) is
    // strictly better than leaking an IP.
    static V4: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
            .unwrap_or_else(|e| panic!("BUG: V4 redactor regex: {e}"))
    });
    // IPv6: anything containing `::` plus surrounding hex+colons
    // (compressed form, including `::1` and bare `::`), or the full
    // 8-group dotted form. We avoid `\b` here because `:` is not a
    // word character — `\b::1\b` never matches `::1` after a space.
    // Over-redaction (e.g. trapping `key::value`) is acceptable;
    // missing a leak is not.
    static V6: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"[0-9a-fA-F:]*::[0-9a-fA-F:]*|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")
            .unwrap_or_else(|e| panic!("BUG: V6 redactor regex: {e}"))
    });
    let s = V4.replace_all(s, "<node>").into_owned();
    V6.replace_all(&s, "<node>").into_owned()
}

/// Render a themed error page or fall back to plain HTML when
/// the template render fails.
fn render_themed(
    status: StatusCode,
    title: &str,
    headline: &str,
    body: &str,
    hints: &[&str],
    action: Option<(&str, &str)>,
) -> Response {
    let tpl = ErrorPageTpl {
        css_version: crate::handlers::css_version(),
        code: status.as_u16(),
        title,
        headline,
        body,
        hints,
        action,
    };
    match tpl.render() {
        Ok(html) => (status, [("content-type", "text/html; charset=utf-8")], html).into_response(),
        Err(_) => (
            status,
            [("content-type", "text/html; charset=utf-8")],
            format!("<h1>{} {title}</h1><p>{body}</p>", status.as_u16()),
        )
            .into_response(),
    }
}

/// Router fallback for URLs that match no route at all. axum's built-in
/// fallback is a bare empty `404` with no body — this renders the themed error
/// page instead. Wording is generic ("this page doesn't exist"), distinct from
/// [`AppError::NotFound`], which is for a known-but-missing resource.
pub async fn not_found_fallback() -> Response {
    render_themed(
        StatusCode::NOT_FOUND,
        "Not found",
        "This page doesn't exist",
        "The address may be mistyped, or the page may have moved. \
         Head back to the dashboard to find your way around.",
        &[],
        Some(("Back to dashboard", "/")),
    )
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthenticated => render_themed(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "Please sign in",
                "Your session expired or wasn't recognised. Sign in again to continue.",
                &[],
                Some(("Sign in", "/login")),
            ),
            AppError::Forbidden => render_themed(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "You don't have access to this page",
                "Your role doesn't grant access to the requested resource. \
                 Ask a super_admin if you think this is a mistake.",
                &[],
                Some(("Back to dashboard", "/")),
            ),
            AppError::BadRequest(m) => {
                let safe = redact_addresses(&m);
                render_themed(
                    StatusCode::BAD_REQUEST,
                    "Bad request",
                    "Something in the form didn't validate",
                    &safe,
                    &[],
                    Some(("Go back", "javascript:history.back()")),
                )
            }
            AppError::NotFound => render_themed(
                StatusCode::NOT_FOUND,
                "Not found",
                "We couldn't find that.",
                "The URL might be stale or the hosting may have been deleted.",
                &[],
                Some(("Back to hostings", "/hostings")),
            ),
            AppError::NodeUnreachable { node_id, hint } => {
                // node_id is operator-controlled label (set at enrollment)
                // so it's safe to surface; `hint` already comes pre-scrubbed.
                let body = format!(
                    "We tried to reach node \"{node_id}\" over signed RPC and the connection \
                     failed: {hint}"
                );
                render_themed(
                    StatusCode::BAD_GATEWAY,
                    "Node unreachable",
                    "Couldn't reach the target node",
                    &body,
                    &[
                        "Make sure hyperion-agent is running on the target node \
                         (`systemctl status hyperion-agent` on the node).",
                        "Check the node's agent.toml has `[remote_rpc] enabled = true` \
                         and the configured `bind` matches what the master is dialing.",
                        "If a firewall is in the path, allow TCP 9443 inbound on the worker.",
                        "Re-run the connectivity test on /install for a per-node breakdown.",
                    ],
                    Some(("Open /install", "/install")),
                )
            }
            AppError::Rpc(m) => {
                let safe = redact_addresses(&m);
                // Heuristic: when the agent rpc error mentions a curl-7
                // / connect / refused fingerprint we treat it as a
                // generic node-unreachable since the caller didn't
                // tell us which node_id was at fault.
                let looks_like_connect = safe.contains("Couldn't connect")
                    || safe.contains("connect refused")
                    || safe.contains("curl exit Some(7)")
                    || safe.contains("Failed to connect");
                let headline = if looks_like_connect {
                    "Couldn't reach the agent"
                } else {
                    "Agent rejected the request"
                };
                let hints: &[&str] = if looks_like_connect {
                    &[
                        "The agent may be restarting after a deploy — try again in a moment.",
                        "If this is a worker node, confirm the master can route to it \
                         on TCP 9443.",
                        "Check `journalctl -u hyperion-agent -n 50` on the target node.",
                    ]
                } else {
                    &[]
                };
                render_themed(
                    StatusCode::BAD_GATEWAY,
                    "Agent error",
                    headline,
                    &safe,
                    hints,
                    Some(("Retry", "javascript:location.reload()")),
                )
            }
            AppError::Internal(m) => {
                tracing::error!(error=%m, "internal error");
                render_themed(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error",
                    "Something went wrong on our side",
                    "The full details were logged to the audit log. Try again, \
                     and contact the operator if the problem persists.",
                    &[],
                    Some(("Back to dashboard", "/")),
                )
            }
            AppError::TooManyRequests(m) => {
                let safe = redact_addresses(&m);
                render_themed(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many requests",
                    "Please slow down",
                    &safe,
                    &["The rate limit resets within a minute — retry shortly."],
                    Some(("Retry", "javascript:location.reload()")),
                )
            }
        }
    }
}

impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        AppError::Internal(format!("template: {e}"))
    }
}

impl From<hyperion_rpc_client::ClientError> for AppError {
    fn from(e: hyperion_rpc_client::ClientError) -> Self {
        AppError::Rpc(e.to_string())
    }
}

impl From<hyperion_validate::ValidationError> for AppError {
    fn from(e: hyperion_validate::ValidationError) -> Self {
        AppError::BadRequest(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    // The real curl-error string we got in production. The IP must
    // never appear in the rendered body.
    const LEAKING_MSG: &str = "curl exit Some(7): curl: (7) Failed to connect to 168.119.104.66 \
         port 9443 after 2 ms: Couldn't connect to server";

    #[test]
    fn redacts_ipv4() {
        let out = redact_addresses(LEAKING_MSG);
        assert!(!out.contains("168.119.104.66"), "leaked IPv4: {out}");
        assert!(out.contains("<node>"));
    }

    #[test]
    fn redacts_multiple_ipv4() {
        let out = redact_addresses("from 10.0.0.1 to 192.168.1.1");
        assert!(!out.contains("10.0.0.1"));
        assert!(!out.contains("192.168.1.1"));
        assert_eq!(out.matches("<node>").count(), 2);
    }

    #[test]
    fn redacts_ipv6() {
        let out = redact_addresses("Failed to connect to 2001:db8::1 port 9443");
        assert!(!out.contains("2001:db8"), "leaked IPv6: {out}");
        assert!(out.contains("<node>"));
    }

    #[test]
    fn redacts_loopback_ipv6() {
        let out = redact_addresses("connect ::1 port 9443");
        assert!(!out.contains("::1"), "leaked ::1: {out}");
    }

    #[test]
    fn rpc_error_response_does_not_leak_ip() {
        // Simulate what dispatcher used to do (raw curl error through
        // AppError::Rpc) and assert the rendered body doesn't contain
        // the IP. Regression guard: if anyone reverts the redaction,
        // this test will catch it.
        let err = AppError::Rpc(LEAKING_MSG.to_string());
        let resp = err.into_response();
        // Tokio test runtime needed for to_bytes — block manually.
        let body = futures_block_on(async { to_bytes(resp.into_body(), 64 * 1024).await.unwrap() });
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("168.119.104.66"),
            "IP leaked through into rendered response: {text}"
        );
        // And the page should actually be themed (contain our marker).
        assert!(text.contains("HY"), "page not themed");
    }

    #[test]
    fn node_unreachable_includes_node_id_but_no_ip() {
        let err = AppError::NodeUnreachable {
            node_id: "stav".to_string(),
            hint: "TCP connect refused (port 9443)".to_string(),
        };
        let resp = err.into_response();
        let body = futures_block_on(async { to_bytes(resp.into_body(), 64 * 1024).await.unwrap() });
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("stav"), "node_id missing from page");
        assert!(
            text.contains("TCP connect refused"),
            "hint missing from page"
        );
        // No accidental IP from elsewhere in the codebase.
        assert!(!text.contains("9443.168"), "false-positive IP shape");
    }

    #[test]
    fn bad_request_redacts_too() {
        // BadRequest comes from form validation but operators
        // occasionally pipe error tails in (e.g. "couldn't reach
        // <ip>") — make sure we scrub those.
        let err = AppError::BadRequest("validation failed talking to 10.0.0.5".to_string());
        let resp = err.into_response();
        let body = futures_block_on(async { to_bytes(resp.into_body(), 64 * 1024).await.unwrap() });
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("10.0.0.5"));
    }

    /// Tiny single-threaded executor so we don't depend on the
    /// `#[tokio::test]` macro just for these blocking-on-body cases.
    fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
        // tokio's runtime is overkill for this — we just need to
        // poll a `to_bytes` future which is already-resolved by the
        // time IntoResponse returns. Use the lightweight pollster
        // pattern.
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }
        let waker: Waker = Arc::new(Noop).into();
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }
}
