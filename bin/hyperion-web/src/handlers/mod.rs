pub mod audit;
pub mod dashboard;
pub mod enroll;
pub mod health;
pub mod hostings;
pub mod install;
pub mod login;
pub mod emails;
pub mod files;
pub mod me;
pub mod migration;
pub mod monitoring;
pub mod notifications;
pub mod profile;
pub mod profiles;
pub mod search;
pub mod services_health;
pub mod settings;
pub mod statics;
pub mod stats;
pub mod users;

/// Uppercase first ASCII letter of `username`, or `?` if empty / non-ASCII.
/// Used as the avatar glyph in the sidebar.
pub fn user_initial(username: &str) -> char {
    username
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('?')
}

/// Short content hash of the bundled CSS. Goes into `?v=…` on the
/// `<link>` tag so a redeploy invalidates the browser cache cleanly.
pub fn css_version() -> &'static str {
    statics::css_version()
}

/// Same for the htmx bundle.
pub fn htmx_version() -> &'static str {
    statics::htmx_version()
}

/// Session-wide CSRF token. ONE token valid for any POST in the same
/// session — way nicer for templates than minting a separate scoped
/// token for every form. Verified by the middleware via the wildcard
/// `SESSION_WIDE_FORM_ID` path.
///
/// Templates inject this as `<input type="hidden" name="_csrf" value="{{ csrf_token }}">`
/// in every form. Returns empty string on unauthenticated requests
/// (which never reach the CSRF guard anyway — they're redirected to
/// /login before the POST middleware runs).
pub fn session_csrf_token(
    state: &crate::state::SharedState,
    ctx: &crate::auth::AuthCtx,
) -> String {
    let sid = ctx
        .session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default();
    hyperion_auth::csrf::mint(
        state.csrf_key.as_ref(),
        &sid,
        hyperion_auth::csrf::SESSION_WIDE_FORM_ID,
        hyperion_types::now_secs(),
    )
}

/// Derive the master's externally-reachable URL from the incoming
/// request. Used wherever the UI prints a URL that the operator (or
/// a node, or another tool) will paste somewhere reachable from
/// outside this box — install one-liner, migration bundle download
/// URL, etc.
///
/// Logic:
///   1. Browser's `Host` header — almost always the right answer.
///      Honours `X-Forwarded-Proto` for installs behind a reverse
///      proxy.
///   2. If `Host` is missing OR contains a host no remote can reach
///      (`0.0.0.0`, `127.0.0.1`, `localhost`, `::1`, `::`), fall
///      through to the master's public IP — detected once via curl
///      against ipify, cached for 1h per process so /install renders
///      don't add multi-second latency.
///   3. If even that fails (offline box / firewall), return a clear
///      placeholder (`CHANGE-ME-set-master-url-below`) so the
///      template can surface a banner instead of letting a bogus
///      URL slip into the install command.
pub async fn derive_master_url(
    state: &crate::state::SharedState,
    headers: &axum::http::HeaderMap,
) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| {
            if state.cfg.web.secure_cookies {
                "https".to_string()
            } else {
                "http".to_string()
            }
        });
    if let Some(h) = headers.get("host").and_then(|v| v.to_str().ok()) {
        if !host_is_useless(h) {
            return format!("{scheme}://{h}");
        }
    }
    let port = port_from_listen(&state.cfg.web.listen);
    if let Some(pub_ip) = cached_public_ip().await {
        return match port {
            Some(p) => format!("{scheme}://{pub_ip}:{p}"),
            None => format!("{scheme}://{pub_ip}"),
        };
    }
    format!(
        "{scheme}://CHANGE-ME-set-master-url-below:{}",
        port.unwrap_or(8443)
    )
}

/// True iff `host` is a value that no remote node can reach us at:
/// unspecified / loopback / empty. Strips optional port suffix
/// (`0.0.0.0:8443` → `0.0.0.0`, `[::1]:8443` → `::1`).
fn host_is_useless(host: &str) -> bool {
    if host.is_empty() {
        return true;
    }
    // Catch bare IPv6 hosts first — `::1` without brackets would
    // otherwise split on the first colon and produce empty string.
    if host == "::1" || host == "::" {
        return true;
    }
    let bare = if host.starts_with('[') {
        host.split(']').next().unwrap_or(host).trim_start_matches('[')
    } else {
        // Only split on colon when the host has at most ONE colon —
        // anything with multiple colons is an unbracketed IPv6 host
        // (which we already caught above) or malformed.
        if host.matches(':').count() > 1 {
            host
        } else {
            host.split(':').next().unwrap_or(host)
        }
    };
    matches!(bare, "0.0.0.0" | "127.0.0.1" | "localhost" | "::1" | "::")
}

/// Parse the port out of the listen address. Returns None for
/// unparseable input — callers default to 8443.
fn port_from_listen(listen: &str) -> Option<u16> {
    let after_colon = if listen.starts_with('[') {
        listen.split(']').nth(1)?.trim_start_matches(':')
    } else {
        listen.rsplit(':').next()?
    };
    after_colon.parse().ok()
}

/// 1-hour cached public-IP fetch. Per-process. Single shot, no
/// retries — failure returns None and the caller handles it.
async fn cached_public_ip() -> Option<String> {
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    static CACHE: Lazy<Mutex<Option<(String, std::time::Instant)>>> =
        Lazy::new(|| Mutex::new(None));
    const TTL: std::time::Duration = std::time::Duration::from_secs(3600);
    {
        let g = CACHE.lock().ok()?;
        if let Some((ip, ts)) = g.as_ref() {
            if ts.elapsed() < TTL {
                return Some(ip.clone());
            }
        }
    }
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args(["-fsS", "--max-time", "4", "https://api.ipify.org"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if ip.is_empty() || ip.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    let mut g = CACHE.lock().ok()?;
    *g = Some((ip.clone(), std::time::Instant::now()));
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_useless_catches_loopback_variants() {
        assert!(host_is_useless(""));
        assert!(host_is_useless("0.0.0.0"));
        assert!(host_is_useless("0.0.0.0:8443"));
        assert!(host_is_useless("127.0.0.1"));
        assert!(host_is_useless("127.0.0.1:443"));
        assert!(host_is_useless("localhost"));
        assert!(host_is_useless("localhost:8443"));
        assert!(host_is_useless("::1"));
        assert!(host_is_useless("[::1]:8443"));
        assert!(host_is_useless("[::]:8443"));
    }

    #[test]
    fn host_is_useless_passes_real_hosts() {
        assert!(!host_is_useless("s4.digitalka.cz"));
        assert!(!host_is_useless("s4.digitalka.cz:8443"));
        assert!(!host_is_useless("178.105.99.35"));
        assert!(!host_is_useless("178.105.99.35:8443"));
        assert!(!host_is_useless("my-master.local"));
        assert!(!host_is_useless("[2a00:1450:4001:830::200e]:443"));
    }

    #[test]
    fn port_from_listen_handles_ipv4() {
        assert_eq!(port_from_listen("0.0.0.0:8443"), Some(8443));
        assert_eq!(port_from_listen("127.0.0.1:443"), Some(443));
        assert_eq!(port_from_listen("not-a-port"), None);
    }

    #[test]
    fn port_from_listen_handles_ipv6_brackets() {
        assert_eq!(port_from_listen("[::]:8443"), Some(8443));
        assert_eq!(port_from_listen("[::1]:443"), Some(443));
    }
}
