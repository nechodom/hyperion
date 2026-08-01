pub mod api_docs;
pub mod api_v1;
pub mod audit;
pub mod avatar;
pub mod backups;
pub mod bans;
pub mod certs;
pub mod dashboard;
pub mod emails;
pub mod enroll;
pub mod files;
pub mod firewall;
pub mod health;
pub mod hostings;
pub mod import_panel;
pub mod import_wizard;
pub mod install;
pub mod jobs;
pub mod login;
pub mod me;
pub mod migration;
pub mod monitoring;
pub mod notifications;
pub mod profile;
pub mod profiles;
pub mod roles;
pub mod search;
pub mod services_health;
pub mod sessions;
pub mod settings;
pub mod statics;
pub mod stats;
pub mod trash;
pub mod users;
pub mod vulns;

/// Uppercase first ASCII letter of `username`, or `?` if empty / non-ASCII.
/// Used as the avatar glyph in the sidebar.
pub fn user_initial(username: &str) -> char {
    username
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('?')
}

/// Friendly display label for an internal role id. The stored strings
/// (`super_admin`, …) stay as-is for permission checks + the DB; only the
/// UI shows these clearer names. Keep in sync with ROLE_LABELS in base.html.
pub fn role_label(role: &str) -> &'static str {
    match role {
        "super_admin" => "Owner",
        "admin" => "Administrator",
        "operator" => "Operator",
        "customer" => "Customer",
        "viewer" => "Read-only",
        _ => "Unknown",
    }
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

/// Banner text for the nodes a fan-out DROPPED because their response
/// failed authentication, or `None` when none did.
///
/// Every cluster-aggregate page feeds the `failed` half of
/// [`crate::dispatcher::fan_out_reporting`] through here and renders the
/// result via `_node_auth_banner.html`. Staying silent is the real bug:
/// a discarded response makes the page show FEWER rows, and "no sites"
/// must never be mistaken for "the sites are gone". Nodes that merely
/// timed out or were unreachable are NOT reported here — those are
/// ordinary downtime, already visible as a stale-heartbeat pill, and
/// mixing them in would train operators to ignore this banner.
///
/// Only the operator-chosen node label is interpolated — never the
/// response body, the verifier's reason string, or the worker's IP.
pub(crate) fn node_auth_warning(
    failed: &[(
        hyperion_types::NodeSummary,
        crate::dispatcher::DispatchError,
    )],
) -> Option<String> {
    let names: Vec<&str> = failed
        .iter()
        .filter(|(_, e)| {
            matches!(
                e,
                crate::dispatcher::DispatchError::ResponseAuthFailed { .. }
            )
        })
        .map(|(n, _)| {
            if n.label.is_empty() {
                n.node_id.as_str()
            } else {
                n.label.as_str()
            }
        })
        .collect();
    if names.is_empty() {
        return None;
    }
    let (subject, possessive, responses, them) = if names.len() == 1 {
        ("Node", "its", "response", "it")
    } else {
        ("Nodes", "their", "responses", "them")
    };
    Some(format!(
        "{subject} {} could not be authenticated. The master rejected the signature on \
         {possessive} {responses} and discarded {them}, so {possessive} rows are MISSING \
         from this page — a short or empty list here does not mean the data is gone. \
         This is a signature failure, not downtime: check `journalctl -u hyperion-agent` \
         on the node, and whether anything is intercepting master→worker traffic.",
        names.join(", "),
    ))
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
pub fn session_csrf_token(state: &crate::state::SharedState, ctx: &crate::auth::AuthCtx) -> String {
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
    // Scheme detection — priority order:
    //   1. X-Forwarded-Proto when behind a reverse proxy
    //   2. host header carries an explicit `:443` or `:8443` port
    //      (Hyperion's own TLS listener) ⇒ force https. Without
    //      this rule a single-host master without secure_cookies=true
    //      derives `http://master.tld:8443`, which the target node
    //      then hits and curl bails with `Received HTTP/0.9 when
    //      not allowed` (curl's symptom for "TLS handshake bytes
    //      arrived where HTTP was expected"). The user just hit
    //      this on stav with `http://178.105.99.35:8443/...`.
    //   3. listen port from agent.toml (same TLS-port inference
    //      when the host header is useless and we fell through
    //      to cached_public_ip).
    //   4. secure_cookies flag — boolean operator preference.
    //   5. plain http as last resort.
    let host_header = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let listen_port = port_from_listen(&state.cfg.web.listen);

    let scheme_from_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
        .filter(|s| s == "http" || s == "https");

    let scheme_from_port = host_header
        .as_deref()
        .and_then(port_from_host_header)
        .or(listen_port)
        .and_then(|p| match p {
            443 | 8443 => Some("https".to_string()),
            // 80 + 8080 + 8000 etc. don't get forced http — operator
            // might be terminating TLS in front; let the secure_cookies
            // / x-forwarded-proto cases speak.
            _ => None,
        });

    let scheme = scheme_from_proto.or(scheme_from_port).unwrap_or_else(|| {
        if state.cfg.web.secure_cookies {
            "https".to_string()
        } else {
            "http".to_string()
        }
    });

    if let Some(h) = host_header.as_deref() {
        if !host_is_useless(h) {
            return format!("{scheme}://{h}");
        }
    }
    if let Some(pub_ip) = cached_public_ip().await {
        return match listen_port {
            Some(p) => format!("{scheme}://{pub_ip}:{p}"),
            None => format!("{scheme}://{pub_ip}"),
        };
    }
    format!(
        "{scheme}://CHANGE-ME-set-master-url-below:{}",
        listen_port.unwrap_or(8443)
    )
}

/// The bare host — no scheme, no port — that the operator reached this
/// panel on. Same `Host`-header → cached-public-IP precedence as
/// [`derive_master_url`], but stripped down so it can be dropped into a
/// non-HTTP context (an FTP/FTPS host handed to a client, an SSH host, …).
///
/// Only meaningful for a resource served by *this* (master) box. For one
/// that lives on a worker node, resolve that node's `public_ip` instead —
/// this host would point a client straight at the wrong machine.
pub async fn panel_host(headers: &axum::http::HeaderMap) -> String {
    if let Some(h) = headers.get("host").and_then(|v| v.to_str().ok()) {
        if !host_is_useless(h) {
            return host_without_port(h).to_string();
        }
    }
    if let Some(ip) = cached_public_ip().await {
        return ip;
    }
    // No Host header AND public-IP detection failed (offline box). Surface
    // a clear marker rather than a bogus host a client would silently fail
    // to reach.
    "CHANGE-ME-server-host".to_string()
}

/// Extract the explicit port from a Host header. Returns None
/// when the header has no port (browser elided the default 80/443).
/// Handles bracketed IPv6 (`[::1]:8443`) + bare hostnames + IPv4.
fn port_from_host_header(host: &str) -> Option<u16> {
    if host.starts_with('[') {
        // [::1]:8443 → after ']:' is "8443"
        let after = host.split("]:").nth(1)?;
        return after.parse().ok();
    }
    // Bare IPv6 (no brackets, multiple colons) ⇒ no explicit port.
    if host.matches(':').count() > 1 {
        return None;
    }
    host.split(':').nth(1).and_then(|s| s.parse().ok())
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
        host.split(']')
            .next()
            .unwrap_or(host)
            .trim_start_matches('[')
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

/// Strip an explicit `:port` off a `Host` header while preserving a
/// bracketed IPv6 literal (`[2001:db8::1]:8443` → `[2001:db8::1]`).
/// Bare hostnames / IPv4 drop a trailing `:port`; an unbracketed IPv6
/// (2+ colons, so no port) is returned untouched. No allocation.
fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        // Bracketed IPv6 — keep through the closing bracket, dropping any
        // `:port` that follows it.
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }
    // Unbracketed IPv6 (2+ colons) carries no port — leave as-is.
    if host.matches(':').count() > 1 {
        return host;
    }
    // hostname / IPv4, optionally suffixed with `:port`.
    host.split(':').next().unwrap_or(host)
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
    use crate::dispatcher::DispatchError;

    fn node(node_id: &str, label: &str) -> hyperion_types::NodeSummary {
        hyperion_types::NodeSummary {
            node_id: node_id.to_string(),
            label: label.to_string(),
            master_url: None,
            agent_version: String::new(),
            public_ip: None,
            enrolled_at: 0,
            last_seen_at: 0,
            is_drained: false,
            drain_reason: String::new(),
            tls_spki_pin: None,
            resp_pubkey: None,
        }
    }

    /// Downtime must NOT raise the banner. If it did, every routine
    /// worker reboot would show the security warning and operators would
    /// learn to scroll past the one case that matters.
    #[test]
    fn unreachable_node_does_not_raise_the_banner() {
        let failed = vec![(
            node("n1", "web-1"),
            DispatchError::NodeUnreachable {
                node_id: "n1".into(),
                kind: "TCP connect refused".into(),
            },
        )];
        assert!(node_auth_warning(&failed).is_none());
        assert!(node_auth_warning(&[]).is_none());
    }

    /// The whole point: the page must say the rows are missing, and name
    /// the node by its operator-chosen label.
    #[test]
    fn auth_failure_names_the_node_and_says_rows_are_missing() {
        let failed = vec![(
            node("n1", "web-1"),
            DispatchError::ResponseAuthFailed {
                node_id: "n1".into(),
                reason: "signature verify failed".into(),
            },
        )];
        let w = node_auth_warning(&failed).expect("auth failure must warn");
        assert!(w.contains("web-1"), "{w}");
        assert!(w.contains("MISSING"), "{w}");
        // Never presented as downtime — that would send the operator off
        // restarting a healthy agent.
        assert!(w.contains("not downtime"), "{w}");
    }

    /// A node with no label falls back to its id — an unnamed node must
    /// still be identifiable from the banner alone.
    #[test]
    fn auth_failure_falls_back_to_node_id_when_unlabelled() {
        let failed = vec![(
            node("n2", ""),
            DispatchError::ResponseAuthFailed {
                node_id: "n2".into(),
                reason: "unsigned".into(),
            },
        )];
        let w = node_auth_warning(&failed).expect("auth failure must warn");
        assert!(w.contains("n2"), "{w}");
    }

    /// Mixed batch: only the auth failure is reported, and the plural
    /// wording tracks the number of REPORTED nodes, not the batch size.
    #[test]
    fn mixed_failures_report_only_the_auth_ones() {
        let failed = vec![
            (
                node("n1", "web-1"),
                DispatchError::ResponseAuthFailed {
                    node_id: "n1".into(),
                    reason: "signature verify failed".into(),
                },
            ),
            (
                node("n2", "web-2"),
                DispatchError::NodeUnreachable {
                    node_id: "n2".into(),
                    kind: "timeout".into(),
                },
            ),
        ];
        let w = node_auth_warning(&failed).expect("auth failure must warn");
        assert!(w.starts_with("Node web-1"), "{w}");
        assert!(!w.contains("web-2"), "{w}");
    }

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

    /// The Host header carries the URL the operator's browser
    /// hit. derive_master_url uses the port there to force https
    /// when the agent's TLS listener (8443) or standard TLS (443)
    /// is in play — otherwise a master without secure_cookies=true
    /// builds `http://master:8443/…` which the worker hits and
    /// curl bails on the TLS handshake (Received HTTP/0.9 when
    /// not allowed). User hit this on stav after the --max-time
    /// fix landed.
    #[test]
    fn port_from_host_header_extracts_explicit_port() {
        // IPv4 + port.
        assert_eq!(port_from_host_header("178.105.99.35:8443"), Some(8443));
        assert_eq!(port_from_host_header("master.tld:443"), Some(443));
        // No port (browser elided default 80/443).
        assert_eq!(port_from_host_header("master.tld"), None);
        assert_eq!(port_from_host_header("178.105.99.35"), None);
        // IPv6 bracketed.
        assert_eq!(port_from_host_header("[::1]:8443"), Some(8443));
        assert_eq!(
            port_from_host_header("[2a00:1450:4001:830::200e]:443"),
            Some(443)
        );
        // IPv6 bare (no brackets) ⇒ no explicit port — multiple
        // colons confuse a naive split, so we MUST not return one
        // of the address segments as the port.
        assert_eq!(port_from_host_header("::1"), None);
        assert_eq!(port_from_host_header("2a00:1450:4001:830::200e"), None);
        // Garbage after the colon is not a port.
        assert_eq!(port_from_host_header("master.tld:not-a-port"), None);
    }

    #[test]
    fn host_without_port_strips_port_and_keeps_ipv6_brackets() {
        // hostname / IPv4 — drop the :port, keep the host.
        assert_eq!(host_without_port("s4.digitalka.cz"), "s4.digitalka.cz");
        assert_eq!(host_without_port("s4.digitalka.cz:8443"), "s4.digitalka.cz");
        assert_eq!(host_without_port("178.105.99.35:443"), "178.105.99.35");
        // Bracketed IPv6 — strip the :port but keep the literal intact
        // (an FTP client needs the brackets to parse it).
        assert_eq!(
            host_without_port("[2a00:1450:4001:830::200e]:443"),
            "[2a00:1450:4001:830::200e]"
        );
        assert_eq!(host_without_port("[::1]"), "[::1]");
        // Unbracketed IPv6 carries no port — must not lose a segment.
        assert_eq!(
            host_without_port("2a00:1450:4001:830::200e"),
            "2a00:1450:4001:830::200e"
        );
    }
}
