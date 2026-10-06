//! phpMyAdmin pass-through — the wire shapes and the rules both ends apply.
//!
//! phpMyAdmin runs on every node, behind nginx listening on a ROOT-ONLY unix
//! socket. Nothing on the network can reach it: not the internet, not the
//! tenants who share the box. The only way in is the panel, which
//!
//!  1. authenticates the browser (panel session, re-derived privileges),
//!  2. checks the hosting grant (`HostingDatabases`, manage level),
//!  3. ships the request to the OWNING node over the signed RPC channel,
//!
//! and the agent there adds the database credentials from the node's own
//! secrets store before handing the request to nginx. The DB password never
//! leaves the node and never reaches the browser.
//!
//! phpMyAdmin's long CVE history is mostly pre-authentication bugs and XSS.
//! The first are unreachable here — every byte phpMyAdmin parses has already
//! passed the panel's login. The second is why the panel serves phpMyAdmin
//! from its OWN origin (a separate port, see `hyperion-web`'s `pma_listen`):
//! a script injected through data a tenant controls runs in an origin that
//! holds no panel page, so it cannot read the panel or its CSRF tokens.
//!
//! Everything here is pure so both sides can share it and tests can pin it.

use serde::{Deserialize, Serialize};

/// URL prefix both the panel's pma origin and the node's nginx use. The full
/// path is `/pma/<hosting-id>/<phpMyAdmin path>`; keeping the browser path and
/// the path nginx sees identical is what makes phpMyAdmin's cookie path and
/// relative links line up without rewriting a single response.
pub const PATH_PREFIX: &str = "/pma/";

/// Largest request body the panel forwards. The node's inbound RPC listener
/// accepts 2 MiB and the body travels base64-encoded inside JSON, so 1 MiB is
/// what fits with room to spare. phpMyAdmin's pool is configured with the
/// same upload limit, so its import page states the real ceiling instead of a
/// bigger one that would fail mid-upload.
pub const MAX_REQUEST_BODY: usize = 1024 * 1024;

/// Largest response body the agent returns. An export of a big table is the
/// only thing that gets near it; past this the agent answers 502 with a
/// sentence instead of buffering an unbounded body in two processes.
pub const MAX_RESPONSE_BODY: usize = 32 * 1024 * 1024;

/// Longest `path` (path + query) accepted. phpMyAdmin's GET URLs carry SQL in
/// the query string, so this is generous; it still bounds the request line.
pub const MAX_PATH_LEN: usize = 16 * 1024;

/// Browser request headers forwarded to phpMyAdmin. An allowlist, never a
/// denylist: the panel's own session cookie, `Authorization`, any
/// `X-Hyperion-*` header and every hop-by-hop header are dropped by not being
/// here. The credential headers the agent adds can therefore never be
/// supplied — or overridden — by the browser.
pub const FORWARDED_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "cache-control",
    "content-type",
    "if-modified-since",
    "if-none-match",
    "origin",
    "referer",
    "user-agent",
    "x-requested-with",
];

/// phpMyAdmin response headers passed back to the browser. Its own
/// `Content-Security-Policy` is replaced by the panel's (see hyperion-web).
pub const FORWARDED_RESPONSE_HEADERS: &[&str] = &[
    "cache-control",
    "content-disposition",
    "content-type",
    "etag",
    "expires",
    "last-modified",
    "location",
    "pragma",
    "set-cookie",
];

/// One browser request, as the panel ships it to the owning node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PmaHttpRequest {
    /// `GET`, `POST`, … — see [`method_allowed`].
    pub method: String,
    /// Path + query AFTER `/pma/<hosting-id>`, always starting with `/`
    /// (e.g. `/index.php?route=/sql`). See [`rest_path_ok`].
    pub path: String,
    /// Already filtered through [`FORWARDED_REQUEST_HEADERS`] + the panel's
    /// cookie stripping. The agent filters again — it never trusts the wire.
    pub headers: Vec<(String, String)>,
    /// Request body, base64 (standard alphabet, padded).
    pub body_b64: String,
    /// Absolute URL of this hosting's phpMyAdmin root as the BROWSER sees it,
    /// e.g. `https://panel.example.com:8447/pma/<id>/`. phpMyAdmin builds its
    /// redirects and cookie path from it. See [`base_url_ok`].
    pub base_url: String,
}

/// phpMyAdmin's answer, relayed back to the panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PmaHttpResponse {
    pub status: u16,
    /// Already filtered through [`FORWARDED_RESPONSE_HEADERS`].
    pub headers: Vec<(String, String)>,
    pub body_b64: String,
}

/// Methods phpMyAdmin actually uses. Anything else (TRACE, CONNECT, WebDAV
/// verbs) is refused before it reaches PHP.
pub fn method_allowed(m: &str) -> bool {
    matches!(m, "GET" | "HEAD" | "POST")
}

/// A hosting id as it may appear in the URL: the lowercase hyphenated UUID
/// form `HostingId` renders. Checked before the id is used for anything, so a
/// path can never smuggle a traversal or a domain selector into a lookup.
pub fn hosting_id_ok(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// The path + query forwarded to phpMyAdmin.
///
/// Printable ASCII only (a browser percent-encodes everything else), so no
/// CR/LF can split the request line the agent writes, and no `.`/`..`
/// segment, plain or percent-encoded — nginx would normalise one, but there
/// is no reason to send it one. A literal `..` inside the query string is
/// legitimate SQL, so the segment checks only look at the path part.
pub fn rest_path_ok(p: &str) -> bool {
    if !p.starts_with('/') || p.len() > MAX_PATH_LEN {
        return false;
    }
    if !p.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return false;
    }
    let path_part = p.split('?').next().unwrap_or("");
    // phpMyAdmin's own paths never percent-encode a dot, a slash or a
    // backslash, so an encoded one can only be an attempt to slip a segment
    // past this check and have nginx decode it afterwards.
    let lower = path_part.to_ascii_lowercase();
    if ["#", "\\", "%2e", "%2f", "%5c", "%00"]
        .iter()
        .any(|bad| lower.contains(bad))
    {
        return false;
    }
    !path_part.split('/').any(|seg| seg == ".." || seg == ".")
}

/// `https://<host[:port]>/pma/<hosting-id>/` and nothing else. The host part
/// comes from the browser's `Host` header, so it is validated here rather
/// than trusted: phpMyAdmin echoes it into `Location` headers.
pub fn base_url_ok(u: &str, hosting_id: &str) -> bool {
    let Some(rest) = u.strip_prefix("https://") else {
        return false;
    };
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if authority.is_empty()
        || authority.len() > 255
        || !authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return false;
    }
    path == format!("pma/{hosting_id}/")
}

/// Header value safe to write verbatim into an HTTP/1.x header block.
pub fn header_value_ok(v: &str) -> bool {
    v.len() <= 8 * 1024 && v.bytes().all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
}

/// Keep only the allowlisted request headers with sane values, lowercased.
/// `Cookie` is handled separately by the panel (it must drop its own session
/// cookie first) and passed through [`filter_cookie_header`].
pub fn filter_request_headers<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter_map(|(k, v)| {
            let k = k.to_ascii_lowercase();
            (FORWARDED_REQUEST_HEADERS.contains(&k.as_str()) && header_value_ok(v))
                .then(|| (k, v.to_string()))
        })
        .collect()
}

/// Keep only the allowlisted response headers with sane values, lowercased.
pub fn filter_response_headers<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter_map(|(k, v)| {
            let k = k.to_ascii_lowercase();
            (FORWARDED_RESPONSE_HEADERS.contains(&k.as_str()) && header_value_ok(v))
                .then(|| (k, v.to_string()))
        })
        .collect()
}

/// Rebuild a `Cookie` header with only phpMyAdmin's own cookies.
///
/// The browser sends EVERY cookie for the host, port-agnostic — including
/// the panel's session cookie. phpMyAdmin has no business seeing it, and a
/// phpMyAdmin bug that echoes cookies back would otherwise hand it out. Its
/// cookies all start with `pma` or `phpMyAdmin` (behind an optional
/// `__Secure-` prefix), so that is the allowlist.
/// Returns `None` when nothing is left.
pub fn filter_cookie_header<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let kept: Vec<&str> = values
        .into_iter()
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|kv| {
            let name = kv.split('=').next().unwrap_or("");
            // Over HTTPS phpMyAdmin prefixes its cookies with `__Secure-`
            // (`__Secure-phpMyAdmin_https`, `__Secure-pma_lang_https`).
            let bare = name
                .strip_prefix("__Secure-")
                .or_else(|| name.strip_prefix("__Host-"))
                .unwrap_or(name);
            bare.starts_with("pma") || bare.starts_with("phpMyAdmin")
        })
        .filter(|kv| header_value_ok(kv))
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "01920a3b-7c4d-7e8f-9a0b-1c2d3e4f5a6b";

    #[test]
    fn hosting_id_shape() {
        assert!(hosting_id_ok(ID));
        assert!(!hosting_id_ok("01920A3B-7C4D-7E8F-9A0B-1C2D3E4F5A6B"));
        assert!(!hosting_id_ok("example.com"));
        assert!(!hosting_id_ok("../../../../etc/passwd/aaaaaaaaaaaaaaa"));
        assert!(!hosting_id_ok(""));
    }

    #[test]
    fn rest_paths() {
        assert!(rest_path_ok("/"));
        assert!(rest_path_ok("/index.php?route=/sql&db=x"));
        assert!(rest_path_ok("/themes/pmahomme/img/logo.png"));
        // `..` in a query string is SQL, not traversal.
        assert!(rest_path_ok("/index.php?sql_query=SELECT%20'..'"));
        assert!(!rest_path_ok("index.php"));
        assert!(!rest_path_ok("/../setup/index.php"));
        assert!(!rest_path_ok("/js/%2e%2e/config.inc.php"));
        assert!(!rest_path_ok("/index.php\r\nX-Hyperion-Pma-User: x"));
        assert!(!rest_path_ok("/a b"));
        assert!(!rest_path_ok(&format!("/{}", "a".repeat(MAX_PATH_LEN))));
    }

    #[test]
    fn base_urls() {
        assert!(base_url_ok(
            &format!("https://panel.example.com:8447/pma/{ID}/"),
            ID
        ));
        assert!(base_url_ok(
            &format!("https://203.0.113.9:8447/pma/{ID}/"),
            ID
        ));
        assert!(base_url_ok(
            &format!("https://[2001:db8::1]:8447/pma/{ID}/"),
            ID
        ));
        assert!(!base_url_ok(
            &format!("http://panel.example.com/pma/{ID}/"),
            ID
        ));
        assert!(!base_url_ok(&format!("https://evil.com/x/pma/{ID}/"), ID));
        assert!(!base_url_ok(&format!("https://a\r\nb/pma/{ID}/"), ID));
        assert!(!base_url_ok(
            "https://panel.example.com/pma/01920a3b-7c4d-7e8f-9a0b-000000000000/",
            ID
        ));
    }

    #[test]
    fn request_headers_are_allowlisted() {
        let got = filter_request_headers([
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Authorization", "Basic Zm9vOmJhcg=="),
            ("X-Hyperion-Pma-User", "cm9vdA=="),
            ("Cookie", "hyperion_session=abc"),
            ("Connection", "keep-alive"),
            ("User-Agent", "bad\nvalue"),
        ]);
        assert_eq!(
            got,
            vec![(
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string()
            )]
        );
    }

    #[test]
    fn response_headers_are_allowlisted() {
        let got = filter_response_headers([
            (
                "Set-Cookie",
                "phpMyAdmin_https=x; path=/pma/a/; secure; HttpOnly",
            ),
            ("Content-Security-Policy", "default-src *"),
            ("X-Powered-By", "PHP/8.3"),
            ("Location", "https://h:8447/pma/a/index.php"),
        ]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "set-cookie");
        assert_eq!(got[1].0, "location");
    }

    #[test]
    fn panel_session_cookie_never_forwarded() {
        let got = filter_cookie_header([
            "hyperion_session=SECRET; pmaUser-1=x",
            "phpMyAdmin_https=abc; pma_lang=cs; other=1",
        ]);
        assert_eq!(
            got.as_deref(),
            Some("pmaUser-1=x; phpMyAdmin_https=abc; pma_lang=cs")
        );
        assert_eq!(filter_cookie_header(["hyperion_session=SECRET"]), None);
        // The names phpMyAdmin really sets over HTTPS.
        assert_eq!(
            filter_cookie_header([
                "__Secure-phpMyAdmin_https=a; hyperion_session=S; __Secure-pma_lang_https=en"
            ])
            .as_deref(),
            Some("__Secure-phpMyAdmin_https=a; __Secure-pma_lang_https=en")
        );
        assert_eq!(filter_cookie_header(["__Secure-hyperion=S"]), None);
    }

    #[test]
    fn methods() {
        assert!(method_allowed("GET"));
        assert!(method_allowed("POST"));
        assert!(!method_allowed("TRACE"));
        assert!(!method_allowed("get"));
    }
}
