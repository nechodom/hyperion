//! Fetch a site the way a visitor would, and say what is broken.
//!
//! # What this replaces
//!
//! "Check the main pages render, the navigation works, the links resolve and
//! the gallery displays" is on every care plan ever sold, and until now
//! nothing in hyperion did any of it. The uptime monitor fetches ONE url and
//! asks only whether it answered — a site whose every image 404s, whose menu
//! links all lead to a white page, and whose contact page died in last
//! week's update is 100 % "up" by that measure.
//!
//! So: walk the site's own sitemap, fetch each page, pull the links and
//! images out of the HTML, and check those too. It is not a person looking —
//! nothing here can tell you the layout is broken or the gallery looks wrong
//! — and the panel says so wherever this is shown. What it CAN do is find
//! the failures a person would have to click through fifty pages to notice.
//!
//! # Fetched from this node, not from DNS
//!
//! Every request is pinned to loopback with curl's `--resolve`, so what is
//! checked is the copy THIS server hosts. A site whose DNS still points at
//! the old host would otherwise be reported healthy on the strength of
//! somebody else's server, which is exactly backwards: the pages we can be
//! blamed for are the ones we serve. Certificate verification is off for the
//! same reason and only for that reason — the connection cannot leave the
//! machine, and a site still on its self-signed bootstrap certificate has to
//! be checkable.
//!
//! # It shows up in the customer's traffic
//!
//! These requests land in the site's access log like any other, and that log
//! is what the care report's traffic figures come from. The budget is
//! deliberately small — a few dozen requests a week against a site serving
//! thousands — and the user agent is distinctive, so the hits are greppable
//! if a figure ever looks off.

use crate::cmd;
use crate::AdapterError;
use std::collections::BTreeSet;

/// How this crawler identifies itself. Distinctive on purpose: it is what an
/// operator greps the access log for when a traffic figure looks wrong.
pub const USER_AGENT: &str = "Hyperion-SiteCheck/1 (+https://github.com/nechodom/hyperion)";

/// Marker curl writes after the body so one request yields both.
const METRICS_MARK: &str = "\nHYPERION-SITECHECK ";

/// Pages fetched in full. A care plan promises "the main pages", not a
/// crawl of a 10 000-post archive, and every page fetched is a request on
/// the customer's own traffic bill.
pub const MAX_PAGES: usize = 8;

/// Links and images checked per run, across all pages.
pub const MAX_LINKS: usize = 40;

/// Seconds before a fetch is given up on. Longer than any healthy page and
/// short enough that a hung site does not stall the whole tick.
const TIMEOUT_SECS: u32 = 20;

/// A page served slower than this is worth mentioning. Not a failure —
/// measured from inside the same machine, so it is the server's own
/// thinking time with no network in it, which is the part an operator can
/// actually do something about.
pub const SLOW_TTFB_MS: i64 = 1_500;

/// One fetched URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub url: String,
    /// 0 when curl could not complete the request at all.
    pub status: u16,
    /// Time to first byte, milliseconds — the server's own thinking time.
    pub ttfb_ms: i64,
    pub total_ms: i64,
    pub bytes: i64,
    /// Body, only for pages we asked to keep it.
    pub body: String,
}

impl Fetched {
    pub fn is_ok(&self) -> bool {
        (200..400).contains(&self.status)
    }
}

/// Build the curl config for one fetch.
///
/// `resolve_to` pins the hostname to an address so the request cannot leave
/// this machine; `keep_body` decides whether the response is returned or
/// discarded (a link check wants the status, not a megabyte of HTML).
fn fetch_config(url: &str, host: &str, resolve_to: &str, keep_body: bool) -> String {
    let mut cfg = String::new();
    cfg.push_str(&format!("url = \"{}\"\n", cmd::curl_config_quote(url)));
    for port in [443, 80] {
        cfg.push_str(&format!(
            "resolve = \"{}\"\n",
            cmd::curl_config_quote(&format!("{host}:{port}:{resolve_to}"))
        ));
    }
    // The connection cannot leave the machine (see the module docs), and a
    // site on its bootstrap certificate still has to be checkable.
    cfg.push_str("insecure\n");
    cfg.push_str("silent\n");
    cfg.push_str("show-error\n");
    cfg.push_str("location\n");
    cfg.push_str("max-redirs = 5\n");
    cfg.push_str(&format!("max-time = {TIMEOUT_SECS}\n"));
    cfg.push_str(&format!(
        "user-agent = \"{}\"\n",
        cmd::curl_config_quote(USER_AGENT)
    ));
    if !keep_body {
        // Status and timing only. `--head` would be wrong: plenty of sites
        // answer HEAD with 405 while serving GET perfectly, and reporting
        // that as a broken link is a false alarm on a working page.
        cfg.push_str("output = \"/dev/null\"\n");
    }
    cfg.push_str(&format!(
        "write-out = \"{}%{{http_code}} %{{time_starttransfer}} %{{time_total}} %{{size_download}}\"\n",
        cmd::curl_config_quote(METRICS_MARK)
    ));
    cfg
}

/// Split curl's output into the body and the trailing metrics line.
///
/// The marker is searched for from the END: a page that happens to contain
/// the marker text in its own HTML must not be able to truncate its body or
/// forge a status code.
pub fn split_metrics(url: &str, out: &str) -> Fetched {
    let mut f = Fetched {
        url: url.to_string(),
        status: 0,
        ttfb_ms: 0,
        total_ms: 0,
        bytes: 0,
        body: String::new(),
    };
    let Some(at) = out.rfind(METRICS_MARK) else {
        // curl produced no report — it never ran, or died mid-write. Status
        // stays 0, which every caller reads as "could not be fetched".
        f.body = out.to_string();
        return f;
    };
    f.body = out[..at].to_string();
    let fields: Vec<&str> = out[at + METRICS_MARK.len()..].split_whitespace().collect();
    if let Some(v) = fields.first() {
        f.status = v.parse().unwrap_or(0);
    }
    if let Some(v) = fields.get(1) {
        f.ttfb_ms = secs_to_ms(v);
    }
    if let Some(v) = fields.get(2) {
        f.total_ms = secs_to_ms(v);
    }
    if let Some(v) = fields.get(3) {
        f.bytes = v.parse().unwrap_or(0);
    }
    f
}

/// curl reports times as seconds with a fraction; a locale that uses a comma
/// is handled because the value is ours to parse, not the operator's.
fn secs_to_ms(v: &str) -> i64 {
    v.replace(',', ".").parse::<f64>().map(|s| (s * 1000.0).round() as i64).unwrap_or(0)
}

/// Fetch one URL through this node's own nginx.
pub async fn fetch(
    url: &str,
    host: &str,
    resolve_to: &str,
    keep_body: bool,
) -> Result<Fetched, AdapterError> {
    let cfg = fetch_config(url, host, resolve_to, keep_body);
    // Non-zero exit is an ANSWER here (a timeout, a refused connection), not
    // a transport bug: the report says which page failed and why.
    let (stdout, _stderr, _code) = cmd::curl_with_config_capture(&cfg).await?;
    Ok(split_metrics(url, &stdout))
}

/// URLs out of a sitemap, in document order.
///
/// Handles both a sitemap of pages and a sitemap INDEX pointing at more
/// sitemaps — WordPress 5.5+ serves the latter at `/wp-sitemap.xml`, so
/// taking `<loc>` values naively yields a list of sitemaps rather than a
/// list of pages. The caller follows one level.
pub fn sitemap_locs(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(open) = rest.find("<loc>") {
        let after = &rest[open + 5..];
        let Some(close) = after.find("</loc>") else {
            break;
        };
        let raw = after[..close].trim();
        if !raw.is_empty() {
            out.push(decode_entities(raw));
        }
        rest = &after[close + 6..];
    }
    out
}

/// True when this sitemap points at other sitemaps rather than at pages.
pub fn is_sitemap_index(xml: &str) -> bool {
    xml.contains("<sitemapindex")
}

/// The `&amp;` family, which sitemaps and HTML attributes both use.
fn decode_entities(v: &str) -> String {
    v.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#039;", "'")
        .replace("&#39;", "'")
}

/// A link found in a page, and what kind of thing it points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkKind {
    /// `<a href>` — navigation. A broken one is a dead end for a visitor.
    Nav,
    /// `<img src>` / `<source srcset>` — the gallery, in practice.
    Image,
    /// `<link href>` / `<script src>` — a missing stylesheet is why a site
    /// "looks broken" without anything being down.
    Asset,
}

impl LinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Nav => "link",
            LinkKind::Image => "image",
            LinkKind::Asset => "asset",
        }
    }
}

/// Pull the internal links out of one page.
///
/// Deliberately a scanner, not a parser: the alternative is an HTML5 tree
/// builder for the sake of four attributes, and a malformed page — which is
/// exactly the kind we are looking for — is what tree builders disagree
/// about. Anything not resolvable to this site is dropped: an external link
/// that 404s is somebody else's problem, and checking them would turn a
/// hosting panel into an outbound scanner.
pub fn extract_links(html: &str, base_url: &str, host: &str) -> Vec<(LinkKind, String)> {
    let mut out: Vec<(LinkKind, String)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (tag, attr, kind) in [
        ("<a ", "href", LinkKind::Nav),
        ("<img ", "src", LinkKind::Image),
        ("<source ", "src", LinkKind::Image),
        ("<link ", "href", LinkKind::Asset),
        ("<script ", "src", LinkKind::Asset),
    ] {
        let mut rest = html;
        while let Some(at) = find_ci(rest, tag) {
            let after = &rest[at + tag.len()..];
            let end = after.find('>').unwrap_or(after.len());
            let inside = &after[..end];
            if let Some(raw) = attr_value(inside, attr) {
                if let Some(abs) = resolve_url(&decode_entities(&raw), base_url, host) {
                    if seen.insert(abs.clone()) {
                        out.push((kind, abs));
                    }
                }
            }
            rest = &after[end.min(after.len())..];
        }
    }
    out
}

/// Case-insensitive `find` for ASCII needles (every tag name here is ASCII).
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.to_ascii_lowercase();
    h.find(needle)
}

/// `attr="value"` / `attr='value'` out of a tag's interior.
fn attr_value(tag_inside: &str, attr: &str) -> Option<String> {
    let lower = tag_inside.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(at) = lower[from..].find(attr) {
        let idx = from + at;
        // Must be a whole attribute name: `data-href` is not `href`, and
        // `srcset` is not `src`.
        let before_ok = idx == 0
            || !lower.as_bytes()[idx - 1].is_ascii_alphanumeric()
                && lower.as_bytes()[idx - 1] != b'-'
                && lower.as_bytes()[idx - 1] != b'_';
        let after = &tag_inside[idx + attr.len()..];
        let trimmed = after.trim_start();
        if before_ok && trimmed.starts_with('=') {
            let v = trimmed[1..].trim_start();
            let quote = v.chars().next()?;
            if quote == '"' || quote == '\'' {
                let end = v[1..].find(quote)?;
                return Some(v[1..1 + end].to_string());
            }
            // Unquoted: up to the next whitespace.
            let end = v.find(char::is_whitespace).unwrap_or(v.len());
            return Some(v[..end].to_string());
        }
        from = idx + attr.len();
    }
    None
}

/// Absolute URL on THIS site, or `None` for anything we will not follow.
///
/// Dropped: other hosts, `mailto:`/`tel:`/`javascript:`/`data:`, and bare
/// fragments. A fragment is the same page — following it would double every
/// in-page anchor into the request budget for no information at all.
pub fn resolve_url(raw: &str, base_url: &str, host: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    for scheme in ["mailto:", "tel:", "javascript:", "data:", "sms:", "ftp:"] {
        if lower.starts_with(scheme) {
            return None;
        }
    }
    let abs = if lower.starts_with("http://") || lower.starts_with("https://") {
        raw.to_string()
    } else if let Some(rest) = raw.strip_prefix("//") {
        format!("https://{rest}")
    } else if raw.starts_with('/') {
        format!("https://{host}{raw}")
    } else {
        // Relative to the current directory of `base_url`.
        let dir = base_url.rfind('/').map(|i| &base_url[..i + 1]).unwrap_or(base_url);
        format!("{dir}{raw}")
    };
    // Strip the fragment: two links differing only after '#' are one request.
    let abs = abs.split('#').next().unwrap_or(&abs).to_string();
    // Same site only.
    let after_scheme = abs.split("://").nth(1)?;
    let abs_host = after_scheme
        .split('/')
        .next()?
        .split(':')
        .next()?
        .to_ascii_lowercase();
    let want = host.to_ascii_lowercase();
    if abs_host == want || abs_host == format!("www.{want}") || want == format!("www.{abs_host}") {
        Some(abs)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_come_off_the_end_and_the_body_survives() {
        let out = format!("<html>hello</html>{METRICS_MARK}200 0.123 0.456 1234");
        let f = split_metrics("https://x/", &out);
        assert_eq!(f.body, "<html>hello</html>");
        assert_eq!(f.status, 200);
        assert_eq!(f.ttfb_ms, 123);
        assert_eq!(f.total_ms, 456);
        assert_eq!(f.bytes, 1234);
        assert!(f.is_ok());
    }

    /// A page containing the marker in its own HTML must not be able to
    /// truncate itself or claim a status it did not get.
    #[test]
    fn a_page_cannot_forge_its_own_metrics() {
        let hostile = format!("evil{METRICS_MARK}200 0 0 0");
        let out = format!("{hostile}{METRICS_MARK}404 0.1 0.2 9");
        let f = split_metrics("https://x/", &out);
        assert_eq!(f.status, 404);
        assert!(f.body.starts_with("evil"));
        assert!(!f.is_ok());
    }

    #[test]
    fn no_metrics_line_reads_as_not_fetched() {
        let f = split_metrics("https://x/", "curl: (7) failed to connect");
        assert_eq!(f.status, 0);
        assert!(!f.is_ok());
    }

    #[test]
    fn the_request_cannot_leave_the_machine() {
        let cfg = fetch_config("https://example.cz/a", "example.cz", "127.0.0.1", true);
        assert!(cfg.contains("resolve = \"example.cz:443:127.0.0.1\""));
        assert!(cfg.contains("resolve = \"example.cz:80:127.0.0.1\""));
        // A site on its bootstrap certificate still has to be checkable, and
        // the connection is pinned to loopback above.
        assert!(cfg.contains("insecure\n"));
        assert!(cfg.contains(USER_AGENT));
    }

    /// A hostile domain must not be able to close the quoted value and add
    /// directives of its own — `output = "/etc/cron.d/x"` as root.
    #[test]
    fn a_quote_in_a_url_cannot_inject_curl_directives() {
        let cfg = fetch_config("https://x/\"\noutput = \"/etc/passwd", "x", "127.0.0.1", true);
        assert!(!cfg.contains("\noutput = \"/etc/passwd"));
        assert!(cfg.contains("\\\"\\noutput"));
    }

    #[test]
    fn sitemap_locs_are_read_in_order() {
        let xml = r#"<?xml version="1.0"?><urlset>
            <url><loc>https://example.cz/</loc></url>
            <url><loc>https://example.cz/o-nas?a=1&amp;b=2</loc></url>
        </urlset>"#;
        assert!(!is_sitemap_index(xml));
        assert_eq!(
            sitemap_locs(xml),
            vec![
                "https://example.cz/".to_string(),
                "https://example.cz/o-nas?a=1&b=2".to_string()
            ]
        );
    }

    /// WordPress 5.5+ serves an INDEX at /wp-sitemap.xml. Taking its <loc>
    /// values as pages would "check" a list of sitemaps.
    #[test]
    fn a_sitemap_index_is_recognised() {
        let xml = r#"<sitemapindex><sitemap><loc>https://example.cz/wp-sitemap-posts-post-1.xml</loc></sitemap></sitemapindex>"#;
        assert!(is_sitemap_index(xml));
        assert_eq!(sitemap_locs(xml).len(), 1);
    }

    #[test]
    fn links_images_and_assets_are_all_found() {
        let html = r#"
            <a href="/o-nas">O nás</a>
            <a href='kontakt.html'>Kontakt</a>
            <IMG SRC="/wp-content/uploads/1.jpg">
            <link rel="stylesheet" href="/style.css">
            <script src="/app.js"></script>
        "#;
        let links = extract_links(html, "https://example.cz/blog/post", "example.cz");
        let urls: Vec<&str> = links.iter().map(|(_, u)| u.as_str()).collect();
        assert!(urls.contains(&"https://example.cz/o-nas"));
        // Relative to the current directory, not to the site root.
        assert!(urls.contains(&"https://example.cz/blog/kontakt.html"));
        assert!(urls.contains(&"https://example.cz/wp-content/uploads/1.jpg"));
        assert!(urls.contains(&"https://example.cz/style.css"));
        assert!(urls.contains(&"https://example.cz/app.js"));
        assert!(links.iter().any(|(k, _)| *k == LinkKind::Image));
        assert!(links.iter().any(|(k, _)| *k == LinkKind::Asset));
    }

    #[test]
    fn a_repeated_link_is_one_request() {
        let html = r#"<a href="/x">a</a><a href="/x">b</a><a href="/x#top">c</a>"#;
        let links = extract_links(html, "https://example.cz/", "example.cz");
        assert_eq!(links.len(), 1, "{links:?}");
    }

    #[test]
    fn other_sites_and_non_http_schemes_are_left_alone() {
        for raw in [
            "https://google.com/",
            "mailto:a@b.cz",
            "tel:+420",
            "javascript:void(0)",
            "data:image/png;base64,AAAA",
            "#top",
            "",
        ] {
            assert_eq!(
                resolve_url(raw, "https://example.cz/", "example.cz"),
                None,
                "{raw} should not be followed"
            );
        }
    }

    #[test]
    fn www_and_bare_are_the_same_site() {
        assert!(resolve_url("https://www.example.cz/a", "https://example.cz/", "example.cz").is_some());
        assert!(resolve_url("https://example.cz/a", "https://www.example.cz/", "www.example.cz").is_some());
    }

    #[test]
    fn a_protocol_relative_url_stays_on_the_site() {
        assert_eq!(
            resolve_url("//example.cz/a.png", "https://example.cz/", "example.cz").as_deref(),
            Some("https://example.cz/a.png")
        );
    }

    /// `data-href` is not `href`, and `srcset` is not `src`. Reading the
    /// wrong attribute produces a broken-link report about a link the page
    /// does not have.
    #[test]
    fn a_prefixed_attribute_is_not_the_attribute() {
        assert_eq!(attr_value(r#"data-href="/x""#, "href"), None);
        assert_eq!(attr_value(r#"srcset="/x 2x""#, "src"), None);
        assert_eq!(attr_value(r#"href="/x""#, "href").as_deref(), Some("/x"));
        assert_eq!(attr_value(r#"class="a" href='/y'"#, "href").as_deref(), Some("/y"));
        assert_eq!(attr_value(r#"href=/z rel=next"#, "href").as_deref(), Some("/z"));
    }

    #[test]
    fn entities_are_decoded_once() {
        assert_eq!(decode_entities("a&amp;b&#039;c"), "a&b'c");
    }
}
