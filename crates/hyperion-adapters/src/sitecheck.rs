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
/// Header lines follow the metrics line, one per header, because a
/// `cache-control` value contains spaces and commas and would wreck a
/// single space-separated report line.
const HEADER_MARK: &str = "HYPERION-HDR ";

/// Pages fetched in full. A care plan promises "the main pages", not a
/// crawl of a 10 000-post archive, and every page fetched is a request on
/// the customer's own traffic bill.
pub const MAX_PAGES: usize = 8;

/// Links and images checked per run, across all pages.
pub const MAX_LINKS: usize = 40;

/// Seconds before a fetch is given up on. Longer than any healthy page and
/// short enough that a hung site does not stall the whole tick.
const TIMEOUT_SECS: u32 = 20;

/// Bytes we are willing to pull down for one URL.
///
/// A timeout alone is not a limit: twenty seconds of loopback is gigabytes,
/// and the body is buffered in the agent's memory. A tenant serving an
/// endless stream from their own site would OOM the node that hosts them —
/// they do not even have to mean it, a runaway export script does the same.
/// Eight megabytes is far past any real page; beyond it the fetch is cut
/// short, which costs a truncated link list rather than a wrong verdict.
const MAX_BYTES: u64 = 8 * 1024 * 1024;

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
    /// `content-encoding` as sent, lowercased. Empty when the server sent
    /// none — which for HTML means it is shipping every byte uncompressed.
    pub content_encoding: String,
    /// `cache-control` as sent. Empty when the server sent none, which for
    /// a stylesheet or an image means every repeat visitor downloads it
    /// again.
    pub cache_control: String,
    /// `location` as sent, when this was a redirect. Curl does NOT follow it
    /// — the caller does, after putting the target through the same-site
    /// test, because `--resolve` pins only the site's own hostname.
    pub location: String,
    /// Body, only for pages we asked to keep it.
    pub body: String,
}

impl Fetched {
    /// Answered with something a visitor can use.
    ///
    /// A 3xx is NOT "ok" now that curl no longer follows redirects: treating
    /// one as a working page would report a site that only ever redirects as
    /// healthy without a single page having been read.
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// A redirect with somewhere to go.
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status) && !self.location.trim().is_empty()
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
    // Redirects are NOT followed by curl. `--resolve` pins only the site's
    // own hostname, so a redirect to another host leaves the pin behind and
    // curl reaches the real internet — or the node's own network. A site
    // that redirects (http to https, bare to www) is ordinary, so the hop is
    // followed by the CALLER, which re-runs the same-site test on the target
    // the way it does for every other URL.
    cfg.push_str("max-redirs = 0\n");
    // Belt and braces: even a Location we somehow followed could not be a
    // file:// or gopher:// URL.
    cfg.push_str("proto = \"=http,https\"\n");
    cfg.push_str("proto-redir = \"=http,https\"\n");
    // Ask for compression, the way a browser does. Without this the server
    // never gets the chance to compress, so "is compression on?" cannot be
    // answered — and `size_download` would be the uncompressed size either
    // way, which is the page weight a browser has to parse.
    cfg.push_str("compressed\n");
    cfg.push_str(&format!("max-time = {TIMEOUT_SECS}\n"));
    cfg.push_str(&format!("max-filesize = {MAX_BYTES}\n"));
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
    // `%header{...}` needs curl 7.84+ (Debian 12 ships 7.88). On anything
    // older it comes back unexpanded, which `split_metrics` reads as "not
    // reported" rather than as a header value.
    cfg.push_str(&format!(
        // ONE write-out: curl honours only the last one it is given, so a
        // second line would silently drop the first's fields.
        "write-out = \"{}%{{http_code}} %{{time_starttransfer}} %{{time_total}} %{{size_download}}\\n{}content-encoding: %header{{content-encoding}}\\n{}cache-control: %header{{cache-control}}\\n{}location: %header{{location}}\"\n",
        cmd::curl_config_quote(METRICS_MARK),
        HEADER_MARK,
        HEADER_MARK,
        HEADER_MARK
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
        content_encoding: String::new(),
        cache_control: String::new(),
        location: String::new(),
        body: String::new(),
    };
    let Some(at) = out.rfind(METRICS_MARK) else {
        // curl produced no report — it never ran, or died mid-write. Status
        // stays 0, which every caller reads as "could not be fetched".
        f.body = out.to_string();
        return f;
    };
    f.body = out[..at].to_string();
    let block = &out[at + METRICS_MARK.len()..];
    let mut lines = block.lines();
    let fields: Vec<&str> = lines.next().unwrap_or("").split_whitespace().collect();
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
    for line in lines {
        let Some(rest) = line.strip_prefix(HEADER_MARK) else {
            continue;
        };
        let Some((name, value)) = rest.split_once(':') else {
            continue;
        };
        let value = value.trim();
        // An old curl leaves `%header{...}` unexpanded. That is "not
        // reported", never a header value — reading it as one would have the
        // report claim a site sets a Cache-Control of "%header{...}".
        if value.is_empty() || value.contains("%header{") {
            continue;
        }
        match name.trim().to_ascii_lowercase().as_str() {
            "content-encoding" => f.content_encoding = value.to_ascii_lowercase(),
            "cache-control" => f.cache_control = value.to_string(),
            "location" => f.location = value.to_string(),
            _ => {}
        }
    }
    f
}

/// Does this `cache-control` let a browser reuse the file without asking?
///
/// `no-store` / `no-cache` / `max-age=0` all mean "come back every time",
/// which for a stylesheet or a logo is a request per visit per visitor. A
/// missing header entirely is the same answer, so an empty string is false.
pub fn caches_in_browser(cache_control: &str) -> bool {
    let cc = cache_control.to_ascii_lowercase();
    if cc.is_empty() || cc.contains("no-store") || cc.contains("no-cache") {
        return false;
    }
    let Some(at) = cc.find("max-age=") else {
        return false;
    };
    let rest = &cc[at + "max-age=".len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<i64>().map(|n| n > 0).unwrap_or(false)
}

/// curl reports times as seconds with a fraction; a locale that uses a comma
/// is handled because the value is ours to parse, not the operator's.
fn secs_to_ms(v: &str) -> i64 {
    v.replace(',', ".")
        .parse::<f64>()
        .map(|s| (s * 1000.0).round() as i64)
        .unwrap_or(0)
}

/// Redirect hops followed. Enough for the ordinary http→https→www chain,
/// short enough that a redirect loop is not a denial of service.
const MAX_HOPS: usize = 3;

/// Fetch one URL through this node's own nginx, following redirects ONLY
/// while they stay on the site.
///
/// The hop is taken here rather than by curl because `--resolve` pins the
/// site's hostname and nothing else: a `Location:` pointing at
/// `169.254.169.254` would leave the pin behind and let a tenant use the
/// crawler to reach the node's own network. Every hop goes back through
/// `resolve_url`, the same test every link on a page has to pass.
pub async fn fetch(
    url: &str,
    host: &str,
    resolve_to: &str,
    keep_body: bool,
) -> Result<Fetched, AdapterError> {
    let mut current = url.to_string();
    let mut last: Option<Fetched> = None;
    for _ in 0..=MAX_HOPS {
        let cfg = fetch_config(&current, host, resolve_to, keep_body);
        // Non-zero exit is an ANSWER here (a timeout, a refused connection),
        // not a transport bug: the report says which page failed and why.
        let (stdout, _stderr, _code) = cmd::curl_with_config_capture(&cfg).await?;
        let f = split_metrics(&current, &stdout);
        if !f.is_redirect() {
            return Ok(f);
        }
        let Some(next) = resolve_url(&f.location, &current, host) else {
            // Off-site, or a scheme we will not follow. Reported as the
            // redirect it is rather than chased.
            return Ok(f);
        };
        if next == current {
            return Ok(f);
        }
        current = next;
        last = Some(f);
    }
    // Ran out of hops: report the last redirect rather than pretending.
    Ok(last.unwrap_or_else(|| Fetched {
        url: url.to_string(),
        status: 0,
        ttfb_ms: 0,
        total_ms: 0,
        bytes: 0,
        content_encoding: String::new(),
        cache_control: String::new(),
        location: String::new(),
        body: String::new(),
    }))
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
    let scan = Scanner::new(html);
    for (tag, attr, kind) in [
        ("<a ", "href", LinkKind::Nav),
        ("<img ", "src", LinkKind::Image),
        ("<source ", "src", LinkKind::Image),
        ("<link ", "href", LinkKind::Asset),
        ("<script ", "src", LinkKind::Asset),
    ] {
        for at in scan.offsets_of(tag) {
            // A page with a million links is a page we stop reading. The
            // caller caps how many are FETCHED; this caps how many are held
            // in memory to decide that.
            if out.len() >= MAX_LINKS_PER_PAGE {
                return out;
            }
            let inside = scan.tag_interior(at, tag.len());
            if let Some(raw) = attr_value(inside, attr) {
                if let Some(abs) = resolve_url(&decode_entities(&raw), base_url, host) {
                    if seen.insert(abs.clone()) {
                        out.push((kind, abs));
                    }
                }
            }
        }
    }
    out
}

/// Links held in memory from ONE page while deciding what to fetch.
///
/// Generous — a real page has tens — and there only so that a page with a
/// hundred thousand anchors cannot make the agent allocate for all of them.
pub const MAX_LINKS_PER_PAGE: usize = 500;

/// Case-insensitive `find` for ASCII needles (every tag name here is ASCII).
///
/// `to_ascii_lowercase` only maps A-Z, so it preserves byte length even for
/// multi-byte UTF-8 — the returned offset is therefore valid in `haystack`
/// too. Every caller relies on that.
///
/// Allocates. Callers that scan a page tag by tag must NOT call this in a
/// loop over a shrinking slice: that is one copy of the remaining page per
/// tag found, which on a page with thousands of links is gigabytes of
/// churn. Use [`Scanner`] for those.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.to_ascii_lowercase();
    h.find(needle)
}

/// One lowercase copy of a page, scanned repeatedly.
///
/// Exists because the obvious loop — lowercase the rest of the page, find
/// the next tag, repeat — is quadratic in the page size, and the page is
/// supplied by the site being checked. A large page is not hostile input
/// and still made the crawler burn CPU proportional to length times tag
/// count.
struct Scanner<'a> {
    original: &'a str,
    lower: String,
}

impl<'a> Scanner<'a> {
    fn new(html: &'a str) -> Self {
        Self {
            original: html,
            lower: html.to_ascii_lowercase(),
        }
    }

    /// Byte offsets, in document order, where `needle` (already lowercase)
    /// starts. Offsets index BOTH strings — see `find_ci`.
    fn offsets_of(&self, needle: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let mut from = 0usize;
        while let Some(at) = self.lower[from..].find(needle) {
            let idx = from + at;
            out.push(idx);
            from = idx + needle.len();
        }
        out
    }

    /// The text between `<tag ` and the next `>`, as it appears in the
    /// ORIGINAL (attribute values are case-sensitive).
    fn tag_interior(&self, tag_start: usize, tag_len: usize) -> &'a str {
        let after = &self.original[tag_start + tag_len..];
        let end = after.find('>').unwrap_or(after.len());
        &after[..end]
    }
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
        let dir = base_url
            .rfind('/')
            .map(|i| &base_url[..i + 1])
            .unwrap_or(base_url);
        format!("{dir}{raw}")
    };
    // Strip the fragment: two links differing only after '#' are one request.
    let abs = abs.split('#').next().unwrap_or(&abs).to_string();
    // Same site only — and the authority has to be parsed properly to know
    // that. `split(':').next()` on `example.cz:80@169.254.169.254` yields
    // "example.cz", which passed this test while curl went to the metadata
    // service: the part before an `@` is USERINFO, not the host.
    let after_scheme = abs.split("://").nth(1)?;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    // A link on a site never legitimately carries credentials, and every
    // parser disagrees about them. Refused outright rather than parsed.
    if authority.contains('@') {
        return None;
    }
    let (host_part, port) = split_host_port(authority)?;
    // Only the two ports the fetch pins with `--resolve`. Any other port
    // would leave the pin behind and reach whatever is listening there —
    // which on a hosting node is every tenant's FPM socket and the agent
    // itself.
    if !matches!(port, None | Some(80) | Some(443)) {
        return None;
    }
    let abs_host = host_part.to_ascii_lowercase();
    let want = host.to_ascii_lowercase();
    if abs_host == want || abs_host == format!("www.{want}") || want == format!("www.{abs_host}") {
        Some(abs)
    } else {
        None
    }
}

/// Split an authority into host and optional port, honouring the `[::1]`
/// form so a bracketed IPv6 address is not chopped at its own colons.
fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => Some(p.parse().ok()?),
            Some(_) => return None,
            None if after.is_empty() => None,
            None => return None,
        };
        return Some((host, port));
    }
    match authority.split_once(':') {
        Some((h, p)) if !p.is_empty() => Some((h, Some(p.parse().ok()?))),
        // A trailing colon with no port is malformed.
        Some(_) => None,
        None => Some((authority, None)),
    }
}

/// What in a page's own HTML makes it slow or makes it jump about.
///
/// # Why this is not "Core Web Vitals"
///
/// Core Web Vitals are FIELD measurements: Google's numbers come from real
/// visitors, on their own phones and their own networks. A number produced
/// here — one fetch, over loopback, on server hardware with no network in
/// the way — would be a different measurement wearing the same name, and it
/// would flatter every site we host. That is the same lie the care report
/// refuses to tell about uptime, and it is refused here for the same reason.
///
/// What IS honest is the causes, because they are in the HTML and they are
/// what an operator would change anyway:
///
/// * a script in `<head>` with neither `defer` nor `async` stops the parser
///   dead until it has downloaded and run — the usual reason a page is blank
///   for a second;
/// * an `<img>` with no width and height reserves no space, so everything
///   below it jumps when the image arrives. That is Cumulative Layout Shift,
///   in one sentence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PageWeight {
    /// `<script src>` in `<head>` without `defer` or `async`.
    pub blocking_scripts: usize,
    /// `<img>` tags missing a width or a height attribute.
    pub unsized_images: usize,
    /// `<img>` tags seen at all, so the count above has a denominator.
    pub images: usize,
}

/// Analyse one page's HTML.
pub fn page_weight(html: &str) -> PageWeight {
    let mut w = PageWeight::default();
    // Only `<head>` blocks rendering. A script at the end of `<body>` is the
    // recommended shape and must not be reported as a problem.
    let head_end = find_ci(html, "</head>").unwrap_or(html.len());
    let head = &html[..head_end];

    let head_scan = Scanner::new(head);
    for at in head_scan.offsets_of("<script ") {
        let inside = head_scan.tag_interior(at, "<script ".len());
        let lower = inside.to_ascii_lowercase();
        // Only an external script blocks on the network. An inline one is
        // already downloaded by the time the parser reaches it.
        if attr_value(inside, "src").is_some()
            && !has_bare_attr(&lower, "defer")
            && !has_bare_attr(&lower, "async")
            // A module is deferred by definition.
            && attr_value(inside, "type").map(|t| t.to_ascii_lowercase()) != Some("module".into())
        {
            w.blocking_scripts += 1;
        }
    }

    let body_scan = Scanner::new(html);
    for at in body_scan.offsets_of("<img ") {
        let inside = body_scan.tag_interior(at, "<img ".len());
        w.images += 1;
        // BOTH are needed: the browser reserves space from the ratio, so one
        // without the other reserves nothing.
        let sized = attr_value(inside, "width").is_some_and(|v| !v.trim().is_empty())
            && attr_value(inside, "height").is_some_and(|v| !v.trim().is_empty());
        if !sized {
            w.unsized_images += 1;
        }
    }
    w
}

/// Is `name` present as a valueless attribute (`defer`, `async`)?
///
/// Whole-word, so `data-async` is not `async` — the same trap `attr_value`
/// guards against.
fn has_bare_attr(tag_inside_lower: &str, name: &str) -> bool {
    let bytes = tag_inside_lower.as_bytes();
    let mut from = 0usize;
    while let Some(at) = tag_inside_lower[from..].find(name) {
        let idx = from + at;
        let before_ok = idx == 0 || !is_attr_char(bytes[idx - 1]);
        let after_idx = idx + name.len();
        let after_ok = after_idx >= bytes.len() || !is_attr_char(bytes[after_idx]);
        if before_ok && after_ok {
            return true;
        }
        from = idx + name.len();
    }
    false
}

fn is_attr_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
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
        let cfg = fetch_config(
            "https://x/\"\noutput = \"/etc/passwd",
            "x",
            "127.0.0.1",
            true,
        );
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
        assert!(resolve_url(
            "https://www.example.cz/a",
            "https://example.cz/",
            "example.cz"
        )
        .is_some());
        assert!(resolve_url(
            "https://example.cz/a",
            "https://www.example.cz/",
            "www.example.cz"
        )
        .is_some());
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
        assert_eq!(
            attr_value(r#"class="a" href='/y'"#, "href").as_deref(),
            Some("/y")
        );
        assert_eq!(
            attr_value(r#"href=/z rel=next"#, "href").as_deref(),
            Some("/z")
        );
    }

    #[test]
    fn entities_are_decoded_once() {
        assert_eq!(decode_entities("a&amp;b&#039;c"), "a&b'c");
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn compression_is_requested_the_way_a_browser_does() {
        let cfg = fetch_config("https://example.cz/", "example.cz", "127.0.0.1", true);
        assert!(cfg.contains("compressed\n"));
        assert!(cfg.contains("%header{content-encoding}"));
        assert!(cfg.contains("%header{cache-control}"));
    }

    #[test]
    fn headers_are_read_off_their_own_lines() {
        let out = format!(
            "<html>x</html>{METRICS_MARK}200 0.1 0.2 500\n\
             {HEADER_MARK}content-encoding: GZIP\n\
             {HEADER_MARK}cache-control: public, max-age=3600"
        );
        let f = split_metrics("https://x/", &out);
        assert_eq!(f.body, "<html>x</html>");
        assert_eq!(f.status, 200);
        assert_eq!(f.content_encoding, "gzip");
        // A value with a comma and a space would have wrecked a single
        // space-separated report line.
        assert_eq!(f.cache_control, "public, max-age=3600");
    }

    /// curl before 7.84 has no `%header{}` and leaves it literal. Reading
    /// that as a value would make the report claim the site sets a
    /// Cache-Control of "%header{cache-control}".
    #[test]
    fn an_old_curl_reports_nothing_rather_than_the_literal() {
        let out = format!(
            "body{METRICS_MARK}200 0.1 0.2 5\n\
             {HEADER_MARK}content-encoding: %header{{content-encoding}}\n\
             {HEADER_MARK}cache-control: %header{{cache-control}}"
        );
        let f = split_metrics("https://x/", &out);
        assert_eq!(f.status, 200);
        assert!(f.content_encoding.is_empty());
        assert!(f.cache_control.is_empty());
    }

    #[test]
    fn a_server_that_sent_no_headers_reports_none() {
        let out = format!("body{METRICS_MARK}200 0.1 0.2 5");
        let f = split_metrics("https://x/", &out);
        assert!(f.content_encoding.is_empty());
        assert!(f.cache_control.is_empty());
    }

    #[test]
    fn browser_caching_needs_a_real_max_age() {
        assert!(caches_in_browser("public, max-age=31536000, immutable"));
        assert!(caches_in_browser("max-age=60"));
        // Every one of these means "ask me again every time".
        assert!(!caches_in_browser(""));
        assert!(!caches_in_browser("no-store"));
        assert!(!caches_in_browser("no-cache"));
        assert!(!caches_in_browser("public, max-age=0"));
        assert!(!caches_in_browser("public"));
        // `no-cache` wins even beside a max-age, which is what it means.
        assert!(!caches_in_browser("no-cache, max-age=600"));
    }
}

#[cfg(test)]
mod weight_tests {
    use super::*;

    #[test]
    fn a_blocking_script_in_head_is_counted() {
        let html = r#"<html><head>
            <script src="/a.js"></script>
            </head><body></body></html>"#;
        assert_eq!(page_weight(html).blocking_scripts, 1);
    }

    /// The recommended shapes must not be reported as problems, or the card
    /// tells an operator to fix a page that is already right.
    #[test]
    fn deferred_async_module_and_inline_scripts_are_fine() {
        for tag in [
            r#"<script src="/a.js" defer></script>"#,
            r#"<script src="/a.js" async></script>"#,
            r#"<script src="/a.js" type="module"></script>"#,
            r#"<script>var a = 1;</script>"#,
        ] {
            let html = format!("<html><head>{tag}</head></html>");
            assert_eq!(page_weight(&html).blocking_scripts, 0, "{tag}");
        }
    }

    /// `data-async` is not `async`. Reading it as one would silently excuse
    /// a script that really does block.
    #[test]
    fn a_prefixed_attribute_does_not_count_as_defer_or_async() {
        let html = r#"<html><head><script src="/a.js" data-async="1"></script></head></html>"#;
        assert_eq!(page_weight(html).blocking_scripts, 1);
    }

    /// A script at the end of `<body>` is the shape everyone is told to
    /// use — it does not block rendering and is not a finding.
    #[test]
    fn a_script_after_head_does_not_block() {
        let html = r#"<html><head></head><body><script src="/a.js"></script></body></html>"#;
        assert_eq!(page_weight(html).blocking_scripts, 0);
    }

    #[test]
    fn images_need_both_dimensions_to_reserve_space() {
        let html = r#"
            <img src="/a.jpg" width="800" height="600">
            <img src="/b.jpg" width="800">
            <img src="/c.jpg">
        "#;
        let w = page_weight(html);
        assert_eq!(w.images, 3);
        // One with only a width reserves nothing, so it shifts the page too.
        assert_eq!(w.unsized_images, 2);
    }

    #[test]
    fn an_empty_dimension_is_not_a_dimension() {
        let html = r#"<img src="/a.jpg" width="" height="600">"#;
        assert_eq!(page_weight(html).unsized_images, 1);
    }

    #[test]
    fn a_page_with_no_head_still_parses() {
        let w = page_weight("<img src=/a.jpg>");
        assert_eq!(w.images, 1);
        assert_eq!(w.unsized_images, 1);
        assert_eq!(w.blocking_scripts, 0);
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::*;

    /// The one that got through review. `split(':').next()` on
    /// `example.cz:80@169.254.169.254` yields "example.cz" — userinfo read
    /// as the host — so the URL passed the same-site test while curl went to
    /// the cloud metadata service, which `--resolve` does not pin.
    #[test]
    fn userinfo_cannot_impersonate_the_host() {
        for raw in [
            "https://example.cz:80@169.254.169.254/latest/meta-data/",
            "https://example.cz@169.254.169.254/",
            "https://example.cz:443@127.0.0.1:9443/",
            "http://user:pass@example.cz/",
        ] {
            assert_eq!(
                resolve_url(raw, "https://example.cz/", "example.cz"),
                None,
                "{raw} must not pass the same-site test"
            );
        }
    }

    /// `--resolve` pins ports 80 and 443 and nothing else, so any other port
    /// leaves the pin behind. On a hosting node that reaches every tenant's
    /// FPM socket and the agent's own RPC.
    #[test]
    fn only_the_pinned_ports_are_followed() {
        assert!(resolve_url(
            "https://example.cz:443/a",
            "https://example.cz/",
            "example.cz"
        )
        .is_some());
        assert!(resolve_url(
            "http://example.cz:80/a",
            "https://example.cz/",
            "example.cz"
        )
        .is_some());
        assert!(resolve_url("https://example.cz/a", "https://example.cz/", "example.cz").is_some());
        for bad in [
            "https://example.cz:9443/a",
            "http://example.cz:8080/a",
            "https://example.cz:22/",
        ] {
            assert_eq!(
                resolve_url(bad, "https://example.cz/", "example.cz"),
                None,
                "{bad} is not a pinned port"
            );
        }
    }

    #[test]
    fn a_bracketed_ipv6_authority_is_parsed_not_chopped() {
        assert_eq!(split_host_port("[::1]"), Some(("::1", None)));
        assert_eq!(split_host_port("[::1]:443"), Some(("::1", Some(443))));
        assert_eq!(
            split_host_port("example.cz:8080"),
            Some(("example.cz", Some(8080)))
        );
        assert_eq!(split_host_port("example.cz"), Some(("example.cz", None)));
        // Malformed authorities are refused rather than guessed at.
        assert_eq!(split_host_port("example.cz:"), None);
        assert_eq!(split_host_port(""), None);
    }

    /// curl must not chase a Location itself: it would leave the pin behind.
    /// The hop is taken by `fetch`, which re-runs the same-site test.
    #[test]
    fn curl_is_told_not_to_follow_redirects_or_odd_schemes() {
        let cfg = fetch_config("https://example.cz/", "example.cz", "127.0.0.1", true);
        assert!(cfg.contains("max-redirs = 0"));
        assert!(
            !cfg.contains("\nlocation\n"),
            "curl would follow the redirect itself"
        );
        assert!(cfg.contains("proto = \"=http,https\""));
        assert!(cfg.contains("proto-redir = \"=http,https\""));
        // One write-out only — curl honours the last and silently drops the rest.
        assert_eq!(cfg.matches("write-out").count(), 1);
        assert!(cfg.contains("%header{location}"));
    }

    /// A 3xx is not a working page now that we do not follow them blindly;
    /// reporting one as ok would grade a site that only redirects as healthy.
    #[test]
    fn a_redirect_is_not_a_working_page() {
        let f = split_metrics(
            "https://example.cz/",
            &format!("{METRICS_MARK}301 0.1 0.2 0\n{HEADER_MARK}location: https://example.cz/new"),
        );
        assert!(!f.is_ok());
        assert!(f.is_redirect());
        assert_eq!(f.location, "https://example.cz/new");
    }

    /// A redirect the crawler will not chase must still not read as ok.
    #[test]
    fn an_offsite_redirect_target_is_refused_by_the_same_test() {
        assert_eq!(
            resolve_url(
                "https://169.254.169.254/",
                "https://example.cz/",
                "example.cz"
            ),
            None
        );
        assert_eq!(
            resolve_url(
                "http://localhost:9443/",
                "https://example.cz/",
                "example.cz"
            ),
            None
        );
    }
}
