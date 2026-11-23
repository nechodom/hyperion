//! Markup in, observations out.
//!
//! A scanner, not a parser, for the reason `sitecheck` gives: the input is
//! whatever a tenant (or whoever broke in) stored, a fragment as often as a
//! document, and a tree builder's opinion about malformed markup is not what is
//! being asked. What is asked: which external hosts does this markup load, frame
//! or link to, which of those links can a visitor not see, and does any script
//! in it match a rule.
//!
//! Every loop here moves forward through the input and nothing recurses, so a
//! hostile page costs time in proportion to its length and no more.

use super::rules;
use hyperion_types::content::{ContentKind, MAX_SNIPPET};

/// One thing seen in one fragment or page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub kind: ContentKind,
    /// A host, or `rule:hash`.
    pub key: String,
    pub snippet: String,
}

/// Open elements remembered, for "is an ancestor hidden". Deeper nesting than
/// this keeps the deepest answer it has.
const MAX_DEPTH: usize = 256;
/// A tag's attributes are read this far and no further.
const MAX_TAG: usize = 64 * 1024;
/// Observations from one fragment. Past this the fragment has said enough.
const MAX_SEEN: usize = 2_000;

const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Script types a browser doesn't run.
fn is_data_script(kind: &str) -> bool {
    let k = kind.trim().to_ascii_lowercase();
    k.contains("json") || k.contains("template") || k == "text/html" || k == "text/plain"
}

/// A host the way every comparison here spells it: lowercase, no `www.`, no
/// trailing dot.
pub fn normal_host(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h.strip_prefix("www.").unwrap_or(&h).to_string()
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.contains('.')
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// The host a URL points at, when it names one. A relative URL, a fragment, a
/// `mailto:` name none.
pub fn url_host(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !c.is_whitespace())
        .collect();
    let lower = cleaned.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .or_else(|| lower.strip_prefix("//"))?;
    let authority = rest.split(['/', '?', '#', '\\']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = normal_host(host_port.split(':').next()?);
    valid_host(&host).then_some(host)
}

/// Is this host the site itself, or under it?
fn is_own(host: &str, site_hosts: &[String]) -> bool {
    site_hosts.iter().any(|s| {
        let s = normal_host(s);
        host == s || host.ends_with(&format!(".{s}"))
    })
}

fn external_host(raw: &str, site_hosts: &[String]) -> Option<String> {
    url_host(raw).filter(|h| !is_own(h, site_hosts))
}

/// `&amp;`, `&quot;`, `&#104;`, `&#x68;` and friends, because an `href` spelled
/// in character references still goes where it says.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let end = tail[1..]
            .char_indices()
            .take(10)
            .find(|(_, c)| *c == ';')
            .map(|(i, _)| i + 1);
        let decoded = end.and_then(|e| {
            let name = &tail[1..e];
            match name {
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "colon" => Some(':'),
                "sol" => Some('/'),
                "period" => Some('.'),
                _ => {
                    let n = name.strip_prefix('#')?;
                    let code = match n.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => n.parse::<u32>().ok()?,
                    };
                    char::from_u32(code)
                }
            }
        });
        match (decoded, end) {
            (Some(c), Some(e)) => {
                out.push(c);
                rest = &tail[e + 1..];
            }
            _ => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A tag's markup, cut for showing.
fn snippet(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_SNIPPET)
        .collect();
    flat.trim().to_string()
}

/// Find `needle` (ASCII, lowercase) in `hay` from `from`, ignoring ASCII case.
fn find_ci(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len())
        .find(|&i| hay[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

struct Tag<'a> {
    name: String,
    attrs: Vec<(String, String)>,
    self_closing: bool,
    /// Offset just past the `>`.
    end: usize,
    raw: &'a str,
}

impl Tag<'_> {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Read the tag that starts at `html[start] == '<'`, when it is an opening tag.
fn read_tag(html: &str, start: usize) -> Option<Tag<'_>> {
    let bytes = html.as_bytes();
    let mut i = start + 1;
    let name_start = i;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b':')
    {
        i += 1;
    }
    if i == name_start || !bytes[name_start].is_ascii_alphabetic() {
        return None;
    }
    let name = html[name_start..i].to_ascii_lowercase();
    let limit = (start + MAX_TAG).min(bytes.len());
    let mut attrs = Vec::new();
    let mut self_closing = false;
    loop {
        while i < limit && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            self_closing = bytes[i] == b'/';
            i += 1;
        }
        if i >= limit {
            break;
        }
        if bytes[i] == b'>' {
            i += 1;
            break;
        }
        self_closing = false;
        let an = i;
        while i < limit
            && !bytes[i].is_ascii_whitespace()
            && !matches!(bytes[i], b'=' | b'>' | b'/')
        {
            i += 1;
        }
        if i == an {
            // A stray `=` or the like. Step over it or this never ends.
            i += 1;
            continue;
        }
        let attr_name = html[an..i].to_ascii_lowercase();
        while i < limit && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < limit && bytes[i] == b'=' {
            i += 1;
            while i < limit && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < limit && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                let vs = i + 1;
                let ve = bytes[vs..limit]
                    .iter()
                    .position(|b| *b == quote)
                    .map_or(limit, |p| vs + p);
                value = decode_entities(&html[vs..ve]);
                i = (ve + 1).min(limit);
            } else {
                let vs = i;
                while i < limit && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                value = decode_entities(&html[vs..i]);
            }
        }
        if attrs.len() < 64 {
            attrs.push((attr_name, value));
        }
    }
    // `limit` and every stop above sit on an ASCII byte or the end, but a cut at
    // MAX_TAG can land inside a character.
    let mut end = i.min(bytes.len());
    while !html.is_char_boundary(end) {
        end += 1;
    }
    Some(Tag {
        name,
        attrs,
        self_closing,
        end,
        raw: &html[start..end],
    })
}

struct Out<'a> {
    seen: Vec<Seen>,
    site_hosts: &'a [String],
    page: bool,
}

impl Out<'_> {
    fn push(&mut self, kind: ContentKind, key: String, text: &str) {
        if self.seen.len() < MAX_SEEN {
            self.seen.push(Seen {
                kind,
                key,
                snippet: snippet(text),
            });
        }
    }

    fn script_text(&mut self, script: &str, shown: &str) {
        for hit in rules::inline_hits(script) {
            let from = (0..=hit.at)
                .rev()
                .find(|i| script.is_char_boundary(*i))
                .unwrap_or(0);
            let text = if shown.is_empty() {
                &script[from..]
            } else {
                shown
            };
            self.push(
                ContentKind::InlineScript,
                rules::snippet_key(hit.rule, script, hit.at),
                text,
            );
        }
        for host in rules::loader_hosts(script) {
            let host = normal_host(&host);
            if !is_own(&host, self.site_hosts) {
                self.push(ContentKind::ScriptHost, host, shown_or(shown, script));
            }
        }
    }

    fn element(&mut self, tag: &Tag<'_>, hidden: bool) {
        for (name, value) in &tag.attrs {
            if name.starts_with("on") && name.len() > 2 && !value.is_empty() {
                self.script_text(value, tag.raw);
            }
        }
        match tag.name.as_str() {
            "a" | "area" => {
                let Some(href) = tag.attr("href") else { return };
                let trimmed = href.trim_start();
                if trimmed
                    .get(..11)
                    .is_some_and(|p| p.eq_ignore_ascii_case("javascript:"))
                {
                    self.script_text(&trimmed[11..], tag.raw);
                    return;
                }
                if let Some(host) = external_host(href, self.site_hosts) {
                    if hidden {
                        self.push(ContentKind::HiddenLink, host, tag.raw);
                    } else if self.page {
                        self.push(ContentKind::LinkHost, host, tag.raw);
                    }
                }
            }
            "script" => {
                let Some(src) = tag.attr("src") else { return };
                if src.trim_start().to_ascii_lowercase().starts_with("data:") {
                    // Code carried in the address itself, where no host names it.
                    self.push(
                        ContentKind::InlineScript,
                        rules::snippet_key("data-src", src, 0),
                        tag.raw,
                    );
                } else if let Some(host) = external_host(src, self.site_hosts) {
                    self.push(ContentKind::ScriptHost, host, tag.raw);
                }
            }
            "iframe" | "embed" | "frame" => {
                if let Some(host) = tag
                    .attr("src")
                    .and_then(|s| external_host(s, self.site_hosts))
                {
                    self.push(ContentKind::FrameHost, host, tag.raw);
                }
            }
            "object" => {
                if let Some(host) = tag
                    .attr("data")
                    .and_then(|s| external_host(s, self.site_hosts))
                {
                    self.push(ContentKind::FrameHost, host, tag.raw);
                }
            }
            "meta" => {
                let refresh = tag
                    .attr("http-equiv")
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("refresh"));
                if !refresh {
                    return;
                }
                let content = tag.attr("content").unwrap_or("");
                let lower = content.to_ascii_lowercase();
                let Some(at) = lower.find("url=") else { return };
                let target = content[at + 4..].trim().trim_matches(['"', '\'']);
                if let Some(host) = external_host(target, self.site_hosts) {
                    self.push(ContentKind::Redirect, host, tag.raw);
                }
            }
            "link" if self.page => {
                let canonical = tag
                    .attr("rel")
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("canonical"));
                if !canonical {
                    return;
                }
                if let Some(host) = tag
                    .attr("href")
                    .and_then(|s| external_host(s, self.site_hosts))
                {
                    self.push(ContentKind::Redirect, host, tag.raw);
                }
            }
            _ => {}
        }
    }
}

fn shown_or<'a>(shown: &'a str, script: &'a str) -> &'a str {
    if shown.is_empty() {
        script
    } else {
        shown
    }
}

/// What this markup loads, frames, links to and runs.
///
/// `site_hosts` are the site's own names; anything under them is not external.
/// `page` says the markup is a fetched page rather than stored content: only a
/// page reports its visible outbound links and its canonical, because stored
/// content is a fragment and a post is expected to link out.
pub fn extract(html: &str, site_hosts: &[String], page: bool) -> Vec<Seen> {
    let bytes = html.as_bytes();
    let mut out = Out {
        seen: Vec::new(),
        site_hosts,
        page,
    };
    // (name, hidden: this element or an ancestor is).
    let mut stack: Vec<(String, bool)> = Vec::new();
    let mut i = 0usize;
    while let Some(lt) = bytes[i..].iter().position(|b| *b == b'<').map(|p| i + p) {
        if bytes[lt..].starts_with(b"<!--") {
            i = find_ci(bytes, lt + 4, b"-->").map_or(bytes.len(), |e| e + 3);
            continue;
        }
        if bytes.get(lt + 1) == Some(&b'/') {
            let ns = lt + 2;
            let ne = bytes[ns..]
                .iter()
                .position(|b| !(b.is_ascii_alphanumeric() || *b == b'-' || *b == b':'))
                .map_or(bytes.len(), |p| ns + p);
            let name = html[ns..ne].to_ascii_lowercase();
            if let Some(at) = stack.iter().rposition(|(n, _)| *n == name) {
                stack.truncate(at);
            }
            i = ne;
            continue;
        }
        let Some(tag) = read_tag(html, lt) else {
            i = lt + 1;
            continue;
        };
        i = tag.end;
        let inherited = stack.last().is_some_and(|(_, h)| *h);
        let hidden = inherited
            || tag.attr("style").is_some_and(rules::hides)
            || tag.attrs.iter().any(|(n, _)| n == "hidden");
        out.element(&tag, hidden);
        match tag.name.as_str() {
            "script" | "style" => {
                let close: &[u8] = if tag.name == "script" {
                    b"</script"
                } else {
                    b"</style"
                };
                let body_end = find_ci(bytes, i, close).unwrap_or(bytes.len());
                if tag.name == "script"
                    && !tag.self_closing
                    && !tag.attr("type").is_some_and(is_data_script)
                {
                    let body = &html[i..body_end];
                    if !body.trim().is_empty() {
                        out.script_text(body, "");
                    }
                }
                i = body_end;
            }
            name if !tag.self_closing && !VOID.contains(&name) && stack.len() < MAX_DEPTH => {
                stack.push((tag.name.clone(), hidden));
            }
            _ => {}
        }
    }
    out.seen
}

/// Stored builder data is JSON, where `</script>` is spelled `<\/script>` and a
/// `<` may be `<`. Undo that much, so the markup inside reads as markup.
/// Not a JSON parser: a value cut short at the size cap must still be readable.
pub fn unescape_json(text: &str) -> String {
    if !text.contains('\\') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n' | 'r' | 't') => out.push(' '),
            Some('u') => {
                let hex: String = chars.clone().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(decoded) if hex.len() == 4 => {
                        out.push(decoded);
                        for _ in 0..4 {
                            chars.next();
                        }
                    }
                    _ => out.push_str("\\u"),
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site() -> Vec<String> {
        vec!["shop.example.com".to_string()]
    }

    fn kinds(html: &str, page: bool) -> Vec<(ContentKind, String)> {
        extract(html, &site(), page)
            .into_iter()
            .map(|s| (s.kind, s.key))
            .collect()
    }

    fn one(kind: ContentKind, key: &str) -> Vec<(ContentKind, String)> {
        vec![(kind, key.to_string())]
    }

    #[test]
    fn a_link_hidden_by_its_own_style_is_a_hidden_link() {
        let html =
            r#"<p>Text</p><a href="https://pills.spam.test/buy" style="display:none">cheap</a>"#;
        assert_eq!(
            kinds(html, false),
            one(ContentKind::HiddenLink, "pills.spam.test")
        );
    }

    #[test]
    fn links_inside_a_hidden_ancestor_are_hidden_links() {
        let html = r#"<div style="position:absolute; left:-9999px">
            <span><a href="http://www.casino.spam.test/">a</a></span>
            <a href='//loans.spam.test/x'>b</a>
        </div><a href="https://friend.example.org/">visible</a>"#;
        assert_eq!(
            kinds(html, false),
            vec![
                (ContentKind::HiddenLink, "casino.spam.test".to_string()),
                (ContentKind::HiddenLink, "loans.spam.test".to_string()),
            ]
        );
    }

    #[test]
    fn the_hidden_attribute_hides_too() {
        let html = r#"<div hidden><a href="https://spam.test/">x</a></div>"#;
        assert_eq!(
            kinds(html, false),
            one(ContentKind::HiddenLink, "spam.test")
        );
    }

    #[test]
    fn hiding_ends_where_the_hidden_element_closes() {
        let html = r#"<div style="display:none"><br><img src="x.png"></div>
            <a href="https://friend.example.org/">after</a>"#;
        assert_eq!(kinds(html, false), vec![]);
        assert_eq!(
            kinds(html, true),
            one(ContentKind::LinkHost, "friend.example.org")
        );
    }

    #[test]
    fn a_hidden_link_to_the_site_itself_is_nothing() {
        let html = r#"<div style="display:none">
            <a href="/cart">c</a><a href="https://shop.example.com/x">x</a>
            <a href="https://cdn.shop.example.com/x">y</a><a href="mailto:a@spam.test">m</a>
            <a href="\#top">t</a></div>"#;
        assert_eq!(kinds(html, true), vec![]);
    }

    #[test]
    fn a_visible_link_is_inventory_on_a_page_and_nothing_in_content() {
        let html = r#"<a href="https://friend.example.org/about">friend</a>"#;
        assert_eq!(kinds(html, false), vec![]);
        assert_eq!(
            kinds(html, true),
            one(ContentKind::LinkHost, "friend.example.org")
        );
    }

    #[test]
    fn an_href_spelled_in_character_references_still_counts() {
        let html = r#"<a style="font-size:0" href="&#104;ttps&#x3a;//spam.test&sol;x">.</a>"#;
        assert_eq!(
            kinds(html, false),
            one(ContentKind::HiddenLink, "spam.test")
        );
    }

    #[test]
    fn external_scripts_are_script_hosts_and_own_ones_are_not() {
        let html = r#"<script src="https://cdn.loader.test/a.js"></script>
            <SCRIPT SRC=//Other.Loader.test/b.js></SCRIPT>
            <script src="/wp-includes/js/jquery.js"></script>
            <script src="https://shop.example.com/x.js"></script>"#;
        assert_eq!(
            kinds(html, false),
            vec![
                (ContentKind::ScriptHost, "cdn.loader.test".to_string()),
                (ContentKind::ScriptHost, "other.loader.test".to_string()),
            ]
        );
    }

    #[test]
    fn frames_objects_and_embeds_are_frame_hosts() {
        let html = r#"<iframe src="https://video.example.net/embed/1" width="560"></iframe>
            <object data="https://flash.old.test/x.swf"></object>
            <embed src="https://embed.old.test/x">"#;
        assert_eq!(
            kinds(html, false),
            vec![
                (ContentKind::FrameHost, "video.example.net".to_string()),
                (ContentKind::FrameHost, "flash.old.test".to_string()),
                (ContentKind::FrameHost, "embed.old.test".to_string()),
            ]
        );
    }

    #[test]
    fn an_inline_script_that_matches_a_rule_is_an_inline_script() {
        let html = "<p>x</p><script>eval(atob('YWxlcnQoMSk='))</script>";
        let seen = extract(html, &site(), false);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].kind, ContentKind::InlineScript);
        assert!(seen[0].key.starts_with("decode-exec:"));
        assert!(seen[0].snippet.starts_with("eval(atob("));
    }

    #[test]
    fn script_bodies_are_not_read_as_markup() {
        let html =
            r#"<script>var t = '<a style="display:none" href="https://spam.test/">';</script>"#;
        assert_eq!(kinds(html, true), vec![]);
    }

    #[test]
    fn json_and_template_scripts_are_not_run_so_not_judged() {
        let blob = "QUJD".repeat(300);
        let html = format!(
            r#"<script type="application/ld+json">{{"x":"{blob}"}}</script>
               <script type="text/template">eval(atob('x'))</script>"#
        );
        assert_eq!(kinds(&html, true), vec![]);
    }

    #[test]
    fn the_analytics_loader_is_a_script_host() {
        let html = r"<script>(function(d){var j=d.createElement('script');
            j.src='https://tags.example.net/gtm.js';d.head.appendChild(j);})(document);</script>";
        assert_eq!(
            kinds(html, true),
            one(ContentKind::ScriptHost, "tags.example.net")
        );
    }

    #[test]
    fn handlers_and_javascript_urls_are_judged_as_scripts() {
        let html = r#"<img src="x.png" onerror="eval(atob('QQ=='))">
            <a href="javascript:eval(unescape('%61'))">x</a>
            <a href="javascript:void(0)" onclick="toggle()">menu</a>"#;
        let seen = extract(html, &site(), false);
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|s| s.kind == ContentKind::InlineScript));
        assert!(seen[0].snippet.starts_with("<img"));
    }

    #[test]
    fn a_script_carried_in_a_data_address_is_an_inline_script() {
        let html = r#"<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>"#;
        let seen = extract(html, &site(), false);
        assert_eq!(seen.len(), 1);
        assert!(seen[0].key.starts_with("data-src:"));
    }

    #[test]
    fn a_meta_refresh_elsewhere_is_a_redirect_and_canonical_only_on_a_page() {
        let refresh = r#"<meta http-equiv="Refresh" content="0; URL='https://away.spam.test/'">"#;
        assert_eq!(
            kinds(refresh, false),
            one(ContentKind::Redirect, "away.spam.test")
        );
        let canonical = r#"<link rel="canonical" href="https://other.spam.test/page">"#;
        assert_eq!(kinds(canonical, false), vec![]);
        assert_eq!(
            kinds(canonical, true),
            one(ContentKind::Redirect, "other.spam.test")
        );
        let own = r#"<link rel="canonical" href="https://www.shop.example.com/page">"#;
        assert_eq!(kinds(own, true), vec![]);
    }

    #[test]
    fn comments_are_skipped() {
        let html = r#"<!-- <script src="https://old.loader.test/a.js"></script> --><p>x</p>"#;
        assert_eq!(kinds(html, true), vec![]);
    }

    #[test]
    fn broken_markup_neither_panics_nor_hangs() {
        for html in [
            "<",
            "<a",
            "<a href=",
            "<a href=\"https://spam.test/",
            "</",
            "</div></div></div>",
            "<div style=\"display:none\"><div><div>",
            "<script>eval(atob('x'))",
            "<!-- never closed",
            "<a = = = >",
            "<é>",
            "<a href='https://spam.test/' style='display:none' é='ž'>ž</a>",
            "\u{feff}<p>\u{1F600}</p><",
        ] {
            let _ = extract(html, &site(), true);
        }
        let deep = "<div>".repeat(5_000) + "<a href=\"https://friend.example.org/\">x</a>";
        assert_eq!(
            kinds(&deep, true),
            one(ContentKind::LinkHost, "friend.example.org")
        );
        let huge_tag = format!(
            "<a title=\"{}\" href=\"https://spam.test/\">",
            "é".repeat(MAX_TAG)
        );
        let _ = extract(&huge_tag, &site(), true);
    }

    #[test]
    fn snippets_are_cut_and_flattened() {
        let html = format!(
            "<a style=\"display:none\"\n href=\"https://spam.test/{}\">x</a>",
            "a".repeat(500)
        );
        let seen = extract(&html, &site(), false);
        assert_eq!(seen[0].snippet.chars().count(), MAX_SNIPPET);
        assert!(!seen[0].snippet.contains('\n'));
    }

    #[test]
    fn url_hosts_are_normalised_and_odd_ones_refused() {
        assert_eq!(
            url_host("HTTPS://WWW.Example.NET:8443/x").as_deref(),
            Some("example.net")
        );
        assert_eq!(
            url_host(" ht\ttps://a.example.net").as_deref(),
            Some("a.example.net")
        );
        assert_eq!(
            url_host("https://user:pw@b.example.net/").as_deref(),
            Some("b.example.net")
        );
        assert_eq!(
            url_host("//c.example.net").as_deref(),
            Some("c.example.net")
        );
        assert_eq!(url_host("https://[::1]/"), None);
        assert_eq!(url_host("/relative"), None);
        assert_eq!(url_host("https://localhost/"), None);
        assert_eq!(url_host("ftp://d.example.net/"), None);
    }

    #[test]
    fn builder_json_reads_as_markup_once_unescaped() {
        let stored = r#"[{"widgetType":"html","settings":{"html":"<div style=\"display:none\"><a href=\"https:\/\/spam.test\/x\">x<\/a><\/div><script src=\"https:\/\/cdn.loader.test\/a.js\"><\/script>"}}]"#;
        let seen = kinds(&unescape_json(stored), false);
        assert_eq!(
            seen,
            vec![
                (ContentKind::HiddenLink, "spam.test".to_string()),
                (ContentKind::ScriptHost, "cdn.loader.test".to_string()),
            ]
        );
    }

    #[test]
    fn a_cut_escape_at_the_end_is_kept_not_panicked_on() {
        assert_eq!(unescape_json("abc\\"), "abc\\");
        assert_eq!(unescape_json("abc\\u00"), "abc\\u00");
        assert_eq!(unescape_json("a\\nb"), "a b");
    }
}
