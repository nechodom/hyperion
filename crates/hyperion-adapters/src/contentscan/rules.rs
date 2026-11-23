//! What counts as hidden, and what counts as a script nobody should have written.
//!
//! Compiled in and versioned, like the file scanner's rules. Everything here
//! reads tenant text and nothing else: a string in, a verdict out.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// Bump when a rule changes what it matches.
pub const RULE_PACK: u32 = 1;

/// An offset this far off-screen (in px) is hiding, not layout.
const OFFSCREEN_PX: f64 = -500.0;
/// The same in em/rem, where `-999em` is the usual spelling.
const OFFSCREEN_EM: f64 = -50.0;

/// The number a CSS value starts with, and what follows it.
fn css_number(value: &str) -> Option<(f64, &str)> {
    let v = value.trim();
    let end = v
        .char_indices()
        .find(|(i, c)| !(c.is_ascii_digit() || *c == '.' || (*i == 0 && (*c == '-' || *c == '+'))))
        .map_or(v.len(), |(i, _)| i);
    let n = v[..end].parse::<f64>().ok()?;
    Some((n, v[end..].trim()))
}

fn far_off(value: &str) -> bool {
    match css_number(value) {
        Some((n, unit)) if unit.starts_with("em") || unit.starts_with("rem") => n <= OFFSCREEN_EM,
        Some((n, _)) => n <= OFFSCREEN_PX,
        None => false,
    }
}

fn is_zero(value: &str) -> bool {
    css_number(value).is_some_and(|(n, _)| n == 0.0)
}

fn at_most_one_px(value: &str) -> bool {
    css_number(value).is_some_and(|(n, unit)| {
        (0.0..=1.0).contains(&n) && (unit.is_empty() || unit.starts_with("px"))
    })
}

/// Does this inline style take its element off the page a visitor sees?
///
/// `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, a box of at
/// most one pixel that clips its content, or an offset or text indent far off
/// screen. Nothing else: a style that merely looks odd isn't hiding.
pub fn hides(style: &str) -> bool {
    let lower = style.to_ascii_lowercase();
    let mut tiny_box = false;
    let mut clips = false;
    for decl in lower.split(';') {
        let Some((prop, value)) = decl.split_once(':') else {
            continue;
        };
        let prop = prop.trim();
        let value = value.replace("!important", "");
        let value = value.trim();
        match prop {
            "display" if value == "none" => return true,
            "visibility" if value == "hidden" || value == "collapse" => return true,
            "opacity" | "font-size" if is_zero(value) => return true,
            "left" | "top" | "margin-left" | "margin-top" | "text-indent" if far_off(value) => {
                return true
            }
            "width" | "height" | "max-width" | "max-height" if at_most_one_px(value) => {
                tiny_box = true;
            }
            "overflow" | "overflow-x" | "overflow-y" if value.starts_with("hidden") => clips = true,
            _ => {}
        }
    }
    tiny_box && clips
}

struct Rule {
    id: &'static str,
    re: Regex,
}

// A pattern that doesn't compile is a bug every test in this file would hit.
#[allow(clippy::expect_used)]
fn rule(id: &'static str, pattern: &str) -> Rule {
    Rule {
        id,
        re: Regex::new(pattern).expect("content rule compiles"),
    }
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let decoder = r"(?:atob|unescape|decodeURIComponent|String\s*\.\s*fromCharCode)";
    vec![
        // A decoder's output handed straight to something that runs it.
        rule(
            "decode-exec",
            &format!(
                r"(?i)\b(?:eval|Function|setTimeout|setInterval|execScript)\s*\(\s*{decoder}\s*\("
            ),
        ),
        rule(
            "write-decode",
            &format!(r"(?i)document\s*\.\s*write(?:ln)?\s*\(\s*{decoder}\s*\("),
        ),
        // Text spelled out number by number, or byte by byte.
        rule(
            "charcode-chain",
            r"(?i)fromCharCode\s*\((?:\s*(?:0x[0-9a-f]+|\d+)\s*,){20,}|(?:\\x[0-9a-f]{2}){40,}",
        ),
        rule(
            "packer",
            r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,",
        ),
        // A quoted run of base64 over about 1 kB. A `data:` URI doesn't match:
        // its quote is followed by `data:`, not by the run.
        rule("encoded-literal", r#"["'`][A-Za-z0-9+/]{1024,}={0,2}["'`]"#),
    ]
});

/// One rule's objection to a script, and where in the text it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InlineHit {
    pub rule: &'static str,
    pub at: usize,
}

/// Every rule this script (or handler, or `javascript:` URL) matches.
pub fn inline_hits(script: &str) -> Vec<InlineHit> {
    RULES
        .iter()
        .filter_map(|r| {
            r.re.find(script).map(|m| InlineHit {
                rule: r.id,
                at: m.start(),
            })
        })
        .collect()
}

#[allow(clippy::expect_used)]
static CREATES_SCRIPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)createElement\s*\(\s*["'`]script["'`]"#).expect("regex"));
#[allow(clippy::expect_used)]
static URL_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)["'`](?:https?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:[/:?"'`])"#)
        .expect("regex")
});

/// The hosts a script that builds a `<script>` element names in its own text.
///
/// The ordinary analytics snippet does exactly this, so it is not an objection:
/// each host is a script host like any `<script src>`, for the baseline to know.
/// A loader that hides its host behind a decoder is what [`inline_hits`] is for.
pub fn loader_hosts(script: &str) -> Vec<String> {
    if !CREATES_SCRIPT.is_match(script) {
        return Vec::new();
    }
    let mut hosts: Vec<String> = URL_LITERAL
        .captures_iter(script)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_ascii_lowercase()))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// How much of a script, from the match on, names it.
const KEY_WINDOW: usize = 256;

/// A key for one rule hit that survives the things a page changes on every
/// request: whitespace, and numbers (timestamps, cache busters, counters).
///
/// Taken from the match onward rather than from the whole script, so text ahead
/// of the payload (a nonce, a config object) doesn't make it a new item each
/// sweep.
pub fn snippet_key(rule: &str, text: &str, at: usize) -> String {
    let from = (0..=at.min(text.len()))
        .rev()
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(0);
    let mut normal = String::with_capacity(KEY_WINDOW);
    let mut last_digit = false;
    for c in text[from..].chars().filter(|c| !c.is_whitespace()) {
        if normal.len() >= KEY_WINDOW {
            break;
        }
        if c.is_ascii_digit() {
            if !last_digit {
                normal.push('0');
            }
            last_digit = true;
        } else {
            normal.push(c);
            last_digit = false;
        }
    }
    let digest = Sha256::digest(normal.as_bytes());
    format!("{rule}:{}", hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_declared_way_of_hiding_hides() {
        for style in [
            "display:none",
            "DISPLAY : NONE !important",
            "color:red; visibility:hidden",
            "opacity:0",
            "opacity: 0.0",
            "font-size:0px",
            "position:absolute; left:-9999px",
            "position:absolute;top:-5000px",
            "text-indent:-999em",
            "margin-left: -2000px",
            "height:1px;width:1px;overflow:hidden",
            "overflow:hidden; height:0",
        ] {
            assert!(hides(style), "{style}");
        }
    }

    #[test]
    fn ordinary_styles_do_not_hide() {
        for style in [
            "",
            "color:#fff",
            "display:block",
            "opacity:0.5",
            "font-size:10px",
            "left:-10px",
            "text-indent:-1em",
            "overflow:hidden",
            "height:1px",
            "height:100px; overflow:hidden",
            "margin-left:auto",
            "display",
        ] {
            assert!(!hides(style), "{style}");
        }
    }

    fn ids(script: &str) -> Vec<&'static str> {
        inline_hits(script).into_iter().map(|h| h.rule).collect()
    }

    #[test]
    fn decoders_feeding_execution_are_hits() {
        assert_eq!(ids("eval(atob('YWxlcnQoMSk='))"), ["decode-exec"]);
        assert_eq!(ids("new Function( atob(x) )()"), ["decode-exec"]);
        assert_eq!(ids("setTimeout(unescape('%61'),1)"), ["decode-exec"]);
        assert_eq!(
            ids("document.write(unescape('%3Cscript%3E'))"),
            ["write-decode"]
        );
        assert_eq!(
            ids("document.writeln(String.fromCharCode(60,115))"),
            ["write-decode"]
        );
        assert_eq!(
            ids("eval(function(p,a,c,k,e,d){return p}('x',1,1,'a'.split('|')))"),
            ["packer"]
        );
    }

    #[test]
    fn a_long_run_of_character_codes_is_a_hit() {
        let codes = (0..30)
            .map(|n| (97 + n % 20).to_string())
            .collect::<Vec<_>>();
        let script = format!("var s=String.fromCharCode({});", codes.join(","));
        assert_eq!(ids(&script), ["charcode-chain"]);
        assert!(ids("String.fromCharCode(60,115,99)").is_empty());
        let hexed = "\\x61".repeat(40);
        assert_eq!(ids(&format!("var s='{hexed}';")), ["charcode-chain"]);
    }

    #[test]
    fn a_large_encoded_literal_is_a_hit_and_a_data_uri_is_not() {
        let blob = "QUJD".repeat(300);
        assert_eq!(ids(&format!("var p=\"{blob}\";")), ["encoded-literal"]);
        assert!(ids(&format!("var i=\"data:image/png;base64,{blob}\";")).is_empty());
        let short = "QUJD".repeat(100);
        assert!(ids(&format!("var p=\"{short}\";")).is_empty());
    }

    #[test]
    fn ordinary_scripts_are_not_hits() {
        for script in [
            "window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);}",
            "var x = atob(token); console.log(x);",
            "jQuery(function($){ $('.menu').hide(); });",
            "eval('1+1')",
        ] {
            assert!(ids(script).is_empty(), "{script}");
        }
    }

    #[test]
    fn the_analytics_loader_names_its_host_and_is_not_a_hit() {
        let script = r"(function(w,d,s){var f=d.getElementsByTagName(s)[0],
            j=d.createElement('script');j.async=true;
            j.src='https://tags.example.net/gtm.js?id=X';f.parentNode.insertBefore(j,f);
        })(window,document,'script');";
        assert!(ids(script).is_empty());
        assert_eq!(loader_hosts(script), ["tags.example.net"]);
    }

    #[test]
    fn urls_in_a_script_that_builds_nothing_are_not_loader_hosts() {
        assert!(loader_hosts("var api='https://api.example.net/v1';").is_empty());
    }

    #[test]
    fn digits_do_not_change_the_key() {
        let a = "var t=1700000000; eval(atob('QQ=='));";
        let b = "var t=1700099999;\n eval( atob('QQ==') );";
        let at = |s: &str| inline_hits(s)[0].at;
        assert_eq!(
            snippet_key("decode-exec", a, at(a)),
            snippet_key("decode-exec", b, at(b))
        );
        let c = "eval(atob('Wg=='));";
        assert_ne!(
            snippet_key("decode-exec", a, at(a)),
            snippet_key("decode-exec", c, at(c))
        );
    }

    #[test]
    fn a_key_offset_inside_a_character_does_not_panic() {
        let text = "é eval(atob('x'))";
        assert!(snippet_key("decode-exec", text, 1).starts_with("decode-exec:"));
        assert!(snippet_key("decode-exec", text, 10_000).starts_with("decode-exec:"));
    }
}
