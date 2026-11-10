//! Files a plugin writes outside its own folder, recognised by what it writes.
//!
//! A cache or object-cache plugin keeps a drop-in in `wp-content/` and rewrites
//! it whenever its settings or its version change. Each change would otherwise
//! be a change to review that nobody can do anything about. Each check here
//! says the file is exactly what the plugin writes: its own file copied
//! verbatim, its template filled in with values that can't carry code, or data
//! with no statement that runs. Anything else is a change like any other.
//!
//! What the plugin writes from (its template, its copy) lives in its own
//! folder, which the scan watches like every other file: a template edited to
//! carry a payload is a change there.

/// The drop-in folder: WordPress loads drop-ins from `WP_CONTENT_DIR`.
const CONTENT_DIR: &str = "wp-content";

/// Largest drop-in or template compared, in bytes. WP Rocket's template is
/// about 4 kB, Redis Object Cache's drop-in about 90 kB.
pub const PLUGIN_FILE_MAX_BYTES: usize = 512 * 1024;

/// Drop-ins copied verbatim from the plugin's folder: Redis Object Cache
/// (`$wp_filesystem->copy` of `includes/object-cache.php`) and LiteSpeed Cache
/// (`copy` of `lib/object-cache.php`).
const COPIED_DROPINS: &[(&str, &str)] = &[
    (
        "object-cache.php",
        "plugins/redis-cache/includes/object-cache.php",
    ),
    (
        "object-cache.php",
        "plugins/litespeed-cache/lib/object-cache.php",
    ),
];

/// WP Rocket's `advanced-cache.php` template, under the content dir.
const WP_ROCKET_TEMPLATE: &str = "plugins/wp-rocket/views/cache/advanced-cache.php";

/// The content dir of a drop-in at `rel_path` and its name, when it sits in
/// one: `wp-content/<name>`, or `<subdir>/wp-content/<name>` for a site in a
/// subfolder.
fn dropin(rel_path: &str) -> Option<(&str, &str)> {
    let (dir, name) = rel_path.rsplit_once('/')?;
    (dir == CONTENT_DIR || dir.ends_with(&format!("/{CONTENT_DIR}"))).then_some((dir, name))
}

/// Where a plugin keeps the original of the drop-in at `rel_path`, if any plugin
/// writes one there. More than one plugin may: each is a candidate.
pub fn dropin_sources(rel_path: &str) -> Vec<String> {
    let Some((dir, name)) = dropin(rel_path) else {
        return Vec::new();
    };
    let mut out: Vec<String> = COPIED_DROPINS
        .iter()
        .filter(|(n, _)| *n == name)
        .map(|(_, src)| format!("{dir}/{src}"))
        .collect();
    if name == "advanced-cache.php" {
        out.push(format!("{dir}/{WP_ROCKET_TEMPLATE}"));
    }
    out
}

/// `file` is what the plugin writes from `source` (one of [`dropin_sources`]).
pub fn written_from(rel_path: &str, source_rel: &str, file: &[u8], source: &[u8]) -> bool {
    if file.len() > PLUGIN_FILE_MAX_BYTES || source.len() > PLUGIN_FILE_MAX_BYTES {
        return false;
    }
    let Some((dir, name)) = dropin(rel_path) else {
        return false;
    };
    let Some(src) = source_rel
        .strip_prefix(dir)
        .and_then(|s| s.strip_prefix('/'))
    else {
        return false;
    };
    if COPIED_DROPINS.contains(&(name, src)) {
        return file == source;
    }
    name == "advanced-cache.php"
        && src == WP_ROCKET_TEMPLATE
        && is_wp_rocket_advanced_cache(file, source)
}

/// The placeholders WP Rocket fills in `advanced-cache.php`
/// (`AdvancedCache::get_advanced_cache_content`): its minimum PHP version and
/// three absolute paths, every one inside single quotes in the template.
const ROCKET_KEYS: [&str; 4] = [
    "{{WP_ROCKET_PHP_VERSION}}",
    "{{WP_ROCKET_PATH}}",
    "{{WP_ROCKET_CONFIG_PATH}}",
    "{{WP_ROCKET_CACHE_PATH}}",
];
const ROCKET_MOBILE_OPEN: &str = "'{{MOBILE_CACHE}}';";
const ROCKET_MOBILE_CLOSE: &str = "'{{/MOBILE_CACHE}}';";
const ROCKET_VALUE_MAX: usize = 1024;

/// `file` is WP Rocket's `template` filled in: the mobile block kept (its
/// markers dropped) or removed, then each placeholder replaced by one value
/// throughout. A version is digits and dots; a path is absolute and made of
/// characters that can't end a single-quoted string or escape out of one.
pub fn is_wp_rocket_advanced_cache(file: &[u8], template: &[u8]) -> bool {
    let Ok(template) = std::str::from_utf8(template) else {
        return false;
    };
    if !template.contains("WP_ROCKET_ADVANCED_CACHE") {
        return false;
    }
    let open = template.find(ROCKET_MOBILE_OPEN);
    let close = template.rfind(ROCKET_MOBILE_CLOSE);
    let variants: Vec<String> = match (open, close) {
        (Some(o), Some(c)) if o + ROCKET_MOBILE_OPEN.len() <= c => {
            let (pre, mid, post) = (
                &template[..o],
                &template[o + ROCKET_MOBILE_OPEN.len()..c],
                &template[c + ROCKET_MOBILE_CLOSE.len()..],
            );
            vec![format!("{pre}{mid}{post}"), format!("{pre}{post}")]
        }
        (None, None) => vec![template.to_string()],
        _ => return false,
    };
    variants.iter().any(|t| fills(file, t))
}

fn value_byte(key: usize, b: u8, first: bool) -> bool {
    if key == 0 {
        return b.is_ascii_digit() || b == b'.';
    }
    if first {
        return b == b'/';
    }
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'~' | b'+' | b'@')
}

/// `file` is `template` with each of [`ROCKET_KEYS`] replaced, the same value
/// every time. A first value runs as far as its characters allow; the template
/// then has to go on from there.
fn fills(file: &[u8], template: &str) -> bool {
    let mut bound: [Option<&[u8]>; 4] = [None; 4];
    let mut rest = file;
    let mut t = template;
    loop {
        let next = ROCKET_KEYS
            .iter()
            .enumerate()
            .filter_map(|(k, key)| t.find(key).map(|pos| (pos, k)))
            .min();
        let Some((pos, k)) = next else {
            return rest == t.as_bytes();
        };
        let Some(after) = rest.strip_prefix(&t.as_bytes()[..pos]) else {
            return false;
        };
        t = &t[pos + ROCKET_KEYS[k].len()..];
        let value = match bound[k] {
            Some(v) => v,
            None => {
                let n = after
                    .iter()
                    .enumerate()
                    .take_while(|(i, b)| value_byte(k, **b, *i == 0))
                    .count();
                if n == 0 || n > ROCKET_VALUE_MAX {
                    return false;
                }
                bound[k] = Some(&after[..n]);
                &after[..n]
            }
        };
        let Some(after) = after.strip_prefix(value) else {
            return false;
        };
        rest = after;
    }
}

/// WP Rocket's per-site config (`get_rocket_config_file`):
/// `wp-content/wp-rocket-config/<host>.php`, rewritten on every settings save.
/// It is `<?php`, `defined( 'ABSPATH' ) || exit;`, then only assignments of
/// literals to `$rocket_*` variables: integers, single-quoted strings, and
/// `var_export` arrays of those. Nothing in it calls anything.
pub fn is_wp_rocket_config(rel_path: &str, bytes: &[u8]) -> bool {
    let mut parts = rel_path.rsplit('/');
    let (Some(name), Some("wp-rocket-config")) = (parts.next(), parts.next()) else {
        return false;
    };
    if !name.ends_with(".php") || bytes.len() > PLUGIN_FILE_MAX_BYTES {
        return false;
    }
    let Some(mut p) = bytes.strip_prefix(&b"<?php\ndefined( 'ABSPATH' ) || exit;\n"[..]) else {
        return false;
    };
    loop {
        p = skip_ws(p);
        if p.is_empty() {
            return true;
        }
        let Some(after) = p.strip_prefix(&b"$rocket_"[..]) else {
            return false;
        };
        let n = after
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
            .count();
        if n == 0 {
            return false;
        }
        let Some(after) = skip_ws(&after[n..]).strip_prefix(&b"="[..]) else {
            return false;
        };
        let Some(after) = literal(skip_ws(after), 0) else {
            return false;
        };
        let Some(after) = skip_ws(after).strip_prefix(&b";"[..]) else {
            return false;
        };
        p = after;
    }
}

fn skip_ws(p: &[u8]) -> &[u8] {
    let n = p
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .count();
    &p[n..]
}

/// One literal at the start of `p`, and what follows it: an integer, a
/// single-quoted string, `true`/`false`/`null`, or an `array( … )` of
/// `key => literal` pairs, as `var_export` writes them.
fn literal(p: &[u8], depth: u8) -> Option<&[u8]> {
    match p.first()? {
        b'\'' => {
            let mut i = 1;
            loop {
                match p.get(i)? {
                    b'\\' => i += 2,
                    b'\'' => return Some(&p[i + 1..]),
                    _ => i += 1,
                }
            }
        }
        b'-' | b'0'..=b'9' => {
            let body = p.strip_prefix(&b"-"[..]).unwrap_or(p);
            let n = body.iter().take_while(|b| b.is_ascii_digit()).count();
            (n > 0).then(|| &body[n..])
        }
        _ => {
            for word in [&b"true"[..], b"false", b"null"] {
                if p.len() >= word.len()
                    && p[..word.len()].eq_ignore_ascii_case(word)
                    && !p
                        .get(word.len())
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    return Some(&p[word.len()..]);
                }
            }
            if depth >= 4 {
                return None;
            }
            let mut q = p.strip_prefix(&b"array("[..])?;
            loop {
                q = skip_ws(q);
                if let Some(after) = q.strip_prefix(&b")"[..]) {
                    return Some(after);
                }
                // A key is an integer or a string.
                if !matches!(q.first(), Some(b'\'' | b'-' | b'0'..=b'9')) {
                    return None;
                }
                let key_end = literal(q, depth + 1)?;
                q = skip_ws(key_end).strip_prefix(&b"=>"[..])?;
                q = literal(skip_ws(q), depth + 1)?;
                q = skip_ws(q);
                if let Some(after) = q.strip_prefix(&b","[..]) {
                    q = after;
                } else if !q.starts_with(b")") {
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WP Rocket 3.x `views/cache/advanced-cache.php`, abridged in the middle but
    /// with every placeholder and the mobile block as the plugin ships them.
    const TEMPLATE: &str = "<?php\n\nuse WP_Rocket\\Buffer\\Cache;\n\ndefined( 'ABSPATH' ) || exit;\n\ndefine( 'WP_ROCKET_ADVANCED_CACHE', true );\n\n$rocket_path        = '{{WP_ROCKET_PATH}}';\n$rocket_config_path = '{{WP_ROCKET_CONFIG_PATH}}';\n$rocket_cache_path  = '{{WP_ROCKET_CACHE_PATH}}';\n\nif (\n\tversion_compare( phpversion(), '{{WP_ROCKET_PHP_VERSION}}', '<' )\n\t|| ! file_exists( $rocket_path )\n) {\n\tdefine( 'WP_ROCKET_ADVANCED_CACHE_PROBLEM', true );\n\treturn;\n}\n\n'{{MOBILE_CACHE}}';\nif ( file_exists( '{{WP_ROCKET_PATH}}inc/Dependencies/Detection/MobileDetect.php' ) ) {\n\tinclude_once '{{WP_ROCKET_PATH}}inc/Dependencies/Detection/MobileDetect.php';\n}\n'{{/MOBILE_CACHE}}';\n\nspl_autoload_register( function ( $class ) use ( $rocket_path ) {\n\trequire $rocket_path . 'inc/classes/Buffer/class-cache.php';\n} );\n";

    const PLUGIN: &str = "/home/site/htdocs/wp-content/plugins/wp-rocket/";
    const CONFIG: &str = "/home/site/htdocs/wp-content/wp-rocket-config/";
    const CACHE: &str = "/home/site/htdocs/wp-content/cache/wp-rocket/";

    fn render(mobile: bool, path: &str) -> String {
        let o = TEMPLATE.find(ROCKET_MOBILE_OPEN).unwrap();
        let c = TEMPLATE.find(ROCKET_MOBILE_CLOSE).unwrap();
        let mid = if mobile {
            &TEMPLATE[o + ROCKET_MOBILE_OPEN.len()..c]
        } else {
            ""
        };
        format!(
            "{}{}{}",
            &TEMPLATE[..o],
            mid,
            &TEMPLATE[c + ROCKET_MOBILE_CLOSE.len()..]
        )
        .replace("{{WP_ROCKET_PHP_VERSION}}", "7.3")
        .replace("{{WP_ROCKET_PATH}}", path)
        .replace("{{WP_ROCKET_CONFIG_PATH}}", CONFIG)
        .replace("{{WP_ROCKET_CACHE_PATH}}", CACHE)
    }

    #[test]
    fn wp_rockets_filled_template_is_recognised() {
        for mobile in [true, false] {
            let file = render(mobile, PLUGIN);
            assert!(
                is_wp_rocket_advanced_cache(file.as_bytes(), TEMPLATE.as_bytes()),
                "mobile={mobile}"
            );
            assert!(written_from(
                "wp-content/advanced-cache.php",
                "wp-content/plugins/wp-rocket/views/cache/advanced-cache.php",
                file.as_bytes(),
                TEMPLATE.as_bytes(),
            ));
        }
    }

    #[test]
    fn anything_added_to_wp_rockets_template_is_not_it() {
        let good = render(true, PLUGIN);
        let tampered = [
            good.replace(
                "spl_autoload_register",
                "eval($_POST['x']);spl_autoload_register",
            ),
            format!("{good}@include '/tmp/x.php';\n"),
            // A value that leaves its string.
            render(true, "/home/site/'; system($_GET['c']); '/"),
            // One placeholder, two values.
            good.replacen(PLUGIN, "/home/other/", 1),
            render(true, "relative/path/"),
        ];
        for t in tampered {
            assert!(
                !is_wp_rocket_advanced_cache(t.as_bytes(), TEMPLATE.as_bytes()),
                "{t}"
            );
        }
        // Another plugin's file is not compared with WP Rocket's template.
        assert!(!is_wp_rocket_advanced_cache(
            b"<?php // W3TC",
            b"<?php // W3TC"
        ));
    }

    #[test]
    fn copied_dropins_must_be_byte_for_byte() {
        let src = b"<?php\n/* Plugin Name: Redis Object Cache Drop-In */\n";
        let from = "wp-content/plugins/redis-cache/includes/object-cache.php";
        assert!(written_from("wp-content/object-cache.php", from, src, src));
        assert!(!written_from(
            "wp-content/object-cache.php",
            from,
            b"<?php eval($_POST[1]);",
            src
        ));
        // A source path that isn't one of the plugin's.
        assert!(!written_from(
            "wp-content/object-cache.php",
            "wp-content/uploads/object-cache.php",
            src,
            src
        ));
        // Not a drop-in folder.
        assert!(!written_from(
            "wp-content/themes/x/object-cache.php",
            "wp-content/themes/x/plugins/redis-cache/includes/object-cache.php",
            src,
            src
        ));
    }

    #[test]
    fn dropin_sources_follow_the_content_dir() {
        assert_eq!(
            dropin_sources("blog/wp-content/object-cache.php"),
            [
                "blog/wp-content/plugins/redis-cache/includes/object-cache.php",
                "blog/wp-content/plugins/litespeed-cache/lib/object-cache.php"
            ]
        );
        assert_eq!(
            dropin_sources("wp-content/advanced-cache.php"),
            ["wp-content/plugins/wp-rocket/views/cache/advanced-cache.php"]
        );
        assert!(dropin_sources("wp-content/db.php").is_empty());
        assert!(dropin_sources("object-cache.php").is_empty());
    }

    /// The shape `get_rocket_config_file` writes, with every kind of value it
    /// can: ints, strings with escapes and regex, `var_export` arrays (empty,
    /// listed, keyed) and the last line without a newline.
    const ROCKET_CONFIG: &str = "<?php\ndefined( 'ABSPATH' ) || exit;\n\n$rocket_cookie_hash = '0123456789abcdef0123456789abcdef';\n$rocket_logged_in_cookie = 'wordpress_logged_in_0123456789abcdef0123456789abcdef';\n$rocket_cache_mobile_files_tablet = 'desktop';\n$rocket_cache_ssl = 1;\n$rocket_cache_webp = 0;\n$rocket_secret_cache_key = '5f0e0c0a0b0d';\n$rocket_cache_reject_uri = '/(?:.+/)?feed(?:/(?:.+/?)?)?$|/(?:.+/)?embed/|/(index.php/)?(.*)wp-json(/.*|$)';\n$rocket_cache_query_strings = array();\n$rocket_cache_reject_cookies = 'wordpress_logged_in_.+|wp-postpass_|wptouch_switch_toggle|comment_author_|comment_author_email_';\n$rocket_cache_reject_ua = 'facebookexternalhit|It\\'s a bot';\n$rocket_cache_ignored_parameters = array(\n  'utm_source' => 1,\n  'fbclid' => 1,\n);\n$rocket_cache_mandatory_cookies = '';\n$rocket_cache_dynamic_cookies = array(\n  0 => 'wpml_browser_redirect_test',\n  1 => '_icl_current_language',\n);\n$rocket_permalink_structure = '/%postname%/';\n$rocket_url_no_dots = 1;";

    const ROCKET_CONFIG_PATH: &str = "wp-content/wp-rocket-config/example.org.php";

    #[test]
    fn wp_rocket_config_is_data_only() {
        assert!(is_wp_rocket_config(
            ROCKET_CONFIG_PATH,
            ROCKET_CONFIG.as_bytes()
        ));
        assert!(is_wp_rocket_config(
            "wp-content/wp-rocket-config/example.org.shop.php",
            ROCKET_CONFIG.as_bytes()
        ));
    }

    #[test]
    fn code_in_a_wp_rocket_config_is_not_data() {
        for extra in [
            "\nsystem($_GET['c']);",
            "\n$rocket_x = system('id');",
            "\n$rocket_x = \"{${phpinfo()}}\";",
            "\n$rocket_x = 'a' . 'b';",
            "\n$rocket_x = array( 'a' => exec('id') );",
            "\n$rocket_x = 1",
            "\n$other = 1;",
            "\n?><?php system('id');",
            "\n$rocket_x = 'unterminated;",
        ] {
            let body = format!("{ROCKET_CONFIG}{extra}");
            assert!(
                !is_wp_rocket_config(ROCKET_CONFIG_PATH, body.as_bytes()),
                "{extra}"
            );
        }
        // Somewhere else, or without the plugin's opening, it is not its config.
        assert!(!is_wp_rocket_config(
            "wp-content/example.org.php",
            ROCKET_CONFIG.as_bytes()
        ));
        assert!(!is_wp_rocket_config(
            ROCKET_CONFIG_PATH,
            ROCKET_CONFIG
                .replacen("defined( 'ABSPATH' ) || exit;\n", "", 1)
                .as_bytes()
        ));
    }
}
