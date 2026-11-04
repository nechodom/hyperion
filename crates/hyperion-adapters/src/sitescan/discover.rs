//! What a WordPress docroot contains, learned by parsing, never by running it.
//!
//! Core version and locale come from `wp-includes/version.php`, plugin and
//! theme versions from their header comments, read the way WordPress reads
//! them (first 8 KiB, first match). Every read goes through the pinned
//! `TenantRoot` and is bounded, so a tenant file can't make root read more.

use std::io::Read;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::manifest::{valid_locale, valid_version, ComponentKey, ComponentKind};
use super::walk::{DirListing, EntryKind, TenantRoot};

/// WordPress reads the first 8 KiB of a plugin or theme file for its header.
pub const HEADER_BYTES: u64 = 8 * 1024;
/// `version.php` is a few hundred bytes; this is a ceiling, not a target.
const VERSION_PHP_BYTES: u64 = 64 * 1024;
/// Entries read from one directory listing.
const LIST_CAP: usize = 5_000;
/// Root-level PHP files tried per plugin when looking for its header.
const MAX_PLUGIN_CANDIDATES: usize = 32;

const VERSION_PHP: &str = "wp-includes/version.php";
const PLUGINS_DIR: &str = "wp-content/plugins";
const THEMES_DIR: &str = "wp-content/themes";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub key: ComponentKey,
    /// Relative to the docroot; empty for core, a file for a single-file plugin.
    #[serde(default)]
    pub rel_root: String,
    #[serde(default)]
    pub is_child_theme: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    #[serde(default)]
    pub is_wordpress: bool,
    #[serde(default)]
    pub components: Vec<Component>,
    /// Anything unusual that stopped a part of the site from being understood.
    #[serde(default)]
    pub problems: Vec<String>,
}

/// Header fields this module reads.
#[derive(Debug, Clone, Copy)]
pub enum Field {
    PluginName,
    Version,
    ThemeName,
    Template,
}

impl Field {
    fn label(self) -> &'static str {
        match self {
            Field::PluginName => "Plugin Name",
            Field::Version => "Version",
            Field::ThemeName => "Theme Name",
            Field::Template => "Template",
        }
    }
}

/// WordPress's own pattern (`get_file_data`): optional `<?php`, then comment
/// punctuation, then the field name and a colon, at the start of a line.
// Constant patterns, all exercised by the tests, so a failure never reaches production.
#[allow(clippy::expect_used)]
static HEADER_RES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        Field::PluginName,
        Field::Version,
        Field::ThemeName,
        Field::Template,
    ]
    .iter()
    .map(|f| {
        let re = Regex::new(&format!(
            r"(?mi)^(?:[ \t]*<\?php)?[ \t/*#@]*{}:(.*)$",
            regex::escape(f.label())
        ))
        .expect("header regex");
        (f.label(), re)
    })
    .collect()
});

/// The value of header `field` in the first `HEADER_BYTES` of `head`: the first
/// match wins, as in WordPress. A `Version:` further down, or in prose that
/// merely mentions the word, is not a header.
pub fn header_field(head: &[u8], field: Field) -> Option<String> {
    let head = &head[..head.len().min(HEADER_BYTES as usize)];
    let text = String::from_utf8_lossy(head).replace('\r', "\n");
    let re = &HEADER_RES.iter().find(|(l, _)| *l == field.label())?.1;
    let raw = re.captures(&text)?.get(1)?.as_str();
    // `_cleanup_header_comment`: a closing `*/` or `?>` ends the value.
    let end = ["*/", "?>"]
        .iter()
        .filter_map(|m| raw.find(m))
        .min()
        .unwrap_or(raw.len());
    let v = raw[..end].trim();
    (!v.is_empty()).then(|| v.to_string())
}

/// The order a plugin's root-level PHP files are tried for a header:
/// `<slug>.php` first, then the rest sorted, at most `MAX_PLUGIN_CANDIDATES`.
pub fn plugin_candidates(slug: &str, mut names: Vec<String>) -> Vec<String> {
    names.sort_unstable();
    let main = format!("{slug}.php");
    if let Some(at) = names.iter().position(|n| *n == main) {
        let m = names.remove(at);
        names.insert(0, m);
    }
    names.truncate(MAX_PLUGIN_CANDIDATES);
    names
}

fn read_head(root: &TenantRoot, rel: &str, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    root.open_file(rel)?.take(limit).read_to_end(&mut buf)?;
    Ok(buf)
}

#[allow(clippy::expect_used)]
static WP_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*\$wp_version[ \t]*=[ \t]*['"]([^'"\r\n]{1,64})['"][ \t]*;"#)
        .expect("wp_version regex")
});
#[allow(clippy::expect_used)]
static WP_LOCAL_PACKAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*\$wp_local_package[ \t]*=[ \t]*['"]([^'"\r\n]{1,64})['"][ \t]*;"#)
        .expect("wp_local_package regex")
});

/// Read the site's components. Parse-only: nothing from the tenant tree is
/// ever executed.
pub fn discover(root: &TenantRoot) -> Discovery {
    let mut d = Discovery::default();
    discover_core(root, &mut d);
    discover_plugins(root, &mut d);
    discover_themes(root, &mut d);
    d
}

fn discover_core(root: &TenantRoot, d: &mut Discovery) {
    let head = match read_head(root, VERSION_PHP, VERSION_PHP_BYTES) {
        Ok(h) => h,
        // No WordPress here, which is not a problem on its own.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            d.problems
                .push(format!("{VERSION_PHP} could not be read: {e}"));
            return;
        }
    };
    let text = String::from_utf8_lossy(&head);
    let Some(version) = WP_VERSION_RE
        .captures(&text)
        .map(|c| c[1].to_string())
        .filter(|v| valid_version(v))
    else {
        d.problems
            .push(format!("{VERSION_PHP} has no readable $wp_version"));
        return;
    };
    let locale = match WP_LOCAL_PACKAGE_RE
        .captures(&text)
        .map(|c| c[1].to_string())
    {
        None => None,
        Some(l) if l == "en_US" => None,
        Some(l) if valid_locale(&l) => Some(l),
        Some(_) => {
            // Guessing en_US would flag every translated file.
            d.problems
                .push(format!("{VERSION_PHP} has an unreadable $wp_local_package"));
            return;
        }
    };
    d.is_wordpress = true;
    d.components.push(Component {
        key: ComponentKey {
            kind: ComponentKind::Core,
            slug: "wordpress".into(),
            version,
            locale,
        },
        rel_root: String::new(),
        is_child_theme: false,
    });
}

/// List `dir`, noting what could not be listed. None when there is no such
/// directory (not a problem) or it can't be read (a problem).
fn list(root: &TenantRoot, dir: &str, d: &mut Discovery) -> Option<DirListing> {
    match root.list_dir(dir, LIST_CAP) {
        Ok(mut l) => {
            if l.truncated {
                d.problems.push(format!(
                    "{dir} has more than {LIST_CAP} entries; the rest were not looked at"
                ));
            }
            if l.non_utf8 > 0 {
                d.problems.push(format!(
                    "{dir} has {} entries with non-UTF-8 names",
                    l.non_utf8
                ));
            }
            l.entries.sort_by(|a, b| a.name.cmp(&b.name));
            Some(l)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            d.problems.push(format!("{dir} could not be listed: {e}"));
            None
        }
    }
}

fn discover_plugins(root: &TenantRoot, d: &mut Discovery) {
    let Some(listing) = list(root, PLUGINS_DIR, d) else {
        return;
    };
    for e in &listing.entries {
        match e.kind {
            EntryKind::Symlink => d.problems.push(format!(
                "{PLUGINS_DIR}/{} is a symlink and was not looked at",
                e.name
            )),
            EntryKind::File => {
                // A single-file plugin: its slug is the file stem.
                let Some(stem) = e.name.strip_suffix(".php") else {
                    continue;
                };
                let rel = format!("{PLUGINS_DIR}/{}", e.name);
                let Ok(head) = read_head(root, &rel, HEADER_BYTES) else {
                    continue;
                };
                if header_field(&head, Field::PluginName).is_some() {
                    push_component(
                        d,
                        ComponentKind::Plugin,
                        stem,
                        header_field(&head, Field::Version),
                        rel,
                        false,
                    );
                }
            }
            EntryKind::Dir => {
                if let Some(head) = plugin_header(root, &e.name, d) {
                    push_component(
                        d,
                        ComponentKind::Plugin,
                        &e.name,
                        header_field(&head, Field::Version),
                        format!("{PLUGINS_DIR}/{}", e.name),
                        false,
                    );
                }
            }
            EntryKind::Other => {}
        }
    }
}

/// The header block of the folder's main file: `<slug>/<slug>.php` first, then
/// the other root-level PHP files in sorted order, the first with a
/// `Plugin Name:`. A folder without one is not a plugin to WordPress either.
fn plugin_header(root: &TenantRoot, slug: &str, d: &mut Discovery) -> Option<Vec<u8>> {
    let dir = format!("{PLUGINS_DIR}/{slug}");
    let listing = match root.list_dir(&dir, LIST_CAP) {
        Ok(l) => l,
        Err(e) => {
            d.problems.push(format!("{dir} could not be listed: {e}"));
            return None;
        }
    };
    let php: Vec<String> = listing
        .entries
        .into_iter()
        .filter(|e| e.kind == EntryKind::File && e.name.ends_with(".php"))
        .map(|e| e.name)
        .collect();
    for name in plugin_candidates(slug, php) {
        match read_head(root, &format!("{dir}/{name}"), HEADER_BYTES) {
            Ok(head) if header_field(&head, Field::PluginName).is_some() => return Some(head),
            Ok(_) => {}
            Err(e) => d
                .problems
                .push(format!("{dir}/{name} could not be read: {e}")),
        }
    }
    None
}

fn discover_themes(root: &TenantRoot, d: &mut Discovery) {
    let Some(listing) = list(root, THEMES_DIR, d) else {
        return;
    };
    for e in &listing.entries {
        match e.kind {
            EntryKind::Symlink => d.problems.push(format!(
                "{THEMES_DIR}/{} is a symlink and was not looked at",
                e.name
            )),
            EntryKind::Dir => {
                let css = format!("{THEMES_DIR}/{}/style.css", e.name);
                let head = match read_head(root, &css, HEADER_BYTES) {
                    Ok(h) => h,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => {
                        d.problems.push(format!("{css} could not be read: {err}"));
                        continue;
                    }
                };
                if header_field(&head, Field::ThemeName).is_none() {
                    continue;
                }
                let child = header_field(&head, Field::Template).is_some_and(|t| t != e.name);
                push_component(
                    d,
                    ComponentKind::Theme,
                    &e.name,
                    header_field(&head, Field::Version),
                    format!("{THEMES_DIR}/{}", e.name),
                    child,
                );
            }
            _ => {}
        }
    }
}

fn push_component(
    d: &mut Discovery,
    kind: ComponentKind,
    slug: &str,
    version: Option<String>,
    rel_root: String,
    is_child_theme: bool,
) {
    if version.is_none() {
        d.problems.push(format!("{rel_root} declares no Version"));
    }
    d.components.push(Component {
        key: ComponentKey {
            kind,
            slug: slug.to_string(),
            version: version.unwrap_or_default(),
            locale: None,
        },
        rel_root,
        is_child_theme,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(p, body).expect("write");
    }

    fn run(root: &Path) -> Discovery {
        discover(&TenantRoot::open(root).expect("open"))
    }

    fn find<'a>(d: &'a Discovery, kind: ComponentKind, slug: &str) -> &'a Component {
        d.components
            .iter()
            .find(|c| c.key.kind == kind && c.key.slug == slug)
            .unwrap_or_else(|| panic!("no {kind:?} {slug}: {:?}", d.components))
    }

    const CZ_VERSION_PHP: &str = "<?php\n/**\n * @global string $wp_version\n */\n$wp_version = '6.5.3';\n$wp_db_version = 58975;\n$wp_local_package = 'cs_CZ';\n";

    #[test]
    fn czech_locale_is_read_from_version_php() {
        let t = tempfile::tempdir().expect("tmp");
        write(t.path(), "wp-includes/version.php", CZ_VERSION_PHP);
        let d = run(t.path());
        assert!(d.is_wordpress);
        assert!(d.problems.is_empty(), "{:?}", d.problems);
        let core = find(&d, ComponentKind::Core, "wordpress");
        assert_eq!(core.key.version, "6.5.3");
        assert_eq!(core.key.locale.as_deref(), Some("cs_CZ"));
        assert_eq!(core.rel_root, "");

        // en_US is the default locale, not a locale to ask for.
        write(
            t.path(),
            "wp-includes/version.php",
            "<?php\n$wp_version = '6.5.3';\n$wp_local_package = 'en_US';\n",
        );
        assert_eq!(run(t.path()).components[0].key.locale, None);
    }

    #[test]
    fn version_php_in_a_comment_is_not_the_version() {
        let t = tempfile::tempdir().expect("tmp");
        write(
            t.path(),
            "wp-includes/version.php",
            "<?php\n// $wp_version = '1.0';\n * $wp_version = '2.0';\n$wp_version = '6.5.3';\n",
        );
        assert_eq!(run(t.path()).components[0].key.version, "6.5.3");
    }

    #[test]
    fn broken_version_php_is_a_problem_not_wordpress() {
        let t = tempfile::tempdir().expect("tmp");
        write(
            t.path(),
            "wp-includes/version.php",
            "<?php\n$wp_version = $other;\n",
        );
        let d = run(t.path());
        assert!(!d.is_wordpress);
        assert!(d.components.is_empty());
        assert_eq!(d.problems.len(), 1);

        write(
            t.path(),
            "wp-includes/version.php",
            "<?php\n$wp_version = '6.5';\n$wp_local_package = '../x';\n",
        );
        let d = run(t.path());
        assert!(!d.is_wordpress);
        assert_eq!(d.problems.len(), 1);

        // No WordPress at all is not a problem.
        let empty = tempfile::tempdir().expect("tmp");
        let d = run(empty.path());
        assert_eq!(d, Discovery::default());
    }

    #[test]
    fn header_parser_ignores_commented_version() {
        let head =
            b"<?php\n/**\n * Plugin Name: Demo\n * Version: 2.0\n */\n// Version: 1.0 (old)\n";
        assert_eq!(header_field(head, Field::Version).as_deref(), Some("2.0"));
        // Prose mentioning the word is not a header.
        let prose =
            b"<?php\n/* Plugin Name: Demo\n * This Version: is not it\n * Version: 3.1 */\n";
        assert_eq!(header_field(prose, Field::Version).as_deref(), Some("3.1"));
        // `*/` and `?>` end the value; CR line ends work; case is ignored.
        assert_eq!(
            header_field(b"/* version: 4.0 */ x", Field::Version).as_deref(),
            Some("4.0")
        );
        assert_eq!(
            header_field(b"<?php /* Plugin Name: A\rVersion: 5 */", Field::Version).as_deref(),
            Some("5")
        );
        // A Version past the first 8 KiB does not exist.
        let mut far = vec![b' '; HEADER_BYTES as usize];
        far.extend_from_slice(b"\nVersion: 9.9\n");
        assert_eq!(header_field(&far, Field::Version), None);
        // `Template:` is not `Template Name:`.
        assert_eq!(
            header_field(b"/*\nTemplate Name: Wide\n*/", Field::Template),
            None
        );
    }

    #[test]
    fn single_file_plugin_discovered() {
        let t = tempfile::tempdir().expect("tmp");
        write(
            t.path(),
            "wp-content/plugins/hello.php",
            "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n",
        );
        write(
            t.path(),
            "wp-content/plugins/index.php",
            "<?php\n// Silence is golden.\n",
        );
        let d = run(t.path());
        assert_eq!(d.components.len(), 1, "{:?}", d.components);
        let c = find(&d, ComponentKind::Plugin, "hello");
        assert_eq!(c.key.version, "1.7.2");
        assert_eq!(c.rel_root, "wp-content/plugins/hello.php");
        assert!(d.problems.is_empty(), "{:?}", d.problems);
    }

    #[test]
    fn plugin_header_comes_from_main_file_then_sorted_order() {
        let t = tempfile::tempdir().expect("tmp");
        let hdr = |v: &str| format!("<?php\n/*\nPlugin Name: P\nVersion: {v}\n*/\n");
        // <slug>/<slug>.php wins even though a.php sorts first.
        write(t.path(), "wp-content/plugins/demo/a.php", &hdr("1.0"));
        write(t.path(), "wp-content/plugins/demo/demo.php", &hdr("2.0"));
        // No main file: the first sorted file WITH a header; index.php has none.
        write(
            t.path(),
            "wp-content/plugins/odd/index.php",
            "<?php // nothing",
        );
        write(t.path(), "wp-content/plugins/odd/zeta.php", &hdr("3.0"));
        write(t.path(), "wp-content/plugins/odd/beta.php", &hdr("4.0"));
        // Not a plugin at all.
        write(t.path(), "wp-content/plugins/junk/readme.txt", "x");
        let d = run(t.path());
        assert_eq!(find(&d, ComponentKind::Plugin, "demo").key.version, "2.0");
        assert_eq!(find(&d, ComponentKind::Plugin, "odd").key.version, "4.0");
        assert_eq!(
            find(&d, ComponentKind::Plugin, "odd").rel_root,
            "wp-content/plugins/odd"
        );
        assert!(d.components.iter().all(|c| c.key.slug != "junk"));
    }

    #[test]
    fn plugin_candidate_order() {
        let names = vec![
            "z.php".to_string(),
            "demo.php".to_string(),
            "a.php".to_string(),
        ];
        assert_eq!(
            plugin_candidates("demo", names.clone()),
            vec!["demo.php", "a.php", "z.php"]
        );
        assert_eq!(
            plugin_candidates("other", names),
            vec!["a.php", "demo.php", "z.php"]
        );
        let many: Vec<String> = (0..100).map(|i| format!("f{i:03}.php")).collect();
        assert_eq!(plugin_candidates("x", many).len(), MAX_PLUGIN_CANDIDATES);
    }

    #[test]
    fn theme_version_from_style_css() {
        let t = tempfile::tempdir().expect("tmp");
        write(
            t.path(),
            "wp-content/themes/hello-elementor/style.css",
            "/*\nTheme Name: Hello Elementor\nVersion: 3.0.1\n*/\n",
        );
        write(
            t.path(),
            "wp-content/themes/hello-elementor/functions.php",
            "<?php",
        );
        write(t.path(), "wp-content/themes/index.php", "<?php");
        let d = run(t.path());
        let c = find(&d, ComponentKind::Theme, "hello-elementor");
        assert_eq!(c.key.version, "3.0.1");
        assert_eq!(c.rel_root, "wp-content/themes/hello-elementor");
        assert!(!c.is_child_theme);
    }

    #[test]
    fn child_theme_flagged_by_template_header() {
        let t = tempfile::tempdir().expect("tmp");
        write(
            t.path(),
            "wp-content/themes/kid/style.css",
            "/*\nTheme Name: Kid\nTemplate: hello-elementor\nVersion: 1.0\n*/\n",
        );
        write(
            t.path(),
            "wp-content/themes/hello-elementor/style.css",
            "/*\nTheme Name: Hello\nTemplate: hello-elementor\nVersion: 3.0.1\n*/\n",
        );
        let d = run(t.path());
        assert!(find(&d, ComponentKind::Theme, "kid").is_child_theme);
        // A theme naming itself as its template is a parent.
        assert!(!find(&d, ComponentKind::Theme, "hello-elementor").is_child_theme);
    }

    #[test]
    fn missing_version_and_symlinks_are_reported() {
        let t = tempfile::tempdir().expect("tmp");
        write(
            t.path(),
            "wp-content/plugins/nover/nover.php",
            "<?php\n/* Plugin Name: N */\n",
        );
        std::os::unix::fs::symlink("/tmp", t.path().join("wp-content/plugins/linked"))
            .expect("link");
        let d = run(t.path());
        assert_eq!(find(&d, ComponentKind::Plugin, "nover").key.version, "");
        assert_eq!(d.problems.len(), 2, "{:?}", d.problems);
    }

    #[test]
    fn discovery_roundtrips_as_json() {
        let t = tempfile::tempdir().expect("tmp");
        write(t.path(), "wp-includes/version.php", CZ_VERSION_PHP);
        let d = run(t.path());
        let back: Discovery =
            serde_json::from_str(&serde_json::to_string(&d).expect("ser")).expect("de");
        assert_eq!(back, d);
        assert_eq!(
            serde_json::from_str::<Discovery>("{}").expect("default"),
            Discovery::default()
        );
    }
}
