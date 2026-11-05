//! What a WordPress docroot contains, learned by parsing, never by running it.
//!
//! Core version and locale come from `wp-includes/version.php`, plugin and
//! theme versions from their header comments, read the way WordPress reads
//! them (first 8 KiB, first match). Every read goes through the pinned
//! `TenantRoot` and is bounded, so a tenant file can't make root read more.
//!
//! Tenant files never decide whether a site is checked: a site that looks like
//! WordPress stays one when its `version.php` is broken or gone, and says so.

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
pub const MAX_PLUGIN_CANDIDATES: usize = 32;
/// Problems kept; the rest become one "and more" line.
const MAX_PROBLEMS: usize = 100;
/// Header values are short; a tenant can write 8 KiB of anything.
const MAX_HEADER_VALUE: usize = 64;

const VERSION_PHP: &str = "wp-includes/version.php";
const PLUGINS_DIR: &str = "wp-content/plugins";
const THEMES_DIR: &str = "wp-content/themes";

/// Single-file plugins whose file stem is not their wordpress.org slug.
const SINGLE_FILE_SLUGS: [(&str, &str); 1] = [("hello", "hello-dolly")];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub key: ComponentKey,
    /// Relative to the docroot; empty for core, the file for a single-file plugin.
    #[serde(default)]
    pub rel_root: String,
    #[serde(default)]
    pub is_child_theme: bool,
    /// A plugin that is one PHP file directly in `wp-content/plugins`.
    #[serde(default)]
    pub single_file: bool,
}

impl Component {
    /// The manifest key for the tree path `rel` (relative to the docroot), or
    /// None when the path isn't part of this component. A manifest for a
    /// folder lists paths below the folder; for a single-file plugin it lists
    /// the file by its name.
    pub fn manifest_key(&self, rel: &str) -> Option<String> {
        if self.single_file {
            return (rel == self.rel_root)
                .then(|| rel.rsplit('/').next().unwrap_or(rel).to_string());
        }
        if self.rel_root.is_empty() {
            return Some(rel.to_string());
        }
        rel.strip_prefix(&self.rel_root)
            .and_then(|r| r.strip_prefix('/'))
            .filter(|r| !r.is_empty())
            .map(str::to_string)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    /// The docroot looks like WordPress (`wp-includes/`, `wp-load.php` or
    /// `wp-content/` is there). Not decided by `version.php`, which a tenant
    /// can break or delete.
    #[serde(default)]
    pub is_wordpress: bool,
    /// Looks like WordPress but core's version couldn't be read: core is
    /// "couldn't check", never clean.
    #[serde(default)]
    pub core_version_unknown: bool,
    #[serde(default)]
    pub components: Vec<Component>,
    /// Anything unusual that stopped a part of the site from being understood.
    /// At most `MAX_PROBLEMS`, then one "and more" line.
    #[serde(default)]
    pub problems: Vec<String>,
}

impl Discovery {
    fn note(&mut self, msg: String) {
        match self.problems.len() {
            n if n < MAX_PROBLEMS => self.problems.push(msg),
            MAX_PROBLEMS => self.problems.push("and more".to_string()),
            _ => {}
        }
    }
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
/// merely mentions the word, is not a header. The value is cut to
/// `MAX_HEADER_VALUE` characters with control characters removed.
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
    let v: String = raw[..end]
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_HEADER_VALUE)
        .collect();
    let v = v.trim();
    (!v.is_empty()).then(|| v.to_string())
}

/// The order a plugin's root-level PHP files are tried for a header:
/// `<slug>.php` first, then the rest sorted. Callers try at most
/// `MAX_PLUGIN_CANDIDATES` and report it when more existed.
pub fn plugin_candidates(slug: &str, mut names: Vec<String>) -> Vec<String> {
    names.sort_unstable();
    let main = format!("{slug}.php");
    if let Some(at) = names.iter().position(|n| *n == main) {
        let m = names.remove(at);
        names.insert(0, m);
    }
    names
}

fn read_head(root: &TenantRoot, rel: &str, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    root.open_file(rel)?.take(limit).read_to_end(&mut buf)?;
    Ok(buf)
}

fn not_found(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
}

// Constant patterns, exercised by the tests.
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

/// Does anything in the docroot say "WordPress"? A name that exists but can't
/// be opened (a symlink, a wrong type) counts, and is reported.
fn looks_like_wordpress(root: &TenantRoot, d: &mut Discovery) -> bool {
    let mut found = false;
    for dir in ["wp-includes", "wp-content"] {
        match root.list_dir(dir, 1) {
            Ok(_) => found = true,
            Err(e) if not_found(&e) => {}
            Err(e) => {
                found = true;
                d.note(format!("{dir} could not be opened: {e}"));
            }
        }
    }
    match root.open_file("wp-load.php") {
        Ok(_) => found = true,
        Err(e) if not_found(&e) => {}
        Err(e) => {
            found = true;
            d.note(format!("wp-load.php could not be opened: {e}"));
        }
    }
    found
}

fn discover_core(root: &TenantRoot, d: &mut Discovery) {
    d.is_wordpress = looks_like_wordpress(root, d);
    if !d.is_wordpress {
        return;
    }
    d.core_version_unknown = true;
    let head = match read_head(root, VERSION_PHP, VERSION_PHP_BYTES) {
        Ok(h) => h,
        Err(e) if not_found(&e) => {
            d.note(format!("{VERSION_PHP} is missing"));
            return;
        }
        Err(e) => {
            d.note(format!("{VERSION_PHP} could not be read: {e}"));
            return;
        }
    };
    let text = String::from_utf8_lossy(&head);
    let Some(version) = WP_VERSION_RE
        .captures(&text)
        .map(|c| c[1].to_string())
        .filter(|v| valid_version(v))
    else {
        d.note(format!("{VERSION_PHP} has no readable $wp_version"));
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
            d.note(format!("{VERSION_PHP} has an unreadable $wp_local_package"));
            return;
        }
    };
    d.core_version_unknown = false;
    d.components.push(Component {
        key: ComponentKey {
            kind: ComponentKind::Core,
            slug: "wordpress".into(),
            version,
            locale,
        },
        rel_root: String::new(),
        is_child_theme: false,
        single_file: false,
    });
}

/// List `dir`, noting what could not be listed. None when there is no such
/// directory (not a problem) or it can't be read (a problem).
fn list(root: &TenantRoot, dir: &str, d: &mut Discovery) -> Option<DirListing> {
    match root.list_dir(dir, LIST_CAP) {
        Ok(mut l) => {
            note_listing(d, dir, &l);
            l.entries.sort_by(|a, b| a.name.cmp(&b.name));
            Some(l)
        }
        Err(e) if not_found(&e) => None,
        Err(e) => {
            d.note(format!("{dir} could not be listed: {e}"));
            None
        }
    }
}

fn note_listing(d: &mut Discovery, dir: &str, l: &DirListing) {
    if l.truncated {
        d.note(format!(
            "{dir} has more than {LIST_CAP} entries; the rest were not looked at"
        ));
    }
    if l.non_utf8 > 0 {
        d.note(format!(
            "{dir} has {} entries with non-UTF-8 names that were not looked at",
            l.non_utf8
        ));
    }
}

fn discover_plugins(root: &TenantRoot, d: &mut Discovery) {
    let Some(listing) = list(root, PLUGINS_DIR, d) else {
        return;
    };
    for e in &listing.entries {
        match e.kind {
            EntryKind::Symlink => d.note(format!(
                "{PLUGINS_DIR}/{} is a symlink and was not looked at",
                e.name
            )),
            EntryKind::File => {
                // A single-file plugin: its slug is the file stem.
                let Some(stem) = e.name.strip_suffix(".php") else {
                    continue;
                };
                let rel = format!("{PLUGINS_DIR}/{}", e.name);
                let head = match read_head(root, &rel, HEADER_BYTES) {
                    Ok(h) => h,
                    Err(err) => {
                        d.note(format!("{rel} could not be read: {err}"));
                        continue;
                    }
                };
                if header_field(&head, Field::PluginName).is_some() {
                    let slug = SINGLE_FILE_SLUGS
                        .iter()
                        .find(|(s, _)| *s == stem)
                        .map_or(stem, |(_, slug)| slug);
                    push_component(
                        d,
                        ComponentKind::Plugin,
                        slug,
                        header_field(&head, Field::Version),
                        rel,
                        false,
                        true,
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
                        false,
                    );
                }
            }
            EntryKind::Other => {}
        }
    }
}

/// The header block of the folder's main file: `<slug>/<slug>.php` first
/// (opened directly, so a big folder can't push it out of the listing), then
/// the other root-level PHP files in sorted order, the first with a
/// `Plugin Name:`. A folder without one is not a plugin to WordPress either.
/// Whatever couldn't be read is reported, never skipped silently.
fn plugin_header(root: &TenantRoot, slug: &str, d: &mut Discovery) -> Option<Vec<u8>> {
    let dir = format!("{PLUGINS_DIR}/{slug}");
    let main = format!("{slug}.php");
    match read_head(root, &format!("{dir}/{main}"), HEADER_BYTES) {
        Ok(head) if header_field(&head, Field::PluginName).is_some() => return Some(head),
        Ok(_) => {}
        Err(e) if not_found(&e) => {}
        Err(e) => d.note(format!("{dir}/{main} could not be read: {e}")),
    }
    let listing = match root.list_dir(&dir, LIST_CAP) {
        Ok(l) => l,
        Err(e) => {
            d.note(format!("{dir} could not be listed: {e}"));
            return None;
        }
    };
    note_listing(d, &dir, &listing);
    let mut php = Vec::new();
    for e in listing
        .entries
        .into_iter()
        .filter(|e| e.name.ends_with(".php"))
    {
        match e.kind {
            EntryKind::File => php.push(e.name),
            EntryKind::Symlink | EntryKind::Other => d.note(format!(
                "{dir}/{} is not a regular file and was not read",
                e.name
            )),
            EntryKind::Dir => {}
        }
    }
    let names = plugin_candidates(slug, php);
    let more = names.len() > MAX_PLUGIN_CANDIDATES;
    for name in names.into_iter().take(MAX_PLUGIN_CANDIDATES) {
        if name == main {
            // Already tried above (and reported if it failed).
            continue;
        }
        match read_head(root, &format!("{dir}/{name}"), HEADER_BYTES) {
            Ok(head) if header_field(&head, Field::PluginName).is_some() => return Some(head),
            Ok(_) => {}
            Err(e) => d.note(format!("{dir}/{name} could not be read: {e}")),
        }
    }
    if more {
        d.note(format!(
            "{dir} has more than {MAX_PLUGIN_CANDIDATES} PHP files; the rest were not checked for a plugin header"
        ));
    }
    None
}

fn discover_themes(root: &TenantRoot, d: &mut Discovery) {
    let Some(listing) = list(root, THEMES_DIR, d) else {
        return;
    };
    for e in &listing.entries {
        match e.kind {
            EntryKind::Symlink => d.note(format!(
                "{THEMES_DIR}/{} is a symlink and was not looked at",
                e.name
            )),
            EntryKind::Dir => {
                let css = format!("{THEMES_DIR}/{}/style.css", e.name);
                let head = match read_head(root, &css, HEADER_BYTES) {
                    Ok(h) => h,
                    Err(err) if not_found(&err) => continue,
                    Err(err) => {
                        d.note(format!("{css} could not be read: {err}"));
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
                    false,
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
    single_file: bool,
) {
    if version.is_none() {
        d.note(format!("{rel_root} declares no Version"));
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
        single_file,
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
    fn tenant_cannot_turn_core_checking_off() {
        let t = tempfile::tempdir().expect("tmp");
        // Broken version.php: still WordPress, version unknown, reported.
        write(
            t.path(),
            "wp-includes/version.php",
            "<?php\n$wp_version = $other;\n",
        );
        let d = run(t.path());
        assert!(d.is_wordpress);
        assert!(d.core_version_unknown);
        assert!(d.components.is_empty());
        assert_eq!(d.problems.len(), 1, "{:?}", d.problems);

        // Deleted version.php: the same, with a reason.
        std::fs::remove_file(t.path().join("wp-includes/version.php")).expect("rm");
        let d = run(t.path());
        assert!(d.is_wordpress && d.core_version_unknown);
        assert!(
            d.problems.iter().any(|p| p.contains("missing")),
            "{:?}",
            d.problems
        );

        // Bad locale: also unknown, never a guess of en_US.
        write(
            t.path(),
            "wp-includes/version.php",
            "<?php\n$wp_version = '6.5';\n$wp_local_package = '../x';\n",
        );
        let d = run(t.path());
        assert!(d.is_wordpress && d.core_version_unknown);
        assert!(d.components.is_empty());

        // Any of the three markers is enough.
        for marker in ["wp-load.php", "wp-content/index.php"] {
            let t = tempfile::tempdir().expect("tmp");
            write(t.path(), marker, "<?php");
            let d = run(t.path());
            assert!(d.is_wordpress && d.core_version_unknown, "{marker}");
        }

        // A readable one clears the flag.
        write(t.path(), "wp-includes/version.php", CZ_VERSION_PHP);
        let d = run(t.path());
        assert!(d.is_wordpress && !d.core_version_unknown);

        // Nothing WordPress about this root: not WordPress, nothing to report.
        let plain = tempfile::tempdir().expect("tmp");
        write(plain.path(), "index.php", "<?php");
        assert_eq!(run(plain.path()), Discovery::default());
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
            "wp-content/plugins/mine.php",
            "<?php\n/*\nPlugin Name: Mine\nVersion: 0.1\n*/\n",
        );
        write(
            t.path(),
            "wp-content/plugins/index.php",
            "<?php\n// Silence is golden.\n",
        );
        let d = run(t.path());
        assert_eq!(d.components.len(), 2, "{:?}", d.components);
        // wordpress.org knows Hello Dolly as `hello-dolly`; otherwise the slug
        // is the file stem.
        let c = find(&d, ComponentKind::Plugin, "hello-dolly");
        assert_eq!(c.key.version, "1.7.2");
        assert_eq!(c.rel_root, "wp-content/plugins/hello.php");
        assert!(c.single_file);
        assert_eq!(
            find(&d, ComponentKind::Plugin, "mine").rel_root,
            "wp-content/plugins/mine.php"
        );
        assert!(
            d.problems.iter().all(|p| p.contains("wp-includes")),
            "{:?}",
            d.problems
        );
    }

    #[test]
    fn single_file_component_resolves_to_its_manifest_entry() {
        use crate::sitescan::manifest::parse_plugin_checksums;
        let t = tempfile::tempdir().expect("tmp");
        write(
            t.path(),
            "wp-content/plugins/hello.php",
            "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n",
        );
        write(
            t.path(),
            "wp-content/plugins/demo/demo.php",
            "<?php\n/*\nPlugin Name: D\nVersion: 2\n*/\n",
        );
        let d = run(t.path());
        // What plugin-checksums/hello-dolly/1.7.2.json holds.
        let manifest = parse_plugin_checksums(
            r#"{"files":{"hello.php":{"md5":"0123456789abcdef0123456789abcdef"}}}"#,
        )
        .expect("manifest");
        let hello = find(&d, ComponentKind::Plugin, "hello-dolly");
        let key = hello
            .manifest_key("wp-content/plugins/hello.php")
            .expect("key");
        assert_eq!(key, "hello.php");
        assert!(manifest.contains_key(&key));
        assert_eq!(hello.manifest_key("wp-content/plugins/other.php"), None);
        assert_eq!(hello.manifest_key("wp-content/plugins/hello.php/x"), None);
        // A folder plugin's keys are relative to the folder.
        let demo = find(&d, ComponentKind::Plugin, "demo");
        assert_eq!(
            demo.manifest_key("wp-content/plugins/demo/lib/a.php")
                .as_deref(),
            Some("lib/a.php")
        );
        assert_eq!(demo.manifest_key("wp-content/plugins/demo"), None);
        assert_eq!(demo.manifest_key("wp-content/plugins/demo2/a.php"), None);
        // Core's keys are docroot paths.
        let core = Component {
            key: ComponentKey {
                kind: ComponentKind::Core,
                slug: "wordpress".into(),
                version: "6".into(),
                locale: None,
            },
            rel_root: String::new(),
            is_child_theme: false,
            single_file: false,
        };
        assert_eq!(
            core.manifest_key("wp-login.php").as_deref(),
            Some("wp-login.php")
        );
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
        write(t.path(), "wp-includes/version.php", CZ_VERSION_PHP);
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

    const HDR: &str = "<?php\n/*\nPlugin Name: P\nVersion: 1.0\n*/\n";

    #[test]
    fn unreadable_plugin_files_are_reported_not_dropped() {
        let t = tempfile::tempdir().expect("tmp");
        let plugins = t.path().join("wp-content/plugins");
        write(t.path(), "wp-content/plugins/real.php", HDR);
        // A hard-linked single-file plugin can't be opened by the scanner.
        write(t.path(), "wp-content/plugins/evil-src.txt", "x");
        std::fs::write(plugins.join("evil.php"), HDR).expect("w");
        std::fs::hard_link(plugins.join("evil.php"), t.path().join("evil-link.php")).expect("link");
        // A folder whose main file is a symlink.
        write(
            t.path(),
            "wp-content/plugins/dir/other.php",
            "<?php // none",
        );
        std::os::unix::fs::symlink("/etc/hostname", plugins.join("dir/dir.php")).expect("link");
        let d = run(t.path());
        let all = d.problems.join("\n");
        assert!(all.contains("plugins/evil.php could not be read"), "{all}");
        assert!(all.contains("plugins/dir/dir.php"), "{all}");
        assert!(d.components.iter().any(|c| c.key.slug == "real"));
    }

    #[test]
    fn big_plugin_folder_still_finds_its_main_file_and_says_it_was_cut_short() {
        let t = tempfile::tempdir().expect("tmp");
        let dir = t.path().join("wp-content/plugins/big");
        std::fs::create_dir_all(&dir).expect("mkdir");
        for i in 0..(LIST_CAP + 10) {
            std::fs::write(dir.join(format!("f{i:05}.txt")), b"x").expect("w");
        }
        std::fs::write(dir.join("big.php"), HDR).expect("w");
        let d = run(t.path());
        assert_eq!(find(&d, ComponentKind::Plugin, "big").key.version, "1.0");

        // 40 PHP files and no header anywhere: not silently "not a plugin".
        let t = tempfile::tempdir().expect("tmp");
        for i in 0..40 {
            write(
                t.path(),
                &format!("wp-content/plugins/many/f{i:02}.php"),
                "<?php // none",
            );
        }
        let d = run(t.path());
        assert!(d.components.is_empty());
        assert!(
            d.problems
                .iter()
                .any(|p| p.contains("more than 32 PHP files")),
            "{:?}",
            d.problems
        );
        // The listing cap itself is reported.
        let t = tempfile::tempdir().expect("tmp");
        let dir = t.path().join("wp-content/plugins/huge");
        std::fs::create_dir_all(&dir).expect("mkdir");
        for i in 0..(LIST_CAP + 10) {
            std::fs::write(dir.join(format!("f{i:05}.txt")), b"x").expect("w");
        }
        let d = run(t.path());
        assert!(
            d.problems
                .iter()
                .any(|p| p.contains("more than 5000 entries")),
            "{:?}",
            d.problems
        );
    }

    #[test]
    fn problems_are_capped_and_header_values_are_clean() {
        let mut d = Discovery::default();
        for i in 0..250 {
            d.note(format!("p{i}"));
        }
        assert_eq!(d.problems.len(), MAX_PROBLEMS + 1);
        assert_eq!(d.problems.last().map(String::as_str), Some("and more"));

        let long = "9".repeat(5000);
        let head = format!("/*\nPlugin Name: P\nVersion: 1.0\x07\x1b[31m{long}\n*/");
        let v = header_field(head.as_bytes(), Field::Version).expect("version");
        assert_eq!(v.chars().count(), MAX_HEADER_VALUE);
        assert!(v.chars().all(|c| !c.is_control()));
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
