//! A real client compromise as an acceptance test, plus the rules a per-site
//! scan has to keep. Every sample is synthetic and inert; real malware never
//! enters the repo.
//!
//! One stage of the incident is deliberately absent: the SEO spam URLs served
//! to Googlebot. They live in the database and in responses, not in files, so
//! the scan makes no claim about them (a non-goal in the design).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use hyperion_adapters::sitescan::baseline::{Baseline, BaselineEntry};
use hyperion_adapters::sitescan::discover::discover;
use hyperion_adapters::sitescan::manifest::{
    cache_path_for, ComponentKey, ComponentKind, Digest, Manifest, ManifestSource,
};
use hyperion_adapters::sitescan::rules::RULE_PACK_VERSION;
use hyperion_adapters::sitescan::scan::{
    metadata_hash, scan_site, ScanInput, ScanMode, SiteScanOutcome,
};
use hyperion_adapters::sitescan::TenantRoot;
use hyperion_types::{FindingKind, SiteFileFinding};
use md5::Md5;
use sha2::{Digest as _, Sha256};

const SHELL: &[u8] = include_bytes!("fixtures/sitescan/fake403_shell.php");
const EVAL: &[u8] = include_bytes!("fixtures/sitescan/fake_doctrine.php");
const JS_LOADER: &[u8] = include_bytes!("fixtures/sitescan/appended_js_loader.js");
const FOOTER: &[u8] = include_bytes!("fixtures/sitescan/functions_footer.php");
const CLEAN_FUNCTIONS: &[u8] = include_bytes!("fixtures/sitescan/clean_functions.php");

const WP_VERSION: &str = "6.8.1";
const NOW: i64 = 1_800_000_000;

fn sha_of(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn link_sha(target: &str) -> [u8; 32] {
    sha_of(format!("symlink:{target}").as_bytes())
}

fn md5_of(b: &[u8]) -> [u8; 16] {
    Md5::digest(b).into()
}

struct Site {
    _t: tempfile::TempDir,
    root: PathBuf,
    cache: PathBuf,
    baseline: PathBuf,
    known: Option<BTreeSet<String>>,
    /// What the agent would hand the scan as vouched for.
    trusted: std::cell::RefCell<BTreeMap<String, [u8; 32]>>,
}

impl Site {
    fn new() -> Site {
        let t = tempfile::tempdir().expect("tmp");
        let base = t.path().canonicalize().expect("canonical");
        let root = base.join("htdocs");
        fs::create_dir(&root).expect("mkdir");
        Site {
            root,
            cache: base.join("manifests"),
            baseline: base.join("baselines").join("7"),
            known: Some(BTreeSet::new()),
            trusted: Default::default(),
            _t: t,
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn write(&self, rel: &str, body: impl AsRef<[u8]>) {
        let p = self.path(rel);
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        fs::write(p, body).expect("write");
    }

    fn append(&self, rel: &str, body: &[u8]) {
        let mut all = fs::read(self.path(rel)).expect("read");
        all.extend_from_slice(body);
        fs::write(self.path(rel), all).expect("append");
    }

    fn rm(&self, rel: &str) {
        fs::remove_file(self.path(rel)).expect("rm");
    }

    /// Set a file's mtime back a year, as the attacker did.
    fn forge_mtime(&self, rel: &str) {
        fs::File::options()
            .write(true)
            .open(self.path(rel))
            .expect("open")
            .set_modified(SystemTime::now() - Duration::from_secs(365 * 86400))
            .expect("forge");
    }

    fn put_manifest(&self, key: &ComponentKey, manifest: &Manifest) {
        let p = cache_path_for(&self.cache, key, manifest.source).expect("cache path");
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        fs::write(p, serde_json::to_vec(manifest).expect("json")).expect("write");
    }

    /// A manifest listing `files` by SHA-256, as a theme ZIP produces.
    fn manifest(
        &self,
        kind: ComponentKind,
        slug: &str,
        version: &str,
        source: ManifestSource,
        files: &[(String, Vec<u8>)],
    ) {
        let key = ComponentKey {
            kind,
            slug: slug.into(),
            version: version.into(),
            locale: None,
        };
        let files = files
            .iter()
            .map(|(p, b)| (p.clone(), Digest::Sha256(sha_of(b))))
            .collect();
        self.put_manifest(
            &key,
            &Manifest {
                source,
                files,
                served_locale: None,
            },
        );
    }

    /// The core tree on disk and its manifest, MD5 like the real checksums API.
    /// The release ships `wp-content/` files, which are out of core's scope.
    fn wordpress(&self) {
        self.wordpress_with(None, None);
    }

    fn wordpress_with(&self, locale: Option<&str>, served: Option<&str>) {
        let local = locale
            .map(|l| format!("$wp_local_package = '{l}';\n"))
            .unwrap_or_default();
        let version_php = format!("<?php\n$wp_version = '{WP_VERSION}';\n{local}");
        let tree: Vec<(&str, Vec<u8>)> = vec![
            ("index.php", b"<?php // front\n".to_vec()),
            ("wp-load.php", b"<?php // load\n".to_vec()),
            ("wp-settings.php", b"<?php // settings\n".to_vec()),
            ("wp-includes/version.php", version_php.into_bytes()),
            ("wp-includes/load.php", b"<?php // helpers\n".to_vec()),
            ("wp-admin/admin.php", b"<?php // admin\n".to_vec()),
        ];
        let mut files: BTreeMap<String, Digest> = tree
            .iter()
            .map(|(p, b)| (p.to_string(), Digest::Md5(md5_of(b))))
            .collect();
        for (p, b) in &tree {
            self.write(p, b);
        }
        self.write("wp-config.php", "<?php // config\n");
        files.insert(
            "wp-content/plugins/akismet/akismet.php".into(),
            Digest::Md5(md5_of(b"not on this site")),
        );
        let key = ComponentKey {
            kind: ComponentKind::Core,
            slug: "wordpress".into(),
            version: WP_VERSION.into(),
            locale: locale.map(str::to_string),
        };
        self.put_manifest(
            &key,
            &Manifest {
                source: ManifestSource::WordPressOrg,
                files,
                served_locale: served.map(str::to_string),
            },
        );
    }

    /// A plugin on disk: its main file plus `files`. Returns every file with
    /// its content, relative to the plugin folder, for a manifest.
    fn plugin(&self, slug: &str, version: &str, files: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        let main = format!("<?php\n/*\nPlugin Name: {slug}\nVersion: {version}\n*/\n");
        let mut all = vec![(format!("{slug}.php"), main.into_bytes())];
        all.extend(files.iter().map(|(p, b)| (p.to_string(), b.to_vec())));
        for (p, b) in &all {
            self.write(&format!("wp-content/plugins/{slug}/{p}"), b);
        }
        all
    }

    fn verified_plugin(&self, slug: &str, version: &str, files: &[(&str, &[u8])]) {
        let all = self.plugin(slug, version, files);
        self.manifest(
            ComponentKind::Plugin,
            slug,
            version,
            ManifestSource::WordPressOrg,
            &all,
        );
    }

    /// Rewrite a plugin's main file to claim another version.
    fn bump(&self, slug: &str, version: &str) {
        self.write(
            &format!("wp-content/plugins/{slug}/{slug}.php"),
            format!("<?php\n/*\nPlugin Name: {slug}\nVersion: {version}\n*/\n"),
        );
    }

    fn child_theme(&self, slug: &str) {
        self.write(
            &format!("wp-content/themes/{slug}/style.css"),
            format!("/*\nTheme Name: {slug}\nTemplate: hello-elementor\nVersion: 1.0\n*/\n"),
        );
        self.write(
            &format!("wp-content/themes/{slug}/functions.php"),
            CLEAN_FUNCTIONS,
        );
    }

    fn scan_with(&self, mode: ScanMode, pause: &dyn Fn() -> bool) -> SiteScanOutcome {
        let root = TenantRoot::open(&self.root).expect("open");
        let input = ScanInput {
            root: self.root.clone(),
            discovery: discover(&root),
            manifests_dir: self.cache.clone(),
            baseline_path: self.baseline.clone(),
            mode,
            now: NOW,
            wporg_known_slugs: self.known.clone(),
            accept_since: None,
            trusted: self.trusted.borrow().clone(),
        };
        scan_site(&input, pause).expect("scan")
    }

    fn scan(&self) -> SiteScanOutcome {
        self.scan_with(ScanMode::Delta, &|| false)
    }

    fn load(&self) -> Baseline {
        Baseline::load(&self.baseline).expect("load").expect("some")
    }

    /// What the Trust action will do for a symlink: path plus the hash it reported.
    fn trust_link(&self, rel: &str, target: &str) {
        self.trusted
            .borrow_mut()
            .insert(rel.to_string(), link_sha(target));
    }

    fn trust(&self, rel: &str) {
        let body = fs::read(self.path(rel)).expect("read");
        self.trusted
            .borrow_mut()
            .insert(rel.to_string(), sha_of(&body));
    }
}

/// Past the window in which a just-written file counts as racy, so the next
/// scan's records are the real ctimes.
fn settle() {
    std::thread::sleep(Duration::from_millis(30));
}

#[track_caller]
fn item<'a>(list: &'a [SiteFileFinding], rel: &str) -> &'a SiteFileFinding {
    list.iter()
        .find(|f| f.rel == rel)
        .unwrap_or_else(|| panic!("{rel} not in {list:#?}"))
}

fn rels(list: &[SiteFileFinding]) -> Vec<&str> {
    list.iter().map(|f| f.rel.as_str()).collect()
}

fn incident_site() -> Site {
    let s = Site::new();
    s.wordpress();
    s.verified_plugin(
        "elementor",
        "3.25.0",
        &[(
            "assets/lib/swiper/swiper.min.js",
            b"/*! swiper */ var Swiper = 1;\n",
        )],
    );
    s.verified_plugin(
        "woocommerce",
        "9.4.0",
        &[(
            "assets/js/js-cookie/js.cookie.min.js",
            b"/*! js-cookie */ var Cookies = 1;\n",
        )],
    );
    s.child_theme("hello-child");
    s
}

/// Every file-based stage except the child theme edit, which needs a first scan
/// before it to be a change.
fn plant_incident(s: &Site) {
    s.append(
        "wp-content/plugins/elementor/assets/lib/swiper/swiper.min.js",
        JS_LOADER,
    );
    s.write("wp-config-modules.php", SHELL);
    s.write("wp-content/wp-config-modules.php", SHELL);
    s.write("wp-includes/class-wp-strongers.php", EVAL);
    s.forge_mtime("wp-includes/class-wp-strongers.php");
    s.write(
        "wp-content/plugins/woocommerce/includes/class-wc-x.php",
        EVAL,
    );
    s.append(
        "wp-content/plugins/woocommerce/assets/js/js-cookie/js.cookie.min.js",
        JS_LOADER,
    );
}

#[track_caller]
fn assert_incident_found(out: &SiteScanOutcome) {
    let f = &out.findings;
    let swiper = item(
        f,
        "wp-content/plugins/elementor/assets/lib/swiper/swiper.min.js",
    );
    assert_eq!(swiper.kind, FindingKind::UpstreamModified);
    assert_eq!(swiper.severity, "high");
    assert_eq!(swiper.component.as_deref(), Some("elementor"));
    assert_eq!(swiper.source_label.as_deref(), Some("wordpress.org"));
    // The rule's detail travels with the failed comparison.
    assert_eq!(swiper.rule_id.as_deref(), Some("js_self_removing_loader"));
    assert!(swiper
        .domains
        .iter()
        .any(|d| d == "malicious-loader.example"));

    let root_shell = item(f, "wp-config-modules.php");
    assert_eq!(root_shell.kind, FindingKind::CoreUnexpected);
    assert_eq!(root_shell.rule_id.as_deref(), Some("webshell_marker"));

    let content_shell = item(f, "wp-content/wp-config-modules.php");
    assert_eq!(content_shell.kind, FindingKind::RuleHit);
    assert_eq!(content_shell.severity, "high");
    assert_eq!(content_shell.rule_id.as_deref(), Some("webshell_marker"));

    let strongers = item(f, "wp-includes/class-wp-strongers.php");
    assert_eq!(strongers.kind, FindingKind::CoreUnexpected);
    assert_eq!(strongers.rule_id.as_deref(), Some("eval_decoder"));
    assert_eq!(strongers.sha256, hex::encode(sha_of(EVAL)));

    let added = item(f, "wp-content/plugins/woocommerce/includes/class-wc-x.php");
    assert_eq!(added.kind, FindingKind::UpstreamAdded);

    let cookie = item(
        f,
        "wp-content/plugins/woocommerce/assets/js/js-cookie/js.cookie.min.js",
    );
    assert_eq!(cookie.kind, FindingKind::UpstreamModified);

    let up = &out.upstream;
    assert!(up.ran);
    assert!(up
        .core_unexpected
        .contains(&"wp-config-modules.php".to_string()));
    assert!(up
        .core_unexpected
        .contains(&"wp-includes/class-wp-strongers.php".to_string()));
    let woo = up
        .plugins_failed
        .iter()
        .find(|p| p.slug == "woocommerce")
        .expect("woocommerce failed");
    assert_eq!(woo.issues.len(), 2);
}

#[test]
fn every_stage_of_the_incident_is_found() {
    let s = incident_site();
    let first = s.scan();
    assert_eq!(rels(&first.findings), Vec::<&str>::new());
    assert_eq!(rels(&first.review), Vec::<&str>::new());
    assert_eq!(first.coverage.partial_reasons, Vec::<String>::new());
    assert_eq!(first.coverage.plugins_verified, 2);

    settle();
    plant_incident(&s);
    s.write("wp-content/themes/hello-child/functions.php", FOOTER);
    s.forge_mtime("wp-content/themes/hello-child/functions.php");

    let out = s.scan();
    assert_incident_found(&out);
    let footer = item(&out.findings, "wp-content/themes/hello-child/functions.php");
    assert_eq!(footer.kind, FindingKind::RuleHit);
    assert_eq!(footer.severity, "high");
    assert_eq!(footer.rule_id.as_deref(), Some("footer_hook_payload"));
    assert_eq!(footer.component.as_deref(), Some("hello-child"));

    // Nothing is forgotten on the scan after: they are all still there.
    let again = s.scan();
    assert_incident_found(&again);
    item(
        &again.findings,
        "wp-content/themes/hello-child/functions.php",
    );
}

#[test]
fn a_site_already_infected_at_its_first_scan_is_not_blessed() {
    let s = incident_site();
    s.write("wp-content/themes/hello-child/functions.php", FOOTER);
    plant_incident(&s);
    let out = s.scan();
    assert_incident_found(&out);
    let footer = item(&out.findings, "wp-content/themes/hello-child/functions.php");
    assert_eq!(footer.kind, FindingKind::RuleHit);
    // Bad files stay out of the baseline, so the next scan reports them too.
    let b = s.load();
    assert!(!b.entries.contains_key("wp-content/wp-config-modules.php"));
    assert!(!b
        .entries
        .contains_key("wp-content/themes/hello-child/functions.php"));
    assert_incident_found(&s.scan());
}

#[test]
fn forged_mtime_on_a_same_size_rewrite_is_still_found() {
    let s = incident_site();
    let rel = "wp-content/themes/hello-child/functions.php";
    s.write(rel, "<?php // aaaa\n");
    s.scan();
    settle();
    let before = fs::metadata(s.path(rel)).expect("stat");
    s.write(rel, "<?php // bbbb\n");
    fs::File::options()
        .write(true)
        .open(s.path(rel))
        .expect("open")
        .set_modified(before.modified().expect("mtime"))
        .expect("forge");
    let out = s.scan();
    assert_eq!(item(&out.review, rel).kind, FindingKind::BaselineChange);
}

#[test]
fn no_php_is_executed() {
    let s = Site::new();
    let dir = s._t.path().canonicalize().expect("canonical");
    let marker = dir.join("marker");
    let payload = format!("<?php file_put_contents('{}', 'ran');\n", marker.display());
    s.wordpress();
    s.write("wp-config.php", &payload);
    s.write(
        "wp-content/plugins/evil/evil.php",
        format!("<?php\n/*\nPlugin Name: evil\nVersion: 1.0\n*/\n{payload}"),
    );
    s.write(
        "wp-content/themes/t/style.css",
        "/*\nTheme Name: t\nVersion: 1.0\n*/\n",
    );
    s.write("wp-content/themes/t/functions.php", &payload);

    // A `php` or `wp` found on PATH would leave the marker too.
    let bin = dir.join("bin");
    fs::create_dir(&bin).expect("mkdir");
    for name in ["php", "wp"] {
        use std::os::unix::fs::PermissionsExt;
        let p = bin.join(name);
        fs::write(&p, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).expect("write");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let old = std::env::var_os("PATH").unwrap_or_default();
    std::env::set_var("PATH", &bin);
    s.scan();
    s.scan_with(ScanMode::FullRehash, &|| false);
    std::env::set_var("PATH", old);

    assert!(!marker.exists(), "something ran the tenant's PHP");
    // And nothing in the scanner can start a tenant's interpreter. The only
    // program any module runs is curl, in the agent's fetch step; the module the
    // worker scans with runs none.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sitescan");
    let mut modules = 0;
    for ent in fs::read_dir(dir).expect("ls") {
        let path = ent.expect("entry").path();
        let src = fs::read_to_string(&path).expect("read");
        let code = src.split("#[cfg(test)]").next().expect("code");
        modules += 1;
        let spawns = code.matches("Command::new(").count();
        let curl = code.matches("Command::new(CURL)").count();
        if path.ends_with("runner.rs") {
            // The agent's side of the worker: systemd-run, nice, and the agent's
            // own binary. It never touches a tenant's tree, and the worker it
            // starts is what the scan runs in.
            let own = [
                "Command::new(SYSTEMD_RUN)",
                "Command::new(NICE)",
                "Command::new(exe)",
            ]
            .map(|c| code.matches(c).count());
            assert_eq!(own, [1, 1, 1], "runner.rs spawns something else");
            assert_eq!(spawns, 3, "runner.rs spawns something else");
            continue;
        }
        assert_eq!(spawns, curl, "{} spawns something else", path.display());
        assert_eq!(
            code.matches("process::").count(),
            curl,
            "{} reaches for processes",
            path.display()
        );
        if path.ends_with("scan.rs") {
            assert_eq!(spawns, 0, "scan.rs spawns a process");
        }
    }
    assert!(modules >= 6, "{modules}");
}

#[test]
fn first_scan_runs_rules_over_everything() {
    let s = Site::new();
    s.wordpress();
    s.plugin(
        "premium",
        "1.0",
        &[("lib/a.php", EVAL), ("lib/b.php", b"<?php // b\n")],
    );
    s.write("wp-content/mu-plugins/m.php", SHELL);
    // A big encoded literal alone is Medium: reported in the lower bucket.
    let big = format!("<?php $x = '{}';\n", "QUJD".repeat(1000));
    s.write("wp-content/mu-plugins/encoded.php", &big);
    let out = s.scan();
    let a = item(&out.findings, "wp-content/plugins/premium/lib/a.php");
    assert_eq!(a.kind, FindingKind::RuleHit);
    assert_eq!(a.line, 2);
    item(&out.findings, "wp-content/mu-plugins/m.php");
    let e = item(&out.review, "wp-content/mu-plugins/encoded.php");
    assert_eq!(e.kind, FindingKind::RuleHit);
    assert_eq!(e.severity, "medium");
    let b = s.load();
    assert!(b
        .entries
        .contains_key("wp-content/plugins/premium/lib/b.php"));
    assert!(!b
        .entries
        .contains_key("wp-content/plugins/premium/lib/a.php"));
    assert!(!b.entries.contains_key("wp-content/mu-plugins/encoded.php"));
    assert_eq!(b.since, NOW);
    assert_eq!(b.rule_pack, RULE_PACK_VERSION);
}

#[test]
fn first_scan_does_not_report_changes() {
    let s = Site::new();
    s.wordpress();
    s.plugin(
        "premium",
        "1.0",
        &[("a.php", b"<?php // a\n"), ("a.js", b"var a;\n")],
    );
    s.child_theme("kid");
    s.write("custom.php", "<?php // site's own\n");
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    assert!(out.coverage.files_watched > 0);
    assert_eq!(out.coverage.watching_since, NOW);
}

#[test]
fn premium_plugin_change_without_rule_is_review_not_finding() {
    let s = Site::new();
    s.wordpress();
    s.plugin("premium", "1.0", &[("a.php", b"<?php // a\n")]);
    let first = s.scan();
    assert_eq!(first.upstream.plugins_unknown, vec!["premium".to_string()]);
    settle();
    let rel = "wp-content/plugins/premium/a.php";
    s.write(rel, "<?php // edited\n");
    let out = s.scan();
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    let r = item(&out.review, rel);
    assert_eq!(r.kind, FindingKind::BaselineChange);
    assert_eq!(r.component.as_deref(), Some("premium"));
    assert_eq!(r.sha256, hex::encode(sha_of(b"<?php // edited\n")));
    assert!(out.auto_accepted.is_empty());
    assert_eq!(s.scan().review.len(), 1);
}

#[test]
fn premium_version_bump_auto_accepted_when_slug_unknown_to_wporg() {
    let s = Site::new();
    s.wordpress();
    s.plugin(
        "premium",
        "1.0",
        &[("a.php", b"<?php // a\n"), ("b.php", b"<?php // b\n")],
    );
    s.scan();
    settle();
    s.bump("premium", "1.1");
    s.write("wp-content/plugins/premium/a.php", "<?php // a2\n");
    s.write("wp-content/plugins/premium/new.php", "<?php // new\n");
    s.write("wp-content/plugins/premium/bad.php", EVAL);
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    // Rule hits behave normally.
    assert_eq!(rels(&out.findings), ["wp-content/plugins/premium/bad.php"]);
    let mut accepted = out.auto_accepted.clone();
    accepted.sort();
    assert_eq!(
        accepted,
        [
            "wp-content/plugins/premium/a.php",
            "wp-content/plugins/premium/new.php",
            "wp-content/plugins/premium/premium.php",
        ]
    );
    assert_eq!(s.load().components["plugin/premium"], "1.1");

    // The pass was for that one update: the next edit is a normal change.
    settle();
    s.write("wp-content/plugins/premium/a.php", "<?php // a3\n");
    let next = s.scan();
    assert_eq!(rels(&next.review), ["wp-content/plugins/premium/a.php"]);
    assert!(next.auto_accepted.is_empty());
}

#[test]
fn a_newly_installed_premium_plugin_gets_no_pass() {
    // A dropper with a made-up header is not an update.
    let s = Site::new();
    s.wordpress();
    s.scan();
    settle();
    s.plugin("fresh", "1.0", &[("a.php", b"<?php // a\n")]);
    let out = s.scan();
    assert!(out.auto_accepted.is_empty());
    item(&out.review, "wp-content/plugins/fresh/a.php");
}

#[test]
fn dropping_the_version_header_gets_no_pass() {
    let s = Site::new();
    s.wordpress();
    s.plugin("premium", "1.0", &[("a.php", b"<?php // a\n")]);
    s.scan();
    settle();
    s.write(
        "wp-content/plugins/premium/premium.php",
        "<?php\n/*\nPlugin Name: premium\n*/\n",
    );
    s.write("wp-content/plugins/premium/a.php", "<?php // a2\n");
    let out = s.scan();
    assert!(out.auto_accepted.is_empty());
    item(&out.review, "wp-content/plugins/premium/a.php");
}

#[test]
fn a_theme_sharing_a_plugins_slug_does_not_look_like_an_update() {
    // Recorded per slug alone, the two versions would differ on every scan and
    // the plugin would get the update pass forever.
    let s = Site::new();
    s.wordpress();
    s.plugin("astra", "1.0", &[("a.php", b"<?php // a\n")]);
    s.write(
        "wp-content/themes/astra/style.css",
        "/*\nTheme Name: astra\nVersion: 2.0\n*/\n",
    );
    s.scan();
    settle();
    s.write("wp-content/plugins/astra/a.php", "<?php // edited\n");
    let out = s.scan();
    assert!(out.auto_accepted.is_empty());
    item(&out.review, "wp-content/plugins/astra/a.php");
}

#[test]
fn wporg_slug_with_no_manifest_goes_to_review_after_retry() {
    let mut s = Site::new();
    s.known = Some(BTreeSet::from(["free".to_string()]));
    s.wordpress();
    s.plugin("free", "1.0", &[("a.php", b"<?php // a\n")]);
    assert_eq!(s.scan().upstream.plugins_unknown, vec!["free".to_string()]);
    settle();
    // Claims a version wordpress.org has no checksums for.
    s.bump("free", "9.9");
    s.write("wp-content/plugins/free/a.php", "<?php // edited\n");
    for _ in 0..2 {
        let out = s.scan();
        assert!(out.auto_accepted.is_empty());
        assert_eq!(out.upstream.plugins_unknown, vec!["free".to_string()]);
        let r = item(&out.review, "wp-content/plugins/free/a.php");
        assert_eq!(r.kind, FindingKind::BaselineChange);
        item(&out.review, "wp-content/plugins/free/free.php");
    }
    // The agent's retry finds a manifest: now it is compared, and it fails.
    s.manifest(
        ComponentKind::Plugin,
        "free",
        "9.9",
        ManifestSource::WordPressOrg,
        &[
            (
                "free.php".into(),
                fs::read(s.path("wp-content/plugins/free/free.php")).unwrap(),
            ),
            ("a.php".into(), b"<?php // the real one\n".to_vec()),
        ],
    );
    let out = s.scan();
    assert_eq!(out.coverage.plugins_verified, 1);
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_eq!(
        item(&out.findings, "wp-content/plugins/free/a.php").kind,
        FindingKind::UpstreamModified
    );
}

fn twenty_files() -> Vec<(String, Vec<u8>)> {
    (0..19)
        .map(|i| {
            (
                format!("inc/f{i}.php"),
                format!("<?php // {i}\n").into_bytes(),
            )
        })
        .collect()
}

fn borrowed(files: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    files
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect()
}

#[test]
fn slug_collision_groups_to_one_finding() {
    // A private plugin in a wordpress.org slug's folder: nothing lines up.
    let s = Site::new();
    s.wordpress();
    let upstream = s.plugin("contact", "2.0", &borrowed(&twenty_files()));
    s.manifest(
        ComponentKind::Plugin,
        "contact",
        "2.0",
        ManifestSource::WordPressOrg,
        &upstream,
    );
    for (i, (p, _)) in twenty_files().iter().enumerate() {
        let rel = format!("wp-content/plugins/contact/{p}");
        if i < 5 {
            s.rm(&rel);
        } else {
            s.write(&rel, format!("<?php // ours {i}\n"));
        }
    }
    for i in 0..200 {
        s.write(
            &format!("wp-content/plugins/contact/own/o{i}.php"),
            "<?php\n",
        );
    }
    let out = s.scan();
    assert_eq!(out.findings.len(), 1, "{:?}", rels(&out.findings));
    let f = &out.findings[0];
    assert_eq!(f.rel, "wp-content/plugins/contact");
    assert_eq!(f.kind, FindingKind::UpstreamModified);
    assert_eq!(f.severity, "high");
    assert_eq!(f.component.as_deref(), Some("contact"));
    assert_eq!(f.source_label.as_deref(), Some("wordpress.org"));
    assert!(f.snippet.contains("19 of 20"), "{}", f.snippet);
    assert!(f.snippet.contains("200 added"), "{}", f.snippet);
    assert_eq!(out.upstream.plugins_failed.len(), 1);
    assert_eq!(out.upstream.plugins_failed[0].issues.len(), 1);
    assert_eq!(rels(&out.review), Vec::<&str>::new());
}

#[test]
fn mass_injection_is_one_high_finding() {
    let s = Site::new();
    s.wordpress();
    let files = twenty_files();
    s.verified_plugin("big", "1.0", &borrowed(&files));
    for (p, _) in files.iter().take(11) {
        s.append(&format!("wp-content/plugins/big/{p}"), EVAL);
    }
    let out = s.scan();
    assert_eq!(rels(&out.findings), ["wp-content/plugins/big"]);
    let f = &out.findings[0];
    assert_eq!(f.severity, "high");
    assert_eq!(f.rule_id.as_deref(), Some("eval_decoder"));
    assert!(f.snippet.contains("11 of 20"), "{}", f.snippet);
}

#[test]
fn mass_tampering_of_core_is_one_finding_too() {
    let s = Site::new();
    s.wordpress();
    let files = (0..12)
        .map(|i| (format!("wp-includes/f{i}.php"), Digest::Md5([0; 16])))
        .collect();
    let key = ComponentKey {
        kind: ComponentKind::Core,
        slug: "wordpress".into(),
        version: WP_VERSION.into(),
        locale: None,
    };
    s.put_manifest(
        &key,
        &Manifest {
            source: ManifestSource::WordPressOrg,
            files,
            served_locale: None,
        },
    );
    let out = s.scan();
    // Everything on disk is unexpected and everything listed is missing.
    assert_eq!(rels(&out.findings), ["."]);
    assert_eq!(out.findings[0].kind, FindingKind::CoreModified);
    assert_eq!(out.findings[0].severity, "high");
    assert_eq!(out.upstream.core_modified, ["."]);
    assert!(out.upstream.core_missing.is_empty());
}

#[test]
fn half_or_fewer_files_differing_stays_per_file() {
    let s = Site::new();
    s.wordpress();
    let files = twenty_files();
    s.verified_plugin("big", "1.0", &borrowed(&files));
    for (p, _) in files.iter().take(10) {
        s.append(&format!("wp-content/plugins/big/{p}"), b"// x\n");
    }
    assert_eq!(s.scan().findings.len(), 10);
}

#[test]
fn under_ten_manifest_files_never_group() {
    let s = Site::new();
    s.wordpress();
    let files: Vec<(&str, &[u8])> = vec![("a.php", b"<?php // a\n"), ("b.php", b"<?php // b\n")];
    s.verified_plugin("small", "1.0", &files);
    s.append("wp-content/plugins/small/a.php", b"// x\n");
    s.append("wp-content/plugins/small/b.php", b"// x\n");
    assert_eq!(s.scan().findings.len(), 2);
}

#[test]
fn trusted_hash_clears_review() {
    let s = incident_site();
    s.scan();
    settle();
    let rel = "wp-content/themes/hello-child/functions.php";
    s.write(rel, "<?php // dev edit\n");
    assert_eq!(rels(&s.scan().review), [rel]);
    s.trust(rel);
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    let e = &s.load().entries[rel];
    assert_eq!(e.sha256, sha_of(b"<?php // dev edit\n"));

    // Trust covers a rule hit too: a person looked and said it's fine.
    settle();
    let shell = "wp-content/mu-plugins/tool.php";
    s.write(shell, SHELL);
    item(&s.scan().findings, shell);
    s.trust(shell);
    assert_eq!(rels(&s.scan().findings), Vec::<&str>::new());
}

#[test]
fn trust_does_not_clear_upstream_failure() {
    let s = incident_site();
    let rel = "wp-content/plugins/elementor/assets/lib/swiper/swiper.min.js";
    s.append(rel, JS_LOADER);
    s.scan();
    s.trust(rel);
    let out = s.scan();
    assert_eq!(item(&out.findings, rel).kind, FindingKind::UpstreamModified);
    assert!(!s.load().entries.contains_key(rel));
}

#[test]
fn trusted_then_changed_flags_again() {
    let s = incident_site();
    s.scan();
    settle();
    let rel = "wp-content/themes/hello-child/functions.php";
    s.write(rel, "<?php // one\n");
    s.scan();
    s.trust(rel);
    assert_eq!(rels(&s.scan().review), Vec::<&str>::new());
    settle();
    s.write(rel, "<?php // two\n");
    assert_eq!(
        item(&s.scan().review, rel).kind,
        FindingKind::BaselineChange
    );
}

#[test]
fn pending_item_persists_across_scans() {
    let s = incident_site();
    s.scan();
    settle();
    let changed = "wp-content/themes/hello-child/functions.php";
    let added = "wp-content/themes/hello-child/extra.php";
    s.write(changed, "<?php // edited\n");
    s.write(added, "<?php // new\n");
    for _ in 0..3 {
        let out = s.scan();
        assert_eq!(out.review.len(), 2, "{:?}", rels(&out.review));
        item(&out.review, changed);
        item(&out.review, added);
    }
    // A pending file is compared with its old entry, not its last state:
    // putting the old content back ends it.
    s.write(changed, CLEAN_FUNCTIONS);
    assert_eq!(rels(&s.scan().review), [added]);
    // Removing one that never entered the baseline ends it too.
    s.rm(added);
    assert_eq!(rels(&s.scan().review), Vec::<&str>::new());
}

#[test]
fn broken_wordpress_is_not_clean() {
    // Unparsable version.
    let s = Site::new();
    s.wordpress();
    s.write("wp-includes/version.php", "<?php // what version?\n");
    let out = s.scan();
    assert!(!out.upstream.ran);
    assert!(!out.coverage.upstream_ran);
    assert!(!out.coverage.no_upstream);
    assert!(!out.coverage.partial_reasons.is_empty());
    // Everything still gets rules: core just can't be compared.
    s.write("wp-includes/shell.php", SHELL);
    item(&s.scan().findings, "wp-includes/shell.php");

    // Partly installed: wp-content and nothing else.
    let s = Site::new();
    s.write("wp-content/index.php", "<?php\n");
    let out = s.scan();
    assert!(!out.upstream.ran);
    assert!(!out.coverage.partial_reasons.is_empty());

    // No manifest in the cache for a readable version.
    let s = Site::new();
    s.write("wp-includes/version.php", "<?php\n$wp_version = '6.8.1';\n");
    s.write("wp-config.php", "<?php\n");
    let out = s.scan();
    assert!(!out.upstream.ran);
    assert!(
        out.coverage
            .partial_reasons
            .iter()
            .any(|r| r.contains("6.8.1")),
        "{:?}",
        out.coverage.partial_reasons
    );

    // A damaged manifest is the same as none, and says so.
    let s = Site::new();
    s.wordpress();
    let key = ComponentKey {
        kind: ComponentKind::Core,
        slug: "wordpress".into(),
        version: WP_VERSION.into(),
        locale: None,
    };
    let p = cache_path_for(&s.cache, &key, ManifestSource::WordPressOrg).expect("path");
    fs::write(p, "{not json").expect("write");
    let out = s.scan();
    assert!(!out.upstream.ran);
    assert!(!out.coverage.partial_reasons.is_empty());
}

#[test]
fn wp_config_above_the_docroot_is_not_clean() {
    let s = Site::new();
    s.wordpress();
    s.rm("wp-config.php");
    let out = s.scan();
    assert!(out.upstream.ran);
    assert!(
        out.coverage
            .partial_reasons
            .iter()
            .any(|r| r.contains("wp-config.php")),
        "{:?}",
        out.coverage.partial_reasons
    );
}

#[test]
fn non_wp_site_watches_php_not_vendor_js() {
    let s = Site::new();
    s.write("index.php", "<?php // app\n");
    s.write("public/.htaccess", "Require all granted\n");
    s.write("assets/app.js", "var a;\n");
    s.write("vendor/acme/lib.php", "<?php // lib\n");
    s.write("vendor/acme/lib.js", "var l;\n");
    s.write("web/node_modules/x/y.js", "var y;\n");
    let first = s.scan();
    assert!(first.coverage.no_upstream);
    assert!(!first.coverage.upstream_ran);
    assert!(!first.upstream.ran);
    assert_eq!(first.coverage.partial_reasons, Vec::<String>::new());
    let b = s.load();
    let watched: Vec<&str> = b.entries.keys().map(String::as_str).collect();
    assert_eq!(watched, ["index.php", "public/.htaccess"]);

    settle();
    s.scan();
    settle();
    // Rules-only files that didn't change aren't read again.
    assert_eq!(s.scan().files_hashed, 0);

    // Edits raise nothing where there is no change detection...
    s.write("assets/app.js", "var a2;\n");
    s.write("vendor/acme/lib.php", "<?php // lib2\n");
    s.write("vendor/acme/lib.js", "var l2;\n");
    s.write("index.php", "<?php // edited\n");
    let out = s.scan();
    assert_eq!(rels(&out.review), ["index.php"]);
    assert_eq!(rels(&out.findings), Vec::<&str>::new());

    // ...but the rules still run there, and a hit stays reported.
    s.write("vendor/acme/lib.php", EVAL);
    s.write("web/node_modules/x/y.js", JS_LOADER);
    for _ in 0..2 {
        let out = s.scan();
        assert_eq!(
            item(&out.findings, "vendor/acme/lib.php").kind,
            FindingKind::RuleHit
        );
        item(&out.findings, "web/node_modules/x/y.js");
    }
}

#[test]
fn churn_paths_get_rules_but_no_change_detection() {
    let s = Site::new();
    s.wordpress();
    s.write("wp-content/cache/page.php", "<?php // cached\n");
    s.write("wp-content/cache/page.js", EVAL);
    s.write("wp-content/uploads/2026/a.js", JS_LOADER);
    s.write("wp-content/uploads/2026/a.jpg", SHELL);
    s.write("wp-content/upgrade/x/y.php", SHELL);
    let out = s.scan();
    // PHP-like in a churn path: rules. Anything else there: not looked at.
    assert_eq!(rels(&out.findings), ["wp-content/upgrade/x/y.php"]);
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    let b = s.load();
    assert!(
        b.entries.keys().all(|k| !k.starts_with("wp-content/")),
        "{:?}",
        b.entries
    );

    settle();
    s.write("wp-content/cache/page.php", "<?php // cached again\n");
    assert_eq!(rels(&s.scan().review), Vec::<&str>::new());
    s.write("wp-content/cache/page.php", EVAL);
    assert_eq!(
        item(&s.scan().findings, "wp-content/cache/page.php").kind,
        FindingKind::RuleHit
    );
}

#[test]
fn php_in_uploads_is_reported_until_dealt_with() {
    let s = Site::new();
    s.wordpress();
    s.write("wp-content/uploads/2026/x.php", "<?php // looks harmless\n");
    s.write(
        "wp-content/uploads/2026/x.php.jpg",
        "<?php // so does this\n",
    );
    for _ in 0..2 {
        let out = s.scan();
        let f = item(&out.findings, "wp-content/uploads/2026/x.php");
        assert_eq!(f.rule_id.as_deref(), Some("php_in_uploads"));
        item(&out.findings, "wp-content/uploads/2026/x.php.jpg");
    }
}

#[test]
fn verified_tree_files_are_not_rule_inspected() {
    // Upstream's own file that happens to trip a rule: the comparison speaks for it.
    let s = Site::new();
    s.wordpress();
    s.verified_plugin("odd", "1.0", &[("lib/compat.php", EVAL)]);
    let out = s.scan();
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_eq!(
        s.load().verified["wp-content/plugins/odd/lib/compat.php"],
        "plugin/odd@1.0"
    );
}

#[test]
fn rule_pack_bump_reinspects_once() {
    let s = Site::new();
    s.wordpress();
    s.plugin(
        "premium",
        "1.0",
        &[("a.php", b"<?php // a\n"), ("b.php", EVAL)],
    );
    s.write("wp-content/mu-plugins/m.php", "<?php // m\n");
    s.write("wp-content/cache/c.php", "<?php // c\n");
    settle();
    s.scan();
    settle();
    s.scan();

    // An entry an older pack passed, which today's pack catches.
    let rel = "wp-content/plugins/premium/b.php";
    let md = fs::metadata(s.path(rel)).expect("stat");
    let mut b = s.load();
    assert!(!b.entries.contains_key(rel));
    b.entries.insert(
        rel.to_string(),
        BaselineEntry {
            size: md.len(),
            ctime: md.ctime(),
            ctime_nsec: md.ctime_nsec(),
            sha256: sha_of(EVAL),
        },
    );
    b.rule_pack = RULE_PACK_VERSION - 1;
    b.save_atomic(&s.baseline).expect("save");

    let out = s.scan();
    assert_eq!(item(&out.findings, rel).kind, FindingKind::RuleHit);
    // Layer B scope, churn paths included, was read again; verified core wasn't.
    assert!(out.files_hashed >= 4, "{}", out.files_hashed);
    let b = s.load();
    assert_eq!(b.rule_pack, RULE_PACK_VERSION);
    assert!(!b.entries.contains_key(rel));
    assert!(b.entries.contains_key("wp-content/mu-plugins/m.php"));

    // Once: only the pending file is read from now on.
    let out = s.scan();
    assert_eq!(out.files_hashed, 1);
    item(&out.findings, rel);
}

#[test]
fn hard_linked_php_is_reported() {
    let s = Site::new();
    s.wordpress();
    s.write("wp-content/mu-plugins/real.php", SHELL);
    fs::hard_link(
        s.path("wp-content/mu-plugins/real.php"),
        s.path("wp-content/mu-plugins/link.php"),
    )
    .expect("link");
    s.write("wp-content/data.bin", "x");
    fs::hard_link(
        s.path("wp-content/data.bin"),
        s.path("wp-content/data2.bin"),
    )
    .expect("link");
    s.write("wp-content/app.js", "var a;\n");
    fs::hard_link(s.path("wp-content/app.js"), s.path("wp-content/app2.js")).expect("link");
    let out = s.scan();
    assert_eq!(
        out.files_hashed,
        6 + 1,
        "core plus wp-config, nothing linked"
    );
    let r = item(&out.review, "wp-content/mu-plugins/link.php");
    assert_eq!(r.kind, FindingKind::BaselineChange);
    assert_eq!(r.sha256, "");
    assert!(r.snippet.contains("hard"), "{}", r.snippet);
    item(&out.review, "wp-content/mu-plugins/real.php");
    // Any file type in scope, by name; a data file only counts.
    item(&out.review, "wp-content/app.js");
    item(&out.review, "wp-content/app2.js");
    assert_eq!(out.review.len(), 4, "{:?}", rels(&out.review));
    assert!(out
        .coverage
        .partial_reasons
        .iter()
        .any(|r| r.contains("hard-linked")));
}

#[test]
fn a_skipped_core_file_is_not_called_missing() {
    let s = Site::new();
    s.wordpress();
    s.rm("wp-includes/load.php");
    std::os::unix::fs::symlink("/etc/passwd", s.path("wp-includes/load.php")).expect("symlink");
    let out = s.scan();
    assert!(!out
        .upstream
        .core_missing
        .contains(&"wp-includes/load.php".to_string()));
    assert_eq!(
        item(&out.review, "wp-includes/load.php").kind,
        FindingKind::CoreModified
    );
    assert_says_unchecked(&out);
}

#[test]
fn symlinks_are_named_when_php_and_counted_otherwise() {
    let s = Site::new();
    s.wordpress();
    let link = |target: &str, rel: &str| {
        let p = s.path(rel);
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::os::unix::fs::symlink(target, p).expect("symlink");
    };
    link("/tmp/evil.php", "wp-content/mu-plugins/loader.php");
    link("/tmp/evil", ".maintenance");
    link("../shared/uploads", "wp-content/uploads");
    link("/tmp/x.txt", "wp-content/notes.txt");
    let out = s.scan();
    let r = item(&out.review, "wp-content/mu-plugins/loader.php");
    assert_eq!(r.kind, FindingKind::BaselineChange);
    assert_eq!(r.sha256, hex::encode(link_sha("/tmp/evil.php")));
    assert!(r.snippet.contains("/tmp/evil.php"), "{}", r.snippet);
    item(&out.review, ".maintenance");
    assert_eq!(out.review.len(), 2, "{:?}", rels(&out.review));
    assert_eq!(out.coverage.symlinks_skipped, 2);
    // A git-deploy `uploads` link is an ordinary site, not a partial scan. The
    // others point at absolute paths, which are never looked at to tell a
    // directory from a file, so they count as possible directories.
    let reasons = out.coverage.partial_reasons.join(" ");
    assert_eq!(out.coverage.partial_reasons.len(), 1, "{reasons}");
    assert!(!reasons.contains("uploads"), "{reasons}");
    assert!(reasons.contains("notes.txt"), "{reasons}");
}

#[test]
fn stop_keeps_unvisited_entries() {
    let s = Site::new();
    for i in 0..600 {
        s.write(&format!("app/f{i}.php"), format!("<?php // {i}\n"));
    }
    s.scan();
    assert_eq!(s.load().entries.len(), 600);
    s.rm("app/f7.php");

    let calls = Cell::new(0);
    let stop = || {
        calls.set(calls.get() + 1);
        true
    };
    let out = s.scan_with(ScanMode::Delta, &stop);
    assert_eq!(calls.get(), 1, "stop means stop");
    assert!(out.stopped);
    assert!(!out.coverage.partial_reasons.is_empty());
    assert_eq!(s.load().entries.len(), 600);

    // The next full walk is what notices the deletion.
    let out = s.scan();
    assert!(!out.stopped);
    assert_eq!(s.load().entries.len(), 599);
    assert_eq!(rels(&out.review), Vec::<&str>::new());
}

#[test]
fn an_interrupted_first_scan_resumes_as_a_first_scan() {
    let s = Site::new();
    for i in 0..600 {
        s.write(&format!("app/f{i}.php"), format!("<?php // {i}\n"));
    }
    let out = s.scan_with(ScanMode::Delta, &|| true);
    assert!(out.stopped);
    let partway = s.load();
    assert!(partway.entries.len() < 600);
    assert!(!partway.first_done);

    // What the first run never reached are not new files.
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    let b = s.load();
    assert_eq!(b.entries.len(), 600);
    assert!(b.first_done);
    assert_eq!(b.since, NOW);
}

#[test]
fn the_baseline_is_flushed_during_the_scan() {
    let s = Site::new();
    for i in 0..600 {
        s.write(&format!("app/f{i}.php"), format!("<?php // {i}\n"));
    }
    let mut counts = Vec::new();
    let seen = std::cell::RefCell::new(&mut counts);
    let path = s.baseline.clone();
    s.scan_with(ScanMode::Delta, &|| {
        // A worker killed here resumes from what was flushed.
        let n = Baseline::load(&path)
            .expect("load")
            .map(|b| b.entries.len());
        seen.borrow_mut().push(n);
        false
    });
    // Asked at 256 and 512 files: nothing flushed yet, then the first 500.
    assert_eq!(counts, vec![None, Some(500)]);
}

#[test]
fn repeat_scan_reads_no_file_contents() {
    let s = incident_site();
    s.write("wp-content/mu-plugins/m.php", "<?php // m\n");
    s.write("wp-content/cache/c.php", "<?php // c\n");
    // Unused types are not hashed at all.
    s.write("wp-content/uploads/2026/a.jpg", "jpeg");
    settle();
    let first = s.scan();
    assert!(first.files_hashed > 10, "{}", first.files_hashed);
    assert_eq!(s.scan().files_hashed, 0);
    let again = s.scan();
    assert_eq!(again.files_hashed, 0);
    assert_eq!(rels(&again.findings), Vec::<&str>::new());
    assert_eq!(rels(&again.review), Vec::<&str>::new());
}

#[test]
fn full_rehash_rereads_and_catches_what_metadata_hides() {
    let s = incident_site();
    settle();
    s.scan();
    settle();
    let rel = "wp-content/themes/hello-child/functions.php";
    // Same size and ctime as recorded, different content: only a re-hash can
    // tell. Stand-in for a ctime reset by a clock change or a raw disk write.
    let mut b = s.load();
    b.entries.get_mut(rel).expect("entry").sha256 = [7; 32];
    b.save_atomic(&s.baseline).expect("save");

    let delta = s.scan();
    assert_eq!(delta.files_hashed, 0);
    assert_eq!(rels(&delta.review), Vec::<&str>::new());

    let full = s.scan_with(ScanMode::FullRehash, &|| false);
    assert!(full.files_hashed > 10, "{}", full.files_hashed);
    assert_eq!(rels(&full.review), [rel]);
}

#[test]
fn deleted_files_leave_the_baseline_silently() {
    let s = incident_site();
    s.write("wp-content/mu-plugins/m.php", "<?php // m\n");
    s.scan();
    s.rm("wp-content/mu-plugins/m.php");
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    assert!(!s.load().entries.contains_key("wp-content/mu-plugins/m.php"));
}

#[test]
fn missing_files_are_reported_by_kind() {
    let s = incident_site();
    s.rm("wp-includes/load.php");
    s.rm("wp-content/plugins/elementor/assets/lib/swiper/swiper.min.js");
    let out = s.scan();
    assert_eq!(
        item(&out.findings, "wp-includes/load.php").kind,
        FindingKind::CoreMissing
    );
    let up = item(
        &out.findings,
        "wp-content/plugins/elementor/assets/lib/swiper/swiper.min.js",
    );
    assert_eq!(up.kind, FindingKind::UpstreamMissing);
    assert_eq!(out.upstream.core_missing, ["wp-includes/load.php"]);
    // `wp-content/` is not core scope, in either direction.
    assert!(!out
        .upstream
        .core_missing
        .iter()
        .any(|p| p.starts_with("wp-content/")));
    assert_eq!(
        out.upstream.plugins_failed[0].issues[0].path,
        "assets/lib/swiper/swiper.min.js"
    );
}

#[test]
fn core_scope_and_its_exemptions() {
    let s = Site::new();
    s.wordpress();
    s.write(".htaccess", "# rewrite\n");
    s.write(".user.ini", "; ini\n");
    s.write(".maintenance", "<?php $upgrading = 1;\n");
    s.write("wp-admin/.htaccess", "# hardening\n");
    s.write("google123.html", "google-site-verification");
    s.write("custom.php", "<?php // site's own\n");
    s.write("wp-admin/extra.php", "<?php // dropped\n");
    s.write("wp-includes/wp-config.php", "<?php // not the real one\n");
    s.write("wp-foo.php", "<?php // dropped\n");
    let out = s.scan();
    let mut got = rels(&out.findings);
    got.sort();
    assert_eq!(
        got,
        [
            "wp-admin/extra.php",
            "wp-foo.php",
            "wp-includes/wp-config.php"
        ]
    );
    assert!(out
        .findings
        .iter()
        .all(|f| f.kind == FindingKind::CoreUnexpected));
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    // The exempt and unknown ones are Layer B, so a change to them is seen.
    let b = s.load();
    for rel in [
        ".htaccess",
        ".user.ini",
        "wp-admin/.htaccess",
        "custom.php",
        "wp-config.php",
    ] {
        assert!(b.entries.contains_key(rel), "{rel}");
    }
    settle();
    s.write(".htaccess", "# rewrite, edited\n");
    item(&s.scan().review, ".htaccess");

    // WordPress requires `.maintenance` as PHP on every load, whatever its name
    // says, and it comes and goes with updates: rules, no change detection.
    assert!(!s.load().entries.contains_key(".maintenance"));
    settle();
    s.write(".maintenance", SHELL);
    let f = s.scan();
    let hit = item(&f.findings, ".maintenance");
    assert_eq!(hit.kind, FindingKind::RuleHit);
    assert_eq!(hit.rule_id.as_deref(), Some("webshell_marker"));
}

#[test]
fn non_code_added_to_a_verified_tree_raises_nothing() {
    let s = incident_site();
    for rel in [
        "wp-cli.yml",
        "error_log",
        "wp-admin/error_log",
        "wp-includes/notes.txt",
        "wp-admin/page.html",
        "wp-content/plugins/elementor/storage/data.json",
        "wp-content/plugins/woocommerce/logs/x.log",
    ] {
        s.write(rel, "anything");
    }
    let out = s.scan();
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert!(out.upstream.plugins_failed.is_empty());
    assert!(out.upstream.core_unexpected.is_empty());

    // A `.php.bak` is a name PHP can run under on older setups: that's code.
    s.write("wp-config.php.bak", "<?php // old\n");
    assert_eq!(rels(&s.scan().findings), ["wp-config.php.bak"]);
}

#[test]
fn soft_files_are_not_compared() {
    let s = Site::new();
    s.wordpress();
    s.verified_plugin(
        "p",
        "1.0",
        &[("readme.txt", b"upstream"), ("a.php", b"<?php\n")],
    );
    s.write("wp-content/plugins/p/readme.txt", "translated");
    assert_eq!(rels(&s.scan().findings), Vec::<&str>::new());
    s.rm("wp-content/plugins/p/readme.txt");
    assert_eq!(rels(&s.scan().findings), Vec::<&str>::new());
}

#[test]
fn single_file_plugin_verifies_and_only_its_file_counts() {
    let s = Site::new();
    s.wordpress();
    let body = b"<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n".to_vec();
    s.write("wp-content/plugins/hello.php", &body);
    s.manifest(
        ComponentKind::Plugin,
        "hello-dolly",
        "1.7.2",
        ManifestSource::WordPressOrg,
        &[
            ("hello.php".into(), body),
            ("readme.txt".into(), b"r".to_vec()),
            ("other.php".into(), b"o".to_vec()),
        ],
    );
    let out = s.scan();
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    assert_eq!(out.coverage.plugins_verified, 1);

    s.append("wp-content/plugins/hello.php", b"// x\n");
    let out = s.scan();
    let f = item(&out.findings, "wp-content/plugins/hello.php");
    assert_eq!(f.kind, FindingKind::UpstreamModified);
    assert_eq!(f.component.as_deref(), Some("hello-dolly"));
}

#[test]
fn vendor_package_files() {
    let s = Site::new();
    s.wordpress();
    let all = s.plugin(
        "pro",
        "1.0",
        &[("a.php", b"<?php // a\n"), ("b.php", b"<?php // b\n")],
    );
    s.manifest(
        ComponentKind::Plugin,
        "pro",
        "1.0",
        ManifestSource::VendorPackage,
        &all,
    );
    let out = s.scan();
    assert_eq!(out.coverage.plugins_verified, 1);
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    settle();

    // Changed: a finding, labelled for what it is.
    s.append("wp-content/plugins/pro/a.php", b"// x\n");
    // Added: some premium plugins write into their own folder, so it's review...
    s.write("wp-content/plugins/pro/generated.php", "<?php // gen\n");
    // ...or a finding on a rule hit.
    s.write("wp-content/plugins/pro/shell.php", SHELL);
    // And files of no watched type aren't anyone's concern.
    s.write("wp-content/plugins/pro/log.txt", "x");
    let out = s.scan();
    let f = item(&out.findings, "wp-content/plugins/pro/a.php");
    assert_eq!(f.kind, FindingKind::UpstreamModified);
    assert_eq!(f.source_label.as_deref(), Some("vendor package"));
    assert_eq!(
        item(&out.findings, "wp-content/plugins/pro/shell.php").kind,
        FindingKind::RuleHit
    );
    assert_eq!(rels(&out.review), ["wp-content/plugins/pro/generated.php"]);
    assert_eq!(out.findings.len(), 2);
}

#[test]
fn theme_failures_are_listed_apart() {
    let s = Site::new();
    s.wordpress();
    let css = b"/*\nTheme Name: hello-elementor\nVersion: 3.0\n*/\n".to_vec();
    s.write("wp-content/themes/hello-elementor/style.css", &css);
    s.write(
        "wp-content/themes/hello-elementor/functions.php",
        "<?php // t\n",
    );
    s.manifest(
        ComponentKind::Theme,
        "hello-elementor",
        "3.0",
        ManifestSource::WordPressOrg,
        &[
            ("style.css".into(), css),
            ("functions.php".into(), b"<?php // real\n".to_vec()),
        ],
    );
    s.child_theme("kid");
    let out = s.scan();
    assert_eq!(out.coverage.themes_verified, 1);
    assert_eq!(out.coverage.themes_total, 2);
    assert_eq!(out.upstream.themes_unknown, ["kid"]);
    assert_eq!(out.upstream.themes_failed.len(), 1);
    assert_eq!(out.upstream.themes_failed[0].slug, "hello-elementor");
    assert_eq!(
        out.upstream.themes_failed[0].issues[0].path,
        "functions.php"
    );
    assert!(out.upstream.plugins_failed.is_empty());
}

#[test]
fn czech_fallback_ignores_version_php() {
    // wordpress.org had no cs_CZ checksums: en_US stood in, and only
    // version.php differs between the two.
    let s = Site::new();
    s.wordpress_with(Some("cs_CZ"), Some("en_US"));
    s.write(
        "wp-includes/version.php",
        format!("<?php\n$wp_version = '{WP_VERSION}';\n$wp_local_package = 'cs_CZ';\n// cz\n"),
    );
    let out = s.scan();
    assert!(out.upstream.ran);
    assert_eq!(rels(&out.findings), Vec::<&str>::new());

    // Everything else is still compared.
    s.append("wp-includes/load.php", b"// x\n");
    let out = s.scan();
    assert_eq!(out.upstream.core_modified, ["wp-includes/load.php"]);

    // The digest can't speak for version.php here, and a tenant can pick this
    // state with `$wp_local_package`, so the rules still do.
    s.write(
        "wp-includes/version.php",
        [
            format!("<?php\n$wp_version = '{WP_VERSION}';\n$wp_local_package = 'cs_CZ';\n")
                .as_bytes(),
            &EVAL[5..],
        ]
        .concat(),
    );
    let out = s.scan();
    let f = item(&out.findings, "wp-includes/version.php");
    assert_eq!(f.kind, FindingKind::CoreModified);
    assert_eq!(f.rule_id.as_deref(), Some("eval_decoder"));
}

#[test]
fn a_clean_fallback_version_php_is_not_read_again() {
    let s = Site::new();
    s.wordpress_with(Some("cs_CZ"), Some("en_US"));
    settle();
    s.scan();
    assert_eq!(s.scan().files_hashed, 0);
}

#[test]
fn a_real_locale_manifest_still_compares_version_php() {
    let s = Site::new();
    s.wordpress_with(Some("cs_CZ"), Some("cs_CZ"));
    s.append("wp-includes/version.php", b"// x\n");
    let out = s.scan();
    assert_eq!(out.upstream.core_modified, ["wp-includes/version.php"]);
    assert_eq!(
        item(&out.findings, "wp-includes/version.php").kind,
        FindingKind::CoreModified
    );
}

#[test]
fn a_huge_file_is_reported_without_being_read() {
    // Sparse: free to make, and days to hash, for one worker every site waits on.
    let s = Site::new();
    let rel = "app/huge.php";
    s.write(rel, "");
    fs::File::options()
        .write(true)
        .open(s.path(rel))
        .expect("open")
        .set_len(3 << 30)
        .expect("grow");
    let out = s.scan();
    assert_eq!(out.files_hashed, 0);
    let r = item(&out.review, rel);
    assert_eq!(r.kind, FindingKind::TooLargeToInspect);
    // Its metadata's hash: nothing was read.
    assert_eq!(r.sha256.len(), 64);
}

fn grow(s: &Site, rel: &str, len: u64) {
    s.write(rel, "");
    fs::File::options()
        .write(true)
        .open(s.path(rel))
        .expect("open")
        .set_len(len)
        .expect("grow");
}

#[test]
fn a_file_with_no_manifest_over_64_mib_is_not_read() {
    let s = Site::new();
    grow(&s, "app/big.php", 65 << 20);
    grow(&s, "app/big.js", 65 << 20);
    let out = s.scan();
    assert_eq!(out.files_hashed, 0);
    let r = item(&out.review, "app/big.php");
    assert_eq!(r.kind, FindingKind::TooLargeToInspect);
    assert_eq!(rels(&out.review), ["app/big.php"]);
    assert_eq!(out.coverage.files_partly_inspected, 1);
}

#[test]
fn big_javascript_enters_by_hash_with_its_start_inspected() {
    let s = Site::new();
    let rel = "app/bundle.js";
    s.write(rel, vec![b' '; 3 << 20]);
    settle();
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_eq!(out.coverage.files_partly_inspected, 1);
    assert!(s.load().entries.is_empty(), "rules-only on a non-WP site");

    // In a WordPress tree it's watched like any other file.
    let s = Site::new();
    s.wordpress();
    let rel = "wp-content/mu-plugins/bundle.js";
    s.write(rel, vec![b' '; 3 << 20]);
    settle();
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_eq!(out.coverage.files_partly_inspected, 1);
    assert!(s.load().entries.contains_key(rel));
    settle();
    // Not a pending item: unchanged, it isn't read again, and it still counts.
    let again = s.scan();
    assert_eq!(again.files_hashed, 0);
    assert_eq!(again.coverage.files_partly_inspected, 1);

    // Same size, new content: a change like any other.
    let mut edited = vec![b' '; 3 << 20];
    edited[0] = b'/';
    s.write(rel, &edited);
    assert_eq!(
        item(&s.scan().review, rel).kind,
        FindingKind::BaselineChange
    );

    // A loader in the part that's read is still a finding.
    let mut loaded = JS_LOADER.to_vec();
    loaded.resize(3 << 20, b' ');
    s.write(rel, loaded);
    assert_eq!(item(&s.scan().findings, rel).kind, FindingKind::RuleHit);
}

#[test]
fn a_large_php_file_is_never_skipped_silently() {
    let s = Site::new();
    let rel = "app/big.php";
    s.write(rel, vec![b'/'; 2 * 1024 * 1024 + 100]);
    let out = s.scan();
    let r = item(&out.review, rel);
    assert_eq!(r.kind, FindingKind::TooLargeToInspect);
    assert_eq!(r.severity, "medium");
    assert_eq!(r.rule_id.as_deref(), Some("too_large_to_inspect"));

    // With a High hit in the part that was read, the hit is the news.
    let mut body = EVAL.to_vec();
    body.resize(2 * 1024 * 1024 + 100, b' ');
    s.write(rel, body);
    let out = s.scan();
    assert_eq!(item(&out.findings, rel).kind, FindingKind::RuleHit);
}

#[test]
fn a_root_that_cannot_be_opened_is_an_error_not_a_clean_scan() {
    let s = Site::new();
    let input = ScanInput {
        root: Path::new("/nonexistent/hyperion/site").to_path_buf(),
        discovery: Default::default(),
        manifests_dir: s.cache.clone(),
        baseline_path: s.baseline.clone(),
        mode: ScanMode::Delta,
        now: NOW,
        wporg_known_slugs: None,
        accept_since: None,
        trusted: BTreeMap::new(),
    };
    assert!(scan_site(&input, &|| false).is_err());
}

#[test]
fn a_baseline_that_cannot_be_saved_says_so() {
    // Root ignores directory permissions, so the save would succeed.
    if rustix::process::geteuid().is_root() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let s = Site::new();
    s.write("index.php", "<?php\n");
    s.scan();
    let dir = s.baseline.parent().expect("dir").to_path_buf();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).expect("chmod");
    let out = s.scan();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod back");
    assert!(
        out.coverage
            .partial_reasons
            .iter()
            .any(|r| r.contains("baseline")),
        "{:?}",
        out.coverage.partial_reasons
    );
}

/// Built with `*at` calls: only each syscall is bound by PATH_MAX, and a tenant
/// can go on like this down to the walker's depth limit. Overlayfs (a container's
/// /tmp) gives up around 4 KiB, so this stops a level before it refuses.
fn deep_php(s: &Site) -> String {
    use rustix::fs::{mkdirat, openat, Mode, OFlags, CWD};
    let name = "\u{1}".repeat(200);
    let flags = OFlags::RDONLY | OFlags::DIRECTORY;
    let mut dir = openat(CWD, &s.root, flags, Mode::empty()).expect("root");
    let mut rel = String::new();
    for _ in 0..60 {
        if mkdirat(&dir, &name, Mode::RWXU).is_err() {
            break;
        }
        let next = openat(&dir, &name, flags, Mode::empty()).expect("descend");
        // Is there room for the deeper one? Only then is this level final.
        if mkdirat(&next, &name, Mode::RWXU).is_err() {
            break;
        }
        rustix::fs::unlinkat(&next, &name, rustix::fs::AtFlags::REMOVEDIR).expect("rmdir");
        dir = next;
        rel.push_str(&name);
        rel.push('/');
    }
    let flags = OFlags::CREATE | OFlags::WRONLY;
    let f = openat(&dir, "x.php", flags, Mode::RUSR | Mode::WUSR).expect("create");
    drop(f);
    rel.push_str("x.php");
    rel
}

#[test]
fn one_long_file_name_does_not_turn_off_change_detection() {
    let s = Site::new();
    s.wordpress();
    s.child_theme("kid");
    let rel = deep_php(&s);
    assert!(rel.len() > 1024, "{}", rel.len());

    let first = s.scan();
    // Named, as far as a name that long is any use, and said out loud.
    assert_eq!(first.review.len(), 1, "{:?}", first.review.len());
    let r = &first.review[0];
    assert!(r.rel.len() <= 256, "{}", r.rel.len());
    assert!(rel.starts_with(r.rel.trim_end_matches('…')));
    assert!(first
        .coverage
        .partial_reasons
        .iter()
        .any(|p| p.contains("1024")));

    // The baseline survived it.
    let b = s.load();
    assert!(!b.entries.contains_key(&rel));
    assert!(b.first_done);

    settle();
    let f = "wp-content/themes/kid/functions.php";
    s.write(f, "<?php // attacker edit with no rule hit\n");
    let second = s.scan();
    assert_eq!(item(&second.review, f).kind, FindingKind::BaselineChange);
    assert_eq!(s.load().since, NOW);
}

#[test]
fn an_unreadable_baseline_is_partial_for_that_run() {
    let s = incident_site();
    s.scan();
    fs::write(&s.baseline, "damaged").expect("write");
    let out = s.scan();
    assert!(
        out.coverage
            .partial_reasons
            .iter()
            .any(|r| r.contains("baseline")),
        "{:?}",
        out.coverage.partial_reasons
    );
    // It was started again, so the next run has one to compare with.
    assert_eq!(s.scan().coverage.partial_reasons, Vec::<String>::new());
    // No baseline at all is just a first scan.
    let fresh = incident_site();
    assert_eq!(fresh.scan().coverage.partial_reasons, Vec::<String>::new());
}

#[test]
fn many_added_code_files_group_even_with_a_tiny_manifest() {
    // A one-file manifest: 300 High findings would be the flood grouping is for.
    let s = Site::new();
    s.wordpress();
    s.verified_plugin("contact", "2.0", &[("a.php", b"<?php // a\n")]);
    for i in 0..1100 {
        s.write(
            &format!("wp-content/plugins/contact/own/o{i}.php"),
            "<?php\n",
        );
    }
    let out = s.scan();
    assert_eq!(rels(&out.findings), ["wp-content/plugins/contact"]);
    assert!(out.findings[0].snippet.contains("1100 added"));
    assert_eq!(out.coverage.partial_reasons, Vec::<String>::new());

    // Below the line each file still stands alone.
    let s = Site::new();
    s.wordpress();
    s.verified_plugin("contact", "2.0", &[("a.php", b"<?php // a\n")]);
    for i in 0..49 {
        s.write(
            &format!("wp-content/plugins/contact/own/o{i}.php"),
            "<?php\n",
        );
    }
    assert_eq!(s.scan().findings.len(), 49);
}

#[test]
fn the_item_cap_in_one_component_says_so() {
    // Under half of the files differ, so nothing groups and the cap bites.
    let s = Site::new();
    s.wordpress();
    let files: Vec<(String, Vec<u8>)> = (0..3000)
        .map(|i| (format!("inc/f{i}.txt"), format!("{i}\n").into_bytes()))
        .collect();
    s.verified_plugin("big", "1.0", &borrowed(&files));
    for (p, _) in files.iter().take(1100) {
        s.append(&format!("wp-content/plugins/big/{p}"), b"x");
    }
    let out = s.scan();
    assert_eq!(out.findings.len(), 1000);
    assert!(
        out.coverage
            .partial_reasons
            .iter()
            .any(|r| r.contains("100 more findings not listed")),
        "{:?}",
        out.coverage.partial_reasons
    );
}

#[test]
fn child_themes_get_no_update_pass() {
    // A child theme is the site's own code, and its version says nothing.
    let s = Site::new();
    s.wordpress();
    s.child_theme("kid");
    s.scan();
    settle();
    s.write(
        "wp-content/themes/kid/style.css",
        "/*\nTheme Name: kid\nTemplate: hello-elementor\nVersion: 2.0\n*/\n",
    );
    s.write("wp-content/themes/kid/functions.php", "<?php // edited\n");
    let out = s.scan();
    assert!(out.auto_accepted.is_empty());
    item(&out.review, "wp-content/themes/kid/functions.php");
}

#[test]
fn no_slug_list_means_no_update_pass() {
    // wordpress.org's answer wasn't available: any plugin might be a free one.
    let mut s = Site::new();
    s.known = None;
    s.wordpress();
    s.plugin("premium", "1.0", &[("a.php", b"<?php // a\n")]);
    s.scan();
    settle();
    s.bump("premium", "1.1");
    s.write("wp-content/plugins/premium/a.php", "<?php // a2\n");
    let out = s.scan();
    assert!(out.auto_accepted.is_empty());
    item(&out.review, "wp-content/plugins/premium/a.php");
}

#[test]
fn ordinary_generated_php_paths_are_churn() {
    let s = Site::new();
    s.wordpress();
    let dirs = [
        "wp-content/languages/plugins",
        "wp-content/et-cache/1",
        "wp-content/litespeed/php",
        "wp-content/ai1wm-backups",
        "wp-content/updraft",
    ];
    for d in dirs {
        s.write(&format!("{d}/x.php"), "<?php // generated\n");
    }
    s.scan();
    settle();
    for d in dirs {
        s.write(&format!("{d}/x.php"), "<?php // generated again\n");
    }
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    let b = s.load();
    assert!(b.entries.keys().all(|k| !k.starts_with("wp-content/")));
    // Still rules-only, not unchecked.
    s.write("wp-content/languages/plugins/x.php", EVAL);
    item(&s.scan().findings, "wp-content/languages/plugins/x.php");
}

#[test]
fn php_settings_under_uploads_get_rules() {
    const INI: &str = "; Wordfence WAF\nauto_prepend_file = '/home/u/htdocs/wordfence-waf.php'\n";
    const HTA: &str =
        "<IfModule mod_php.c>\n\tphp_value auto_prepend_file '/tmp/x.php'\n</IfModule>\n";
    let s = Site::new();
    s.wordpress();
    s.write("wp-content/uploads/.user.ini", INI);
    s.write("wp-content/uploads/2026/.htaccess", HTA);
    s.write("wp-content/uploads/plain/.htaccess", "Require all denied\n");
    let out = s.scan();
    let a = item(&out.review, "wp-content/uploads/.user.ini");
    assert_eq!(a.kind, FindingKind::RuleHit);
    assert_eq!(a.severity, "medium");
    assert_eq!(a.rule_id.as_deref(), Some("php_prepend_setting"));
    item(&out.review, "wp-content/uploads/2026/.htaccess");
    assert_eq!(out.review.len(), 2, "{:?}", rels(&out.review));
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    // Plugins write these, so no change detection on the plain one.
    settle();
    s.write(
        "wp-content/uploads/plain/.htaccess",
        "Require all granted\n",
    );
    assert_eq!(s.scan().review.len(), 2);

    // Wordfence's own setup in the root: worth a look, not an alarm.
    let s = Site::new();
    s.wordpress();
    s.write(".user.ini", INI);
    let out = s.scan();
    assert_eq!(item(&out.review, ".user.ini").severity, "medium");
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
}

/// Move a real directory out of the docroot and leave a symlink to it.
fn swap_dir_for_link(s: &Site, rel: &str, hidden: &str) -> PathBuf {
    let hid = s.root.parent().expect("parent").join(hidden);
    fs::rename(s.path(rel), &hid).expect("rename");
    std::os::unix::fs::symlink(&hid, s.path(rel)).expect("link");
    hid
}

#[track_caller]
fn assert_says_unchecked(out: &SiteScanOutcome) {
    assert!(
        out.coverage
            .partial_reasons
            .iter()
            .any(|r| r.contains("could not be checked")),
        "{:?}",
        out.coverage.partial_reasons
    );
}

#[test]
fn a_symlink_over_core_is_not_clean() {
    let s = Site::new();
    s.wordpress();
    s.scan();
    settle();
    let hid = swap_dir_for_link(&s, "wp-admin", "hid-admin");
    fs::write(hid.join("admin.php"), EVAL).expect("write");
    let out = s.scan();
    let r = item(&out.review, "wp-admin");
    assert_eq!(r.kind, FindingKind::BaselineChange);
    assert!(r.snippet.contains("symlink"), "{}", r.snippet);
    assert_says_unchecked(&out);
    assert!(out.upstream.core_missing.is_empty());
}

#[test]
fn a_symlink_inside_a_verified_plugin_is_not_clean() {
    let s = incident_site();
    s.scan();
    settle();
    let hid = swap_dir_for_link(&s, "wp-content/plugins/elementor/assets", "hid-assets");
    fs::write(hid.join("lib/swiper/swiper.min.js"), JS_LOADER).expect("write");
    let out = s.scan();
    let r = item(&out.review, "wp-content/plugins/elementor/assets");
    assert_eq!(r.component.as_deref(), Some("elementor"));
    assert_says_unchecked(&out);
    assert!(out.upstream.plugins_failed.is_empty());
}

#[test]
fn a_listed_file_replaced_by_a_symlink_is_not_clean() {
    let s = incident_site();
    s.scan();
    settle();
    let rel = "wp-content/plugins/elementor/assets/lib/swiper/swiper.min.js";
    let hid = s.root.parent().expect("parent").join("evil.js");
    fs::write(&hid, JS_LOADER).expect("write");
    s.rm(rel);
    std::os::unix::fs::symlink(&hid, s.path(rel)).expect("link");
    let out = s.scan();
    let r = item(&out.review, rel);
    assert_eq!(r.kind, FindingKind::UpstreamModified);
    assert_eq!(r.source_label.as_deref(), Some("wordpress.org"));
    assert_says_unchecked(&out);

    // A manifest can't be trusted away, whatever the link says.
    s.trust_link(rel, hid.to_str().expect("utf8"));
    let out = s.scan();
    assert_eq!(item(&out.review, rel).kind, FindingKind::UpstreamModified);
    assert_says_unchecked(&out);
}

#[test]
fn whole_plugins_and_mu_plugins_as_symlinks_are_not_clean() {
    let s = incident_site();
    s.scan();
    settle();
    swap_dir_for_link(&s, "wp-content/plugins/elementor", "hid-el");
    let out = s.scan();
    item(&out.review, "wp-content/plugins/elementor");
    assert!(!out.coverage.partial_reasons.is_empty());

    let hid = s.root.parent().expect("parent").join("hid-evil");
    fs::create_dir(&hid).expect("mkdir");
    fs::write(hid.join("evil.php"), SHELL).expect("write");
    std::os::unix::fs::symlink(&hid, s.path("wp-content/plugins/evil")).expect("link");
    std::os::unix::fs::symlink(&hid, s.path("wp-content/mu-plugins")).expect("link");
    std::os::unix::fs::symlink(&hid, s.path("wp-content/themes/evil")).expect("link");
    let out = s.scan();
    item(&out.review, "wp-content/plugins/evil");
    item(&out.review, "wp-content/themes/evil");
    item(&out.review, "wp-content/mu-plugins");
}

#[test]
fn a_symlinked_php_settings_file_is_not_clean() {
    let s = Site::new();
    s.wordpress();
    s.write(".user.ini", "; ok\n");
    s.scan();
    settle();
    let hid = s.root.parent().expect("parent").join("x.ini");
    fs::write(&hid, "auto_prepend_file=/tmp/evil.php\n").expect("write");
    s.rm(".user.ini");
    std::os::unix::fs::symlink(&hid, s.path(".user.ini")).expect("link");
    item(&s.scan().review, ".user.ini");
}

#[test]
fn symlinks_where_nothing_would_be_looked_at_only_count() {
    let s = Site::new();
    s.wordpress();
    let elsewhere = s.root.parent().expect("parent").join("elsewhere");
    fs::create_dir(&elsewhere).expect("mkdir");
    let link = |rel: &str| {
        let p = s.path(rel);
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::os::unix::fs::symlink(&elsewhere, p).expect("symlink");
    };
    // A deploy's links into what the scan ignores anyway.
    link("wp-content/uploads");
    link("wp-content/cache");
    link("wp-content/languages/shared");
    // Links that lead to a file or nowhere, inside the site.
    s.write("wp-content/real.txt", "x");
    std::os::unix::fs::symlink("real.txt", s.path("wp-content/notes.txt")).expect("link");
    std::os::unix::fs::symlink("missing.txt", s.path("wp-content/dangling.txt")).expect("link");
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_eq!(out.coverage.symlinks_skipped, 5);
    assert_eq!(out.coverage.partial_reasons, Vec::<String>::new());
}

#[test]
fn a_link_out_of_the_site_is_partial_whatever_is_out_there() {
    // Root never looks at where the link points, so the card says the same for a
    // directory, a file and nothing: no answer about anyone else's paths.
    for (name, target) in [
        ("a-dir", "their-home"),
        ("a-file", "their-file"),
        ("a-nothing", "nothing"),
    ] {
        for relative in [false, true] {
            let s = Site::new();
            let outside = s.root.parent().expect("parent").to_path_buf();
            fs::create_dir(outside.join("their-home")).expect("mkdir");
            fs::write(outside.join("their-file"), "x").expect("write");
            let target = if relative {
                Path::new("..").join(target)
            } else {
                outside.join(target)
            };
            std::os::unix::fs::symlink(&target, s.path(name)).expect("link");
            assert_names_link(&s.scan(), name);
        }
    }
}

#[track_caller]
fn assert_names_link(out: &SiteScanOutcome, rel: &str) {
    assert!(
        out.coverage
            .partial_reasons
            .iter()
            .any(|r| r.contains("symlinked directories") && r.contains(rel)),
        "{rel}: {:?}",
        out.coverage.partial_reasons
    );
}

#[test]
fn a_symlinked_directory_outside_ignored_paths_is_never_clean() {
    // The usual deploy, on a site with no other trace of the application.
    let s = Site::new();
    let releases = s.root.parent().expect("parent").join("releases");
    fs::create_dir(&releases).expect("mkdir");
    fs::write(releases.join("evil.php"), SHELL).expect("write");
    std::os::unix::fs::symlink(&releases, s.path("app")).expect("link");
    std::os::unix::fs::symlink(&releases, s.path("vendor")).expect("link");
    s.write("index.php", "<?php\n");
    let out = s.scan();
    assert_eq!(rels(&out.findings), Vec::<&str>::new());
    assert_names_link(&out, "app");
    // `vendor` is nobody's churn here: a link to it hides a tree like any other.
    assert_names_link(&out, "vendor");
    assert_eq!(out.coverage.symlinks_skipped, 2);

    // The same on WordPress, wherever the name is nobody's in particular.
    let s = Site::new();
    s.wordpress();
    let d = s.root.parent().expect("parent").join("d");
    fs::create_dir(&d).expect("mkdir");
    std::os::unix::fs::symlink(&d, s.path("blog")).expect("link");
    s.write("wp-content/index.php", "<?php\n");
    std::os::unix::fs::symlink(&d, s.path("wp-content/custom")).expect("link");
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_names_link(&out, "blog");
    assert_names_link(&out, "wp-content/custom");

    // Where the link also gets an item, the reason is still there.
    let s = incident_site();
    swap_dir_for_link(&s, "wp-content/plugins/elementor/assets", "hid");
    assert_names_link(&s.scan(), "wp-content/plugins/elementor/assets");
}

#[test]
fn many_symlinked_directories_stay_one_bounded_reason() {
    let s = Site::new();
    let d = s.root.parent().expect("parent").join("d");
    fs::create_dir(&d).expect("mkdir");
    for i in 0..30 {
        std::os::unix::fs::symlink(&d, s.path(&format!("l{i}"))).expect("link");
    }
    let out = s.scan();
    assert_eq!(out.coverage.partial_reasons.len(), 1);
    assert!(
        out.coverage.partial_reasons[0].contains("25 more"),
        "{:?}",
        out.coverage.partial_reasons
    );
}

#[test]
fn a_trusted_symlink_is_cleared_until_it_points_elsewhere() {
    let s = Site::new();
    s.wordpress();
    let rel = "wp-content/mu-plugins/loader.php";
    fs::create_dir_all(s.path("wp-content/mu-plugins")).expect("mkdir");
    std::os::unix::fs::symlink("/opt/shared/loader.php", s.path(rel)).expect("link");
    let out = s.scan();
    assert_eq!(item(&out.review, rel).kind, FindingKind::BaselineChange);
    assert!(item(&out.review, rel).symlink);

    s.trust_link(rel, "/opt/shared/loader.php");
    assert_eq!(rels(&s.scan().review), Vec::<&str>::new());

    s.rm(rel);
    std::os::unix::fs::symlink("/tmp/evil.php", s.path(rel)).expect("link");
    let r = s.scan();
    assert_eq!(
        item(&r.review, rel).sha256,
        hex::encode(link_sha("/tmp/evil.php"))
    );
}

#[test]
fn a_trusted_directory_symlink_still_says_its_contents_are_unscanned() {
    let s = incident_site();
    s.scan();
    let rel = "wp-content/plugins/elementor/assets";
    let hid = swap_dir_for_link(&s, rel, "hid");
    let out = s.scan();
    let r = item(&out.review, rel);
    assert_eq!(r.sha256, hex::encode(link_sha(hid.to_str().expect("utf8"))));
    assert_eq!(r.kind, FindingKind::BaselineChange);

    s.trust_link(rel, hid.to_str().expect("utf8"));
    let out = s.scan();
    assert_eq!(rels(&out.review), Vec::<&str>::new());
    assert_names_link(&out, rel);
    assert_says_unchecked(&out);
}

#[test]
fn a_new_code_file_past_64_mib_is_too_large_without_being_read() {
    let s = Site::new();
    s.wordpress();
    // There at the first scan: known, counted, and no news afterwards.
    let old = "wp-content/mu-plugins/old.js";
    s.write(old, "");
    grow(&s, old, 65 << 20);
    settle();
    let first = s.scan();
    assert_eq!(rels(&first.review), Vec::<&str>::new());
    assert_eq!(first.coverage.files_partly_inspected, 1);
    settle();
    assert_eq!(rels(&s.scan().review), Vec::<&str>::new());

    // Turned up since.
    let new = "wp-content/mu-plugins/new.js";
    grow(&s, new, 65 << 20);
    for _ in 0..2 {
        let out = s.scan();
        assert_eq!(out.files_hashed, 0);
        let r = item(&out.review, new);
        assert_eq!(r.kind, FindingKind::TooLargeToInspect);
        // Never read, so its metadata stands in for a hash.
        let st = fs::metadata(s.path(new)).expect("stat");
        assert_eq!(
            r.sha256,
            hex::encode(metadata_hash(st.len(), st.ctime(), st.ctime_nsec()))
        );
        assert_eq!(rels(&out.review), [new]);
    }

    // The one from the first scan changing is a change.
    settle();
    grow(&s, old, 66 << 20);
    let out = s.scan();
    assert_eq!(item(&out.review, old).kind, FindingKind::BaselineChange);

    // Back under the limit it's read and judged like anything else.
    settle();
    s.write(old, JS_LOADER);
    assert_eq!(item(&s.scan().findings, old).kind, FindingKind::RuleHit);
}

/// Nothing past 64 MiB is read, so Trust holds it to its size and ctime: it stays
/// quiet while the file is left alone, whatever a scan's mode, and any touch brings
/// it back. Without this a big file would be on the card forever.
#[test]
fn metadata_item_can_be_trusted_and_flags_on_ctime_change() {
    let s = Site::new();
    s.wordpress();
    for rel in [
        "wp-content/mu-plugins/big.php",
        "wp-content/cache/big.php",
        "wp-content/mu-plugins/big.js",
    ] {
        s.write(rel, "");
        grow(&s, rel, 65 << 20);
    }
    settle();
    let out = s.scan();
    // A big bundle at the first scan is remembered; what PHP runs never is.
    for rel in ["wp-content/mu-plugins/big.php", "wp-content/cache/big.php"] {
        let r = item(&out.review, rel);
        assert_eq!(r.kind, FindingKind::TooLargeToInspect);
        assert_eq!(r.sha256.len(), 64);
        let mut sha = [0u8; 32];
        hex::decode_to_slice(&r.sha256, &mut sha).expect("hex");
        s.trusted.borrow_mut().insert(rel.to_string(), sha);
    }

    settle();
    assert_eq!(rels(&s.scan().review), Vec::<&str>::new());
    assert_eq!(
        rels(&s.scan_with(ScanMode::FullRehash, &|| false).review),
        Vec::<&str>::new()
    );

    // Same size, same content, and a new ctime.
    for rel in ["wp-content/mu-plugins/big.php", "wp-content/cache/big.php"] {
        settle();
        fs::set_permissions(s.path(rel), fs::Permissions::from_mode(0o640)).expect("chmod");
        let out = s.scan();
        let r = item(&out.review, rel);
        assert_ne!(
            hex::encode(s.trusted.borrow().get(rel).expect("trusted")),
            r.sha256
        );
        assert_eq!(out.files_hashed, 0);
    }

    // A changed bundle reports the same way, so it can be trusted too.
    settle();
    let rel = "wp-content/mu-plugins/big.js";
    grow(&s, rel, 66 << 20);
    let r = s.scan();
    let r = item(&r.review, rel);
    assert_eq!(r.kind, FindingKind::BaselineChange);
    assert_eq!(r.sha256.len(), 64);
}

/// A trusted path a whole walk found nothing at can come off the list. A walk
/// that stopped can't say, and neither can a name it was refused.
#[test]
fn trusted_paths_with_nothing_there_are_named() {
    let s = Site::new();
    s.wordpress();
    s.write("wp-content/mu-plugins/here.php", "<?php\n");
    for i in 0..300 {
        s.write(&format!("app/f{i}.php"), format!("<?php // {i}\n"));
    }
    for rel in [
        "wp-content/mu-plugins/here.php",
        "wp-content/mu-plugins/gone.php",
    ] {
        s.trusted.borrow_mut().insert(rel.to_string(), [1; 32]);
    }
    assert_eq!(s.scan().trust_gone, ["wp-content/mu-plugins/gone.php"]);
    let stopped = s.scan_with(ScanMode::FullRehash, &|| true);
    assert!(stopped.stopped);
    assert!(stopped.trust_gone.is_empty());
}

#[test]
fn a_new_rules_only_file_past_64_mib_is_too_large_too() {
    let s = Site::new();
    s.write("index.php", "<?php\n");
    settle();
    s.scan();
    grow(&s, "app/new.js", 65 << 20);
    let out = s.scan();
    assert_eq!(out.files_hashed, 0);
    assert_eq!(
        item(&out.review, "app/new.js").kind,
        FindingKind::TooLargeToInspect
    );
}

#[test]
fn watched_javascript_grown_past_64_mib_is_a_change() {
    let s = Site::new();
    s.wordpress();
    let rel = "wp-content/mu-plugins/app.js";
    s.write(rel, "var a;\n");
    settle();
    s.scan();
    settle();
    s.write(rel, JS_LOADER);
    fs::File::options()
        .write(true)
        .open(s.path(rel))
        .expect("open")
        .set_len(65 << 20)
        .expect("grow");
    for _ in 0..2 {
        let out = s.scan();
        assert_eq!(out.files_hashed, 0);
        let r = item(&out.review, rel);
        assert_eq!(r.kind, FindingKind::BaselineChange);
        // Its metadata's hash: nothing was read.
        assert_eq!(r.sha256.len(), 64);
    }
}

#[test]
fn php_settings_past_64_mib_are_reported_like_php() {
    let grow = |s: &Site| {
        s.write(".user.ini", "auto_prepend_file=/tmp/evil.php\n");
        fs::File::options()
            .write(true)
            .open(s.path(".user.ini"))
            .expect("open")
            .set_len(65 << 20)
            .expect("grow");
    };
    // Watched and grown.
    let s = Site::new();
    s.wordpress();
    s.write(".user.ini", "; ok\n");
    s.scan();
    settle();
    grow(&s);
    let out = s.scan();
    assert_eq!(
        item(&out.review, ".user.ini").kind,
        FindingKind::TooLargeToInspect
    );
    assert_eq!(out.coverage.files_partly_inspected, 0);

    // New, and in a first scan too.
    let s = Site::new();
    s.wordpress();
    grow(&s);
    assert_eq!(
        item(&s.scan().review, ".user.ini").kind,
        FindingKind::TooLargeToInspect
    );
}

#[test]
fn php_settings_padded_past_the_inspect_limit_are_reported() {
    let s = Site::new();
    s.wordpress();
    let mut b = vec![b';'; 3 << 20];
    b.extend_from_slice(b"\nauto_prepend_file=/tmp/evil.php\n");
    s.write("wp-content/uploads/.user.ini", &b);
    s.write(".htaccess", &b);
    let out = s.scan();
    for rel in ["wp-content/uploads/.user.ini", ".htaccess"] {
        assert_eq!(
            item(&out.review, rel).kind,
            FindingKind::TooLargeToInspect,
            "{rel}"
        );
    }
    assert_eq!(out.coverage.files_partly_inspected, 0);
}

#[test]
fn php_settings_with_cr_line_ends_are_read() {
    let s = Site::new();
    s.wordpress();
    s.write(
        "wp-content/uploads/.user.ini",
        "; x\rauto_prepend_file=/tmp/evil.php\r",
    );
    let out = s.scan();
    let r = item(&out.review, "wp-content/uploads/.user.ini");
    assert_eq!(r.rule_id.as_deref(), Some("php_prepend_setting"));
    assert!(r.snippet.starts_with("auto_prepend_file"), "{}", r.snippet);
}

fn padded_version_php() -> Vec<u8> {
    let mut b = format!("<?php\n$wp_version = '{WP_VERSION}';\n$wp_local_package = 'cs_CZ';\n/*")
        .into_bytes();
    b.resize(3 << 20, b' ');
    b.extend_from_slice(b"*/\n");
    b.extend_from_slice(&EVAL[5..]);
    b
}

#[test]
fn a_fallback_version_php_past_the_inspect_limit_fails() {
    let s = Site::new();
    s.wordpress_with(Some("cs_CZ"), Some("en_US"));
    s.scan();
    settle();
    s.write("wp-includes/version.php", padded_version_php());
    let out = s.scan();
    let f = item(&out.findings, "wp-includes/version.php");
    assert_eq!(f.kind, FindingKind::CoreModified);
    assert_eq!(f.severity, "high");
    assert!(!s.load().verified.contains_key("wp-includes/version.php"));
}

#[test]
fn a_rule_pack_bump_reinspects_a_fallback_version_php() {
    let s = Site::new();
    s.wordpress_with(Some("cs_CZ"), Some("en_US"));
    let rel = "wp-includes/version.php";
    let body = [
        format!("<?php\n$wp_version = '{WP_VERSION}';\n$wp_local_package = 'cs_CZ';\n").as_bytes(),
        &EVAL[5..],
    ]
    .concat();
    s.write(rel, &body);
    settle();
    item(&s.scan().findings, rel);

    // As if an older pack had passed it: rules are all that vouches for it.
    let md = fs::metadata(s.path(rel)).expect("stat");
    let mut b = s.load();
    b.entries.insert(
        rel.to_string(),
        BaselineEntry {
            size: md.len(),
            ctime: md.ctime(),
            ctime_nsec: md.ctime_nsec(),
            sha256: sha_of(&body),
        },
    );
    let id = "core/wordpress@6.8.1~en_US".to_string();
    b.verified.insert(rel.to_string(), id);
    b.save_atomic(&s.baseline).expect("save");
    assert_eq!(
        rels(&s.scan().findings),
        Vec::<&str>::new(),
        "no bump, no read"
    );

    let mut b = s.load();
    b.rule_pack = RULE_PACK_VERSION - 1;
    b.save_atomic(&s.baseline).expect("save");
    item(&s.scan().findings, rel);
    assert!(!s.load().verified.contains_key(rel));
}

#[test]
fn outcome_crosses_the_worker_boundary() {
    let s = incident_site();
    plant_incident(&s);
    let out = s.scan();
    let json = serde_json::to_string(&out).expect("ser");
    let back: SiteScanOutcome = serde_json::from_str(&json).expect("de");
    assert_eq!(back, out);
    // Old records missing every new field still parse.
    let old: hyperion_types::WpIntegrityScanResult =
        serde_json::from_str(r#"{"core_ok":true,"wp_cli_ok":true}"#).expect("old");
    assert!(!old.native_scan_ran);
    assert!(old.findings.is_empty());
}
