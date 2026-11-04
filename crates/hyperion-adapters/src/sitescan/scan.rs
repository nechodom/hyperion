//! One site's scan: every file is judged by the strongest layer that can speak
//! for it.
//!
//! A file inside a component with a cached manifest is compared with that
//! manifest, and a match needs no rules. Everything else in scope goes through
//! the baseline and the rules. A file enters `Baseline::entries` only when it is
//! clean or trusted, so what is pending for a person is not stored anywhere: it
//! is any file with no entry, or whose hash differs from its entry, and every
//! scan derives it again.
//!
//! Nothing here touches the network or starts a program. Manifests come from the
//! cache the agent filled; one that isn't there means "unverifiable".

use std::cmp::Reverse;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::hash::BuildHasher;
use std::io::{self, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hyperion_types::{
    FindingKind, ScanCoverage, SiteFileFinding, WpIntegrityFileIssue, WpIntegrityPluginResult,
};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::baseline::{classify, Baseline, BaselineEntry, Change};
use super::discover::{Component, Discovery};
use super::manifest::{
    cache_path_for, is_soft_file, ComponentKey, ComponentKind, Digest, Manifest, ManifestSource,
};
use super::rules::{inspect, is_php_like, RuleHit, Severity, INSPECT_MAX_BYTES, RULE_PACK_VERSION};
use super::walk::{FileMeta, SkipReason, TenantRoot, WalkEvent, WalkOpts, WalkStats};
use crate::AdapterError;

const PAUSE_EVERY_FILES: u64 = 256;
const FLUSH_EVERY_HASHED: u64 = 500;
const HASH_BUF_BYTES: usize = 64 * 1024;
/// A file hashed this close to its ctime could change again within the same
/// clock tick and keep that ctime, so its record can't be believed next time.
const RACY_CTIME_NANOS: i128 = 10_000_000;
/// Files larger than this are reported, not read. Tenants can make a sparse file
/// of any size for free, and hashing one would hold up every site on the node.
const HASH_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const AUTO_ACCEPTED_CAP: usize = 200;
const PARTIAL_REASONS_CAP: usize = 20;
/// Skipped names remembered, so they aren't called deleted or missing. Past this
/// nothing is called either.
const SKIPS_TRACKED: usize = 20_000;
/// A component this size or larger with most files differing is one finding.
const GROUP_MIN_FILES: usize = 10;

const VERSION_PHP: &str = "wp-includes/version.php";
const WP_CONFIG: &str = "wp-config.php";
/// In the docroot root these are the site's own, not an unexpected core file.
const ROOT_EXEMPT: [&str; 4] = [WP_CONFIG, ".htaccess", ".user.ini", ".maintenance"];
/// In `wp-admin` and `wp-includes` only these are: a `wp-config.php` there isn't
/// the real one.
const CORE_DIR_EXEMPT: [&str; 2] = [".htaccess", ".user.ini"];
const CHURN_DIRS: [&str; 3] = [
    "wp-content/cache/",
    "wp-content/wflogs/",
    "wp-content/upgrade/",
];
const UPLOADS_DIR: &str = "wp-content/uploads/";
const NON_WP_CHURN_NAMES: [&str; 2] = ["vendor", "node_modules"];
const TOO_LARGE_RULE: &str = "too_large_to_inspect";

const MSG_MODIFIED: &str = "Checksum does not match";
const MSG_ADDED: &str = "File was added";
const MSG_MISSING: &str = "File is missing";

struct Limits {
    /// Directory entries the walk looks at.
    max_entries: u64,
    /// Items listed per site, for findings and for review each.
    max_items: usize,
}

const LIMITS: Limits = Limits {
    max_entries: 300_000,
    max_items: 1000,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    /// Stat walk, read what changed.
    Delta,
    /// Read everything, for what metadata can't show.
    FullRehash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriterKind {
    GitDeploy,
    Restore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanInput {
    /// The docroot.
    pub root: PathBuf,
    pub discovery: Discovery,
    pub manifests_dir: PathBuf,
    pub baseline_path: PathBuf,
    pub mode: ScanMode,
    pub now: i64,
    /// Slugs wordpress.org knows: these get no premium-update pass.
    #[serde(default)]
    pub wporg_known_slugs: BTreeSet<String>,
    /// Carried for a later task: a writer whose changes go through the rules only.
    #[serde(default)]
    pub accept_since: Option<(WriterKind, i64)>,
}

/// What the comparison with upstream said, in the shape the stored result has.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamResult {
    /// Core was compared. False for a WordPress site means "couldn't check".
    #[serde(default)]
    pub ran: bool,
    #[serde(default)]
    pub core_modified: Vec<String>,
    #[serde(default)]
    pub core_unexpected: Vec<String>,
    #[serde(default)]
    pub core_missing: Vec<String>,
    #[serde(default)]
    pub plugins_failed: Vec<WpIntegrityPluginResult>,
    #[serde(default)]
    pub themes_failed: Vec<WpIntegrityPluginResult>,
    /// Installed with no manifest in the cache.
    #[serde(default)]
    pub plugins_unknown: Vec<String>,
    #[serde(default)]
    pub themes_unknown: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteScanOutcome {
    #[serde(default)]
    pub upstream: UpstreamResult,
    #[serde(default)]
    pub findings: Vec<SiteFileFinding>,
    #[serde(default)]
    pub review: Vec<SiteFileFinding>,
    #[serde(default)]
    pub coverage: ScanCoverage,
    /// Premium-update files accepted without review, for the audit log.
    #[serde(default)]
    pub auto_accepted: Vec<String>,
    /// Files whose content was read.
    #[serde(default)]
    pub files_hashed: u64,
    /// `pause` asked to stop before the walk ended. The next run resumes.
    #[serde(default)]
    pub stopped: bool,
}

/// Scan one site. `pause` is called every few hundred files and may sleep; true
/// means stop now, which still saves the baseline and returns a partial outcome.
/// `Err` means the site couldn't be checked at all.
pub fn scan_site(
    input: &ScanInput,
    pause: &dyn Fn() -> bool,
) -> Result<SiteScanOutcome, AdapterError> {
    scan_with_limits(input, pause, &LIMITS)
}

fn scan_with_limits(
    input: &ScanInput,
    pause: &dyn Fn() -> bool,
    limits: &Limits,
) -> Result<SiteScanOutcome, AdapterError> {
    let root = TenantRoot::open(&input.root)?;
    let loaded = Baseline::load(&input.baseline_path)?;
    let mut scan = Scan::new(input, &root, loaded, limits, pause);
    let opts = WalkOpts {
        max_entries: limits.max_entries,
        prune: Vec::new(),
    };
    let stats = root.walk_until(&opts, |ev| scan.on_event(ev))?;
    Ok(scan.finish(stats))
}

/// One component of the site and what the walk found in it. Items wait here
/// until the walk ends: only then is it known whether they group into one.
struct Comp<'a> {
    c: &'a Component,
    manifest: Option<Manifest>,
    /// Recorded next to each verified file. Says which manifest vouched, so a
    /// better one arriving later compares again.
    id: String,
    /// Compared with en_US checksums for lack of the site's locale.
    locale_fallback: bool,
    /// Premium update: changed files with no rule hit are accepted.
    accept_update: bool,
    items: Vec<SiteFileFinding>,
    modified: u64,
    added: u64,
    missing: u64,
}

impl Comp<'_> {
    fn slug(&self) -> &str {
        &self.c.key.slug
    }

    fn is_core(&self) -> bool {
        self.c.key.kind == ComponentKind::Core
    }

    fn source_label(&self) -> Option<String> {
        self.manifest.as_ref().map(|m| {
            match m.source {
                ManifestSource::WordPressOrg => "wordpress.org",
                ManifestSource::VendorPackage => "vendor package",
            }
            .to_string()
        })
    }

    /// The manifest's files this site is answerable for: `(key, rel)`.
    fn in_scope_files(&self) -> Vec<(&str, String)> {
        let Some(m) = &self.manifest else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for key in m.files.keys().filter(|k| !is_soft_file(k)) {
            if self.is_core() {
                if in_core_scope(key) {
                    out.push((key.as_str(), key.clone()));
                }
            } else if self.c.single_file {
                if self.c.manifest_key(&self.c.rel_root).as_deref() == Some(key) {
                    out.push((key.as_str(), self.c.rel_root.clone()));
                }
            } else {
                out.push((key.as_str(), format!("{}/{key}", self.c.rel_root)));
            }
        }
        out
    }
}

/// Core's scope: `wp-content/` belongs to the site, whatever the release ships.
fn in_core_scope(rel: &str) -> bool {
    !rel.contains('/') || rel.starts_with("wp-admin/") || rel.starts_with("wp-includes/")
}

fn base_name(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

fn is_js(rel: &str) -> bool {
    base_name(rel)
        .rsplit_once('.')
        .is_some_and(|(_, e)| e.eq_ignore_ascii_case("js") || e.eq_ignore_ascii_case("mjs"))
}

/// The file types Layer B looks at.
fn in_scope(rel: &str) -> bool {
    is_php_like(rel) || is_js(rel) || matches!(base_name(rel), ".htaccess" | ".user.ini")
}

/// Where a file goes.
enum Route {
    /// Compare with this component's manifest, under this key.
    Manifest(usize, String),
    /// Baseline and rules.
    Watch(Option<usize>),
    /// Rules on new or changed content, and no change detection.
    RulesOnly(Option<usize>),
    Ignore,
}

/// What the walk has been past: visited files, and names it was refused. Hashes
/// instead of paths, because at the walk's limit the paths would double the
/// baseline's memory.
struct Seen {
    state: RandomState,
    visited: HashSet<u64>,
    skipped: HashSet<String>,
    skips_overflowed: bool,
}

impl Seen {
    fn visit(&mut self, rel: &str) {
        self.visited.insert(self.state.hash_one(rel));
    }

    fn skip(&mut self, rel: &str) {
        if self.skipped.len() >= SKIPS_TRACKED {
            self.skips_overflowed = true;
        } else {
            self.skipped.insert(rel.to_string());
        }
    }

    /// The walk reached this file, or couldn't say: a skipped name may be the
    /// file itself or a directory above it, and "" is the root.
    fn may_exist(&self, rel: &str) -> bool {
        if self.skips_overflowed || self.visited.contains(&self.state.hash_one(rel)) {
            return true;
        }
        if self.skipped.is_empty() {
            return false;
        }
        let mut at = rel;
        loop {
            if self.skipped.contains(at) {
                return true;
            }
            match at.rfind('/') {
                Some(i) => at = &at[..i],
                None => return self.skipped.contains(""),
            }
        }
    }
}

struct FileRead {
    sha256: [u8; 32],
    md5: Option<[u8; 16]>,
    /// Up to `INSPECT_MAX_BYTES + 1`, so `inspect` can tell a file was cut short.
    head: Vec<u8>,
    hashed_at: (i64, i64),
}

fn unix_now() -> (i64, i64) {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or((0, 0), |d| {
            (
                i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                i64::from(d.subsec_nanos()),
            )
        })
}

/// One open, one pass: the digests and the bytes the rules see are the same
/// content, whatever the tenant does to the file meanwhile.
fn read_file(root: &TenantRoot, rel: &str, want_md5: bool, buf: &mut [u8]) -> io::Result<FileRead> {
    let hashed_at = unix_now();
    let mut f = root.open_file(rel)?.take(HASH_MAX_BYTES);
    let mut sha = Sha256::new();
    let mut md5 = want_md5.then(Md5::new);
    let mut head = Vec::new();
    loop {
        let n = match f.read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        sha.update(&buf[..n]);
        if let Some(m) = md5.as_mut() {
            m.update(&buf[..n]);
        }
        let room = (INSPECT_MAX_BYTES + 1).saturating_sub(head.len());
        head.extend_from_slice(&buf[..n.min(room)]);
    }
    Ok(FileRead {
        sha256: sha.finalize().into(),
        md5: md5.map(|m| m.finalize().into()),
        head,
        hashed_at,
    })
}

fn digest_matches(d: &Digest, read: &FileRead) -> bool {
    match d {
        Digest::Sha256(h) => *h == read.sha256,
        Digest::Sha256Any(v) => v.contains(&read.sha256),
        Digest::Md5(h) => read.md5.as_ref() == Some(h),
        Digest::Md5Any(v) => read.md5.as_ref().is_some_and(|m| v.contains(m)),
    }
}

fn is_racy(ctime: i64, ctime_nsec: i64, at: (i64, i64)) -> bool {
    let nanos = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
    (nanos(at.0, at.1) - nanos(ctime, ctime_nsec)).abs() < RACY_CTIME_NANOS
}

/// The record for a file just read. A racy ctime is stored as 0, so the next
/// scan reads the file again instead of believing it.
fn entry_for(m: &FileMeta, read: &FileRead) -> BaselineEntry {
    let racy = is_racy(m.ctime, m.ctime_nsec, read.hashed_at);
    BaselineEntry {
        size: m.size,
        ctime: if racy { 0 } else { m.ctime },
        ctime_nsec: if racy { 0 } else { m.ctime_nsec },
        sha256: read.sha256,
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
    }
}

/// The hit that speaks for a file: the worst, and among equals a real match
/// before the size notice, then the first in the file.
fn worst(hits: &[RuleHit]) -> Option<&RuleHit> {
    hits.iter()
        .min_by_key(|h| (Reverse(h.severity), h.rule_id == TOO_LARGE_RULE, h.line))
}

fn add_domains(into: &mut Vec<String>, from: impl IntoIterator<Item = String>) {
    for d in from {
        if into.len() >= 10 {
            return;
        }
        if !into.contains(&d) {
            into.push(d);
        }
    }
}

/// Put the rule detail on an item.
fn with_hits(mut item: SiteFileFinding, hits: &[RuleHit]) -> SiteFileFinding {
    if let Some(top) = worst(hits) {
        item.rule_id = Some(top.rule_id.to_string());
        item.line = top.line;
        item.snippet = top.snippet.clone();
    }
    add_domains(
        &mut item.domains,
        hits.iter().flat_map(|h| h.domains.iter().cloned()),
    );
    item
}

fn manifest_id(key: &ComponentKey, m: &Manifest) -> String {
    let mut id = format!("{}/{}@{}", key.kind.as_str(), key.slug, key.version);
    if let Some(l) = &m.served_locale {
        id.push('~');
        id.push_str(l);
    }
    if m.source == ManifestSource::VendorPackage {
        id.push_str("#vendor");
    }
    id
}

fn component_key(c: &Component) -> String {
    format!("{}/{}", c.key.kind.as_str(), c.key.slug)
}

/// What the cache holds for a component. Upstream's copy beats a vendor's. A key
/// that can't be a file name (no `Version:` header) has no manifest by definition.
fn load_manifest(dir: &Path, key: &ComponentKey, reasons: &mut Vec<String>) -> Option<Manifest> {
    for source in [ManifestSource::WordPressOrg, ManifestSource::VendorPackage] {
        let path = cache_path_for(dir, key, source).ok()?;
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                reasons.push(format!("manifest for {} unreadable: {e}", key.slug));
                continue;
            }
        };
        match serde_json::from_slice(&bytes) {
            Ok(m) => return Some(m),
            Err(_) => reasons.push(format!("cached manifest for {} is damaged", key.slug)),
        }
    }
    None
}

struct Scan<'a> {
    input: &'a ScanInput,
    root: &'a TenantRoot,
    limits: &'a Limits,
    pause: &'a dyn Fn() -> bool,
    baseline: Baseline,
    /// The first scan hasn't reached the end yet: nothing counts as a change.
    first: bool,
    /// The rule pack is newer than what checked the entries.
    rules_bumped: bool,
    comps: Vec<Comp<'a>>,
    /// Index of core, when it has a manifest.
    core: Option<usize>,
    by_root: HashMap<&'a str, usize>,
    seen: Seen,
    skip_counts: BTreeMap<SkipReason, (u64, String)>,
    findings: Vec<SiteFileFinding>,
    review: Vec<SiteFileFinding>,
    dropped_findings: u64,
    dropped_review: u64,
    auto_accepted: Vec<String>,
    files_seen: u64,
    files_hashed: u64,
    hashed_since_flush: u64,
    stopped: bool,
    /// Why parts of this run couldn't check something, apart from the walk.
    reasons: Vec<String>,
    save_failed: bool,
    buf: Vec<u8>,
}

impl<'a> Scan<'a> {
    fn new(
        input: &'a ScanInput,
        root: &'a TenantRoot,
        loaded: Option<Baseline>,
        limits: &'a Limits,
        pause: &'a dyn Fn() -> bool,
    ) -> Scan<'a> {
        let mut baseline = loaded.unwrap_or_else(|| Baseline {
            since: input.now,
            rule_pack: RULE_PACK_VERSION,
            ..Baseline::default()
        });
        let first = !baseline.first_done;
        let rules_bumped = baseline.rule_pack < RULE_PACK_VERSION;
        if rules_bumped {
            // Their memory of "clean" was this older pack's.
            baseline.churn.clear();
        }

        let mut reasons = Vec::new();
        let mut comps = Vec::with_capacity(input.discovery.components.len());
        let mut by_root = HashMap::new();
        let mut core = None;
        for c in &input.discovery.components {
            let manifest = load_manifest(&input.manifests_dir, &c.key, &mut reasons);
            let i = comps.len();
            if c.key.kind == ComponentKind::Core {
                if manifest.is_some() {
                    core = Some(i);
                }
            } else {
                by_root.insert(c.rel_root.as_str(), i);
            }
            // No pass for a slug wordpress.org knows, or for a first sighting: a
            // dropper with a made-up header is not an update.
            let accept_update = manifest.is_none()
                && c.key.kind != ComponentKind::Core
                && !c.key.version.is_empty()
                && !input.wporg_known_slugs.contains(&c.key.slug)
                && baseline
                    .components
                    .get(&component_key(c))
                    .is_some_and(|old| *old != c.key.version);
            comps.push(Comp {
                c,
                id: manifest
                    .as_ref()
                    .map_or_else(String::new, |m| manifest_id(&c.key, m)),
                locale_fallback: manifest
                    .as_ref()
                    .is_some_and(|m| m.is_locale_fallback(&c.key)),
                manifest,
                accept_update,
                items: Vec::new(),
                modified: 0,
                added: 0,
                missing: 0,
            });
        }

        Scan {
            input,
            root,
            limits,
            pause,
            baseline,
            first,
            rules_bumped,
            comps,
            core,
            by_root,
            seen: Seen {
                state: RandomState::new(),
                visited: HashSet::new(),
                skipped: HashSet::new(),
                skips_overflowed: false,
            },
            skip_counts: BTreeMap::new(),
            findings: Vec::new(),
            review: Vec::new(),
            dropped_findings: 0,
            dropped_review: 0,
            auto_accepted: Vec::new(),
            files_seen: 0,
            files_hashed: 0,
            hashed_since_flush: 0,
            stopped: false,
            reasons,
            save_failed: false,
            buf: vec![0; HASH_BUF_BYTES],
        }
    }

    fn on_event(&mut self, ev: WalkEvent<'_>) -> ControlFlow<()> {
        match ev {
            WalkEvent::Skipped { rel, why } => self.on_skip(rel, why),
            WalkEvent::File(m) => {
                self.on_file(m);
                self.files_seen += 1;
                if self.hashed_since_flush >= FLUSH_EVERY_HASHED {
                    self.flush();
                }
                if self.files_seen % PAUSE_EVERY_FILES == 0 && (self.pause)() {
                    self.stopped = true;
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }

    fn count_skip(&mut self, rel: &str, why: SkipReason) {
        let slot = self
            .skip_counts
            .entry(why)
            .or_insert_with(|| (0, rel.to_string()));
        slot.0 += 1;
    }

    fn on_skip(&mut self, rel: String, why: SkipReason) {
        self.count_skip(&rel, why);
        if why == SkipReason::FileCapReached {
            return;
        }
        self.seen.skip(&rel);
        // A name a tenant can't hide behind: linking a file twice mustn't make
        // it invisible, even though it isn't read.
        if why == SkipReason::HardLinked && is_php_like(&rel) {
            let component = self.owner(&rel).map(|i| self.comps[i].slug().to_string());
            let item = SiteFileFinding {
                snippet: "hard-linked file: not read".to_string(),
                component,
                ..self.base_item(&rel, FindingKind::BaselineChange, None)
            };
            self.push_review(item);
        }
    }

    fn base_item(
        &self,
        rel: &str,
        kind: FindingKind,
        sha256: Option<&[u8; 32]>,
    ) -> SiteFileFinding {
        SiteFileFinding {
            rel: rel.to_string(),
            kind,
            severity: severity_str(Severity::Medium).to_string(),
            sha256: sha256.map(hex::encode).unwrap_or_default(),
            ..SiteFileFinding::default()
        }
    }

    fn push_finding(&mut self, item: SiteFileFinding) {
        if self.findings.len() < self.limits.max_items {
            self.findings.push(item);
        } else {
            self.dropped_findings += 1;
        }
    }

    fn push_review(&mut self, item: SiteFileFinding) {
        if self.review.len() < self.limits.max_items {
            self.review.push(item);
        } else {
            self.dropped_review += 1;
        }
    }

    /// The plugin or theme whose tree holds `rel`.
    fn owner(&self, rel: &str) -> Option<usize> {
        if let Some(i) = self.by_root.get(rel) {
            return Some(*i);
        }
        // Plugin and theme folders are all `wp-content/<kind>/<slug>`.
        let (end, _) = rel.match_indices('/').nth(2)?;
        self.by_root.get(&rel[..end]).copied()
    }

    /// Is this file core's to answer for?
    fn core_claims(&self, core: usize, rel: &str) -> bool {
        if !in_core_scope(rel) {
            return false;
        }
        let listed = self.comps[core]
            .manifest
            .as_ref()
            .is_some_and(|m| m.files.contains_key(rel));
        if listed {
            return true;
        }
        let name = base_name(rel);
        if rel.contains('/') {
            !CORE_DIR_EXEMPT.contains(&name)
        } else {
            // Sites keep their own files in the root (`google*.html`, custom PHP).
            name.starts_with("wp-") && !ROOT_EXEMPT.contains(&name)
        }
    }

    fn route(&self, rel: &str) -> Route {
        let owner = self.owner(rel);
        match owner {
            Some(i) if self.comps[i].manifest.is_some() => {
                if let Some(key) = self.comps[i].c.manifest_key(rel) {
                    return Route::Manifest(i, key);
                }
            }
            None => {
                if let Some(core) = self.core.filter(|c| self.core_claims(*c, rel)) {
                    return Route::Manifest(core, rel.to_string());
                }
            }
            Some(_) => {}
        }
        self.route_unverified(rel, owner)
    }

    fn route_unverified(&self, rel: &str, owner: Option<usize>) -> Route {
        if !in_scope(rel) {
            return Route::Ignore;
        }
        let php = is_php_like(rel);
        if self.input.discovery.is_wordpress {
            if CHURN_DIRS.iter().any(|d| rel.starts_with(d)) {
                return if php {
                    Route::RulesOnly(owner)
                } else {
                    Route::Ignore
                };
            }
            if rel.starts_with(UPLOADS_DIR) && !php {
                return Route::Ignore;
            }
            return Route::Watch(owner);
        }
        let mut dirs = rel.split('/');
        dirs.next_back();
        if dirs.any(|d| NON_WP_CHURN_NAMES.contains(&d)) {
            return if php || is_js(rel) {
                Route::RulesOnly(owner)
            } else {
                Route::Ignore
            };
        }
        if is_js(rel) {
            return Route::RulesOnly(owner);
        }
        Route::Watch(owner)
    }

    fn on_file(&mut self, m: &FileMeta) {
        match self.route(&m.rel) {
            Route::Manifest(i, key) => {
                self.seen.visit(&m.rel);
                self.baseline.churn.remove(&m.rel);
                self.compare(i, &key, m);
            }
            Route::Watch(owner) => {
                self.seen.visit(&m.rel);
                self.watch(m, owner);
            }
            Route::RulesOnly(owner) => {
                self.seen.visit(&m.rel);
                self.rules_only(m, owner);
            }
            // Not visited on purpose: any stale record of it gets pruned.
            Route::Ignore => {}
        }
    }

    /// Read a file, keeping the count. A file that can't be read leaves its
    /// records alone and goes into the partial reasons.
    fn read(&mut self, rel: &str, want_md5: bool) -> Option<FileRead> {
        match read_file(self.root, rel, want_md5, &mut self.buf) {
            Ok(r) => {
                self.files_hashed += 1;
                self.hashed_since_flush += 1;
                Some(r)
            }
            Err(e) => {
                let why = if e.kind() == io::ErrorKind::NotFound {
                    SkipReason::Vanished
                } else {
                    SkipReason::Unreadable
                };
                self.count_skip(rel, why);
                None
            }
        }
    }

    /// Step 1: a file inside a component with a manifest.
    fn compare(&mut self, i: usize, key: &str, m: &FileMeta) {
        let comp = &self.comps[i];
        if is_soft_file(key) {
            return;
        }
        let digest = comp
            .manifest
            .as_ref()
            .and_then(|mf| mf.files.get(key))
            .cloned();
        let Some(digest) = digest else {
            return self.unlisted(i, m);
        };
        if comp.locale_fallback && m.rel == VERSION_PHP {
            return;
        }
        if self.input.mode == ScanMode::Delta
            && self.baseline.verified.get(&m.rel) == Some(&comp.id)
            && classify(self.baseline.entries.get(&m.rel), m) == Change::Unchanged
        {
            return;
        }
        if m.size > HASH_MAX_BYTES {
            return self.mismatch(i, m, None, &[]);
        }
        let want_md5 = matches!(digest, Digest::Md5(_) | Digest::Md5Any(_));
        let Some(read) = self.read(&m.rel, want_md5) else {
            return;
        };
        if digest_matches(&digest, &read) {
            let id = self.comps[i].id.clone();
            self.baseline
                .entries
                .insert(m.rel.clone(), entry_for(m, &read));
            self.baseline.verified.insert(m.rel.clone(), id);
            return;
        }
        let hits = inspect(&m.rel, &read.head);
        self.mismatch(i, m, Some(&read.sha256), &hits);
    }

    fn forget(&mut self, rel: &str) {
        self.baseline.entries.remove(rel);
        self.baseline.verified.remove(rel);
    }

    fn mismatch(&mut self, i: usize, m: &FileMeta, sha: Option<&[u8; 32]>, hits: &[RuleHit]) {
        self.forget(&m.rel);
        let core = self.comps[i].is_core();
        self.comps[i].modified += 1;
        let kind = if core {
            FindingKind::CoreModified
        } else {
            FindingKind::UpstreamModified
        };
        self.stage(i, m, kind, sha, hits);
    }

    /// A file in a verified tree that the manifest doesn't list.
    fn unlisted(&mut self, i: usize, m: &FileMeta) {
        let comp = &self.comps[i];
        let vendor = comp
            .manifest
            .as_ref()
            .is_some_and(|mf| mf.source == ManifestSource::VendorPackage);
        if vendor && !comp.is_core() {
            // Some premium plugins write into their own folder.
            if in_scope(&m.rel) {
                self.watch(m, Some(i));
            } else {
                self.seen.visited.remove(&self.seen.state.hash_one(&m.rel));
            }
            return;
        }
        self.forget(&m.rel);
        self.comps[i].added += 1;
        // Past the cap it won't be listed, so there's nothing to read it for.
        if self.comps[i].items.len() >= self.limits.max_items || m.size > HASH_MAX_BYTES {
            let core = self.comps[i].is_core();
            return self.stage(i, m, added_kind(core), None, &[]);
        }
        let Some(read) = self.read(&m.rel, false) else {
            return;
        };
        let hits = inspect(&m.rel, &read.head);
        let core = self.comps[i].is_core();
        self.stage(i, m, added_kind(core), Some(&read.sha256), &hits);
    }

    fn stage(
        &mut self,
        i: usize,
        m: &FileMeta,
        kind: FindingKind,
        sha: Option<&[u8; 32]>,
        hits: &[RuleHit],
    ) {
        if self.comps[i].items.len() >= self.limits.max_items {
            return;
        }
        let item = with_hits(
            SiteFileFinding {
                severity: severity_str(Severity::High).to_string(),
                component: Some(self.comps[i].slug().to_string()),
                source_label: self.comps[i].source_label(),
                ..self.base_item(&m.rel, kind, sha)
            },
            hits,
        );
        self.comps[i].items.push(item);
    }

    fn component_of(&self, owner: Option<usize>) -> Option<String> {
        owner.map(|i| self.comps[i].slug().to_string())
    }

    /// A hit file's item, in the bucket its worst hit calls for.
    fn report_hits(
        &mut self,
        m: &FileMeta,
        owner: Option<usize>,
        sha: &[u8; 32],
        hits: &[RuleHit],
    ) {
        let Some(top) = worst(hits) else { return };
        let kind = if top.rule_id == TOO_LARGE_RULE {
            FindingKind::TooLargeToInspect
        } else {
            FindingKind::RuleHit
        };
        let severity = top.severity;
        let item = with_hits(
            SiteFileFinding {
                severity: severity_str(severity).to_string(),
                component: self.component_of(owner),
                ..self.base_item(&m.rel, kind, Some(sha))
            },
            hits,
        );
        match severity {
            Severity::High => self.push_finding(item),
            Severity::Medium => self.push_review(item),
        }
    }

    fn report_oversize(&mut self, m: &FileMeta, owner: Option<usize>) {
        let item = SiteFileFinding {
            snippet: format!("{} bytes: too large to read", m.size),
            component: self.component_of(owner),
            ..self.base_item(&m.rel, FindingKind::TooLargeToInspect, None)
        };
        self.push_review(item);
    }

    /// Steps 2 and 3: baseline and rules.
    fn watch(&mut self, m: &FileMeta, owner: Option<usize>) {
        self.baseline.churn.remove(&m.rel);
        self.baseline.verified.remove(&m.rel);
        let change = classify(self.baseline.entries.get(&m.rel), m);
        if change == Change::Unchanged && self.input.mode == ScanMode::Delta && !self.rules_bumped {
            return;
        }
        if m.size > HASH_MAX_BYTES {
            return self.report_oversize(m, owner);
        }
        let Some(read) = self.read(&m.rel, false) else {
            return;
        };
        let trusted = self.baseline.trusted.get(&m.rel) == Some(&read.sha256);
        let same = self
            .baseline
            .entries
            .get(&m.rel)
            .is_some_and(|e| e.sha256 == read.sha256);
        if same {
            // Only a High hit from a newer pack takes back what was accepted.
            if self.rules_bumped && !trusted {
                let hits = inspect(&m.rel, &read.head);
                if worst(&hits).is_some_and(|h| h.severity == Severity::High) {
                    self.baseline.entries.remove(&m.rel);
                    return self.report_hits(m, owner, &read.sha256, &hits);
                }
            }
            self.baseline
                .entries
                .insert(m.rel.clone(), entry_for(m, &read));
            return;
        }
        if trusted {
            self.baseline
                .entries
                .insert(m.rel.clone(), entry_for(m, &read));
            return;
        }
        let hits = inspect(&m.rel, &read.head);
        if !hits.is_empty() {
            return self.report_hits(m, owner, &read.sha256, &hits);
        }
        let accept = owner.is_some_and(|i| self.comps[i].accept_update);
        if self.first || accept {
            self.baseline
                .entries
                .insert(m.rel.clone(), entry_for(m, &read));
            if !self.first && self.auto_accepted.len() < AUTO_ACCEPTED_CAP {
                self.auto_accepted.push(m.rel.clone());
            }
            return;
        }
        let item = SiteFileFinding {
            component: self.component_of(owner),
            ..self.base_item(&m.rel, FindingKind::BaselineChange, Some(&read.sha256))
        };
        self.push_review(item);
    }

    /// Churn paths: rules on what's new by its metadata, and nothing else. A
    /// clean file is remembered so it isn't read again; one with a hit isn't, so
    /// it keeps being reported.
    fn rules_only(&mut self, m: &FileMeta, owner: Option<usize>) {
        self.forget(&m.rel);
        let change = classify(self.baseline.churn.get(&m.rel), m);
        if change == Change::Unchanged && self.input.mode == ScanMode::Delta {
            return;
        }
        if m.size > HASH_MAX_BYTES {
            return self.report_oversize(m, owner);
        }
        let Some(read) = self.read(&m.rel, false) else {
            return;
        };
        if self.baseline.trusted.get(&m.rel) != Some(&read.sha256) {
            let hits = inspect(&m.rel, &read.head);
            if !hits.is_empty() {
                self.baseline.churn.remove(&m.rel);
                return self.report_hits(m, owner, &read.sha256, &hits);
            }
        }
        self.baseline
            .churn
            .insert(m.rel.clone(), entry_for(m, &read));
    }

    /// Save what's known so far, so a killed worker resumes from here.
    fn flush(&mut self) {
        self.hashed_since_flush = 0;
        self.save_failed = self
            .baseline
            .save_atomic(&self.input.baseline_path)
            .is_err();
    }

    /// Manifest files the walk never met.
    fn add_missing(&mut self) {
        for i in 0..self.comps.len() {
            let missing: Vec<String> = self.comps[i]
                .in_scope_files()
                .into_iter()
                .map(|(_, rel)| rel)
                .filter(|rel| !self.seen.may_exist(rel))
                .collect();
            let core = self.comps[i].is_core();
            let kind = if core {
                FindingKind::CoreMissing
            } else {
                FindingKind::UpstreamMissing
            };
            for rel in missing {
                self.forget(&rel);
                self.comps[i].missing += 1;
                if self.comps[i].items.len() >= self.limits.max_items {
                    continue;
                }
                // Usually a botched update, not an attack: not High on its own.
                let item = SiteFileFinding {
                    component: Some(self.comps[i].slug().to_string()),
                    source_label: self.comps[i].source_label(),
                    ..self.base_item(&rel, kind, None)
                };
                self.comps[i].items.push(item);
            }
        }
    }

    /// Most of a component differing is one fact, not hundreds: a mass injector
    /// or a private plugin in a wordpress.org slug's folder. Either way one High
    /// finding on the folder says it.
    fn group_components(&mut self) {
        for comp in &mut self.comps {
            let differ = comp.modified + comp.missing;
            if differ == 0 {
                continue;
            }
            let total = comp.in_scope_files().len();
            if total < GROUP_MIN_FILES || differ.saturating_mul(2) <= total as u64 {
                continue;
            }
            let label = comp.source_label().unwrap_or_default();
            let mut item = SiteFileFinding {
                rel: if comp.is_core() {
                    ".".to_string()
                } else {
                    comp.c.rel_root.clone()
                },
                kind: if comp.is_core() {
                    FindingKind::CoreModified
                } else {
                    FindingKind::UpstreamModified
                },
                severity: severity_str(Severity::High).to_string(),
                snippet: format!(
                    "{differ} of {total} files differ from {label}, {} added",
                    comp.added
                ),
                component: Some(comp.slug().to_string()),
                source_label: comp.source_label(),
                ..SiteFileFinding::default()
            };
            if let Some(hit) = comp.items.iter().find(|i| i.rule_id.is_some()) {
                item.rule_id.clone_from(&hit.rule_id);
                item.line = hit.line;
            }
            for it in &comp.items {
                add_domains(&mut item.domains, it.domains.iter().cloned());
            }
            comp.items = vec![item];
        }
    }

    /// Findings in their final order, and the upstream lists made from the same
    /// items so the two can't disagree. Upstream's failures come first: when the
    /// cap bites, they are the ones with no other record.
    fn assemble(&mut self, ran: bool) -> (Vec<SiteFileFinding>, UpstreamResult) {
        let mut up = UpstreamResult {
            ran,
            ..UpstreamResult::default()
        };
        let mut all = Vec::new();
        let max = self.limits.max_items;
        let mut dropped = self.dropped_findings;
        for comp in &mut self.comps {
            let items = std::mem::take(&mut comp.items);
            let kind = comp.c.key.kind;
            match (kind, &comp.manifest) {
                (ComponentKind::Plugin, None) => up.plugins_unknown.push(comp.slug().to_string()),
                (ComponentKind::Theme, None) => up.themes_unknown.push(comp.slug().to_string()),
                _ => {}
            }
            let mut issues = Vec::new();
            for item in items {
                if all.len() >= max {
                    dropped += 1;
                    continue;
                }
                match (kind, item.kind) {
                    (ComponentKind::Core, FindingKind::CoreModified) => {
                        up.core_modified.push(item.rel.clone());
                    }
                    (ComponentKind::Core, FindingKind::CoreUnexpected) => {
                        up.core_unexpected.push(item.rel.clone());
                    }
                    (ComponentKind::Core, _) => up.core_missing.push(item.rel.clone()),
                    (_, k) => issues.push(WpIntegrityFileIssue {
                        path: issue_path(comp, &item),
                        message: match k {
                            FindingKind::UpstreamAdded => MSG_ADDED.to_string(),
                            FindingKind::UpstreamMissing => MSG_MISSING.to_string(),
                            _ if item.rel == comp.c.rel_root && !comp.c.single_file => {
                                item.snippet.clone()
                            }
                            _ => MSG_MODIFIED.to_string(),
                        },
                    }),
                }
                all.push(item);
            }
            if !issues.is_empty() {
                let failed = WpIntegrityPluginResult {
                    slug: comp.slug().to_string(),
                    issues,
                };
                match kind {
                    ComponentKind::Theme => up.themes_failed.push(failed),
                    _ => up.plugins_failed.push(failed),
                }
            }
        }
        for item in std::mem::take(&mut self.findings) {
            if all.len() >= max {
                dropped += 1;
            } else {
                all.push(item);
            }
        }
        self.dropped_findings = dropped;
        (all, up)
    }

    fn walk_reasons(&self, stats: &WalkStats) -> Vec<String> {
        let mut out = Vec::new();
        for (why, (n, first)) in &self.skip_counts {
            let label = match why {
                SkipReason::Symlink => "symlinks not followed",
                SkipReason::NotRegular => "special files not read",
                SkipReason::HardLinked => "hard-linked files not read",
                SkipReason::Unreadable => "files or directories could not be read",
                SkipReason::NonUtf8Name => "names that aren't UTF-8 not looked at",
                SkipReason::Vanished => "files vanished during the scan",
                SkipReason::OtherFilesystem => "directories on another filesystem not looked at",
                SkipReason::FileCapReached => continue,
            };
            let first = if first.is_empty() {
                "the docroot"
            } else {
                first
            };
            out.push(format!("{n} {label} (first: {first})"));
        }
        if stats.capped {
            out.push(format!(
                "stopped at the limit of {} entries; the rest of the site was not looked at",
                self.limits.max_entries
            ));
        }
        if self.stopped {
            out.push("the scan was stopped early and resumes on the next run".to_string());
        }
        out
    }

    fn finish(mut self, stats: WalkStats) -> SiteScanOutcome {
        let d = &self.input.discovery;
        let complete = !self.stopped && !stats.capped;
        let mut reasons = self.walk_reasons(&stats);
        let mut ran = false;
        if d.is_wordpress {
            let core_comp = self.comps.iter().find(|c| c.is_core());
            if d.core_version_unknown {
                reasons.push("WordPress's version could not be read; core was not compared".into());
            } else if let Some(c) = core_comp.filter(|c| c.manifest.is_none()) {
                reasons.push(format!(
                    "no checksums for WordPress {} yet; core was not compared",
                    c.c.key.version
                ));
            } else {
                ran = core_comp.is_some();
            }
            if complete && !self.seen.may_exist(WP_CONFIG) {
                reasons.push(format!(
                    "{WP_CONFIG} is not in the document root, so it could not be checked"
                ));
            }
        }

        if complete {
            self.add_missing();
            let seen = &self.seen;
            self.baseline.entries.retain(|p, _| seen.may_exist(p));
            self.baseline.verified.retain(|p, _| seen.may_exist(p));
            self.baseline.churn.retain(|p, _| seen.may_exist(p));
        }
        self.group_components();
        let (findings, upstream) = self.assemble(ran);

        if !self.stopped {
            self.baseline.first_done = true;
            self.baseline.rule_pack = self.baseline.rule_pack.max(RULE_PACK_VERSION);
            self.baseline.components = self
                .comps
                .iter()
                .filter(|c| !c.is_core() && !c.c.key.version.is_empty())
                .map(|c| (component_key(c.c), c.c.key.version.clone()))
                .collect();
        }
        self.flush();

        if self.dropped_findings > 0 {
            reasons.push(format!(
                "{} more findings not listed (limit {})",
                self.dropped_findings, self.limits.max_items
            ));
        }
        if self.dropped_review > 0 {
            reasons.push(format!(
                "{} more changes to review not listed (limit {})",
                self.dropped_review, self.limits.max_items
            ));
        }
        if self.save_failed {
            reasons.push("the baseline could not be saved".to_string());
        }
        reasons.append(&mut self.reasons);
        reasons.extend(d.problems.iter().cloned());
        if reasons.len() > PARTIAL_REASONS_CAP {
            let more = reasons.len() - (PARTIAL_REASONS_CAP - 1);
            reasons.truncate(PARTIAL_REASONS_CAP - 1);
            reasons.push(format!("and {more} more"));
        }

        let count = |kind: ComponentKind, verified: bool| -> i64 {
            let n = self
                .comps
                .iter()
                .filter(|c| c.c.key.kind == kind && (!verified || c.manifest.is_some()))
                .count();
            i64::try_from(n).unwrap_or(i64::MAX)
        };
        let coverage = ScanCoverage {
            plugins_verified: count(ComponentKind::Plugin, true),
            plugins_total: count(ComponentKind::Plugin, false),
            themes_verified: count(ComponentKind::Theme, true),
            themes_total: count(ComponentKind::Theme, false),
            files_watched: i64::try_from(self.baseline.entries.len()).unwrap_or(i64::MAX),
            watching_since: self.baseline.since,
            upstream_ran: ran,
            no_upstream: !d.is_wordpress,
            partial_reasons: reasons,
        };
        SiteScanOutcome {
            upstream,
            findings,
            review: self.review,
            coverage,
            auto_accepted: self.auto_accepted,
            files_hashed: self.files_hashed,
            stopped: self.stopped,
        }
    }
}

fn added_kind(core: bool) -> FindingKind {
    if core {
        FindingKind::CoreUnexpected
    } else {
        FindingKind::UpstreamAdded
    }
}

/// An issue's path, relative to the component like wp-cli reports it.
fn issue_path(comp: &Comp<'_>, item: &SiteFileFinding) -> String {
    if comp.c.single_file {
        return base_name(&item.rel).to_string();
    }
    comp.c
        .manifest_key(&item.rel)
        .unwrap_or_else(|| ".".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sitescan::discover::discover;
    use crate::sitescan::manifest::cache_path;

    fn write(root: &Path, rel: &str, body: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        fs::write(p, body).expect("write");
    }

    fn input(base: &Path, root: &Path) -> ScanInput {
        ScanInput {
            root: root.to_path_buf(),
            discovery: discover(&TenantRoot::open(root).expect("open")),
            manifests_dir: base.join("m"),
            baseline_path: base.join("b"),
            mode: ScanMode::Delta,
            now: 1,
            wporg_known_slugs: BTreeSet::new(),
            accept_since: None,
        }
    }

    fn tree() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().expect("tmp");
        let base = t.path().canonicalize().expect("canonical");
        let root = base.join("htdocs");
        fs::create_dir(&root).expect("mkdir");
        (t, base, root)
    }

    #[test]
    fn a_ctime_this_close_to_the_read_is_racy() {
        assert!(is_racy(100, 5, (100, 5)));
        assert!(is_racy(100, 999_000_000, (101, 5_000_000)));
        assert!(is_racy(100, 5_000_000, (100, 0)));
        assert!(!is_racy(100, 0, (100, 10_000_000)));
        assert!(!is_racy(100, 0, (101, 0)));
    }

    #[test]
    fn a_racy_entry_stores_ctime_zero() {
        let m = FileMeta {
            rel: "a.php".into(),
            size: 3,
            ctime: 100,
            ctime_nsec: 7,
            mode: 0o644,
            uid: 0,
            nlink: 1,
        };
        let read = |at| FileRead {
            sha256: [1; 32],
            md5: None,
            head: Vec::new(),
            hashed_at: at,
        };
        let e = entry_for(&m, &read((100, 8)));
        assert_eq!((e.ctime, e.ctime_nsec), (0, 0));
        // The next scan then sees different metadata and reads it again.
        assert_eq!(classify(Some(&e), &m), Change::NeedsHash);
        let e = entry_for(&m, &read((200, 0)));
        assert_eq!((e.ctime, e.ctime_nsec), (100, 7));
        assert_eq!(classify(Some(&e), &m), Change::Unchanged);
    }

    #[test]
    fn file_cap_gives_partial() {
        let (_t, base, root) = tree();
        write(
            &root,
            "wp-includes/version.php",
            b"<?php\n$wp_version = '6.8.1';\n",
        );
        write(&root, "wp-config.php", b"<?php\n");
        for i in 0..50 {
            write(&root, &format!("app/f{i}.php"), b"<?php\n");
        }
        // A release file the capped walk may simply not have reached.
        let key = ComponentKey {
            kind: ComponentKind::Core,
            slug: "wordpress".into(),
            version: "6.8.1".into(),
            locale: None,
        };
        let p = cache_path(&base.join("m"), &key).expect("path");
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        let mut files = BTreeMap::new();
        files.insert("wp-includes/nope.php".to_string(), Digest::Md5([0; 16]));
        let manifest = Manifest {
            source: ManifestSource::WordPressOrg,
            files,
            served_locale: None,
        };
        fs::write(p, serde_json::to_vec(&manifest).expect("json")).expect("write");

        let inp = input(&base, &root);
        let limits = Limits {
            max_entries: 20,
            max_items: 1000,
        };
        let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        let reasons = &out.coverage.partial_reasons;
        assert!(
            reasons.iter().any(|r| r.contains("limit of 20")),
            "{reasons:?}"
        );
        assert!(out.upstream.core_missing.is_empty());
        let first_run = Baseline::load(&inp.baseline_path)
            .expect("load")
            .expect("some");
        assert!(first_run.entries.len() < 20);

        // A capped walk ends the first scan, and deletes nothing it didn't visit.
        assert!(first_run.first_done);
        let again = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        assert!(!again.coverage.partial_reasons.is_empty());
        let second = Baseline::load(&inp.baseline_path)
            .expect("load")
            .expect("some");
        assert_eq!(second.entries.len(), first_run.entries.len());
    }

    #[test]
    fn findings_and_review_are_capped_with_a_reason() {
        let (_t, base, root) = tree();
        for i in 0..30 {
            write(
                &root,
                &format!("app/s{i}.php"),
                b"<?php eval(base64_decode('QQ=='));\n",
            );
            write(&root, &format!("app/h{i}.php"), b"<?php\n");
        }
        let inp = input(&base, &root);
        let limits = Limits {
            max_entries: 1000,
            max_items: 10,
        };
        scan_with_limits(&inp, &|| false, &LIMITS).expect("first");
        for i in 0..30 {
            write(&root, &format!("app/h{i}.php"), b"<?php // edited\n");
        }
        let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        assert_eq!(out.findings.len(), 10);
        assert_eq!(out.review.len(), 10);
        let reasons = &out.coverage.partial_reasons;
        assert!(
            reasons.iter().any(|r| r.contains("20 more findings")),
            "{reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| r.contains("20 more changes")),
            "{reasons:?}"
        );
    }

    #[test]
    fn partial_reasons_are_bounded() {
        let (_t, base, root) = tree();
        write(&root, "index.php", b"<?php\n");
        let mut inp = input(&base, &root);
        inp.discovery.problems = (0..100).map(|i| format!("problem {i}")).collect();
        let out = scan_site(&inp, &|| false).expect("scan");
        assert_eq!(out.coverage.partial_reasons.len(), PARTIAL_REASONS_CAP);
        assert_eq!(out.coverage.partial_reasons[19], "and 81 more");
    }

    #[test]
    fn auto_accepted_is_capped() {
        let (_t, base, root) = tree();
        write(&root, "wp-load.php", b"<?php\n");
        write(&root, "wp-config.php", b"<?php\n");
        let main = |v: &str| format!("<?php\n/*\nPlugin Name: p\nVersion: {v}\n*/\n").into_bytes();
        write(&root, "wp-content/plugins/p/p.php", &main("1"));
        scan_site(&input(&base, &root), &|| false).expect("first");
        write(&root, "wp-content/plugins/p/p.php", &main("2"));
        for i in 0..250 {
            write(&root, &format!("wp-content/plugins/p/f{i}.php"), b"<?php\n");
        }
        let out = scan_site(&input(&base, &root), &|| false).expect("scan");
        assert!(out.review.is_empty());
        assert_eq!(out.auto_accepted.len(), AUTO_ACCEPTED_CAP);
    }
}
