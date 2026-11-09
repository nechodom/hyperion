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
    HARD_LINKED_SNIPPET, PACKAGES_DISAGREE_LABEL, VENDOR_PACKAGE_LABEL,
};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::baseline::{classify, Baseline, BaselineEntry, Change, Loaded};
use super::discover::{Component, Discovery};
use super::manifest::{
    cache_path_for, is_soft_file, vendor_disputed_path, ComponentKey, ComponentKind, Digest,
    Manifest, ManifestSource,
};
use super::rules::{
    inspect, inspect_as_php, is_php_like, RuleHit, Severity, INSPECT_MAX_BYTES, RULE_PACK_VERSION,
};
use super::walk::{FileMeta, SkipReason, TenantRoot, WalkEvent, WalkOpts, WalkStats};
use crate::wpplugin::{managed_files, status_shape_ok, ManagedContent};
use crate::AdapterError;

const PAUSE_EVERY_FILES: u64 = 256;
const FLUSH_EVERY_HASHED: u64 = 500;
/// Past that, a save waits for this fraction of what is recorded to be new: a save
/// writes all of it. A run killed in between does this much again.
const FLUSH_GROWTH_DIVISOR: u64 = 8;
const HASH_BUF_BYTES: usize = 64 * 1024;
/// A file hashed this close to its ctime could change again within the same
/// clock tick and keep that ctime, so its record can't be believed next time.
const RACY_CTIME_NANOS: i128 = 10_000_000;
/// Files a manifest lists larger than this are a mismatch without being read. A
/// tenant can make a sparse file of any size for free, and hashing one would hold
/// up every site on the node.
const HASH_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// With no manifest to compare with, this is where reading stops being worth it.
const NO_MANIFEST_READ_MAX: u64 = 64 * 1024 * 1024;
/// `pause` also gets asked this often inside one file.
const PAUSE_EVERY_READ_BYTES: u64 = 16 * 1024 * 1024;
const AUTO_ACCEPTED_CAP: usize = 200;
const PARTIAL_REASONS_CAP: usize = 20;
/// Skipped names remembered, so they aren't called deleted or missing. Past this
/// nothing is called either.
const SKIPS_TRACKED: usize = 20_000;
/// A component this size or larger with most files differing is one finding.
const GROUP_MIN_FILES: usize = 10;
/// So is one with this many code files added, whatever the manifest's size.
const GROUP_ADDED_CODE: u64 = 50;
/// The hash in a record of a file too big to read. No file hashes to it, so one
/// that comes back small enough to read counts as changed.
const METADATA_ONLY: [u8; 32] = [0; 32];
/// Symlinked directories named in the partial reason; the rest are counted.
const DIR_LINKS_NAMED: usize = 5;
/// How much of an over-long name an item shows.
const NAME_SHOWN_BYTES: usize = 200;

const VERSION_PHP: &str = "wp-includes/version.php";
const WP_CONFIG: &str = "wp-config.php";
/// WordPress requires this root file as PHP on every load, and updates write and
/// remove it.
const MAINTENANCE: &str = ".maintenance";
/// In the docroot root these are the site's own, not an unexpected core file.
const ROOT_EXEMPT: [&str; 4] = [WP_CONFIG, ".htaccess", ".user.ini", MAINTENANCE];
/// In `wp-admin` and `wp-includes` only these are: a `wp-config.php` there isn't
/// the real one.
const CORE_DIR_EXEMPT: [&str; 2] = [".htaccess", ".user.ini"];
/// Core files a site may delete on purpose (they reveal the version) and that
/// nothing loads: gone is not a finding, changed still is.
const CORE_OPTIONAL: [&str; 2] = ["license.txt", "readme.html"];
const CHURN_DIRS: [&str; 9] = [
    "wp-content/cache/",
    "wp-content/wflogs/",
    "wp-content/upgrade/",
    // WordPress's copy of a plugin or theme during its update, left behind
    // when the update is cut short.
    "wp-content/upgrade-temp-backup/",
    "wp-content/languages/",
    "wp-content/et-cache/",
    "wp-content/litespeed/",
    "wp-content/ai1wm-backups/",
    "wp-content/updraft/",
];
const UPLOADS_DIR: &str = "wp-content/uploads/";
const NON_WP_CHURN_NAMES: [&str; 2] = ["vendor", "node_modules"];
const TOO_LARGE_RULE: &str = "too_large_to_inspect";

/// The `source_label` on a finding about Hyperion's own files.
const OWN_LABEL: &str = "hyperion";
/// After an agent starts, an older copy of its files may sit on disk until the
/// install tick rewrites them. For this long a mismatch is for a person to look
/// at, not an alarm.
const OWN_GRACE_SECS: i64 = 3600;
/// Hyperion's files are small. Anything bigger than this at their path is not one.
const OWN_READ_MAX: u64 = 1024 * 1024;

const MSG_MODIFIED: &str = "Checksum does not match";
const MSG_ADDED: &str = "File was added";
const MSG_MISSING: &str = "File is missing";

struct Limits {
    /// Directory entries the walk looks at.
    max_entries: u64,
    /// Items listed per site, for findings and for review each.
    max_items: usize,
    /// A longer `rel` is never recorded. The kernel's PATH_MAX doesn't bound it
    /// (each `openat` is short), and a line the baseline can't load back would
    /// silently make every scan a first scan.
    max_rel_bytes: usize,
    /// Names recorded in the baseline in total, as they cost once written. Keeps
    /// the file under the size `Baseline::load` accepts.
    recorded_rel_bytes: u64,
    /// Bytes read per run. Past it the run stops and the next one resumes.
    read_budget: u64,
}

const LIMITS: Limits = Limits {
    max_entries: 300_000,
    max_items: 1000,
    max_rel_bytes: 1024,
    recorded_rel_bytes: 32 * 1024 * 1024,
    read_budget: 8 * 1024 * 1024 * 1024,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    /// Stat walk, read what changed.
    Delta,
    /// Read everything, for what metadata can't show.
    FullRehash,
}

/// Who wrote into the tree on the site's behalf, as the agent knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriterKind {
    GitDeploy,
    Restore,
}

/// The hashed list a writer left, as the agent read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriterAccepted {
    pub kind: WriterKind,
    #[serde(default)]
    pub files: BTreeMap<String, [u8; 32]>,
}

impl WriterKind {
    /// What the card says next to a file this writer changed.
    pub fn label(self) -> &'static str {
        match self {
            WriterKind::GitDeploy => "changed by deploy",
            WriterKind::Restore => "changed by restore",
        }
    }
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
    /// Slugs wordpress.org knows: these get no premium-update pass. None means
    /// the answer wasn't available, and then no slug gets it.
    #[serde(default)]
    pub wporg_known_slugs: Option<BTreeSet<String>>,
    /// What a writer of ours (git deploy, restore) left, by path and hash. A new
    /// or changed file whose content is exactly that, and which no rule hits, is
    /// accepted and listed rather than sent to review. Rule hits and manifest
    /// comparisons are unaffected, and so is every file not on the list.
    #[serde(default)]
    pub accepted: Option<WriterAccepted>,
    /// What Hyperion's own per-site files should hold (the mail module), by path,
    /// as the agent renders them. A file with no entry here has only the rules.
    #[serde(default)]
    pub own_expected: BTreeMap<String, [u8; 32]>,
    /// When the running agent started. Hyperion's own files from an older version
    /// are review, not findings, for the hour after. 0 means no grace.
    #[serde(default)]
    pub own_files_since: i64,
    /// Files someone vouched for, by path and the hash they vouched for. A
    /// symlink's is the hash of its target, a file too large to read its
    /// [`metadata_hash`]. The agent keeps this list; a worker has no say in it.
    #[serde(default)]
    pub trusted: BTreeMap<String, [u8; 32]>,
    /// What the last run listed that this one may carry, should it stop or hit
    /// its cap. Each is looked up by name after the walk; at most
    /// [`MAX_CARRIED_RELS`] are.
    #[serde(default)]
    pub carried_rels: Vec<String>,
}

/// The most `carried_rels` a scan looks up.
pub const MAX_CARRIED_RELS: usize = 2000;

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
    /// The files a git deploy or a restore changed and nothing objected to, with
    /// who changed them in `source_label`. Also in `auto_accepted`.
    #[serde(default)]
    pub accepted_by_writer: Vec<SiteFileFinding>,
    /// Files whose content was read.
    #[serde(default)]
    pub files_hashed: u64,
    /// `pause` asked to stop before the walk ended. The next run resumes.
    #[serde(default)]
    pub stopped: bool,
    /// The walk hit its entry limit. The next run gets no further.
    #[serde(default)]
    pub capped: bool,
    /// Trusted paths a finished walk found nothing at. They needn't take up room
    /// in the list any more.
    #[serde(default)]
    pub trust_gone: Vec<String>,
    /// `carried_rels` with nothing at them, however far the walk got: what the
    /// last run said about them can't stand.
    #[serde(default)]
    pub absent_carried: Vec<String>,
}

/// Scan one site. `pause` is called every few hundred files and during long
/// reads, and may sleep; true
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
    let loaded = Baseline::load_state(&input.baseline_path)?;
    let mut scan = Scan::new(input, &root, loaded, limits, pause);
    let opts = WalkOpts {
        max_entries: limits.max_entries,
        prune: Vec::new(),
    };
    let stats = root.walk_until(&opts, |ev| scan.on_event(ev))?;
    let mut outcome = scan.finish(stats);
    outcome.absent_carried = input
        .carried_rels
        .iter()
        .take(MAX_CARRIED_RELS)
        .filter(|rel| root.is_gone(rel))
        .cloned()
        .collect();
    Ok(outcome)
}

/// One component of the site and what the walk found in it. Items wait here
/// until the walk ends: only then is it known whether they group into one.
struct Comp<'a> {
    c: &'a Component,
    manifest: Option<Manifest>,
    /// A vendor manifest whose version has a `disputed` marker beside it.
    disputed: bool,
    /// Recorded next to each verified file. Says which manifest vouched, so a
    /// better one arriving later compares again.
    id: String,
    /// Compared with en_US checksums for lack of the site's locale.
    locale_fallback: bool,
    /// Premium update: changed files with no rule hit are accepted.
    accept_update: bool,
    items: Vec<SiteFileFinding>,
    modified: u64,
    /// Code files only: anything else added to a tree raises nothing.
    added: u64,
    missing: u64,
    /// Items past the cap. Forgiven if the component groups into one.
    dropped: u64,
}

impl Comp<'_> {
    fn slug(&self) -> &str {
        &self.c.key.slug
    }

    fn is_core(&self) -> bool {
        self.c.key.kind == ComponentKind::Core
    }

    /// What was compared with, as the words for it.
    fn reference_label(&self) -> Option<String> {
        self.manifest.as_ref().map(|m| {
            match m.source {
                ManifestSource::WordPressOrg => "wordpress.org",
                ManifestSource::VendorPackage => VENDOR_PACKAGE_LABEL,
            }
            .to_string()
        })
    }

    /// The label on its findings. Packages for this version were seen to differ, so
    /// nobody can say this one was the vendor's: the agent holds these for review.
    fn source_label(&self) -> Option<String> {
        if self.disputed {
            return Some(PACKAGES_DISAGREE_LABEL.to_string());
        }
        self.reference_label()
    }

    fn is_vendor_verified(&self) -> bool {
        self.manifest
            .as_ref()
            .is_some_and(|m| m.source == ManifestSource::VendorPackage)
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

fn is_php_settings(rel: &str) -> bool {
    matches!(base_name(rel), ".htaccess" | ".user.ini")
}

fn runs_as_php(rel: &str) -> bool {
    is_php_like(rel) || rel == MAINTENANCE
}

/// The file types a writer's hash covers: PHP, JavaScript and the files PHP
/// obeys. `.maintenance` is left out, as a deploy never writes it.
pub fn is_layer_b_code(rel: &str) -> bool {
    is_php_like(rel) || is_js(rel) || is_php_settings(rel)
}

/// The file types Layer B looks at. These are what counts as code.
fn in_scope(rel: &str) -> bool {
    runs_as_php(rel) || is_js(rel) || is_php_settings(rel)
}

/// Too big to read to the end is a loose end only for what PHP runs or obeys: a
/// big bundle gets its start inspected and is watched by hash like anything else.
fn size_is_a_loose_end(rel: &str) -> bool {
    runs_as_php(rel) || is_php_settings(rel)
}

fn rules_for(rel: &str, head: &[u8]) -> Vec<RuleHit> {
    if rel == MAINTENANCE {
        return inspect_as_php(rel, head);
    }
    let mut hits = inspect(rel, head);
    if !size_is_a_loose_end(rel) {
        hits.retain(|h| h.rule_id != TOO_LARGE_RULE);
    }
    hits
}

/// What a Trust action vouches for when it trusts a symlink: where it points.
fn link_hash(target: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"symlink:");
    h.update(target);
    h.finalize().into()
}

/// What a Trust action vouches for when a file is too large to read: its size
/// and when it last changed. Anything that touches the file changes this.
pub fn metadata_hash(size: u64, ctime: i64, ctime_nsec: i64) -> [u8; 32] {
    Sha256::digest(format!("meta:{size}:{ctime}:{ctime_nsec}")).into()
}

fn metadata_hash_of(m: &FileMeta) -> [u8; 32] {
    metadata_hash(m.size, m.ctime, m.ctime_nsec)
}

/// Plain text from a tenant's link, like any snippet.
fn link_snippet(target: &[u8]) -> String {
    let shown: String = String::from_utf8_lossy(target)
        .chars()
        .take(100)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!("symlink to {shown}")
}

/// Directories whose contents WordPress runs, wherever a symlink sends them.
fn holds_code(rel: &str) -> bool {
    matches!(
        rel,
        "wp-admin" | "wp-includes" | "wp-content" | "wp-content/plugins" | "wp-content/themes"
    ) || rel == "wp-content/mu-plugins"
        || rel.starts_with("wp-content/mu-plugins/")
        || rel.starts_with("wp-content/plugins/")
        || rel.starts_with("wp-content/themes/")
}

/// What a name costs in the baseline file: JSON escapes control characters into
/// six bytes, and a tenant picks the characters.
fn recorded_cost(rel: &str) -> u64 {
    rel.bytes()
        .map(|b| match b {
            0..=0x1f => 6,
            b'"' | b'\\' => 2,
            _ => 1,
        })
        .sum()
}

fn short_name(rel: &str) -> String {
    if rel.len() <= NAME_SHOWN_BYTES {
        return rel.to_string();
    }
    let mut end = NAME_SHOWN_BYTES;
    while !rel.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &rel[..end])
}

/// Hyperion's own files in a docroot, by path, with the digest the running
/// binary expects. A file whose bytes depend on the site (the mail module) or on
/// the hour (the status page) has no compiled-in digest and is not in here.
pub fn own_manifest() -> BTreeMap<String, Digest> {
    managed_files()
        .into_iter()
        .filter_map(|f| match f.content {
            ManagedContent::Fixed(body) => Some((
                f.rel,
                Digest::Sha256(Sha256::digest(body.as_bytes()).into()),
            )),
            _ => None,
        })
        .collect()
}

/// How one of Hyperion's own files is judged.
#[derive(Clone)]
enum OwnCheck {
    /// By a digest: compiled in, or the agent's rendering of it.
    Digest(Digest),
    /// By its shape, then the rules.
    Status,
    /// Only the rules: the agent gave no expected content for it.
    RulesOnly,
}

fn own_checks(expected: &BTreeMap<String, [u8; 32]>) -> BTreeMap<String, OwnCheck> {
    managed_files()
        .into_iter()
        .map(|f| {
            let check = match f.content {
                ManagedContent::Fixed(body) => {
                    OwnCheck::Digest(Digest::Sha256(Sha256::digest(body.as_bytes()).into()))
                }
                ManagedContent::PerSite => expected.get(&f.rel).map_or(OwnCheck::RulesOnly, |h| {
                    OwnCheck::Digest(Digest::Sha256(*h))
                }),
                ManagedContent::Status => OwnCheck::Status,
            };
            (f.rel, check)
        })
        .collect()
}

/// Where a file goes.
enum Route {
    /// One of Hyperion's own files: compare with the digest it was written from.
    Own,
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

    /// It turned out not to be anyone's concern: any stale record of it goes.
    fn unvisit(&mut self, rel: &str) {
        self.visited.remove(&self.state.hash_one(rel));
    }

    fn skip(&mut self, rel: &str) {
        if self.skipped.len() >= SKIPS_TRACKED {
            self.skips_overflowed = true;
        } else {
            self.skipped.insert(rel.to_string());
        }
    }

    fn visited(&self, rel: &str) -> bool {
        self.visited.contains(&self.state.hash_one(rel))
    }

    /// The walk reached this file, or couldn't say: a skipped name may be the
    /// file itself or a directory above it, and "" is the root.
    fn may_exist(&self, rel: &str) -> bool {
        if self.skips_overflowed || self.visited(rel) {
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
    bytes: u64,
}

fn flush_due(hashed_since_flush: u64, recorded: u64) -> bool {
    hashed_since_flush >= FLUSH_EVERY_HASHED.max(recorded / FLUSH_GROWTH_DIVISOR)
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
/// content, whatever the tenant does to the file meanwhile. `Ok(None)` means
/// `pause` asked to stop partway through.
fn read_file(
    root: &TenantRoot,
    rel: &str,
    want_md5: bool,
    buf: &mut [u8],
    pause: &dyn Fn() -> bool,
) -> io::Result<Option<FileRead>> {
    let hashed_at = unix_now();
    let mut f = root.open_file(rel)?.take(HASH_MAX_BYTES);
    let mut sha = Sha256::new();
    let mut md5 = want_md5.then(Md5::new);
    let mut head = Vec::new();
    let mut bytes = 0u64;
    let mut next_pause = PAUSE_EVERY_READ_BYTES;
    loop {
        if bytes >= next_pause {
            next_pause += PAUSE_EVERY_READ_BYTES;
            if pause() {
                return Ok(None);
            }
        }
        let n = match f.read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        bytes += n as u64;
        sha.update(&buf[..n]);
        if let Some(m) = md5.as_mut() {
            m.update(&buf[..n]);
        }
        let room = (INSPECT_MAX_BYTES + 1).saturating_sub(head.len());
        head.extend_from_slice(&buf[..n.min(room)]);
    }
    Ok(Some(FileRead {
        sha256: sha.finalize().into(),
        md5: md5.map(|m| m.finalize().into()),
        head,
        hashed_at,
        bytes,
    }))
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

/// What a record says when Hyperion's own digest vouched for the file: another
/// digest is another id, so a file is compared again after an update changes it.
fn own_id(d: &Digest) -> String {
    match d {
        Digest::Sha256(h) => format!("hyperion/{}", hex::encode(&h[..8])),
        _ => "hyperion".to_string(),
    }
}

fn manifest_id(key: &ComponentKey, m: &Manifest) -> String {
    let mut id = format!("{}/{}@{}", key.kind.as_str(), key.slug, key.version);
    if let Some(l) = &m.served_locale {
        id.push('~');
        id.push_str(l);
    }
    // A vendor's can be forgotten and come back different under the same version,
    // and what the old one verified must not count for the new one.
    if m.source == ManifestSource::VendorPackage {
        id.push_str("#vendor-");
        let files = serde_json::to_vec(&m.files).unwrap_or_default();
        id.push_str(&hex::encode(&Sha256::digest(&files)[..8]));
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
    /// What Hyperion writes into a docroot.
    own: BTreeMap<String, OwnCheck>,
    by_root: HashMap<&'a str, usize>,
    seen: Seen,
    skip_counts: BTreeMap<SkipReason, (u64, String)>,
    findings: Vec<SiteFileFinding>,
    review: Vec<SiteFileFinding>,
    dropped_findings: u64,
    dropped_review: u64,
    auto_accepted: Vec<String>,
    accepted_by_writer: Vec<SiteFileFinding>,
    files_seen: u64,
    skips_seen: u64,
    files_hashed: u64,
    hashed_since_flush: u64,
    stopped: bool,
    /// Why it stopped: this run's read budget ran out.
    out_of_budget: bool,
    bytes_read: u64,
    /// What the names in the baseline cost so far.
    recorded_bytes: u64,
    /// Files with no room left in the baseline.
    not_recorded: u64,
    /// Code files with a name over the limit.
    long_names: u64,
    /// Manifest files behind something the walk wouldn't go through.
    listed_unchecked: u64,
    /// Symlinked directories whose contents would have been looked at.
    dir_links: u64,
    dir_links_named: Vec<String>,
    partly_inspected: i64,
    symlinks_skipped: i64,
    /// Why parts of this run couldn't check something, apart from the walk.
    reasons: Vec<String>,
    save_failed: bool,
    buf: Vec<u8>,
}

impl<'a> Scan<'a> {
    fn new(
        input: &'a ScanInput,
        root: &'a TenantRoot,
        loaded: Loaded,
        limits: &'a Limits,
        pause: &'a dyn Fn() -> bool,
    ) -> Scan<'a> {
        let mut reasons = Vec::new();
        let loaded = match loaded {
            Loaded::Found(b) => Some(b),
            Loaded::Missing => None,
            Loaded::Unreadable => {
                reasons.push(
                    "the saved baseline could not be read and was started again; earlier changes can't be proven"
                        .to_string(),
                );
                None
            }
        };
        let mut baseline = loaded.unwrap_or_else(|| Baseline {
            since: input.now,
            rule_pack: RULE_PACK_VERSION,
            ..Baseline::default()
        });
        baseline.trusted.clear();
        let first = !baseline.first_done;
        let rules_bumped = baseline.rule_pack < RULE_PACK_VERSION;
        if rules_bumped {
            // Their memory of "clean" was this older pack's. Files too big to read
            // were never judged by it, and are known by their metadata alone.
            baseline.churn.retain(|_, e| e.sha256 == METADATA_ONLY);
        }

        let recorded_bytes = baseline
            .entries
            .keys()
            .chain(baseline.verified.keys())
            .chain(baseline.churn.keys())
            .map(|p| recorded_cost(p))
            .sum();
        let mut comps = Vec::with_capacity(input.discovery.components.len());
        let mut by_root = HashMap::new();
        let mut core = None;
        for c in &input.discovery.components {
            let manifest = load_manifest(&input.manifests_dir, &c.key, &mut reasons);
            let disputed = manifest
                .as_ref()
                .is_some_and(|m| m.source == ManifestSource::VendorPackage)
                && cache_path_for(&input.manifests_dir, &c.key, ManifestSource::VendorPackage)
                    .is_ok_and(|p| vendor_disputed_path(&p).exists());
            let i = comps.len();
            if c.key.kind == ComponentKind::Core {
                if manifest.is_some() {
                    core = Some(i);
                }
            } else {
                by_root.insert(c.rel_root.as_str(), i);
            }
            // No pass for a slug wordpress.org knows or might, for a child theme
            // (the site's own code), or for a first sighting: a dropper with a
            // made-up header is not an update.
            let accept_update = manifest.is_none()
                && c.key.kind != ComponentKind::Core
                && !c.is_child_theme
                && !c.key.version.is_empty()
                && input
                    .wporg_known_slugs
                    .as_ref()
                    .is_some_and(|k| !k.contains(&c.key.slug))
                && baseline
                    .components
                    .get(&component_key(c))
                    .is_some_and(|old| *old != c.key.version);
            comps.push(Comp {
                c,
                disputed,
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
                dropped: 0,
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
            own: own_checks(&input.own_expected),
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
            accepted_by_writer: Vec::new(),
            files_seen: 0,
            skips_seen: 0,
            files_hashed: 0,
            hashed_since_flush: 0,
            stopped: false,
            out_of_budget: false,
            bytes_read: 0,
            recorded_bytes,
            not_recorded: 0,
            long_names: 0,
            listed_unchecked: 0,
            dir_links: 0,
            dir_links_named: Vec::new(),
            partly_inspected: 0,
            symlinks_skipped: 0,
            reasons,
            save_failed: false,
            buf: vec![0; HASH_BUF_BYTES],
        }
    }

    fn on_event(&mut self, ev: WalkEvent<'_>) -> ControlFlow<()> {
        match ev {
            WalkEvent::Skipped { rel, why } => {
                self.on_skip(rel, why);
                // A tree of links or odd files has no `File` events to yield on.
                self.skips_seen += 1;
                if self.skips_seen % PAUSE_EVERY_FILES == 0 && (self.pause)() {
                    self.stopped = true;
                    return ControlFlow::Break(());
                }
            }
            WalkEvent::File(m) => {
                self.on_file(m);
                self.files_seen += 1;
                if flush_due(self.hashed_since_flush, self.files_seen) {
                    self.flush();
                }
                if self.stopped {
                    return ControlFlow::Break(());
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
            .or_insert_with(|| (0, short_name(rel)));
        slot.0 += 1;
    }

    fn on_skip(&mut self, rel: String, why: SkipReason) {
        // Files below a name this long aren't recorded or listed in a manifest
        // either, so nothing needs it remembered.
        if why != SkipReason::FileCapReached && rel.len() <= self.limits.max_rel_bytes {
            self.seen.skip(&rel);
        }
        // Linking a file twice or pointing a name elsewhere mustn't make code
        // invisible, even though it isn't read.
        match why {
            SkipReason::Symlink => return self.on_symlink(&rel),
            SkipReason::Vanished if self.is_churn_path(&rel) => return,
            SkipReason::HardLinked if in_scope(&rel) => {
                self.report_unread(&rel, HARD_LINKED_SNIPPET);
            }
            _ => {}
        }
        self.count_skip(&rel, why);
    }

    fn on_symlink(&mut self, rel: &str) {
        // What's behind it stays unscanned, whatever anyone thinks of the link.
        // If it can't be told what it leads to, it may be a directory.
        if !self.dir_link_is_ignored(rel) && self.root.link_may_lead_to_dir(rel) {
            self.dir_links += 1;
            if self.dir_links_named.len() < DIR_LINKS_NAMED {
                self.dir_links_named.push(short_name(rel));
            }
        }
        if !self.symlink_stands_for_code(rel) {
            // A deploy's `uploads` link is an ordinary site, not a partial scan.
            self.symlinks_skipped += 1;
            return;
        }
        let target = self.root.read_link(rel).ok();
        let sha = target.as_deref().map(link_hash);
        let listed = self.listed_in(rel);
        if listed.is_none() && sha.is_some() && self.input.trusted.get(rel) == sha.as_ref() {
            return;
        }
        let why = target
            .as_deref()
            .map_or_else(|| "symlink: not followed".to_string(), link_snippet);
        let mut item = self.unread_item(rel, why, sha.as_ref());
        item.symlink = true;
        // Where a manifest speaks, this is a failed comparison: no trust list can
        // override that.
        if let Some(i) = listed {
            item.kind = if self.comps[i].is_core() {
                FindingKind::CoreModified
            } else {
                FindingKind::UpstreamModified
            };
            item.source_label = self.comps[i].source_label();
        }
        self.push_review(item);
    }

    /// The component whose manifest lists this path.
    fn listed_in(&self, rel: &str) -> Option<usize> {
        let Route::Manifest(i, key) = self.route(rel) else {
            return None;
        };
        let listed = self.comps[i]
            .manifest
            .as_ref()
            .is_some_and(|m| m.files.contains_key(&key));
        (listed && !is_soft_file(&key)).then_some(i)
    }

    /// A WordPress deploy's link for `uploads` or a cache: what's in there would
    /// mostly have been ignored anyway. Elsewhere nothing is: a `vendor` link
    /// can lead anywhere, and the scan doesn't follow it.
    fn dir_link_is_ignored(&self, rel: &str) -> bool {
        self.input.discovery.is_wordpress
            && CHURN_DIRS
                .iter()
                .chain(std::iter::once(&UPLOADS_DIR))
                .any(|d| rel.starts_with(d) || d.strip_suffix('/') == Some(rel))
    }

    /// A symlink is only harmless where a file of that name wouldn't have been
    /// looked at anyway. Anywhere else it hides what would have been: a plugin's
    /// subfolder or a listed file behind one is never compared.
    fn symlink_stands_for_code(&self, rel: &str) -> bool {
        holds_code(rel) || self.owner(rel).is_some() || !matches!(self.route(rel), Route::Ignore)
    }

    /// A review item for a file this scan won't read.
    fn report_unread(&mut self, rel: &str, why: &str) {
        let item = self.unread_item(rel, why.to_string(), None);
        self.push_review(item);
    }

    fn unread_item(&self, rel: &str, why: String, sha: Option<&[u8; 32]>) -> SiteFileFinding {
        let component = self.owner(rel).map(|i| self.comps[i].slug().to_string());
        // An exact name for anything that could be acted on by name.
        let name = if rel.len() > self.limits.max_rel_bytes {
            short_name(rel)
        } else {
            rel.to_string()
        };
        SiteFileFinding {
            snippet: why,
            component,
            ..self.base_item(&name, FindingKind::BaselineChange, sha)
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
        match self.own.get(rel) {
            Some(OwnCheck::RulesOnly) => return Route::RulesOnly(None),
            Some(_) => return Route::Own,
            None => {}
        }
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

    /// Files here come and go by themselves: no change detection.
    fn is_churn_path(&self, rel: &str) -> bool {
        if self.input.discovery.is_wordpress {
            return CHURN_DIRS.iter().any(|d| rel.starts_with(d))
                || (rel.starts_with(UPLOADS_DIR) && !is_php_like(rel));
        }
        let mut dirs = rel.split('/');
        dirs.next_back();
        dirs.any(|d| NON_WP_CHURN_NAMES.contains(&d))
    }

    fn route_unverified(&self, rel: &str, owner: Option<usize>) -> Route {
        if !in_scope(rel) {
            return Route::Ignore;
        }
        if rel == MAINTENANCE {
            return Route::RulesOnly(owner);
        }
        let wordpress = self.input.discovery.is_wordpress;
        if self.is_churn_path(rel) {
            return if is_php_like(rel) || is_php_settings(rel) || (!wordpress && is_js(rel)) {
                Route::RulesOnly(owner)
            } else {
                Route::Ignore
            };
        }
        if !wordpress && is_js(rel) {
            return Route::RulesOnly(owner);
        }
        Route::Watch(owner)
    }

    fn on_file(&mut self, m: &FileMeta) {
        if m.rel.len() > self.limits.max_rel_bytes {
            if in_scope(&m.rel) {
                self.long_names += 1;
                self.report_unread(&m.rel, "file name too long to record: not read");
            }
            return;
        }
        match self.route(&m.rel) {
            Route::Own => {
                self.seen.visit(&m.rel);
                self.own_file(m);
            }
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
    /// records alone and goes into the partial reasons. None with `stopped` set
    /// means this run ends here, for the next one to resume.
    fn read(&mut self, m: &FileMeta, want_md5: bool) -> Option<FileRead> {
        if self.bytes_read.saturating_add(m.size) > self.limits.read_budget {
            self.out_of_budget = true;
            self.stopped = true;
            return None;
        }
        match read_file(self.root, &m.rel, want_md5, &mut self.buf, self.pause) {
            Ok(Some(r)) => {
                self.files_hashed += 1;
                self.hashed_since_flush += 1;
                self.bytes_read += r.bytes;
                Some(r)
            }
            Ok(None) => {
                self.stopped = true;
                None
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !self.is_churn_path(&m.rel) {
                    self.count_skip(&m.rel, SkipReason::Vanished);
                }
                None
            }
            Err(_) => {
                self.count_skip(&m.rel, SkipReason::Unreadable);
                None
            }
        }
    }

    /// Would one more name fit in the baseline?
    fn fits(&self, rel: &str) -> bool {
        self.recorded_bytes.saturating_add(recorded_cost(rel)) <= self.limits.recorded_rel_bytes
    }

    /// Account for a new name, or say there's no room for it.
    fn make_room(&mut self, rel: &str) -> bool {
        if !self.fits(rel) {
            self.not_recorded += 1;
            return false;
        }
        self.recorded_bytes += recorded_cost(rel);
        true
    }

    fn remember_entry(&mut self, m: &FileMeta, read: &FileRead) {
        if self.baseline.entries.contains_key(&m.rel) || self.make_room(&m.rel) {
            self.baseline
                .entries
                .insert(m.rel.clone(), entry_for(m, read));
        }
    }

    fn remember_churn(&mut self, m: &FileMeta, read: &FileRead) {
        if self.baseline.churn.contains_key(&m.rel) || self.make_room(&m.rel) {
            self.baseline
                .churn
                .insert(m.rel.clone(), entry_for(m, read));
        }
    }

    fn remember_verified(&mut self, m: &FileMeta, read: &FileRead, id: String) {
        self.remember_entry(m, read);
        if self.baseline.verified.contains_key(&m.rel) || self.make_room(&m.rel) {
            self.baseline.verified.insert(m.rel.clone(), id);
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
        // Translated, so the digest can't speak for it. A tenant can pick this
        // state with `$wp_local_package`, so the rules still have to.
        let rules_decide = comp.locale_fallback && m.rel == VERSION_PHP;
        if self.input.mode == ScanMode::Delta
            && !(rules_decide && self.rules_bumped)
            && self.baseline.verified.get(&m.rel) == Some(&comp.id)
            && classify(self.baseline.entries.get(&m.rel), m) == Change::Unchanged
        {
            return;
        }
        if m.size > HASH_MAX_BYTES {
            return self.mismatch(i, m, None, &[]);
        }
        // A release ships its default themes and `hello.php` with small differences
        // from their standalone copies, under the same version. What core's own
        // checksums list at this path is as good a reference.
        let bundled = self
            .core
            .filter(|c| *c != i)
            .and_then(|c| self.comps[c].manifest.as_ref())
            .and_then(|mf| mf.files.get(&m.rel))
            .cloned();
        let is_md5 = |d: &Digest| matches!(d, Digest::Md5(_) | Digest::Md5Any(_));
        let want_md5 = is_md5(&digest) || bundled.as_ref().is_some_and(is_md5);
        let Some(read) = self.read(m, want_md5) else {
            return;
        };
        let matched = digest_matches(&digest, &read)
            || bundled.as_ref().is_some_and(|d| digest_matches(d, &read));
        let hits = (rules_decide || !matched).then(|| rules_for(&m.rel, &read.head));
        let failed = match &hits {
            None => false,
            // Rules are its only check, so what they couldn't read can't pass.
            Some(h) if rules_decide => {
                read.head.len() > INSPECT_MAX_BYTES
                    || worst(h).is_some_and(|h| h.severity == Severity::High)
            }
            Some(_) => true,
        };
        if failed {
            let hits = hits.unwrap_or_default();
            return self.mismatch(i, m, Some(&read.sha256), &hits);
        }
        let id = self.comps[i].id.clone();
        self.remember_verified(m, &read, id);
    }

    /// One of Hyperion's own files: the digest it was written from speaks for it
    /// and a match needs no rules. The status page is judged by its shape, then by
    /// the rules.
    fn own_file(&mut self, m: &FileMeta) {
        let Some(check) = self.own.get(&m.rel).cloned() else {
            return;
        };
        let id = match &check {
            OwnCheck::Digest(d) => own_id(d),
            _ => "hyperion/shape".to_string(),
        };
        self.baseline.churn.remove(&m.rel);
        if self.input.mode == ScanMode::Delta
            && self.baseline.verified.get(&m.rel) == Some(&id)
            && classify(self.baseline.entries.get(&m.rel), m) == Change::Unchanged
        {
            return;
        }
        if m.size > OWN_READ_MAX {
            self.forget(&m.rel);
            return self.own_mismatch(m, None, &[]);
        }
        let Some(read) = self.read(m, false) else {
            return;
        };
        let fits = match &check {
            OwnCheck::Digest(d) => digest_matches(d, &read),
            _ => {
                read.head.len() <= INSPECT_MAX_BYTES
                    && std::str::from_utf8(&read.head).is_ok_and(status_shape_ok)
            }
        };
        let rules = !matches!(check, OwnCheck::Digest(_)) || !fits;
        let hits = if rules {
            rules_for(&m.rel, &read.head)
        } else {
            Vec::new()
        };
        if fits && hits.is_empty() {
            return self.remember_verified(m, &read, id);
        }
        self.forget(&m.rel);
        if fits {
            // Its shape is right, so only what the rules found is the news.
            return self.report_hits(m, None, &read.sha256, &hits);
        }
        self.own_mismatch(m, Some(&read.sha256), &hits);
    }

    /// Hyperion's file isn't what this binary writes. Right after an agent
    /// starts that is most likely the last version, waiting for the install tick,
    /// unless the rules say otherwise.
    fn own_mismatch(&mut self, m: &FileMeta, sha: Option<&[u8; 32]>, hits: &[RuleHit]) {
        let since = self.input.own_files_since;
        let in_grace =
            since > 0 && (0..OWN_GRACE_SECS).contains(&self.input.now.saturating_sub(since));
        let bad = worst(hits).is_some_and(|h| h.severity == Severity::High);
        let mut item = with_hits(
            SiteFileFinding {
                source_label: Some(OWN_LABEL.to_string()),
                snippet: "differs from what this Hyperion version writes".to_string(),
                ..self.base_item(&m.rel, FindingKind::UpstreamModified, sha)
            },
            hits,
        );
        if in_grace && !bad {
            self.push_review(item);
        } else {
            item.severity = severity_str(Severity::High).to_string();
            self.push_finding(item);
        }
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
        // `wp-cli.yml`, `error_log`, a plugin's storage: only code is a finding.
        if !in_scope(&m.rel) {
            self.seen.unvisit(&m.rel);
            return;
        }
        let comp = &self.comps[i];
        let vendor = comp
            .manifest
            .as_ref()
            .is_some_and(|mf| mf.source == ManifestSource::VendorPackage);
        if vendor && !comp.is_core() {
            // Some premium plugins write into their own folder.
            return self.watch(m, Some(i));
        }
        self.forget(&m.rel);
        self.comps[i].added += 1;
        let core = self.comps[i].is_core();
        // Past the cap it won't be listed, so there's nothing to read it for.
        if self.comps[i].items.len() >= self.limits.max_items {
            return self.stage(i, m, added_kind(core), None, &[]);
        }
        if m.size > NO_MANIFEST_READ_MAX {
            let meta = metadata_hash_of(m);
            return self.stage(i, m, added_kind(core), Some(&meta), &[]);
        }
        let Some(read) = self.read(m, false) else {
            return;
        };
        let hits = rules_for(&m.rel, &read.head);
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
            self.comps[i].dropped += 1;
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
            ..self.base_item(
                &m.rel,
                FindingKind::TooLargeToInspect,
                Some(&metadata_hash_of(m)),
            )
        };
        self.push_review(item);
    }

    fn note_partly_inspected(&mut self, m: &FileMeta) {
        if m.size > INSPECT_MAX_BYTES as u64 && !size_is_a_loose_end(&m.rel) {
            self.partly_inspected += 1;
        }
    }

    /// Too big to be worth reading with nothing to compare it with? What PHP runs
    /// or obeys is always reported. Otherwise metadata can still tell what's new
    /// or changed since the first scan, and what was there at the first scan is
    /// remembered by it.
    fn too_big_to_read(
        &mut self,
        m: &FileMeta,
        owner: Option<usize>,
        change: Change,
        rules_only: bool,
    ) -> bool {
        if m.size <= NO_MANIFEST_READ_MAX {
            return false;
        }
        // Someone vouched for it as it stands. It comes back when it's touched.
        if self.input.trusted.get(&m.rel) == Some(&metadata_hash_of(m)) {
            self.remember_unread(m, rules_only);
            return true;
        }
        if size_is_a_loose_end(&m.rel) {
            self.report_oversize(m, owner);
            return true;
        }
        match change {
            Change::Unchanged => {}
            Change::New if self.first => self.remember_unread(m, rules_only),
            Change::NeedsHash if !rules_only => {
                let item = SiteFileFinding {
                    snippet: format!("{} bytes: changed, too large to read", m.size),
                    component: self.component_of(owner),
                    ..self.base_item(
                        &m.rel,
                        FindingKind::BaselineChange,
                        Some(&metadata_hash_of(m)),
                    )
                };
                self.push_review(item);
            }
            _ => self.report_oversize(m, owner),
        }
        true
    }

    fn remember_unread(&mut self, m: &FileMeta, rules_only: bool) {
        let known = if rules_only {
            self.baseline.churn.contains_key(&m.rel)
        } else {
            self.baseline.entries.contains_key(&m.rel)
        };
        if !known && !self.make_room(&m.rel) {
            return;
        }
        let entry = BaselineEntry {
            size: m.size,
            ctime: m.ctime,
            ctime_nsec: m.ctime_nsec,
            sha256: METADATA_ONLY,
        };
        let map = if rules_only {
            &mut self.baseline.churn
        } else {
            &mut self.baseline.entries
        };
        map.insert(m.rel.clone(), entry);
    }

    /// Steps 2 and 3: baseline and rules.
    fn watch(&mut self, m: &FileMeta, owner: Option<usize>) {
        self.baseline.churn.remove(&m.rel);
        self.baseline.verified.remove(&m.rel);
        self.note_partly_inspected(m);
        let change = classify(self.baseline.entries.get(&m.rel), m);
        if change == Change::Unchanged && self.input.mode == ScanMode::Delta && !self.rules_bumped {
            return;
        }
        if self.too_big_to_read(m, owner, change, false) {
            return;
        }
        let Some(read) = self.read(m, false) else {
            return;
        };
        let trusted = self.input.trusted.get(&m.rel) == Some(&read.sha256);
        let same = self
            .baseline
            .entries
            .get(&m.rel)
            .is_some_and(|e| e.sha256 == read.sha256);
        if same {
            // Only a High hit from a newer pack takes back what was accepted.
            if self.rules_bumped && !trusted {
                let hits = rules_for(&m.rel, &read.head);
                if worst(&hits).is_some_and(|h| h.severity == Severity::High) {
                    self.baseline.entries.remove(&m.rel);
                    return self.report_hits(m, owner, &read.sha256, &hits);
                }
            }
            return self.remember_entry(m, &read);
        }
        if trusted {
            return self.remember_entry(m, &read);
        }
        let hits = rules_for(&m.rel, &read.head);
        if !hits.is_empty() {
            return self.report_hits(m, owner, &read.sha256, &hits);
        }
        let accept = owner.is_some_and(|i| self.comps[i].accept_update);
        if self.first || accept {
            self.remember_entry(m, &read);
            if !self.first && self.auto_accepted.len() < AUTO_ACCEPTED_CAP {
                self.auto_accepted.push(m.rel.clone());
            }
            return;
        }
        // Something we wrote, and exactly as we wrote it: the rules found nothing,
        // so it is what we meant. Past the audit cap nothing is remembered
        // unlisted: it goes to review instead.
        if self.auto_accepted.len() < AUTO_ACCEPTED_CAP {
            if let Some(label) = self.written_by(m, &read.sha256) {
                self.remember_entry(m, &read);
                self.auto_accepted.push(m.rel.clone());
                let item = SiteFileFinding {
                    component: self.component_of(owner),
                    source_label: Some(label.to_string()),
                    ..self.base_item(&m.rel, FindingKind::BaselineChange, Some(&read.sha256))
                };
                self.accepted_by_writer.push(item);
                return;
            }
        }
        // With the baseline full, "no entry" says nothing about the file: the
        // rules found nothing, and the partial reason covers the rest.
        if !self.baseline.entries.contains_key(&m.rel) && !self.fits(&m.rel) {
            self.not_recorded += 1;
            return;
        }
        let item = SiteFileFinding {
            component: self.component_of(owner),
            ..self.base_item(&m.rel, FindingKind::BaselineChange, Some(&read.sha256))
        };
        self.push_review(item);
    }

    /// The writer whose list holds this path with exactly this content.
    fn written_by(&self, m: &FileMeta, sha: &[u8; 32]) -> Option<&'static str> {
        let acc = self.input.accepted.as_ref()?;
        (acc.files.get(&m.rel) == Some(sha)).then(|| acc.kind.label())
    }

    /// Churn paths: rules on what's new by its metadata, and nothing else. A
    /// clean file is remembered so it isn't read again; one with a hit isn't, so
    /// it keeps being reported.
    fn rules_only(&mut self, m: &FileMeta, owner: Option<usize>) {
        self.forget(&m.rel);
        self.note_partly_inspected(m);
        let change = classify(self.baseline.churn.get(&m.rel), m);
        if change == Change::Unchanged && self.input.mode == ScanMode::Delta {
            return;
        }
        if self.too_big_to_read(m, owner, change, true) {
            return;
        }
        let Some(read) = self.read(m, false) else {
            return;
        };
        if self.input.trusted.get(&m.rel) != Some(&read.sha256) {
            let hits = rules_for(&m.rel, &read.head);
            if !hits.is_empty() {
                self.baseline.churn.remove(&m.rel);
                return self.report_hits(m, owner, &read.sha256, &hits);
            }
        }
        self.remember_churn(m, &read);
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
            let core = self.comps[i].is_core();
            let mut missing = Vec::new();
            for (_, rel) in self.comps[i].in_scope_files() {
                if self.seen.visited(&rel) || (core && CORE_OPTIONAL.contains(&rel.as_str())) {
                    continue;
                }
                if self.seen.may_exist(&rel) {
                    self.listed_unchecked += 1;
                } else {
                    missing.push(rel);
                }
            }
            let kind = if core {
                FindingKind::CoreMissing
            } else {
                FindingKind::UpstreamMissing
            };
            for rel in missing {
                self.forget(&rel);
                self.comps[i].missing += 1;
                if self.comps[i].items.len() >= self.limits.max_items {
                    self.comps[i].dropped += 1;
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

    /// Most of a component differing, or a pile of code added to it, is one fact,
    /// not hundreds: a mass injector or a private plugin in a wordpress.org slug's
    /// folder. Either way one High finding on the folder says it.
    fn group_components(&mut self) {
        for comp in &mut self.comps {
            let differ = comp.modified + comp.missing;
            let many_added = comp.added >= GROUP_ADDED_CODE;
            if differ == 0 && !many_added {
                continue;
            }
            let total = comp.in_scope_files().len();
            let most_differ = total >= GROUP_MIN_FILES && differ.saturating_mul(2) > total as u64;
            if !most_differ && !many_added {
                continue;
            }
            let label = comp.reference_label().unwrap_or_default();
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
            comp.dropped = 0;
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
            dropped += comp.dropped;
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
                    version: comp.c.key.version.clone(),
                    source: comp.source_label(),
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
                SkipReason::NotRegular => "special files not read",
                SkipReason::HardLinked => "hard-linked files not read",
                SkipReason::Unreadable => "files or directories could not be read",
                SkipReason::NonUtf8Name => "names that aren't UTF-8 not looked at",
                SkipReason::Vanished => "files vanished during the scan",
                SkipReason::OtherFilesystem => "directories on another filesystem not looked at",
                SkipReason::Symlink | SkipReason::FileCapReached => continue,
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
        if self.out_of_budget {
            out.push(format!(
                "this run's read budget of {} bytes ran out; the scan resumes on the next run",
                self.limits.read_budget
            ));
        } else if self.stopped {
            out.push("the scan was stopped early and resumes on the next run".to_string());
        }
        if self.dir_links > 0 {
            let mut names = self.dir_links_named.join(", ");
            let more = self.dir_links - self.dir_links_named.len() as u64;
            if more > 0 {
                names.push_str(&format!(", and {more} more"));
            }
            out.push(format!("symlinked directories not looked at: {names}"));
        }
        if self.long_names > 0 {
            out.push(format!(
                "{} files with names over {} bytes were not recorded or read",
                self.long_names, self.limits.max_rel_bytes
            ));
        }
        if self.not_recorded > 0 {
            out.push(format!(
                "the baseline has no room for more names; {} files are not watched for changes",
                self.not_recorded
            ));
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

        let mut trust_gone = Vec::new();
        if complete {
            self.add_missing();
            let seen = &self.seen;
            trust_gone.extend(
                self.input
                    .trusted
                    .keys()
                    .filter(|p| !seen.may_exist(p))
                    .cloned(),
            );
            self.baseline.entries.retain(|p, _| seen.may_exist(p));
            self.baseline.verified.retain(|p, _| seen.may_exist(p));
            self.baseline.churn.retain(|p, _| seen.may_exist(p));
        }
        if self.listed_unchecked > 0 {
            reasons.push(format!(
                "{} files with an upstream checksum could not be checked: something in their path is not a plain file or directory",
                self.listed_unchecked
            ));
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
        let vendor_verified = |kind: ComponentKind| -> i64 {
            let n = self
                .comps
                .iter()
                .filter(|c| c.c.key.kind == kind && c.is_vendor_verified())
                .count();
            i64::try_from(n).unwrap_or(i64::MAX)
        };
        let coverage = ScanCoverage {
            plugins_verified: count(ComponentKind::Plugin, true),
            plugins_vendor_verified: vendor_verified(ComponentKind::Plugin),
            themes_vendor_verified: vendor_verified(ComponentKind::Theme),
            plugins_total: count(ComponentKind::Plugin, false),
            themes_verified: count(ComponentKind::Theme, true),
            themes_total: count(ComponentKind::Theme, false),
            files_watched: i64::try_from(self.baseline.entries.len()).unwrap_or(i64::MAX),
            watching_since: self.baseline.since,
            files_partly_inspected: self.partly_inspected,
            symlinks_skipped: self.symlinks_skipped,
            upstream_ran: ran,
            no_upstream: !d.is_wordpress,
            partial_reasons: reasons,
            ..Default::default()
        };
        SiteScanOutcome {
            upstream,
            findings,
            review: self.review,
            coverage,
            auto_accepted: self.auto_accepted,
            accepted_by_writer: self.accepted_by_writer,
            files_hashed: self.files_hashed,
            stopped: self.stopped,
            capped: stats.capped,
            trust_gone,
            absent_carried: Vec::new(),
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
            wporg_known_slugs: Some(BTreeSet::new()),
            accepted: None,
            own_expected: BTreeMap::new(),
            own_files_since: 0,
            trusted: BTreeMap::new(),
            carried_rels: Vec::new(),
        }
    }

    fn tree() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().expect("tmp");
        let base = t.path().canonicalize().expect("canonical");
        let root = base.join("htdocs");
        fs::create_dir(&root).expect("mkdir");
        (t, base, root)
    }

    /// Each save writes the whole baseline, so a fixed interval costs the square of
    /// the site: measured, 3.1 GB written and 11 CPU minutes over 300k files.
    #[test]
    fn saves_of_a_big_first_scan_cost_about_what_it_records() {
        let (mut recorded, mut since, mut saved) = (0u64, 0u64, 0u64);
        for _ in 0..300_000 {
            recorded += 1;
            since += 1;
            if flush_due(since, recorded) {
                saved += recorded;
                since = 0;
            }
        }
        assert!(saved < 12 * recorded, "{saved} lines for {recorded}");
        assert!(flush_due(FLUSH_EVERY_HASHED, FLUSH_EVERY_HASHED));
        assert!(!flush_due(FLUSH_EVERY_HASHED - 1, 100));
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
            bytes: 0,
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
            ..LIMITS
        };
        let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        let reasons = &out.coverage.partial_reasons;
        assert!(
            reasons.iter().any(|r| r.contains("limit of 20")),
            "{reasons:?}"
        );
        assert!(out.capped);
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
            max_items: 10,
            ..LIMITS
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

    /// A plugin on disk with a wordpress.org manifest listing `listed` files, the
    /// first `gone` of which aren't on disk.
    fn verified_plugin(base: &Path, root: &Path, listed: usize, gone: usize) {
        let mut files = BTreeMap::new();
        let main = b"<?php\n/*\nPlugin Name: p\nVersion: 1\n*/\n";
        write(root, "wp-content/plugins/p/p.php", main);
        files.insert(
            "p.php".to_string(),
            Digest::Sha256(Sha256::digest(main).into()),
        );
        for i in 0..listed {
            let body = format!("<?php // {i}\n");
            if i >= gone {
                write(
                    root,
                    &format!("wp-content/plugins/p/f{i}.php"),
                    body.as_bytes(),
                );
            }
            files.insert(
                format!("f{i}.php"),
                Digest::Sha256(Sha256::digest(body.as_bytes()).into()),
            );
        }
        let key = ComponentKey {
            kind: ComponentKind::Plugin,
            slug: "p".into(),
            version: "1".into(),
            locale: None,
        };
        let p = cache_path(&base.join("m"), &key).expect("path");
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        let manifest = Manifest {
            source: ManifestSource::WordPressOrg,
            files,
            served_locale: None,
        };
        fs::write(p, serde_json::to_vec(&manifest).expect("json")).expect("write");
    }

    #[test]
    fn dropped_added_files_are_counted() {
        let (_t, base, root) = tree();
        write(&root, "wp-load.php", b"<?php\n");
        verified_plugin(&base, &root, 1, 0);
        for i in 0..12 {
            write(
                &root,
                &format!("wp-content/plugins/p/own/o{i}.php"),
                b"<?php\n",
            );
        }
        let limits = Limits {
            max_items: 10,
            ..LIMITS
        };
        let out = scan_with_limits(&input(&base, &root), &|| false, &limits).expect("scan");
        assert_eq!(out.findings.len(), 10);
        let reasons = &out.coverage.partial_reasons;
        assert!(
            reasons.iter().any(|r| r.contains("2 more findings")),
            "{reasons:?}"
        );
    }

    #[test]
    fn dropped_missing_files_are_counted() {
        let (_t, base, root) = tree();
        write(&root, "wp-load.php", b"<?php\n");
        verified_plugin(&base, &root, 42, 12);
        let limits = Limits {
            max_items: 10,
            ..LIMITS
        };
        let out = scan_with_limits(&input(&base, &root), &|| false, &limits).expect("scan");
        assert_eq!(out.findings.len(), 10);
        let reasons = &out.coverage.partial_reasons;
        assert!(
            reasons.iter().any(|r| r.contains("2 more findings")),
            "{reasons:?}"
        );
    }

    #[test]
    fn a_name_over_the_limit_is_named_and_never_recorded() {
        let (_t, base, root) = tree();
        let long = "app/a-name-well-over-the-limit.php";
        write(&root, long, b"<?php\n");
        write(&root, "app/ok.php", b"<?php\n");
        write(&root, "app/not-code-well-over-the-limit.txt", b"x");
        let limits = Limits {
            max_rel_bytes: 20,
            ..LIMITS
        };
        let inp = input(&base, &root);
        let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        assert_eq!(out.review.len(), 1, "{:?}", out.review);
        assert_eq!(out.review[0].rel, long);
        assert_eq!(out.files_hashed, 1);
        let reasons = &out.coverage.partial_reasons;
        assert!(
            reasons.iter().any(|r| r.contains("over 20 bytes")),
            "{reasons:?}"
        );
        let b = Baseline::load(&inp.baseline_path)
            .expect("load")
            .expect("some");
        assert_eq!(b.entries.keys().collect::<Vec<_>>(), ["app/ok.php"]);
    }

    #[test]
    fn a_full_baseline_stops_recording_and_says_so() {
        let (_t, base, root) = tree();
        for i in 10..20 {
            write(&root, &format!("app/f{i}.php"), b"<?php\n");
        }
        // Room for three of these 11-byte names.
        let limits = Limits {
            recorded_rel_bytes: 40,
            ..LIMITS
        };
        let inp = input(&base, &root);
        let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        let has_reason = |o: &SiteScanOutcome| {
            o.coverage
                .partial_reasons
                .iter()
                .any(|r| r.contains("no room"))
        };
        assert!(has_reason(&out), "{:?}", out.coverage.partial_reasons);
        let b = Baseline::load(&inp.baseline_path)
            .expect("load")
            .expect("some");
        assert_eq!(b.entries.len(), 3);

        // The next run: what's in still works, what isn't raises no false change.
        let recorded = b.entries.keys().next().expect("one").clone();
        write(&root, &recorded, b"<?php // edited\n");
        let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        assert!(has_reason(&out));
        let got: Vec<&str> = out.review.iter().map(|r| r.rel.as_str()).collect();
        assert_eq!(got, [recorded.as_str()]);

        // And the rules still run on files with no room.
        write(
            &root,
            "app/new.php",
            b"<?php eval(base64_decode('QQ=='));\n",
        );
        let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        assert_eq!(out.findings.len(), 1);
    }

    #[test]
    fn a_name_costs_what_it_costs_once_escaped() {
        assert_eq!(recorded_cost("abc"), 3);
        assert_eq!(recorded_cost("a\u{1}\"\\"), 1 + 6 + 2 + 2);
        assert_eq!(recorded_cost("é"), 2);
    }

    #[test]
    fn the_real_budgets_keep_the_baseline_loadable() {
        // All names share the budget, escapes counted. Add the rest of a file's
        // line and a verified line for every file at the walk's limit, and it's
        // still under the 200 MiB `Baseline::load` reads.
        let per_file = 130 + 70;
        let most = LIMITS.recorded_rel_bytes + per_file * LIMITS.max_entries;
        assert!(most < 200 * 1024 * 1024, "{most}");
    }

    #[test]
    fn the_read_budget_stops_the_run_and_the_next_resumes() {
        let (_t, base, root) = tree();
        for i in 0..10 {
            write(&root, &format!("app/f{i}.php"), &[b'/'; 300]);
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
        let limits = Limits {
            read_budget: 1000,
            ..LIMITS
        };
        let inp = input(&base, &root);
        let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
        assert!(out.stopped);
        assert_eq!(out.files_hashed, 3);
        let reasons = &out.coverage.partial_reasons;
        assert!(reasons.iter().any(|r| r.contains("budget")), "{reasons:?}");

        let mut runs = 1;
        loop {
            let out = scan_with_limits(&inp, &|| false, &limits).expect("scan");
            runs += 1;
            assert!(runs <= 4, "no progress");
            if !out.stopped {
                assert!(out.review.is_empty(), "still a first scan");
                assert_eq!(out.coverage.partial_reasons, Vec::<String>::new());
                break;
            }
        }
        let b = Baseline::load(&inp.baseline_path)
            .expect("load")
            .expect("some");
        assert_eq!(b.entries.len(), 10);
    }

    #[test]
    fn pause_is_asked_inside_a_long_read() {
        let (_t, base, root) = tree();
        write(&root, "app/big.js", b"");
        write(&root, "app/big.php", b"");
        let grow = |rel: &str| {
            fs::File::options()
                .write(true)
                .open(root.join(rel))
                .expect("open")
                .set_len(20 * 1024 * 1024)
                .expect("grow");
        };
        grow("app/big.js");
        grow("app/big.php");
        let inp = input(&base, &root);
        let calls = std::cell::Cell::new(0);
        let stop = || {
            calls.set(calls.get() + 1);
            true
        };
        let out = scan_with_limits(&inp, &stop, &LIMITS).expect("scan");
        assert_eq!(calls.get(), 1);
        assert!(out.stopped);
        assert_eq!(out.files_hashed, 0, "that read didn't finish");
    }

    #[test]
    fn pause_is_asked_every_256_skipped_events() {
        let (_t, base, root) = tree();
        let inp = input(&base, &root);
        let tenant = TenantRoot::open(&root).expect("open");
        let calls = std::cell::Cell::new(0);
        let pause = || {
            calls.set(calls.get() + 1);
            calls.get() == 2
        };
        let mut scan = Scan::new(&inp, &tenant, Loaded::Missing, &LIMITS, &pause);
        let skip = || WalkEvent::Skipped {
            rel: "fifo".to_string(),
            why: SkipReason::NotRegular,
        };
        for _ in 0..255 {
            assert!(scan.on_event(skip()).is_continue());
        }
        assert_eq!(calls.get(), 0);
        assert!(scan.on_event(skip()).is_continue());
        assert_eq!(calls.get(), 1);
        for _ in 0..255 {
            assert!(scan.on_event(skip()).is_continue());
        }
        // The second ask says stop.
        assert!(scan.on_event(skip()).is_break());
        assert_eq!(calls.get(), 2);
        assert!(scan.finish(WalkStats::default()).stopped);
    }

    #[test]
    fn a_vanished_file_is_partial_only_outside_churn() {
        let (_t, base, root) = tree();
        write(&root, "wp-load.php", b"<?php\n");
        write(&root, "wp-config.php", b"<?php\n");
        let inp = input(&base, &root);
        let tenant = TenantRoot::open(&root).expect("open");
        let pause = || false;
        let mut scan = Scan::new(&inp, &tenant, Loaded::Missing, &LIMITS, &pause);
        let vanish = |rel: &str| WalkEvent::Skipped {
            rel: rel.to_string(),
            why: SkipReason::Vanished,
        };
        let _ = scan.on_event(vanish("wp-content/cache/x.php"));
        let _ = scan.on_event(vanish("wp-content/uploads/a.js"));
        let _ = scan.on_event(vanish("wp-content/themes/t/functions.php"));
        let out = scan.finish(WalkStats::default());
        let vanished: Vec<&String> = out
            .coverage
            .partial_reasons
            .iter()
            .filter(|r| r.contains("vanished"))
            .collect();
        assert_eq!(vanished.len(), 1, "{vanished:?}");
        assert!(vanished[0].starts_with("1 "), "{}", vanished[0]);
        assert!(vanished[0].contains("functions.php"), "{}", vanished[0]);
    }

    #[test]
    fn a_link_whose_target_cant_be_read_has_no_hash() {
        let (_t, base, root) = tree();
        write(&root, "index.php", b"<?php\n");
        let inp = input(&base, &root);
        let tenant = TenantRoot::open(&root).expect("open");
        let pause = || false;
        let mut scan = Scan::new(&inp, &tenant, Loaded::Missing, &LIMITS, &pause);
        // Reported by the walk, gone by the time it's asked about.
        let _ = scan.on_event(WalkEvent::Skipped {
            rel: "app/x.php".to_string(),
            why: SkipReason::Symlink,
        });
        let out = scan.finish(WalkStats::default());
        assert_eq!(out.review.len(), 1);
        assert_eq!(out.review[0].sha256, "");
        assert!(out.review[0].snippet.contains("symlink"));
    }

    #[test]
    fn a_link_snippet_is_plain_and_short() {
        let s = link_snippet("a\u{1}b\nc".repeat(100).as_bytes());
        assert!(s.starts_with("symlink to a b c"), "{s}");
        assert!(s.chars().count() <= 120);
        assert!(!s.chars().any(char::is_control));
    }
}
