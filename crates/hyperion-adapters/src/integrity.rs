//! ClamAV adapter: the optional signature pass beside the native site scan in
//! `sitescan`. Its database costs over a gigabyte of RAM, so it is never
//! required and never installed for the operator: a missing binary means "not
//! available", never an error and never a false "clean".
//!
//! One `clamscan` runs per sweep, over a file list our own walker wrote for
//! every scanned site, so the database is loaded once instead of once per site.
//! It runs in a capped transient unit and its stdout is read as it arrives: a
//! pass that is killed halfway still hands back the detections it printed.
//!
//! What shells out is at the top of this module; what parses and decides is in
//! pure functions, unit-tested against real-shaped clamscan and systemd output.
//! Getting those wrong is how this feature would lie to a paying customer, so
//! they are the part that is tested hardest.

use crate::sitescan::pressure::host_cores;
use crate::sitescan::walk::{SkipReason, TenantRoot, WalkEvent, WalkOpts};
use crate::AdapterError;
use hyperion_types::{HostingId, WpMalwareHit};
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Where `clamscan` may live. Debian's `clamav` package ships
/// `/usr/bin/clamscan`; source builds land in `/usr/local/bin`.
const CLAMSCAN_BINS: &[&str] = &["/usr/bin/clamscan", "/usr/local/bin/clamscan"];

/// Where freshclam keeps the signature database.
const CLAMAV_DB_DIR: &str = "/var/lib/clamav";

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const NICE: &str = "/usr/bin/nice";
/// Fixed, so systemd itself refuses a second pass on the node.
pub const UNIT_NAME: &str = "hyperion-clamscan";
/// The unit is stopped after this long (6 hours).
const RUNTIME_MAX_SEC: u64 = 21_600;

/// The pass needs this much `MemAvailable` to start: the signature database is
/// over a gigabyte once loaded, and the unit is capped at 3 GiB.
pub const MIN_MEM_AVAILABLE: u64 = 2 << 30;
/// A pass the kernel killed for memory is not tried again for this long.
pub const OOM_BACKOFF_SECS: i64 = 7 * 24 * 3600;

/// Files bigger than this are not handed to clamscan, and clamscan is told the
/// same, so a list can't be made to cost more than the flags allow.
const MAX_FILE_BYTES: u64 = 64 << 20;
/// Detections kept per hosting. A site with more has bigger problems than a
/// full list, and the sweep says so.
const MAX_HITS_PER_ROOT: usize = 1000;
/// Directory entries one site's walk may look at.
const LIST_MAX_ENTRIES: u64 = 2_000_000;
/// How much of the unit's stderr is kept: systemd's verdict is its last lines.
const STDERR_TAIL_BYTES: usize = 4096;

/// Files ClamAV isn't given: images, video, audio, fonts and PDFs are most of a
/// site's bytes and a poor place for the signatures it has to offer.
const MEDIA_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "svg", "mp4", "webm", "mov", "avi", "mp3", "wav", "woff",
    "woff2", "ttf", "eot", "pdf",
];

// ---------------------------------------------------------------------------
// What the node is like
// ---------------------------------------------------------------------------

/// What the node can say about running the pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClamFacts {
    pub installed: bool,
    /// Signatures are there. Right after the package installs, `freshclam` is
    /// still downloading them and `clamscan` exits 2 with "No supported
    /// database files found": a state to wait out, not a scan that failed.
    pub db_present: bool,
    /// `MemAvailable`, in bytes. 0 when unreadable, which never lets it run.
    pub mem_available: u64,
}

impl ClamFacts {
    pub fn read() -> Self {
        Self {
            installed: clamav_available(),
            db_present: clamav_db_present(),
            mem_available: std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|t| parse_mem_available(&t))
                .unwrap_or(0),
        }
    }
}

/// `MemAvailable` from `/proc/meminfo`, in bytes.
pub fn parse_mem_available(text: &str) -> Option<u64> {
    let kib: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

/// Does this node have its ClamAV signatures yet?
pub fn clamav_db_present() -> bool {
    clamav_db_present_in(Path::new(CLAMAV_DB_DIR))
}

/// The base signatures are `main` and `daily`, each a `.cvd` or, once updated,
/// a `.cld`. Either alone is an update still downloading.
fn clamav_db_present_in(dir: &Path) -> bool {
    let has = |stem: &str| {
        std::fs::read_dir(dir).is_ok_and(|rd| {
            rd.flatten().any(|e| {
                let p = e.path();
                p.file_stem().and_then(|x| x.to_str()) == Some(stem)
                    && matches!(p.extension().and_then(|x| x.to_str()), Some("cvd" | "cld"))
            })
        })
    };
    has("main") && has("daily")
}

/// First `clamscan` binary that exists on this node, if any.
fn clamscan_bin() -> Option<&'static str> {
    CLAMSCAN_BINS
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
}

/// Is an on-demand ClamAV scanner installed here? Absence is a normal
/// state, not an error: the operator may simply not want a scanner
/// resident on a shared host.
pub fn clamav_available() -> bool {
    clamscan_bin().is_some()
}

/// Whether the weekly pass may start, and if not, why. Not running is never a
/// failure and never "clean": the caller says so on the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClamPreflight {
    Run,
    /// Under [`MIN_MEM_AVAILABLE`] free.
    SkipLowMemory,
    SignaturesDownloading,
    /// The last pass was killed for memory and is resting.
    BackingOff,
    NotInstalled,
}

/// Node facts come in as arguments so this stays testable.
pub fn clamav_preflight(
    installed: bool,
    mem_available: u64,
    db_present: bool,
    backoff_until: i64,
    now: i64,
) -> ClamPreflight {
    if !installed {
        ClamPreflight::NotInstalled
    } else if !db_present {
        ClamPreflight::SignaturesDownloading
    } else if now < backoff_until {
        ClamPreflight::BackingOff
    } else if mem_available < MIN_MEM_AVAILABLE {
        ClamPreflight::SkipLowMemory
    } else {
        ClamPreflight::Run
    }
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

/// A path longer than this is not listed. clamscan splits `--file-list` lines at
/// 1023 bytes, and the pieces would be scanned (and reported) as paths of their
/// own; this stays well under.
pub const MAX_LISTED_PATH: usize = 1000;

/// What the list may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClamLimits {
    /// Files one site gives the pass.
    pub site_files: usize,
    /// Bytes of paths the whole list may hold. Past it, the sites still to be
    /// listed are partial: the list lives on disk, so this is a disk and
    /// clamscan-time cap, not a memory one.
    pub node_bytes: u64,
}

impl Default for ClamLimits {
    fn default() -> Self {
        Self {
            site_files: 300_000,
            node_bytes: 256 << 20,
        }
    }
}

/// What one site gave the list, and what it could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteListing {
    pub id: HostingId,
    /// Paths written.
    pub files: u64,
    /// Files whose names can't go in a one-path-per-line list: a control
    /// character (a newline would add a line of the tenant's choosing), bytes that
    /// aren't UTF-8, or more than [`MAX_LISTED_PATH`] bytes.
    pub left_out: u64,
    /// Files the walk could not hand over: hard-linked (both names are skipped, so
    /// `ln shell.php .x` would hide it), unreadable, on another filesystem, past
    /// the walker's entry limit. Symlinks, special files and files that vanished
    /// hide no content and are not counted; media and files over 64 MiB are
    /// left out by design and are not counted either.
    pub skipped: u64,
    /// The site's file cap, or the walker's entry limit, ended the list early.
    pub capped: bool,
    /// The node's byte cap was reached in or before this site.
    pub node_full: bool,
    /// The walk failed, so the list may be short.
    pub failed: bool,
}

impl SiteListing {
    pub fn new(id: HostingId) -> Self {
        Self {
            id,
            files: 0,
            left_out: 0,
            skipped: 0,
            capped: false,
            node_full: false,
            failed: false,
        }
    }

    /// Something was not given to ClamAV, so a pass that read everything it was
    /// given still has not covered this site.
    pub fn is_partial(&self) -> bool {
        self.left_out > 0 || self.skipped > 0 || self.capped || self.node_full || self.failed
    }
}

/// 128 bits of the path's BLAKE3: enough that the tenant can't make another path
/// collide with a listed one, at 16 bytes each instead of the path.
fn path_key(path: &str) -> u128 {
    let h = blake3::hash(path.as_bytes());
    let mut k = [0u8; 16];
    k.copy_from_slice(&h.as_bytes()[..16]);
    u128::from_le_bytes(k)
}

fn is_media(rel: &str) -> bool {
    rel.rsplit_once('.')
        .is_some_and(|(_, ext)| MEDIA_EXTENSIONS.iter().any(|m| m.eq_ignore_ascii_case(ext)))
}

fn listable(name: &str) -> bool {
    name.len() <= MAX_LISTED_PATH && !name.chars().any(char::is_control)
}

/// Removes the list when the pass is over, however it ended.
#[derive(Debug)]
struct ListFile(PathBuf);

impl Drop for ListFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

enum Added {
    Yes,
    LeftOut,
    NodeFull,
}

/// The list, written as the walk goes. Only the paths' hashes are kept.
struct ListWriter {
    out: std::io::BufWriter<std::fs::File>,
    listed: HashSet<u128>,
    bytes: u64,
    limit: u64,
    full: bool,
}

impl ListWriter {
    /// A stale file from a crashed pass is replaced, never appended to or
    /// followed; the new one is readable by root alone.
    fn create(path: &Path, limit: u64) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            out: std::io::BufWriter::new(file),
            listed: HashSet::new(),
            bytes: 0,
            limit,
            full: false,
        })
    }

    fn add(&mut self, path: &str) -> std::io::Result<Added> {
        use std::io::Write;
        if !listable(path) {
            return Ok(Added::LeftOut);
        }
        let cost = path.len() as u64 + 1;
        if self.bytes + cost > self.limit {
            self.full = true;
            return Ok(Added::NodeFull);
        }
        self.out.write_all(path.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.bytes += cost;
        self.listed.insert(path_key(path));
        Ok(Added::Yes)
    }
}

/// Walk one docroot into the list: every regular file but media and anything
/// over 64 MiB, as an absolute path.
fn list_site(
    root: &Path,
    w: &mut ListWriter,
    site_files: usize,
    listing: &mut SiteListing,
) -> std::io::Result<()> {
    let base = root
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "root is not UTF-8"))?
        .trim_end_matches('/');
    let tenant = TenantRoot::open(root)?;
    let opts = WalkOpts {
        max_entries: LIST_MAX_ENTRIES,
        prune: Vec::new(),
    };
    let mut io_err: Option<std::io::Error> = None;
    let stats = tenant.walk_until(&opts, |ev| {
        match ev {
            WalkEvent::File(m) => {
                if m.size > MAX_FILE_BYTES || is_media(&m.rel) {
                    return ControlFlow::Continue(());
                }
                if listing.files as usize >= site_files {
                    listing.capped = true;
                    return ControlFlow::Break(());
                }
                match w.add(&format!("{base}/{}", m.rel)) {
                    Ok(Added::Yes) => listing.files += 1,
                    Ok(Added::LeftOut) => listing.left_out += 1,
                    Ok(Added::NodeFull) => {
                        listing.node_full = true;
                        return ControlFlow::Break(());
                    }
                    Err(e) => {
                        io_err = Some(e);
                        return ControlFlow::Break(());
                    }
                }
            }
            WalkEvent::Skipped { why, .. } => match why {
                SkipReason::NonUtf8Name => listing.left_out += 1,
                SkipReason::HardLinked
                | SkipReason::Unreadable
                | SkipReason::OtherFilesystem
                | SkipReason::FileCapReached => listing.skipped += 1,
                SkipReason::Symlink | SkipReason::NotRegular | SkipReason::Vanished => {}
            },
        }
        ControlFlow::Continue(())
    })?;
    if let Some(e) = io_err {
        return Err(e);
    }
    listing.capped |= stats.capped;
    Ok(())
}

/// What the sweep is about to read: the list on disk, which site gave what, and
/// the hash of every listed path, which is what a detection or an error line has
/// to match to be believed. Dropping it removes the list.
#[derive(Debug)]
pub struct ClamPlan {
    _file: ListFile,
    list_path: PathBuf,
    /// The hostings' roots, to attribute what the pass says.
    pub roots: Vec<(HostingId, String)>,
    pub sites: Vec<SiteListing>,
    listed: Arc<HashSet<u128>>,
    files: u64,
}

impl ClamPlan {
    /// A plan with no list on disk: for a port that is not the real one.
    pub fn in_memory(
        roots: Vec<(HostingId, String)>,
        sites: Vec<SiteListing>,
        listed: impl IntoIterator<Item = String>,
    ) -> Self {
        let listed: HashSet<u128> = listed.into_iter().map(|p| path_key(&p)).collect();
        Self {
            _file: ListFile(PathBuf::new()),
            list_path: PathBuf::new(),
            roots,
            files: listed.len() as u64,
            sites,
            listed: Arc::new(listed),
        }
    }
}

/// Walk every site into one list file, streaming; blocking, so the caller runs it
/// on a blocking thread. Sites go in the order given, so the byte cap cuts the
/// tail, and the caller rotates the order.
pub fn clamav_prepare(
    roots: &[(HostingId, String)],
    list_path: &Path,
) -> std::io::Result<ClamPlan> {
    clamav_prepare_with(roots, list_path, ClamLimits::default())
}

pub fn clamav_prepare_with(
    roots: &[(HostingId, String)],
    list_path: &Path,
    limits: ClamLimits,
) -> std::io::Result<ClamPlan> {
    let file = ListFile(list_path.to_path_buf());
    let mut w = ListWriter::create(list_path, limits.node_bytes)?;
    let mut sites = Vec::with_capacity(roots.len());
    for (id, root) in roots {
        let mut listing = SiteListing::new(id.clone());
        if w.full {
            listing.node_full = true;
        } else if let Err(e) = list_site(Path::new(root), &mut w, limits.site_files, &mut listing) {
            tracing::warn!(error = %e, "clamav: a site could not be listed in full");
            listing.failed = true;
        }
        sites.push(listing);
    }
    {
        use std::io::Write;
        w.out.flush()?;
    }
    let files = sites.iter().map(|s| s.files).sum();
    Ok(ClamPlan {
        _file: file,
        list_path: list_path.to_path_buf(),
        roots: roots.to_vec(),
        sites,
        listed: Arc::new(w.listed),
        files,
    })
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// How a pass ended, for every site in it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SweepEnd {
    /// It ended normally and everything it said is accounted for: every exit
    /// code and stderr line named a listed path, and files that had vanished
    /// cost no coverage. A site is complete when it has no read error of its own
    /// ([`ClamSweep::unread`]) and nothing was left out of its list.
    #[default]
    Complete,
    /// It stopped, or said something nothing can account for (an unknown stderr
    /// line, exit 2 with no file named): no site can be called complete, but the
    /// detections are real.
    Partial,
    /// The kernel killed it for memory. Not tried again for a week.
    OutOfMemory,
    /// Stopped at the six-hour limit.
    TimedOut,
    /// Not a result at all: it didn't start or ended in a way that says nothing.
    Failed,
}

impl SweepEnd {
    /// Anything but a normal end: what it found stands, what it didn't find
    /// proves nothing.
    pub fn is_partial(self) -> bool {
        self != SweepEnd::Complete
    }
}

/// What one sweep found and how far it got.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClamSweep {
    /// Detections on exact list entries, at most 1000 per root.
    pub hits: Vec<WpMalwareHit>,
    pub end: SweepEnd,
    /// Sites with a file clamscan could not read (a real error, not a vanished
    /// file). Partial, and no more than that.
    pub unread: Vec<HostingId>,
    /// Files in the list that were gone by the time clamscan came to them.
    pub vanished: u64,
    /// Detection lines that named no listed path: a file reached through a
    /// symlink swapped into the tree, or a split fragment. Never shown.
    pub dropped_hits: u64,
    /// Sites with more than 1000 detections; the rest were not kept.
    pub hits_capped: Vec<HostingId>,
}

/// How the process ended, before anything is read into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepExit {
    Code(i32),
    Signal(i32),
    /// We stopped it at the time limit.
    TimedOut,
}

/// What stderr said, line by line, against the list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ErrFacts {
    /// clamscan had nowhere to unpack.
    pub no_tmp: bool,
    /// A listed file was gone.
    pub vanished: bool,
    /// A listed file could not be read.
    pub unread: bool,
    /// A line that is none of the above.
    pub unknown: bool,
}

/// What the process's end means. Pure, because this is where a killed pass could
/// otherwise read as a clean one.
///
/// The exit code alone does not say. Real clamscan 1.4.6: one vanished file and
/// no detection exits 2, a detection plus a vanished file exits 1 in either
/// order (a detection hides errors), and a clean pass exits 0. So the verdict
/// reads stderr, whose lines all name a path: `<path>: No such file or directory`
/// (gone, which costs no coverage), `<path>: <other reason>` and
/// `WARNING: <path>: Can't access file` / `Not supported file type` (a real read
/// error), `LibClamAV Error: Can't create temporary directory…` (nothing was
/// scanned). Exit 2 needs at least one such line to be explained. Anything else
/// on stderr makes the pass partial for every site.
///
/// Through `systemd-run --wait` the unit's own verdict is on stderr too
/// (`Finished with result: oom-kill`); without it nothing can be said: the client
/// exits 1 when it can't start the unit at all, which must never read as
/// "infections found" with none listed.
pub fn classify_sweep(
    exit: SweepExit,
    via_systemd: bool,
    systemd_tail: &str,
    err: ErrFacts,
) -> SweepEnd {
    let end = if exit == SweepExit::TimedOut {
        SweepEnd::TimedOut
    } else if via_systemd {
        match systemd_result(systemd_tail) {
            None => SweepEnd::Failed,
            Some("oom-kill") => SweepEnd::OutOfMemory,
            Some("timeout") => SweepEnd::TimedOut,
            Some("success" | "exit-code") => end_of_exit(exit, err),
            Some(_) => SweepEnd::Partial,
        }
    } else {
        end_of_exit(exit, err)
    };
    // Nothing was scanned, whatever the exit code says.
    if err.no_tmp && end == SweepEnd::Complete {
        SweepEnd::Failed
    } else {
        end
    }
}

fn end_of_exit(exit: SweepExit, err: ErrFacts) -> SweepEnd {
    match exit {
        SweepExit::Code(0 | 1) if !err.unknown => SweepEnd::Complete,
        SweepExit::Code(2) if !err.unknown && (err.vanished || err.unread) => SweepEnd::Complete,
        SweepExit::Code(0..=2) => SweepEnd::Partial,
        SweepExit::Code(_) => SweepEnd::Failed,
        // SIGKILL with no unit to say why is what the OOM killer sends.
        SweepExit::Signal(9) => SweepEnd::OutOfMemory,
        SweepExit::Signal(_) => SweepEnd::Partial,
        SweepExit::TimedOut => SweepEnd::TimedOut,
    }
}

/// clamscan could not create its temporary directory: the whole line, so a path
/// in some other message can't pass for it.
fn is_no_tmp_error(line: &str) -> bool {
    const HEAD: &str = "LibClamAV Error: Can't create temporary directory for scan: ";
    line.strip_prefix(HEAD)
        .is_some_and(|dir| dir.len() > 1 && dir.ends_with('.') && !dir.contains(": "))
}

/// One line of clamscan's stderr, against the list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ErrLine {
    NoTmp,
    Vanished,
    /// A real read error on this listed path.
    Unread(String),
    /// The `WARNING: <path>: Can't access file` that follows a strerror line for
    /// the same path.
    Echo,
    Unknown,
}

fn classify_err_line(line: &str, listed: &HashSet<u128>, prev: &mut Option<String>) -> ErrLine {
    if is_no_tmp_error(line) {
        return ErrLine::NoTmp;
    }
    let (body, warning) = match line.strip_prefix("WARNING: ") {
        Some(b) => (b, true),
        None => (line, false),
    };
    let Some((path, reason)) = body.rsplit_once(": ") else {
        return ErrLine::Unknown;
    };
    if !listed.contains(&path_key(path)) {
        return ErrLine::Unknown;
    }
    let was = prev.replace(path.to_string());
    if warning && reason == "Can't access file" && was.as_deref() == Some(path) {
        return ErrLine::Echo;
    }
    if !warning && reason == "No such file or directory" {
        ErrLine::Vanished
    } else {
        ErrLine::Unread(path.to_string())
    }
}

/// The result word from the last `Finished with result: <word>` line of
/// `systemd-run --wait`'s stderr. The last, because the unit's own stderr comes
/// through the same pipe before it and a line there can say anything.
fn systemd_result(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("Finished with result: "))
        .map(str::trim)
}

/// Roots, longest first, to say which hosting a path is under.
struct RootIndex(Vec<(usize, usize, PathBuf)>);

impl RootIndex {
    fn new(roots: &[(HostingId, String)]) -> Self {
        let mut v: Vec<(usize, usize, PathBuf)> = roots
            .iter()
            .enumerate()
            .map(|(i, (_, r))| (i, PathBuf::from(r)))
            .filter(|(_, r)| r.is_absolute())
            .map(|(i, r)| (r.components().count(), i, r))
            .collect();
        v.sort_by_key(|o| std::cmp::Reverse(o.0));
        Self(v)
    }

    /// By path components: `/home/a/htdocs2` is not under `/home/a/htdocs`.
    fn find(&self, path: &str) -> Option<usize> {
        let p = Path::new(path);
        if !p.is_absolute() {
            return None;
        }
        self.0
            .iter()
            .find(|(_, _, root)| p.starts_with(root))
            .map(|(_, i, _)| *i)
    }
}

/// Hand each detection to the hosting whose root it is under, the longest root
/// first. A detection under no root is logged and dropped.
pub fn attribute_hits(
    hits: Vec<WpMalwareHit>,
    roots: &[(HostingId, String)],
) -> HashMap<HostingId, Vec<WpMalwareHit>> {
    let index = RootIndex::new(roots);
    let mut out: HashMap<HostingId, Vec<WpMalwareHit>> = HashMap::new();
    for hit in hits {
        match index.find(&hit.path) {
            Some(i) => out.entry(roots[i].0.clone()).or_default().push(hit),
            None => tracing::warn!(path = ?hit.path, "clamav: a detection under no scanned root"),
        }
    }
    out
}

/// What is run, and whether systemd is the one running it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Launch {
    program: String,
    args: Vec<String>,
    via_systemd: bool,
}

/// clamscan's own flags. No `-r`: the list is the walk. Symlinks are never
/// followed, and the size limits are the list's, repeated.
fn clamscan_args(list_path: &Path) -> Vec<String> {
    [
        format!("--file-list={}", list_path.display()),
        "--infected".to_string(),
        "--no-summary".to_string(),
        "--follow-dir-symlinks=0".to_string(),
        "--follow-file-symlinks=0".to_string(),
        "--max-filesize=64M".to_string(),
        "--max-scansize=256M".to_string(),
    ]
    .to_vec()
}

/// The command line: the capped unit when systemd is there, else a child under
/// `nice`. The unit may read everything and write nothing; there is no syscall
/// filter because none has been tried against clamscan.
fn launch_for(bin: &str, list_path: &Path, cores: usize, systemd: bool, nice: bool) -> Launch {
    let scan = clamscan_args(list_path);
    if systemd {
        let quota = if cores <= 2 { "50%" } else { "100%" };
        let mut args: Vec<String> = [
            format!("--unit={UNIT_NAME}"),
            "--wait".to_string(),
            "--pipe".to_string(),
            "--collect".to_string(),
        ]
        .to_vec();
        let props = [
            "MemoryMax=3G".to_string(),
            "MemorySwapMax=0".to_string(),
            "CPUWeight=10".to_string(),
            "IOWeight=10".to_string(),
            "Nice=19".to_string(),
            "IOSchedulingClass=idle".to_string(),
            format!("CPUQuota={quota}"),
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH".to_string(),
            "NoNewPrivileges=yes".to_string(),
            "PrivateNetwork=yes".to_string(),
            "ProtectSystem=strict".to_string(),
            // clamscan unpacks into a temporary directory, and under a read-only
            // system without one it says so on stderr and scans nothing.
            "PrivateTmp=yes".to_string(),
            "PrivateDevices=yes".to_string(),
            "ProtectKernelTunables=yes".to_string(),
            "ProtectKernelModules=yes".to_string(),
            "ProtectControlGroups=yes".to_string(),
            "ReadOnlyPaths=/run".to_string(),
            format!("RuntimeMaxSec={RUNTIME_MAX_SEC}"),
        ];
        for p in props {
            args.push("-p".to_string());
            args.push(p);
        }
        args.push(bin.to_string());
        args.extend(scan);
        Launch {
            program: SYSTEMD_RUN.to_string(),
            args,
            via_systemd: true,
        }
    } else if nice {
        let mut args = vec!["-n".to_string(), "19".to_string(), bin.to_string()];
        args.extend(scan);
        Launch {
            program: NICE.to_string(),
            args,
            via_systemd: false,
        }
    } else {
        Launch {
            program: bin.to_string(),
            args: scan,
            via_systemd: false,
        }
    }
}

/// One `clamscan` over the plan's list. `Err` only when it could not be
/// started: a pass that ran and came back with a bad ending is a [`ClamSweep`]
/// that says so. Nothing is held while it runs. The list goes with the plan.
pub async fn clamav_run(plan: ClamPlan) -> Result<ClamSweep, AdapterError> {
    static WARNED: std::sync::Once = std::sync::Once::new();
    let bin = clamscan_bin()
        .ok_or_else(|| AdapterError::Other("clamscan is not installed".to_string()))?;
    let systemd = Path::new(SYSTEMD_RUN).exists();
    if !systemd {
        WARNED.call_once(|| {
            tracing::warn!(
                "systemd-run not found: ClamAV runs without its resource caps and sandbox"
            );
        });
    }
    let launch = launch_for(
        bin,
        &plan.list_path,
        host_cores(),
        systemd,
        Path::new(NICE).exists(),
    );
    // The unit stops itself at its limit; without one, this does.
    let limit = Duration::from_secs(RUNTIME_MAX_SEC + if systemd { 120 } else { 0 });
    run_plan(plan, launch, limit).await
}

/// Stop a pass an earlier agent started and lost: its output went to a pipe that
/// is gone. Nothing there is not an error.
pub async fn clamav_stop_orphan() {
    let _ = Command::new("/usr/bin/systemctl")
        .args(["stop", &format!("{UNIT_NAME}.service")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

async fn run_plan(
    plan: ClamPlan,
    launch: Launch,
    limit: Duration,
) -> Result<ClamSweep, AdapterError> {
    if plan.files == 0 {
        return Ok(ClamSweep::default());
    }
    run_launch(&launch, limit, &plan).await
}

/// Run it, reading stdout line by line so a pass that dies keeps what it found.
async fn run_launch(
    launch: &Launch,
    limit: Duration,
    plan: &ClamPlan,
) -> Result<ClamSweep, AdapterError> {
    // The arguments are flags and the list's path: no credential is near them.
    tracing::debug!(program = %launch.program, "exec clamscan sweep");
    let mut cmd = Command::new(&launch.program);
    cmd.args(&launch.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn()?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(AdapterError::Other(
            "could not reach clamscan's pipes".into(),
        ));
    };
    let index = Arc::new(RootIndex::new(&plan.roots));
    // The tail is systemd's verdict; the rest is clamscan's, line by line against
    // the list.
    let tail = {
        let (listed, index) = (plan.listed.clone(), index.clone());
        tokio::spawn(async move {
            let mut keep: Vec<u8> = Vec::new();
            let mut facts = ErrFacts::default();
            let mut unread: HashSet<usize> = HashSet::new();
            let mut prev: Option<String> = None;
            let mut lines = BufReader::new(stderr).split(b'\n');
            while let Ok(Some(line)) = lines.next_segment().await {
                let text = String::from_utf8_lossy(&line);
                // systemd's own lines are the client's, not clamscan's.
                if !is_systemd_line(&text) {
                    match classify_err_line(&text, &listed, &mut prev) {
                        ErrLine::NoTmp => facts.no_tmp = true,
                        ErrLine::Vanished => facts.vanished = true,
                        ErrLine::Echo => {}
                        ErrLine::Unread(path) => match index.find(&path) {
                            Some(i) => {
                                facts.unread = true;
                                unread.insert(i);
                            }
                            None => facts.unknown = true,
                        },
                        ErrLine::Unknown => facts.unknown = true,
                    }
                }
                keep.extend_from_slice(&line);
                keep.push(b'\n');
                if keep.len() > STDERR_TAIL_BYTES {
                    keep.drain(..keep.len() - STDERR_TAIL_BYTES);
                }
            }
            (String::from_utf8_lossy(&keep).into_owned(), facts, unread)
        })
    };
    let mut hits: Vec<WpMalwareHit> = Vec::new();
    let mut per_root: HashMap<usize, usize> = HashMap::new();
    let mut capped: HashSet<usize> = HashSet::new();
    let mut dropped = 0u64;
    let waited = tokio::time::timeout(limit, async {
        let mut lines = BufReader::new(stdout).split(b'\n');
        while let Some(line) = lines.next_segment().await? {
            let Some(hit) = parse_hit_line(&String::from_utf8_lossy(&line)) else {
                continue;
            };
            // Only what the list holds, exactly: a file reached through a
            // symlink swapped into the tree, or one piece of a split line, is
            // another tenant's or nobody's.
            let Some(root) = plan
                .listed
                .contains(&path_key(&hit.path))
                .then(|| index.find(&hit.path))
                .flatten()
            else {
                dropped += 1;
                continue;
            };
            let n = per_root.entry(root).or_default();
            if *n >= MAX_HITS_PER_ROOT {
                capped.insert(root);
            } else {
                *n += 1;
                hits.push(hit);
            }
        }
        child.wait().await
    })
    .await;
    let exit = match waited {
        Ok(Ok(status)) => match status.code() {
            Some(c) => SweepExit::Code(c),
            None => {
                use std::os::unix::process::ExitStatusExt;
                SweepExit::Signal(status.signal().unwrap_or(0))
            }
        },
        Ok(Err(e)) => {
            // The pipe broke or the wait failed: what was read stands.
            tracing::warn!(error = %e, "clamav sweep: lost the scanner");
            let _ = child.start_kill();
            SweepExit::Signal(0)
        }
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            SweepExit::TimedOut
        }
    };
    let (systemd_tail, facts, unread) = tokio::time::timeout(Duration::from_secs(5), tail)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_else(|| {
            // Could not be read: nothing can be said about it.
            (
                String::new(),
                ErrFacts {
                    unknown: true,
                    ..Default::default()
                },
                HashSet::new(),
            )
        });
    if dropped > 0 {
        tracing::warn!(dropped, "clamav: detections on paths that were not listed");
    }
    let ids = |set: &HashSet<usize>| {
        let mut v: Vec<usize> = set.iter().copied().collect();
        v.sort_unstable();
        v.into_iter().map(|i| plan.roots[i].0.clone()).collect()
    };
    Ok(ClamSweep {
        end: classify_sweep(exit, launch.via_systemd, &systemd_tail, facts),
        hits,
        unread: ids(&unread),
        vanished: u64::from(facts.vanished),
        dropped_hits: dropped,
        hits_capped: ids(&capped),
    })
}

/// systemd-run's own lines on its stderr (the client's, not the unit's).
fn is_systemd_line(line: &str) -> bool {
    line.starts_with("Running as unit: ")
        || line.starts_with("Finished with result: ")
        || line.starts_with("Main processes terminated with: ")
        || line.starts_with("Service runtime: ")
        || line.starts_with("CPU time consumed: ")
        || line.starts_with("IO bytes read: ")
        || line.starts_with("IO bytes written: ")
        || line.starts_with("Memory peak: ")
        || line.starts_with("Memory swap peak: ")
}

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

/// One `clamscan --infected --no-summary` line: `<path>: <Signature> FOUND`.
/// `ERROR` lines for unreadable files, blank lines, whatever a future clamscan
/// adds: not a detection, so `None` rather than a guess.
fn parse_hit_line(line: &str) -> Option<WpMalwareHit> {
    // Only " FOUND" lines are detections; "… ERROR" / "… OK" are not.
    let body = line.strip_suffix(" FOUND")?;
    // Split from the RIGHT: a path may itself contain ": ", the signature name
    // never does. The path is the text exactly as printed, trailing space and
    // all: `index.php ` is not `index.php`.
    let (path, signature) = body.rsplit_once(": ")?;
    if path.is_empty() || signature.is_empty() {
        return None;
    }
    Some(WpMalwareHit {
        path: path.to_string(),
        signature: signature.to_string(),
    })
}

/// Parse `clamscan --infected --no-summary` output.
pub fn parse_clamscan_output(text: &str) -> Vec<WpMalwareHit> {
    text.lines().filter_map(parse_hit_line).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- clamav ------------------------------------------------------------

    #[test]
    fn clamscan_parses_multiple_hits() {
        let out = "\
/home/site/htdocs/wp-content/uploads/2026/01/x.php: Php.Trojan.Webshell-1 FOUND
/home/site/htdocs/wp-content/plugins/evil/a.php: Php.Malware.Agent-9876543-0 FOUND
";
        let hits = parse_clamscan_output(out);
        assert_eq!(hits.len(), 2);
        assert_eq!(
            hits[0].path,
            "/home/site/htdocs/wp-content/uploads/2026/01/x.php"
        );
        assert_eq!(hits[0].signature, "Php.Trojan.Webshell-1");
        assert_eq!(hits[1].signature, "Php.Malware.Agent-9876543-0");
    }

    #[test]
    fn clamscan_ignores_errors_and_noise() {
        let out = "\
/home/site/htdocs/broken-link: Can't open file or directory ERROR
/home/site/htdocs/ok.php: OK

LibClamAV Warning: something
/home/site/htdocs/bad.php: Php.Trojan.Webshell-1 FOUND
";
        let hits = parse_clamscan_output(out);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/home/site/htdocs/bad.php");
    }

    #[test]
    fn clamscan_path_containing_colon_space_keeps_full_path() {
        let out = "/home/site/htdocs/weird: name/x.php: Php.Trojan.Agent-1 FOUND\n";
        let hits = parse_clamscan_output(out);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/home/site/htdocs/weird: name/x.php");
        assert_eq!(hits[0].signature, "Php.Trojan.Agent-1");
    }

    #[test]
    fn clamscan_empty_and_garbage_input_yields_nothing() {
        for s in ["", "\n\n", "FOUND", " FOUND", ": FOUND", "\u{0}\u{1} FOUND"] {
            assert!(
                parse_clamscan_output(s).is_empty(),
                "must not invent a hit from {s:?}"
            );
        }
    }

    #[test]
    fn missing_signature_db_is_not_a_failure() {
        let dir = std::env::temp_dir().join(format!("hyp-clamdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Absent directory and a directory with only freshclam's lock/temp
        // files both read as "signatures still downloading".
        assert!(!clamav_db_present_in(&dir));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("freshclam.dat"), b"x").expect("write");
        assert!(!clamav_db_present_in(&dir));
        // One of the two base files is an update still coming.
        std::fs::write(dir.join("daily.cld"), b"x").expect("write");
        assert!(!clamav_db_present_in(&dir));
        std::fs::write(dir.join("main.cvd"), b"x").expect("write");
        assert!(clamav_db_present_in(&dir));
        std::fs::remove_file(dir.join("daily.cld")).expect("rm");
        assert!(!clamav_db_present_in(&dir));
        std::fs::write(dir.join("daily.cvd"), b"x").expect("write");
        assert!(clamav_db_present_in(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_is_the_text_exactly_as_printed() {
        // Real clamscan 1.4.6 prints `index.php ` (trailing space) as is.
        let out = "/t/a/index.php : Hyp.Test.UNOFFICIAL FOUND\n";
        let hits = parse_clamscan_output(out);
        assert_eq!(hits[0].path, "/t/a/index.php ");
        assert_eq!(hits[0].signature, "Hyp.Test.UNOFFICIAL");
        // No ": " is no detection, whatever follows.
        assert!(parse_clamscan_output("/t/a/x:Sig FOUND\n").is_empty());
    }

    // -- one bounded sweep -------------------------------------------------

    fn id(s: &str) -> HostingId {
        HostingId(s.to_string())
    }

    fn hit(path: &str) -> WpMalwareHit {
        WpMalwareHit {
            path: path.into(),
            signature: "Php.Trojan.Webshell-1".into(),
        }
    }

    /// A plan over `(id, root, paths)`, written the way the walk writes it.
    fn plan_of(dir: &Path, sites: &[(&str, &str, &[&str])]) -> ClamPlan {
        let list_path = dir.join("list");
        let file = ListFile(list_path.clone());
        let mut w = ListWriter::create(&list_path, 1 << 20).expect("list");
        let mut listings = Vec::new();
        for (name, _, paths) in sites {
            let mut l = SiteListing::new(id(name));
            for p in *paths {
                match w.add(p).expect("write") {
                    Added::Yes => l.files += 1,
                    Added::LeftOut => l.left_out += 1,
                    Added::NodeFull => l.node_full = true,
                }
            }
            listings.push(l);
        }
        std::io::Write::flush(&mut w.out).expect("flush");
        let files = listings.iter().map(|s| s.files).sum();
        ClamPlan {
            _file: file,
            list_path,
            roots: sites
                .iter()
                .map(|(n, r, _)| (id(n), r.to_string()))
                .collect(),
            sites: listings,
            listed: Arc::new(w.listed),
            files,
        }
    }

    /// A stand-in for the scanner: counts its runs, keeps the list it was given
    /// and the flags, prints what it is told and exits as it is told.
    fn fake_clamscan(dir: &Path, stdout: &str, stderr: &str, exit: i32) -> Launch {
        std::fs::write(dir.join("out"), stdout).expect("out");
        std::fs::write(dir.join("err"), stderr).expect("err");
        let script = format!(
            r#"echo run >> '{runs}'
echo "$@" > '{args}'
for a in "$@"; do case "$a" in --file-list=*) cp "${{a#--file-list=}}" '{list}';; esac; done
cat '{out}'
cat '{err}' >&2
exit {exit}"#,
            runs = dir.join("runs").display(),
            args = dir.join("args").display(),
            list = dir.join("seen-list").display(),
            out = dir.join("out").display(),
            err = dir.join("err").display(),
        );
        let mut args = vec!["-c".to_string(), script, "fake-clamscan".to_string()];
        args.extend(clamscan_args(&dir.join("list")));
        Launch {
            program: "/bin/sh".into(),
            args,
            via_systemd: false,
        }
    }

    const LIMIT: Duration = Duration::from_secs(30);

    async fn run_fake(
        dir: &Path,
        sites: &[(&str, &str, &[&str])],
        stdout: &str,
        stderr: &str,
        exit: i32,
    ) -> ClamSweep {
        let plan = plan_of(dir, sites);
        let launch = fake_clamscan(dir, stdout, stderr, exit);
        run_plan(plan, launch, LIMIT).await.expect("ran")
    }

    const A: (&str, &str) = ("a", "/home/a/htdocs");
    const A_FILES: &[&str] = &["/home/a/htdocs/x.php", "/home/a/htdocs/y.php"];

    #[tokio::test]
    async fn one_process_per_sweep_with_file_list() {
        let dir = tempfile::tempdir().expect("tmp");
        let sites: &[(&str, &str, &[&str])] = &[
            (A.0, A.1, A_FILES),
            ("b", "/home/b/htdocs", &["/home/b/htdocs/z.php"]),
        ];
        let sweep = run_fake(
            dir.path(),
            sites,
            "/home/b/htdocs/z.php: Php.Trojan.Webshell-1 FOUND\n",
            "",
            1,
        )
        .await;

        let runs = std::fs::read_to_string(dir.path().join("runs")).expect("runs");
        assert_eq!(runs.lines().count(), 1, "one clamscan for every site");
        let seen = std::fs::read_to_string(dir.path().join("seen-list")).expect("list");
        assert_eq!(
            seen,
            "/home/a/htdocs/x.php\n/home/a/htdocs/y.php\n/home/b/htdocs/z.php\n"
        );
        let args = std::fs::read_to_string(dir.path().join("args")).expect("args");
        for flag in [
            "--infected",
            "--no-summary",
            "--follow-dir-symlinks=0",
            "--follow-file-symlinks=0",
            "--max-filesize=64M",
            "--max-scansize=256M",
        ] {
            assert!(args.contains(flag), "{flag} missing from {args}");
        }
        assert!(!args.contains(" -r"), "no recursion: the list is the walk");
        assert!(
            !dir.path().join("list").exists(),
            "the list goes with the plan"
        );
        assert_eq!(sweep.end, SweepEnd::Complete);
        assert_eq!(sweep.hits, vec![hit("/home/b/htdocs/z.php")]);
    }

    #[tokio::test]
    async fn nothing_to_scan_starts_nothing() {
        let dir = tempfile::tempdir().expect("tmp");
        let plan = plan_of(dir.path(), &[(A.0, A.1, &[])]);
        let launch = fake_clamscan(dir.path(), "", "", 0);
        let sweep = run_plan(plan, launch, LIMIT).await.expect("ran");
        assert_eq!(sweep.end, SweepEnd::Complete);
        assert!(!dir.path().join("runs").exists(), "no process for no files");
    }

    // The exit code does not say what a pass covered. These are clamscan 1.4.6's
    // real outputs for the cases the reviewer ran.

    const GONE_ERR: &str = "/home/a/htdocs/gone.php: No such file or directory\nWARNING: /home/a/htdocs/gone.php: Can't access file\n";
    const WITH_GONE: &[&str] = &[
        "/home/a/htdocs/x.php",
        "/home/a/htdocs/gone.php",
        "/home/a/htdocs/bad.php",
    ];

    #[tokio::test]
    async fn exit_1_with_a_vanished_file_is_complete_and_keeps_the_hit() {
        let dir = tempfile::tempdir().expect("tmp");
        let sweep = run_fake(
            dir.path(),
            &[(A.0, A.1, WITH_GONE)],
            "/home/a/htdocs/bad.php: Php.Trojan.Webshell-1 FOUND\n",
            GONE_ERR,
            1,
        )
        .await;
        assert_eq!(sweep.end, SweepEnd::Complete);
        assert_eq!(sweep.hits, vec![hit("/home/a/htdocs/bad.php")]);
        assert!(sweep.unread.is_empty(), "a vanished file costs no coverage");
        assert_eq!(sweep.vanished, 1);
    }

    #[tokio::test]
    async fn exit_2_with_no_hits_and_a_vanished_file_costs_no_coverage() {
        let dir = tempfile::tempdir().expect("tmp");
        let sweep = run_fake(dir.path(), &[(A.0, A.1, WITH_GONE)], "", GONE_ERR, 2).await;
        assert_eq!(sweep.end, SweepEnd::Complete);
        assert!(sweep.hits.is_empty() && sweep.unread.is_empty());
    }

    #[tokio::test]
    async fn exit_2_that_nothing_explains_is_partial_for_everyone() {
        let dir = tempfile::tempdir().expect("tmp");
        let sweep = run_fake(dir.path(), &[(A.0, A.1, A_FILES)], "", "", 2).await;
        assert_eq!(sweep.end, SweepEnd::Partial);
    }

    #[tokio::test]
    async fn a_real_read_error_marks_that_site_alone() {
        let dir = tempfile::tempdir().expect("tmp");
        let sites: &[(&str, &str, &[&str])] = &[
            (A.0, A.1, A_FILES),
            ("b", "/home/b/htdocs", &["/home/b/htdocs/z.php"]),
        ];
        let err = "/home/b/htdocs/z.php: Permission denied\nWARNING: /home/b/htdocs/z.php: Can't access file\n";
        let sweep = run_fake(dir.path(), sites, "", err, 2).await;
        assert_eq!(sweep.end, SweepEnd::Complete);
        assert_eq!(sweep.unread, vec![id("b")]);
        // With a detection elsewhere the exit is 1 and the errors are still read.
        let dir = tempfile::tempdir().expect("tmp");
        let sweep = run_fake(
            dir.path(),
            sites,
            "/home/a/htdocs/x.php: Php.Trojan.Webshell-1 FOUND\n",
            err,
            1,
        )
        .await;
        assert_eq!(sweep.end, SweepEnd::Complete);
        assert_eq!(sweep.unread, vec![id("b")]);
        assert_eq!(sweep.hits.len(), 1);
    }

    #[tokio::test]
    async fn a_stderr_line_nothing_accounts_for_makes_the_pass_partial() {
        let dir = tempfile::tempdir().expect("tmp");
        for (err, why) in [
            ("LibClamAV Warning: something new\n", "noise"),
            (
                "/home/b/htdocs/other.php: Permission denied\n",
                "unlisted path",
            ),
            (
                "/home/a/htdocs/x.php: Permission denied\nWARNING: odd\n",
                "odd line",
            ),
        ] {
            let sweep = run_fake(dir.path(), &[(A.0, A.1, A_FILES)], "", err, 0).await;
            assert_eq!(sweep.end, SweepEnd::Partial, "{why}");
        }
        // A path under no root can't be given to a site.
        let sweep = run_fake(
            dir.path(),
            &[(A.0, "/elsewhere", A_FILES)],
            "",
            "/home/a/htdocs/x.php: Permission denied\n",
            2,
        )
        .await;
        assert_eq!(sweep.end, SweepEnd::Partial);
    }

    #[tokio::test]
    async fn no_temp_dir_is_a_failed_pass_not_a_clean_one() {
        let dir = tempfile::tempdir().expect("tmp");
        let err = "LibClamAV Error: Can't create temporary directory for scan: /tmp/20261105-scantemp.ab12.\n";
        let sweep = run_fake(dir.path(), &[(A.0, A.1, A_FILES)], "", err, 0).await;
        assert_eq!(sweep.end, SweepEnd::Failed);
    }

    /// A detection on a path the list doesn't hold is not shown: clamscan reads
    /// through a symlink swapped into the tree, and a split line leaves fragments.
    #[tokio::test]
    async fn a_hit_on_an_unlisted_path_never_reaches_a_card() {
        let dir = tempfile::tempdir().expect("tmp");
        let out = "\
/home/a/htdocs/lnk/htdocs/target.php: Php.Trojan.Webshell-1 FOUND
/home/a/htdocs/x.php: Php.Trojan.Webshell-1 FOUND
/home/a/htdocs/x.ph: Php.Trojan.Webshell-1 FOUND
";
        let sweep = run_fake(dir.path(), &[(A.0, A.1, A_FILES)], out, "", 1).await;
        assert_eq!(sweep.hits, vec![hit("/home/a/htdocs/x.php")]);
        assert_eq!(sweep.dropped_hits, 2);
        assert_eq!(sweep.end, SweepEnd::Complete);
    }

    #[tokio::test]
    async fn a_name_with_a_trailing_space_is_matched_exactly() {
        let dir = tempfile::tempdir().expect("tmp");
        let files: &[&str] = &["/home/a/htdocs/index.php", "/home/a/htdocs/index.php "];
        let sweep = run_fake(
            dir.path(),
            &[(A.0, A.1, files)],
            "/home/a/htdocs/index.php : Php.Trojan.Webshell-1 FOUND\n",
            "",
            1,
        )
        .await;
        assert_eq!(sweep.hits, vec![hit("/home/a/htdocs/index.php ")]);
    }

    #[tokio::test]
    async fn a_site_keeps_at_most_a_thousand_detections() {
        let dir = tempfile::tempdir().expect("tmp");
        let paths: Vec<String> = (0..1005)
            .map(|i| format!("/home/a/htdocs/{i}.php"))
            .collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let out: String = paths
            .iter()
            .map(|p| format!("{p}: Php.Trojan.Webshell-1 FOUND\n"))
            .collect();
        let sweep = run_fake(dir.path(), &[(A.0, A.1, &refs)], &out, "", 1).await;
        assert_eq!(sweep.hits.len(), 1000);
        assert_eq!(sweep.hits_capped, vec![id("a")]);
        assert!(sweep.unread.is_empty(), "not blamed on unreadable files");
        assert_eq!(sweep.end, SweepEnd::Complete);
    }

    #[tokio::test]
    async fn a_killed_scanner_keeps_what_it_printed() {
        // SIGKILL, as the OOM killer sends it, with no systemd to say why.
        let dir = tempfile::tempdir().expect("tmp");
        let script = r#"echo '/home/a/htdocs/x.php: Php.Trojan.Webshell-1 FOUND'; kill -9 $$"#;
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            via_systemd: false,
        };
        let plan = plan_of(dir.path(), &[(A.0, A.1, A_FILES)]);
        let sweep = run_plan(plan, launch, LIMIT).await.expect("ran");
        assert_eq!(sweep.end, SweepEnd::OutOfMemory);
        assert_eq!(sweep.hits, vec![hit("/home/a/htdocs/x.php")]);
    }

    #[tokio::test]
    async fn the_time_limit_stops_the_pass_and_keeps_its_hits() {
        let dir = tempfile::tempdir().expect("tmp");
        let script = r#"echo '/home/a/htdocs/x.php: Php.Trojan.Webshell-1 FOUND'; exec sleep 60"#;
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            via_systemd: false,
        };
        let plan = plan_of(dir.path(), &[(A.0, A.1, A_FILES)]);
        let started = std::time::Instant::now();
        let sweep = run_plan(plan, launch, Duration::from_millis(500))
            .await
            .expect("ran");
        assert!(started.elapsed() < Duration::from_secs(20));
        assert_eq!(sweep.end, SweepEnd::TimedOut);
        assert_eq!(sweep.hits, vec![hit("/home/a/htdocs/x.php")]);
    }

    #[tokio::test]
    async fn a_scanner_that_cannot_start_is_an_error_and_leaves_no_list() {
        let dir = tempfile::tempdir().expect("tmp");
        let launch = Launch {
            program: "/nonexistent/clamscan".into(),
            args: vec![],
            via_systemd: false,
        };
        let plan = plan_of(dir.path(), &[(A.0, A.1, A_FILES)]);
        assert!(dir.path().join("list").exists());
        assert!(run_plan(plan, launch, LIMIT).await.is_err());
        assert!(!dir.path().join("list").exists(), "no list left behind");
    }

    #[test]
    fn exit_codes_decide_the_pass() {
        let none = ErrFacts::default();
        let c = |exit, systemd, err| classify_sweep(exit, systemd, "", err);
        let gone = ErrFacts {
            vanished: true,
            ..none
        };
        assert_eq!(c(SweepExit::Code(0), false, none), SweepEnd::Complete);
        assert_eq!(c(SweepExit::Code(1), false, none), SweepEnd::Complete);
        assert_eq!(c(SweepExit::Code(1), false, gone), SweepEnd::Complete);
        assert_eq!(c(SweepExit::Code(2), false, gone), SweepEnd::Complete);
        assert_eq!(c(SweepExit::Code(2), false, none), SweepEnd::Partial);
        let odd = ErrFacts {
            unknown: true,
            ..gone
        };
        assert_eq!(c(SweepExit::Code(0), false, odd), SweepEnd::Partial);
        assert_eq!(c(SweepExit::Code(2), false, odd), SweepEnd::Partial);
        assert_eq!(c(SweepExit::Code(127), false, none), SweepEnd::Failed);
        assert_eq!(c(SweepExit::Signal(9), false, none), SweepEnd::OutOfMemory);
        assert_eq!(c(SweepExit::Signal(15), false, none), SweepEnd::Partial);
        assert_eq!(c(SweepExit::TimedOut, false, none), SweepEnd::TimedOut);
        let no_tmp = ErrFacts {
            no_tmp: true,
            ..none
        };
        assert_eq!(c(SweepExit::Code(0), false, no_tmp), SweepEnd::Failed);
    }

    #[test]
    fn systemd_says_why_a_unit_ended() {
        let none = ErrFacts::default();
        let run = |code, err: &str| classify_sweep(SweepExit::Code(code), true, err, none);
        let said = |result: &str| {
            format!("Running as unit: hyperion-clamscan.service\nFinished with result: {result}\nService runtime: 3h\n")
        };
        assert_eq!(run(1, &said("oom-kill")), SweepEnd::OutOfMemory);
        assert_eq!(run(1, &said("timeout")), SweepEnd::TimedOut);
        assert_eq!(run(1, &said("signal")), SweepEnd::Partial);
        assert_eq!(run(1, &said("exit-code")), SweepEnd::Complete);
        assert_eq!(run(0, &said("success")), SweepEnd::Complete);
        // The last word counts, and a line that only starts like it doesn't.
        let tricked = format!("Finished with result: success\n{}", said("oom-kill"));
        assert_eq!(run(1, &tricked), SweepEnd::OutOfMemory);
        let echoed = "/home/a/htdocs/x: Finished with result: success\n";
        assert_eq!(run(1, echoed), SweepEnd::Failed);
        // systemd-run's own failure (the unit name taken, a bad property) exits
        // 1 as well: with no word from the unit, that must not read as "hits".
        let refused = "Failed to start transient service unit: Unit hyperion-clamscan.service was already loaded or has a fragment file.\n";
        assert_eq!(run(1, refused), SweepEnd::Failed);
        assert_eq!(run(0, ""), SweepEnd::Failed);
    }

    /// Lines as clamscan 1.4.6 printed them, against a list.
    #[test]
    fn stderr_lines_are_read_against_the_list() {
        let listed: HashSet<u128> = [
            "/t/a/gone.php",
            "/t/a/unread/f",
            "/t/a/fifo",
            "/t/a/ok: odd.php",
        ]
        .iter()
        .map(|p| path_key(p))
        .collect();
        let mut prev = None;
        let mut c = |l: &str| classify_err_line(l, &listed, &mut prev);
        assert_eq!(
            c("/t/a/gone.php: No such file or directory"),
            ErrLine::Vanished
        );
        assert_eq!(
            c("WARNING: /t/a/gone.php: Can't access file"),
            ErrLine::Echo
        );
        assert_eq!(
            c("/t/a/unread/f: Permission denied"),
            ErrLine::Unread("/t/a/unread/f".into())
        );
        assert_eq!(
            c("WARNING: /t/a/unread/f: Can't access file"),
            ErrLine::Echo
        );
        assert_eq!(
            c("WARNING: /t/a/fifo: Not supported file type"),
            ErrLine::Unread("/t/a/fifo".into())
        );
        // A path with ": " in it is still the listed path.
        assert_eq!(
            c("/t/a/ok: odd.php: Permission denied"),
            ErrLine::Unread("/t/a/ok: odd.php".into())
        );
        // A "Can't access file" that follows nothing is a real error.
        assert_eq!(
            c("WARNING: /t/a/fifo: Can't access file"),
            ErrLine::Unread("/t/a/fifo".into())
        );
        assert_eq!(
            c("/t/a/other.php: No such file or directory"),
            ErrLine::Unknown
        );
        assert_eq!(c("LibClamAV Warning: x"), ErrLine::Unknown);
        assert_eq!(c(""), ErrLine::Unknown);
        assert_eq!(
            c("LibClamAV Error: Can't create temporary directory for scan: /tmp/2026-scantemp.ab."),
            ErrLine::NoTmp
        );
        // Only the whole line: this is a message about some file.
        assert_ne!(
            c("LibClamAV Error: Can't create temporary directory for scan: /tmp/x: Permission denied"),
            ErrLine::NoTmp
        );
    }

    #[test]
    fn hits_attributed_by_path_prefix_not_substring() {
        let roots = vec![
            (id("a"), "/home/a/htdocs".to_string()),
            (id("a2"), "/home/a/htdocs2".to_string()),
        ];
        let got = attribute_hits(
            vec![
                hit("/home/a/htdocs/wp-content/x.php"),
                hit("/home/a/htdocs2/y.php"),
                hit("/home/a/htdocs2"),
            ],
            &roots,
        );
        assert_eq!(got[&id("a")], vec![hit("/home/a/htdocs/wp-content/x.php")]);
        assert_eq!(
            got[&id("a2")],
            vec![hit("/home/a/htdocs2/y.php"), hit("/home/a/htdocs2")]
        );
    }

    #[test]
    fn the_longest_root_wins_and_a_hit_under_no_root_is_dropped() {
        let roots = vec![
            (id("outer"), "/srv/site".to_string()),
            (id("inner"), "/srv/site/sub/htdocs".to_string()),
        ];
        let got = attribute_hits(
            vec![
                hit("/srv/site/sub/htdocs/a.php"),
                hit("/srv/site/b.php"),
                hit("/tmp/elsewhere.php"),
                hit("relative.php"),
            ],
            &roots,
        );
        assert_eq!(got[&id("inner")], vec![hit("/srv/site/sub/htdocs/a.php")]);
        assert_eq!(got[&id("outer")], vec![hit("/srv/site/b.php")]);
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn the_unit_carries_the_caps_and_no_syscall_filter() {
        let args = launch_for(
            "/usr/bin/clamscan",
            Path::new("/var/lib/hyperion/scan/clamav-list"),
            2,
            true,
            true,
        );
        assert_eq!(args.program, "/usr/bin/systemd-run");
        assert!(args.via_systemd);
        let props: Vec<&str> = args
            .args
            .windows(2)
            .filter(|w| w[0] == "-p")
            .map(|w| w[1].as_str())
            .collect();
        for p in [
            "MemoryMax=3G",
            "MemorySwapMax=0",
            "CPUWeight=10",
            "IOWeight=10",
            "Nice=19",
            "IOSchedulingClass=idle",
            "CPUQuota=50%",
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
            "NoNewPrivileges=yes",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectControlGroups=yes",
            "ReadOnlyPaths=/run",
            "RuntimeMaxSec=21600",
        ] {
            assert!(props.contains(&p), "{p} missing from {props:?}");
        }
        assert!(
            !props.iter().any(|p| p.starts_with("SystemCallFilter")),
            "the filter is untested with clamscan"
        );
        for flag in ["--wait", "--pipe", "--collect", "--unit=hyperion-clamscan"] {
            assert!(args.args.iter().any(|a| a == flag), "{flag}");
        }
        assert!(args
            .args
            .iter()
            .any(|a| a == "--file-list=/var/lib/hyperion/scan/clamav-list"));
        let many = launch_for("/usr/bin/clamscan", Path::new("/l"), 8, true, true);
        assert!(many.args.iter().any(|a| a == "CPUQuota=100%"));
    }

    #[test]
    fn without_systemd_it_runs_niced() {
        let l = launch_for("/usr/bin/clamscan", Path::new("/l"), 4, false, true);
        assert!(!l.via_systemd);
        assert_eq!(l.program, "/usr/bin/nice");
        assert_eq!(&l.args[..3], ["-n", "19", "/usr/bin/clamscan"]);
        let bare = launch_for("/usr/bin/clamscan", Path::new("/l"), 4, false, false);
        assert_eq!(bare.program, "/usr/bin/clamscan");
    }

    #[test]
    fn preflight_says_why_it_will_not_run() {
        const GIB: u64 = 1 << 30;
        let now = 1_700_000_000;
        let p = |installed, mem, db, until| clamav_preflight(installed, mem, db, until, now);
        assert_eq!(p(true, 2 * GIB, true, 0), ClamPreflight::Run);
        assert_eq!(p(true, 2 * GIB - 1, true, 0), ClamPreflight::SkipLowMemory);
        assert_eq!(p(false, 8 * GIB, true, 0), ClamPreflight::NotInstalled);
        assert_eq!(
            p(true, 8 * GIB, false, 0),
            ClamPreflight::SignaturesDownloading
        );
        assert_eq!(p(true, 8 * GIB, true, now + 1), ClamPreflight::BackingOff);
        assert_eq!(p(true, 8 * GIB, true, now), ClamPreflight::Run, "over");
        assert_eq!(p(false, 0, false, now + 1), ClamPreflight::NotInstalled);
        assert_eq!(p(true, 0, true, now + 1), ClamPreflight::BackingOff);
    }

    #[test]
    fn mem_available_is_read_from_meminfo() {
        let text = "MemTotal:       16384000 kB\nMemFree:          100000 kB\nMemAvailable:    2097152 kB\n";
        assert_eq!(parse_mem_available(text), Some(2 << 30));
        assert_eq!(parse_mem_available("MemTotal: 1 kB\n"), None);
        assert_eq!(parse_mem_available("MemAvailable: lots\n"), None);
    }

    // -- the list from the walker -----------------------------------------

    /// clamscan 1.4.6 reads a path up to 1022 bytes whole and mangles one of
    /// 1023 or more; 1000 is where this stops.
    #[test]
    fn a_path_over_a_thousand_bytes_is_not_listable() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = ListWriter::create(&dir.path().join("l"), 1 << 20).expect("w");
        let of = |n: usize| format!("/{}", "x".repeat(n - 1));
        assert!(matches!(w.add(&of(1000)).expect("w"), Added::Yes));
        assert!(matches!(w.add(&of(1001)).expect("w"), Added::LeftOut));
        assert!(matches!(w.add("/a\nb").expect("w"), Added::LeftOut));
        assert!(matches!(w.add("/a\rb").expect("w"), Added::LeftOut));
        assert!(matches!(w.add("/a\u{7f}b").expect("w"), Added::LeftOut));
    }

    fn site(dir: &Path) -> Vec<(HostingId, String)> {
        vec![(id("a"), dir.display().to_string())]
    }

    #[test]
    fn the_list_skips_media_big_files_links_and_names_it_cannot_hold() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path().join("htdocs");
        std::fs::create_dir_all(root.join("wp-content/uploads")).expect("mkdir");
        std::fs::write(root.join("index.php"), "<?php").expect("w");
        std::fs::write(root.join("wp-content/uploads/shell.php.jpg"), "x").expect("w");
        for name in ["a.JPG", "b.png", "c.mp4", "d.woff2", "e.pdf", "f.svg"] {
            std::fs::write(root.join(name), "x").expect("w");
        }
        std::fs::write(root.join("wp-content/uploads/x.js"), "x").expect("w");
        let big = std::fs::File::create(root.join("dump.sql")).expect("big");
        big.set_len(64 * 1024 * 1024 + 1).expect("sparse");
        let ok = std::fs::File::create(root.join("edge.bin")).expect("edge");
        ok.set_len(64 * 1024 * 1024).expect("sparse");
        std::os::unix::fs::symlink("/etc/passwd", root.join("link.php")).expect("link");
        std::fs::write(
            root.join(std::ffi::OsStr::from_bytes(b"line\nbreak.php")),
            "x",
        )
        .expect("newline name");
        std::fs::write(
            root.join(std::ffi::OsStr::from_bytes(b"tab\tname.php")),
            "x",
        )
        .expect("tab name");

        let list = dir.path().join("list");
        let plan = clamav_prepare(&site(&root), &list).expect("walk");
        let base = root.display().to_string();
        let mut got: Vec<String> = std::fs::read_to_string(&list)
            .expect("list")
            .lines()
            .map(String::from)
            .collect();
        got.sort();
        // `shell.php.jpg` is media whatever it hides: ClamAV isn't given those.
        let mut want = vec![
            format!("{base}/index.php"),
            format!("{base}/wp-content/uploads/x.js"),
            format!("{base}/edge.bin"),
        ];
        want.sort();
        assert_eq!(got, want);
        let l = &plan.sites[0];
        assert_eq!((l.files, l.left_out, l.skipped), (3, 2, 0));
        assert!(l.is_partial(), "names it could not list: not a full pass");
        assert!(plan
            .listed
            .contains(&path_key(&format!("{base}/index.php"))));
        assert!(!plan.listed.contains(&path_key(&format!("{base}/link.php"))));
        drop(plan);
        assert!(!list.exists(), "the list goes with the plan");
    }

    /// `ln shell.php .x` makes both names hard-linked, and the walker skips both:
    /// the pass can't be called full for a site that did it.
    #[test]
    fn hiding_a_file_in_a_hard_link_makes_the_site_partial() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path().join("htdocs");
        std::fs::create_dir_all(&root).expect("mkdir");
        std::fs::write(root.join("shell.php"), "x").expect("w");
        std::fs::write(root.join("index.php"), "x").expect("w");
        std::fs::hard_link(root.join("shell.php"), root.join(".x")).expect("ln");
        std::os::unix::fs::symlink("index.php", root.join("lnk.php")).expect("symlink");
        let plan = clamav_prepare(&site(&root), &dir.path().join("list")).expect("walk");
        let l = &plan.sites[0];
        assert_eq!(l.files, 1, "only index.php");
        assert_eq!(l.skipped, 2, "both names of the linked file");
        assert!(l.is_partial());
        // A plain symlink hides nothing and costs nothing.
        std::fs::remove_file(root.join(".x")).expect("rm");
        std::fs::write(root.join("shell.php"), "x").expect("w");
        let plan = clamav_prepare(&site(&root), &dir.path().join("list")).expect("walk");
        assert!(!plan.sites[0].is_partial(), "{:?}", plan.sites[0]);
    }

    #[test]
    fn the_list_stops_at_its_cap_and_says_so() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path().join("htdocs");
        std::fs::create_dir_all(&root).expect("mkdir");
        for i in 0..20 {
            std::fs::write(root.join(format!("f{i}.php")), "x").expect("w");
        }
        let limits = |n| ClamLimits {
            site_files: n,
            ..Default::default()
        };
        let list = dir.path().join("list");
        let p = clamav_prepare_with(&site(&root), &list, limits(5)).expect("walk");
        assert_eq!(p.sites[0].files, 5);
        assert!(p.sites[0].capped && p.sites[0].is_partial());
        let p = clamav_prepare_with(&site(&root), &list, limits(20)).expect("walk");
        assert_eq!(p.sites[0].files, 20);
        assert!(!p.sites[0].capped, "exactly at the cap is not over it");
    }

    /// The node's byte cap, injected small: the site it falls in is cut and the
    /// ones after it get nothing, and say so.
    #[test]
    fn past_the_nodes_byte_cap_the_rest_of_the_sites_are_partial() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut roots = Vec::new();
        for n in ["one", "two", "three"] {
            let root = dir.path().join(n);
            std::fs::create_dir_all(&root).expect("mkdir");
            for i in 0..4 {
                std::fs::write(root.join(format!("f{i}.php")), "x").expect("w");
            }
            roots.push((id(n), root.display().to_string()));
        }
        let per_path = (dir.path().join("one/f0.php").display().to_string().len() + 1) as u64;
        let limits = ClamLimits {
            node_bytes: per_path * 6,
            ..Default::default()
        };
        let list = dir.path().join("list");
        let plan = clamav_prepare_with(&roots, &list, limits).expect("walk");
        let [one, two, three] = &plan.sites[..] else {
            panic!("three sites");
        };
        assert_eq!((one.files, one.node_full), (4, false));
        assert_eq!(two.files, 2, "cut where the cap fell");
        assert!(two.node_full && two.is_partial());
        assert_eq!((three.files, three.node_full), (0, true));
        assert!(std::fs::metadata(&list).expect("list").len() <= limits.node_bytes);
    }

    #[test]
    fn a_stale_list_is_replaced_and_the_new_one_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path().join("htdocs");
        std::fs::create_dir_all(&root).expect("mkdir");
        std::fs::write(root.join("a.php"), "x").expect("w");
        let list = dir.path().join("list");
        std::fs::write(&list, "/etc/shadow\n").expect("stale");
        let plan = clamav_prepare(&site(&root), &list).expect("walk");
        let content = std::fs::read_to_string(&list).expect("list");
        assert_eq!(content, format!("{}/a.php\n", root.display()));
        let mode = std::fs::metadata(&list).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(plan);
    }

    #[test]
    fn a_site_that_cannot_be_walked_is_failed_not_clean() {
        let dir = tempfile::tempdir().expect("tmp");
        let roots = vec![(id("gone"), dir.path().join("nope").display().to_string())];
        let plan = clamav_prepare(&roots, &dir.path().join("list")).expect("walk");
        assert!(plan.sites[0].failed && plan.sites[0].is_partial());
    }
}
