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
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;
use std::process::Stdio;
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
/// Detections kept from one sweep. A node with more than this has bigger
/// problems than a full list, and the sweep says it was cut short.
const MAX_SWEEP_HITS: usize = 20_000;
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

/// Does this node have any ClamAV signatures yet?
pub fn clamav_db_present() -> bool {
    clamav_db_present_in(Path::new(CLAMAV_DB_DIR))
}

fn clamav_db_present_in(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|rd| {
        rd.flatten().any(|e| {
            matches!(
                e.path().extension().and_then(|x| x.to_str()),
                Some("cvd" | "cld")
            )
        })
    })
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

/// What a site hands to the sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClamList {
    /// Absolute paths, one per file.
    pub files: Vec<String>,
    /// Files whose names can't go in a one-path-per-line list: a control
    /// character (a newline would add a line of the tenant's choosing) or bytes
    /// that aren't UTF-8.
    pub left_out: u64,
    /// The cap, or the walk's own limit, ended the list early.
    pub capped: bool,
}

fn is_media(rel: &str) -> bool {
    rel.rsplit_once('.')
        .is_some_and(|(_, ext)| MEDIA_EXTENSIONS.iter().any(|m| m.eq_ignore_ascii_case(ext)))
}

fn listable(name: &str) -> bool {
    !name.chars().any(char::is_control)
}

/// Walk a docroot with the pinned-root walker and list what ClamAV should read:
/// every regular file but the media types and anything over 64 MiB, at most
/// `cap`. Blocking; the caller runs it on a blocking thread.
pub fn clamav_file_list(root: &Path, cap: usize) -> std::io::Result<ClamList> {
    let base = root
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "root is not UTF-8"))?
        .trim_end_matches('/');
    let tenant = TenantRoot::open(root)?;
    let opts = WalkOpts {
        max_entries: LIST_MAX_ENTRIES,
        prune: Vec::new(),
    };
    let mut list = ClamList::default();
    let stats = tenant.walk_until(&opts, |ev| {
        match ev {
            WalkEvent::File(m) => {
                if m.size > MAX_FILE_BYTES || is_media(&m.rel) {
                    return ControlFlow::Continue(());
                }
                if !listable(&m.rel) {
                    list.left_out += 1;
                } else if list.files.len() >= cap {
                    list.capped = true;
                    return ControlFlow::Break(());
                } else {
                    list.files.push(format!("{base}/{}", m.rel));
                }
            }
            WalkEvent::Skipped {
                why: SkipReason::NonUtf8Name,
                ..
            } => list.left_out += 1,
            WalkEvent::Skipped { .. } => {}
        }
        ControlFlow::Continue(())
    })?;
    list.capped |= stats.capped;
    Ok(list)
}

/// Write every site's paths, one per line, to a file only root can read. A
/// stale file from a crashed pass is replaced, never appended to or followed.
/// Returns how many paths went in; one with a control character is not one.
fn write_list(path: &Path, lists: &[(HostingId, Vec<String>)]) -> std::io::Result<u64> {
    use std::io::Write;
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
    let mut out = std::io::BufWriter::new(file);
    let mut written = 0u64;
    for p in lists.iter().flat_map(|(_, files)| files) {
        if !listable(p) {
            continue;
        }
        out.write_all(p.as_bytes())?;
        out.write_all(b"\n")?;
        written += 1;
    }
    out.flush()?;
    Ok(written)
}

/// Removes the list when the sweep is over, however it ended.
struct ListGuard<'a>(&'a Path);

impl Drop for ListGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// How a sweep ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepEnd {
    /// Every file in the list was looked at (exit 0 or 1).
    Complete,
    /// Some were not: clamscan exited 2 (a file it couldn't read), or was
    /// stopped. The detections are real; the absence of more is not proven.
    Partial,
    /// The kernel killed it for memory. Not tried again for a week.
    OutOfMemory,
    /// Stopped at the six-hour limit.
    TimedOut,
    /// Not a result at all: it didn't start or ended in a way that says nothing.
    Failed,
}

impl SweepEnd {
    /// Anything but a full pass: what it found stands, what it didn't find
    /// proves nothing.
    pub fn is_partial(self) -> bool {
        self != SweepEnd::Complete
    }
}

/// What one sweep found and how far it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClamSweep {
    pub hits: Vec<WpMalwareHit>,
    pub end: SweepEnd,
}

/// How the process ended, before anything is read into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepExit {
    Code(i32),
    Signal(i32),
    /// We stopped it at the time limit.
    TimedOut,
}

/// What the process's end means. Pure, because this is where a killed pass could
/// otherwise read as a clean one.
///
/// Exit 0 = nothing found, 1 = infections, 2 = an error somewhere (usually one
/// file that vanished or can't be read), so its detections stand and the pass is
/// partial. Through `systemd-run --wait` the unit's own verdict is on stderr
/// (`Finished with result: oom-kill`), and without it nothing can be said: the
/// client exits 1 when it can't start the unit at all, which must never read as
/// "infections found" with none listed.
pub fn classify_sweep(
    exit: SweepExit,
    via_systemd: bool,
    stderr: &str,
    hits: Vec<WpMalwareHit>,
) -> ClamSweep {
    let end = if exit == SweepExit::TimedOut {
        SweepEnd::TimedOut
    } else if via_systemd {
        match systemd_result(stderr) {
            None => SweepEnd::Failed,
            Some("oom-kill") => SweepEnd::OutOfMemory,
            Some("timeout") => SweepEnd::TimedOut,
            Some("success" | "exit-code") => end_of_exit(exit),
            Some(_) => SweepEnd::Partial,
        }
    } else {
        end_of_exit(exit)
    };
    ClamSweep { hits, end }
}

fn end_of_exit(exit: SweepExit) -> SweepEnd {
    match exit {
        SweepExit::Code(0 | 1) => SweepEnd::Complete,
        SweepExit::Code(2) => SweepEnd::Partial,
        SweepExit::Code(_) => SweepEnd::Failed,
        // SIGKILL with no unit to say why is what the OOM killer sends.
        SweepExit::Signal(9) => SweepEnd::OutOfMemory,
        SweepExit::Signal(_) => SweepEnd::Partial,
        SweepExit::TimedOut => SweepEnd::TimedOut,
    }
}

/// clamscan could not create its temporary directory.
fn is_no_tmp_error(line: &str) -> bool {
    line.starts_with("LibClamAV Error: Can't create temporary directory")
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

/// Hand each detection to the hosting whose root it is under. By path
/// components, the longest root first: `/home/a/htdocs2` is not under
/// `/home/a/htdocs`, and a site nested in another's tree gets its own files. A
/// detection under no root is logged and dropped.
pub fn attribute_hits(
    hits: Vec<WpMalwareHit>,
    roots: &[(HostingId, String)],
) -> HashMap<HostingId, Vec<WpMalwareHit>> {
    let mut order: Vec<(usize, &HostingId, &Path)> = roots
        .iter()
        .map(|(id, r)| (Path::new(r), id))
        .filter(|(r, _)| r.is_absolute())
        .map(|(r, id)| (r.components().count(), id, r))
        .collect();
    order.sort_by_key(|o| std::cmp::Reverse(o.0));
    let mut out: HashMap<HostingId, Vec<WpMalwareHit>> = HashMap::new();
    for hit in hits {
        let p = Path::new(&hit.path);
        match order
            .iter()
            .find(|(_, _, root)| p.is_absolute() && p.starts_with(root))
        {
            Some((_, id, _)) => out.entry((*id).clone()).or_default().push(hit),
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

/// One `clamscan` over every site's list. `Err` only when it could not be
/// started: a pass that ran and came back with a bad ending is a [`ClamSweep`]
/// that says so. Nothing is held while it runs.
pub async fn clamav_sweep(
    lists: &[(HostingId, Vec<String>)],
    list_path: &Path,
) -> Result<ClamSweep, AdapterError> {
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
        list_path,
        host_cores(),
        systemd,
        Path::new(NICE).exists(),
    );
    // The unit stops itself at its limit; without one, this does.
    let limit = Duration::from_secs(RUNTIME_MAX_SEC + if systemd { 120 } else { 0 });
    sweep_with(lists, list_path, launch, limit).await
}

async fn sweep_with(
    lists: &[(HostingId, Vec<String>)],
    list_path: &Path,
    launch: Launch,
    limit: Duration,
) -> Result<ClamSweep, AdapterError> {
    let _list = ListGuard(list_path);
    if write_list(list_path, lists)? == 0 {
        return Ok(ClamSweep {
            hits: Vec::new(),
            end: SweepEnd::Complete,
        });
    }
    run_launch(&launch, limit).await
}

/// Run it, reading stdout line by line so a pass that dies keeps what it found.
async fn run_launch(launch: &Launch, limit: Duration) -> Result<ClamSweep, AdapterError> {
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
    // The tail is systemd's verdict; the flag is clamscan saying it had nowhere to
    // unpack, which it does without failing: every file is then read as clean.
    let tail = tokio::spawn(async move {
        let mut keep: Vec<u8> = Vec::new();
        let mut saw_no_tmp = false;
        let mut lines = BufReader::new(stderr).split(b'\n');
        while let Ok(Some(line)) = lines.next_segment().await {
            saw_no_tmp |= is_no_tmp_error(&String::from_utf8_lossy(&line));
            keep.extend_from_slice(&line);
            keep.push(b'\n');
            if keep.len() > STDERR_TAIL_BYTES {
                keep.drain(..keep.len() - STDERR_TAIL_BYTES);
            }
        }
        (String::from_utf8_lossy(&keep).into_owned(), saw_no_tmp)
    });
    let mut hits: Vec<WpMalwareHit> = Vec::new();
    let mut too_many = false;
    let waited = tokio::time::timeout(limit, async {
        let mut lines = BufReader::new(stdout).split(b'\n');
        while let Some(line) = lines.next_segment().await? {
            if let Some(hit) = parse_hit_line(&String::from_utf8_lossy(&line)) {
                if hits.len() < MAX_SWEEP_HITS {
                    hits.push(hit);
                } else {
                    too_many = true;
                }
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
    let (stderr, no_tmp) = tokio::time::timeout(Duration::from_secs(5), tail)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let mut sweep = classify_sweep(exit, launch.via_systemd, &stderr, hits);
    if too_many && sweep.end == SweepEnd::Complete {
        sweep.end = SweepEnd::Partial;
    }
    // Nothing was scanned, whatever the exit code says.
    if no_tmp && sweep.end == SweepEnd::Complete {
        sweep.end = SweepEnd::Failed;
    }
    Ok(sweep)
}

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

/// One `clamscan --infected --no-summary` line: `<path>: <Signature> FOUND`.
/// `ERROR` lines for unreadable files, blank lines, whatever a future clamscan
/// adds: not a detection, so `None` rather than a guess.
fn parse_hit_line(raw: &str) -> Option<WpMalwareHit> {
    let line = raw.trim_end();
    // Only " FOUND" lines are detections; "… ERROR" / "… OK" are not.
    let body = line.strip_suffix(" FOUND")?;
    // Split from the RIGHT: a path may itself contain ": ", the signature name
    // never does.
    let (path, signature) = body
        .rsplit_once(": ")
        .or_else(|| body.rsplit_once(':'))
        .map(|(p, s)| (p.trim(), s.trim()))?;
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
        std::fs::write(dir.join("daily.cld"), b"x").expect("write");
        assert!(clamav_db_present_in(&dir));
        std::fs::remove_file(dir.join("daily.cld")).expect("rm");
        std::fs::write(dir.join("main.cvd"), b"x").expect("write");
        assert!(clamav_db_present_in(&dir));
        let _ = std::fs::remove_dir_all(&dir);
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

    /// A stand-in for the scanner: counts its runs, keeps the list it was given
    /// and the flags, prints `$FAKE_OUT` and exits as `$FAKE_EXIT` says.
    fn fake_clamscan(dir: &Path, hits: &str, exit: i32) -> Launch {
        let script = format!(
            r#"echo run >> '{runs}'
echo "$@" > '{args}'
for a in "$@"; do case "$a" in --file-list=*) cp "${{a#--file-list=}}" '{list}';; esac; done
printf '%s' '{hits}'
exit {exit}"#,
            runs = dir.join("runs").display(),
            args = dir.join("args").display(),
            list = dir.join("seen-list").display(),
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

    #[tokio::test]
    async fn one_process_per_sweep_with_file_list() {
        let dir = tempfile::tempdir().expect("tmp");
        let lists = vec![
            (
                id("a"),
                vec![
                    "/home/a/htdocs/x.php".to_string(),
                    "/home/a/htdocs/y.php".into(),
                ],
            ),
            (id("b"), vec!["/home/b/htdocs/z.php".to_string()]),
        ];
        let launch = fake_clamscan(
            dir.path(),
            "/home/b/htdocs/z.php: Php.Trojan.Webshell-1 FOUND\n",
            1,
        );
        let sweep = sweep_with(&lists, &dir.path().join("list"), launch, LIMIT)
            .await
            .expect("ran");

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
            "the list is removed after"
        );
        assert_eq!(sweep.end, SweepEnd::Complete);
        assert_eq!(sweep.hits, vec![hit("/home/b/htdocs/z.php")]);
    }

    #[tokio::test]
    async fn a_list_left_by_a_crash_is_replaced_and_is_private() {
        let dir = tempfile::tempdir().expect("tmp");
        let list = dir.path().join("list");
        std::fs::write(&list, "/etc/shadow\n").expect("stale");
        let lists = vec![(id("a"), vec!["/home/a/htdocs/x.php".to_string()])];
        // A scanner that reports the mode of the list it was given.
        let script = format!(
            r#"for a in "$@"; do case "$a" in --file-list=*) f="${{a#--file-list=}}"; cat "$f" > '{c}'; ls -l "$f" | cut -c1-10 > '{m}';; esac; done"#,
            c = dir.path().join("content").display(),
            m = dir.path().join("mode").display(),
        );
        let mut args = vec!["-c".to_string(), script, "fake".to_string()];
        args.extend(clamscan_args(&list));
        let launch = Launch {
            program: "/bin/sh".into(),
            args,
            via_systemd: false,
        };
        sweep_with(&lists, &list, launch, LIMIT).await.expect("ran");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("content")).expect("c"),
            "/home/a/htdocs/x.php\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("mode"))
                .expect("m")
                .trim(),
            "-rw-------"
        );
    }

    #[tokio::test]
    async fn a_name_that_would_split_the_list_is_never_written() {
        let dir = tempfile::tempdir().expect("tmp");
        let lists = vec![(
            id("a"),
            vec![
                "/home/a/htdocs/ok.php".to_string(),
                "/home/a/htdocs/x\n/etc/shadow".to_string(),
                "/home/a/htdocs/cr\rx".to_string(),
            ],
        )];
        let launch = fake_clamscan(dir.path(), "", 0);
        sweep_with(&lists, &dir.path().join("list"), launch, LIMIT)
            .await
            .expect("ran");
        let seen = std::fs::read_to_string(dir.path().join("seen-list")).expect("list");
        assert_eq!(seen, "/home/a/htdocs/ok.php\n");
    }

    #[tokio::test]
    async fn nothing_to_scan_starts_nothing() {
        let dir = tempfile::tempdir().expect("tmp");
        let launch = fake_clamscan(dir.path(), "", 0);
        let sweep = sweep_with(
            &[(id("a"), vec![])],
            &dir.path().join("list"),
            launch,
            LIMIT,
        )
        .await
        .expect("ran");
        assert_eq!(sweep.end, SweepEnd::Complete);
        assert!(!dir.path().join("runs").exists(), "no process for no files");
    }

    #[tokio::test]
    async fn partial_keeps_hits() {
        // One unreadable file makes clamscan exit 2 after it printed a webshell.
        let dir = tempfile::tempdir().expect("tmp");
        let launch = fake_clamscan(
            dir.path(),
            "/home/a/htdocs/x.php: Php.Trojan.Webshell-1 FOUND\n/home/a/htdocs/gone: Can't open file ERROR\n",
            2,
        );
        let lists = vec![(id("a"), vec!["/home/a/htdocs/x.php".to_string()])];
        let sweep = sweep_with(&lists, &dir.path().join("list"), launch, LIMIT)
            .await
            .expect("ran");
        assert_eq!(sweep.end, SweepEnd::Partial);
        assert_eq!(sweep.hits, vec![hit("/home/a/htdocs/x.php")]);
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
        let lists = vec![(id("a"), vec!["/home/a/htdocs/x.php".to_string()])];
        let sweep = sweep_with(&lists, &dir.path().join("list"), launch, LIMIT)
            .await
            .expect("ran");
        assert_eq!(sweep.end, SweepEnd::OutOfMemory);
        assert_eq!(sweep.hits, vec![hit("/home/a/htdocs/x.php")]);
    }

    /// Without a writable temp directory clamscan complains and reads every file
    /// as clean, exit 0. That is not a pass.
    #[tokio::test]
    async fn a_scanner_with_nowhere_to_unpack_is_not_a_clean_pass() {
        let dir = tempfile::tempdir().expect("tmp");
        let script = r#"echo "LibClamAV Error: Can't create temporary directory for scan: /tmp/x." >&2; exit 0"#;
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            via_systemd: false,
        };
        let lists = vec![(id("a"), vec!["/home/a/htdocs/x.php".to_string()])];
        let sweep = sweep_with(&lists, &dir.path().join("list"), launch, LIMIT)
            .await
            .expect("ran");
        assert_eq!(sweep.end, SweepEnd::Failed);
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
        let lists = vec![(id("a"), vec!["/home/a/htdocs/x.php".to_string()])];
        let started = std::time::Instant::now();
        let sweep = sweep_with(
            &lists,
            &dir.path().join("list"),
            launch,
            Duration::from_millis(500),
        )
        .await
        .expect("ran");
        assert!(started.elapsed() < Duration::from_secs(20));
        assert_eq!(sweep.end, SweepEnd::TimedOut);
        assert_eq!(sweep.hits, vec![hit("/home/a/htdocs/x.php")]);
    }

    #[tokio::test]
    async fn a_scanner_that_cannot_start_is_an_error() {
        let dir = tempfile::tempdir().expect("tmp");
        let launch = Launch {
            program: "/nonexistent/clamscan".into(),
            args: vec![],
            via_systemd: false,
        };
        let lists = vec![(id("a"), vec!["/home/a/htdocs/x.php".to_string()])];
        let r = sweep_with(&lists, &dir.path().join("list"), launch, LIMIT).await;
        assert!(r.is_err());
        assert!(!dir.path().join("list").exists(), "no list left behind");
    }

    #[test]
    fn exit_codes_decide_the_pass() {
        let h = vec![hit("/h/a.php")];
        let c = |end, systemd, err: &str| classify_sweep(end, systemd, err, h.clone());
        assert_eq!(c(SweepExit::Code(0), false, "").end, SweepEnd::Complete);
        assert_eq!(c(SweepExit::Code(1), false, "").end, SweepEnd::Complete);
        assert_eq!(c(SweepExit::Code(2), false, "").end, SweepEnd::Partial);
        assert_eq!(c(SweepExit::Code(2), false, "").hits, h);
        assert_eq!(c(SweepExit::Code(127), false, "").end, SweepEnd::Failed);
        assert_eq!(
            c(SweepExit::Signal(9), false, "").end,
            SweepEnd::OutOfMemory
        );
        assert_eq!(c(SweepExit::Signal(15), false, "").end, SweepEnd::Partial);
        assert_eq!(c(SweepExit::TimedOut, false, "").end, SweepEnd::TimedOut);
    }

    #[test]
    fn systemd_says_why_a_unit_ended() {
        let h = vec![hit("/h/a.php")];
        let run = |code, err: &str| classify_sweep(SweepExit::Code(code), true, err, h.clone());
        let said = |result: &str| {
            format!("Running as unit: hyperion-clamscan.service\nFinished with result: {result}\nService runtime: 3h\n")
        };
        assert_eq!(run(1, &said("oom-kill")).end, SweepEnd::OutOfMemory);
        assert_eq!(run(1, &said("timeout")).end, SweepEnd::TimedOut);
        assert_eq!(run(1, &said("signal")).end, SweepEnd::Partial);
        assert_eq!(run(1, &said("exit-code")).end, SweepEnd::Complete);
        assert_eq!(run(2, &said("exit-code")).end, SweepEnd::Partial);
        assert_eq!(run(0, &said("success")).end, SweepEnd::Complete);
        // The last word counts, and a line that only starts like it doesn't.
        let tricked = format!("Finished with result: success\n{}", said("oom-kill"));
        assert_eq!(run(1, &tricked).end, SweepEnd::OutOfMemory);
        let echoed = "/home/a/htdocs/x: Finished with result: success\n";
        assert_eq!(run(1, echoed).end, SweepEnd::Failed);
        // systemd-run's own failure (the unit name taken, a bad property) exits
        // 1 as well: with no word from the unit, that must not read as "hits".
        let refused = "Failed to start transient service unit: Unit hyperion-clamscan.service was already loaded or has a fragment file.\n";
        assert_eq!(run(1, refused).end, SweepEnd::Failed);
        assert_eq!(run(0, "").end, SweepEnd::Failed);
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
        // More cores: the whole core is the cap.
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
        // Not installed beats everything; the backoff beats memory (the reason
        // worth giving is the kill).
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

    #[test]
    fn the_list_skips_media_big_files_links_and_names_it_cannot_hold() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path();
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

        let list = clamav_file_list(root, 1000).expect("walk");
        let base = root.display().to_string();
        // `shell.php.jpg` is media whatever it hides: ClamAV isn't given those.
        let mut want = vec![
            format!("{base}/index.php"),
            format!("{base}/wp-content/uploads/x.js"),
            format!("{base}/edge.bin"),
        ];
        let mut got = list.files.clone();
        got.sort();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(list.left_out, 2, "the two names with control characters");
        assert!(!list.capped);
    }

    #[test]
    fn the_list_stops_at_its_cap_and_says_so() {
        let dir = tempfile::tempdir().expect("tmp");
        for i in 0..20 {
            std::fs::write(dir.path().join(format!("f{i}.php")), "x").expect("w");
        }
        let list = clamav_file_list(dir.path(), 5).expect("walk");
        assert_eq!(list.files.len(), 5);
        assert!(list.capped);
        let all = clamav_file_list(dir.path(), 20).expect("walk");
        assert_eq!(all.files.len(), 20);
        assert!(!all.capped, "exactly at the cap is not over it");
    }
}
