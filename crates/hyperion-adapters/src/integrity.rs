//! ClamAV adapter: the optional signature pass over a docroot, beside the
//! native site scan in `sitescan`. clamd is heavy for a shared host, so a missing
//! binary means "not available", never an error and never a false "clean".
//!
//! What shells out is at the top of this module; what parses is a pure function
//! at the bottom, unit-tested against real-shaped clamscan output. Getting the
//! parsing wrong is how this feature would lie to a paying customer, so it is
//! the part that is tested hardest.

use crate::AdapterError;
use hyperion_types::WpMalwareHit;
use std::path::Path;
use tokio::process::Command;
use tracing::debug;

/// Where `clamscan` may live. Debian's `clamav` package ships
/// `/usr/bin/clamscan`; source builds land in `/usr/local/bin`.
const CLAMSCAN_BINS: &[&str] = &["/usr/bin/clamscan", "/usr/local/bin/clamscan"];

// ---------------------------------------------------------------------------
// Command plumbing
// ---------------------------------------------------------------------------

/// Raw outcome of a command whose non-zero exit is a legitimate *result*.
#[derive(Debug, Clone)]
pub struct Captured {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run a command and return its exit code together with BOTH streams,
/// treating a non-zero exit as data rather than as a failure.
///
/// Neither `cmd::run` nor `cmd::run_capturing_all` fits this module: both
/// turn a non-zero exit into `AdapterError`, and both keep only the last
/// 4 KiB of output. Here non-zero is the *normal* case — clamscan exits 1 on
/// every detection — and the text it emits alongside it is precisely the
/// finding list we must not lose or truncate. Only a failure to *spawn* (binary
/// missing, fork failure) is an error.
async fn run_capturing(program: &str, args: &[&str]) -> Result<Captured, AdapterError> {
    // No redaction pass here (unlike `cmd::run`): every argument this module
    // builds is a flag or a docroot path — no credential ever reaches this argv.
    debug!(program, ?args, "exec (exit code is a result)");
    let out = Command::new(program).args(args).output().await?;
    Ok(Captured {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Refuse anything that isn't a plain absolute path. `..` is rejected
/// outright rather than normalised: every caller passes a hosting's own
/// docroot straight from the state table, so a traversal component means
/// something upstream is wrong and we would rather fail loudly than scan
/// (or report on) another tenant's tree.
fn guard_path(path: &str) -> Result<(), AdapterError> {
    let ok = path.starts_with('/')
        && path.len() <= 4096
        && !path.contains("..")
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'));
    if !ok {
        return Err(AdapterError::Other(format!("unsafe path: {path}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ClamAV
// ---------------------------------------------------------------------------

/// Outcome of a ClamAV pass. `available == false` means "not scanned" —
/// callers must never render an empty `hits` from an unavailable scanner as
/// a clean bill of health.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MalwareScan {
    pub available: bool,
    pub hits: Vec<WpMalwareHit>,
    /// clamscan exited 2 (part of the tree could not be read) but still
    /// reported detections. The hits are real; the absence of more is not
    /// proven.
    pub partial: bool,
}

/// Where freshclam keeps the signature database.
const CLAMAV_DB_DIR: &str = "/var/lib/clamav";

/// Does this node have any ClamAV signatures yet? Right after the package
/// installs, `freshclam` is still downloading them and `clamscan` exits 2
/// with "No supported database files found". That is a state to wait out,
/// not a scan that failed.
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

/// Turn a finished `clamscan` run into a [`MalwareScan`].
///
/// Exit 0 = clean, 1 = infections, 2 = an error occurred. Exit 2 is
/// usually one unreadable file, so detections printed before it are kept
/// (`partial`); without any, a half-walked tree proves nothing and the scan
/// is not `available`. Any other code is not a result at all.
pub fn classify_clamscan(code: i32, stdout: &str) -> MalwareScan {
    match code {
        0 => MalwareScan {
            available: true,
            ..Default::default()
        },
        1 => MalwareScan {
            available: true,
            // Detections go to stdout; stderr carries only diagnostics.
            hits: parse_clamscan_output(stdout),
            partial: false,
        },
        2 => {
            let hits = parse_clamscan_output(stdout);
            MalwareScan {
                available: !hits.is_empty(),
                hits,
                partial: true,
            }
        }
        _ => MalwareScan::default(),
    }
}

/// First `clamscan` binary that exists on this node, if any.
fn clamscan_bin() -> Option<&'static str> {
    CLAMSCAN_BINS
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
}

/// Is an on-demand ClamAV scanner installed here? Absence is a normal
/// state, not an error — the operator may simply not want a scanner
/// resident on a shared host.
pub fn clamav_available() -> bool {
    clamscan_bin().is_some()
}

/// Recursively scan `path` for malware signatures.
///
/// Exit-code contract (`clamscan(1)`): 0 = nothing found, 1 = infections
/// found, 2 = an error occurred. Exit 2 with no detections is an error, not
/// "clean": some part of the tree could not be read and a partial pass must
/// not be reported as a pass. Exit 2 WITH detections keeps them, marked
/// `partial` (see [`classify_clamscan`]).
pub async fn scan_malware(path: &str) -> Result<MalwareScan, AdapterError> {
    scan_malware_niced(path, 0).await
}

/// How hard a scan is allowed to lean on the box.
///
/// `clamscan` is single-threaded but CPU-bound, and on a small VPS it will
/// happily saturate a core for minutes — long enough for sites on that box to
/// go visibly slow while an unattended sweep runs. `nice` is the right tool:
/// unlike a hard cap it costs nothing when the machine is idle (the scan still
/// gets the full core) and yields immediately when a web request wants the
/// CPU. A hard percentage cap would make the scan slower even on a quiet box,
/// for no benefit.
///
/// `ionice` best-effort class 7 goes with it. Scanning a docroot is mostly I/O
/// against files the web server also wants, and starving nginx of disk is the
/// other half of "the site went slow during a scan".
///
/// `niceness` is clamped to clamscan's useful range. 0 means "no change",
/// which is what callers that never configured this get.
pub async fn scan_malware_niced(path: &str, niceness: i32) -> Result<MalwareScan, AdapterError> {
    guard_path(path)?;
    let Some(bin) = clamscan_bin() else {
        return Ok(MalwareScan::default());
    };
    // `--infected` prints detections only, `--no-summary` drops the trailing
    // stats block — both keep the output to exactly the lines we parse.
    let scan_args = ["-r", "--infected", "--no-summary", path];
    let niceness = niceness.clamp(0, 19);
    let out = if niceness > 0 && std::path::Path::new("/usr/bin/nice").exists() {
        let n = niceness.to_string();
        // ionice is best-effort: on a kernel or filesystem that does not
        // support it the wrapper still runs the scan, so a missing scheduler
        // class must not become a failed scan.
        let mut args: Vec<&str> = Vec::new();
        let have_ionice = std::path::Path::new("/usr/bin/ionice").exists();
        if have_ionice {
            args.extend(["-n", &n, "/usr/bin/ionice", "-c", "2", "-n", "7", bin]);
        } else {
            args.extend(["-n", &n, bin]);
        }
        args.extend(scan_args);
        run_capturing("/usr/bin/nice", &args).await?
    } else {
        run_capturing(bin, &scan_args).await?
    };
    let scan = classify_clamscan(out.code, &out.stdout);
    if scan.available {
        return Ok(scan);
    }
    // Nothing usable: no pass at all, so say why.
    Err(AdapterError::Command {
        cmd: format!("{bin} -r --infected --no-summary {path}"),
        code: out.code,
        stderr_tail: out.stderr,
    })
}

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

/// Parse `clamscan --infected --no-summary` output.
///
/// Every detection is one line, `<path>: <Signature> FOUND`. Non-detection
/// lines — `ERROR` lines for unreadable files, blank lines, whatever a
/// future clamscan adds — are ignored rather than guessed at.
pub fn parse_clamscan_output(text: &str) -> Vec<WpMalwareHit> {
    let mut hits = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        // Only " FOUND" lines are detections; "… ERROR" / "… OK" are not.
        let Some(body) = line.strip_suffix(" FOUND") else {
            continue;
        };
        // Split from the RIGHT: a path may itself contain ": ", the
        // signature name never does.
        let Some((path, signature)) = body
            .rsplit_once(": ")
            .or_else(|| body.rsplit_once(':'))
            .map(|(p, s)| (p.trim(), s.trim()))
        else {
            continue;
        };
        if path.is_empty() || signature.is_empty() {
            continue;
        }
        hits.push(WpMalwareHit {
            path: path.to_string(),
            signature: signature.to_string(),
        });
    }
    hits
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
    fn exit_two_keeps_real_hits_and_marks_partial() {
        // One unreadable file makes clamscan exit 2 even though it found a
        // webshell elsewhere; dropping that hit would hide a real infection.
        let out = "/home/site/htdocs/wp-content/uploads/x.php: Php.Trojan.Webshell-1 FOUND\n";
        let scan = classify_clamscan(2, out);
        assert!(scan.available);
        assert!(scan.partial);
        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.hits[0].signature, "Php.Trojan.Webshell-1");
    }

    #[test]
    fn exit_two_without_hits_proves_nothing() {
        let scan = classify_clamscan(2, "");
        assert!(!scan.available, "a partial walk with no hits is not a pass");
        assert!(scan.hits.is_empty());
    }

    #[test]
    fn exit_zero_is_not_partial() {
        let scan = classify_clamscan(0, "");
        assert!(scan.available);
        assert!(!scan.partial);
        assert!(scan.hits.is_empty());
        let scan = classify_clamscan(1, "/h/a.php: Php.Trojan.Agent-1 FOUND\n");
        assert!(scan.available && !scan.partial);
        assert_eq!(scan.hits.len(), 1);
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

    // -- guards ------------------------------------------------------------

    #[test]
    fn guards_refuse_injection_shaped_input() {
        for bad in [
            "htdocs",                     // not absolute
            "/home/site/../other/htdocs", // traversal
            "/home/site/htdocs; rm -rf /",
            "/home/site/$(id)",
            "/home/site/htdocs\n",
        ] {
            assert!(guard_path(bad).is_err(), "must refuse path {bad:?}");
        }
        assert!(guard_path("/home/site_1/htdocs").is_ok());
    }
}
