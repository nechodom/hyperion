//! The scan runs in a separate process, the agent binary's hidden `scan-worker`
//! subcommand, inside a transient systemd unit that can read every tenant file
//! and write none. It parses hostile input as root, so what it may do is cut to
//! what it needs, and a reply that doesn't arrive whole is a failure, never a
//! clean site.
//!
//! The job goes in as one JSON document on stdin and the reply comes out as one
//! on stdout. Anything the worker logs goes to stderr.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Once;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::accept::{writer_hash, WriterPaths};
use super::discover::{discover, Discovery};
use super::pressure::{host_cores, system_gate};
use super::scan::{scan_site, ScanInput, SiteScanOutcome, WriterKind};
use super::walk::TenantRoot;
use crate::AdapterError;

/// The subcommand the agent binary answers to as the worker.
pub const WORKER_ARG: &str = "scan-worker";
/// Fixed, so systemd itself refuses a second worker on the node.
pub const UNIT_NAME: &str = "hyperion-sitescan";
/// The unit the hash of a writer's files runs in. Its own name, so it isn't held
/// behind a scan that takes hours.
pub const ACCEPT_UNIT_NAME: &str = "hyperion-sitescan-accept";
/// The worker's state: `manifests/`, `baselines/` and `accepted/`. [`unit_args`]
/// names it.
pub const SCAN_DIR: &str = "/var/lib/hyperion/scan";
/// Replies and jobs bigger than this are refused. A reply that large is a bug or
/// an attack, and holding it in memory would not be free.
pub const MAX_REPLY_BYTES: usize = 64 * 1024 * 1024;
/// The unit is stopped after this long (6 hours).
const RUNTIME_MAX_SEC: u64 = 21_600;
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const NICE: &str = "/usr/bin/nice";
/// How much of the worker's stderr goes into a failure message.
const STDERR_TAIL_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerJob {
    /// Look at the docroot and say what it holds, so the agent knows which
    /// manifests to fetch.
    Discover {
        root: PathBuf,
    },
    Scan(ScanInput),
    /// A writer of ours (git deploy, restore) has finished. Hash the code files
    /// it names, or all of them, and write what the scan may accept to `out`.
    WriterHash {
        root: PathBuf,
        kind: WriterKind,
        paths: WriterPaths,
        out: PathBuf,
    },
}

impl WorkerJob {
    /// The transient unit this job runs in.
    fn unit(&self) -> &'static str {
        match self {
            WorkerJob::WriterHash { .. } => ACCEPT_UNIT_NAME,
            _ => UNIT_NAME,
        }
    }
}

// One reply is alive per run, so the size of the variants costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerReply {
    Discovery(Discovery),
    Scan(SiteScanOutcome),
    /// The hash of a writer's files is written. `partial`: a cap stopped it, and
    /// what it left unlisted gets reviewed.
    Hashed {
        listed: u64,
        partial: bool,
    },
    /// Another worker holds the node's one slot. Try again later.
    Busy,
    /// The job did not run to an answer. The message says why.
    Failed(String),
}

/// Arguments for `systemd-run`, the caps included: the worker may read what a
/// scan reads and write only its own state directory.
pub fn unit_args(cores: usize, exe: &Path) -> Vec<String> {
    unit_args_for(UNIT_NAME, cores, exe)
}

/// [`unit_args`] for the named unit: same caps, another name.
pub fn unit_args_for(unit: &str, cores: usize, exe: &Path) -> Vec<String> {
    let quota = if cores <= 2 { "50%" } else { "100%" };
    let mut args = vec![format!("--unit={unit}")];
    args.extend(["--wait", "--pipe", "--collect"].map(String::from));
    let props = [
        "MemoryMax=256M".to_string(),
        "CPUWeight=10".to_string(),
        "IOWeight=10".to_string(),
        "Nice=19".to_string(),
        "IOSchedulingClass=idle".to_string(),
        format!("CPUQuota={quota}"),
        "CapabilityBoundingSet=CAP_DAC_READ_SEARCH".to_string(),
        "NoNewPrivileges=yes".to_string(),
        "PrivateNetwork=yes".to_string(),
        "ProtectSystem=strict".to_string(),
        // `strict` leaves /home, /root and /run/user to this: without it a worker
        // taken over could write /root/.ssh/authorized_keys.
        "ProtectHome=read-only".to_string(),
        "ReadWritePaths=/var/lib/hyperion/scan".to_string(),
        // Home-directory hostings, and the manifests inside the writable
        // directory: the worker reads those and never changes them.
        "ReadOnlyPaths=/home /var/lib/hyperion/scan/manifests".to_string(),
        format!("RuntimeMaxSec={RUNTIME_MAX_SEC}"),
        // What the caps above leave open to a worker that has been taken over
        // by a hostile file: PID 1's private socket (an unconfined unit), the
        // agent's sockets in /run, devices, kernel knobs, handle-based opens
        // through the writable mount, and signalling other processes.
        "PrivateDevices=yes".to_string(),
        "ProtectKernelTunables=yes".to_string(),
        "ProtectKernelModules=yes".to_string(),
        "ProtectKernelLogs=yes".to_string(),
        "ProtectControlGroups=yes".to_string(),
        "ProtectClock=yes".to_string(),
        "RestrictNamespaces=yes".to_string(),
        "LockPersonality=yes".to_string(),
        "RestrictSUIDSGID=yes".to_string(),
        "SystemCallArchitectures=native".to_string(),
        "MemorySwapMax=0".to_string(),
        // The tunables and cgroup protections leave a real /run writable.
        "ReadOnlyPaths=/run".to_string(),
        "SystemCallFilter=@system-service".to_string(),
        "SystemCallFilter=~@privileged @mount @debug @raw-io @reboot @swap @module @network-io kill tkill tgkill pidfd_send_signal".to_string(),
    ];
    // No `RestrictAddressFamilies=none` (systemd-run 252 rejects it) and no
    // `InaccessiblePaths=/run` (the unit fails to start): the syscall filter
    // and `PrivateNetwork` close sockets, and `ReadOnlyPaths` closes /run.
    for p in props {
        args.push("-p".to_string());
        args.push(p);
    }
    args.push(exe.to_string_lossy().into_owned());
    args.push(WORKER_ARG.to_string());
    args
}

/// Make the directories the unit mounts, root-only. Without them it exits 226
/// before the worker starts.
pub fn prepare_scan_dirs(base: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for dir in [
        base.to_path_buf(),
        base.join("manifests"),
        base.join("baselines"),
        base.join("accepted"),
    ] {
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// After an update `current_exe` names the replaced file, with this suffix. The
/// new binary is at the path without it, and the old one can't be started by name.
fn strip_deleted_suffix(exe: PathBuf) -> PathBuf {
    match exe.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
        Some(s) => PathBuf::from(s),
        None => exe,
    }
}

/// Run one job the way the agent does: the directories made, this binary as the
/// worker. Every way that can fail is `WorkerReply::Failed`.
pub async fn run_job(job: &WorkerJob) -> WorkerReply {
    if let Err(e) = prepare_scan_dirs(Path::new(SCAN_DIR)) {
        return failed(format!("could not prepare {SCAN_DIR}: {e}"));
    }
    let exe = match std::env::current_exe() {
        Ok(p) => strip_deleted_suffix(p),
        Err(e) => return failed(format!("could not find the agent binary: {e}")),
    };
    run_worker(job, &exe)
        .await
        .unwrap_or_else(|e| failed(e.to_string()))
}

/// Run one job in the capped unit, or, without `systemd-run`, as a child under
/// `nice`. `Err` only when the job could not be written down; every way the
/// worker can fail to answer is `Ok(WorkerReply::Failed)`.
pub async fn run_worker(job: &WorkerJob, exe: &Path) -> Result<WorkerReply, AdapterError> {
    if !Path::new(SYSTEMD_RUN).exists() {
        return run_direct(job, exe, MAX_REPLY_BYTES).await;
    }
    let mut cmd = Command::new(SYSTEMD_RUN);
    cmd.args(unit_args_for(job.unit(), host_cores(), exe));
    run_child(cmd, job, MAX_REPLY_BYTES, Some(job.unit())).await
}

/// The no-systemd path, also what the tests drive.
pub async fn run_direct(
    job: &WorkerJob,
    exe: &Path,
    max_reply: usize,
) -> Result<WorkerReply, AdapterError> {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            "systemd-run not found: the site scan runs without its resource caps, as full root and with no read-only sandbox"
        );
    });
    let mut cmd;
    if Path::new(NICE).exists() {
        cmd = Command::new(NICE);
        cmd.args(["-n", "19"]).arg(exe);
    } else {
        cmd = Command::new(exe);
    }
    cmd.arg(WORKER_ARG);
    run_child(cmd, job, max_reply, None).await
}

async fn run_child(
    mut cmd: Command,
    job: &WorkerJob,
    max_reply: usize,
    // The unit systemd runs it in, when it does.
    systemd_unit: Option<&str>,
) -> Result<WorkerReply, AdapterError> {
    let input = serde_json::to_vec(job).map_err(|e| AdapterError::Other(e.to_string()))?;
    let program = cmd.as_std().get_program().to_string_lossy().into_owned();
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Ok(failed(format!("could not start {program}: {e}"))),
    };
    let (Some(mut stdin), Some(mut stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Ok(failed(format!("could not reach {program}'s pipes")));
    };
    // Writing and reading at once, so a big job and a big reply cannot wait on
    // each other. A worker that stops reading early is not an error here: its
    // exit status says what happened.
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&input).await;
        let _ = stdin.shutdown().await;
    });
    let tail = tokio::spawn(async move {
        let mut keep: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf).await {
            if n == 0 {
                break;
            }
            keep.extend_from_slice(&buf[..n]);
            if keep.len() > STDERR_TAIL_BYTES {
                keep.drain(..keep.len() - STDERR_TAIL_BYTES);
            }
        }
        String::from_utf8_lossy(&keep).trim().to_string()
    });
    let mut reply = Vec::new();
    let limit = max_reply as u64 + 1;
    let waited = tokio::time::timeout(Duration::from_secs(RUNTIME_MAX_SEC + 60), async {
        let read = (&mut stdout).take(limit).read_to_end(&mut reply).await;
        if reply.len() > max_reply {
            let _ = child.start_kill();
        }
        (read, child.wait().await)
    })
    .await;
    writer.abort();
    let tail = tokio::time::timeout(Duration::from_secs(5), tail)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let (read, status) = match waited {
        Ok(v) => v,
        Err(_) => {
            let _ = child.start_kill();
            return Ok(failed(format!(
                "{program} timed out after {RUNTIME_MAX_SEC} s"
            )));
        }
    };
    if reply.len() > max_reply {
        return Ok(failed(format!(
            "scan worker reply too large (over {max_reply} bytes)"
        )));
    }
    if let Err(e) = read {
        return Ok(failed(format!(
            "could not read the scan worker's reply: {e}"
        )));
    }
    let status = match status {
        Ok(s) => s,
        Err(e) => return Ok(failed(format!("could not wait for {program}: {e}"))),
    };
    if !status.success() {
        if systemd_unit.is_some_and(|u| reply.is_empty() && is_busy_message_for(u, &tail)) {
            return Ok(WorkerReply::Busy);
        }
        let said = if tail.is_empty() {
            String::new()
        } else {
            format!(": {tail}")
        };
        return Ok(failed(format!("scan worker ended with {status}{said}")));
    }
    // A worker stopped by SIGTERM leaves systemd with a clean status and nothing
    // written.
    if reply.is_empty() {
        return Ok(failed("scan worker ended with no reply".to_string()));
    }
    Ok(serde_json::from_slice::<WorkerReply>(&reply)
        .unwrap_or_else(|e| failed(format!("scan worker reply could not be read: {e}"))))
}

fn failed(msg: String) -> WorkerReply {
    WorkerReply::Failed(msg)
}

/// What `systemd-run` says when the fixed unit name is taken, on systemd 252:
/// `Failed to start transient service unit: Unit hyperion-sitescan.service was
/// already loaded or has a fragment file.` Only a line that starts that way
/// counts: stderr can also carry names a tenant chose.
#[cfg(test)]
fn is_busy_message(stderr: &str) -> bool {
    is_busy_message_for(UNIT_NAME, stderr)
}

fn is_busy_message_for(unit: &str, stderr: &str) -> bool {
    let head = format!("Failed to start transient service unit: Unit {unit}.service ");
    stderr
        .lines()
        .any(|l| l.starts_with(&head) && l.contains("already"))
}

/// What the worker process does, from stdin to stdout: the exit code. No async
/// runtime, no `agent.toml`, no network. Everything the agent needs to know is in
/// the reply; a non-zero exit means no reply can be trusted.
pub fn worker_main() -> i32 {
    let mut input = Vec::new();
    let read = std::io::stdin()
        .lock()
        .take(MAX_REPLY_BYTES as u64 + 1)
        .read_to_end(&mut input);
    let reply = match read {
        Err(e) => WorkerReply::Failed(format!("could not read the job: {e}")),
        Ok(_) if input.len() > MAX_REPLY_BYTES => {
            WorkerReply::Failed("the job was too large".to_string())
        }
        Ok(_) => match serde_json::from_slice::<WorkerJob>(&input) {
            Ok(job) => execute(job, &system_gate()),
            Err(e) => WorkerReply::Failed(format!("the job could not be read: {e}")),
        },
    };
    let mut out = match serde_json::to_vec(&reply) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("could not write the reply: {e}");
            return 1;
        }
    };
    if out.len() > MAX_REPLY_BYTES {
        out = serde_json::to_vec(&WorkerReply::Failed("the result was too large".to_string()))
            .unwrap_or_default();
    }
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(&out).and_then(|()| stdout.flush()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("could not write the reply: {e}");
            1
        }
    }
}

/// One job, run here.
pub fn execute(job: WorkerJob, pause: &dyn Fn() -> bool) -> WorkerReply {
    match job {
        WorkerJob::Discover { root } => match TenantRoot::open(&root) {
            Ok(r) => WorkerReply::Discovery(discover(&r)),
            Err(e) => WorkerReply::Failed(format!("could not open {}: {e}", root.display())),
        },
        WorkerJob::Scan(input) => match scan_site(&input, pause) {
            Ok(outcome) => WorkerReply::Scan(outcome),
            Err(e) => WorkerReply::Failed(e.to_string()),
        },
        WorkerJob::WriterHash {
            root,
            kind,
            paths,
            out,
        } => match writer_hash(&root, kind, &paths, &out, pause) {
            Ok(h) => WorkerReply::Hashed {
                listed: h.listed,
                partial: h.partial,
            },
            Err(e) => WorkerReply::Failed(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::LazyLock;
    use tokio::sync::Mutex;

    /// Writing a script and executing it while another test forks can hit
    /// ETXTBSY, so tests that run scripts take turns.
    static SCRIPTS: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn script(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("worker.sh");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        p
    }

    fn job() -> WorkerJob {
        WorkerJob::Discover {
            root: PathBuf::from("/nowhere"),
        }
    }

    /// The unit names these in `ReadWritePaths` and `ReadOnlyPaths`: if one is
    /// missing it exits 226 before the worker starts.
    #[test]
    fn scan_dirs_exist_and_are_root_only() {
        let t = tempfile::tempdir().expect("tmp");
        let base = t.path().join("hyperion/scan");
        prepare_scan_dirs(&base).expect("prepare");
        for d in [
            &base,
            &base.join("manifests"),
            &base.join("baselines"),
            &base.join("accepted"),
        ] {
            let mode = std::fs::metadata(d).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", d.display());
        }
        // Again, over a directory something widened: put back, contents kept.
        std::fs::set_permissions(
            base.join("baselines"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("chmod");
        std::fs::write(base.join("baselines/site"), b"x").expect("write");
        prepare_scan_dirs(&base).expect("prepare again");
        let mode = std::fs::metadata(base.join("baselines"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(base.join("baselines/site").exists());
    }

    /// `current_exe` after an update names the replaced file: the new binary is
    /// at the path without the suffix, and the old one can't be started by name.
    #[test]
    fn a_replaced_binary_resolves_to_its_path() {
        assert_eq!(
            strip_deleted_suffix(PathBuf::from("/usr/bin/hyperion-agent (deleted)")),
            PathBuf::from("/usr/bin/hyperion-agent")
        );
        assert_eq!(
            strip_deleted_suffix(PathBuf::from("/usr/bin/hyperion-agent")),
            PathBuf::from("/usr/bin/hyperion-agent")
        );
    }

    fn arg_after(args: &[String], prop: &str) -> Option<String> {
        args.windows(2)
            .find(|w| w[0] == "-p" && w[1].starts_with(&format!("{prop}=")))
            .map(|w| w[1].clone())
    }

    const BUSY_LINE: &str = "Failed to start transient service unit: Unit hyperion-sitescan.service was already loaded or has a fragment file.";

    /// The hash of a writer's files has its own unit, so it isn't held behind a scan
    /// of hours, and the same caps.
    #[test]
    fn the_hash_runs_in_its_own_capped_unit() {
        let exe = Path::new("/usr/local/bin/hyperion-agent");
        let hash = WorkerJob::WriterHash {
            root: PathBuf::from("/x"),
            kind: WriterKind::Restore,
            paths: WriterPaths::All,
            out: PathBuf::from("/y"),
        };
        assert_eq!(hash.unit(), "hyperion-sitescan-accept");
        assert_eq!(job().unit(), UNIT_NAME);
        let a = unit_args_for(hash.unit(), 4, exe);
        let b = unit_args(4, exe);
        assert!(a.iter().any(|x| x == "--unit=hyperion-sitescan-accept"));
        assert!(!a.iter().any(|x| x == "--unit=hyperion-sitescan"));
        assert_eq!(a[1..], b[1..], "same caps, only the name differs");
        // Busy means its own unit was taken, not the scan's.
        let line = "Failed to start transient service unit: Unit hyperion-sitescan-accept.service was already loaded or has a fragment file.";
        assert!(is_busy_message_for(ACCEPT_UNIT_NAME, line));
        assert!(!is_busy_message_for(UNIT_NAME, line));
    }

    #[test]
    fn unit_args_contain_every_cap() {
        let a = unit_args(4, Path::new("/usr/local/bin/hyperion-agent"));
        // Not quiet: on a failure stderr says why (oom-kill, ...).
        assert!(!a.iter().any(|x| x == "--quiet"), "{a:?}");
        for flag in ["--unit=hyperion-sitescan", "--wait", "--pipe", "--collect"] {
            assert!(a.iter().any(|x| x == flag), "{flag}: {a:?}");
        }
        for prop in [
            "MemoryMax=256M",
            "CPUWeight=10",
            "IOWeight=10",
            "Nice=19",
            "IOSchedulingClass=idle",
            "CPUQuota=100%",
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
            "NoNewPrivileges=yes",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "ReadWritePaths=/var/lib/hyperion/scan",
            "ReadOnlyPaths=/home /var/lib/hyperion/scan/manifests",
            "RuntimeMaxSec=21600",
            "PrivateDevices=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
            "ProtectControlGroups=yes",
            "ProtectClock=yes",
            "RestrictNamespaces=yes",
            "LockPersonality=yes",
            "RestrictSUIDSGID=yes",
            "SystemCallArchitectures=native",
            "MemorySwapMax=0",
            "ReadOnlyPaths=/run",
            "SystemCallFilter=@system-service",
            "SystemCallFilter=~@privileged @mount @debug @raw-io @reboot @swap @module @network-io kill tkill tgkill pidfd_send_signal",
        ] {
            assert!(
                a.windows(2).any(|w| w[0] == "-p" && w[1] == prop),
                "{prop}: {a:?}"
            );
        }
        // Both rejected by systemd-run 252 or fatal to the unit.
        assert!(!a.iter().any(|x| x.starts_with("RestrictAddressFamilies=")));
        assert!(!a.iter().any(|x| x.starts_with("InaccessiblePaths=")));
        // Properties come before the program, and the program is last.
        let n = a.len();
        assert_eq!(a[n - 2], "/usr/local/bin/hyperion-agent");
        assert_eq!(a[n - 1], "scan-worker");
        let first_prog = a.iter().position(|x| x.starts_with('/')).expect("prog");
        assert!(a[..first_prog].iter().filter(|x| *x == "-p").count() >= 27);
    }

    #[test]
    fn cpu_quota_is_50_on_two_cores_100_on_eight() {
        let exe = Path::new("/x");
        assert_eq!(
            arg_after(&unit_args(1, exe), "CPUQuota").as_deref(),
            Some("CPUQuota=50%")
        );
        assert_eq!(
            arg_after(&unit_args(2, exe), "CPUQuota").as_deref(),
            Some("CPUQuota=50%")
        );
        assert_eq!(
            arg_after(&unit_args(3, exe), "CPUQuota").as_deref(),
            Some("CPUQuota=100%")
        );
        assert_eq!(
            arg_after(&unit_args(8, exe), "CPUQuota").as_deref(),
            Some("CPUQuota=100%")
        );
    }

    #[test]
    fn the_reply_types_round_trip() {
        for r in [
            WorkerReply::Busy,
            WorkerReply::Failed("no".into()),
            WorkerReply::Discovery(Discovery::default()),
            WorkerReply::Scan(SiteScanOutcome::default()),
        ] {
            let text = serde_json::to_string(&r).expect("ser");
            assert_eq!(serde_json::from_str::<WorkerReply>(&text).expect("de"), r);
        }
    }

    #[test]
    fn a_busy_unit_is_told_from_any_other_failure() {
        assert!(is_busy_message(BUSY_LINE));
        assert!(is_busy_message(&format!("some noise\n{BUSY_LINE}\n")));
        assert!(!is_busy_message("Failed to connect to bus: No such file"));
        assert!(!is_busy_message(
            "Failed to start transient service unit: Unit other.service was already loaded"
        ));
        // Names a tenant chose can end up on stderr; only systemd-run's own
        // line at the start of a line counts.
        assert!(!is_busy_message(
            "/home/x/Unit hyperion-sitescan.service already exists."
        ));
        assert!(!is_busy_message(&format!("path: {BUSY_LINE}")));
    }

    async fn under_systemd(body: &str) -> WorkerReply {
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        let fake = script(t.path(), body);
        run_child(Command::new(fake), &job(), MAX_REPLY_BYTES, Some(UNIT_NAME))
            .await
            .expect("run")
    }

    #[tokio::test]
    async fn a_taken_unit_name_is_busy_only_under_systemd_and_with_no_reply() {
        let line = format!("echo '{BUSY_LINE}' >&2");
        assert_eq!(
            under_systemd(&format!("{line}; exit 1")).await,
            WorkerReply::Busy
        );
        // A reply on stdout beats the message on stderr.
        let r = under_systemd(&format!("echo '\"Busy\"'; {line}; exit 1")).await;
        assert!(matches!(r, WorkerReply::Failed(_)), "{r:?}");
        // The same text from a run that did not fail is not Busy.
        let r = under_systemd(&format!("{line}; echo '{{\"Failed\":\"x\"}}'")).await;
        assert_eq!(r, WorkerReply::Failed("x".into()));
        // Other systemd-run failures are Failed and say why.
        let WorkerReply::Failed(why) =
            under_systemd("echo 'Failed to connect to bus' >&2; exit 1").await
        else {
            panic!("not busy");
        };
        assert!(why.contains("Failed to connect to bus"), "{why}");
        // Same stderr without systemd is a plain failure.
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        let fake = script(t.path(), &format!("{line}; exit 1"));
        let r = run_child(Command::new(fake), &job(), MAX_REPLY_BYTES, None)
            .await
            .expect("run");
        assert!(matches!(r, WorkerReply::Failed(_)), "{r:?}");
    }

    #[tokio::test]
    async fn a_worker_ended_with_no_reply_is_failed_saying_so() {
        // SIGTERM to a unit's main process leaves systemd-run exiting 0.
        let WorkerReply::Failed(why) = under_systemd("exit 0").await else {
            panic!("an empty stdout is not a result");
        };
        assert!(why.contains("no reply"), "{why}");
    }

    #[tokio::test]
    async fn worker_reply_is_passed_through() {
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        let exe = script(t.path(), r#"cat >/dev/null; echo '{"Failed":"nope"}'"#);
        let r = run_direct(&job(), &exe, MAX_REPLY_BYTES)
            .await
            .expect("run");
        assert_eq!(r, WorkerReply::Failed("nope".into()));
    }

    #[tokio::test]
    async fn killed_worker_is_failed_not_clean() {
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        let exe = script(t.path(), "kill -9 $$");
        let WorkerReply::Failed(why) = run_direct(&job(), &exe, MAX_REPLY_BYTES)
            .await
            .expect("run")
        else {
            panic!("a killed worker must not look like a result");
        };
        assert!(why.contains("signal: 9"), "{why}");
    }

    #[tokio::test]
    async fn a_failing_worker_is_failed_with_status_and_stderr() {
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        let exe = script(t.path(), "echo boom >&2; exit 3");
        let WorkerReply::Failed(why) = run_direct(&job(), &exe, MAX_REPLY_BYTES)
            .await
            .expect("run")
        else {
            panic!("exit 3 is not a result");
        };
        assert!(
            why.contains("exit status: 3") && why.contains("boom"),
            "{why}"
        );
    }

    #[tokio::test]
    async fn a_bad_exit_wins_over_a_reply() {
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        let exe = script(t.path(), r#"echo '"Busy"'; exit 1"#);
        let r = run_direct(&job(), &exe, MAX_REPLY_BYTES)
            .await
            .expect("run");
        assert!(matches!(r, WorkerReply::Failed(_)), "{r:?}");
    }

    #[tokio::test]
    async fn unparsable_or_empty_reply_is_failed() {
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        for body in ["echo not json", "true", r#"echo '{"Scan": 5}'"#] {
            let exe = script(t.path(), body);
            let r = run_direct(&job(), &exe, MAX_REPLY_BYTES)
                .await
                .expect("run");
            assert!(matches!(r, WorkerReply::Failed(_)), "{body}: {r:?}");
        }
    }

    #[tokio::test]
    async fn oversized_reply_is_refused() {
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        // Ten times the cap, and the worker would go on forever.
        let exe = script(t.path(), "exec yes '{\"Failed\":\"x\"}'");
        let WorkerReply::Failed(why) = run_direct(&job(), &exe, 10_000).await.expect("run") else {
            panic!("an oversized reply must be refused");
        };
        assert!(why.contains("too large"), "{why}");
    }

    #[tokio::test]
    async fn a_worker_that_never_reads_its_job_does_not_hang_or_error() {
        let _g = SCRIPTS.lock().await;
        let t = tempfile::tempdir().expect("tmp");
        let exe = script(t.path(), r#"echo '"Busy"'"#);
        // A job far bigger than a pipe buffer.
        let big = WorkerJob::Discover {
            root: PathBuf::from("/".to_string() + &"a".repeat(1 << 20)),
        };
        let r = run_direct(&big, &exe, MAX_REPLY_BYTES).await.expect("run");
        assert_eq!(r, WorkerReply::Busy);
    }

    #[tokio::test]
    async fn a_missing_program_is_failed_naming_it() {
        let WorkerReply::Failed(why) = run_direct(&job(), Path::new("/no/such/agent"), 1024)
            .await
            .expect("run")
        else {
            panic!("could not start is a failure");
        };
        assert!(
            why.contains("/no/such/agent") || why.contains("nice"),
            "{why}"
        );
    }

    #[test]
    fn execute_discovers_a_docroot_and_fails_a_bad_one() {
        let t = tempfile::tempdir().expect("tmp");
        let root = t.path().canonicalize().expect("canonical");
        std::fs::create_dir_all(root.join("wp-includes")).expect("mkdir");
        let r = execute(WorkerJob::Discover { root: root.clone() }, &|| false);
        let WorkerReply::Discovery(d) = r else {
            panic!("{r:?}");
        };
        assert!(d.is_wordpress);
        let r = execute(
            WorkerJob::Discover {
                root: root.join("missing"),
            },
            &|| false,
        );
        assert!(matches!(r, WorkerReply::Failed(_)), "{r:?}");
        let r = execute(
            WorkerJob::Discover {
                root: PathBuf::from("relative"),
            },
            &|| false,
        );
        assert!(matches!(r, WorkerReply::Failed(_)), "{r:?}");
    }
}
