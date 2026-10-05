//! The node update job — operating-system upgrade and/or Hyperion's own
//! `update.sh` — run as a transient systemd unit, outside the agent.
//!
//! # Why not a child process of the agent
//!
//! It used to be one, and that broke both halves of the job:
//!
//! * **The OS upgrade inherited the agent's sandbox.** `ProtectKernelModules`
//!   hides `/lib/modules` and `ProtectSystem` mounts `/boot` read-only, so a
//!   kernel package died in its preinst (`mkdir: cannot create directory
//!   '/lib/modules/…': Read-only file system`) and left dpkg half-configured —
//!   on a machine whose own shell showed every filesystem writable.
//! * **`update.sh` killed itself.** It stops `hyperion-agent`, and stopping a
//!   unit kills its whole cgroup — the script included.
//!
//! `systemd-run` starts the runner as `hyperion-node-update.service`: no
//! sandbox, its own cgroup, alive across an agent restart. Because the agent
//! may restart mid-job (update.sh does exactly that), nothing about the job is
//! kept in agent memory. It is all on disk:
//!
//! * `job.json` — what was asked for and when, written before the start;
//! * the log file the unit's stdout/stderr append to;
//! * `result` — `<exit code> <finished unix>`, written by the runner's EXIT
//!   trap. Unit gone and no result = the run was killed (a reboot).

use crate::AdapterError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// The runner. An asset rather than a format! string so CI can `bash -n` it.
const RUNNER: &str = include_str!("../assets/node-update.sh");

/// Fixed, so "is an update running" is one `systemctl show` and two updates
/// can never run at once — systemd refuses a second unit of the same name.
pub const UNIT: &str = "hyperion-node-update.service";

const JOB_DIR: &str = "/var/lib/hyperion/node-update";
/// Under the agent's `LogsDirectory`, next to its own logs.
const LOG_FILE: &str = "/var/log/hyperion/node-update.log";

/// What the panel shows of the log. A kernel upgrade prints a lot; the tail is
/// where the answer is.
const LOG_TAIL_BYTES: u64 = 16 * 1024;

/// What was asked for, persisted when the job starts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobSpec {
    pub started_at: i64,
    pub do_apt: bool,
    pub do_hyperion: bool,
    pub safe: bool,
}

/// Where a job stands, read back from disk and systemd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    /// No job has ever been started on this node.
    Never,
    Running,
    Finished {
        exit_code: i32,
        finished_at: i64,
    },
    /// The unit is gone and left no result: killed before it could write one
    /// (reboot, OOM, `systemctl kill`). dpkg may be mid-way; the next run
    /// repairs that first.
    Interrupted,
}

#[derive(Debug, Clone)]
pub struct JobStatus {
    pub spec: Option<JobSpec>,
    pub state: JobState,
    pub log_tail: String,
}

fn job_dir() -> PathBuf {
    PathBuf::from(JOB_DIR)
}

/// Is the update unit running right now?
///
/// `activating`/`deactivating` count: the unit exists and owns the dpkg lock
/// (or is about to). Anything that cannot be asked counts as NOT running —
/// a node without systemd cannot have started one.
pub async fn is_running() -> bool {
    let Ok(out) = Command::new("/usr/bin/systemctl")
        .args(["show", "-p", "ActiveState", "--value", UNIT])
        .output()
        .await
    else {
        return false;
    };
    unit_state_is_running(String::from_utf8_lossy(&out.stdout).trim())
}

fn unit_state_is_running(active_state: &str) -> bool {
    matches!(
        active_state,
        "active" | "activating" | "deactivating" | "reloading"
    )
}

/// Parse the runner's `result` file: `<exit code> <finished unix>`.
pub fn parse_result(s: &str) -> Option<(i32, i64)> {
    let mut it = s.split_whitespace();
    let code = it.next()?.parse().ok()?;
    let at = it.next()?.parse().ok()?;
    Some((code, at))
}

/// Start a job. The caller checks [`is_running`] first for a friendly error;
/// systemd's refusal of a duplicate unit name is the real guard.
pub async fn start(spec: &JobSpec) -> Result<(), AdapterError> {
    let dir = job_dir();
    create_private_dir(&dir).await?;

    let runner = dir.join("runner.sh");
    write_private(&runner, RUNNER.as_bytes()).await?;
    // The previous run's result must not be read as this one's.
    match tokio::fs::remove_file(dir.join("result")).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if let Some(parent) = Path::new(LOG_FILE).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(LOG_FILE, b"").await?;
    let spec_json =
        serde_json::to_vec(spec).map_err(|e| AdapterError::Other(format!("job spec: {e}")))?;
    write_private(&dir.join("job.json"), &spec_json).await?;

    let flag = |b: bool| if b { "1" } else { "0" };
    let out = Command::new("/usr/bin/systemd-run")
        .arg(format!("--unit={UNIT}"))
        .arg("--description=Hyperion node update")
        // Garbage-collect the unit when it ends, failed or not, so the next
        // run can reuse the name. The outcome lives in `result`, not in the
        // unit.
        .arg("--collect")
        .args(["-p", "Type=exec"])
        .args(["-p", &format!("StandardOutput=append:{LOG_FILE}")])
        .args(["-p", &format!("StandardError=append:{LOG_FILE}")])
        .arg(format!("--setenv=HYP_DO_APT={}", flag(spec.do_apt)))
        .arg(format!(
            "--setenv=HYP_DO_HYPERION={}",
            flag(spec.do_hyperion)
        ))
        .arg(format!("--setenv=HYP_SAFE={}", flag(spec.safe)))
        .arg(format!("--setenv=HYP_JOB_DIR={}", dir.display()))
        .arg("/bin/bash")
        .arg(&runner)
        .output()
        .await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        // Leave a result behind so the panel shows a failed run with the
        // reason, not a run that never ended.
        let _ = tokio::fs::write(LOG_FILE, format!("could not start {UNIT}: {stderr}\n")).await;
        let _ = write_private(
            &dir.join("result"),
            format!("127 {}\n", spec.started_at).as_bytes(),
        )
        .await;
        return Err(AdapterError::Command {
            cmd: "systemd-run".into(),
            code: out.status.code().unwrap_or(-1),
            stderr_tail: stderr,
        });
    }
    Ok(())
}

/// Read the current (or last) job back.
pub async fn status() -> JobStatus {
    let dir = job_dir();
    let spec: Option<JobSpec> = tokio::fs::read(dir.join("job.json"))
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let log_tail = read_tail(Path::new(LOG_FILE), LOG_TAIL_BYTES)
        .await
        .unwrap_or_default();
    if spec.is_none() {
        return JobStatus {
            spec,
            state: JobState::Never,
            log_tail,
        };
    }
    // The result is written before the runner exits, so it is checked
    // first: a finished run is finished even while systemd tears down.
    let result = tokio::fs::read_to_string(dir.join("result"))
        .await
        .ok()
        .and_then(|s| parse_result(&s));
    let state = match result {
        Some((exit_code, finished_at)) => JobState::Finished {
            exit_code,
            finished_at,
        },
        None if is_running().await => JobState::Running,
        None => JobState::Interrupted,
    };
    JobStatus {
        spec,
        state,
        log_tail,
    }
}

async fn create_private_dir(dir: &Path) -> Result<(), AdapterError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::create_dir_all(dir).await?;
    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

/// Write a root-only file via a temp name + rename, so systemd never execs a
/// half-written runner.
async fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AdapterError> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// The last `max` bytes of a file, cut forward to a line start so the panel
/// never shows half a line (or half a UTF-8 character).
async fn read_tail(path: &Path, max: u64) -> std::io::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = tokio::fs::File::open(path).await?;
    let len = f.metadata().await?.len();
    let from = len.saturating_sub(max);
    f.seek(std::io::SeekFrom::Start(from)).await?;
    let mut buf = Vec::with_capacity((len - from) as usize);
    f.read_to_end(&mut buf).await?;
    Ok(tail_from_line_start(&buf, from > 0))
}

fn tail_from_line_start(buf: &[u8], cut: bool) -> String {
    let start = if cut {
        buf.iter().position(|&b| b == b'\n').map_or(0, |i| i + 1)
    } else {
        0
    };
    String::from_utf8_lossy(&buf[start..]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_parses_code_and_time() {
        assert_eq!(parse_result("0 1759651200\n"), Some((0, 1_759_651_200)));
        assert_eq!(parse_result("100 5"), Some((100, 5)));
        assert_eq!(parse_result(""), None);
        assert_eq!(parse_result("0"), None);
        assert_eq!(parse_result("x 5"), None);
    }

    #[test]
    fn running_states() {
        assert!(unit_state_is_running("active"));
        assert!(unit_state_is_running("activating"));
        assert!(unit_state_is_running("deactivating"));
        assert!(!unit_state_is_running("inactive"));
        assert!(!unit_state_is_running("failed"));
        // `systemctl show` of a unit that never existed.
        assert!(!unit_state_is_running(""));
    }

    #[test]
    fn tail_drops_the_partial_first_line_only_when_cut() {
        assert_eq!(tail_from_line_start(b"abc\ndef\n", true), "def\n");
        assert_eq!(tail_from_line_start(b"abc\ndef\n", false), "abc\ndef\n");
        // No newline at all in the window: keep it rather than show nothing.
        assert_eq!(tail_from_line_start(b"abcdef", true), "abcdef");
    }

    #[tokio::test]
    async fn tail_of_a_long_file_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("log");
        let body: String = (0..2000).map(|i| format!("line {i}\n")).collect();
        tokio::fs::write(&p, &body).await.unwrap();
        let t = read_tail(&p, 100).await.unwrap();
        assert!(t.len() <= 100);
        assert!(t.starts_with("line "));
        assert!(t.ends_with("line 1999\n"));
    }

    #[test]
    fn runner_is_the_asset() {
        // The unit runs bash on this; a stray format!-style brace or a lost
        // shebang-less header would only show up on a real node.
        assert!(RUNNER.contains("upgrade --with-new-pkgs"));
        assert!(RUNNER.contains("trap finish EXIT"));
        assert!(!RUNNER.contains("dist-upgrade -y"));
    }
}
