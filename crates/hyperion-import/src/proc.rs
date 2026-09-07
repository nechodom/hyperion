//! Spawning a command that might never come back.
//!
//! Everything this crate runs on a source box goes through here, because every
//! one of them can hang: a `mysqldump --single-transaction` blocks on a metadata
//! lock, an `ssh` session dies without its TCP connection noticing, a `df`
//! touches an unresponsive network mount. Unbudgeted, any of those stops an
//! export forever — and since the run is DETACHED there is no terminal to
//! notice, so `--status` keeps rendering the same line and the operator's only
//! recourse is to find the pid and kill it by hand.
//!
//! The budgets themselves are NOT here: what a command may reasonably take is a
//! property of the command, so each caller names its own (see
//! [`crate::bundle`]'s budget block, and [`crate::adapter::READ_BUDGET`]).

use crate::error::ImportError;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// The command as it will be named in an error — Debug on the std command,
/// clipped. No credential reaches argv in this crate (they go through 0600
/// defaults-files and stdin), so this is safe to print.
fn shown(cmd: &Command) -> String {
    format!("{:?}", cmd.as_std()).chars().take(160).collect()
}

fn timed_out(what: &str, budget: Duration, cmd: &str) -> ImportError {
    ImportError::Timeout {
        what: what.to_string(),
        budget: crate::progress::human_secs(budget.as_secs() as i64),
        cmd: cmd.to_string(),
    }
}

/// Refuse to spawn under a budget an earlier attempt already spent, rather than
/// starting a command only to kill it in the same breath.
fn already_spent(what: &str, cmd: &str) -> ImportError {
    ImportError::Command {
        cmd: cmd.to_string(),
        msg: format!("not started: the budget for {what} was already spent"),
    }
}

/// Common spawn setup: no stdin (a detached run has no terminal to read from,
/// and a command that waits on one would hang forever), its own process group,
/// and a kill if the handle is dropped.
fn prime(cmd: &mut Command) {
    cmd.stdin(Stdio::null());
    #[cfg(unix)]
    cmd.process_group(0);
    cmd.kill_on_drop(true);
}

/// SIGKILL a whole process group.
///
/// The group, not the child, is what makes the kill complete. `sh -c "mysqldump
/// …"` execs the dump in place, so killing the direct child is enough there —
/// but `sudo -u postgres pg_dump …` is not: sudo cannot forward a SIGKILL it
/// never receives, so the dump would keep running, still holding its
/// transaction and still writing into a file we have already deleted.
///
/// Shelling out to `kill` keeps this crate free of `unsafe`/libc for one
/// syscall. It is belt to `kill_on_drop`'s braces: the direct child is already
/// dead by the time this runs (and un-reaped, so it still holds the group id),
/// and if `kill` is missing this simply adds nothing.
async fn kill_group(pid: Option<u32>) {
    let Some(pid) = pid else { return };
    let mut cmd = Command::new("kill");
    cmd.arg("-KILL")
        .arg(format!("-{pid}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // Budgeted like everything else here — not via [`capture`], which would call
    // back into this function. Dropping the future on expiry kills it.
    let _ = tokio::time::timeout(Duration::from_secs(10), cmd.status()).await;
}

/// Spawn `cmd` under `budget` and collect its output, or kill it — and
/// everything it started — once the budget is spent.
pub(crate) async fn capture(
    mut cmd: Command,
    budget: Duration,
    what: &str,
) -> Result<std::process::Output, ImportError> {
    let shown_cmd = shown(&cmd);
    if budget.is_zero() {
        return Err(already_spent(what, &shown_cmd));
    }
    prime(&mut cmd);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn()?;
    let pid = child.id();
    // `wait_with_output` consumes the child, so the pid is taken first: on
    // expiry the future is dropped (which SIGKILLs the child) and the pid is
    // all that is left to aim the group kill with.
    match tokio::time::timeout(budget, child.wait_with_output()).await {
        Ok(out) => Ok(out?),
        Err(_) => {
            kill_group(pid).await;
            Err(timed_out(what, budget, &shown_cmd))
        }
    }
}

/// Spawn `cmd` under `budget` for its exit status, draining stderr as it
/// arrives, and kill its process group once the budget is spent.
///
/// Draining CONCURRENTLY is not a nicety. An unread stderr pipe holds 64 KB and
/// then blocks the writer forever — a `mysqldump` that warns per table can reach
/// that on a large schema — which is the same invisible stall this module exists
/// to remove, arriving by a different route. [`capture`] gets this for free from
/// `wait_with_output`; a command writing its stdout to a file does not.
pub(crate) async fn wait_status(
    mut cmd: Command,
    budget: Duration,
    what: &str,
) -> Result<(std::process::ExitStatus, String), ImportError> {
    let shown_cmd = shown(&cmd);
    if budget.is_zero() {
        return Err(already_spent(what, &shown_cmd));
    }
    prime(&mut cmd);
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let pid = child.id();
    let mut pipe = child.stderr.take();
    let work = async {
        let mut head = String::new();
        if let Some(p) = pipe.as_mut() {
            head = drain(p).await;
        }
        (child.wait().await, head)
    };
    // Bound to a `let` first: the future borrows `child`, and a temporary in a
    // `match` scrutinee would keep that borrow alive across the arms.
    let outcome = tokio::time::timeout(budget, work).await;
    match outcome {
        Ok((status, head)) => Ok((status?, head)),
        Err(_) => {
            // The group first, while our own child is still un-reaped and
            // therefore still holds the group id; then reap it.
            kill_group(pid).await;
            let _ = child.kill().await;
            Err(timed_out(what, budget, &shown_cmd))
        }
    }
}

/// Read a child's stderr to EOF — so it can never block on a full pipe — while
/// keeping only the head of it for the error message.
async fn drain(pipe: &mut tokio::process::ChildStderr) -> String {
    use tokio::io::AsyncReadExt;
    const KEEP: usize = 8 * 1024;
    let mut kept: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    while let Ok(n) = pipe.read(&mut buf).await {
        if n == 0 {
            break;
        }
        let room = KEEP.saturating_sub(kept.len());
        if room > 0 {
            kept.extend_from_slice(&buf[..n.min(room)]);
        }
    }
    String::from_utf8_lossy(&kept).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::capture;
    use crate::error::ImportError;
    use std::time::Duration;

    /// [`capture`] kills by a different route than [`wait_status`]: it hands the
    /// child to `wait_with_output`, which consumes it, so the kill rides on
    /// `kill_on_drop` plus the group kill aimed at a pid taken beforehand. Worth
    /// its own test for that reason.
    ///
    /// The command backgrounds a grandchild, so this also pins down that the
    /// whole process GROUP dies — killing the direct child is not enough for an
    /// `ssh` or a `sudo` that has already forked.
    #[tokio::test]
    async fn a_captured_command_that_hangs_is_killed_with_its_whole_group() {
        let dir = tempfile::tempdir().expect("tmp");
        let late = dir.path().join("late");
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg(format!(
            "( sleep 3; : > {} ) & wait",
            crate::adapter::shell_quote(&late.display().to_string())
        ));

        let t0 = std::time::Instant::now();
        let err = capture(cmd, Duration::from_secs(1), "reading the source panel")
            .await
            .expect_err("a hung read must not be waited on forever");
        let waited = t0.elapsed();

        assert!(waited < Duration::from_secs(3), "gave up after {waited:?}");
        assert!(matches!(err, ImportError::Timeout { .. }), "{err}");
        assert!(
            err.to_string().contains("reading the source panel"),
            "the message must name the step: {err}"
        );

        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            !late.exists(),
            "the process group outlived its budget: a killed `ssh`/`sudo` leaves \
             its grandchildren running"
        );
    }
}
