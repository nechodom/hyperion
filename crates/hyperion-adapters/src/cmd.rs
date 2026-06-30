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
