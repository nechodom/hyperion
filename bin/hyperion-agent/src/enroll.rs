//! Node-side enrollment with the master.
//!
//! On first boot of an enrollment-configured agent we POST
//! `master_url/api/enroll` with `{token, label, agent_version, public_ip}`,
//! receive back `{node_id, master_url}`, persist it, and stop.
//! Subsequent boots see the state file and skip enrollment.
//!
//! TLS note: the master defaults to a self-signed cert (install-
//! master.sh does NOT provision a real LE cert because at install
//! time the master often has no DNS yet). The node has no trust
//! anchor — chicken-egg — so the enrollment + heartbeat curls use
//! `-k` (skip TLS verification). The bearer token + per-node secret
//! ARE the authentication; TLS here is just encryption-in-transit.
//! Operators with a real LE cert on the master can flip
//! `verify_tls = true` in agent.toml to enforce verification.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct EnrollmentConfig {
    pub master_url: String,
    pub token: String,
    pub label: String,
    pub state_file: PathBuf,
    /// When `false`, curl uses `-k` (skip TLS verification) — the
    /// default because the master usually has a self-signed cert
    /// and there's no trust anchor on the node yet. Flip to `true`
    /// when the master serves a real LE cert.
    pub verify_tls: bool,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    token: &'a str,
    label: &'a str,
    agent_version: &'a str,
    public_ip: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct EnrollResponse {
    node_id: String,
    master_url: String,
    secret: String,
}

#[derive(Deserialize, Serialize)]
pub struct PersistedNodeId {
    pub node_id: String,
    pub master_url: String,
    #[serde(default)]
    pub secret: String,
    pub enrolled_at: i64,
}

/// Load the persisted node identity if present.
pub async fn load_persisted(path: &std::path::Path) -> Option<PersistedNodeId> {
    let bytes = tokio::fs::read(path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub async fn ensure_enrolled(cfg: EnrollmentConfig) -> Result<(), String> {
    if cfg.state_file.exists() {
        tracing::debug!(path=%cfg.state_file.display(), "node already enrolled, skipping");
        return Ok(());
    }
    // Don't hammer the master if it's unreachable on first boot — give
    // it 10s to settle (relevant when both come up in parallel).
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    enroll_with_retry(&cfg).await
}

/// Try `enroll_now` up to 5 times with growing backoff. Bridges the
/// gap when the master is briefly unreachable (boot order, firewall
/// rule landing late, transient DNS, etc.) without permanently
/// stalling enrollment until the next reboot.
///
/// Backoff schedule: 0s, 20s, 60s, 180s, 300s (total ~9 minutes).
/// Past that the operator's network is probably broken; we log a
/// loud warning with the manual-retry command.
pub async fn enroll_with_retry(cfg: &EnrollmentConfig) -> Result<(), String> {
    const DELAYS_SECS: &[u64] = &[0, 20, 60, 180, 300];
    let mut last_err = String::new();
    for (attempt, delay) in DELAYS_SECS.iter().enumerate() {
        if *delay > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(*delay)).await;
        }
        match enroll_now(cfg).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(
                    attempt = attempt + 1,
                    of = DELAYS_SECS.len(),
                    error = %e,
                    "enrollment attempt failed — will retry"
                );
                last_err = e;
            }
        }
    }
    Err(format!(
        "{}\n→ {} attempts exhausted. Retry manually with: \
         sudo rm -f /etc/hyperion/node-id.json && sudo systemctl restart hyperion-agent",
        last_err,
        DELAYS_SECS.len()
    ))
}

/// Immediate, no-delay enrollment attempt. Used by `hctl enroll`.
/// Auto-tries the http URL as https on transient TLS errors — covers
/// the common case where the operator pasted http:// but the master
/// listens on https only.
pub async fn enroll_now(cfg: &EnrollmentConfig) -> Result<(), String> {
    let agent_version = env!("CARGO_PKG_VERSION");
    let public_ip = fetch_public_ip().await;
    let base = cfg.master_url.trim_end_matches('/').to_string();
    let body = serde_json::to_string(&EnrollRequest {
        token: &cfg.token,
        label: &cfg.label,
        agent_version,
        public_ip,
    })
    .map_err(|e| format!("serialize: {e}"))?;

    // Try the URL the operator gave us first. On TLS-shaped errors
    // (empty reply, "wrong version number") AND the URL is http://,
    // retry as https:// — that's the very common "master is HTTPS
    // but operator copy-pasted http:" trap.
    tracing::info!(master = %base, "attempting node enrollment");
    let primary_url = format!("{base}/api/enroll");
    match post_json(&primary_url, &body, cfg.verify_tls).await {
        Ok(stdout) => return finish_enrollment(cfg, &stdout).await,
        Err(e) if should_try_https_fallback(&base, &e) => {
            let https = format!("https://{}/api/enroll", &base[7..]);
            tracing::warn!(
                error = %e,
                "enrollment over {base} failed — retrying with https://"
            );
            let stdout = post_json(&https, &body, cfg.verify_tls).await?;
            // Persist the discovered scheme so subsequent heartbeats
            // skip the fallback dance.
            let mut adjusted = cfg.clone();
            adjusted.master_url = format!("https://{}", &base[7..]);
            return finish_enrollment(&adjusted, &stdout).await;
        }
        Err(e) => return Err(e),
    }
}

/// Helper: POST JSON, return stdout on HTTP 2xx or a useful error
/// string. `verify_tls=false` adds `-k` (chicken-egg: until we've
/// enrolled we have no trust anchor for the master's cert).
///
/// Body is fed via curl's stdin (`--data-binary @-`), NOT via argv.
/// The previous `--data <body>` approach put the invite token (on
/// enrollment) and the per-node bearer secret (on every heartbeat)
/// onto curl's command line, visible to any local user via
/// `/proc/<pid>/cmdline` for the lifetime of the subprocess.
async fn post_json(url: &str, body: &str, verify_tls: bool) -> Result<Vec<u8>, String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut args: Vec<&str> = vec!["-fsS", "--max-time", "15"];
    if !verify_tls {
        args.push("-k");
    }
    args.extend([
        "-X", "POST",
        "-H", "content-type: application/json",
        "--data-binary", "@-",
        url,
    ]);
    let mut child = tokio::process::Command::new("/usr/bin/curl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl spawn: {e}"))?;

    // Write body to stdin then close. Curl reads it as the POST body.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(body.as_bytes())
            .await
            .map_err(|e| format!("curl stdin write: {e}"))?;
        stdin.shutdown().await.ok();
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("curl wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "POST {url} exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Decide whether to retry an http:// URL as https://. We only do
/// this when the URL is http:// AND the error looks TLS-shaped.
/// Curl reports the same root cause ("server sent TLS handshake
/// bytes when I asked HTTP") under several different exit codes
/// depending on version and which buffer it caught first:
///
///   - 1   `CURLE_UNSUPPORTED_PROTOCOL` — typical for newer curl
///         which trims "HTTP/0.9" responses as invalid (the TLS
///         handshake bytes look like a malformed HTTP/0.9 reply).
///         Stderr: "Received HTTP/0.9 when not allowed".
///   - 35  `CURLE_SSL_CONNECT_ERROR` — TLS handshake failure (rare
///         in the http→https mistake, more on https→bad-cert).
///   - 52  `CURLE_GOT_NOTHING` — server closed after seeing
///         garbage. Classic on older curl + nginx.
///   - 56  `CURLE_RECV_ERROR` — connection reset during the read.
///
/// We also match stderr substrings as a belt-and-suspenders since
/// curl exit codes sometimes shift between distro versions.
fn should_try_https_fallback(base: &str, err: &str) -> bool {
    if !base.starts_with("http://") {
        return false;
    }
    let e = err.to_ascii_lowercase();
    // Exit-code matches.
    if e.contains("exit some(1)")
        || e.contains("exit some(35)")
        || e.contains("exit some(52)")
        || e.contains("exit some(56)")
    {
        return true;
    }
    // Substring matches — covers cases where the exit code is
    // different but the message is unambiguous.
    e.contains("http/0.9")
        || e.contains("empty reply from server")
        || e.contains("wrong version number")
        || e.contains("ssl routines")
        || e.contains("alert handshake")
        || e.contains("recv failure")
}

async fn finish_enrollment(cfg: &EnrollmentConfig, stdout: &[u8]) -> Result<(), String> {
    let resp: EnrollResponse = serde_json::from_slice(stdout)
        .map_err(|e| format!("parse response: {e} (raw: {})", String::from_utf8_lossy(stdout)))?;
    // Persist the OPERATOR-supplied master_url (cfg.master_url), NOT
    // the URL returned in the enrollment response. The master is
    // happy to tell us "I'm at https://attacker.example" if a MITM
    // is in flight during the first enrollment; trusting that value
    // would pin every future heartbeat to the attacker. The operator
    // typed the master URL in install-node.sh — that's the trust
    // anchor.
    //
    // If enroll_now's http→https fallback fired, cfg has already been
    // adjusted to point at the working URL — so we still capture that
    // upgrade without trusting the response.
    let _server_suggested_url = resp.master_url; // discarded by design.

    // Persist node_id so future boots skip enrollment. Atomic write:
    // tmp → chmod 0600 → rename. Without this the file briefly exists
    // at the default umask (0o644) between `write` and
    // `set_permissions`.
    if let Some(parent) = cfg.state_file.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let persisted = PersistedNodeId {
        node_id: resp.node_id.clone(),
        master_url: cfg.master_url.clone(),
        secret: resp.secret.clone(),
        enrolled_at: chrono::Utc::now().timestamp(),
    };
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|e| format!("serialize persisted: {e}"))?;
    let tmp = cfg.state_file.with_extension("json.tmp");
    tokio::fs::write(&tmp, &bytes)
        .await
        .map_err(|e| format!("write tmp {}: {e}", tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await;
    tokio::fs::rename(&tmp, &cfg.state_file)
        .await
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), cfg.state_file.display()))?;
    tracing::info!(node_id=%resp.node_id, master=%cfg.master_url, "node enrolled");
    Ok(())
}

/// Background heartbeat loop. Reads the persisted node-id file every
/// `period_secs` and POSTs {node_id, secret, agent_version} to
/// `<master>/api/heartbeat`. Single error → log + retry next tick.
///
/// `verify_tls` mirrors `EnrollmentConfig::verify_tls` — default
/// off so self-signed master certs work. The bearer secret is the
/// auth; TLS is just encryption-in-transit.
pub async fn heartbeat_loop(state_file: std::path::PathBuf, period_secs: u64, verify_tls: bool) {
    let agent_version = env!("CARGO_PKG_VERSION");
    let period = std::time::Duration::from_secs(period_secs);
    let mut interval = tokio::time::interval(period);
    // First tick fires immediately — skip it so we wait one period after
    // enrollment before phoning home.
    interval.tick().await;
    loop {
        interval.tick().await;
        let p = match load_persisted(&state_file).await {
            Some(p) if !p.secret.is_empty() => p,
            _ => continue, // not enrolled yet, or pre-secret deploy
        };
        let url = format!("{}/api/heartbeat", p.master_url.trim_end_matches('/'));
        let body = match serde_json::to_string(&serde_json::json!({
            "node_id": p.node_id,
            "secret": p.secret,
            "agent_version": agent_version,
        })) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error=%e, "heartbeat serialize");
                continue;
            }
        };
        // Body via stdin, NOT argv — see post_json comment. The
        // heartbeat carries the per-node bearer secret on every
        // tick; argv would leak it to /proc/<pid>/cmdline.
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        let mut args: Vec<&str> = vec!["-fsS", "--max-time", "8"];
        if !verify_tls {
            args.push("-k");
        }
        args.extend([
            "-X", "POST",
            "-H", "content-type: application/json",
            "--data-binary", "@-",
            &url,
        ]);
        let mut child = match tokio::process::Command::new("/usr/bin/curl")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error=%e, "heartbeat curl spawn failed");
                continue;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(body.as_bytes()).await {
                tracing::warn!(error=%e, "heartbeat stdin write");
                continue;
            }
            stdin.shutdown().await.ok();
        }
        let result = child.wait_with_output().await;
        match result {
            Ok(out) if out.status.success() => {
                tracing::debug!(node = %p.node_id, master = %p.master_url, "heartbeat ok");
            }
            Ok(out) => {
                tracing::warn!(
                    code = ?out.status.code(),
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    master = %p.master_url,
                    "heartbeat returned non-zero — will retry"
                );
            }
            Err(e) => tracing::warn!(error=%e, "heartbeat curl failed"),
        }
    }
}

async fn fetch_public_ip() -> Option<String> {
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args(["-fsS", "--max-time", "4", "https://api.ipify.org"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_fallback_triggers_on_tls_signature_errors() {
        // Exit 1 + "HTTP/0.9" — the case the user actually hit on
        // stav.pur.cz with newer curl. Server sent TLS handshake
        // bytes; curl tagged them as "Received HTTP/0.9 when not
        // allowed" and exited with CURLE_UNSUPPORTED_PROTOCOL.
        assert!(should_try_https_fallback(
            "http://178.105.99.35:8443",
            "POST http://178.105.99.35:8443/api/enroll exit Some(1): curl: (1) Received HTTP/0.9 when not allowed"
        ));
        // Exit 35 — SSL handshake failure
        assert!(should_try_https_fallback(
            "http://master.example.com:8443",
            "POST http://master.example.com:8443/api/enroll exit Some(35): SSL connect error"
        ));
        // Exit 52 — empty reply from server (classic HTTP-on-TLS-port)
        assert!(should_try_https_fallback(
            "http://178.105.99.35:8443",
            "exit Some(52): Empty reply from server"
        ));
        // Lowercased "wrong version number" — TLS lib variant
        assert!(should_try_https_fallback(
            "http://master:8443",
            "tlsv1 alert wrong version number"
        ));
        // Stderr substring HTTP/0.9 without exit code 1 — defensive
        assert!(should_try_https_fallback(
            "http://master:8443",
            "POST http://master:8443 exit Some(56): Received HTTP/0.9 when not allowed"
        ));
    }

    #[test]
    fn https_fallback_does_not_trigger_for_https_or_non_tls_errors() {
        // Already https — no fallback (we can't try "more secure")
        assert!(!should_try_https_fallback(
            "https://master.example.com",
            "exit Some(52): Empty reply"
        ));
        // Plain 404 / unrelated error — don't dance
        assert!(!should_try_https_fallback(
            "http://master.example.com:8443",
            "exit Some(22): 404 Not Found"
        ));
        // DNS / connection refused — operator config issue, not TLS mismatch
        assert!(!should_try_https_fallback(
            "http://master.example.com:8443",
            "exit Some(6): Could not resolve host"
        ));
    }
}
