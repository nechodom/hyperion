//! Node-side enrollment with the master.
//!
//! On first boot of an enrollment-configured agent we POST
//! `master_url/api/enroll` with `{token, label, agent_version, public_ip}`,
//! receive back `{node_id, master_url}`, persist it, and stop.
//! Subsequent boots see the state file and skip enrollment.
//!
//! TLS note: this is the leg that can actually be verified. The master
//! is the side that normally holds a CA-issued certificate (it serves
//! the panel on a real hostname); the worker is the side that cannot,
//! which is why the master→worker direction still leans on cert
//! pinning. And it is the leg worth verifying: every heartbeat carries
//! this node's per-node secret in the clear, so an on-path attacker who
//! can read it can then impersonate the node to the master.
//!
//! So `[enrollment] verify_tls` is a TRI-STATE (see
//! [`decide_verify_tls`]): absent ⇒ verify whenever the master URL is
//! `https://` with a DNS hostname, `true` ⇒ always verify, `false` ⇒
//! the documented escape hatch for the self-signed master that
//! install-master.sh still ships. A verification failure is never
//! retried with `-k`: silently downgrading is exactly the outcome an
//! attacker wants, so the agent aborts and logs the fix instead.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct EnrollmentConfig {
    pub master_url: String,
    pub token: String,
    pub label: String,
    pub state_file: PathBuf,
    /// The operator's `[enrollment] verify_tls`, un-defaulted: `None`
    /// when the key is absent. Resolved per-URL by
    /// [`decide_verify_tls`] rather than here, because the http→https
    /// fallback below can change which URL we are actually talking to.
    pub verify_tls: Option<bool>,
    /// Path to the agent.toml so we can blank out `invite_token`
    /// after a successful enrollment. `None` for tests + the `hctl
    /// enroll` one-shot path that didn't load a config. The clear
    /// is best-effort — failures log a warning but don't abort
    /// enrollment.
    pub config_file: Option<PathBuf>,
    /// Address to report to the master as this node's reachable RPC endpoint,
    /// overriding the auto-detected public IP. `None`/empty ⇒ auto-detect.
    /// Set to a private-network IP to keep master↔node RPC off the public net.
    pub advertise_addr: Option<String>,
    /// Base64 of this node's Ed25519 response-signing public key, taken from
    /// the signer main() loaded at startup. Sent WITH the enrollment — not
    /// left to the first heartbeat — so the master can verify our responses
    /// from its very first dispatch instead of trusting a ~60 s window of
    /// unauthenticated ones. `None` when the key file couldn't be loaded.
    pub resp_pubkey: Option<String>,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    token: &'a str,
    label: &'a str,
    agent_version: &'a str,
    public_ip: Option<String>,
    /// Block B idempotent re-enrollment: our existing identity from
    /// node-id.json, if any, so the master can reuse our node_id instead
    /// of minting a fresh one + orphaning the old row. Omitted (skipped)
    /// on a true first enrollment.
    #[serde(skip_serializing_if = "Option::is_none")]
    prior_node_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prior_secret: Option<&'a str>,
    /// Our response-signing pubkey, so the master pins it at registration
    /// time and every subsequent RPC answer is verifiable. Skipped when
    /// absent, keeping the request byte-identical to the pre-signing shape
    /// for a master that doesn't know the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_pubkey: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
struct EnrollResponse {
    node_id: String,
    master_url: String,
    secret: String,
    #[serde(default)]
    master_rpc_pubkey: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct PersistedNodeId {
    pub node_id: String,
    pub master_url: String,
    #[serde(default)]
    pub secret: String,
    pub enrolled_at: i64,
    /// Base64 of the master's Ed25519 public key for the master→
    /// node remote-RPC channel. Populated on enrollment if the
    /// master supports remote RPC; otherwise updated lazily from
    /// any subsequent heartbeat ack that carries it.
    #[serde(default)]
    pub master_rpc_pubkey: Option<String>,
}

/// Load the persisted node identity if present.
pub async fn load_persisted(path: &std::path::Path) -> Option<PersistedNodeId> {
    let bytes = tokio::fs::read(path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub async fn ensure_enrolled(cfg: EnrollmentConfig) -> Result<(), String> {
    // Already enrolled AND no fresh invite_token configured → nothing to
    // do. A NON-blank token on an *already-enrolled* node is the operator's
    // explicit "re-enroll me" signal (Block B): enroll_now then presents
    // our existing node-id.json identity (prior_node_id + prior_secret) so
    // the master REUSES our node_id instead of orphaning our hostings, and
    // blanks the token afterward. Without this trigger the reuse path was
    // unreachable — enrollment only ever ran when node-id.json was absent,
    // where there is no prior identity to present.
    if cfg.state_file.exists() && cfg.token.trim().is_empty() {
        tracing::debug!(path=%cfg.state_file.display(), "node already enrolled, no fresh token — skipping");
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

/// What TLS verification one node→master request gets. Produced by
/// [`decide_verify_tls`] and consumed by every curl on this leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MasterTls {
    /// Verify the master's certificate against this node's CA bundle.
    Verify,
    /// The operator wrote `verify_tls = false` — the documented escape
    /// hatch for a master that serves a self-signed certificate.
    SkipByOperator,
    /// `https://` to a host no public CA could certify (an IP literal,
    /// a single-label name), so there is nothing to verify against.
    SkipNoAnchor,
    /// `http://` — this connection has no TLS at all.
    Plaintext,
}

impl MasterTls {
    fn verifies(self) -> bool {
        matches!(self, MasterTls::Verify)
    }

    /// One line for the log. The operator has to be able to answer "is
    /// this node actually verifying anything?" from `journalctl` alone
    /// — a bare `verify_tls=false` field would not say *why*.
    fn describe(self) -> &'static str {
        match self {
            MasterTls::Verify => "verifying the master certificate against this node's CA bundle",
            MasterTls::SkipByOperator => {
                "NOT verifying — [enrollment] verify_tls = false in agent.toml; anyone on the \
                 path can read this node's secret"
            }
            MasterTls::SkipNoAnchor => {
                "NOT verifying — the master URL is an IP literal or a single-label name, which \
                 no public CA certifies; give the master a hostname + certificate, then set \
                 verify_tls = true"
            }
            MasterTls::Plaintext => {
                "NO TLS — master_url is http://, so the invite token and this node's secret \
                 cross the network in cleartext; move the master to https://"
            }
        }
    }
}

/// Resolve `[enrollment] verify_tls` for ONE url.
///
/// `http://` short-circuits: there is no certificate on that connection
/// to verify, and reporting "verifying" for it would be a lie. Past
/// that the operator's explicit choice wins in both directions — `true`
/// even against an IP literal (they may have a private CA installed),
/// `false` as the escape hatch. Only the ABSENT case is decided here,
/// and it verifies whenever the master URL has the shape a CA-issued
/// certificate can cover.
fn decide_verify_tls(master_url: &str, configured: Option<bool>) -> MasterTls {
    let url = master_url.trim();
    if !url.starts_with("https://") {
        return MasterTls::Plaintext;
    }
    match configured {
        Some(false) => MasterTls::SkipByOperator,
        Some(true) => MasterTls::Verify,
        None if host_can_hold_a_ca_certificate(host_of(url)) => MasterTls::Verify,
        None => MasterTls::SkipNoAnchor,
    }
}

/// Host portion of `https://host[:port][/path]`, brackets stripped off
/// an IPv6 literal. Deliberately not a general URL parser — the only
/// input is the master URL the operator typed into install-node.sh.
fn host_of(url: &str) -> &str {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    let rest = rest.split('/').next().unwrap_or("");
    if let Some(inner) = rest.strip_prefix('[') {
        // `[2a01:...]:9443` — the colons are the address, not a port.
        return inner.split(']').next().unwrap_or(inner);
    }
    match rest.rsplit_once(':') {
        Some((h, _)) => h,
        None => rest,
    }
}

/// Could a certificate for `host` plausibly chain to something in a
/// trust store? True for a dotted DNS name, false for an IP literal or
/// a single-label name like `master` / `localhost`.
///
/// Deliberately permissive about the zone: `master.lan` passes, because
/// an operator who put their own CA in `/usr/local/share/ca-certificates`
/// gets a verified channel out of it, and if they didn't, the failure is
/// loud and names the fix rather than quietly falling back to `-k`.
fn host_can_hold_a_ca_certificate(host: &str) -> bool {
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    match host.trim_end_matches('.').rsplit_once('.') {
        Some((label, tld)) => {
            !label.is_empty() && tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
        }
        None => false,
    }
}

/// Does this curl failure mean specifically "the master's certificate
/// did not verify"? A DNS failure or a refused connection must NOT be
/// reported as a certificate problem — the recipes are unrelated and an
/// operator sent to the wrong one loses an afternoon.
///
/// Exit codes first, substrings as belt-and-braces: distro curl builds
/// disagree on which code a given OpenSSL/GnuTLS error surfaces as.
fn is_tls_verification_failure(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    // Exit-code matches: 60 is CURLE_PEER_FAILED_VERIFICATION, 51 its
    // legacy "peer certificate not OK" spelling, 77 an unreadable CA
    // bundle (still "we could not verify", still not a network fault).
    if e.contains("exit some(60)") || e.contains("exit some(51)") || e.contains("exit some(77)") {
        return true;
    }
    // Substring matches — covers builds whose exit code differs but
    // whose message is unambiguous.
    e.contains("certificate verify failed")
        || e.contains("self-signed certificate")
        || e.contains("self signed certificate")
        || e.contains("unable to get local issuer certificate")
        || e.contains("ssl certificate problem")
}

/// The message an operator gets when the master's certificate is
/// refused. It names every fix rather than one blessed path, because
/// which is correct depends on facts this node cannot see (does the
/// master have DNS? is the CA private?).
///
/// It also states what did NOT happen: we did not retry with `-k`.
/// Silently downgrading is the whole reason this leg was unverified for
/// so long, and an operator who assumes we retried would draw exactly
/// the wrong conclusion from a node that then never appears.
fn tls_verification_help(master_url: &str, err: &str) -> String {
    format!(
        "{err}\n→ the TLS certificate at {master_url} did NOT verify against this node's CA \
         bundle, so the request was ABORTED — NOT retried unverified, which would hand this \
         node's secret to whoever holds the path. Fix one of:\n\
         (a) give the master a CA-issued certificate for that hostname (certbot on the master); \
         or\n\
         (b) trust the master's own CA here: copy it to \
         /usr/local/share/ca-certificates/hyperion-master.crt && sudo update-ca-certificates; \
         or\n\
         (c) accept an unverified channel — set `verify_tls = false` under [enrollment] in \
         /etc/hyperion/agent.toml and restart hyperion-agent. Master→node commands stay \
         Ed25519-signed either way, but this node's heartbeats become readable on the path."
    )
}

/// Attach the recipe above to a failure that IS a refused certificate,
/// and leave every other failure untouched.
fn annotate_tls_failure(master_url: &str, tls: MasterTls, err: String) -> String {
    if tls.verifies() && is_tls_verification_failure(&err) {
        tls_verification_help(master_url, &err)
    } else {
        err
    }
}

/// Immediate, no-delay enrollment attempt. Used by `hctl enroll`.
/// Auto-tries the http URL as https on transient TLS errors — covers
/// the common case where the operator pasted http:// but the master
/// listens on https only.
pub async fn enroll_now(cfg: &EnrollmentConfig) -> Result<(), String> {
    // Real build SHA, not the hardcoded "0.1.0" — this populates the master's
    // nodes.agent_version column (cluster version-skew pill). See agent_version.
    let agent_version = crate::agent_version();
    // Prefer an operator-configured advertise address (typically a private-
    // network IP) over the auto-detected public IP, so the master dials this
    // node on that network. The field name stays `public_ip` on the wire for
    // compatibility — it means "the address the master reaches me at".
    let public_ip = match cfg.advertise_addr.as_deref() {
        Some(a) if !a.trim().is_empty() => Some(a.trim().to_string()),
        _ => fetch_public_ip().await,
    };
    let base = cfg.master_url.trim_end_matches('/').to_string();
    // Block B: if we still hold a node-id.json, present that identity so a
    // re-enroll reuses our node_id (continuity proven by the secret) rather
    // than orphaning us into a new row. `prior` must outlive the borrow in
    // EnrollRequest, so bind it here.
    let prior = load_persisted(&cfg.state_file).await;
    let (prior_node_id, prior_secret) = match prior.as_ref() {
        Some(p) if !p.node_id.is_empty() && !p.secret.is_empty() => {
            (Some(p.node_id.as_str()), Some(p.secret.as_str()))
        }
        _ => (None, None),
    };
    let body = serde_json::to_string(&EnrollRequest {
        token: &cfg.token,
        label: &cfg.label,
        agent_version: &agent_version,
        public_ip,
        prior_node_id,
        prior_secret,
        resp_pubkey: cfg.resp_pubkey.as_deref(),
    })
    .map_err(|e| format!("serialize: {e}"))?;

    // Try the URL the operator gave us first. On TLS-shaped errors
    // (empty reply, "wrong version number") AND the URL is http://,
    // retry as https:// — that's the very common "master is HTTPS
    // but operator copy-pasted http:" trap.
    //
    // The verification decision is therefore resolved per-URL rather
    // than once per config: that fallback changes which connection we
    // are describing, and an http URL has no certificate to verify
    // while its https twin does.
    let tls = decide_verify_tls(&base, cfg.verify_tls);
    tracing::info!(master = %base, tls = tls.describe(), "attempting node enrollment");
    let primary_url = format!("{base}/api/enroll");
    match post_json(&primary_url, &body, tls.verifies()).await {
        Ok(stdout) => finish_enrollment(cfg, &stdout).await,
        Err(e) if should_try_https_fallback(&base, &e) => {
            let https_base = format!("https://{}", &base[7..]);
            // The upgrade to https is also an upgrade in what we can
            // check, so re-decide against the URL we're about to use.
            let tls = decide_verify_tls(&https_base, cfg.verify_tls);
            tracing::warn!(
                error = %e,
                tls = tls.describe(),
                "enrollment over {base} failed — retrying with https://"
            );
            let stdout = post_json(&format!("{https_base}/api/enroll"), &body, tls.verifies())
                .await
                .map_err(|e| annotate_tls_failure(&https_base, tls, e))?;
            // Persist the discovered scheme so subsequent heartbeats
            // skip the fallback dance.
            let mut adjusted = cfg.clone();
            adjusted.master_url = https_base;
            finish_enrollment(&adjusted, &stdout).await
        }
        Err(e) => Err(annotate_tls_failure(&base, tls, e)),
    }
}

/// Helper: POST JSON, return stdout on HTTP 2xx or a useful error
/// string. `verify_tls=false` adds `-k`. This function does NOT decide
/// that — [`decide_verify_tls`] does, per URL, and a caller that hands
/// it `false` has already established there is nothing to verify or
/// that the operator opted out.
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
        "-X",
        "POST",
        "-H",
        "content-type: application/json",
        "--data-binary",
        "@-",
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
    let resp: EnrollResponse = serde_json::from_slice(stdout).map_err(|e| {
        // NEVER echo the raw body: a successful enrollment response carries the
        // per-node `secret`, and dumping it into an error string leaks it to
        // logs. The byte count is enough to tell "empty reply" from "garbage".
        format!("parse enrollment response: {e} ({} bytes)", stdout.len())
    })?;
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
        master_rpc_pubkey: resp.master_rpc_pubkey.clone(),
    };
    atomically_persist(&cfg.state_file, &persisted).await?;
    // Best-effort: wipe the one-time invite_token from agent.toml.
    // The master invalidated it server-side already; keeping it on
    // disk just clutters the file and could mislead a future
    // operator into thinking it's still active. A failure here is
    // intentionally non-fatal.
    if let Some(cfg_path) = cfg.config_file.as_ref() {
        if let Err(e) = clear_invite_token_in_config(cfg_path).await {
            tracing::warn!(
                path=%cfg_path.display(), error=%e,
                "could not blank invite_token in agent.toml — please clear it manually"
            );
        }
    }
    tracing::info!(node_id=%resp.node_id, master=%cfg.master_url, "node enrolled");
    Ok(())
}

/// Rewrite agent.toml in place setting `enrollment.invite_token = ""`.
/// Uses toml_edit so existing comments / formatting / unrelated
/// fields survive the rewrite. Returns Ok(()) on success OR if the
/// file is missing (operator removed it themselves between enroll
/// and now — not our problem). Atomic write: tmp → chmod 0600 →
/// rename.
async fn clear_invite_token_in_config(path: &std::path::Path) -> Result<(), String> {
    let raw = match tokio::fs::read_to_string(path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("parse {}: {e}", path.display()))?;
    // Only mutate if the field actually exists AND has a non-empty
    // value. Avoids touching the file on subsequent restarts.
    // `is_none_or` is stable since 1.82; workspace MSRV is declared 1.80 but
    // the toolchain we build/ship with is current stable, so allow it here
    // rather than open-code a `map_or(true, ..)` (which clippy then flags back).
    #[allow(clippy::incompatible_msrv)]
    let already_blank = doc
        .get("enrollment")
        .and_then(|s| s.get("invite_token"))
        .and_then(|v| v.as_str())
        .is_none_or(|s| s.is_empty());
    if already_blank {
        return Ok(());
    }
    doc["enrollment"]["invite_token"] = toml_edit::value("");
    let updated = doc.to_string();
    let tmp = path.with_extension("toml.tmp");
    tokio::fs::write(&tmp, updated.as_bytes())
        .await
        .map_err(|e| format!("write tmp {}: {e}", tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
    tracing::info!(path=%path.display(), "blanked enrollment.invite_token in agent.toml");
    Ok(())
}

/// Background heartbeat loop. Reads the persisted node-id file every
/// `period_secs` and POSTs {node_id, secret, agent_version} to
/// `<master>/api/heartbeat`. Single error → log + retry next tick.
///
/// `verify_tls` mirrors `EnrollmentConfig::verify_tls` — the operator's
/// un-defaulted setting, resolved per tick by [`decide_verify_tls`]
/// against the master URL we persisted at enrollment. This is the leg
/// that matters most: the body below carries the per-node secret in
/// the clear on every single tick.
///
/// `resp_pubkey` is our response-signing pubkey, derived at startup
/// from the loaded key and passed in rather than read here: it is
/// the same value the enrollment already sent, and re-advertising it
/// every tick is what lets a node enrolled before response signing
/// existed get pinned without a re-enrollment.
pub async fn heartbeat_loop(
    state_file: std::path::PathBuf,
    period_secs: u64,
    verify_tls: Option<bool>,
    inbound_cert: std::path::PathBuf,
    resp_pubkey: Option<String>,
) {
    // Real build SHA (not "0.1.0") so the master's nodes.agent_version — and
    // thus the cluster version-skew pill — reflects the deployed commit.
    let agent_version = crate::agent_version();
    // Our inbound-listener TLS SPKI pin, reported to the master on every
    // heartbeat so it can (warn-only today, enforce later) tell whether
    // the cert presented on RPC connections matches what we say it is.
    // Computed lazily and cached: the cert is auto-provisioned by the
    // inbound listener, which may still be starting on the first tick.
    // `None` when remote_rpc is disabled (no cert) — the master simply
    // records no pin for this node, which is fine.
    let mut tls_spki_pin: Option<String> = None;
    // Both one-shot: the TLS posture and the certificate-refused recipe
    // are identical on every tick, and this loop runs 1440 times a day.
    let mut tls_policy_logged = false;
    let mut tls_help_logged = false;
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
        if tls_spki_pin.is_none() {
            tls_spki_pin = hyperion_core::tls_pin::spki_pin_from_cert_file(&inbound_cert).await;
        }
        // The master URL comes from node-id.json (operator-supplied at
        // enrollment, never from the response), so this is a decision
        // about a trusted string, not one the master can steer.
        let tls = decide_verify_tls(&p.master_url, verify_tls);
        if !tls_policy_logged {
            tls_policy_logged = true;
            tracing::info!(master = %p.master_url, tls = tls.describe(), "heartbeat TLS policy");
        }
        let url = format!("{}/api/heartbeat", p.master_url.trim_end_matches('/'));
        let body = match serde_json::to_string(&serde_json::json!({
            "node_id": p.node_id,
            "secret": p.secret,
            "agent_version": agent_version,
            "tls_spki_pin": tls_spki_pin,
            "resp_pubkey": resp_pubkey,
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
        if !tls.verifies() {
            args.push("-k");
        }
        args.extend([
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "--data-binary",
            "@-",
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
                // The heartbeat ack may carry the master's remote-RPC pubkey.
                // This key is THE trust anchor for the signed master→node RPC
                // channel — whoever's key we hold can issue privileged RPCs to
                // us. The ack arrives over `curl -k` (unverified TLS) and is
                // itself unauthenticated, so we PIN it: adopt it only on first
                // receipt (when we don't have one yet), and REFUSE any later
                // heartbeat that presents a different key. Otherwise an on-path
                // attacker who can spoof one heartbeat response would swap our
                // anchor and then sign arbitrary RPCs to this node. Rotating
                // the master key is therefore a deliberate operator action:
                // re-enrol the node (which re-establishes the anchor through
                // the operator-typed install flow).
                if let Some(new_pk) = parse_heartbeat_pubkey(&out.stdout) {
                    match decide_pubkey_pin(p.master_rpc_pubkey.as_deref(), &new_pk) {
                        PubkeyPin::Refuse => {
                            tracing::error!(
                                node = %p.node_id,
                                "SECURITY: heartbeat presented a master_rpc_pubkey \
                                 different from the pinned one — REFUSING. If you \
                                 rotated the master key, re-enrol this node; \
                                 otherwise this may be an on-path attack."
                            );
                        }
                        PubkeyPin::Keep => { /* same key already pinned — nothing to do */ }
                        PubkeyPin::Adopt => {
                            let mut updated = p.clone();
                            updated.master_rpc_pubkey = Some(new_pk);
                            if let Err(e) = atomically_persist(&state_file, &updated).await {
                                tracing::warn!(
                                    error=%e,
                                    "persisting master_rpc_pubkey to node-id.json failed"
                                );
                            } else {
                                tracing::info!(
                                    "pinned master_rpc_pubkey from heartbeat ack (first receipt)"
                                );
                            }
                        }
                    }
                }
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                // Same shape should_try_https_fallback matches on, so one
                // classifier serves both call sites.
                let detail = format!("exit {:?}: {stderr}", out.status.code());
                if tls.verifies() && is_tls_verification_failure(&detail) {
                    // NOT retried with -k, here or anywhere: a node that
                    // silently downgrades on a bad certificate is a node an
                    // attacker only has to break once. It goes stale in the
                    // panel instead, which is the visible failure we want.
                    if !tls_help_logged {
                        tls_help_logged = true;
                        tracing::error!(
                            master = %p.master_url,
                            "SECURITY: heartbeat refused — {}",
                            tls_verification_help(&p.master_url, &detail)
                        );
                    } else {
                        tracing::warn!(
                            master = %p.master_url,
                            detail = %detail,
                            "heartbeat still refused — the master certificate does not verify"
                        );
                    }
                } else {
                    tracing::warn!(
                        code = ?out.status.code(),
                        stderr = %stderr,
                        master = %p.master_url,
                        "heartbeat returned non-zero — will retry"
                    );
                }
            }
            Err(e) => tracing::warn!(error=%e, "heartbeat curl failed"),
        }
    }
}

/// Outcome of comparing a heartbeat-presented master pubkey against the one
/// we've pinned. See [`decide_pubkey_pin`].
#[derive(Debug, PartialEq, Eq)]
enum PubkeyPin {
    /// No key pinned yet — adopt this one (first value wins).
    Adopt,
    /// Already pinned to the same key — no-op.
    Keep,
    /// Already pinned to a DIFFERENT key — refuse (possible on-path attack).
    Refuse,
}

/// Trust-on-first-use decision for the master's remote-RPC pubkey. We pin the
/// first key we see and refuse any later heartbeat that presents a different
/// one, because the heartbeat channel is unauthenticated (`curl -k`) and the
/// key is the trust anchor for every privileged master→node RPC. Rotation is a
/// deliberate operator action (re-enrol the node).
fn decide_pubkey_pin(pinned: Option<&str>, presented: &str) -> PubkeyPin {
    match pinned {
        Some(p) if p != presented => PubkeyPin::Refuse,
        Some(_) => PubkeyPin::Keep,
        None => PubkeyPin::Adopt,
    }
}

/// Extract the `master_rpc_pubkey` field from a heartbeat response
/// body. Returns `None` if the body isn't valid JSON, doesn't
/// contain that field, or the field isn't a non-empty string.
fn parse_heartbeat_pubkey(stdout: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    v.get("master_rpc_pubkey")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Atomic write of node-id.json (tmp → chmod 0600 → rename) so a
/// crash midway can never leave the file at a wider mode than 0600.
/// Used both by initial enrollment and by the heartbeat loop when
/// it updates fields in-place (e.g. picking up master_rpc_pubkey).
async fn atomically_persist(
    state_file: &std::path::Path,
    persisted: &PersistedNodeId,
) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(persisted).map_err(|e| format!("serialize persisted: {e}"))?;
    let tmp = state_file.with_extension("json.tmp");
    tokio::fs::write(&tmp, &bytes)
        .await
        .map_err(|e| format!("write tmp {}: {e}", tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await;
    tokio::fs::rename(&tmp, state_file)
        .await
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), state_file.display()))?;
    Ok(())
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
    fn pubkey_pin_first_wins_and_refuses_silent_rotation() {
        // Not pinned yet → adopt the first key we see.
        assert_eq!(decide_pubkey_pin(None, "KEY_A"), PubkeyPin::Adopt);
        // Same key on a later heartbeat → no-op.
        assert_eq!(decide_pubkey_pin(Some("KEY_A"), "KEY_A"), PubkeyPin::Keep);
        // A DIFFERENT key (the on-path-attack case) → refuse, never adopt.
        assert_eq!(decide_pubkey_pin(Some("KEY_A"), "KEY_B"), PubkeyPin::Refuse);
    }

    /// The default. A master URL with the shape a CA-issued certificate
    /// can cover gets verified WITHOUT the operator opting in — this is
    /// the leg that carries the node's plaintext secret on every tick.
    #[test]
    fn verify_tls_defaults_on_for_an_https_hostname() {
        for url in [
            "https://master.example.com",
            "https://master.example.cz:8443",
            "https://panel.hyperion.example.co.uk/",
            // A private zone still counts: the operator may have put
            // their own CA in the node's trust store, and if not, the
            // failure names the fix instead of downgrading.
            "https://master.lan",
            // Trailing whitespace from a hand-edited toml.
            "  https://master.example.com  ",
        ] {
            assert_eq!(
                decide_verify_tls(url, None),
                MasterTls::Verify,
                "{url} should verify by default"
            );
        }
    }

    /// ...and nowhere else. Auto must never claim to verify something
    /// it cannot: an IP literal or a single-label name has no publicly
    /// certifiable identity, and http:// has no certificate at all.
    #[test]
    fn verify_tls_auto_declines_where_there_is_no_trust_anchor() {
        assert_eq!(
            decide_verify_tls("https://203.0.113.9:8443", None),
            MasterTls::SkipNoAnchor
        );
        assert_eq!(
            decide_verify_tls("https://[2001:db8::1]:8443", None),
            MasterTls::SkipNoAnchor
        );
        assert_eq!(
            decide_verify_tls("https://master:8443", None),
            MasterTls::SkipNoAnchor
        );
        assert_eq!(
            decide_verify_tls("https://localhost:8443", None),
            MasterTls::SkipNoAnchor
        );
        // Numeric last label — not a TLD, so not a certifiable name.
        assert_eq!(
            decide_verify_tls("https://10.0.0.5", None),
            MasterTls::SkipNoAnchor
        );
        // http:// is Plaintext, not "skip": there is no certificate on
        // that connection, and describing it as skipped verification
        // would understate what actually happens to the token.
        assert_eq!(
            decide_verify_tls("http://master.example.com", None),
            MasterTls::Plaintext
        );
        // None of these are Verify — the invariant that matters.
        for url in [
            "https://203.0.113.9",
            "https://master",
            "http://master.example.com",
        ] {
            assert!(!decide_verify_tls(url, None).verifies(), "{url}");
        }
    }

    /// The escape hatch, and its opposite. An explicit setting wins in
    /// BOTH directions — `false` is what an operator with a self-signed
    /// master sets, `true` is what an operator with a private CA sets
    /// for an IP-literal master that auto would have declined.
    #[test]
    fn an_explicit_setting_beats_the_auto_decision() {
        assert_eq!(
            decide_verify_tls("https://master.example.com", Some(false)),
            MasterTls::SkipByOperator,
            "the documented escape hatch must survive the new default"
        );
        assert_eq!(
            decide_verify_tls("https://203.0.113.9:8443", Some(true)),
            MasterTls::Verify
        );
        // ...except over http://, where there is nothing to verify no
        // matter what the file says.
        assert_eq!(
            decide_verify_tls("http://master.example.com", Some(true)),
            MasterTls::Plaintext
        );
    }

    /// Only a REFUSED certificate gets the certificate recipe. Sending
    /// an operator whose DNS is broken off to install a CA costs them
    /// an afternoon.
    #[test]
    fn only_certificate_failures_get_the_certificate_recipe() {
        assert!(is_tls_verification_failure(
            "POST https://m.example.com/api/enroll exit Some(60): SSL certificate problem: \
             self-signed certificate"
        ));
        assert!(is_tls_verification_failure(
            "exit Some(77): error setting certificate file"
        ));
        assert!(is_tls_verification_failure(
            "exit Some(35): ssl routines::certificate verify failed"
        ));
        // Not certificate problems.
        assert!(!is_tls_verification_failure(
            "exit Some(6): Could not resolve host: master.example.com"
        ));
        assert!(!is_tls_verification_failure(
            "exit Some(7): Failed to connect to master.example.com port 8443"
        ));
        assert!(!is_tls_verification_failure("exit Some(22): 404 Not Found"));

        // The annotation only fires when we were actually verifying...
        let refused = "exit Some(60): self-signed certificate".to_string();
        let helped = annotate_tls_failure("https://m.example.com", MasterTls::Verify, refused);
        assert!(helped.contains("verify_tls = false"), "names the opt-out");
        assert!(
            helped.contains("NOT retried unverified"),
            "must say what did not happen: {helped}"
        );
        // ...and never rewrites an unrelated failure.
        let dns = "exit Some(6): Could not resolve host".to_string();
        assert_eq!(
            annotate_tls_failure("https://m.example.com", MasterTls::Verify, dns.clone()),
            dns
        );
        // Nor one from a connection we never verified in the first
        // place — telling that operator their certificate is bad when
        // we passed `-k` would be a fabricated diagnosis.
        let same = "exit Some(60): self-signed certificate".to_string();
        assert_eq!(
            annotate_tls_failure(
                "https://m.example.com",
                MasterTls::SkipByOperator,
                same.clone()
            ),
            same
        );
    }

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

    #[tokio::test]
    async fn clear_invite_token_blanks_field_and_preserves_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("agent.toml");
        let original = r#"
# operator's comment
[agent]
socket_group = "ops"

[enrollment]
master_url = "https://master.example.cz:8443"
invite_token = "secret-one-time-abc123"
node_label = "stav"
verify_tls = false
"#;
        tokio::fs::write(&p, original).await.unwrap();
        clear_invite_token_in_config(&p).await.unwrap();
        let after = tokio::fs::read_to_string(&p).await.unwrap();
        assert!(
            after.contains("invite_token = \"\""),
            "token field should be blanked, got:\n{after}"
        );
        // Other fields survive
        assert!(after.contains("master_url = \"https://master.example.cz:8443\""));
        assert!(after.contains("node_label = \"stav\""));
        assert!(after.contains("socket_group = \"ops\""));
        // Comment survives (toml_edit preserves layout)
        assert!(after.contains("# operator's comment"));
        // The actual token bytes are gone
        assert!(!after.contains("secret-one-time-abc123"));
    }

    #[tokio::test]
    async fn clear_invite_token_noop_when_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("agent.toml");
        let original = "[enrollment]\ninvite_token = \"\"\n";
        tokio::fs::write(&p, original).await.unwrap();
        let mtime_before = tokio::fs::metadata(&p).await.unwrap().modified().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        clear_invite_token_in_config(&p).await.unwrap();
        let mtime_after = tokio::fs::metadata(&p).await.unwrap().modified().unwrap();
        // Already-blank → didn't touch the file at all.
        assert_eq!(mtime_before, mtime_after);
    }

    #[tokio::test]
    async fn clear_invite_token_noop_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("agent-does-not-exist.toml");
        // Missing file → returns Ok(()), doesn't create it.
        clear_invite_token_in_config(&p).await.unwrap();
        assert!(!p.exists());
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
