//! Master-side outbound RPC client over the signed HTTPS channel.
//!
//! `call_remote(endpoint, signer, target_node_id, req, opts)` signs
//! a `SignedEnvelope` over `(target_node_id, ts, nonce, body_hash)`
//! with the master's Ed25519 key, POSTs the JSON-encoded `Request`
//! body to `<endpoint>/agent-rpc`, and returns the decoded
//! `Response`. Behaves like [`call`](crate::call) for the local
//! Unix-socket path so handlers can swap between them with a
//! single `dispatch_to_node()` helper at the call site.
//!
//! ## Transport choice
//!
//! Shell out to curl, same pattern hyperion-agent's enrollment +
//! heartbeat loops use. Reasons:
//!
//! - The signed `Authorization` header carries the secret; argv is
//!   safe to inspect.
//! - The body goes via stdin (`--data-binary @-`) so the encoded
//!   Request isn't visible on argv either.
//! - No new HTTPS client dependency (reqwest / hyper).
//! - `-k` keeps working through the chicken-egg "node has a
//!   self-signed cert" phase. The Ed25519 signature is the actual
//!   auth — TLS is transport encryption only.

use hyperion_core::master_rpc::{sign_envelope, MasterRpcSigner};
use hyperion_rpc::codec::{Request, Response};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

#[derive(Debug, thiserror::Error)]
pub enum RemoteClientError {
    #[error("serialize request: {0}")]
    Serialize(String),
    #[error("curl spawn: {0}")]
    Spawn(std::io::Error),
    #[error("curl wait: {0}")]
    Wait(std::io::Error),
    #[error("curl exit {code:?}: {stderr}")]
    HttpError { code: Option<i32>, stderr: String },
    #[error("response parse: {0}")]
    Parse(String),
}

/// Settings for a remote call.
#[derive(Debug, Clone)]
pub struct RemoteCallOpts {
    /// Wall-clock timeout for the whole HTTP round trip. Some RPCs
    /// take a while (backup_now, hosting_export); operator code
    /// should pick this per-request kind.
    pub timeout_secs: u64,
    /// Skip TLS verification (the agent's cert is self-signed).
    /// Always true today; left here as a hook for the future when
    /// the master pins a cert fingerprint from enrollment.
    pub verify_tls: bool,
    /// When `Some`, ENFORCE this SPKI pin (the base64 value, no
    /// `sha256//` prefix) via `curl --pinnedpubkey sha256//<value>`:
    /// the connection fails unless the worker presents a cert whose
    /// public key matches. Works alongside `-k` (the pin is checked
    /// independently of CA validation), which is exactly right for the
    /// self-signed worker certs. `None` = no pin enforcement (warn-only
    /// observation still happens). Block C enforce phase — the
    /// dispatcher only sets this when the cluster toggle is on AND the
    /// node has a reported pin.
    pub pinned_pubkey: Option<String>,
}

impl Default for RemoteCallOpts {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            verify_tls: false,
            pinned_pubkey: None,
        }
    }
}

/// Marker curl's `-w %{certs}` output is prefixed with so we can split
/// the certificate chain off the end of stdout from the JSON response
/// body. JSON (our `Response`) is UTF-8 and never contains this token,
/// so the split is unambiguous.
const CERT_MARKER: &[u8] = b"\n__HYPERION_CURL_CERTS__\n";

/// Split curl stdout (response body, optionally followed by the marker +
/// PEM cert chain) into `(body, certs_pem)`. When the marker is absent —
/// older curl without `%{certs}`, or no cert captured — the whole buffer
/// is the body and `certs_pem` is `None`. Pure + total: never panics.
fn split_body_and_certs(stdout: &[u8]) -> (&[u8], Option<&str>) {
    match stdout
        .windows(CERT_MARKER.len())
        .position(|w| w == CERT_MARKER)
    {
        Some(pos) => {
            let body = &stdout[..pos];
            let certs = &stdout[pos + CERT_MARKER.len()..];
            (body, std::str::from_utf8(certs).ok().map(str::trim))
        }
        None => (stdout, None),
    }
}

/// Sign + POST + decode. `endpoint_base` should be the full base URL
/// of the target node's inbound listener, e.g. `https://1.2.3.4:9443`
/// — caller is responsible for the IP + port lookup, this function
/// only signs and ships. Thin wrapper over
/// [`call_remote_with_observed_pin`] that discards the observed pin —
/// kept stable for callers (integration tests) that don't pin.
pub async fn call_remote(
    endpoint_base: &str,
    signer: &Arc<MasterRpcSigner>,
    target_node_id: &str,
    req: Request,
    opts: RemoteCallOpts,
) -> Result<Response, RemoteClientError> {
    call_remote_with_observed_pin(endpoint_base, signer, target_node_id, req, opts)
        .await
        .map(|(resp, _pin)| resp)
}

/// Like [`call_remote`] but also returns the SPKI pin of the leaf
/// certificate the worker actually presented on this connection
/// (curl `--pinnedpubkey` form), captured via `-w %{certs}`. `None`
/// when the cert couldn't be captured or parsed (older curl, parse
/// failure) — best-effort, never affects the RPC result. The dispatcher
/// compares it (warn-only) against the pin the worker reported over its
/// authenticated heartbeat to detect a MITM / unreported cert rotation.
pub async fn call_remote_with_observed_pin(
    endpoint_base: &str,
    signer: &Arc<MasterRpcSigner>,
    target_node_id: &str,
    req: Request,
    opts: RemoteCallOpts,
) -> Result<(Response, Option<String>), RemoteClientError> {
    let body = serde_json::to_vec(&req).map_err(|e| RemoteClientError::Serialize(e.to_string()))?;
    let ts = chrono::Utc::now().timestamp();
    let nonce = ulid::Ulid::new().to_string();
    let auth = sign_envelope(signer, target_node_id, &body, ts, &nonce);
    let header = format!("Authorization: Bearer {}", auth.to_header_value());
    let url = format!("{}/agent-rpc", endpoint_base.trim_end_matches('/'));

    let mut args: Vec<String> = vec!["-fsS".into()];
    args.push("--max-time".into());
    args.push(opts.timeout_secs.to_string());
    // Cap the response the master buffers in RAM so one malicious or buggy
    // worker can't OOM the whole panel (the inbound agent path is bounded by
    // MAX_FRAME, but this outbound client path was not). 192 MiB sits above
    // MAX_FRAME (128 MiB) + base64 overhead; curl exits 63 past it.
    args.push("--max-filesize".into());
    args.push((192 * 1024 * 1024).to_string());
    // Append the presented cert chain (PEM) after the body so we can pin
    // it. `%{certs}` needs curl ≥ 7.88 (Debian 12 ships 7.88.1); on older
    // curl this yields no usable cert and we degrade to no observed pin.
    args.push("--write-out".into());
    args.push("\n__HYPERION_CURL_CERTS__\n%{certs}".into());
    if !opts.verify_tls {
        args.push("-k".into());
    }
    // ENFORCED cert pin (Block C enforce phase). Compatible with -k:
    // curl still fails the connection if the presented cert's SPKI
    // doesn't match, independent of CA validation.
    if let Some(pin) = &opts.pinned_pubkey {
        args.push("--pinnedpubkey".into());
        args.push(format!("sha256//{pin}"));
    }
    args.push("-X".into());
    args.push("POST".into());
    args.push("-H".into());
    args.push(header);
    args.push("-H".into());
    args.push("content-type: application/json".into());
    args.push("--data-binary".into());
    args.push("@-".into());
    args.push(url);

    let mut child = tokio::process::Command::new("/usr/bin/curl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(RemoteClientError::Spawn)?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&body)
            .await
            .map_err(RemoteClientError::Spawn)?;
        stdin.shutdown().await.ok();
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(RemoteClientError::Wait)?;
    if !out.status.success() {
        return Err(RemoteClientError::HttpError {
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    let (body_bytes, certs_pem) = split_body_and_certs(&out.stdout);
    let resp: Response =
        serde_json::from_slice(body_bytes).map_err(|e| RemoteClientError::Parse(e.to_string()))?;
    // Best-effort pin of the leaf cert. Failure here must never fail the
    // call — the RPC already succeeded.
    let observed_pin = match certs_pem {
        Some(pem) if !pem.is_empty() => hyperion_core::tls_pin::spki_pin_from_cert_pem(pem).await,
        _ => None,
    };
    Ok((resp, observed_pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_no_marker_is_all_body() {
        let (body, certs) = split_body_and_certs(b"{\"ok\":true}");
        assert_eq!(body, b"{\"ok\":true}");
        assert_eq!(certs, None);
    }

    #[test]
    fn split_extracts_certs_after_marker() {
        let raw = b"{\"ok\":true}\n__HYPERION_CURL_CERTS__\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
        let (body, certs) = split_body_and_certs(raw);
        assert_eq!(body, b"{\"ok\":true}");
        assert!(certs.unwrap().starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn split_empty_certs_after_marker() {
        let raw = b"{\"ok\":true}\n__HYPERION_CURL_CERTS__\n";
        let (body, certs) = split_body_and_certs(raw);
        assert_eq!(body, b"{\"ok\":true}");
        // trimmed empty string — caller treats as no pin.
        assert_eq!(certs, Some(""));
    }
}
