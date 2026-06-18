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
}

impl Default for RemoteCallOpts {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            verify_tls: false,
        }
    }
}

/// Sign + POST + decode. `endpoint_base` should be the full base URL
/// of the target node's inbound listener, e.g. `https://1.2.3.4:9443`
/// — caller is responsible for the IP + port lookup, this function
/// only signs and ships.
pub async fn call_remote(
    endpoint_base: &str,
    signer: &Arc<MasterRpcSigner>,
    target_node_id: &str,
    req: Request,
    opts: RemoteCallOpts,
) -> Result<Response, RemoteClientError> {
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
    if !opts.verify_tls {
        args.push("-k".into());
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
    let resp: Response =
        serde_json::from_slice(&out.stdout).map_err(|e| RemoteClientError::Parse(e.to_string()))?;
    Ok(resp)
}
