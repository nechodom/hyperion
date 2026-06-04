//! Agent inbound HTTPS RPC listener.
//!
//! Master-orchestrated cluster mode: the master's hyperion-web POSTs
//! `hyperion_rpc::codec::Request` payloads to
//! `https://<node-ip>:9443/agent-rpc` and the agent runs them
//! locally, returning the same `Response` shape that would have come
//! out of the Unix socket.
//!
//! ## Security
//!
//! - **Authentication** by Ed25519 signature, *not* by TLS. TLS on
//!   this port is transport encryption only — self-signed, no
//!   verification on the master side.
//! - The master signs an envelope covering `(node_id, ts, nonce,
//!   body_hash)` with its private signing key (see
//!   `hyperion_core::master_rpc`).
//! - This agent verifies with the master pubkey it received at
//!   enrollment time (or via a later heartbeat ack).
//! - Replay defense: in-memory nonce cache with the same 60 s
//!   freshness window the signature timestamp uses.
//!
//! ## Why a separate HTTP server, not multiplex on hyperion-web?
//!
//! `hyperion-web` runs on the master only. Workers don't have it.
//! Adding a route to hyperion-web would only solve the master→
//! master case (i.e. localhost). For master→worker we need a server
//! the worker actually runs — and the worker only runs
//! hyperion-agent. So the listener belongs here.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use hyperion_core::master_rpc::{verify_envelope, SignedAuthorization, VerifyOpts};
use hyperion_rpc::codec::Request;
use hyperion_rpc::AgentApi;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct InboundState {
    agent: Arc<dyn AgentApi>,
    /// Resolves the receiver's own node_id + master pubkey on every
    /// request — re-read from `/etc/hyperion/node-id.json` so that
    /// a heartbeat-driven pubkey rotation takes effect immediately
    /// (no process restart needed).
    state_file: PathBuf,
    /// Sliding-window nonce cache. Keyed on the master's
    /// `SignedEnvelope.nonce`; entries older than `MAX_NONCE_AGE`
    /// are pruned lazily on each lookup.
    nonce_cache: Arc<Mutex<HashMap<String, Instant>>>,
}

/// How long a nonce stays in the cache. Slightly longer than the
/// signature freshness window so a request signed at `ts - 60s` and
/// arriving at `now` still finds its nonce in the cache when an
/// attacker tries to replay it 1s later.
const MAX_NONCE_AGE: Duration = Duration::from_secs(120);

/// Spawn the inbound HTTPS listener. Returns immediately; the
/// listener runs on a background tokio task until the process exits.
/// `bind_addr` is the SocketAddr to listen on (e.g. `0.0.0.0:9443`).
/// `tls_cert` / `tls_key` are autoprovisioned (self-signed) if
/// missing.
pub async fn spawn_listener(
    bind_addr: SocketAddr,
    agent: Arc<dyn AgentApi>,
    state_file: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
) -> anyhow::Result<()> {
    // Initialize the rustls provider — same incantation as
    // hyperion-web's main(). Subsequent calls in tests are no-ops.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if !tls_cert.exists() || !tls_key.exists() {
        ensure_self_signed(&tls_cert, &tls_key)?;
    }
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        &tls_cert, &tls_key,
    )
    .await?;

    let st = InboundState {
        agent,
        state_file,
        nonce_cache: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = Router::new()
        .route("/agent-rpc", post(handle_rpc))
        .with_state(st);

    tokio::spawn(async move {
        tracing::info!(addr=%bind_addr, "hyperion-agent inbound RPC ready");
        if let Err(e) = axum_server::bind_rustls(bind_addr, rustls_config)
            .serve(app.into_make_service())
            .await
        {
            tracing::error!(error=%e, "inbound RPC server exited");
        }
    });
    Ok(())
}

async fn handle_rpc(
    State(st): State<InboundState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. Pull the receiver's own node_id + master pubkey out of
    //    /etc/hyperion/node-id.json. If we haven't been enrolled
    //    yet, we have no way to verify and must refuse.
    let persisted = match read_persisted(&st.state_file).await {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "node not yet enrolled",
            )
                .into_response();
        }
    };
    let Some(pubkey_b64) = persisted.master_rpc_pubkey.as_deref().filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "master_rpc_pubkey not yet propagated — wait for a heartbeat",
        )
            .into_response();
    };

    // 2. Parse + verify the Authorization header.
    let authz = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return (StatusCode::UNAUTHORIZED, "missing authorization").into_response(),
    };
    let auth = match SignedAuthorization::parse(authz) {
        Ok(a) => a,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let now = chrono::Utc::now().timestamp();
    let env = match verify_envelope(
        &auth,
        pubkey_b64,
        &persisted.node_id,
        &body,
        now,
        VerifyOpts::default(),
    ) {
        Ok(e) => e,
        Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
    };

    // 3. Replay protection — refuse a previously-seen nonce.
    if !st.consume_nonce(&env.nonce) {
        return (StatusCode::UNAUTHORIZED, "replayed nonce").into_response();
    }

    // 4. Decode the actual RPC request and dispatch.
    let req: Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("bad request body: {e}"),
            )
                .into_response();
        }
    };
    let resp = hyperion_rpc_server::dispatch(st.agent.clone(), req).await;
    let body_json = match serde_json::to_vec(&resp) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("response serialize: {e}"),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body_json,
    )
        .into_response()
}

impl InboundState {
    fn consume_nonce(&self, nonce: &str) -> bool {
        consume_nonce_in(&self.nonce_cache, nonce, Instant::now(), MAX_NONCE_AGE)
    }
}

/// Try to record `nonce` as freshly-seen. Returns `true` if it
/// wasn't already present (caller may proceed), `false` if this is
/// a replay. Prunes entries older than `max_age` on each call so
/// the cache size stays bounded by the per-window request volume.
/// Extracted to a free function so the test below can call it
/// without a full `InboundState` (which needs an `AgentApi` impl).
fn consume_nonce_in(
    cache: &Mutex<HashMap<String, Instant>>,
    nonce: &str,
    now: Instant,
    max_age: Duration,
) -> bool {
    let mut g = match cache.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let cutoff = now.checked_sub(max_age).unwrap_or(now);
    g.retain(|_, t| *t > cutoff);
    if g.contains_key(nonce) {
        return false;
    }
    g.insert(nonce.to_string(), now);
    true
}

/// Re-read node-id.json on each request — cheap (small file, OS
/// page cache), and means heartbeat-driven updates to
/// master_rpc_pubkey take effect immediately.
async fn read_persisted(path: &Path) -> Option<crate::enroll::PersistedNodeId> {
    let bytes = tokio::fs::read(path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Auto-generate a self-signed cert if the files don't exist. Same
/// pattern as hyperion-web — TLS here is transport encryption only,
/// the signed envelope is the actual auth.
fn ensure_self_signed(cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    use std::io::Write;
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut params = rcgen::CertificateParams::new(vec!["hyperion-agent".to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "hyperion-agent");
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let mut cert_file = std::fs::File::create(cert_path)?;
    cert_file.write_all(cert.pem().as_bytes())?;
    let mut key_file = std::fs::File::create(key_path)?;
    key_file.write_all(key.serialize_pem().as_bytes())?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_cache_rejects_replay() {
        let cache = Mutex::new(HashMap::new());
        let now = Instant::now();
        assert!(consume_nonce_in(&cache, "n1", now, MAX_NONCE_AGE));
        assert!(
            !consume_nonce_in(&cache, "n1", now, MAX_NONCE_AGE),
            "second use of n1 must be rejected"
        );
        // Distinct nonces don't collide.
        assert!(consume_nonce_in(&cache, "n2", now, MAX_NONCE_AGE));
    }

    #[test]
    fn nonce_cache_evicts_after_max_age() {
        let cache = Mutex::new(HashMap::new());
        let t0 = Instant::now();
        assert!(consume_nonce_in(&cache, "n1", t0, Duration::from_secs(1)));
        // 5 seconds later: n1 has been pruned, so it's accepted
        // again. This isn't ideal (we'd rather reject ANY ts that
        // collides with an old request) but ts/freshness in the
        // envelope already shrinks that window — a captured req
        // older than 60s is rejected by the timestamp check.
        let t1 = t0 + Duration::from_secs(5);
        assert!(consume_nonce_in(&cache, "n1", t1, Duration::from_secs(1)));
    }
}
