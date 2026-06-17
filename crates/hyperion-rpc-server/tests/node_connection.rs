//! Local "2-node" master↔worker connection test.
//!
//! macOS/CI can't run the Linux hosting ops a real worker performs, but the
//! NODE-CONNECTION layer is platform-independent and is what this exercises:
//!
//!  - `wire_*` tests drive the REAL master client (`call_remote`, curl + TLS)
//!    against a REAL TLS listener that runs the REAL verify + dispatch path,
//!    proving the signed-RPC channel composes end to end over the wire.
//!  - `handler_*` tests feed crafted signed envelopes straight through the
//!    handler orchestration (verify → nonce → dispatch) so replay and body
//!    tampering are checked deterministically, with no network.
//!
//! The `handle_signed` fn below MIRRORS `bin/hyperion-agent/src/inbound_rpc.rs`
//! `handle_rpc` — keep them in sync if that handler changes.

mod common;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use hyperion_core::master_rpc::{
    sign_envelope, verify_envelope, MasterRpcSigner, SignedAuthorization, VerifyOpts,
};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::{HostingCreateReq, HostingSelector};
use hyperion_rpc::AgentApi;
use hyperion_rpc_client::{call_remote, RemoteCallOpts};
use hyperion_validate::Domain;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NONCE_MAX_AGE: Duration = Duration::from_secs(120);

/// Mirror of `inbound_rpc::consume_nonce_in`: record a freshly-seen nonce,
/// returning false if it was already present (a replay).
fn consume_nonce(cache: &Mutex<HashMap<String, Instant>>, nonce: &str, now: Instant) -> bool {
    let mut g = cache.lock().unwrap_or_else(|p| p.into_inner());
    let cutoff = now.checked_sub(NONCE_MAX_AGE).unwrap_or(now);
    g.retain(|_, t| *t > cutoff);
    if g.contains_key(nonce) {
        return false;
    }
    g.insert(nonce.to_string(), now);
    true
}

/// Mirror of `inbound_rpc::handle_rpc`: verify the signed envelope against the
/// receiver's node_id + the master pubkey, reject replays, then dispatch.
async fn handle_signed(
    agent: &Arc<dyn AgentApi>,
    expected_node_id: &str,
    pubkey_b64: &str,
    nonce_cache: &Mutex<HashMap<String, Instant>>,
    authz: Option<&str>,
    body: &[u8],
) -> (StatusCode, Vec<u8>) {
    let Some(authz) = authz else {
        return (StatusCode::UNAUTHORIZED, b"missing authorization".to_vec());
    };
    let auth = match SignedAuthorization::parse(authz) {
        Ok(a) => a,
        Err(e) => return (StatusCode::UNAUTHORIZED, e.as_bytes().to_vec()),
    };
    let now = chrono::Utc::now().timestamp();
    let env = match verify_envelope(
        &auth,
        pubkey_b64,
        expected_node_id,
        body,
        now,
        VerifyOpts::default(),
    ) {
        Ok(e) => e,
        Err(e) => return (StatusCode::UNAUTHORIZED, e.as_bytes().to_vec()),
    };
    if !consume_nonce(nonce_cache, &env.nonce, Instant::now()) {
        return (StatusCode::UNAUTHORIZED, b"replayed nonce".to_vec());
    }
    let req: Request = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("bad body: {e}").into_bytes(),
            )
        }
    };
    let resp = hyperion_rpc_server::dispatch(agent.clone(), req).await;
    match serde_json::to_vec(&resp) {
        Ok(b) => (StatusCode::OK, b),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialize: {e}").into_bytes(),
        ),
    }
}

#[derive(Clone)]
struct TestState {
    agent: Arc<dyn AgentApi>,
    node_id: String,
    pubkey: String,
    nonce_cache: Arc<Mutex<HashMap<String, Instant>>>,
}

async fn route(State(st): State<TestState>, headers: HeaderMap, body: Bytes) -> Response {
    let authz = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (code, out) = handle_signed(
        &st.agent,
        &st.node_id,
        &st.pubkey,
        &st.nonce_cache,
        authz,
        &body,
    )
    .await;
    (code, out).into_response()
}

/// A running worker: a real TLS listener bound to an ephemeral loopback port,
/// trusting `signer`'s pubkey and answering for `node_id`.
struct Worker {
    base_url: String,
    signer: Arc<MasterRpcSigner>,
    node_id: String,
    _agent_dir: tempfile::TempDir,
    _tls_dir: tempfile::TempDir,
}

async fn spawn_worker() -> Worker {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (agent, agent_dir) = common::build_agent().await;

    // Master's signing key + the self-signed TLS cert for transport.
    let tls_dir = tempfile::tempdir().expect("tls dir");
    let signer = Arc::new(
        MasterRpcSigner::load_or_init(&tls_dir.path().join("master-rpc.key")).expect("signer"),
    );
    let cert_path = tls_dir.path().join("cert.pem");
    let key_path = tls_dir.path().join("key.pem");
    {
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key = rcgen::KeyPair::generate().expect("keypair");
        let cert = params.self_signed(&key).expect("self-signed");
        std::fs::write(&cert_path, cert.pem()).expect("write cert");
        std::fs::write(&key_path, key.serialize_pem()).expect("write key");
    }

    let node_id = "worker-01".to_string();
    let st = TestState {
        agent,
        node_id: node_id.clone(),
        pubkey: signer.pubkey_b64().to_string(),
        nonce_cache: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = Router::new()
        .route("/agent-rpc", post(route))
        .with_state(st);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .expect("rustls config");
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, config)
            .serve(app.into_make_service())
            .await;
    });

    let base_url = format!("https://127.0.0.1:{port}");
    // Readiness: poll until the server answers a signed AgentInfo.
    for _ in 0..60 {
        if call_remote(
            &base_url,
            &signer,
            &node_id,
            Request::AgentInfo,
            RemoteCallOpts::default(),
        )
        .await
        .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Worker {
        base_url,
        signer,
        node_id,
        _agent_dir: agent_dir,
        _tls_dir: tls_dir,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_roundtrip_real_tls() {
    let w = spawn_worker().await;

    // AgentInfo over the signed TLS channel.
    let resp = call_remote(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts::default(),
    )
    .await
    .expect("AgentInfo over wire");
    assert!(
        matches!(resp, RpcResponse::AgentInfo(_)),
        "expected AgentInfo, got {resp:?}"
    );

    // A data RPC: create a hosting on the worker, then list it back — proving
    // the full master→worker→dispatch→DB→response path works over the wire.
    let create = HostingCreateReq {
        domain: Domain::parse("wire-node.cz").expect("domain"),
        aliases: vec![],
        php_version: None,
        database: None,
        system_user: None,
        kind: "static".into(),
        proxy_upstream_url: None,
    };
    let resp = call_remote(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::HostingCreate(create),
        RemoteCallOpts::default(),
    )
    .await
    .expect("HostingCreate over wire");
    assert!(
        matches!(resp, RpcResponse::HostingCreate(_)),
        "got {resp:?}"
    );

    let resp = call_remote(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::HostingList,
        RemoteCallOpts::default(),
    )
    .await
    .expect("HostingList over wire");
    match resp {
        RpcResponse::HostingList(rows) => assert_eq!(rows.len(), 1, "the created hosting"),
        other => panic!("expected HostingList, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_rejects_request_signed_by_a_different_master() {
    let w = spawn_worker().await;
    // A second master the worker has never enrolled with.
    let other_dir = tempfile::tempdir().expect("dir");
    let impostor =
        Arc::new(MasterRpcSigner::load_or_init(&other_dir.path().join("k")).expect("signer"));
    let result = call_remote(
        &w.base_url,
        &impostor,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts::default(),
    )
    .await;
    assert!(
        result.is_err(),
        "worker must reject a request signed by an untrusted master, got {result:?}"
    );
}

// ---- Deterministic, no-network handler-orchestration checks ----

#[tokio::test]
async fn handler_dispatches_valid_signed_request() {
    let (agent, _d) = common::build_agent().await;
    let kd = tempfile::tempdir().unwrap();
    let signer = MasterRpcSigner::load_or_init(&kd.path().join("k")).unwrap();
    let cache = Mutex::new(HashMap::new());
    let body = serde_json::to_vec(&Request::AgentInfo).unwrap();
    let ts = chrono::Utc::now().timestamp();
    let auth = sign_envelope(&signer, "node-x", &body, ts, "nonce-1");
    let header = format!("Bearer {}", auth.to_header_value());

    let (code, out) = handle_signed(
        &agent,
        "node-x",
        signer.pubkey_b64(),
        &cache,
        Some(&header),
        &body,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let resp: RpcResponse = serde_json::from_slice(&out).unwrap();
    assert!(matches!(resp, RpcResponse::AgentInfo(_)));
}

#[tokio::test]
async fn handler_rejects_replayed_nonce() {
    let (agent, _d) = common::build_agent().await;
    let kd = tempfile::tempdir().unwrap();
    let signer = MasterRpcSigner::load_or_init(&kd.path().join("k")).unwrap();
    let cache = Mutex::new(HashMap::new());
    let body = serde_json::to_vec(&Request::AgentInfo).unwrap();
    let ts = chrono::Utc::now().timestamp();
    let auth = sign_envelope(&signer, "node-x", &body, ts, "same-nonce");
    let header = format!("Bearer {}", auth.to_header_value());

    let (c1, _) = handle_signed(
        &agent,
        "node-x",
        signer.pubkey_b64(),
        &cache,
        Some(&header),
        &body,
    )
    .await;
    assert_eq!(c1, StatusCode::OK, "first use accepted");
    let (c2, _) = handle_signed(
        &agent,
        "node-x",
        signer.pubkey_b64(),
        &cache,
        Some(&header),
        &body,
    )
    .await;
    assert_eq!(c2, StatusCode::UNAUTHORIZED, "replayed nonce rejected");
}

#[tokio::test]
async fn handler_rejects_body_tamper() {
    let (agent, _d) = common::build_agent().await;
    let kd = tempfile::tempdir().unwrap();
    let signer = MasterRpcSigner::load_or_init(&kd.path().join("k")).unwrap();
    let cache = Mutex::new(HashMap::new());
    let signed_body = serde_json::to_vec(&Request::AgentInfo).unwrap();
    let ts = chrono::Utc::now().timestamp();
    let auth = sign_envelope(&signer, "node-x", &signed_body, ts, "n");
    let header = format!("Bearer {}", auth.to_header_value());

    // Attacker swaps in a different body under a captured Authorization.
    let tampered = serde_json::to_vec(&Request::HostingDelete {
        sel: HostingSelector::Domain(Domain::parse("victim.cz").unwrap()),
        opts: hyperion_rpc::wire::DeleteOpts::default(),
    })
    .unwrap();
    let (code, _) = handle_signed(
        &agent,
        "node-x",
        signer.pubkey_b64(),
        &cache,
        Some(&header),
        &tampered,
    )
    .await;
    assert_eq!(
        code,
        StatusCode::UNAUTHORIZED,
        "body-hash mismatch rejected"
    );
}
