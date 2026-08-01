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
//! Both halves of the channel are covered: the master signs the REQUEST and
//! the worker signs the RESPONSE. The response half only earns its keep
//! against a hostile path, so the worker here can be told to forge, replay or
//! strip its own answers ([`Mitm`]) — the primitives in
//! `hyperion_core::node_rpc` are unit-tested, but nothing else proves the
//! signature survives curl, TLS, axum's header casing and the `--write-out`
//! trailer split intact.
//!
//! Two mirrors live in this file and must be kept in step with their
//! originals: `handle_signed` mirrors `bin/hyperion-agent/src/inbound_rpc.rs`
//! `handle_rpc`, and `master_check_response_auth` mirrors
//! `bin/hyperion-web/src/dispatcher.rs` `check_response_auth` (that one lives
//! in a binary crate and cannot be imported).

mod common;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use hyperion_core::master_rpc::{
    sign_envelope, verify_envelope, MasterRpcSigner, SignedAuthorization, VerifyOpts,
};
use hyperion_core::node_rpc::{sign_response, verify_response, NodeRpcSigner, RESP_SIG_HEADER};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::{HostingCreateReq, HostingSelector};
use hyperion_rpc::AgentApi;
use hyperion_rpc_client::remote::{call_remote_attested, RemoteCallOutcome};
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
/// receiver's node_id + the master pubkey, reject replays, dispatch, then sign
/// the response bytes.
///
/// The third element of the return is the [`RESP_SIG_HEADER`] value, `None`
/// when `resp_signer` is `None` — i.e. exactly what an agent that predates
/// response signing puts on the wire.
async fn handle_signed(
    agent: &Arc<dyn AgentApi>,
    expected_node_id: &str,
    pubkey_b64: &str,
    nonce_cache: &Mutex<HashMap<String, Instant>>,
    resp_signer: Option<&NodeRpcSigner>,
    authz: Option<&str>,
    body: &[u8],
) -> (StatusCode, Vec<u8>, Option<String>) {
    let Some(authz) = authz else {
        return (
            StatusCode::UNAUTHORIZED,
            b"missing authorization".to_vec(),
            None,
        );
    };
    let auth = match SignedAuthorization::parse(authz) {
        Ok(a) => a,
        Err(e) => return (StatusCode::UNAUTHORIZED, e.as_bytes().to_vec(), None),
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
        Err(e) => return (StatusCode::UNAUTHORIZED, e.as_bytes().to_vec(), None),
    };
    if !consume_nonce(nonce_cache, &env.nonce, Instant::now()) {
        return (StatusCode::UNAUTHORIZED, b"replayed nonce".to_vec(), None);
    }
    let req: Request = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("bad body: {e}").into_bytes(),
                None,
            )
        }
    };
    let resp = hyperion_rpc_server::dispatch(agent.clone(), req).await;
    let body_json = match serde_json::to_vec(&resp) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("serialize: {e}").into_bytes(),
                None,
            )
        }
    };
    // Sign the EXACT bytes about to go on the wire, bound to THIS request's
    // nonce + ts. `resp_ts` is taken after dispatch, not before, because a
    // dispatch may legitimately run for minutes and the master checks response
    // freshness against its own clock.
    let sig = resp_signer.map(|signer| {
        let resp_ts = chrono::Utc::now().timestamp();
        sign_response(
            signer,
            expected_node_id,
            &env.nonce,
            env.ts,
            resp_ts,
            &body_json,
        )
    });
    (StatusCode::OK, body_json, sig)
}

/// One captured (response body, signature header) pair, shared between the
/// listener and the test so a replaying path can re-serve it.
type CapturedResponse = Arc<Mutex<Option<(Vec<u8>, String)>>>;

/// What sits on the path between the worker and the master. Applied AFTER the
/// node signed its answer and BEFORE the master sees it, which is exactly the
/// position an on-path attacker occupies on the `curl -k` channel.
#[derive(Clone, Default)]
enum Mitm {
    /// Nothing: the master gets the bytes and the signature the node produced.
    #[default]
    None,
    /// Substitute a different — still perfectly well-formed — `Response` for
    /// the one the node signed. The forged body decodes cleanly, so the
    /// signature is the ONLY thing standing between it and the operator.
    ForgeBody(Vec<u8>),
    /// Record the first signed (body, signature) pair to go past and re-serve
    /// it for every later request: a genuine node answer replayed against a
    /// nonce it was never signed for.
    ReplayFirst(CapturedResponse),
}

impl Mitm {
    fn apply(&self, body: Vec<u8>, sig: Option<String>) -> (Vec<u8>, Option<String>) {
        match self {
            Mitm::None => (body, sig),
            Mitm::ForgeBody(forged) => (forged.clone(), sig),
            Mitm::ReplayFirst(slot) => {
                let mut g = slot.lock().unwrap_or_else(|p| p.into_inner());
                match g.as_ref() {
                    Some((b, s)) => (b.clone(), Some(s.clone())),
                    None => {
                        if let Some(s) = &sig {
                            *g = Some((body.clone(), s.clone()));
                        }
                        (body, sig)
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct TestState {
    agent: Arc<dyn AgentApi>,
    node_id: String,
    pubkey: String,
    nonce_cache: Arc<Mutex<HashMap<String, Instant>>>,
    /// `None` ⇒ this worker predates response signing.
    resp_signer: Option<Arc<NodeRpcSigner>>,
    mitm: Mitm,
}

async fn route(State(st): State<TestState>, headers: HeaderMap, body: Bytes) -> Response {
    let authz = headers.get("authorization").and_then(|v| v.to_str().ok());
    let (code, out, sig) = handle_signed(
        &st.agent,
        &st.node_id,
        &st.pubkey,
        &st.nonce_cache,
        st.resp_signer.as_deref(),
        authz,
        &body,
    )
    .await;
    let (out, sig) = st.mitm.apply(out, sig);
    let mut resp = (code, out).into_response();
    if let Some(v) = sig {
        // `HeaderName::from_static` rejects the constant's canonical mixed
        // case, so parse the bytes — the same way inbound_rpc does, so the
        // two sides can never drift on spelling.
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(RESP_SIG_HEADER.as_bytes()),
            HeaderValue::from_str(&v),
        ) {
            resp.headers_mut().insert(name, val);
        }
    }
    resp
}

/// Mirror of `dispatcher::check_response_auth` — the master's four-way
/// response-authentication matrix. `resp_pubkey` is what the node published
/// over its authenticated heartbeat (`nodes.resp_pubkey`); capability is
/// decided by its PRESENCE, never by `agent_version`.
fn master_check_response_auth(
    node_id: &str,
    resp_pubkey: Option<&str>,
    out: &RemoteCallOutcome,
    enforce: bool,
) -> Result<(), String> {
    match (out.resp_sig.as_deref(), resp_pubkey) {
        // (1) Old node, nothing on file — the new-master/old-node transient.
        (None, None) => Ok(()),
        // (2) Verify for real, over the RAW bytes curl received. Mis-signed is
        //     an attack and no toggle makes it benign.
        (Some(sig), Some(pubkey)) => verify_response(
            sig,
            pubkey,
            node_id,
            &out.req_nonce,
            out.req_ts,
            &out.raw_body,
            chrono::Utc::now().timestamp(),
            VerifyOpts::default(),
        )
        .map(|_| ())
        .map_err(str::to_string),
        // (3) Node signs, master hasn't seen its first heartbeat yet.
        (Some(_), None) => Ok(()),
        // (4) The downgrade: a key-publishing node answered unsigned.
        (None, Some(_)) => {
            if enforce {
                Err("unsigned response from a key-publishing node".to_string())
            } else {
                Ok(())
            }
        }
    }
}

/// A running worker: a real TLS listener bound to an ephemeral loopback port,
/// trusting `signer`'s pubkey and answering for `node_id`.
struct Worker {
    base_url: String,
    signer: Arc<MasterRpcSigner>,
    node_id: String,
    /// The response-signing pubkey this worker publishes — i.e. what its next
    /// heartbeat would land in `nodes.resp_pubkey`. `None` for a worker that
    /// predates response signing.
    resp_pubkey: Option<String>,
    /// SPKI pin of the cert this listener actually presents, in curl's
    /// `--pinnedpubkey sha256//<value>` form. `None` when openssl isn't
    /// available to compute it (see `hyperion_core::tls_pin`).
    tls_pin: Option<String>,
    _agent_dir: tempfile::TempDir,
    _tls_dir: tempfile::TempDir,
}

/// How to build a worker. `Default` is an honest, signing node with nothing on
/// the path — what a current agent actually is.
struct WorkerCfg {
    /// `None` ⇒ the worker answers with no signature header at all.
    resp_signer: Option<Arc<NodeRpcSigner>>,
    mitm: Mitm,
}

impl Default for WorkerCfg {
    fn default() -> Self {
        Self {
            resp_signer: Some(fresh_node_signer()),
            mitm: Mitm::None,
        }
    }
}

/// A node response-signing key. The file is only the key's birthplace —
/// `NodeRpcSigner` holds it in memory, so the TempDir may go immediately.
fn fresh_node_signer() -> Arc<NodeRpcSigner> {
    let dir = tempfile::tempdir().expect("key dir");
    Arc::new(NodeRpcSigner::load_or_init(&dir.path().join("node-rpc.key")).expect("node signer"))
}

async fn spawn_worker() -> Worker {
    spawn_worker_with(WorkerCfg::default()).await
}

async fn spawn_worker_with(cfg: WorkerCfg) -> Worker {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (agent, agent_dir) = common::build_agent().await;

    // Master's signing key + the self-signed TLS cert for transport.
    let tls_dir = tempfile::tempdir().expect("tls dir");
    let signer = Arc::new(
        MasterRpcSigner::load_or_init(&tls_dir.path().join("master-rpc.key")).expect("signer"),
    );
    let cert_path = tls_dir.path().join("cert.pem");
    let key_path = tls_dir.path().join("key.pem");
    let cert_pem = {
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key = rcgen::KeyPair::generate().expect("keypair");
        let cert = params.self_signed(&key).expect("self-signed");
        let pem = cert.pem();
        std::fs::write(&cert_path, &pem).expect("write cert");
        std::fs::write(&key_path, key.serialize_pem()).expect("write key");
        pem
    };
    // Same helper the worker uses to report its pin over heartbeat, so a pin
    // enforced here is byte-identical to one enforced in production.
    let tls_pin = hyperion_core::tls_pin::spki_pin_from_cert_pem(&cert_pem).await;

    let node_id = "worker-01".to_string();
    let resp_pubkey = cfg.resp_signer.as_ref().map(|s| s.pubkey_b64().to_string());
    let mitm = cfg.mitm.clone();
    let st = TestState {
        agent,
        node_id: node_id.clone(),
        pubkey: signer.pubkey_b64().to_string(),
        nonce_cache: Arc::new(Mutex::new(HashMap::new())),
        resp_signer: cfg.resp_signer,
        mitm: cfg.mitm,
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
    // The readiness probes went through the mitm too, so a capture-and-replay
    // path has already recorded one. Forget it, or the test's very FIRST call
    // would be served a replay and the "a fresh answer verifies" half of the
    // test would be testing nothing.
    if let Mitm::ReplayFirst(slot) = &mitm {
        *slot.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    Worker {
        base_url,
        signer,
        node_id,
        resp_pubkey,
        tls_pin,
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

// ---- Response authentication, over the real wire ----

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_signed_response_verifies() {
    let w = spawn_worker().await;
    let out = call_remote_attested(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts::default(),
    )
    .await
    .expect("AgentInfo over wire");
    assert!(matches!(out.resp, RpcResponse::AgentInfo(_)));
    // The header survived axum, TLS and curl's `--write-out` trailer split.
    // A silent `None` here would put every remote call in the "accept
    // unverified" branch forever — the worst failure mode of this feature,
    // because it looks exactly like success.
    assert!(
        out.resp_sig.is_some(),
        "the worker's response signature never reached the master"
    );
    master_check_response_auth(&w.node_id, w.resp_pubkey.as_deref(), &out, true)
        .expect("a genuine signature must verify with enforcement on");

    // Matrix case (3): the node signs but the master hasn't stored its key
    // yet (agent upgraded, first heartbeat not landed). Accepted — there is
    // nothing to check against — even under enforcement.
    master_check_response_auth(&w.node_id, None, &out, true)
        .expect("a signing node must not be blocked before its first heartbeat");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_rejects_forged_response_body() {
    // The forgery: an empty hosting list, so every site on this node vanishes
    // from the panel. It is a valid `Response` and decodes without complaint —
    // nothing but the signature can tell it from the truth.
    let forged = serde_json::to_vec(&RpcResponse::HostingList(vec![])).expect("forged body");
    let w = spawn_worker_with(WorkerCfg {
        mitm: Mitm::ForgeBody(forged),
        ..Default::default()
    })
    .await;

    // Give the node something real to list, so the honest answer and the
    // forged one can never coincide.
    let create = HostingCreateReq {
        domain: Domain::parse("forged-node.cz").expect("domain"),
        aliases: vec![],
        php_version: None,
        database: None,
        system_user: None,
        kind: "static".into(),
        proxy_upstream_url: None,
    };
    call_remote(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::HostingCreate(create),
        RemoteCallOpts::default(),
    )
    .await
    .expect("HostingCreate over wire");

    let out = call_remote_attested(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::HostingList,
        RemoteCallOpts::default(),
    )
    .await
    .expect("the transport itself must succeed — the forgery is well-formed");
    match &out.resp {
        RpcResponse::HostingList(rows) => assert!(
            rows.is_empty(),
            "the substituted body should have reached the decoder untouched"
        ),
        other => panic!("expected the forged HostingList, got {other:?}"),
    }
    // Mis-signed is an attack, so it fails whether or not enforcement is on.
    for enforce in [false, true] {
        let err = master_check_response_auth(&w.node_id, w.resp_pubkey.as_deref(), &out, enforce)
            .expect_err("a body the node never signed must be discarded");
        assert_eq!(err, "signature verify failed");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_rejects_response_signed_by_another_nodes_key() {
    // The worker signs with a key the master has never associated with this
    // node — an attacker who owns some node's key, or simply generated one,
    // answering in another node's name.
    let w = spawn_worker_with(WorkerCfg {
        resp_signer: Some(fresh_node_signer()),
        ..Default::default()
    })
    .await;
    // What the master actually holds in `nodes.resp_pubkey` for this node.
    let enrolled = fresh_node_signer();
    assert_ne!(w.resp_pubkey.as_deref(), Some(enrolled.pubkey_b64()));

    let out = call_remote_attested(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts::default(),
    )
    .await
    .expect("AgentInfo over wire");
    assert!(out.resp_sig.is_some(), "the impostor did sign");
    let err = master_check_response_auth(&w.node_id, Some(enrolled.pubkey_b64()), &out, false)
        .expect_err("a signature from a key this node never published must fail");
    assert_eq!(err, "signature verify failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_rejects_replayed_response() {
    let slot = Arc::new(Mutex::new(None));
    let w = spawn_worker_with(WorkerCfg {
        mitm: Mitm::ReplayFirst(Arc::clone(&slot)),
        ..Default::default()
    })
    .await;

    let first = call_remote_attested(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts::default(),
    )
    .await
    .expect("first call");
    master_check_response_auth(&w.node_id, w.resp_pubkey.as_deref(), &first, true)
        .expect("the freshly signed answer verifies");

    // Same bytes, same signature, genuinely produced by this node — but the
    // master signed a NEW nonce into this request, and the signature covers
    // the nonce it was made for.
    let second = call_remote_attested(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts::default(),
    )
    .await
    .expect("second call");
    assert_eq!(
        second.resp_sig, first.resp_sig,
        "the path was supposed to re-serve the captured signature"
    );
    assert_ne!(
        second.req_nonce, first.req_nonce,
        "every request must carry a fresh nonce, or replay is undetectable"
    );
    let err = master_check_response_auth(&w.node_id, w.resp_pubkey.as_deref(), &second, false)
        .expect_err("an answer to an earlier request must not answer this one");
    assert_eq!(err, "signature verify failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_unsigned_response_accepted_until_enforced() {
    // A node that predates response signing: no header on the wire at all.
    let w = spawn_worker_with(WorkerCfg {
        resp_signer: None,
        ..Default::default()
    })
    .await;
    let out = call_remote_attested(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts::default(),
    )
    .await
    .expect("AgentInfo over wire");
    assert!(matches!(out.resp, RpcResponse::AgentInfo(_)));
    assert!(out.resp_sig.is_none(), "an old node signs nothing");

    // Matrix case (1): no key on file. Accepted even with enforcement on —
    // this is the new-master/old-node half of a rolling upgrade, and failing
    // it would take the cluster offline the moment the master is updated.
    master_check_response_auth(&w.node_id, None, &out, true)
        .expect("an old node must keep working under a new master");

    // Matrix case (4): the master DOES hold a key for this node, so an
    // unsigned answer is either a rollback or a stripped header. Warn-only
    // until the operator flips the toggle...
    let known = fresh_node_signer();
    master_check_response_auth(&w.node_id, Some(known.pubkey_b64()), &out, false)
        .expect("warn-only must not break dispatch mid-rollout");
    // ...and refused once they have.
    let err = master_check_response_auth(&w.node_id, Some(known.pubkey_b64()), &out, true)
        .expect_err("enforcement must refuse a stripped signature");
    assert_eq!(err, "unsigned response from a key-publishing node");
}

// ---- TLS cert pinning (curl --pinnedpubkey) ----

/// A syntactically valid SPKI pin — base64 of 32 zero bytes — that no real
/// public key can hash to. Lets the negative test run without openssl.
const WRONG_SPKI_PIN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_enforced_pin_accepts_the_workers_own_cert() {
    let w = spawn_worker().await;
    let Some(pin) = w.tls_pin.clone() else {
        // The pin is computed by shelling openssl; with no openssl there is
        // nothing to enforce and nothing meaningful to assert here. The
        // negative test below still runs.
        eprintln!("skipping: openssl unavailable, cannot compute an SPKI pin");
        return;
    };
    let out = call_remote_attested(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts {
            pinned_pubkey: Some(pin.clone()),
            ..Default::default()
        },
    )
    .await
    .expect("pinning a worker's own cert must not break its connection");
    assert!(matches!(out.resp, RpcResponse::AgentInfo(_)));
    // The pin curl reported back must be the one we enforced — if the two
    // ever computed it differently, enforcement would reject every node.
    assert_eq!(
        out.observed_pin.as_deref(),
        Some(pin.as_str()),
        "the observed pin must match the enforced one"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_enforced_pin_rejects_a_foreign_cert() {
    let w = spawn_worker().await;
    // A pin that doesn't match what the worker presents is what a MITM's
    // substituted cert looks like. Note `-k` is still on: the pin has to be
    // what fails the connection, since nothing validates the CA.
    let result = call_remote(
        &w.base_url,
        &w.signer,
        &w.node_id,
        Request::AgentInfo,
        RemoteCallOpts {
            pinned_pubkey: Some(WRONG_SPKI_PIN.to_string()),
            ..Default::default()
        },
    )
    .await;
    assert!(
        result.is_err(),
        "a cert that doesn't match the enforced pin must fail the connection, got {result:?}"
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

    let (code, out, _sig) = handle_signed(
        &agent,
        "node-x",
        signer.pubkey_b64(),
        &cache,
        None,
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

    let (c1, _, _) = handle_signed(
        &agent,
        "node-x",
        signer.pubkey_b64(),
        &cache,
        None,
        Some(&header),
        &body,
    )
    .await;
    assert_eq!(c1, StatusCode::OK, "first use accepted");
    let (c2, _, _) = handle_signed(
        &agent,
        "node-x",
        signer.pubkey_b64(),
        &cache,
        None,
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
    let (code, _, _) = handle_signed(
        &agent,
        "node-x",
        signer.pubkey_b64(),
        &cache,
        None,
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
