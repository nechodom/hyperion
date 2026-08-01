//! Node → master RPC **response** signing primitives.
//!
//! [`crate::master_rpc`] authenticates the *request* half of a remote
//! RPC: the master signs `(node_id, ts, nonce, body_blake3)` and the
//! node refuses anything it can't verify. The response half was never
//! authenticated — the node replied with bare JSON and the master
//! trusted it byte-for-byte, over a `curl -k` connection. An active
//! on-path attacker could therefore *forge responses*: substitute the
//! reset password shown to the operator, or fake a provisioning
//! success the node never performed. This module closes that gap with
//! a per-node Ed25519 signature over every response.
//!
//! ## Trust model
//!
//! - Each node holds its own **Ed25519 signing key** at
//!   `/etc/hyperion/node-rpc.key` (auto-generated on first start,
//!   mode 0600). It is deliberately *not* the node's TLS key and not
//!   `/etc/hyperion/master-rpc.key` — on a worker the latter is a
//!   locally generated key the master has never seen, so signing with
//!   it would authenticate nothing.
//! - The companion public key travels to the master in the heartbeat
//!   and is persisted in `nodes.resp_pubkey`. **Presence of that
//!   column value is the capability signal**, never `agent_version`:
//!   git-describe strings are unorderable and the version column lags
//!   a node restart by a full heartbeat tick.
//! - Every response carries `X-Hyperion-Resp-Sig: <resp_ts>.<sig>`
//!   over a preimage that includes the *request's* nonce and ts, so a
//!   captured response cannot be replayed as the answer to a
//!   different request.
//!
//! ## Compatibility
//!
//! Both directions must keep working during a rolling upgrade:
//! a new master talking to an old node sees no signature header and
//! accepts (nothing to verify yet), and an old master talking to a
//! new node ignores the extra header entirely. That is why the
//! signature rides in a *header* rather than in the response JSON —
//! an old master parses the body straight into `Response`, so a new
//! enum variant or an outer wrapper object would be a hard parse
//! error.

use crate::master_rpc::{verify_signature, VerifyOpts};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use std::path::Path;
use std::sync::Arc;

/// Default on-disk location of the node's response-signing key.
pub const NODE_RPC_KEY_PATH: &str = "/etc/hyperion/node-rpc.key";

/// Header carrying `<resp_ts>.<sig_b64>` on every signed response.
pub const RESP_SIG_HEADER: &str = "X-Hyperion-Resp-Sig";

/// Domain separator. Keeps a response signature from ever verifying
/// as anything else this key might sign in future (and vice versa);
/// the `v1` suffix is the version hook for changing the field set.
const RESP_DOMAIN: &str = "hyperion-resp-v1\n";

#[derive(Debug, thiserror::Error)]
pub enum NodeRpcKeyError {
    #[error("read key file {0}: {1}")]
    Read(String, std::io::Error),
    #[error("write key file {0}: {1}")]
    Write(String, std::io::Error),
    #[error("key file {0} has wrong length: got {1} bytes, want {2}")]
    WrongLength(String, usize, usize),
    #[error("chmod key file {0}: {1}")]
    Chmod(String, std::io::Error),
}

/// Wraps a node's Ed25519 [`SigningKey`] together with cached base64
/// of its public component so the heartbeat can advertise it without
/// rederiving on every tick.
#[derive(Debug, Clone)]
pub struct NodeRpcSigner {
    signing_key: Arc<SigningKey>,
    pubkey_b64: String,
}

impl NodeRpcSigner {
    /// Load this node's response-signing key from `path`. Generates a
    /// fresh keypair on disk (mode 0600) if the file doesn't exist.
    ///
    /// On any IO or length error the call returns an error and the
    /// caller decides whether to fall back to "responses unsigned"
    /// (still accepted by the master for compatibility) or refuse to
    /// start.
    pub fn load_or_init(path: &Path) -> Result<Self, NodeRpcKeyError> {
        let key = if path.exists() {
            load_signing_key(path)?
        } else {
            init_signing_key(path)?
        };
        let verifying: VerifyingKey = key.verifying_key();
        let pubkey_b64 = STANDARD_NO_PAD.encode(verifying.as_bytes());
        Ok(Self {
            signing_key: Arc::new(key),
            pubkey_b64,
        })
    }

    /// Base64 (no-pad) of the 32-byte public key. Advertised to the
    /// master in the heartbeat and stored in `nodes.resp_pubkey`.
    pub fn pubkey_b64(&self) -> &str {
        &self.pubkey_b64
    }

    /// Produce an Ed25519 signature over `payload`.
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.signing_key.sign(payload).to_bytes()
    }
}

fn load_signing_key(path: &Path) -> Result<SigningKey, NodeRpcKeyError> {
    let raw =
        std::fs::read(path).map_err(|e| NodeRpcKeyError::Read(path.display().to_string(), e))?;
    if raw.len() != SECRET_KEY_LENGTH {
        return Err(NodeRpcKeyError::WrongLength(
            path.display().to_string(),
            raw.len(),
            SECRET_KEY_LENGTH,
        ));
    }
    let mut buf = [0u8; SECRET_KEY_LENGTH];
    buf.copy_from_slice(&raw);
    Ok(SigningKey::from_bytes(&buf))
}

fn init_signing_key(path: &Path) -> Result<SigningKey, NodeRpcKeyError> {
    use rand::rngs::OsRng;
    let key = SigningKey::generate(&mut OsRng);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Create the file already at 0600 BEFORE writing any bytes — anyone with
    // read on this file can forge this node's responses to the master (fake
    // provisioning results, substituted passwords). Writing first and
    // chmod-ing after would leave a brief window at the umask default (often
    // 0644), racing a local unprivileged reader.
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| NodeRpcKeyError::Write(path.display().to_string(), e))?;
    f.write_all(&key.to_bytes())
        .map_err(|e| NodeRpcKeyError::Write(path.display().to_string(), e))?;
    // Defensive: tighten perms if the file pre-existed looser (mode() above
    // only applies to a freshly-created file).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| NodeRpcKeyError::Chmod(path.display().to_string(), e))?;
    tracing::info!(
        path = %path.display(),
        "generated new node_rpc Ed25519 response-signing key"
    );
    Ok(key)
}

// ============================================================
//  Signed responses for node→master remote RPC
// ============================================================

/// Canonical preimage both sides compute independently:
///
/// ```text
/// blake3( "hyperion-resp-v1\n"
///         || node_id   || "\n"
///         || req_nonce || "\n"
///         || req_ts    || "\n"
///         || resp_ts   || "\n"
///         || hex(blake3(body)) )
/// ```
///
/// Field order and the domain prefix are load-bearing — they are the
/// wire format, not an implementation detail. `node_id` binds the
/// answer to the node that was actually asked; `req_nonce` + `req_ts`
/// bind it to *this* request, so a captured response can't be
/// replayed as the answer to a later one; `resp_ts` gives the master
/// a freshness window; the body hash makes the bytes tamper-evident.
///
/// The ASCII join is unambiguous because the arity is fixed and no
/// field's alphabet contains a newline (`node_id` is a hostname,
/// `req_nonce` a ULID, the timestamps are decimal, the tail is hex).
fn response_preimage(
    node_id: &str,
    req_nonce: &str,
    req_ts: i64,
    resp_ts: i64,
    body: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(RESP_DOMAIN.as_bytes());
    h.update(node_id.as_bytes());
    h.update(b"\n");
    h.update(req_nonce.as_bytes());
    h.update(b"\n");
    h.update(req_ts.to_string().as_bytes());
    h.update(b"\n");
    h.update(resp_ts.to_string().as_bytes());
    h.update(b"\n");
    h.update(hex::encode(blake3::hash(body).as_bytes()).as_bytes());
    *h.finalize().as_bytes()
}

/// Sign a response. `node_id` is the *responder's* own id, `req_nonce`
/// and `req_ts` come from the request envelope being answered, `body`
/// is the exact JSON bytes about to be written to the socket.
///
/// Returns the [`RESP_SIG_HEADER`] value: `<resp_ts>.<sig_b64>`.
pub fn sign_response(
    signer: &NodeRpcSigner,
    node_id: &str,
    req_nonce: &str,
    req_ts: i64,
    resp_ts: i64,
    body: &[u8],
) -> String {
    let preimage = response_preimage(node_id, req_nonce, req_ts, resp_ts, body);
    let sig_b64 = STANDARD_NO_PAD.encode(signer.sign(&preimage));
    format!("{resp_ts}.{sig_b64}")
}

/// Verify a [`RESP_SIG_HEADER`] value against the node's advertised
/// pubkey (`nodes.resp_pubkey`), the node we dispatched to, the nonce
/// and ts we signed into the request, and the RAW response bytes.
///
/// Returns the verified `resp_ts` on success. Error strings are short
/// and stable — they end up in master-side logs, so they must not
/// leak anything about the response content.
///
/// Callers gate on *presence* of a pubkey, never on agent_version: no
/// header and no stored pubkey means an old node, which is accepted
/// unverified during a rolling upgrade.
pub fn verify_response(
    header_value: &str,
    pubkey_b64: &str,
    node_id: &str,
    req_nonce: &str,
    req_ts: i64,
    body: &[u8],
    now: i64,
    opts: VerifyOpts,
) -> Result<i64, &'static str> {
    // 1. Split `<resp_ts>.<sig_b64>`. Exactly one dot, both halves
    //    non-empty — anything else is malformed, not "unsigned".
    let v = header_value.trim();
    let (ts_str, sig_b64) = v.split_once('.').ok_or("missing dot separator")?;
    if ts_str.is_empty() || sig_b64.is_empty() {
        return Err("empty ts or signature");
    }
    let resp_ts: i64 = ts_str.parse().map_err(|_| "resp ts parse")?;
    // 2. Signature before freshness — `resp_ts` is attacker-supplied
    //    until the signature says otherwise, so there is nothing to
    //    learn from a clock check on unauthenticated input.
    let sig_bytes = STANDARD_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "signature base64")?;
    let preimage = response_preimage(node_id, req_nonce, req_ts, resp_ts, body);
    verify_signature(pubkey_b64, &preimage, &sig_bytes)?;
    // 3. Freshness — same window as the request envelope, so a
    //    response is no more replayable than the request that
    //    triggered it.
    if resp_ts < now - opts.max_age_secs {
        return Err("response too old");
    }
    if resp_ts > now + opts.max_skew_secs {
        return Err("response in future");
    }
    Ok(resp_ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_signer() -> NodeRpcSigner {
        let tmp = tempfile::tempdir().unwrap();
        NodeRpcSigner::load_or_init(&tmp.path().join("node-rpc.key")).unwrap()
    }

    #[test]
    fn load_or_init_creates_key_with_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("node-rpc.key");
        assert!(!p.exists());
        let s = NodeRpcSigner::load_or_init(&p).unwrap();
        assert!(p.exists());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must be 0600");
        // Pubkey base64 — 32 bytes → 43 chars no-pad.
        assert_eq!(s.pubkey_b64().len(), 43);
    }

    #[test]
    fn load_or_init_reuses_existing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("node-rpc.key");
        let a = NodeRpcSigner::load_or_init(&p).unwrap();
        let b = NodeRpcSigner::load_or_init(&p).unwrap();
        assert_eq!(a.pubkey_b64(), b.pubkey_b64());
    }

    #[test]
    fn load_rejects_wrong_length_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("node-rpc.key");
        std::fs::write(&p, b"not 32 bytes").unwrap();
        let err = NodeRpcSigner::load_or_init(&p).unwrap_err();
        assert!(matches!(err, NodeRpcKeyError::WrongLength(_, _, _)));
    }

    #[test]
    fn sign_then_verify_response_roundtrips() {
        let s = fresh_signer();
        let body = br#"{"Ok":{"hosting":"example.com"}}"#;
        let h = sign_response(&s, "s4", "nonce-abc", 1_700_000_000, 1_700_000_001, body);
        assert!(h.starts_with("1700000001."));
        let ts = verify_response(
            &h,
            s.pubkey_b64(),
            "s4",
            "nonce-abc",
            1_700_000_000,
            body,
            1_700_000_001,
            VerifyOpts::default(),
        )
        .expect("must verify");
        assert_eq!(ts, 1_700_000_001);
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let s = fresh_signer();
        let signed = br#"{"Ok":{"password":"real-secret"}}"#;
        let h = sign_response(&s, "s4", "n1", 1_700_000_000, 1_700_000_000, signed);
        // On-path attacker swapped the password the operator will see.
        let err = verify_response(
            &h,
            s.pubkey_b64(),
            "s4",
            "n1",
            1_700_000_000,
            br#"{"Ok":{"password":"attacker-chosen"}}"#,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "signature verify failed");
    }

    #[test]
    fn verify_rejects_wrong_request_nonce() {
        let s = fresh_signer();
        let body = b"{}";
        let h = sign_response(
            &s,
            "s4",
            "nonce-of-req-1",
            1_700_000_000,
            1_700_000_000,
            body,
        );
        // Captured answer to request 1, replayed against request 2.
        let err = verify_response(
            &h,
            s.pubkey_b64(),
            "s4",
            "nonce-of-req-2",
            1_700_000_000,
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "signature verify failed");
    }

    #[test]
    fn verify_rejects_wrong_node_id() {
        let s = fresh_signer();
        let body = b"{}";
        let h = sign_response(&s, "node_a", "n1", 1_700_000_000, 1_700_000_000, body);
        // We dispatched to node_b — node_a's answer must not pass.
        let err = verify_response(
            &h,
            s.pubkey_b64(),
            "node_b",
            "n1",
            1_700_000_000,
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "signature verify failed");
    }

    #[test]
    fn verify_rejects_wrong_request_ts() {
        let s = fresh_signer();
        let body = b"{}";
        let h = sign_response(&s, "s4", "n1", 1_700_000_000, 1_700_000_000, body);
        let err = verify_response(
            &h,
            s.pubkey_b64(),
            "s4",
            "n1",
            1_700_000_999,
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "signature verify failed");
    }

    #[test]
    fn verify_rejects_stale_response() {
        let s = fresh_signer();
        let body = b"x";
        let h = sign_response(&s, "s4", "n1", 1_700_000_000, 1_700_000_000, body);
        // 120s later — past the 60s default window.
        let err = verify_response(
            &h,
            s.pubkey_b64(),
            "s4",
            "n1",
            1_700_000_000,
            body,
            1_700_000_120,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "response too old");
    }

    #[test]
    fn verify_rejects_future_response() {
        let s = fresh_signer();
        let body = b"x";
        // Node timestamped 60s ahead — beyond the 5s skew tolerance.
        let h = sign_response(&s, "s4", "n1", 1_700_000_000, 1_700_000_060, body);
        let err = verify_response(
            &h,
            s.pubkey_b64(),
            "s4",
            "n1",
            1_700_000_000,
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "response in future");
    }

    #[test]
    fn verify_rejects_malformed_header() {
        let s = fresh_signer();
        let body = b"x";
        let call = |h: &str| {
            verify_response(
                h,
                s.pubkey_b64(),
                "s4",
                "n1",
                1_700_000_000,
                body,
                1_700_000_000,
                VerifyOpts::default(),
            )
        };
        assert_eq!(call("no-dot").unwrap_err(), "missing dot separator");
        assert_eq!(call(".only-sig").unwrap_err(), "empty ts or signature");
        assert_eq!(call("1700000000.").unwrap_err(), "empty ts or signature");
        assert_eq!(call("not-a-ts.AAAA").unwrap_err(), "resp ts parse");
        assert_eq!(call("1700000000.###").unwrap_err(), "signature base64");
        // Right shape, right base64, wrong length.
        let short = STANDARD_NO_PAD.encode([0u8; 60]);
        assert_eq!(
            call(&format!("1700000000.{short}")).unwrap_err(),
            "bad signature length"
        );
    }

    #[test]
    fn verify_rejects_signature_from_other_node() {
        let a = fresh_signer();
        let b = fresh_signer();
        let body = b"x";
        let h = sign_response(&a, "s4", "n1", 1_700_000_000, 1_700_000_000, body);
        // Same data, verified against a different node's advertised
        // pubkey — must fail.
        let err = verify_response(
            &h,
            b.pubkey_b64(),
            "s4",
            "n1",
            1_700_000_000,
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "signature verify failed");
    }
}
