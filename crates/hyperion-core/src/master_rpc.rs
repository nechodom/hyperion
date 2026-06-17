//! Master ↔ node remote-RPC signing primitives.
//!
//! The master's hyperion-web needs to dispatch RPCs (HostingCreate,
//! Delete, Suspend, …) to remote agents — not just its own local
//! Unix socket. Each remote call is a POST to the agent's inbound
//! HTTPS listener (port 9443 by default), carrying a body of the
//! same `hyperion_rpc::codec::Request` shape that the local socket
//! consumes, plus an `Authorization: Bearer <token>` header.
//!
//! ## Trust model
//!
//! - Master holds an **Ed25519 signing key** at
//!   `/etc/hyperion/master-rpc.key` (auto-generated on first agent
//!   startup, mode 0600).
//! - The companion public key is propagated to every enrolled node
//!   via the enrollment response AND every heartbeat response.
//!   Already-enrolled nodes pick up the pubkey within one heartbeat
//!   tick after the master is upgraded.
//! - Each outbound RPC carries a signed token covering
//!   `(node_id, ts, nonce, body_blake3)`. The node:
//!     1. verifies the Ed25519 signature with the persisted master
//!        pubkey,
//!     2. refuses if `ts` is more than 60 s old (replay window),
//!     3. refuses if `nonce` was seen in the last 60 s (replay).
//!
//! ## Why Ed25519 + signed-body, not mTLS?
//!
//! The master and the nodes already exchange asymmetric trust at
//! enrollment time (node trusts master URL the operator typed;
//! master mints node id + per-node secret). Re-using that trust
//! anchor by piggy-backing a fresh Ed25519 keypair is cheaper than
//! standing up a cluster PKI:
//!
//! - No CA management on the master.
//! - Node certificates don't need rotation in lockstep with the
//!   master cert (which is self-signed at install time anyway).
//! - The signature covers the *body* — even if an attacker MITMs
//!   the TLS connection between master and node, they can't forge
//!   a request without the master's private key.
//!
//! TLS on the agent's inbound port stays self-signed; it's
//! transport encryption only, not authentication.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum MasterRpcKeyError {
    #[error("read key file {0}: {1}")]
    Read(String, std::io::Error),
    #[error("write key file {0}: {1}")]
    Write(String, std::io::Error),
    #[error("key file {0} has wrong length: got {1} bytes, want {2}")]
    WrongLength(String, usize, usize),
    #[error("chmod key file {0}: {1}")]
    Chmod(String, std::io::Error),
}

/// Wraps an Ed25519 [`SigningKey`] together with cached base64 of
/// its public component so handlers can hand it to enrollment
/// responses without rederiving on every call.
#[derive(Debug, Clone)]
pub struct MasterRpcSigner {
    signing_key: Arc<SigningKey>,
    pubkey_b64: String,
}

impl MasterRpcSigner {
    /// Load the master's signing key from `path`. Generates a fresh
    /// keypair on disk (mode 0600) if the file doesn't exist.
    ///
    /// On any IO or length error the call returns an error and the
    /// caller is responsible for deciding whether to fall back to
    /// "remote RPC disabled" or refuse to start.
    pub fn load_or_init(path: &Path) -> Result<Self, MasterRpcKeyError> {
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

    /// Base64 (no-pad) of the 32-byte public key. Suitable to send
    /// to nodes via enrollment / heartbeat responses.
    pub fn pubkey_b64(&self) -> &str {
        &self.pubkey_b64
    }

    /// Produce an Ed25519 signature over `payload`. Used by the
    /// outbound RPC client (Batch 10).
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.signing_key.sign(payload).to_bytes()
    }
}

fn load_signing_key(path: &Path) -> Result<SigningKey, MasterRpcKeyError> {
    let raw =
        std::fs::read(path).map_err(|e| MasterRpcKeyError::Read(path.display().to_string(), e))?;
    if raw.len() != SECRET_KEY_LENGTH {
        return Err(MasterRpcKeyError::WrongLength(
            path.display().to_string(),
            raw.len(),
            SECRET_KEY_LENGTH,
        ));
    }
    let mut buf = [0u8; SECRET_KEY_LENGTH];
    buf.copy_from_slice(&raw);
    Ok(SigningKey::from_bytes(&buf))
}

fn init_signing_key(path: &Path) -> Result<SigningKey, MasterRpcKeyError> {
    use rand::rngs::OsRng;
    let key = SigningKey::generate(&mut OsRng);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, key.to_bytes())
        .map_err(|e| MasterRpcKeyError::Write(path.display().to_string(), e))?;
    // 0600 — anyone with read on this file can impersonate the
    // master to any enrolled node, so be strict.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| MasterRpcKeyError::Chmod(path.display().to_string(), e))?;
    tracing::info!(
        path = %path.display(),
        "generated new master_rpc Ed25519 signing key"
    );
    Ok(key)
}

/// Parse a base64-no-pad-encoded 32-byte Ed25519 public key.
/// Used by nodes to deserialize the master pubkey they received
/// at enrollment / heartbeat time.
pub fn parse_pubkey_b64(s: &str) -> Result<VerifyingKey, &'static str> {
    let bytes = STANDARD_NO_PAD
        .decode(s.trim())
        .map_err(|_| "invalid base64")?;
    if bytes.len() != 32 {
        return Err("wrong pubkey length");
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&buf).map_err(|_| "invalid Ed25519 pubkey")
}

/// Verify an Ed25519 signature over `payload` using `pubkey_b64`.
/// Returns Ok(()) on valid signature, an error string on any
/// failure (parse / verify / wrong length). The string is
/// intentionally short — exposed verbatim to remote callers, so
/// we don't want to leak which step failed.
pub fn verify_signature(
    pubkey_b64: &str,
    payload: &[u8],
    sig_bytes: &[u8],
) -> Result<(), &'static str> {
    let pk = parse_pubkey_b64(pubkey_b64)?;
    if sig_bytes.len() != 64 {
        return Err("bad signature length");
    }
    let mut sig_buf = [0u8; 64];
    sig_buf.copy_from_slice(sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_buf);
    pk.verify(payload, &sig)
        .map_err(|_| "signature verify failed")
}

// ============================================================
//  Signed envelope for master→node remote RPC
// ============================================================

/// Metadata covered by the master's signature on every outbound
/// remote RPC. Bound to a specific node so a signed request
/// captured by an attacker can't be replayed against a different
/// node; bound to a body hash so it can't be reused for a
/// different request; bound to ts+nonce so it can't be replayed
/// after the freshness window.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedEnvelope {
    pub node_id: String,
    pub ts: i64,
    pub nonce: String,
    /// BLAKE3 hex of the actual POST body bytes.
    pub body_hash: String,
}

/// The Authorization header carries `Bearer <env_b64>.<sig_b64>` —
/// JWT-shaped but unsigned by us; we control both ends and the
/// payload is a fixed Rust struct, not arbitrary claims.
#[derive(Debug, Clone)]
pub struct SignedAuthorization {
    pub envelope_b64: String,
    pub signature_b64: String,
}

impl SignedAuthorization {
    /// Render in the `<env>.<sig>` shape suitable to drop into the
    /// HTTP Authorization header (Bearer prefix added by caller).
    pub fn to_header_value(&self) -> String {
        format!("{}.{}", self.envelope_b64, self.signature_b64)
    }

    /// Parse a `<env>.<sig>` Bearer value. Rejects anything that
    /// doesn't have exactly one dot.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let s = s.trim();
        // Accept both with and without the "Bearer " prefix.
        let body = s.strip_prefix("Bearer ").unwrap_or(s);
        let (env_b64, sig_b64) = body.split_once('.').ok_or("missing dot separator")?;
        if env_b64.is_empty() || sig_b64.is_empty() {
            return Err("empty envelope or signature");
        }
        Ok(Self {
            envelope_b64: env_b64.to_string(),
            signature_b64: sig_b64.to_string(),
        })
    }
}

/// Sign a remote-RPC envelope. Caller supplies the node_id (target),
/// the request body bytes, and a fresh nonce (typically a random
/// ULID). Returns the Authorization value to put in the header.
pub fn sign_envelope(
    signer: &MasterRpcSigner,
    node_id: &str,
    body: &[u8],
    ts: i64,
    nonce: &str,
) -> SignedAuthorization {
    let env = SignedEnvelope {
        node_id: node_id.to_string(),
        ts,
        nonce: nonce.to_string(),
        body_hash: hex::encode(blake3::hash(body).as_bytes()),
    };
    // serde_json::to_vec on a known struct is infallible in
    // practice (no Map iter, no Display impls that can error).
    let env_json = serde_json::to_vec(&env).unwrap_or_else(|_| b"{}".to_vec());
    let env_b64 = STANDARD_NO_PAD.encode(&env_json);
    // Sign the BASE64 representation, not the raw JSON. That way
    // the verifier doesn't have to round-trip through JSON
    // serialization to recompute the signed bytes — they're
    // literally the bytes of `env_b64`.
    let sig = signer.sign(env_b64.as_bytes());
    let sig_b64 = STANDARD_NO_PAD.encode(sig);
    SignedAuthorization {
        envelope_b64: env_b64,
        signature_b64: sig_b64,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyOpts {
    /// Maximum allowed age of `envelope.ts` in seconds. Requests
    /// older than this are rejected even with a valid signature
    /// (replay protection in the time dimension).
    pub max_age_secs: i64,
    /// Maximum allowed *future* skew. Tolerate a small amount to
    /// survive a few-second clock drift between master and node
    /// without dropping legitimate requests.
    pub max_skew_secs: i64,
}

impl Default for VerifyOpts {
    fn default() -> Self {
        Self {
            max_age_secs: 60,
            max_skew_secs: 5,
        }
    }
}

/// Verify a parsed `SignedAuthorization` against `pubkey_b64`,
/// `expected_node_id` (the receiver's own node_id), and the actual
/// request `body` bytes. Returns the parsed envelope on success
/// so the caller can feed `envelope.nonce` to its replay cache.
pub fn verify_envelope(
    auth: &SignedAuthorization,
    pubkey_b64: &str,
    expected_node_id: &str,
    body: &[u8],
    now: i64,
    opts: VerifyOpts,
) -> Result<SignedEnvelope, &'static str> {
    // 1. Signature first — cheapest way to reject random garbage
    //    before we burn time on JSON parsing.
    let sig_bytes = STANDARD_NO_PAD
        .decode(&auth.signature_b64)
        .map_err(|_| "signature base64")?;
    verify_signature(pubkey_b64, auth.envelope_b64.as_bytes(), &sig_bytes)?;
    // 2. Decode + parse the envelope.
    let env_bytes = STANDARD_NO_PAD
        .decode(&auth.envelope_b64)
        .map_err(|_| "envelope base64")?;
    let env: SignedEnvelope = serde_json::from_slice(&env_bytes).map_err(|_| "envelope parse")?;
    // 3. Bind to receiver — refuse requests addressed to a
    //    different node, even if signed validly.
    if env.node_id != expected_node_id {
        return Err("envelope node mismatch");
    }
    // 4. Freshness — reject stale or implausibly-future ts.
    if env.ts < now - opts.max_age_secs {
        return Err("envelope too old");
    }
    if env.ts > now + opts.max_skew_secs {
        return Err("envelope in future");
    }
    // 5. Body integrity — body_hash MUST match the bytes we
    //    actually received. Otherwise an attacker with a captured
    //    valid Authorization header could swap in a different
    //    POST body (e.g. delete instead of list).
    let actual_body_hash = hex::encode(blake3::hash(body).as_bytes());
    if env.body_hash != actual_body_hash {
        return Err("body hash mismatch");
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_init_creates_key_with_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("master-rpc.key");
        assert!(!p.exists());
        let s = MasterRpcSigner::load_or_init(&p).unwrap();
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
        let p = tmp.path().join("master-rpc.key");
        let a = MasterRpcSigner::load_or_init(&p).unwrap();
        let b = MasterRpcSigner::load_or_init(&p).unwrap();
        // Same pubkey → same private key → loaded, not regenerated.
        assert_eq!(a.pubkey_b64(), b.pubkey_b64());
    }

    #[test]
    fn load_rejects_wrong_length_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("master-rpc.key");
        std::fs::write(&p, b"not 32 bytes").unwrap();
        let err = MasterRpcSigner::load_or_init(&p).unwrap_err();
        assert!(matches!(err, MasterRpcKeyError::WrongLength(_, _, _)));
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("master-rpc.key");
        let s = MasterRpcSigner::load_or_init(&p).unwrap();
        let payload = b"node_01H... | 1717... | nonce-abc | body-hash";
        let sig = s.sign(payload);
        verify_signature(s.pubkey_b64(), payload, &sig).expect("sig must verify");
    }

    #[test]
    fn verify_rejects_wrong_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("master-rpc.key");
        let s = MasterRpcSigner::load_or_init(&p).unwrap();
        let sig = s.sign(b"signed-this");
        assert!(verify_signature(s.pubkey_b64(), b"but-verifying-that", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_signature_length() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("master-rpc.key");
        let s = MasterRpcSigner::load_or_init(&p).unwrap();
        // 60-byte garbage instead of 64.
        let bad_sig = [0u8; 60];
        assert!(verify_signature(s.pubkey_b64(), b"anything", &bad_sig).is_err());
    }

    #[test]
    fn parse_pubkey_rejects_garbage() {
        assert!(parse_pubkey_b64("###not_base64###").is_err());
        assert!(parse_pubkey_b64("YWFh").is_err()); // 3 bytes, wrong length
    }

    // ============================================================
    //  Signed envelope tests
    // ============================================================

    fn fresh_signer() -> MasterRpcSigner {
        let tmp = tempfile::tempdir().unwrap();
        MasterRpcSigner::load_or_init(&tmp.path().join("k")).unwrap()
    }

    #[test]
    fn signed_authorization_header_roundtrip() {
        let a = SignedAuthorization {
            envelope_b64: "abc".into(),
            signature_b64: "def".into(),
        };
        let h = a.to_header_value();
        assert_eq!(h, "abc.def");
        let parsed = SignedAuthorization::parse(&format!("Bearer {h}")).unwrap();
        assert_eq!(parsed.envelope_b64, "abc");
        assert_eq!(parsed.signature_b64, "def");
        // Bare value (without Bearer prefix) also works.
        let parsed2 = SignedAuthorization::parse(&h).unwrap();
        assert_eq!(parsed2.envelope_b64, "abc");
    }

    #[test]
    fn signed_authorization_rejects_bad_shape() {
        assert!(SignedAuthorization::parse("no-dot").is_err());
        assert!(SignedAuthorization::parse(".only-sig").is_err());
        assert!(SignedAuthorization::parse("only-env.").is_err());
    }

    #[test]
    fn sign_then_verify_envelope_roundtrips() {
        let s = fresh_signer();
        let body = br#"{"req":"HostingList"}"#;
        let auth = sign_envelope(&s, "node_target", body, 1_700_000_000, "nonce-abc");
        let env = verify_envelope(
            &auth,
            s.pubkey_b64(),
            "node_target",
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .expect("must verify");
        assert_eq!(env.node_id, "node_target");
        assert_eq!(env.nonce, "nonce-abc");
        assert_eq!(env.ts, 1_700_000_000);
    }

    #[test]
    fn verify_rejects_wrong_target_node() {
        let s = fresh_signer();
        let body = b"{}";
        let auth = sign_envelope(&s, "node_a", body, 1_700_000_000, "n1");
        let err = verify_envelope(
            &auth,
            s.pubkey_b64(),
            // We're node_b — request was for node_a.
            "node_b",
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "envelope node mismatch");
    }

    #[test]
    fn verify_rejects_stale_envelope() {
        let s = fresh_signer();
        let body = b"x";
        let auth = sign_envelope(&s, "n", body, 1_700_000_000, "n1");
        // 120s later — past the 60s default window.
        let err = verify_envelope(
            &auth,
            s.pubkey_b64(),
            "n",
            body,
            1_700_000_120,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "envelope too old");
    }

    #[test]
    fn verify_rejects_future_envelope() {
        let s = fresh_signer();
        let body = b"x";
        // Master timestamped 60s in the future.
        let auth = sign_envelope(&s, "n", body, 1_700_000_060, "n1");
        let err = verify_envelope(
            &auth,
            s.pubkey_b64(),
            "n",
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "envelope in future");
    }

    #[test]
    fn verify_rejects_body_swap() {
        let s = fresh_signer();
        let signed_body = b"original-body";
        let auth = sign_envelope(&s, "n", signed_body, 1_700_000_000, "n1");
        // Attacker captured Authorization and tried to POST a
        // different body with it.
        let err = verify_envelope(
            &auth,
            s.pubkey_b64(),
            "n",
            b"different-body",
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "body hash mismatch");
    }

    #[test]
    fn verify_rejects_signature_for_other_master() {
        let a = fresh_signer();
        let b = fresh_signer();
        let body = b"x";
        let auth = sign_envelope(&a, "n", body, 1_700_000_000, "n1");
        // Same data but verified against a different master's
        // pubkey — must fail.
        let err = verify_envelope(
            &auth,
            b.pubkey_b64(),
            "n",
            body,
            1_700_000_000,
            VerifyOpts::default(),
        )
        .unwrap_err();
        assert_eq!(err, "signature verify failed");
    }
}
