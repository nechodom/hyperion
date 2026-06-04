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
    let raw = std::fs::read(path)
        .map_err(|e| MasterRpcKeyError::Read(path.display().to_string(), e))?;
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
    pk.verify(payload, &sig).map_err(|_| "signature verify failed")
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
}
