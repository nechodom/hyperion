//! Signed session tokens.
//!
//! Format: `base64url(payload_json) || "." || base64url(signature)`.
//! Payload includes the session id, the user id, expiration, and a
//! creation timestamp. Signature is Ed25519 over the payload bytes.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use serde::{Deserialize, Serialize};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("malformed token")]
    Malformed,
    #[error("bad signature")]
    BadSig,
    #[error("expired")]
    Expired,
    #[error("json: {0}")]
    Json(String),
    #[error("base64: {0}")]
    B64(String),
    #[error("key length must be 32 bytes")]
    BadKeyLen,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub sid: String,
    pub user_id: i64,
    pub created_at: i64,
    pub expires_at: i64,
    /// Username for display in the UI. Optional for backward
    /// compatibility with sessions signed before multi-user.
    #[serde(default)]
    pub username: String,
    /// Role string ("super_admin" | "admin" | "operator" | "viewer").
    /// Sessions signed before multi-user default to "super_admin" to
    /// preserve their existing access — they were the bootstrap admin.
    #[serde(default = "default_role")]
    pub role: String,
    /// Cookie purpose. A real authenticated session has
    /// `purpose == "session"`. The short-lived "you've passed password,
    /// now enter TOTP" cookie has `purpose == "pending_2fa"`. Both are
    /// signed by the same Ed25519 key, so without this field a
    /// pending-2FA token replanted in the main session cookie slot
    /// would satisfy authentication and bypass the second factor.
    /// Sessions signed before this field existed default to "session"
    /// — they were always real sessions.
    #[serde(default = "default_purpose")]
    pub purpose: String,
}

fn default_role() -> String {
    "super_admin".to_string()
}

fn default_purpose() -> String {
    "session".to_string()
}

/// Canonical purpose strings used in [`Session::purpose`].
pub const PURPOSE_SESSION: &str = "session";
pub const PURPOSE_PENDING_2FA: &str = "pending_2fa";

impl Session {
    pub fn role_is(&self, role: &str) -> bool {
        self.role == role
    }
    pub fn is_super_admin(&self) -> bool {
        self.role == "super_admin"
    }
    pub fn is_admin_or_higher(&self) -> bool {
        matches!(self.role.as_str(), "super_admin" | "admin")
    }
    pub fn is_read_only(&self) -> bool {
        self.role == "viewer"
    }
    /// True only for tokens issued as full sessions. Authentication
    /// middleware MUST gate on this — see security audit
    /// "pending-2FA cookie shares SessionSigner with real sessions".
    pub fn is_real_session(&self) -> bool {
        self.purpose == PURPOSE_SESSION
    }
    pub fn is_pending_2fa(&self) -> bool {
        self.purpose == PURPOSE_PENDING_2FA
    }
}

pub struct SessionSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SessionSigner {
    pub fn new_random() -> Self {
        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, SessionError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(SessionError::BadKeyLen);
        }
        let mut buf = [0u8; SECRET_KEY_LENGTH];
        buf.copy_from_slice(bytes);
        let signing_key = SigningKey::from_bytes(&buf);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn secret_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    pub fn sign(&self, session: &Session) -> Result<String, SessionError> {
        let payload = serde_json::to_vec(session).map_err(|e| SessionError::Json(e.to_string()))?;
        let sig = self.signing_key.sign(&payload);
        let mut out = String::with_capacity(payload.len() * 2 + 90);
        out.push_str(&B64.encode(&payload));
        out.push('.');
        out.push_str(&B64.encode(sig.to_bytes()));
        Ok(out)
    }

    pub fn verify(&self, token: &str, now: i64) -> Result<Session, SessionError> {
        let (payload_b64, sig_b64) = token.split_once('.').ok_or(SessionError::Malformed)?;
        let payload = B64
            .decode(payload_b64.as_bytes())
            .map_err(|e| SessionError::B64(e.to_string()))?;
        let sig_bytes = B64
            .decode(sig_b64.as_bytes())
            .map_err(|e| SessionError::B64(e.to_string()))?;
        if sig_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
            return Err(SessionError::Malformed);
        }
        let mut sig_buf = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        sig_buf.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_buf);
        self.verifying_key
            .verify(&payload, &sig)
            .map_err(|_| SessionError::BadSig)?;
        let session: Session =
            serde_json::from_slice(&payload).map_err(|e| SessionError::Json(e.to_string()))?;
        if session.expires_at <= now {
            return Err(SessionError::Expired);
        }
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sess(expires_at: i64) -> Session {
        Session {
            sid: "01J7A8GQX".into(),
            user_id: 1,
            created_at: 1000,
            expires_at,
            username: "tester".into(),
            role: "super_admin".into(),
            purpose: PURPOSE_SESSION.into(),
        }
    }

    #[test]
    fn sign_then_verify_ok() {
        let s = SessionSigner::new_random();
        let token = s.sign(&sess(10_000)).expect("sign");
        let got = s.verify(&token, 9_000).expect("verify");
        assert_eq!(got.user_id, 1);
    }

    #[test]
    fn expired_token_rejected() {
        let s = SessionSigner::new_random();
        let token = s.sign(&sess(5_000)).expect("sign");
        let err = s.verify(&token, 5_001).unwrap_err();
        matches!(err, SessionError::Expired);
    }

    #[test]
    fn tampered_payload_rejected() {
        let s = SessionSigner::new_random();
        let token = s.sign(&sess(10_000)).expect("sign");
        let (_, sig) = token.split_once('.').expect("split");
        // Replace payload with a different valid JSON object.
        let evil = Session {
            sid: "evil".into(),
            user_id: 99,
            created_at: 1000,
            expires_at: 10_000,
            username: "evil".into(),
            role: "super_admin".into(),
            purpose: PURPOSE_SESSION.into(),
        };
        let new_payload = serde_json::to_vec(&evil).expect("json");
        let new_token = format!("{}.{}", B64.encode(&new_payload), sig);
        let err = s.verify(&new_token, 9_000).unwrap_err();
        matches!(err, SessionError::BadSig);
    }

    #[test]
    fn different_signer_rejects_token() {
        let a = SessionSigner::new_random();
        let b = SessionSigner::new_random();
        let token = a.sign(&sess(10_000)).expect("sign");
        let err = b.verify(&token, 9_000).unwrap_err();
        matches!(err, SessionError::BadSig);
    }

    #[test]
    fn key_round_trip_through_secret_bytes() {
        let a = SessionSigner::new_random();
        let bytes = a.secret_bytes();
        let b = SessionSigner::from_secret_bytes(&bytes).expect("rebuild");
        let token = a.sign(&sess(10_000)).expect("sign");
        let _ = b.verify(&token, 9_000).expect("verify");
    }

    #[test]
    fn bad_key_length() {
        assert!(SessionSigner::from_secret_bytes(&[0u8; 16]).is_err());
        assert!(SessionSigner::from_secret_bytes(&[0u8; 64]).is_err());
    }

    #[test]
    fn malformed_token_rejected() {
        let s = SessionSigner::new_random();
        for bad in ["", ".", "nodot", "a.b.c", "###.###"] {
            assert!(s.verify(bad, 0).is_err(), "bad: {bad:?}");
        }
    }

    #[test]
    fn pending_2fa_purpose_distinct_from_session() {
        let s = SessionSigner::new_random();
        let pending = Session {
            sid: "p2fa-xyz".into(),
            user_id: 7,
            created_at: 1000,
            expires_at: 10_000,
            username: String::new(),
            role: "pending_2fa".into(),
            purpose: PURPOSE_PENDING_2FA.into(),
        };
        let token = s.sign(&pending).expect("sign");
        let back = s.verify(&token, 9_000).expect("verify");
        assert!(back.is_pending_2fa());
        assert!(!back.is_real_session());
    }

    #[test]
    fn legacy_token_without_purpose_decodes_as_session() {
        // A payload missing the `purpose` field — what tokens signed
        // before the field existed look like. The default must put
        // them into the "session" bucket so existing browsers don't
        // get force-logged-out on deploy.
        let payload = serde_json::json!({
            "sid": "legacy",
            "user_id": 1,
            "created_at": 100,
            "expires_at": 999_999_999_999i64,
            "username": "kevin",
            "role": "super_admin"
            // no `purpose`
        });
        let s: Session = serde_json::from_value(payload).expect("decode");
        assert_eq!(s.purpose, PURPOSE_SESSION);
        assert!(s.is_real_session());
    }
}
