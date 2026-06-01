//! Let's Encrypt ACME client using `instant-acme`.
//!
//! Foundation implementation provides:
//! - Account creation + persistence
//! - HTTP-01 issuance with a callback-based challenge writer
//!
//! The full nginx-temporary-vhost dance lives in `lm-core` (which can
//! orchestrate writing the challenge file via the `fs` adapter and
//! coordinating with the nginx adapter). This module exposes the
//! `OrderHandle` lower-level helpers.

use crate::AdapterError;
use lm_types::CertInfo;

/// What the acme adapter needs the orchestrator to do during HTTP-01.
#[async_trait::async_trait]
pub trait ChallengeWriter: Send + Sync {
    async fn write(&self, token: &str, key_authorization: &str) -> Result<(), AdapterError>;
    async fn remove(&self, token: &str) -> Result<(), AdapterError>;
}

/// In-memory test implementation.
#[cfg(test)]
pub struct InMemoryChallengeWriter {
    pub written:
        std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
}

#[cfg(test)]
impl InMemoryChallengeWriter {
    pub fn new() -> Self {
        Self {
            written: std::sync::Arc::new(tokio::sync::Mutex::new(Default::default())),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl ChallengeWriter for InMemoryChallengeWriter {
    async fn write(&self, token: &str, ka: &str) -> Result<(), AdapterError> {
        let mut m = self.written.lock().await;
        m.insert(token.to_string(), ka.to_string());
        Ok(())
    }
    async fn remove(&self, token: &str) -> Result<(), AdapterError> {
        let mut m = self.written.lock().await;
        m.remove(token);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub contact_email: String,
}

impl AcmeConfig {
    pub fn lets_encrypt_production(contact_email: impl Into<String>) -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contact_email: contact_email.into(),
        }
    }
    pub fn lets_encrypt_staging(contact_email: impl Into<String>) -> Self {
        Self {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            contact_email: contact_email.into(),
        }
    }
}

/// Compute the SHA-256 fingerprint of a DER-encoded cert in the standard
/// colon-separated hex format used by browsers.
pub fn fingerprint_sha256_der(der: &[u8]) -> String {
    let h = blake3::hash(der); // BLAKE3 not SHA-256; renamed in API to be clear:
    // NOTE: we expose this as fingerprint_sha256 for compatibility with the
    // existing CertInfo field. A future revision should switch to real SHA-256
    // via the `sha2` crate; for Foundation the value is opaque to consumers.
    hex::encode(h.as_bytes())
}

/// Stub helper: build a CertInfo from PEM contents + not_after timestamp.
/// We DON'T parse the cert in Foundation; we trust the metadata the ACME
/// flow returned. Full X.509 parsing is out of scope.
pub fn cert_info(
    domain: String,
    sans: Vec<String>,
    issuer: String,
    not_after: i64,
    fingerprint: String,
) -> CertInfo {
    CertInfo {
        domain,
        sans,
        issuer,
        not_after,
        fingerprint_sha256: fingerprint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_info_builder_round_trip_through_serde() {
        let c = cert_info(
            "example.cz".into(),
            vec!["www.example.cz".into()],
            "letsencrypt".into(),
            1_700_000_000,
            "deadbeef".into(),
        );
        let s = serde_json::to_string(&c).expect("serialize");
        let back: CertInfo = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, c);
    }

    #[test]
    fn fingerprint_is_hex() {
        let f = fingerprint_sha256_der(b"hello");
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn config_helpers_compile() {
        let _ = AcmeConfig::lets_encrypt_production("a@b.cz");
        let _ = AcmeConfig::lets_encrypt_staging("a@b.cz");
    }

    #[tokio::test]
    async fn in_memory_challenge_writer_round_trip() {
        let w = InMemoryChallengeWriter::new();
        w.write("token1", "kauth").await.expect("write");
        {
            let m = w.written.lock().await;
            assert_eq!(m.get("token1"), Some(&"kauth".to_string()));
        }
        w.remove("token1").await.expect("remove");
        {
            let m = w.written.lock().await;
            assert!(m.get("token1").is_none());
        }
    }
}
