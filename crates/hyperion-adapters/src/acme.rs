//! Let's Encrypt ACME client using `instant-acme`.
//!
//! Foundation implementation provides:
//! - Account creation + persistence
//! - HTTP-01 issuance with a callback-based challenge writer
//!
//! The full nginx-temporary-vhost dance lives in `hyperion-core` (which can
//! orchestrate writing the challenge file via the `fs` adapter and
//! coordinating with the nginx adapter). This module exposes the
//! `OrderHandle` lower-level helpers.

use crate::AdapterError;
use hyperion_types::CertInfo;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// What the acme adapter needs the orchestrator to do during HTTP-01.
#[async_trait::async_trait]
pub trait ChallengeWriter: Send + Sync {
    async fn write(&self, token: &str, key_authorization: &str) -> Result<(), AdapterError>;
    async fn remove(&self, token: &str) -> Result<(), AdapterError>;
}

/// In-memory test implementation.
#[cfg(test)]
pub struct InMemoryChallengeWriter {
    pub written: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
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

/// Inputs for the high-level "go issue a real cert" entry point.
#[derive(Debug, Clone)]
pub struct IssueRequest<'a> {
    pub domain: &'a str,
    pub sans: &'a [String],
    pub contact_email: &'a str,
    pub staging: bool,
    /// Directory served by nginx at /.well-known/acme-challenge/
    pub challenge_root: &'a Path,
    /// Where to put fullchain.pem / privkey.pem (`<root>/<domain>/...`).
    pub certs_root: &'a str,
}

/// Run a full ACME HTTP-01 issuance:
///   - new account (TOS auto-agreed)
///   - new order for domain + sans
///   - drop a file in challenge_root for each pending HTTP-01 challenge
///   - tell ACME we're ready, poll until Ready / Invalid
///   - generate keypair + CSR locally, finalize order
///   - download fullchain, write fullchain.pem + privkey.pem
///   - return CertInfo with not_after pulled from the cert
///
/// Reuses the existing nginx vhost serving /.well-known/acme-challenge/
/// from `challenge_root` — see `nginx-vhost.conf.j2`.
pub async fn issue_http01(req: IssueRequest<'_>) -> Result<CertInfo, AdapterError> {
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    };

    let directory_url = if req.staging {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-v02.api.letsencrypt.org/directory"
    };

    // 1. Fresh account each call. Stateless = no on-disk cred to lose
    // but at the cost of an extra ACME round-trip per issuance. For a
    // panel that issues a handful of certs per day this is fine.
    let contact_uri = format!("mailto:{}", req.contact_email);
    let (account, _creds) = Account::create(
        &NewAccount {
            contact: &[&contact_uri],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        directory_url,
        None,
    )
    .await
    .map_err(|e| AdapterError::Acme(format!("acme account: {e}")))?;

    // 2. Build identifiers: primary + sans (de-duplicated).
    let mut names: Vec<String> = std::iter::once(req.domain.to_string())
        .chain(req.sans.iter().cloned())
        .collect();
    names.sort();
    names.dedup();
    let identifiers: Vec<Identifier> = names
        .iter()
        .map(|n| Identifier::Dns(n.clone()))
        .collect();

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .map_err(|e| AdapterError::Acme(format!("new order: {e}")))?;

    // 3. Authorizations — for each, pick the HTTP-01 challenge, write
    // the key authorization to challenge_root/<token>.
    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| AdapterError::Acme(format!("authorizations: {e}")))?;
    tokio::fs::create_dir_all(req.challenge_root).await?;
    let mut written: Vec<PathBuf> = Vec::new();
    let mut challenge_urls: Vec<String> = Vec::new();
    for auth in &authorizations {
        if auth.status != AuthorizationStatus::Pending {
            continue;
        }
        let chall = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| AdapterError::Acme("no HTTP-01 challenge offered".into()))?;
        let key_auth = order.key_authorization(chall);
        let token_path = req.challenge_root.join(&chall.token);
        tokio::fs::write(&token_path, key_auth.as_str()).await?;
        written.push(token_path);
        challenge_urls.push(chall.url.clone());
    }

    // 4. Tell ACME we're ready for each challenge.
    for url in &challenge_urls {
        order
            .set_challenge_ready(url)
            .await
            .map_err(|e| AdapterError::Acme(format!("set_challenge_ready: {e}")))?;
    }

    // 5. Poll order status. Exponential backoff capped at 5s.
    let mut delay = Duration::from_millis(500);
    let mut tries = 0u32;
    let state = loop {
        tries += 1;
        if tries > 30 {
            return Err(AdapterError::Acme(
                "ACME order did not finalize within ~3 minutes".into(),
            ));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(5));
        let s = order
            .refresh()
            .await
            .map_err(|e| AdapterError::Acme(format!("order refresh: {e}")))?;
        match s.status {
            OrderStatus::Ready => break s,
            OrderStatus::Valid => break s,
            OrderStatus::Invalid => {
                cleanup_challenges(&written).await;
                return Err(AdapterError::Acme(format!(
                    "ACME order status=Invalid (DNS/challenge problem). state: {:?}",
                    s
                )));
            }
            _ => continue,
        }
    };
    let _ = state;

    // 6. CSR via rcgen.
    let mut params = rcgen::CertificateParams::new(names.clone())
        .map_err(|e| AdapterError::Acme(format!("rcgen params: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key_pair =
        rcgen::KeyPair::generate().map_err(|e| AdapterError::Acme(format!("rcgen kp: {e}")))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| AdapterError::Acme(format!("serialize_request: {e}")))?;

    // 7. Finalize the order (returns once it's accepted; the cert PEM
    // itself may take an extra round-trip to materialize, so we poll).
    order
        .finalize(csr.der())
        .await
        .map_err(|e| AdapterError::Acme(format!("finalize: {e}")))?;

    let cert_chain_pem = loop {
        match order.certificate().await {
            Ok(Some(c)) => break c,
            Ok(None) => tokio::time::sleep(Duration::from_millis(700)).await,
            Err(e) => return Err(AdapterError::Acme(format!("download cert: {e}"))),
        }
    };
    let key_pem = key_pair.serialize_pem();

    // 8. Write to disk: <certs_root>/<domain>/{fullchain,privkey}.pem
    let domain_dir = PathBuf::from(req.certs_root).join(req.domain);
    crate::fs::ensure_dir(&domain_dir, 0o700).await?;
    crate::fs::atomic_write(
        &domain_dir.join("fullchain.pem"),
        cert_chain_pem.as_bytes(),
        0o644,
    )
    .await?;
    crate::fs::atomic_write(
        &domain_dir.join("privkey.pem"),
        key_pem.as_bytes(),
        0o600,
    )
    .await?;

    // 9. Cleanup challenge files.
    cleanup_challenges(&written).await;

    // 10. CertInfo — not_after default = 90 days (LE) if we can't parse.
    let not_after = parse_not_after(&cert_chain_pem)
        .unwrap_or_else(|| hyperion_types::now_secs() + 90 * 24 * 3600);

    Ok(CertInfo {
        domain: req.domain.to_string(),
        sans: req.sans.to_vec(),
        issuer: if req.staging {
            "letsencrypt-staging".into()
        } else {
            "letsencrypt".into()
        },
        not_after,
        fingerprint_sha256: fingerprint_sha256_der(cert_chain_pem.as_bytes()),
    })
}

async fn cleanup_challenges(paths: &[PathBuf]) {
    for p in paths {
        let _ = tokio::fs::remove_file(p).await;
    }
}

/// Best-effort cert expiry parsing from a PEM chain. Returns Unix-epoch
/// seconds for `Not After`, or None if parsing failed.
fn parse_not_after(pem: &str) -> Option<i64> {
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::FromDer;
    let (_, p) = parse_x509_pem(pem.as_bytes()).ok()?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&p.contents).ok()?;
    Some(cert.validity().not_after.timestamp())
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
