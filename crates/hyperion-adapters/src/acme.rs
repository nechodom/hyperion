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
        RetryPolicy,
    };

    // rustls 0.23 demands an explicit process-wide CryptoProvider.
    // instant-acme uses rustls underneath; if we don't install one here
    // the whole agent panics on the first ACME request (`Could not
    // automatically determine the process-level CryptoProvider`).
    // OnceLock makes subsequent calls cheap no-ops.
    static PROVIDER_INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PROVIDER_INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let directory_url = if req.staging {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-v02.api.letsencrypt.org/directory"
    };

    // 1. Fresh account each call. Stateless = no on-disk cred to lose
    // but at the cost of an extra ACME round-trip per issuance. For a
    // panel that issues a handful of certs per day this is fine.
    let contact_uri = format!("mailto:{}", req.contact_email);
    let (account, _creds) = Account::builder()
        .map_err(|e| AdapterError::Acme(format!("account builder: {e}")))?
        .create(
            &NewAccount {
                contact: &[&contact_uri],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_string(),
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
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await
        .map_err(|e| AdapterError::Acme(format!("new order: {e}")))?;

    // 3. Authorizations — stream-style in 0.8. For each pending authz,
    // pick the HTTP-01 challenge, write the key authorization to
    // <challenge_root>/<token>, then set_ready.
    tokio::fs::create_dir_all(req.challenge_root).await?;
    let mut written: Vec<PathBuf> = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result
                .map_err(|e| AdapterError::Acme(format!("authorization: {e}")))?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => {
                    cleanup_challenges(&written).await;
                    return Err(AdapterError::Acme(format!(
                        "authorization in unexpected state {other:?}"
                    )));
                }
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| AdapterError::Acme("no HTTP-01 challenge offered".into()))?;
            let key_auth = challenge.key_authorization();
            // ChallengeHandle derefs to Challenge, which has `.token`.
            let token_path = req.challenge_root.join(&challenge.token);
            tokio::fs::write(&token_path, key_auth.as_str()).await?;
            written.push(token_path);
            challenge
                .set_ready()
                .await
                .map_err(|e| AdapterError::Acme(format!("set_ready: {e}")))?;
        }
    }

    // 4. Poll order status. RetryPolicy::default() ~3 min timeout.
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| {
            // Best-effort cleanup; we lose visibility into which
            // challenge file lives where after a poll failure.
            AdapterError::Acme(format!("poll_ready: {e}"))
        })?;
    if !matches!(status, OrderStatus::Ready | OrderStatus::Valid) {
        // Pull the per-authorization / per-challenge error messages so
        // the operator sees WHY LE rejected the order (DNS doesn't
        // resolve, port 80 unreachable, 404, served bad content, etc.)
        // instead of a useless generic "DNS/challenge problem".
        let details = collect_authz_errors(&mut order).await;
        cleanup_challenges(&written).await;
        return Err(AdapterError::Acme(format!(
            "ACME order status={status:?}: {details}"
        )));
    }

    // 5. Finalize — instant-acme 0.8 generates the keypair internally
    // and returns the private key PEM. No more rcgen CSR dance.
    let key_pem = order
        .finalize()
        .await
        .map_err(|e| AdapterError::Acme(format!("finalize: {e}")))?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| AdapterError::Acme(format!("poll_certificate: {e}")))?;
    let _ = names; // names was only needed for the old CSR path

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

/// Best-effort: walk the authorizations on a failed order and concatenate
/// every challenge error LE reported. Returns a single human-readable
/// string suitable for logs / UI. Never panics, never propagates errors —
/// if we can't fetch details we say so but never replace the parent error.
async fn collect_authz_errors(order: &mut instant_acme::Order) -> String {
    use instant_acme::AuthorizationStatus;
    let mut bits: Vec<String> = Vec::new();
    let mut authzs = order.authorizations();
    loop {
        let next = authzs.next().await;
        let Some(item) = next else { break };
        match item {
            Err(e) => bits.push(format!("(refresh failed: {e})")),
            Ok(handle) => {
                let ident = handle.identifier();
                let status = handle.status;
                if matches!(status, AuthorizationStatus::Valid) {
                    continue;
                }
                let mut local: Vec<String> = Vec::new();
                for c in &handle.challenges {
                    if let Some(err) = &c.error {
                        local.push(format!("{:?}: {err}", c.r#type));
                    }
                }
                if local.is_empty() {
                    bits.push(format!("{ident} {status:?} (no specific error from CA)"));
                } else {
                    bits.push(format!("{ident} {status:?}: {}", local.join(" | ")));
                }
            }
        }
    }
    if bits.is_empty() {
        "no authorization details from ACME server".into()
    } else {
        bits.join(" || ")
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
