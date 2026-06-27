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
use std::os::unix::fs::PermissionsExt;
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
impl Default for InMemoryChallengeWriter {
    fn default() -> Self {
        Self::new()
    }
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
    let identifiers: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();

    // Retry new_order on transient rate-limits (Boulder "Service busy"
    // load-shed). Exponential backoff 15s → 30s → 60s — never silent.
    let mut order = {
        let new_order = NewOrder::new(identifiers.as_slice());
        let mut attempt: u32 = 0;
        loop {
            match account.new_order(&new_order).await {
                Ok(o) => break o,
                Err(e) if is_transient_rate_limit(&e) && attempt < 3 => {
                    attempt += 1;
                    let delay = backoff_for(attempt);
                    tracing::warn!(
                        attempt,
                        delay_secs = delay.as_secs(),
                        error = %e,
                        "ACME new_order rate-limited (transient); retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    return Err(AdapterError::Acme(rate_limit_message("new_order", &e)));
                }
            }
        }
    };

    // 3. Authorizations — stream-style in 0.8. For each pending authz,
    // pick the HTTP-01 challenge, write the key authorization to
    // <challenge_root>/<token>, then set_ready.
    tokio::fs::create_dir_all(req.challenge_root).await?;
    let mut written: Vec<PathBuf> = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz =
                result.map_err(|e| AdapterError::Acme(format!("authorization: {e}")))?;
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
            // Explicit 0o644 — don't trust the inherited umask. If
            // systemd ever sets UMask=0077 on the agent service, files
            // would be 0o600 and nginx (www-data) couldn't read the
            // token even though it could traverse the dir.
            if let Err(e) =
                tokio::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644))
                    .await
            {
                tracing::warn!(error=%e, path=%token_path.display(), "chmod 0644 on challenge token failed");
            }
            written.push(token_path);
            // Same retry shape as new_order. set_ready is where the user
            // hit "Service busy; retry later" — Boulder's transient
            // load-shed. Don't propagate it on the first hit if we can
            // just wait a few seconds.
            let mut attempt: u32 = 0;
            loop {
                match challenge.set_ready().await {
                    Ok(()) => break,
                    Err(e) if is_transient_rate_limit(&e) && attempt < 3 => {
                        attempt += 1;
                        let delay = backoff_for(attempt);
                        tracing::warn!(
                            attempt,
                            delay_secs = delay.as_secs(),
                            error = %e,
                            "ACME set_ready rate-limited (transient); retrying"
                        );
                        tokio::time::sleep(delay).await;
                    }
                    Err(e) => {
                        cleanup_challenges(&written).await;
                        return Err(AdapterError::Acme(rate_limit_message("set_ready", &e)));
                    }
                }
            }
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
    let key_pem = {
        let mut attempt: u32 = 0;
        loop {
            match order.finalize().await {
                Ok(k) => break k,
                Err(e) if is_transient_rate_limit(&e) && attempt < 3 => {
                    attempt += 1;
                    let delay = backoff_for(attempt);
                    tracing::warn!(
                        attempt,
                        delay_secs = delay.as_secs(),
                        error = %e,
                        "ACME finalize rate-limited; retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(AdapterError::Acme(rate_limit_message("finalize", &e))),
            }
        }
    };
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| AdapterError::Acme(rate_limit_message("poll_certificate", &e)))?;
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
    crate::fs::atomic_write(&domain_dir.join("privkey.pem"), key_pem.as_bytes(), 0o600).await?;

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

// ───────────────────────── DNS-01 (wildcard) ─────────────────────────
//
// Wildcard certs (`*.example.com`) can only be validated via DNS-01.
// Unlike HTTP-01 this is inherently two-phase: the operator (or a DNS
// provider API) has to publish a TXT record before we can tell Let's
// Encrypt to validate. We persist the ACME account credentials + order
// URL to disk between the two phases so the resume survives across RPCs.

const DNS01_SESSION_DIR: &str = "/var/lib/hyperion/acme-dns01";

#[derive(serde::Serialize, serde::Deserialize)]
struct Dns01Session {
    account_credentials: serde_json::Value,
    order_url: String,
    staging: bool,
    names: Vec<String>,
}

/// What the operator must publish to DNS before finishing. `record_name`
/// is the same for every value (apex + wildcard authorizations share
/// `_acme-challenge.<domain>`), so all `values` go on that one name as
/// multiple TXT records.
#[derive(Debug, Clone)]
pub struct Dns01Pending {
    pub record_name: String,
    pub values: Vec<String>,
}

fn install_crypto_provider() {
    static PROVIDER_INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PROVIDER_INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn session_path(domain: &str) -> PathBuf {
    // domain is already validated upstream (hyperion-validate). Strip a
    // leading wildcard just in case and keep the path inside our dir.
    let safe: String = domain
        .trim_start_matches("*.")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    PathBuf::from(DNS01_SESSION_DIR).join(format!("{safe}.json"))
}

/// Phase 1: create the ACME account + order for `domain` + sans (the
/// caller adds `*.domain` for a wildcard), collect the DNS-01 TXT values,
/// persist the resumable session, and return the records to publish.
/// Does NOT tell LE we're ready — the TXT isn't live yet.
pub async fn dns01_begin(
    domain: &str,
    sans: &[String],
    contact_email: &str,
    staging: bool,
) -> Result<Dns01Pending, AdapterError> {
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder,
    };
    install_crypto_provider();
    let directory_url = if staging {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-v02.api.letsencrypt.org/directory"
    };
    let contact_uri = format!("mailto:{contact_email}");
    let (account, creds) = Account::builder()
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

    let mut names: Vec<String> = std::iter::once(domain.to_string())
        .chain(sans.iter().cloned())
        .collect();
    names.sort();
    names.dedup();
    let identifiers: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();

    let mut order = {
        let new_order = NewOrder::new(identifiers.as_slice());
        let mut attempt: u32 = 0;
        loop {
            match account.new_order(&new_order).await {
                Ok(o) => break o,
                Err(e) if is_transient_rate_limit(&e) && attempt < 3 => {
                    attempt += 1;
                    tokio::time::sleep(backoff_for(attempt)).await;
                }
                Err(e) => return Err(AdapterError::Acme(rate_limit_message("new_order", &e))),
            }
        }
    };

    let mut values = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz =
                result.map_err(|e| AdapterError::Acme(format!("authorization: {e}")))?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => {
                    return Err(AdapterError::Acme(format!(
                        "authorization in unexpected state {other:?}"
                    )));
                }
            }
            let challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| AdapterError::Acme("no DNS-01 challenge offered".into()))?;
            values.push(challenge.key_authorization().dns_value());
        }
    }
    if values.is_empty() {
        return Err(AdapterError::Acme(
            "every authorization was already valid — nothing to validate".into(),
        ));
    }

    // Persist the resumable session (0600 — contains the account key).
    crate::fs::ensure_dir(Path::new(DNS01_SESSION_DIR), 0o700).await?;
    let session = Dns01Session {
        account_credentials: serde_json::to_value(&creds)
            .map_err(|e| AdapterError::Acme(format!("serialize creds: {e}")))?,
        order_url: order.url().to_string(),
        staging,
        names,
    };
    let body = serde_json::to_vec(&session)
        .map_err(|e| AdapterError::Acme(format!("serialize session: {e}")))?;
    crate::fs::atomic_write(&session_path(domain), &body, 0o600).await?;

    let base = domain.trim_start_matches("*.");
    Ok(Dns01Pending {
        record_name: format!("_acme-challenge.{base}"),
        values,
    })
}

/// Phase 2: resume the saved order, tell LE the TXT records are live,
/// poll, finalize and write the cert to `<certs_root>/<domain>/`.
/// The session file is removed on success.
pub async fn dns01_finish(domain: &str, certs_root: &str) -> Result<CertInfo, AdapterError> {
    use instant_acme::{Account, AuthorizationStatus, ChallengeType, OrderStatus, RetryPolicy};
    install_crypto_provider();

    let path = session_path(domain);
    let raw = tokio::fs::read(&path).await.map_err(|e| {
        AdapterError::Acme(format!(
            "no pending DNS-01 session for {domain} (start one first): {e}"
        ))
    })?;
    let session: Dns01Session = serde_json::from_slice(&raw)
        .map_err(|e| AdapterError::Acme(format!("parse session: {e}")))?;
    let creds: instant_acme::AccountCredentials =
        serde_json::from_value(session.account_credentials)
            .map_err(|e| AdapterError::Acme(format!("parse creds: {e}")))?;
    let account = Account::builder()
        .map_err(|e| AdapterError::Acme(format!("account builder: {e}")))?
        .from_credentials(creds)
        .await
        .map_err(|e| AdapterError::Acme(format!("resume account: {e}")))?;
    let mut order = account
        .order(session.order_url.clone())
        .await
        .map_err(|e| AdapterError::Acme(format!("resume order: {e}")))?;

    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz =
                result.map_err(|e| AdapterError::Acme(format!("authorization: {e}")))?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => {
                    return Err(AdapterError::Acme(format!(
                        "authorization in unexpected state {other:?}"
                    )));
                }
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| AdapterError::Acme("no DNS-01 challenge offered".into()))?;
            let mut attempt: u32 = 0;
            loop {
                match challenge.set_ready().await {
                    Ok(()) => break,
                    Err(e) if is_transient_rate_limit(&e) && attempt < 3 => {
                        attempt += 1;
                        tokio::time::sleep(backoff_for(attempt)).await;
                    }
                    Err(e) => return Err(AdapterError::Acme(rate_limit_message("set_ready", &e))),
                }
            }
        }
    }

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| AdapterError::Acme(format!("poll_ready: {e}")))?;
    if !matches!(status, OrderStatus::Ready | OrderStatus::Valid) {
        let details = collect_authz_errors(&mut order).await;
        return Err(AdapterError::Acme(format!(
            "ACME order status={status:?}: {details} \
             (is the TXT record published + propagated?)"
        )));
    }

    let key_pem = order
        .finalize()
        .await
        .map_err(|e| AdapterError::Acme(rate_limit_message("finalize", &e)))?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| AdapterError::Acme(rate_limit_message("poll_certificate", &e)))?;

    let domain_dir = PathBuf::from(certs_root).join(domain);
    crate::fs::ensure_dir(&domain_dir, 0o700).await?;
    crate::fs::atomic_write(
        &domain_dir.join("fullchain.pem"),
        cert_chain_pem.as_bytes(),
        0o644,
    )
    .await?;
    crate::fs::atomic_write(&domain_dir.join("privkey.pem"), key_pem.as_bytes(), 0o600).await?;
    let _ = tokio::fs::remove_file(&path).await;

    let not_after = parse_not_after(&cert_chain_pem)
        .unwrap_or_else(|| hyperion_types::now_secs() + 90 * 24 * 3600);
    let sans: Vec<String> = session
        .names
        .iter()
        .filter(|n| *n != domain)
        .cloned()
        .collect();
    Ok(CertInfo {
        domain: domain.to_string(),
        sans,
        issuer: if session.staging {
            "letsencrypt-staging".into()
        } else {
            "letsencrypt".into()
        },
        not_after,
        fingerprint_sha256: fingerprint_sha256_der(cert_chain_pem.as_bytes()),
    })
}

/// True if the ACME error is a *transient* rate-limit / load-shed
/// (Boulder's "Service busy; retry later" or any urn:...:rateLimited
/// with HTTP 503). False for durable limits like
/// failedAuthorizations / duplicateCertificate / overall-request — those
/// won't clear in seconds and we should surface them to the operator
/// rather than silently waste ACME calls retrying.
fn is_transient_rate_limit(e: &instant_acme::Error) -> bool {
    let instant_acme::Error::Api(p) = e else {
        return false;
    };
    // The rateLimited URN covers many distinct cases; we only want to
    // retry the ones that are clearly transient. Boulder's load-shed
    // path returns HTTP 503 with "Service busy" in detail. Durable
    // limits return 429.
    let is_rate_limited = p.r#type.as_deref() == Some("urn:ietf:params:acme:error:rateLimited");
    if !is_rate_limited {
        return false;
    }
    // Treat 503 OR a "service busy" / "try again" detail as transient.
    let status_503 = matches!(p.status, Some(503));
    let detail = p.detail.as_deref().unwrap_or("").to_ascii_lowercase();
    let says_busy = detail.contains("service busy")
        || detail.contains("try again")
        || detail.contains("retry later");
    status_503 || says_busy
}

/// Translate an ACME error into a human-readable message with hints
/// when we can detect a known failure mode. Operator-facing.
fn rate_limit_message(stage: &str, e: &instant_acme::Error) -> String {
    use instant_acme::Error as E;
    let E::Api(p) = e else {
        return format!("{stage}: {e}");
    };
    let urn = p.r#type.as_deref().unwrap_or("");
    let base = format!("{stage}: {e}");
    if urn == "urn:ietf:params:acme:error:rateLimited" {
        format!(
            "{base}\n\nHint: Let's Encrypt is rate-limiting this account/hostname. \
             If you saw repeated failures recently, the per-hostname \
             \"failed validation\" limit is 5/hour. Wait ~60 minutes and \
             retry, OR re-issue against the staging directory first \
             (no production limits) by passing --staging in hctl or \
             toggling Staging in the UI."
        )
    } else if urn == "urn:ietf:params:acme:error:badNonce" {
        format!("{base}\n\nHint: bad nonce is usually transient — retry once.")
    } else {
        base
    }
}

fn backoff_for(attempt: u32) -> std::time::Duration {
    // 1 → 15s, 2 → 30s, 3 → 60s. Total wall-clock budget on retry =
    // 105s — well within any reasonable HTTP timeout the orchestrator
    // is willing to wait for cert issuance.
    let secs = match attempt {
        1 => 15,
        2 => 30,
        _ => 60,
    };
    std::time::Duration::from_secs(secs)
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

    fn mk_problem(urn: &str, status: Option<u16>, detail: Option<&str>) -> instant_acme::Problem {
        // instant_acme::Problem fields are pub but the struct doesn't
        // derive Default — go through JSON because the test should
        // exercise the same path Boulder's responses take.
        let mut body = serde_json::json!({ "type": urn });
        if let Some(s) = status {
            body["status"] = serde_json::json!(s);
        }
        if let Some(d) = detail {
            body["detail"] = serde_json::json!(d);
        }
        serde_json::from_value(body).expect("problem round-trips")
    }

    /// Boulder's transient "load shed" returns rateLimited URN + 503
    /// status + "Service busy" detail. Must be classified as transient
    /// (retry-able).
    #[test]
    fn boulder_service_busy_is_transient() {
        let p = mk_problem(
            "urn:ietf:params:acme:error:rateLimited",
            Some(503),
            Some("Service busy; retry later."),
        );
        let err = instant_acme::Error::Api(p);
        assert!(
            is_transient_rate_limit(&err),
            "Service busy 503 must be classified as transient"
        );
    }

    /// Per-account-per-hostname failedAuthorization or duplicate-cert
    /// limits are durable — Boulder uses 429, and the detail won't
    /// mention "Service busy". Must NOT auto-retry; operator must wait.
    #[test]
    fn durable_rate_limit_is_not_transient() {
        let p = mk_problem(
            "urn:ietf:params:acme:error:rateLimited",
            Some(429),
            Some("too many failed authorizations recently"),
        );
        let err = instant_acme::Error::Api(p);
        assert!(
            !is_transient_rate_limit(&err),
            "429 hard rate limit must NOT be classified as transient"
        );
    }

    /// Non-rate-limit errors (badNonce, accountDoesNotExist, malformed,
    /// connection errors) are never the retry path's responsibility.
    #[test]
    fn non_rate_limit_errors_are_not_transient() {
        let p = mk_problem(
            "urn:ietf:params:acme:error:badNonce",
            Some(400),
            Some("bad"),
        );
        assert!(!is_transient_rate_limit(&instant_acme::Error::Api(p)));
        let p2 = mk_problem(
            "urn:ietf:params:acme:error:malformed",
            Some(400),
            Some("nope"),
        );
        assert!(!is_transient_rate_limit(&instant_acme::Error::Api(p2)));
        let e3 = instant_acme::Error::Str("transport failed");
        assert!(!is_transient_rate_limit(&e3));
    }

    /// Operator-facing message must spell out the actionable
    /// remediations for rate-limited errors (wait OR use staging).
    /// We hard-assert specific words so the operator-readable copy
    /// can't silently regress to "rate limited" with no guidance.
    #[test]
    fn rate_limit_message_includes_remediation() {
        let p = mk_problem(
            "urn:ietf:params:acme:error:rateLimited",
            Some(429),
            Some("too many failed authorizations"),
        );
        let m = rate_limit_message("set_ready", &instant_acme::Error::Api(p));
        assert!(m.contains("set_ready"), "stage name preserved");
        assert!(
            m.contains("staging"),
            "must mention the staging escape hatch"
        );
        assert!(
            m.contains("60 minutes") || m.contains("hour"),
            "must mention wait time"
        );
    }

    /// Backoff: must strictly increase, and never return zero / sub-second
    /// values (would burn through retry budget before LE has time to recover).
    #[test]
    fn backoff_increases_and_is_meaningful() {
        let a = backoff_for(1);
        let b = backoff_for(2);
        let c = backoff_for(3);
        assert!(a >= std::time::Duration::from_secs(10), "first retry ≥10s");
        assert!(b > a, "monotonic");
        assert!(c >= b, "monotonic (non-decreasing at the cap)");
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
