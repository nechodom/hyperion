//! Validation + normalization for operator-uploaded TLS certificates.
//!
//! Backs the `CertUpload` RPC for the non-ACME cases — a private CA, a
//! pre-purchased multi-year cert, or a self-signed bootstrap. Everything
//! here is **pure** (no disk, no network) and **never logs or embeds
//! private-key bytes**: the caller writes the validated material out
//! itself, and every [`CertError`] `Display` is safe to show the operator.
//!
//! The two checks that matter for security:
//! 1. the supplied private key actually matches the leaf certificate's
//!    public key (otherwise nginx serves a cert it can't complete a
//!    handshake for), verified via rustls' [`CertifiedKey::keys_match`];
//! 2. the certificate's CN / SANs cover every name the hosting serves
//!    (primary domain + aliases), with proper single-label wildcard
//!    matching — a cert for the wrong domain is rejected.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use std::io::Cursor;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Why an uploaded certificate/key pair was rejected. `Display` is safe
/// to surface to the operator — it never contains private-key material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CertError {
    #[error("certificate PEM contained no certificate")]
    NoCertificate,
    #[error("private key PEM contained no usable private key")]
    NoPrivateKey,
    #[error("certificate could not be parsed: {0}")]
    BadCertificate(String),
    #[error("private key is malformed or uses an unsupported algorithm")]
    BadPrivateKey,
    #[error("the private key does not match the certificate's public key")]
    KeyMismatch,
    #[error("certificate does not cover required name(s): {0}")]
    UncoveredDomains(String),
}

/// A successfully validated upload. The caller writes `fullchain_pem` to
/// `fullchain.pem` (0644) and the operator's key to `privkey.pem` (0600).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCert {
    /// Leaf certificate followed by any supplied CA bundle, ready to be
    /// served as nginx `ssl_certificate`.
    pub fullchain_pem: String,
    /// Leaf `notAfter`, as a unix timestamp.
    pub not_after: i64,
    /// Concise issuer label (Organization → CN → full DN → "custom").
    /// Free-form, and deliberately never the literal "letsencrypt" for a
    /// real CA, so the ACME renewal sweep's issuer filter can't mistake an
    /// uploaded cert for one it should auto-renew.
    pub issuer: String,
    /// Hostnames the leaf actually covers (host-shaped subject CN + every
    /// DNS SAN), lowercased and deduped. For display.
    pub covered_names: Vec<String>,
    /// Opaque content fingerprint for the UI.
    pub fingerprint: String,
}

/// Validate `cert_pem` + `key_pem` (+ optional `ca_bundle_pem`) for a
/// hosting whose certificate must cover every name in `required_names`
/// (primary domain followed by aliases).
///
/// On success the leaf parses, the key matches it, and every required
/// name is covered. The returned `fullchain_pem` is the leaf chain with
/// the CA bundle appended.
pub fn validate_upload(
    cert_pem: &str,
    key_pem: &str,
    ca_bundle_pem: Option<&str>,
    required_names: &[String],
) -> Result<ValidatedCert, CertError> {
    // 1. Parse the certificate chain (leaf first) and the private key.
    let chain = parse_chain(cert_pem)?;
    let key_der = parse_private_key(key_pem)?;

    // 2. Cross-check that the supplied key actually matches the leaf's
    //    public key. rustls extracts the SPKI from both sides (RSA /
    //    ECDSA-P256/P384 / Ed25519 all supported by the ring provider) and
    //    compares them. A failure here — or a key whose public half can't
    //    be recovered — is rejected rather than written to disk.
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|_| CertError::BadPrivateKey)?;
    let certified = CertifiedKey::new(chain.clone(), signing_key);
    certified.keys_match().map_err(|_| CertError::KeyMismatch)?;

    // 3. Pull the metadata we need out of the leaf, then check coverage.
    let leaf_der = chain[0].as_ref();
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|e| CertError::BadCertificate(e.to_string()))?;

    let covered_names = covered_names_of(&leaf);
    let mut missing: Vec<String> = Vec::new();
    for need in required_names {
        let need = need.trim().trim_end_matches('.').to_ascii_lowercase();
        if need.is_empty() {
            continue;
        }
        if !covered_names.iter().any(|pat| name_matches(pat, &need)) {
            missing.push(need);
        }
    }
    missing.sort();
    missing.dedup();
    if !missing.is_empty() {
        return Err(CertError::UncoveredDomains(missing.join(", ")));
    }

    let not_after = leaf.validity().not_after.timestamp();
    let issuer = issuer_label(&leaf);
    let fingerprint = crate::acme::fingerprint_sha256_der(leaf_der);

    // 4. Build the fullchain text: operator's cert (leaf, possibly already
    //    chained) followed by any supplied CA bundle. nginx wants the leaf
    //    first, which the operator's PEM already provides.
    let mut fullchain_pem = cert_pem.trim().to_string();
    fullchain_pem.push('\n');
    if let Some(ca) = ca_bundle_pem {
        let ca = ca.trim();
        if !ca.is_empty() {
            fullchain_pem.push_str(ca);
            fullchain_pem.push('\n');
        }
    }

    Ok(ValidatedCert {
        fullchain_pem,
        not_after,
        issuer,
        covered_names,
        fingerprint,
    })
}

/// Parse every `CERTIFICATE` block in `pem` (leaf first). Empty ⇒
/// [`CertError::NoCertificate`]; a malformed block ⇒
/// [`CertError::BadCertificate`].
fn parse_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>, CertError> {
    let mut rd = Cursor::new(pem.as_bytes());
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut rd) {
        match item {
            Ok(der) => out.push(der),
            Err(e) => return Err(CertError::BadCertificate(e.to_string())),
        }
    }
    if out.is_empty() {
        return Err(CertError::NoCertificate);
    }
    Ok(out)
}

/// Parse the first private key in `pem`. None present ⇒
/// [`CertError::NoPrivateKey`].
fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, CertError> {
    let mut rd = Cursor::new(pem.as_bytes());
    match rustls_pemfile::private_key(&mut rd) {
        Ok(Some(k)) => Ok(k),
        Ok(None) | Err(_) => Err(CertError::NoPrivateKey),
    }
}

/// Hostnames the leaf covers: a host-shaped subject CN plus every DNS
/// SAN, lowercased + deduped.
fn covered_names_of(leaf: &X509Certificate) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for cn in leaf.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            let s = s.trim();
            if looks_like_hostname(s) {
                names.push(s.to_ascii_lowercase());
            }
        }
    }
    if let Ok(Some(san)) = leaf.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::DNSName(d) = gn {
                let d = d.trim();
                if !d.is_empty() {
                    names.push(d.to_ascii_lowercase());
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// A concise, display-friendly issuer label. Prefers Organization, then
/// CN, then the full distinguished name, falling back to "custom" for an
/// empty issuer (e.g. a self-signed bootstrap cert).
fn issuer_label(leaf: &X509Certificate) -> String {
    let first_nonempty = |it: &mut dyn Iterator<Item = &str>| -> Option<String> {
        it.map(str::trim).find(|s| !s.is_empty()).map(String::from)
    };
    let mut orgs = leaf
        .issuer()
        .iter_organization()
        .filter_map(|a| a.as_str().ok());
    if let Some(o) = first_nonempty(&mut orgs) {
        return o;
    }
    let mut cns = leaf
        .issuer()
        .iter_common_name()
        .filter_map(|a| a.as_str().ok());
    if let Some(cn) = first_nonempty(&mut cns) {
        return cn;
    }
    let dn = leaf.issuer().to_string();
    if dn.trim().is_empty() {
        "custom".to_string()
    } else {
        dn
    }
}

/// Loose "is this a hostname, not free text" check for a subject CN —
/// has a dot, no spaces, no `@`.
fn looks_like_hostname(s: &str) -> bool {
    !s.is_empty() && s.contains('.') && !s.contains(char::is_whitespace) && !s.contains('@')
}

/// True when the certificate name `pattern` (possibly a `*.foo` wildcard)
/// matches the concrete hostname `host`. Wildcards match exactly one
/// left-most label — `*.example.com` matches `www.example.com` but not
/// `example.com` (apex) nor `a.b.example.com` (nested). Case-insensitive.
pub(crate) fn name_matches(pattern: &str, host: &str) -> bool {
    // Normalize both sides identically — including a trailing FQDN-root
    // dot, which a SAN may carry (`example.com.`) but the required name
    // won't.
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) if !suffix.is_empty() => {
            // host must be exactly "<single-label>.<suffix>".
            match host.strip_suffix(suffix).and_then(|p| p.strip_suffix('.')) {
                Some(label) => !label.is_empty() && !label.contains('.'),
                None => false,
            }
        }
        _ => pattern == host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed cert + matching key covering `names` (as DNS SANs).
    fn gen(names: &[&str]) -> (String, String) {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let params = rcgen::CertificateParams::new(names).expect("params");
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("sign");
        (cert.pem(), key.serialize_pem())
    }

    fn req(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_matching_key_and_covered_domain() {
        let (cert, key) = gen(&["example.com"]);
        let v = validate_upload(&cert, &key, None, &req(&["example.com"])).expect("valid");
        assert!(v.not_after > 0);
        assert!(v.covered_names.contains(&"example.com".to_string()));
        assert!(v.fullchain_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn rejects_key_that_does_not_match_cert() {
        let (cert, _key) = gen(&["example.com"]);
        // A second, independent keypair — same SAN, different key.
        let (_c2, other_key) = gen(&["example.com"]);
        let err = validate_upload(&cert, &other_key, None, &req(&["example.com"])).unwrap_err();
        assert_eq!(err, CertError::KeyMismatch);
    }

    #[test]
    fn rejects_cert_that_does_not_cover_domain() {
        let (cert, key) = gen(&["example.com"]);
        let err = validate_upload(&cert, &key, None, &req(&["other.com"])).unwrap_err();
        match err {
            CertError::UncoveredDomains(s) => assert!(s.contains("other.com"), "got: {s}"),
            e => panic!("expected UncoveredDomains, got {e:?}"),
        }
    }

    #[test]
    fn wildcard_san_covers_subdomain_but_not_apex_or_nested() {
        let (cert, key) = gen(&["*.example.com"]);
        validate_upload(&cert, &key, None, &req(&["www.example.com"])).expect("covers www");
        assert!(
            validate_upload(&cert, &key, None, &req(&["example.com"])).is_err(),
            "wildcard must not cover the apex"
        );
        assert!(
            validate_upload(&cert, &key, None, &req(&["a.b.example.com"])).is_err(),
            "wildcard must not cover a nested label"
        );
    }

    #[test]
    fn requires_every_alias_to_be_covered() {
        let (cert, key) = gen(&["example.com", "www.example.com"]);
        validate_upload(&cert, &key, None, &req(&["example.com", "www.example.com"]))
            .expect("both covered");
        let err = validate_upload(
            &cert,
            &key,
            None,
            &req(&["example.com", "shop.example.com"]),
        )
        .unwrap_err();
        match err {
            CertError::UncoveredDomains(s) => assert!(s.contains("shop.example.com"), "got: {s}"),
            e => panic!("expected UncoveredDomains, got {e:?}"),
        }
    }

    #[test]
    fn rejects_garbage_cert_pem() {
        let (_c, key) = gen(&["example.com"]);
        let garbage =
            "-----BEGIN CERTIFICATE-----\nnot valid base64 @@@\n-----END CERTIFICATE-----\n";
        let err = validate_upload(garbage, &key, None, &req(&["example.com"])).unwrap_err();
        assert!(
            matches!(err, CertError::NoCertificate | CertError::BadCertificate(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_empty_key_pem() {
        let (cert, _key) = gen(&["example.com"]);
        let err = validate_upload(&cert, "", None, &req(&["example.com"])).unwrap_err();
        assert_eq!(err, CertError::NoPrivateKey);
    }

    #[test]
    fn appends_ca_bundle_to_fullchain() {
        let (cert, key) = gen(&["example.com"]);
        let (ca, _k) = gen(&["ca.example.com"]); // stand-in intermediate
        let v = validate_upload(&cert, &key, Some(&ca), &req(&["example.com"])).expect("ok");
        let n = v.fullchain_pem.matches("BEGIN CERTIFICATE").count();
        assert_eq!(n, 2, "fullchain = leaf + ca bundle");
    }

    #[test]
    fn ed25519_key_match_is_supported() {
        // Exercise a second key algorithm through keys_match.
        let params =
            rcgen::CertificateParams::new(vec!["ed.example.com".to_string()]).expect("params");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key");
        let cert = params.self_signed(&key).expect("sign");
        let v = validate_upload(
            &cert.pem(),
            &key.serialize_pem(),
            None,
            &req(&["ed.example.com"]),
        )
        .expect("valid ed25519");
        assert!(v.covered_names.contains(&"ed.example.com".to_string()));
    }

    #[test]
    fn issuer_is_not_letsencrypt_for_uploaded_cert() {
        let (cert, key) = gen(&["example.com"]);
        let v = validate_upload(&cert, &key, None, &req(&["example.com"])).expect("ok");
        assert!(
            !v.issuer.starts_with("letsencrypt"),
            "uploaded issuer must not collide with the ACME renewal filter, got: {}",
            v.issuer
        );
    }

    #[test]
    fn name_matches_wildcard_rules() {
        assert!(name_matches("example.com", "example.com"));
        assert!(
            name_matches("EXAMPLE.com", "example.com"),
            "case-insensitive"
        );
        assert!(name_matches("*.example.com", "www.example.com"));
        assert!(!name_matches("*.example.com", "example.com"), "apex");
        assert!(!name_matches("*.example.com", "a.b.example.com"), "nested");
        assert!(!name_matches("*.example.com", "www.other.com"));
        assert!(
            !name_matches("*.example.com", "example.com.evil.com"),
            "suffix confusion"
        );
        assert!(!name_matches("", "example.com"));
        assert!(!name_matches("*.example.com", ""));
        // A SAN written in FQDN-root form still matches.
        assert!(name_matches("example.com.", "example.com"));
        assert!(name_matches("*.example.com.", "www.example.com"));
    }
}
