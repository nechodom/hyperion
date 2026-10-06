//! Certificate selection for the phpMyAdmin listener (`[web] pma_listen`).
//!
//! The listener is its own port, so the browser checks its certificate
//! separately from the panel's 443. It must present the same publicly
//! trusted certificate nginx serves there, or every phpMyAdmin link opens on
//! `ERR_CERT_AUTHORITY_INVALID`.
//!
//! The certificate is picked per TLS handshake from the name the browser
//! asked for (SNI): `<certs_root>/<sni>/{fullchain,privkey}.pem` — the files
//! the panel vhost and every hosting vhost already point nginx at. A client
//! without SNI (a bare-IP URL) gets the panel hostname's certificate, and the
//! panel's own self-signed pair is the last resort.
//!
//! Choosing by SNI on every handshake means nothing has to be cached ahead
//! of time: an earlier version picked the certificate from the panel-hostname
//! cache at startup and refreshed it on a timer, and kept serving the
//! self-signed fallback in production. Loaded pairs are cached by the
//! certificate file's mtime, so a renewal is picked up on the next handshake
//! without a restart.

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Where issued certificates live (`<root>/<domain>/fullchain.pem`).
pub const CERTS_ROOT: &str = "/etc/hyperion/certs";

pub struct PmaCertResolver {
    certs_root: PathBuf,
    panel_hostname: Arc<tokio::sync::RwLock<String>>,
    fallback: Arc<CertifiedKey>,
    cache: Mutex<HashMap<String, (SystemTime, Arc<CertifiedKey>)>>,
}

impl std::fmt::Debug for PmaCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PmaCertResolver")
            .field("certs_root", &self.certs_root)
            .finish_non_exhaustive()
    }
}

impl PmaCertResolver {
    pub fn new(
        certs_root: impl Into<PathBuf>,
        panel_hostname: Arc<tokio::sync::RwLock<String>>,
        fallback_cert: &Path,
        fallback_key: &Path,
    ) -> anyhow::Result<Self> {
        let fallback = load_pair(fallback_cert, fallback_key)?;
        Ok(Self {
            certs_root: certs_root.into(),
            panel_hostname,
            fallback: Arc::new(fallback),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The pair for `name`, or `None` when there is no usable one on disk.
    fn for_name(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if !is_plain_hostname(&name) {
            return None;
        }
        let dir = self.certs_root.join(&name);
        let cert = dir.join("fullchain.pem");
        let key = dir.join("privkey.pem");
        let mtime = std::fs::metadata(&cert).and_then(|m| m.modified()).ok()?;
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((seen, ck)) = cache.get(&name) {
            if *seen == mtime {
                return Some(ck.clone());
            }
        }
        match load_pair(&cert, &key) {
            Ok(ck) => {
                tracing::info!(%name, cert=%cert.display(), "phpMyAdmin listener: serving certificate");
                let ck = Arc::new(ck);
                cache.insert(name, (mtime, ck.clone()));
                Some(ck)
            }
            Err(e) => {
                tracing::warn!(%name, cert=%cert.display(), error=%e,
                    "phpMyAdmin listener: certificate unusable — falling back");
                // Keep serving a previously good pair over the self-signed
                // one, and remember this mtime so the broken file is not
                // re-read (and re-logged) on every handshake.
                let prev = cache.get(&name).map(|(_, ck)| ck.clone())?;
                cache.insert(name, (mtime, prev.clone()));
                Some(prev)
            }
        }
    }

    fn pick(&self, sni: Option<&str>) -> Arc<CertifiedKey> {
        if let Some(ck) = sni.and_then(|n| self.for_name(n)) {
            return ck;
        }
        if sni.is_none() {
            let panel = self
                .panel_hostname
                .try_read()
                .map(|g| g.clone())
                .unwrap_or_default();
            if let Some(ck) = self.for_name(&panel) {
                return ck;
            }
        }
        self.fallback.clone()
    }
}

impl ResolvesServerCert for PmaCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.pick(hello.server_name()))
    }
}

/// The listener's rustls config: certificate chosen per handshake.
pub fn server_config(resolver: PmaCertResolver) -> rustls::ServerConfig {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

/// SNI is client-controlled and becomes a path component: allow only
/// a DNS name made of `[a-z0-9-]` labels.
fn is_plain_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn load_pair(cert: &Path, key: &Path) -> anyhow::Result<CertifiedKey> {
    let chain = CertificateDer::pem_file_iter(cert)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", cert.display()))?;
    if chain.is_empty() {
        anyhow::bail!("{} holds no certificate", cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", key.display()))?;
    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let ck = CertifiedKey::from_der(chain, key, &provider)
        .map_err(|e| anyhow::anyhow!("certificate and key do not match: {e}"))?;
    Ok(ck)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pair(dir: &Path, names: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(names)
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        std::fs::write(dir.join("fullchain.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("privkey.pem"), kp.serialize_pem()).unwrap();
    }

    fn resolver(root: &Path, panel: &str) -> PmaCertResolver {
        write_pair(&root.join("_fallback"), &["localhost"]);
        PmaCertResolver::new(
            root,
            Arc::new(tokio::sync::RwLock::new(panel.to_string())),
            &root.join("_fallback/fullchain.pem"),
            &root.join("_fallback/privkey.pem"),
        )
        .unwrap()
    }

    #[test]
    fn sni_with_a_cert_on_disk_gets_that_cert() {
        let d = tempfile::tempdir().unwrap();
        write_pair(&d.path().join("hos-1.example.cz"), &["hos-1.example.cz"]);
        let r = resolver(d.path(), "");
        let got = r.pick(Some("hos-1.example.cz"));
        assert!(!Arc::ptr_eq(&got, &r.fallback));
        // Case and a trailing root dot do not matter.
        let again = r.pick(Some("HOS-1.example.cz."));
        assert!(Arc::ptr_eq(&got, &again), "second handshake hits the cache");
    }

    #[test]
    fn no_sni_uses_the_panel_hostname() {
        let d = tempfile::tempdir().unwrap();
        write_pair(&d.path().join("panel.example.cz"), &["panel.example.cz"]);
        let r = resolver(d.path(), "panel.example.cz");
        assert!(!Arc::ptr_eq(&r.pick(None), &r.fallback));
    }

    #[test]
    fn unknown_or_hostile_names_get_the_fallback() {
        let d = tempfile::tempdir().unwrap();
        write_pair(&d.path().join("a.cz"), &["a.cz"]);
        let r = resolver(d.path(), "");
        for sni in ["nope.cz", "../a.cz", "a.cz/..", "_fallback", ""] {
            assert!(Arc::ptr_eq(&r.pick(Some(sni)), &r.fallback), "{sni}");
        }
        assert!(Arc::ptr_eq(&r.pick(None), &r.fallback));
    }

    #[test]
    fn renewal_is_picked_up_and_a_broken_renewal_keeps_the_old_pair() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("a.cz");
        write_pair(&dir, &["a.cz"]);
        let r = resolver(d.path(), "");
        let first = r.pick(Some("a.cz"));

        let bump = |secs| {
            let f = std::fs::File::options()
                .write(true)
                .open(dir.join("fullchain.pem"))
                .unwrap();
            f.set_modified(SystemTime::now() + std::time::Duration::from_secs(secs))
                .unwrap();
        };
        write_pair(&dir, &["a.cz"]);
        bump(10);
        let renewed = r.pick(Some("a.cz"));
        assert!(!Arc::ptr_eq(&first, &renewed));

        std::fs::write(dir.join("privkey.pem"), "garbage").unwrap();
        bump(20);
        assert!(Arc::ptr_eq(&r.pick(Some("a.cz")), &renewed));
    }
}
