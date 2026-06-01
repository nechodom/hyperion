//! Production `AdapterPort` implementation. Glues the orchestrator to
//! `lm-adapters`. Runs on Debian as root via the lm-agent systemd service.

use crate::service::AdapterPort;
use async_trait::async_trait;
use lm_adapters::AdapterError;
use lm_rpc::wire::DbCredentials;
use lm_types::{CertInfo, DbProvision, HostingDetail, HostingId, PhpVersion};
use lm_validate::SystemUserName;
use std::path::PathBuf;

pub struct RealAdapter {
    pub nginx_paths: lm_adapters::nginx::Paths,
    pub certs_root: PathBuf,
    pub acme_challenge_root: PathBuf,
    pub acme_email: String,
    pub acme_directory_url: String,
}

impl Default for RealAdapter {
    fn default() -> Self {
        Self {
            nginx_paths: lm_adapters::nginx::Paths::debian_defaults(),
            certs_root: PathBuf::from("/etc/linux-manager/certs"),
            acme_challenge_root: PathBuf::from("/var/lib/linux-manager/acme-challenges"),
            acme_email: "admin@example.com".into(),
            acme_directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
        }
    }
}

#[async_trait]
impl AdapterPort for RealAdapter {
    async fn ensure_user(&self, name: &str, home_dir: &str) -> Result<u32, AdapterError> {
        let spec = lm_adapters::users::UserSpec::new_with_default_shell(
            SystemUserName::parse(name)?,
            home_dir.to_string(),
        );
        let info = lm_adapters::users::ensure_user(&spec).await?;
        Ok(info.uid)
    }

    async fn delete_user(&self, name: &str) -> Result<(), AdapterError> {
        let n = SystemUserName::parse(name)?;
        lm_adapters::users::delete_user(&n).await
    }

    async fn ensure_dirs(
        &self,
        htdocs: &str,
        logs: &str,
        tmp: &str,
        owner_uid: u32,
    ) -> Result<(), AdapterError> {
        for p in [htdocs, logs, tmp] {
            lm_adapters::fs::ensure_dir(std::path::Path::new(p), 0o750).await?;
            // chown best-effort via Unix syscall; ignore EPERM on non-root setups.
            let path_c = std::ffi::CString::new(p)
                .map_err(|e| AdapterError::Other(format!("path C-string: {e}")))?;
            // SAFETY: We DO NOT use unsafe code anywhere — call chown via the `nix` crate
            // (forbid(unsafe_code) at lib root). We use std::process::Command instead.
            let _ = path_c;
            let res = tokio::process::Command::new("/usr/bin/chown")
                .arg(format!("{}:{}", owner_uid, owner_uid))
                .arg(p)
                .output()
                .await;
            if let Err(e) = res {
                tracing::warn!(error=%e, path=%p, "chown failed (non-fatal on non-root)");
            }
        }
        Ok(())
    }

    async fn remove_hosting_tree(&self, root: &str) -> Result<(), AdapterError> {
        lm_adapters::fs::remove_dir_all(std::path::Path::new(root)).await
    }

    async fn fpm_ensure(
        &self,
        system_user: &str,
        domain: &str,
        version: PhpVersion,
    ) -> Result<(), AdapterError> {
        let input = lm_adapters::phpfpm::PoolInput::defaults(system_user, domain, version);
        lm_adapters::phpfpm::ensure_pool(&input).await?;
        Ok(())
    }

    async fn fpm_delete(&self, system_user: &str, version: PhpVersion) -> Result<(), AdapterError> {
        lm_adapters::phpfpm::delete_pool(system_user, version).await
    }

    async fn db_create(
        &self,
        engine: DbProvision,
        hosting_id: &HostingId,
        domain: &str,
    ) -> Result<DbCredentials, AdapterError> {
        match engine {
            DbProvision::MariaDB => {
                let r = lm_adapters::mariadb::create_db_and_user(hosting_id, domain).await?;
                Ok(DbCredentials {
                    engine,
                    db_name: r.db_name,
                    db_user: r.db_user,
                    password: r.password,
                })
            }
            DbProvision::Postgres => {
                let r = lm_adapters::postgres::create_db_and_role(hosting_id, domain).await?;
                Ok(DbCredentials {
                    engine,
                    db_name: r.db_name,
                    db_user: r.db_user,
                    password: r.password,
                })
            }
        }
    }

    async fn db_drop(
        &self,
        engine: DbProvision,
        db_name: &str,
        db_user: &str,
    ) -> Result<(), AdapterError> {
        match engine {
            DbProvision::MariaDB => lm_adapters::mariadb::drop_db_and_user(db_name, db_user).await,
            DbProvision::Postgres => {
                lm_adapters::postgres::drop_db_and_role(db_name, db_user).await
            }
        }
    }

    async fn acme_issue(&self, domain: &str, sans: &[String]) -> Result<CertInfo, AdapterError> {
        // Foundation note: a full ACME HTTP-01 flow with nginx temp vhost
        // coordination is deferred to sub-project 9 hardening / a follow-up
        // task. For now we generate a self-signed cert via rcgen and write
        // it to disk so the rest of the pipeline (DB row + nginx vhost)
        // works end-to-end on first boot. Operators replace via
        // `lm cert renew` once the ACME loop ships.
        let mut all_names = vec![domain.to_string()];
        all_names.extend(sans.iter().cloned());
        let params = rcgen::CertificateParams::new(all_names.clone())
            .map_err(|e| AdapterError::Acme(format!("rcgen params: {e}")))?;
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| AdapterError::Acme(format!("rcgen keypair: {e}")))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| AdapterError::Acme(format!("rcgen sign: {e}")))?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let domain_dir = self.certs_root.join(domain);
        lm_adapters::fs::ensure_dir(&domain_dir, 0o700).await?;
        lm_adapters::fs::atomic_write(
            &domain_dir.join("fullchain.pem"),
            cert_pem.as_bytes(),
            0o644,
        )
        .await?;
        lm_adapters::fs::atomic_write(&domain_dir.join("privkey.pem"), key_pem.as_bytes(), 0o600)
            .await?;
        // not_after = now + 365 days as rcgen default
        let not_after = lm_types::now_secs() + 365 * 24 * 3600;
        Ok(CertInfo {
            domain: domain.to_string(),
            sans: sans.to_vec(),
            issuer: "self-signed".into(),
            not_after,
            fingerprint_sha256: lm_adapters::acme::fingerprint_sha256_der(cert_pem.as_bytes()),
        })
    }

    async fn acme_delete(&self, domain: &str) -> Result<(), AdapterError> {
        let domain_dir = self.certs_root.join(domain);
        lm_adapters::fs::remove_dir_all(&domain_dir).await
    }

    async fn nginx_write_vhost(&self, detail: &HostingDetail) -> Result<(), AdapterError> {
        let cert_path = format!(
            "{}/{}/fullchain.pem",
            self.certs_root.display(),
            detail.domain
        );
        let key_path = format!(
            "{}/{}/privkey.pem",
            self.certs_root.display(),
            detail.domain
        );
        let logs_dir = detail.root_dir.replace("/htdocs", "/logs");
        let acme_root = self.acme_challenge_root.display().to_string();
        let php = detail.php_version.map(|v| v.as_str());
        let input = lm_adapters::nginx::VhostInput {
            domain: &detail.domain,
            aliases: &detail.aliases,
            root_dir: &detail.root_dir,
            logs_dir: &logs_dir,
            system_user: &detail.system_user,
            php_version: php,
            cert_path: &cert_path,
            key_path: &key_path,
            acme_challenge_root: &acme_root,
        };
        lm_adapters::nginx::write_vhost(&self.nginx_paths, &input).await
    }

    async fn nginx_delete_vhost(&self, domain: &str) -> Result<(), AdapterError> {
        lm_adapters::nginx::delete_vhost(&self.nginx_paths, domain).await
    }

    async fn nginx_apply_suspended(
        &self,
        domain: &str,
        reason_message: Option<String>,
    ) -> Result<(), AdapterError> {
        let cert_path = format!("{}/{}/fullchain.pem", self.certs_root.display(), domain);
        let key_path = format!("{}/{}/privkey.pem", self.certs_root.display(), domain);
        let msg =
            reason_message.unwrap_or_else(|| "This site is temporarily unavailable.".to_string());
        let input = lm_adapters::nginx::SuspendedInput {
            domain,
            cert_path: &cert_path,
            key_path: &key_path,
            reason_message: &msg,
        };
        lm_adapters::nginx::apply_suspended(&self.nginx_paths, &input).await
    }

    async fn apply_php_limits(
        &self,
        system_user: &str,
        domain: &str,
        version: Option<PhpVersion>,
        php_memory_mb: i64,
        php_max_exec_secs: i64,
        php_max_children: i64,
        php_max_requests: i64,
    ) -> Result<(), AdapterError> {
        let Some(ver) = version else {
            return Ok(());
        };
        let mut input = lm_adapters::phpfpm::PoolInput::defaults(system_user, domain, ver);
        input.memory_mb = php_memory_mb.max(16) as u32;
        input.max_exec_secs = php_max_exec_secs.max(1) as u32;
        input.max_children = php_max_children.max(1) as u32;
        input.max_requests = php_max_requests.max(0) as u32;
        lm_adapters::phpfpm::ensure_pool(&input).await?;
        Ok(())
    }

    async fn db_lock(&self, engine: DbProvision, db_user: &str) -> Result<(), AdapterError> {
        match engine {
            DbProvision::MariaDB => lm_adapters::mariadb::lock_user(db_user).await,
            DbProvision::Postgres => lm_adapters::postgres::lock_role(db_user).await,
        }
    }

    async fn db_unlock(&self, engine: DbProvision, db_user: &str) -> Result<(), AdapterError> {
        match engine {
            DbProvision::MariaDB => lm_adapters::mariadb::unlock_user(db_user).await,
            DbProvision::Postgres => lm_adapters::postgres::unlock_role(db_user).await,
        }
    }

    async fn linux_lock_login(&self, name: &str) -> Result<(), AdapterError> {
        let n = SystemUserName::parse(name)?;
        lm_adapters::users::lock_login(&n).await
    }

    async fn linux_unlock_login(&self, name: &str) -> Result<(), AdapterError> {
        let n = SystemUserName::parse(name)?;
        lm_adapters::users::unlock_login(&n).await
    }

    async fn kill_user_procs(&self, name: &str) -> Result<(), AdapterError> {
        let n = SystemUserName::parse(name)?;
        lm_adapters::users::kill_user_procs(&n).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_adapter_default_paths() {
        let a = RealAdapter::default();
        assert_eq!(
            a.nginx_paths.vhost_file("x.cz").to_string_lossy(),
            "/etc/nginx/sites-available/x.cz.conf"
        );
        assert_eq!(
            a.certs_root.display().to_string(),
            "/etc/linux-manager/certs"
        );
    }

    #[tokio::test]
    async fn acme_issue_writes_self_signed_files() {
        let d = tempfile::tempdir().expect("tempdir");
        let a = RealAdapter {
            certs_root: d.path().to_path_buf(),
            ..Default::default()
        };
        let info = a
            .acme_issue("example.cz", &["www.example.cz".to_string()])
            .await
            .expect("issue");
        assert_eq!(info.domain, "example.cz");
        assert_eq!(info.issuer, "self-signed");
        let cert_path = d.path().join("example.cz/fullchain.pem");
        let key_path = d.path().join("example.cz/privkey.pem");
        assert!(cert_path.exists());
        assert!(key_path.exists());
        // verify PEM markers
        let cert = std::fs::read_to_string(&cert_path).expect("read");
        assert!(cert.contains("BEGIN CERTIFICATE"));
        let key = std::fs::read_to_string(&key_path).expect("read");
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }
}
