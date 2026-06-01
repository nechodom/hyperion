//! nginx vhost generation + reload.

use crate::{cmd, fs::atomic_write, AdapterError};
use askama::Template;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct VhostInput<'a> {
    pub domain: &'a str,
    pub aliases: &'a [String],
    pub root_dir: &'a str,
    pub logs_dir: &'a str,
    pub system_user: &'a str,
    pub php_version: Option<&'a str>,
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub acme_challenge_root: &'a str,
}

#[derive(Template)]
#[template(path = "nginx-vhost.conf.j2", escape = "none")]
struct VhostTpl<'a> {
    domain: &'a str,
    aliases: &'a [String],
    root_dir: &'a str,
    logs_dir: &'a str,
    system_user: &'a str,
    has_php: bool,
    php_version: &'a str,
    cert_path: &'a str,
    key_path: &'a str,
    acme_challenge_root: &'a str,
}

/// Render the vhost file's contents without writing.
#[derive(askama::Template)]
#[template(path = "nginx-vhost-suspended.conf.j2", escape = "none")]
struct SuspendedTpl<'a> {
    domain: &'a str,
    cert_path: &'a str,
    key_path: &'a str,
    reason_message: &'a str,
}

#[derive(Debug, Clone)]
pub struct SuspendedInput<'a> {
    pub domain: &'a str,
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub reason_message: &'a str,
}

/// Render the suspended-state vhost.
pub fn render_suspended(input: &SuspendedInput<'_>) -> Result<String, AdapterError> {
    let tpl = SuspendedTpl {
        domain: input.domain,
        cert_path: input.cert_path,
        key_path: input.key_path,
        reason_message: input.reason_message,
    };
    Ok(tpl.render()?)
}

/// Swap the vhost to the suspended variant.
pub async fn apply_suspended(
    paths: &Paths,
    input: &SuspendedInput<'_>,
) -> Result<(), AdapterError> {
    let body = render_suspended(input)?;
    let vhost = paths.vhost_file(input.domain);
    crate::fs::atomic_write(&vhost, body.as_bytes(), 0o644).await?;
    let symlink = paths.symlink_file(input.domain);
    ensure_symlink(&vhost, &symlink).await?;
    reload().await
}

pub fn render(input: &VhostInput<'_>) -> Result<String, AdapterError> {
    let tpl = VhostTpl {
        domain: input.domain,
        aliases: input.aliases,
        root_dir: input.root_dir,
        logs_dir: input.logs_dir,
        system_user: input.system_user,
        has_php: input.php_version.is_some(),
        php_version: input.php_version.unwrap_or(""),
        cert_path: input.cert_path,
        key_path: input.key_path,
        acme_challenge_root: input.acme_challenge_root,
    };
    Ok(tpl.render()?)
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub sites_available: PathBuf,
    pub sites_enabled: PathBuf,
}

impl Paths {
    pub fn debian_defaults() -> Self {
        Self {
            sites_available: PathBuf::from("/etc/nginx/sites-available"),
            sites_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
        }
    }
    pub fn vhost_file(&self, domain: &str) -> PathBuf {
        self.sites_available.join(format!("{domain}.conf"))
    }
    pub fn symlink_file(&self, domain: &str) -> PathBuf {
        self.sites_enabled.join(format!("{domain}.conf"))
    }
}

/// Write vhost + create symlink + `nginx -t` + reload. Idempotent.
pub async fn write_vhost(paths: &Paths, input: &VhostInput<'_>) -> Result<(), AdapterError> {
    let body = render(input)?;
    let vhost = paths.vhost_file(input.domain);
    let backup = backup_existing(&vhost).await?;
    atomic_write(&vhost, body.as_bytes(), 0o644).await?;
    let symlink = paths.symlink_file(input.domain);
    ensure_symlink(&vhost, &symlink).await?;
    if let Err(e) = cmd::run("/usr/sbin/nginx", &["-t"]).await {
        // Restore previous state.
        restore_or_remove(&vhost, backup.as_deref()).await;
        let _ = tokio::fs::remove_file(&symlink).await;
        return Err(e);
    }
    reload().await
}

/// Remove vhost + symlink + reload. Safe if files already absent.
pub async fn delete_vhost(paths: &Paths, domain: &str) -> Result<(), AdapterError> {
    let _ = tokio::fs::remove_file(paths.symlink_file(domain)).await;
    let _ = tokio::fs::remove_file(paths.vhost_file(domain)).await;
    reload().await
}

pub async fn reload() -> Result<(), AdapterError> {
    cmd::run("/usr/bin/systemctl", &["reload", "nginx"]).await?;
    Ok(())
}

async fn backup_existing(path: &Path) -> Result<Option<PathBuf>, AdapterError> {
    if tokio::fs::metadata(path).await.is_ok() {
        let mut backup = path.as_os_str().to_owned();
        backup.push(".lm-bak");
        let backup = PathBuf::from(backup);
        tokio::fs::copy(path, &backup).await?;
        Ok(Some(backup))
    } else {
        Ok(None)
    }
}

async fn restore_or_remove(target: &Path, backup: Option<&Path>) {
    if let Some(b) = backup {
        let _ = tokio::fs::rename(b, target).await;
    } else {
        let _ = tokio::fs::remove_file(target).await;
    }
}

async fn ensure_symlink(target: &Path, link: &Path) -> Result<(), AdapterError> {
    if let Some(parent) = link.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    match tokio::fs::symlink_metadata(link).await {
        Ok(_) => {
            // Already exists. Re-point (best effort).
            let _ = tokio::fs::remove_file(link).await;
        }
        Err(_) => {}
    }
    tokio::fs::symlink(target, link).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_static_no_php() {
        let aliases: Vec<String> = vec![];
        let out = render(&VhostInput {
            domain: "example.cz",
            aliases: &aliases,
            root_dir: "/home/example_cz/example.cz/htdocs",
            logs_dir: "/home/example_cz/example.cz/logs",
            system_user: "example_cz",
            php_version: None,
            cert_path: "/etc/lm/certs/example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
        })
        .expect("render");
        assert!(out.contains("server_name example.cz;"));
        assert!(!out.contains("fastcgi_pass"));
        assert!(out.contains("try_files $uri $uri/ =404"));
        assert!(out.contains("Strict-Transport-Security"));
        assert!(out.contains("ssl_certificate     /etc/lm/certs/example.cz/fullchain.pem"));
        assert!(out.contains("/var/lib/lm/acme-challenges"));
    }

    #[test]
    fn render_php_with_aliases() {
        let aliases = vec!["www.example.cz".to_string(), "example.com".to_string()];
        let out = render(&VhostInput {
            domain: "example.cz",
            aliases: &aliases,
            root_dir: "/home/example_cz/example.cz/htdocs",
            logs_dir: "/home/example_cz/example.cz/logs",
            system_user: "example_cz",
            php_version: Some("8.3"),
            cert_path: "/etc/lm/certs/example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
        })
        .expect("render");
        assert!(out.contains("server_name example.cz www.example.cz example.com;"));
        assert!(out.contains("fastcgi_pass unix:/run/php/8.3/example_cz.sock"));
        assert!(out.contains("try_files $uri $uri/ /index.php?$args"));
    }

    #[test]
    fn paths_helpers() {
        let p = Paths::debian_defaults();
        assert_eq!(
            p.vhost_file("example.cz"),
            Path::new("/etc/nginx/sites-available/example.cz.conf")
        );
        assert_eq!(
            p.symlink_file("example.cz"),
            Path::new("/etc/nginx/sites-enabled/example.cz.conf")
        );
    }
}
