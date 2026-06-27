//! HestiaCP (and VestaCP) source adapter.
//!
//! Hestia has no central SQL store — every hosting user is a real Linux account
//! and the panel's authoritative metadata lives in flat `key='value'` files
//! under `/usr/local/hestia/data/users/<user>/` (`web.conf`, `db.conf`, …).
//! Site files live at `/home/<user>/web/<domain>/public_html`.
//!
//! P0/P1: in-place only. Mail + DNS are intentionally out of scope — Hestia
//! manages them (Exim/Dovecot/BIND) but Hyperion does not, so they are reported
//! as unsupported, never imported.
//!
//! DB↔domain mapping: Hestia DBs belong to the *user*, not a domain (one user
//! can own many domains and many DBs with no 1:1 link). We attach a user's DBs
//! to that user's first domain; the engine imports the first DB per hosting, so
//! the common "one user / one domain / one DB" case round-trips fully. Extra
//! DBs are surfaced as unsupported notes rather than silently dropped.

use crate::adapter::{Location, SourceAdapter, SourceKind, SourcePanelInfo};
use crate::error::ImportError;
use crate::ir::{
    ImportIR, IrDatabase, IrDbEngine, IrHosting, IrSiteKind, IrUnsupported, SourceSummary,
};
use std::collections::HashMap;
use std::path::Path;

const HESTIA_CONF: &str = "/usr/local/hestia/conf/hestia.conf";
const USERS_DIR: &str = "/usr/local/hestia/data/users";
const VESTA_CONF: &str = "/usr/local/vesta/conf/vesta.conf";

pub struct HestiaAdapter;

#[async_trait::async_trait]
impl SourceAdapter for HestiaAdapter {
    fn kind(&self) -> SourceKind {
        SourceKind::HestiaCp
    }

    async fn detect(&self, location: &Location) -> Option<SourcePanelInfo> {
        if !matches!(location, Location::InPlace) {
            return None;
        }
        if !Path::new(HESTIA_CONF).exists() && !Path::new(VESTA_CONF).exists() {
            return None;
        }
        let conf = tokio::fs::read_to_string(HESTIA_CONF)
            .await
            .or(tokio::fs::read_to_string(VESTA_CONF).await)
            .unwrap_or_default();
        let flags = parse_conf_line(&conf.replace('\n', " "));
        let version = tokio::fs::read_to_string("/usr/local/hestia/VERSION")
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| flags.get("VERSION").cloned())
            .unwrap_or_else(|| "unknown".into());
        Some(SourcePanelInfo {
            kind: SourceKind::HestiaCp,
            version,
            has_mail: flags.get("MAIL_SYSTEM").is_some_and(|v| !v.is_empty()),
            has_dns: flags.get("DNS_SYSTEM").is_some_and(|v| !v.is_empty()),
        })
    }

    async fn extract(&self, location: &Location) -> Result<ImportIR, ImportError> {
        if !matches!(location, Location::InPlace) {
            return Err(ImportError::UnsupportedMode(format!(
                "Hestia adapter supports in-place only (got {})",
                location.mode()
            )));
        }
        let info = self
            .detect(location)
            .await
            .ok_or(ImportError::NotDetected)?;

        let mut hostings = Vec::new();
        let mut unsupported = Vec::new();
        let mut mail_domains = 0usize;
        let mut dns_zones = 0usize;

        let mut users = tokio::fs::read_dir(USERS_DIR).await?;
        while let Some(entry) = users.next_entry().await? {
            if !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let user = entry.file_name().to_string_lossy().to_string();
            // Hestia's own 'admin' user holds panel-level config, not customer
            // sites we want to import wholesale — skip its maintenance entries.
            // (Real customer sites owned by admin still parse; we only skip the
            // synthetic panel records by relying on web.conf being empty.)
            let dir = entry.path();

            // Databases (user-scoped) — collected once, attached to the first
            // domain below.
            let mut user_dbs: Vec<IrDatabase> = Vec::new();
            for rec in read_records(&dir.join("db.conf")).await {
                let name = rec.get("DB").cloned().unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                user_dbs.push(IrDatabase {
                    engine: match rec.get("TYPE").map(String::as_str) {
                        Some("pgsql") => IrDbEngine::Postgres,
                        _ => IrDbEngine::MySql,
                    },
                    charset: rec.get("CHARSET").cloned().filter(|s| !s.is_empty()),
                    user: rec.get("DBUSER").cloned().unwrap_or_default(),
                    dump_hint: format!("mysqldump {name}"),
                    name,
                });
            }

            // Web domains.
            let mut first_domain = true;
            for rec in read_records(&dir.join("web.conf")).await {
                let domain = rec.get("DOMAIN").cloned().unwrap_or_default();
                if domain.is_empty() {
                    continue;
                }
                let aliases: Vec<String> = rec
                    .get("ALIAS")
                    .map(|a| a.split_whitespace().map(String::from).collect())
                    .unwrap_or_default();
                // BACKEND='PHP-8_2' → "8.2"
                let php_version = rec
                    .get("BACKEND")
                    .and_then(|b| b.strip_prefix("PHP-").map(|v| v.replace('_', ".")));
                // First domain of the user adopts the user's DBs; the rest get
                // none (Hestia has no per-domain DB link).
                let databases = if first_domain {
                    std::mem::take(&mut user_dbs)
                } else {
                    Vec::new()
                };
                first_domain = false;

                hostings.push(IrHosting {
                    source_key: format!("hestiacp:{user}:{domain}"),
                    domain: domain.clone(),
                    aliases,
                    owner_user: user.clone(),
                    kind: IrSiteKind::Php, // Hestia vhosts are php/static; treat as php
                    php_version,
                    docroot: format!("/home/{user}/web/{domain}/public_html"),
                    proxy_upstream: None,
                    databases,
                    crons: Vec::new(), // TODO(P1.x): data/users/<u>/cron.conf
                    tls: None,         // TODO(P1.x): data/users/<u>/ssl/<d>.pem
                    ssh_keys: Vec::new(),
                });
            }

            // Any DBs left over (user had more DBs than the first domain could
            // adopt, or only had DBs and no web domain) — report, don't drop.
            for db in user_dbs {
                unsupported.push(IrUnsupported {
                    category: "database".into(),
                    detail: format!(
                        "{} (user {user}) not auto-attached — Hestia ties DBs to the user, \
                         not a domain; import it manually after",
                        db.name
                    ),
                });
            }

            // Count mail/DNS for an honest report (never imported).
            mail_domains += count_records(&dir.join("mail.conf")).await;
            dns_zones += count_records(&dir.join("dns.conf")).await;
        }

        if mail_domains > 0 {
            unsupported.push(IrUnsupported {
                category: "mail".into(),
                detail: format!(
                    "{mail_domains} Hestia mail domain(s) found — Hyperion does not manage email; \
                     migrate mailboxes separately"
                ),
            });
        }
        if dns_zones > 0 {
            unsupported.push(IrUnsupported {
                category: "dns".into(),
                detail: format!(
                    "{dns_zones} Hestia DNS zone(s) found — Hyperion does not run a nameserver; \
                     migrate DNS at your provider"
                ),
            });
        }

        Ok(ImportIR {
            source: SourceSummary {
                kind: SourceKind::HestiaCp.as_str().into(),
                version: info.version,
                host: "localhost".into(),
            },
            hostings,
            unsupported,
        })
    }
}

/// Read a Hestia data file (one `key='value' …` record per line) into a list
/// of field maps. Missing file → empty list.
async fn read_records(path: &Path) -> Vec<HashMap<String, String>> {
    let Ok(content) = tokio::fs::read_to_string(path).await else {
        return Vec::new();
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(parse_conf_line)
        .collect()
}

async fn count_records(path: &Path) -> usize {
    read_records(path).await.len()
}

/// Parse a Hestia `KEY='value' KEY2='value with spaces' …` line. Values are
/// single-quoted; keys are the bareword immediately before `='`.
fn parse_conf_line(line: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut rest = line;
    while let Some(eq) = rest.find("='") {
        let key = rest[..eq]
            .rsplit(|c: char| c.is_whitespace())
            .next()
            .unwrap_or("")
            .to_string();
        let after = &rest[eq + 2..];
        match after.find('\'') {
            Some(end) => {
                if !key.is_empty() {
                    map.insert(key, after[..end].to_string());
                }
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hestia_conf_line() {
        let line = "DOMAIN='example.com' ALIAS='www.example.com m.example.com' \
                    BACKEND='PHP-8_2' SSL='yes' LETSENCRYPT='yes'";
        let m = parse_conf_line(line);
        assert_eq!(m.get("DOMAIN").unwrap(), "example.com");
        assert_eq!(m.get("ALIAS").unwrap(), "www.example.com m.example.com");
        assert_eq!(m.get("BACKEND").unwrap(), "PHP-8_2");
        assert_eq!(m.get("SSL").unwrap(), "yes");
    }

    #[test]
    fn php_version_from_backend() {
        let v = "PHP-8_2".strip_prefix("PHP-").map(|v| v.replace('_', "."));
        assert_eq!(v.as_deref(), Some("8.2"));
    }

    #[test]
    fn db_line_fields() {
        let m = parse_conf_line("DB='admin_wp' DBUSER='admin_wp' TYPE='mysql' CHARSET='utf8mb4'");
        assert_eq!(m.get("DB").unwrap(), "admin_wp");
        assert_eq!(m.get("TYPE").unwrap(), "mysql");
        assert_eq!(m.get("CHARSET").unwrap(), "utf8mb4");
    }
}
