//! HestiaCP (and VestaCP) source adapter.
//!
//! Hestia has no central SQL store — every hosting user is a real Linux account
//! and the panel's authoritative metadata lives in flat `key='value'` files
//! under `/usr/local/hestia/data/users/<user>/` (`web.conf`, `db.conf`, …).
//! Site files live at `/home/<user>/web/<domain>/public_html`.
//!
//! Works **in-place** (local) and **remote** (SSH) via [`Runner`]. Mail + DNS
//! are intentionally out of scope — reported, never imported.
//!
//! DB↔domain mapping: Hestia DBs belong to the *user*, not a domain, so we
//! attach a user's DBs to that user's first domain; extras are reported.

use crate::adapter::{Location, Runner, SourceAdapter, SourceKind, SourcePanelInfo};
use crate::error::ImportError;
use crate::ir::{
    ImportIR, IrDatabase, IrDbEngine, IrHosting, IrSiteKind, IrUnsupported, SourceSummary,
};
use std::collections::HashMap;

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
        if matches!(location, Location::Archive(_)) {
            return None;
        }
        let runner = Runner::for_location(location);
        if !runner.exists(HESTIA_CONF).await && !runner.exists(VESTA_CONF).await {
            return None;
        }
        let conf = runner
            .read(HESTIA_CONF)
            .await
            .or(runner.read(VESTA_CONF).await)
            .unwrap_or_default();
        let flags = parse_conf_line(&conf.replace('\n', " "));
        let version = runner
            .read("/usr/local/hestia/VERSION")
            .await
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
        if matches!(location, Location::Archive(_)) {
            return Err(ImportError::UnsupportedMode(
                "Hestia adapter: archive mode not yet supported".into(),
            ));
        }
        let runner = Runner::for_location(location);
        let info = self
            .detect(location)
            .await
            .ok_or(ImportError::NotDetected)?;

        let mut hostings = Vec::new();
        let mut unsupported = Vec::new();
        let mut mail_domains = 0usize;
        let mut dns_zones = 0usize;

        for user in runner.list_dir(USERS_DIR).await {
            if user.is_empty() {
                continue;
            }
            let base = format!("{USERS_DIR}/{user}");

            // Databases (user-scoped) — attached to the first domain below.
            let mut user_dbs: Vec<IrDatabase> = Vec::new();
            for rec in read_records(&runner, &format!("{base}/db.conf")).await {
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

            let mut first_domain = true;
            for rec in read_records(&runner, &format!("{base}/web.conf")).await {
                let domain = rec.get("DOMAIN").cloned().unwrap_or_default();
                if domain.is_empty() {
                    continue;
                }
                let aliases: Vec<String> = rec
                    .get("ALIAS")
                    .map(|a| a.split_whitespace().map(String::from).collect())
                    .unwrap_or_default();
                let php_version = rec
                    .get("BACKEND")
                    .and_then(|b| b.strip_prefix("PHP-").map(|v| v.replace('_', ".")));
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
                    kind: IrSiteKind::Php,
                    php_version,
                    docroot: format!("/home/{user}/web/{domain}/public_html"),
                    proxy_upstream: None,
                    databases,
                    crons: Vec::new(),
                    tls: None,
                    ssh_keys: Vec::new(),
                });
            }

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

            mail_domains += read_records(&runner, &format!("{base}/mail.conf"))
                .await
                .len();
            dns_zones += read_records(&runner, &format!("{base}/dns.conf"))
                .await
                .len();
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
                host: match location {
                    Location::Remote(t) => t.host.clone(),
                    _ => "localhost".into(),
                },
            },
            hostings,
            unsupported,
        })
    }
}

/// Read a Hestia data file (one `key='value' …` record per line) into field
/// maps. Missing file → empty.
async fn read_records(runner: &Runner, path: &str) -> Vec<HashMap<String, String>> {
    let Some(content) = runner.read(path).await else {
        return Vec::new();
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(parse_conf_line)
        .collect()
}

/// Parse a Hestia `KEY='value' KEY2='value with spaces' …` line.
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
