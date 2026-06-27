//! CloudPanel source adapter.
//!
//! CloudPanel keeps its state in a SQLite DB at
//! `/home/clp/htdocs/app/data/db.sq3`; sites live under
//! `/home/<site-user>/htdocs/<domain>`. It manages **no** mail and **no**
//! authoritative DNS, so those are always reported as `unsupported`.
//!
//! Works in **in-place** (local) and **remote** (SSH) modes via [`Runner`] —
//! the same query logic runs locally or over `ssh`. Archive mode is P1.x.
//! The SQLite store is read with `sqlite3 -readonly -json` (matches the
//! version-variant schema; `-readonly` avoids the live DB lock).

use crate::adapter::{Location, Runner, SourceAdapter, SourceKind, SourcePanelInfo};
use crate::error::ImportError;
use crate::ir::{
    ImportIR, IrDatabase, IrDbEngine, IrHosting, IrSiteKind, IrUnsupported, SourceSummary,
};

const DB_PATH: &str = "/home/clp/htdocs/app/data/db.sq3";
const APP_DIR: &str = "/home/clp/htdocs/app";

pub struct CloudPanelAdapter;

#[async_trait::async_trait]
impl SourceAdapter for CloudPanelAdapter {
    fn kind(&self) -> SourceKind {
        SourceKind::CloudPanel
    }

    async fn detect(&self, location: &Location) -> Option<SourcePanelInfo> {
        if matches!(location, Location::Archive(_)) {
            return None; // archive mode not supported yet
        }
        let runner = Runner::for_location(location);
        if !runner.exists(DB_PATH).await || !runner.exists(APP_DIR).await {
            return None;
        }
        Some(SourcePanelInfo {
            kind: SourceKind::CloudPanel,
            version: clpctl_version(&runner)
                .await
                .unwrap_or_else(|| "unknown".into()),
            has_mail: false, // CloudPanel never manages mail …
            has_dns: false,  // … or authoritative DNS.
        })
    }

    async fn extract(&self, location: &Location) -> Result<ImportIR, ImportError> {
        if matches!(location, Location::Archive(_)) {
            return Err(ImportError::UnsupportedMode(
                "CloudPanel adapter: archive mode not yet supported".into(),
            ));
        }
        let runner = Runner::for_location(location);
        let info = self
            .detect(location)
            .await
            .ok_or(ImportError::NotDetected)?;

        let sites = sqlite_json(
            &runner,
            "SELECT id, domain_name, user, type, root_directory, reverse_proxy_url, ssh_keys \
             FROM site",
        )
        .await?;
        // DB rows joined to their owning site. Best-effort: schema varies by
        // version, so tolerate a failing join (sites still import without DBs).
        let dbs = sqlite_json(
            &runner,
            "SELECT d.name AS db_name, d.site_id AS site_id, ds.engine AS engine, \
             du.user_name AS user_name \
             FROM \"database\" d \
             JOIN database_server ds ON d.database_server_id = ds.id \
             JOIN database_user du ON d.id = du.database_id",
        )
        .await
        .unwrap_or_default();
        let php = sqlite_json(&runner, "SELECT site_id, php_version FROM php_settings")
            .await
            .unwrap_or_default();

        let mut hostings = Vec::new();
        for s in &sites {
            let domain = jstr(s, "domain_name");
            if domain.is_empty() {
                continue;
            }
            let owner = jstr(s, "user");
            let site_id = jstr(s, "id");
            let root = jstr(s, "root_directory");
            let kind = site_kind(&jstr(s, "type"));

            let php_version = php
                .iter()
                .find(|p| jstr(p, "site_id") == site_id)
                .map(|p| jstr(p, "php_version"))
                .filter(|v| !v.is_empty());

            let databases = dbs
                .iter()
                .filter(|d| jstr(d, "site_id") == site_id)
                .map(|d| {
                    let name = jstr(d, "db_name");
                    IrDatabase {
                        engine: db_engine(&jstr(d, "engine")),
                        charset: None,
                        user: jstr(d, "user_name"),
                        dump_hint: format!("clpctl db:export --databaseName={name}"),
                        name,
                    }
                })
                .collect();

            // root_directory is the full path UNDER /home/<user>/htdocs.
            let docroot = if root.is_empty() {
                format!("/home/{owner}/htdocs/{domain}")
            } else {
                format!("/home/{owner}/htdocs/{root}")
            };
            let proxy_upstream = {
                let u = jstr(s, "reverse_proxy_url");
                (!u.is_empty()).then_some(u)
            };
            let ssh_keys: Vec<String> = jstr(s, "ssh_keys")
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();

            hostings.push(IrHosting {
                source_key: format!("cloudpanel:{owner}:{domain}"),
                domain,
                aliases: Vec::new(),
                owner_user: owner,
                kind,
                php_version,
                docroot,
                proxy_upstream,
                databases,
                crons: Vec::new(),
                tls: None,
                ssh_keys,
            });
        }

        Ok(ImportIR {
            source: SourceSummary {
                kind: SourceKind::CloudPanel.as_str().into(),
                version: info.version,
                host: location_host(location),
            },
            hostings,
            unsupported: vec![
                IrUnsupported {
                    category: "mail".into(),
                    detail: "CloudPanel does not manage email — there are no mailboxes to import."
                        .into(),
                },
                IrUnsupported {
                    category: "dns".into(),
                    detail: "CloudPanel runs no authoritative nameserver — DNS lives at an \
                             external provider and must be migrated there."
                        .into(),
                },
            ],
        })
    }
}

/// Host label for the report: the ssh host for remote, else localhost.
fn location_host(loc: &Location) -> String {
    match loc {
        Location::Remote(t) => t.host.clone(),
        _ => "localhost".into(),
    }
}

fn site_kind(raw: &str) -> IrSiteKind {
    let t = raw.to_lowercase();
    if t.contains("php") || t.contains("wordpress") {
        IrSiteKind::Php
    } else if t.contains("static") || t.contains("html") {
        IrSiteKind::Static
    } else {
        IrSiteKind::ReverseProxy
    }
}

fn db_engine(raw: &str) -> IrDbEngine {
    let e = raw.to_lowercase();
    if e.contains("maria") {
        IrDbEngine::MariaDb
    } else if e.contains("pg") || e.contains("postgres") {
        IrDbEngine::Postgres
    } else {
        IrDbEngine::MySql
    }
}

/// `clpctl --version` → just the `X.Y.Z` token (the CLI prints a long banner).
async fn clpctl_version(runner: &Runner) -> Option<String> {
    let out = runner.sh("clpctl --version").await.ok()?;
    out.split_whitespace()
        .find(|t| t.contains('.') && t.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(String::from)
}

/// Run a read-only query via `sqlite3 -json` (local or over ssh) → row objects.
async fn sqlite_json(
    runner: &Runner,
    sql: &str,
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, ImportError> {
    let cmd = format!(
        "sqlite3 -readonly -json {} {}",
        crate::adapter::shell_quote(DB_PATH),
        crate::adapter::shell_quote(sql)
    );
    let text = runner.sh(&cmd).await?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let val: serde_json::Value = serde_json::from_str(text).map_err(|e| ImportError::Parse {
        what: "sqlite3 -json".into(),
        msg: e.to_string(),
    })?;
    Ok(val
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_object().cloned())
        .collect())
}

/// Read a field as a string, coercing numbers; `""` if absent/null.
fn jstr(row: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    match row.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_site_kinds() {
        assert_eq!(site_kind("php"), IrSiteKind::Php);
        assert_eq!(site_kind("WordPress"), IrSiteKind::Php);
        assert_eq!(site_kind("Static HTML"), IrSiteKind::Static);
        assert_eq!(site_kind("Node.js"), IrSiteKind::ReverseProxy);
        assert_eq!(site_kind("python"), IrSiteKind::ReverseProxy);
    }

    #[test]
    fn maps_db_engines() {
        assert_eq!(db_engine("MariaDB 10.11"), IrDbEngine::MariaDb);
        assert_eq!(db_engine("MYSQL_8.0"), IrDbEngine::MySql);
        assert_eq!(db_engine("PostgreSQL"), IrDbEngine::Postgres);
    }

    #[test]
    fn jstr_coerces() {
        let row: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"a":"x","b":7,"c":null}"#).unwrap();
        assert_eq!(jstr(&row, "a"), "x");
        assert_eq!(jstr(&row, "b"), "7");
        assert_eq!(jstr(&row, "c"), "");
        assert_eq!(jstr(&row, "missing"), "");
    }
}
