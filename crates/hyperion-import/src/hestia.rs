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
//! DB↔domain mapping: Hestia DBs belong to the *user*, not a domain, and one
//! user routinely owns several sites, each with its own database. Each DB is
//! attached to the site whose config file names it (see [`assign_databases`]);
//! a DB no site claims is reported, never guessed onto the wrong site.

use crate::adapter::{shell_quote, Location, Runner, SourceAdapter, SourceKind, SourcePanelInfo};
use crate::error::ImportError;
use crate::ir::{
    ImportIR, IrDatabase, IrDbEngine, IrHosting, IrSiteKind, IrUnsupported, SourceSummary,
};
use std::collections::HashMap;

/// Where one flavour of the panel keeps its state. VestaCP is Hestia's
/// ancestor and shares its data-file format, but not its install prefix.
struct DataRoot {
    conf: &'static str,
    users_dir: &'static str,
}

const HESTIA: DataRoot = DataRoot {
    conf: "/usr/local/hestia/conf/hestia.conf",
    users_dir: "/usr/local/hestia/data/users",
};
const VESTA: DataRoot = DataRoot {
    conf: "/usr/local/vesta/conf/vesta.conf",
    users_dir: "/usr/local/vesta/data/users",
};

/// Files in a docroot that name the site's database, most authoritative first:
/// WordPress, Laravel/Symfony `.env`, Joomla.
const DB_CONFIG_FILES: [&str; 3] = ["wp-config.php", ".env", "configuration.php"];

/// Which install is at `location`, Hestia first.
async fn data_root(runner: &Runner) -> Option<&'static DataRoot> {
    for root in [&HESTIA, &VESTA] {
        if runner.exists(root.conf).await {
            return Some(root);
        }
    }
    None
}

pub struct HestiaAdapter;

#[async_trait::async_trait]
impl SourceAdapter for HestiaAdapter {
    fn kind(&self) -> SourceKind {
        SourceKind::HestiaCp
    }

    async fn detect(&self, location: &Location) -> Option<SourcePanelInfo> {
        if let Location::Archive(dir) = location {
            let ir = crate::bundle::read_manifest(dir).await?;
            if ir.source.kind != SourceKind::HestiaCp.as_str() {
                return None;
            }
            return Some(SourcePanelInfo {
                kind: SourceKind::HestiaCp,
                version: ir.source.version,
                has_mail: false,
                has_dns: false,
            });
        }
        let runner = Runner::for_location(location);
        let root = data_root(&runner).await?;
        let conf = runner.read(root.conf).await.unwrap_or_default();
        let flags = parse_conf_line(&conf.replace('\n', " "));
        let version = flags
            .get("VERSION")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into());
        Some(SourcePanelInfo {
            kind: SourceKind::HestiaCp,
            version,
            has_mail: flags.get("MAIL_SYSTEM").is_some_and(|v| !v.is_empty()),
            has_dns: flags.get("DNS_SYSTEM").is_some_and(|v| !v.is_empty()),
        })
    }

    async fn extract(&self, location: &Location) -> Result<ImportIR, ImportError> {
        if let Location::Archive(dir) = location {
            return crate::bundle::read_manifest(dir)
                .await
                .ok_or(ImportError::Parse {
                    what: "bundle manifest".into(),
                    msg: "manifest.json missing or invalid in the uploaded bundle".into(),
                });
        }
        let runner = Runner::for_location(location);
        let info = self
            .detect(location)
            .await
            .ok_or(ImportError::NotDetected)?;
        let root = data_root(&runner).await.ok_or(ImportError::NotDetected)?;

        let mut hostings = Vec::new();
        let mut unsupported = Vec::new();
        let mut mail_domains = 0usize;
        let mut dns_zones = 0usize;

        let mut users = runner.list_dir(root.users_dir).await;
        users.sort();
        for user in users {
            if user.is_empty() || user.starts_with('.') {
                continue;
            }
            let base = format!("{}/{user}", root.users_dir);

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

            let mut sites: Vec<IrHosting> = Vec::new();
            for rec in read_records(&runner, &format!("{base}/web.conf")).await {
                let domain = rec.get("DOMAIN").cloned().unwrap_or_default();
                if domain.is_empty() {
                    continue;
                }
                let aliases: Vec<String> = rec
                    .get("ALIAS")
                    .map(|a| {
                        a.split([' ', ','])
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                            .collect()
                    })
                    .unwrap_or_default();
                sites.push(IrHosting {
                    source_key: format!("hestiacp:{user}:{domain}"),
                    aliases,
                    owner_user: user.clone(),
                    kind: IrSiteKind::Php,
                    php_version: rec.get("BACKEND").and_then(|b| php_from_backend(b)),
                    docroot: docroot_for(&user, &domain, rec.get("CUSTOM_DOCROOT")),
                    domain,
                    proxy_upstream: None,
                    databases: Vec::new(),
                    crons: Vec::new(),
                    tls: None,
                    ssh_keys: Vec::new(),
                    // A scan must stay cheap; the sizes are measured by the
                    // packing pass and stamped into the bundle's manifest.
                    docroot_bytes: 0,
                    db_bytes: 0,
                });
            }

            // Only worth reading the sites' config files when there is a
            // database to place.
            let mut configs: Vec<String> = Vec::with_capacity(sites.len());
            for s in &sites {
                configs.push(if user_dbs.is_empty() {
                    String::new()
                } else {
                    read_db_configs(&runner, &s.docroot).await
                });
            }
            let domains: Vec<String> = sites.iter().map(|s| s.domain.clone()).collect();
            let (per_site, notes) = assign_databases(&user, &domains, &configs, user_dbs);
            for (site, dbs) in sites.iter_mut().zip(per_site) {
                site.databases = dbs;
            }
            hostings.extend(sites);
            unsupported.extend(notes);

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
            // Filled in by the exporter as it packs; empty at extraction time.
            skipped: Vec::new(),
        })
    }
}

/// The site's docroot: Hestia's `CUSTOM_DOCROOT` when one is set (a domain
/// that serves another domain's tree, or a subdirectory of its own), else the
/// standard `public_html`. Ignoring it packed the empty default directory.
fn docroot_for(user: &str, domain: &str, custom: Option<&String>) -> String {
    match custom.map(|c| c.trim().trim_end_matches('/')) {
        Some(c) if c.starts_with('/') && c.len() > 1 => c.to_string(),
        _ => format!("/home/{user}/web/{domain}/public_html"),
    }
}

/// `PHP-8_2` → `8.2`. Anything else (`default`, a custom template name) has no
/// version to report — the import then says so instead of guessing.
fn php_from_backend(backend: &str) -> Option<String> {
    let b = backend.trim();
    let v = b
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("php-"))
        .map(|_| &b[4..])?
        .replace('_', ".");
    v.chars().next().filter(char::is_ascii_digit).map(|_| v)
}

/// The concatenated contents of the files in `docroot` that may name its
/// database. One command per site, not one per file: in remote mode each is
/// an SSH round trip. Each file is capped, and a missing file is not an error.
async fn read_db_configs(runner: &Runner, docroot: &str) -> String {
    let mut files: Vec<String> = DB_CONFIG_FILES
        .iter()
        .map(|f| shell_quote(&format!("{docroot}/{f}")))
        .collect();
    // WordPress also loads wp-config.php from one level above the docroot.
    // Only for the standard layout, where that level is the domain's own
    // directory: a CUSTOM_DOCROOT is often a subdirectory of ANOTHER site's
    // public_html, whose wp-config would claim that site's database.
    if let Some(parent) = docroot.strip_suffix("/public_html") {
        files.insert(1, shell_quote(&format!("{parent}/wp-config.php")));
    }
    let cmd = format!(
        "for f in {}; do [ -f \"$f\" ] && head -c 65536 -- \"$f\" && echo; done; true",
        files.join(" ")
    );
    runner.sh(&cmd).await.unwrap_or_default()
}

/// Database names `config` mentions, in the order it first mentions them.
fn named_databases<'a>(config: &str, dbs: &'a [IrDatabase]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for tok in config.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if let Some(db) = dbs.iter().find(|d| d.name == tok) {
            if !out.contains(&db.name.as_str()) {
                out.push(db.name.as_str());
            }
        }
    }
    out
}

/// Place a Hestia user's databases on that user's sites.
///
/// Hestia ties a database to the user, not to a domain, so the link has to be
/// recovered. It used to be "every DB goes to the first domain in web.conf",
/// and the import restores a site's FIRST database: a user with `blog` and
/// `shop` got shop's data restored into blog, blog's wp-config repointed at it,
/// and shop left pointing at a database that does not exist on the target.
///
/// In order of evidence:
///   1. the site's own config file names the database (`DB_NAME`, `.env`, …);
///   2. the database is called `<user>_<first label of the domain>`, and only
///      one site of this user matches;
///   3. a user with exactly one site gets whatever is left.
///
/// Anything still unplaced is reported rather than guessed onto a site: a
/// wrong guess overwrites the site's real database on the target. A database
/// two sites both name goes to the first and the second is reported.
fn assign_databases(
    user: &str,
    domains: &[String],
    configs: &[String],
    dbs: Vec<IrDatabase>,
) -> (Vec<Vec<IrDatabase>>, Vec<IrUnsupported>) {
    let mut per_site: Vec<Vec<IrDatabase>> = vec![Vec::new(); domains.len()];
    let mut notes = Vec::new();
    if dbs.is_empty() {
        return (per_site, notes);
    }
    let mut owner: Vec<Option<usize>> = vec![None; dbs.len()];
    let idx = |name: &str| dbs.iter().position(|d| d.name == name);

    // 1. Named by the site's config.
    for (site, config) in configs.iter().enumerate().take(domains.len()) {
        for name in named_databases(config, &dbs) {
            let Some(i) = idx(name) else { continue };
            match owner[i] {
                None => owner[i] = Some(site),
                Some(first) if first != site => notes.push(IrUnsupported {
                    category: "database".into(),
                    detail: format!(
                        "{name} (user {user}) is used by both {} and {} — imported with {} \
                         only; {} will need its database set up by hand",
                        domains[first], domains[site], domains[first], domains[site]
                    ),
                }),
                Some(_) => {}
            }
        }
    }

    // 2. Named after the site, when that points at exactly one site.
    for (i, db) in dbs.iter().enumerate() {
        if owner[i].is_some() {
            continue;
        }
        let Some(suffix) = db.name.strip_prefix(&format!("{user}_")) else {
            continue;
        };
        let matches: Vec<usize> = domains
            .iter()
            .enumerate()
            .filter(|(s, d)| d.split('.').next() == Some(suffix) && !owner.contains(&Some(*s)))
            .map(|(s, _)| s)
            .collect();
        if let [only] = matches[..] {
            owner[i] = Some(only);
        }
    }

    // 3. One site: nothing else it could belong to.
    if domains.len() == 1 {
        for o in owner.iter_mut().filter(|o| o.is_none()) {
            *o = Some(0);
        }
    }

    // Keep each site's databases in the order its config names them, so the
    // one it actually uses is first — that is the one the import restores.
    let mut order: Vec<usize> = (0..dbs.len()).collect();
    order.sort_by_key(|&i| {
        owner[i]
            .and_then(|s| configs.get(s))
            .and_then(|c| {
                named_databases(c, &dbs)
                    .iter()
                    .position(|n| *n == dbs[i].name)
            })
            .unwrap_or(usize::MAX)
    });
    let mut dbs: Vec<Option<IrDatabase>> = dbs.into_iter().map(Some).collect();
    for i in order {
        let db = dbs[i].take().expect("each database is placed once");
        match owner[i] {
            Some(site) => per_site[site].push(db),
            None => notes.push(IrUnsupported {
                category: "database".into(),
                detail: if domains.is_empty() {
                    format!(
                        "{} (user {user}) belongs to no web domain — not imported",
                        db.name
                    )
                } else {
                    format!(
                        "{} (user {user}) is not named by any of this user's sites' config \
                         files, so which site it belongs to is unknown — not imported; dump \
                         it by hand if a site needs it",
                        db.name
                    )
                },
            }),
        }
    }
    (per_site, notes)
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
        assert_eq!(php_from_backend("PHP-8_2").as_deref(), Some("8.2"));
        assert_eq!(php_from_backend("php-7_4").as_deref(), Some("7.4"));
        // Vesta and older Hestia templates carry no version at all.
        assert_eq!(php_from_backend("default"), None);
        assert_eq!(php_from_backend("PHP-custom"), None);
        assert_eq!(php_from_backend(""), None);
    }

    #[test]
    fn custom_docroot_wins_over_public_html() {
        let custom = "/home/admin/web/shop.example.com/public_html/static/".to_string();
        assert_eq!(
            docroot_for("admin", "static.example.com", Some(&custom)),
            "/home/admin/web/shop.example.com/public_html/static"
        );
        assert_eq!(
            docroot_for("admin", "a.cz", Some(&String::new())),
            "/home/admin/web/a.cz/public_html"
        );
        assert_eq!(
            docroot_for("admin", "a.cz", None),
            "/home/admin/web/a.cz/public_html"
        );
    }

    fn db(name: &str) -> IrDatabase {
        IrDatabase {
            name: name.into(),
            engine: IrDbEngine::MySql,
            charset: None,
            user: name.into(),
            dump_hint: String::new(),
        }
    }

    fn wp(db: &str) -> String {
        format!("<?php\ndefine( 'DB_NAME', '{db}' );\ndefine( 'DB_USER', '{db}' );\n")
    }

    fn names(v: &[IrDatabase]) -> Vec<&str> {
        v.iter().map(|d| d.name.as_str()).collect()
    }

    /// The shape that broke: blog listed first in web.conf, shop's database
    /// first in db.conf. Everything used to land on blog, and blog's restore
    /// took shop's data.
    #[test]
    fn each_site_gets_the_database_its_config_names() {
        let domains = vec![
            "blog.example.com".to_string(),
            "shop.example.com".to_string(),
        ];
        let configs = vec![wp("admin_blog"), wp("admin_shop")];
        let (per_site, notes) = assign_databases(
            "admin",
            &domains,
            &configs,
            vec![db("admin_shop"), db("admin_blog"), db("admin_orphan")],
        );
        assert_eq!(names(&per_site[0]), ["admin_blog"]);
        assert_eq!(names(&per_site[1]), ["admin_shop"]);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].detail.contains("admin_orphan"), "{notes:?}");
    }

    #[test]
    fn a_database_named_after_the_site_is_placed_when_unambiguous() {
        let domains = vec![
            "blog.example.com".to_string(),
            "shop.example.com".to_string(),
        ];
        // No config names anything (not WordPress, or unreadable).
        let configs = vec![String::new(), String::new()];
        let (per_site, notes) =
            assign_databases("admin", &domains, &configs, vec![db("admin_shop")]);
        assert!(per_site[0].is_empty());
        assert_eq!(names(&per_site[1]), ["admin_shop"]);
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn a_single_site_user_keeps_every_database_with_the_used_one_first() {
        let domains = vec!["alice.test".to_string()];
        let configs = vec![wp("alice_wp")];
        let (per_site, notes) = assign_databases(
            "alice",
            &domains,
            &configs,
            vec![db("alice_old"), db("alice_wp")],
        );
        // First is the one the import restores.
        assert_eq!(names(&per_site[0]), ["alice_wp", "alice_old"]);
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn a_shared_database_goes_to_the_first_site_and_is_reported() {
        let domains = vec!["a.cz".to_string(), "b.cz".to_string()];
        let configs = vec![wp("u_shared"), wp("u_shared")];
        let (per_site, notes) = assign_databases("u", &domains, &configs, vec![db("u_shared")]);
        assert_eq!(names(&per_site[0]), ["u_shared"]);
        assert!(per_site[1].is_empty());
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].detail.contains("b.cz"), "{notes:?}");
    }

    #[test]
    fn databases_of_a_user_without_sites_are_reported() {
        let (per_site, notes) = assign_databases("u", &[], &[], vec![db("u_x")]);
        assert!(per_site.is_empty());
        assert_eq!(notes.len(), 1);
        assert!(notes[0].detail.contains("no web domain"), "{notes:?}");
    }

    /// A name is matched as a whole token, never as a substring: `admin_wp`
    /// must not claim a config that only mentions `admin_wp2`.
    #[test]
    fn database_names_match_whole_tokens_only() {
        let dbs = vec![db("admin_wp"), db("admin_wp2")];
        assert_eq!(named_databases(&wp("admin_wp2"), &dbs), ["admin_wp2"]);
        assert_eq!(
            named_databases("DB_DATABASE=admin_wp\nOTHER=1", &dbs),
            ["admin_wp"]
        );
    }

    #[test]
    fn db_line_fields() {
        let m = parse_conf_line("DB='admin_wp' DBUSER='admin_wp' TYPE='mysql' CHARSET='utf8mb4'");
        assert_eq!(m.get("DB").unwrap(), "admin_wp");
        assert_eq!(m.get("TYPE").unwrap(), "mysql");
        assert_eq!(m.get("CHARSET").unwrap(), "utf8mb4");
    }
}
