//! Export-bundle format: a portable archive an operator produces on the source
//! box (via `hyperion-agent export-bundle`) and hands to Hyperion, so the import
//! needs no inbound SSH/root to the source.
//!
//! Layout of `bundle.tar`:
//! ```text
//! manifest.json                          # serde_json of the whole ImportIR
//! sites/<sanitized-domain>/docroot.tar.gz
//! sites/<sanitized-domain>/db/<dbname>.dump   # mysqldump (plain) | pg_dump -Fc
//! ```
//! The manifest IS the source of truth (the IR is already serialisable); per-site
//! dirs are keyed by domain so the import side finds docroot/DB without the
//! original source paths. `build` runs on the source; `read_manifest` on the node.

use crate::adapter::shell_quote;
use crate::error::ImportError;
use crate::ir::{ImportIR, IrDatabase, IrDbEngine};
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Manifest filename inside the bundle.
pub const MANIFEST: &str = "manifest.json";

/// Per-site subdirectory name inside the bundle — the domain with anything
/// outside `[A-Za-z0-9.-]` collapsed to `_`. Used identically on both sides.
pub fn site_dir(domain: &str) -> String {
    domain
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Read + parse the manifest (the serialized IR) from an already-extracted
/// bundle directory. `None` if absent or unparseable (→ "not a valid bundle").
pub async fn read_manifest(dir: &Path) -> Option<ImportIR> {
    let txt = tokio::fs::read_to_string(dir.join(MANIFEST)).await.ok()?;
    serde_json::from_str(&txt).ok()
}

/// Build a portable bundle from an extracted IR. Runs on the SOURCE box (as
/// root/sudo): tars each docroot, dumps each DB, writes the manifest, then packs
/// everything into `out`. Shells out to `tar`/`mysqldump`/`pg_dump` (present on
/// any panel box) so there are no extra crate deps.
pub async fn build(ir: &ImportIR, out: &Path) -> Result<(), ImportError> {
    // `--out -` streams the final tar straight to stdout (piped into curl on the
    // source by the self-service bootstrap — no bundle file lands on disk).
    let to_stdout = out.as_os_str() == "-";
    let stage = if to_stdout {
        std::env::temp_dir().join(format!("hyperion-export-stage-{}", std::process::id()))
    } else {
        out.with_extension("bundle-stage")
    };
    let _ = tokio::fs::remove_dir_all(&stage).await;
    tokio::fs::create_dir_all(&stage).await?;

    let manifest = serde_json::to_string_pretty(ir).map_err(|e| ImportError::Command {
        cmd: "serialize manifest".into(),
        msg: e.to_string(),
    })?;
    tokio::fs::write(stage.join(MANIFEST), manifest).await?;

    // A single unreadable docroot or DB must not sink a 40-site migration:
    // record the failure, drop the partial artefact, and keep going. The import
    // side skips any site whose docroot/DB dump is absent from the bundle.
    let mut failures: Vec<String> = Vec::new();
    for h in &ir.hostings {
        let site = stage.join("sites").join(site_dir(&h.domain));
        tokio::fs::create_dir_all(site.join("db")).await?;
        if Path::new(&h.docroot).is_dir() {
            let tgz = site.join("docroot.tar.gz");
            if let Err(e) = run(
                "tar",
                &["czf", &tgz.display().to_string(), "-C", &h.docroot, "."],
            )
            .await
            {
                let _ = tokio::fs::remove_file(&tgz).await;
                eprintln!("  ⚠ {}: docroot skipped — {e}", h.domain);
                failures.push(format!("{} (docroot)", h.domain));
            }
        }
        for db in &h.databases {
            let dest = site.join("db").join(format!("{}.dump", db.name));
            if let Err(e) = dump_db(db, &dest, &ir.source.kind).await {
                let _ = tokio::fs::remove_file(&dest).await;
                eprintln!("  ⚠ {}: database '{}' skipped — {e}", h.domain, db.name);
                failures.push(format!("{} (db {})", h.domain, db.name));
            }
        }
    }
    if !failures.is_empty() {
        eprintln!(
            "⚠ {} item(s) could not be exported and were skipped: {}",
            failures.len(),
            failures.join(", ")
        );
    }

    if to_stdout {
        // Stream the packed bundle to our stdout (inherited by .status()).
        let status = Command::new("tar")
            .arg("cf")
            .arg("-")
            .arg("-C")
            .arg(&stage)
            .arg(".")
            .status()
            .await?;
        let _ = tokio::fs::remove_dir_all(&stage).await;
        if !status.success() {
            return Err(ImportError::Command {
                cmd: "tar cf - (stream)".into(),
                msg: format!("tar exited with {status}"),
            });
        }
        return Ok(());
    }

    run(
        "tar",
        &[
            "cf",
            &out.display().to_string(),
            "-C",
            &stage.display().to_string(),
            ".",
        ],
    )
    .await?;
    let _ = tokio::fs::remove_dir_all(&stage).await;
    Ok(())
}

/// Dump one DB to `dest`, matching the format the restore helpers expect
/// (mariadb/mysql → plain SQL; postgres → custom `-Fc`).
async fn dump_db(db: &IrDatabase, dest: &Path, source_kind: &str) -> Result<(), ImportError> {
    match db.engine {
        IrDbEngine::Postgres => {
            let bytes = sh_capture(&format!(
                "sudo -u postgres pg_dump -Fc -- {}",
                shell_quote(&db.name)
            ))
            .await?;
            tokio::fs::write(dest, &bytes).await?;
            Ok(())
        }
        _ => dump_mariadb(&db.name, dest, source_kind).await,
    }
}

/// MariaDB/MySQL → plain SQL at `dest`.
///
/// On CloudPanel the *system* root has NO access to MariaDB (the panel sets a
/// root password), so a bare `mysqldump` fails with "Access denied … (using
/// password: NO)". Try, in order, the methods most likely to work on a panel
/// box, using the first that yields a non-empty dump:
///   1. `mysqldump` with the root creds CloudPanel stores in its own SQLite,
///      passed via a 0600 defaults-file so the password never reaches argv/ps;
///   2. `clpctl db:export` — the panel's native exporter, which handles auth and
///      any password encryption itself; its (often gzipped) output is inflated;
///   3. a plain `mysqldump` (works where root has unix_socket auth or ~/.my.cnf).
async fn dump_mariadb(name: &str, dest: &Path, source_kind: &str) -> Result<(), ImportError> {
    let mut errors: Vec<String> = Vec::new();

    if source_kind == "cloudpanel" {
        match cloudpanel_creds_dump(name).await {
            Ok(Some(bytes)) if !bytes.is_empty() => {
                tokio::fs::write(dest, &bytes).await?;
                return Ok(());
            }
            // Record WHY each method produced nothing, so the per-site skip
            // message names every path that was tried (diagnosability across
            // dozens of sites).
            Ok(Some(_)) => errors.push("stored-creds: empty output".into()),
            Ok(None) => errors.push("stored-creds: no DB server recorded in CloudPanel".into()),
            Err(e) => errors.push(format!("stored-creds: {e}")),
        }
        match clpctl_export(name, dest).await {
            Ok(true) => return Ok(()),
            Ok(false) => errors.push("clpctl db:export: empty output".into()),
            Err(e) => errors.push(format!("clpctl: {e}")),
        }
    }

    // Plain socket mysqldump — root via unix_socket plugin or ~/.my.cnf.
    match sh_capture(&format!(
        "mysqldump --single-transaction --routines --triggers --events -- {}",
        shell_quote(name)
    ))
    .await
    {
        Ok(bytes) if !bytes.is_empty() => {
            tokio::fs::write(dest, &bytes).await?;
            return Ok(());
        }
        Ok(_) => errors.push("mysqldump (socket): empty output".into()),
        Err(e) => errors.push(format!("mysqldump (socket): {e}")),
    }

    Err(ImportError::Command {
        cmd: format!("dump database {name}"),
        msg: errors.join("; "),
    })
}

/// CloudPanel's SQLite path — its source of truth for managed-MariaDB root creds.
const CLOUDPANEL_DB_SQ3: &str = "/home/clp/htdocs/app/data/db.sq3";

/// Read CloudPanel's stored MariaDB root creds (`database_server` table) and
/// `mysqldump` with them via a 0600 defaults-file (so the password never appears
/// in argv / `ps`). `Ok(None)` if the panel records no DB server (nothing to do
/// → let the caller fall through to `clpctl`).
async fn cloudpanel_creds_dump(name: &str) -> Result<Option<Vec<u8>>, ImportError> {
    let sql = "SELECT host,user_name,password,port FROM database_server \
               ORDER BY is_default DESC, id ASC LIMIT 1;";
    let q = format!(
        "sqlite3 -readonly -json {} {}",
        shell_quote(CLOUDPANEL_DB_SQ3),
        shell_quote(sql)
    );
    let raw = sh_capture(&q).await?;
    let text = String::from_utf8_lossy(&raw);
    let text = text.trim();
    if text.is_empty() || text == "[]" {
        return Ok(None);
    }
    let rows: Vec<serde_json::Map<String, serde_json::Value>> = serde_json::from_str(text)
        .map_err(|e| ImportError::Parse {
            what: "database_server".into(),
            msg: e.to_string(),
        })?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let field = |k: &str| -> String {
        match row.get(k) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    };
    let nonempty = |v: String, default: &str| if v.is_empty() { default.to_string() } else { v };
    let host = nonempty(field("host"), "localhost");
    let user = nonempty(field("user_name"), "root");
    let pass = field("password");
    let port = nonempty(field("port"), "3306");

    let cnf = std::env::temp_dir().join(format!(
        "hyperion-mysql-{}-{}.cnf",
        std::process::id(),
        site_dir(name)
    ));
    tokio::fs::write(
        &cnf,
        format!("[client]\nhost={host}\nuser={user}\npassword={pass}\nport={port}\n"),
    )
    .await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&cnf, std::fs::Permissions::from_mode(0o600)).await;
    }
    let cnf_q = shell_quote(&cnf.display().to_string());
    let res = sh_capture(&format!(
        "mysqldump --defaults-extra-file={cnf_q} --single-transaction --routines --triggers --events -- {}",
        shell_quote(name)
    ))
    .await;
    let _ = tokio::fs::remove_file(&cnf).await;
    Ok(Some(res?))
}

/// Drive CloudPanel's own `clpctl db:export`, which authenticates internally,
/// and normalise its output to the plain SQL the bundle/restore contract
/// requires. `Ok(false)` = clpctl produced nothing usable (caller records the
/// skip and falls through); `Err` = clpctl itself failed.
///
/// Hardening (a binary `.dump` would silently break the restore, which just
/// runs `mariadb < dump`): we (1) export into a fresh dir and pick up whatever
/// file clpctl actually writes — it may not honour `--file` exactly; (2) decide
/// gzip vs plain by MAGIC BYTES, never by "try gzip then copy raw on failure";
/// (3) accept the result only if it actually looks like a SQL dump.
///
/// Note: CloudPanel v1 used `db:backup` rather than `db:export`; v2 (CE 6.x,
/// what we target) uses `db:export`. On a v1 box this errors → the DB is
/// skipped-and-reported, never silently corrupted.
async fn clpctl_export(name: &str, dest: &Path) -> Result<bool, ImportError> {
    let dir = std::env::temp_dir().join(format!(
        "hyperion-clpexp-{}-{}",
        std::process::id(),
        site_dir(name)
    ));
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir).await?;
    let want = dir.join(format!("{}.sql.gz", site_dir(name)));
    let result = clpctl_export_inner(name, &dir, &want, dest).await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    result
}

async fn clpctl_export_inner(
    name: &str,
    dir: &Path,
    want: &Path,
    dest: &Path,
) -> Result<bool, ImportError> {
    let out = Command::new("clpctl")
        .arg("db:export")
        .arg(format!("--databaseName={name}"))
        .arg(format!("--file={}", want.display()))
        .output()
        .await?;
    if !out.status.success() {
        return Err(ImportError::Command {
            cmd: format!("clpctl db:export {name}"),
            msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    // clpctl may honour `want`, change the extension, or derive its own name —
    // take whatever single file landed in our fresh dir.
    let file = if tokio::fs::try_exists(want).await.unwrap_or(false) {
        want.to_path_buf()
    } else {
        match newest_file_in(dir).await {
            Some(f) => f,
            None => return Ok(false), // clpctl wrote nothing we can see
        }
    };

    let raw = tokio::fs::read(&file).await?;
    if raw.is_empty() {
        return Ok(false);
    }
    // gzip magic is 1f 8b. Decompress ONLY when it's really gzip; a failure here
    // is a genuine error (surfaced) — we never fall back to writing raw bytes.
    let plain = if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        sh_capture(&format!(
            "gzip -dc {}",
            shell_quote(&file.display().to_string())
        ))
        .await?
    } else {
        raw
    };
    // Refuse to write anything that isn't recognisably a SQL dump, so a stray
    // binary artefact is rejected here (recorded as a skip) instead of poisoning
    // the restore later.
    if !looks_like_sql(&plain) {
        return Ok(false);
    }
    tokio::fs::write(dest, &plain).await?;
    Ok(true)
}

/// Newest regular file in `dir`, if any.
async fn newest_file_in(dir: &Path) -> Option<PathBuf> {
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    while let Ok(Some(e)) = rd.next_entry().await {
        match e.metadata().await {
            Ok(m) if m.is_file() => {
                let t = m.modified().unwrap_or(std::time::UNIX_EPOCH);
                if best.as_ref().map(|(bt, _)| t >= *bt).unwrap_or(true) {
                    best = Some((t, e.path()));
                }
            }
            _ => {}
        }
    }
    best.map(|(_, p)| p)
}

/// Heuristic guard for the "db/<name>.dump is plain SQL" invariant: inspect only
/// the first 64 bytes (a dump's header is ASCII; binary content later in the
/// file is fine) and require it to begin with a token a SQL dump emits. A gzip
/// or other binary blob fails this and is rejected.
fn looks_like_sql(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(64)];
    let head_up = String::from_utf8_lossy(head)
        .trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
        .to_ascii_uppercase();
    if head_up.is_empty() {
        return false;
    }
    const PREFIXES: [&str; 13] = [
        "--",
        "/*",
        "#",
        "SET ",
        "CREATE",
        "INSERT",
        "DROP",
        "USE ",
        "LOCK",
        "ALTER",
        "DELIMITER",
        "START TRANSACTION",
        "BEGIN",
    ];
    PREFIXES.iter().any(|p| head_up.starts_with(p))
}

/// Run `sh -c <cmd>`, returning stdout on success or an error carrying stderr.
async fn sh_capture(cmd: &str) -> Result<Vec<u8>, ImportError> {
    let out = Command::new("sh").arg("-c").arg(cmd).output().await?;
    if !out.status.success() {
        return Err(ImportError::Command {
            cmd: cmd.to_string(),
            msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(out.stdout)
}

async fn run(bin: &str, args: &[&str]) -> Result<(), ImportError> {
    let out = Command::new(bin).args(args).output().await?;
    if !out.status.success() {
        return Err(ImportError::Command {
            cmd: format!("{bin} {}", args.join(" ")),
            msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{looks_like_sql, site_dir};

    #[test]
    fn looks_like_sql_accepts_real_dumps() {
        assert!(looks_like_sql(b"-- MySQL dump 10.19  Distrib 10.11\n"));
        assert!(looks_like_sql(
            b"/*!40101 SET @OLD_CHARACTER_SET=@@CHARACTER_SET */;"
        ));
        assert!(looks_like_sql(b"\n\n  CREATE TABLE `wp_posts` ("));
        assert!(looks_like_sql(b"\xEF\xBB\xBF-- with a UTF-8 BOM\n")); // BOM then SQL
                                                                       // Binary content AFTER an SQL header is fine (we only inspect the head).
        let mut v = b"INSERT INTO t VALUES (".to_vec();
        v.extend_from_slice(&[0u8, 1, 2, 3, 255, 254]);
        assert!(looks_like_sql(&v));
    }

    #[test]
    fn looks_like_sql_rejects_binary_and_gzip() {
        assert!(!looks_like_sql(&[0x1f, 0x8b, 0x08, 0x00, 0x00])); // gzip magic
        assert!(!looks_like_sql(b"")); // empty
        assert!(!looks_like_sql(&[0u8, 1, 2, 3, 4, 5])); // raw bytes
        assert!(!looks_like_sql(b"\x89PNG\r\n\x1a\n")); // a PNG, not SQL
    }

    #[test]
    fn site_dir_collapses_unsafe_chars() {
        assert_eq!(site_dir("a.example.com"), "a.example.com");
        assert_eq!(site_dir("a/b c:d"), "a_b_c_d");
    }
}
