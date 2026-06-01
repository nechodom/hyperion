//! Local backup creation: tar+gzip of a directory + optional `mysqldump` /
//! `pg_dump` to a sidecar `.sql` file, plus a JSON manifest.
//!
//! Sub-project 5 in the spec asks for restic + remote targets — that lands
//! when we ship a real deployment. v1 ships this tighter, dependency-light
//! local path because every Linux box has tar and gzip.

use crate::{cmd, AdapterError};
use hyperion_types::DbProvision;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub hosting_id: String,
    pub domain: String,
    pub system_user: String,
    pub php_version: Option<String>,
    pub database: Option<ManifestDb>,
    pub started_at: i64,
    pub schema_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestDb {
    pub engine: String, // "mariadb" | "postgres"
    pub name: String,
    pub user: String,
}

#[derive(Debug, Clone)]
pub struct BackupOutput {
    pub archive_path: PathBuf,
    pub db_dump_path: Option<PathBuf>,
    pub bytes_total: u64,
}

/// Produce a `tar -czf <archive_path> -C <source_root> <source_subdir>`
/// archive. Used for htdocs + logs etc.
pub async fn make_archive(
    source_root: &Path,
    source_subdir: &str,
    archive_path: &Path,
) -> Result<u64, AdapterError> {
    if let Some(parent) = archive_path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let archive_str = archive_path.display().to_string();
    let source_root_str = source_root.display().to_string();
    cmd::run(
        "/usr/bin/tar",
        &["-czf", &archive_str, "-C", &source_root_str, source_subdir],
    )
    .await?;
    let meta = tokio::fs::metadata(archive_path).await?;
    Ok(meta.len())
}

/// Dump a MariaDB database into `path`. Caller owns mariadb-client install.
pub async fn dump_mariadb(db_name: &str, path: &Path) -> Result<u64, AdapterError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    // mariadb-dump writes to stdout; capture it as a file.
    let out = tokio::process::Command::new("/usr/bin/mariadb-dump")
        .args([
            "--single-transaction",
            "--routines",
            "--triggers",
            "--events",
            db_name,
        ])
        .output()
        .await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return Err(AdapterError::Command {
            cmd: format!("mariadb-dump {db_name}"),
            code: out.status.code().unwrap_or(-1),
            stderr_tail: stderr,
        });
    }
    tokio::fs::write(path, &out.stdout).await?;
    let meta = tokio::fs::metadata(path).await?;
    Ok(meta.len())
}

/// Dump a PostgreSQL database into `path` using `sudo -u postgres pg_dump`.
pub async fn dump_postgres(db_name: &str, path: &Path) -> Result<u64, AdapterError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let out = tokio::process::Command::new("/usr/bin/sudo")
        .args(["-u", "postgres", "/usr/bin/pg_dump", "-Fc", db_name])
        .output()
        .await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return Err(AdapterError::Command {
            cmd: format!("pg_dump {db_name}"),
            code: out.status.code().unwrap_or(-1),
            stderr_tail: stderr,
        });
    }
    tokio::fs::write(path, &out.stdout).await?;
    let meta = tokio::fs::metadata(path).await?;
    Ok(meta.len())
}

/// Write the manifest JSON.
pub async fn write_manifest(manifest: &BackupManifest, path: &Path) -> Result<(), AdapterError> {
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|e| AdapterError::Other(format!("manifest serialize: {e}")))?;
    crate::fs::atomic_write(path, &bytes, 0o600).await
}

/// Extract a previously-taken `tar.gz` over a hosting tree. Restores
/// only the `htdocs` subdir (the only thing make_archive writes) so the
/// rest of the tree (logs/, tmp/) stays whatever the operator has there.
///
/// Roughly equivalent to `tar -xzf <archive> -C <target_root>` — the
/// archive root is the hosting's `htdocs` directory.
pub async fn restore_archive(archive: &Path, target_root: &Path) -> Result<u64, AdapterError> {
    if !archive.exists() {
        return Err(AdapterError::Other(format!(
            "archive not found: {}",
            archive.display()
        )));
    }
    tokio::fs::create_dir_all(target_root).await?;
    let archive_str = archive.display().to_string();
    let target_str = target_root.display().to_string();
    cmd::run(
        "/usr/bin/tar",
        &["-xzf", &archive_str, "-C", &target_str],
    )
    .await?;
    let meta = tokio::fs::metadata(archive).await?;
    Ok(meta.len())
}

/// Restore a `mariadb-dump` SQL dump file into the named DB. Drops +
/// recreates objects (the dump includes DROP/CREATE if --add-drop-table
/// is set; mariadb-dump default does).
pub async fn restore_mariadb_dump(db_name: &str, sql_path: &Path) -> Result<(), AdapterError> {
    if !sql_path.exists() {
        return Err(AdapterError::Other(format!(
            "sql dump not found: {}",
            sql_path.display()
        )));
    }
    let sql_bytes = tokio::fs::read(sql_path).await?;
    crate::cmd::run_with_stdin("/usr/bin/mariadb", &[db_name], &sql_bytes).await?;
    Ok(())
}

/// Restore a `pg_dump -Fc` archive (custom format) into `db_name`.
pub async fn restore_postgres_dump(db_name: &str, dump_path: &Path) -> Result<(), AdapterError> {
    if !dump_path.exists() {
        return Err(AdapterError::Other(format!(
            "pg dump not found: {}",
            dump_path.display()
        )));
    }
    let dump_str = dump_path.display().to_string();
    cmd::run(
        "/usr/bin/sudo",
        &[
            "-u",
            "postgres",
            "/usr/bin/pg_restore",
            "--clean",
            "--if-exists",
            "-d",
            db_name,
            &dump_str,
        ],
    )
    .await?;
    Ok(())
}

pub fn engine_str(engine: DbProvision) -> &'static str {
    match engine {
        DbProvision::MariaDB => "mariadb",
        DbProvision::Postgres => "postgres",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn manifest_round_trip() {
        let m = BackupManifest {
            hosting_id: "01J7A".into(),
            domain: "example.cz".into(),
            system_user: "example_cz".into(),
            php_version: Some("8.3".into()),
            database: Some(ManifestDb {
                engine: "mariadb".into(),
                name: "lm_a_db".into(),
                user: "lm_a_u".into(),
            }),
            started_at: 100,
            schema_version: 1,
        };
        let s = serde_json::to_string(&m).expect("ser");
        let back: BackupManifest = serde_json::from_str(&s).expect("de");
        assert_eq!(back.hosting_id, "01J7A");
        assert_eq!(back.database.as_ref().unwrap().engine, "mariadb");
    }

    #[tokio::test]
    async fn make_archive_creates_tarball() {
        // Set up a sub-tree, tar it, assert the archive exists + is non-empty.
        let d = tempfile::tempdir().expect("dir");
        let root = d.path().join("source");
        std::fs::create_dir_all(root.join("htdocs")).expect("mkdir");
        std::fs::write(root.join("htdocs/index.php"), b"<?php echo 'hi';").expect("write");
        let archive = d.path().join("out.tar.gz");
        let bytes = make_archive(&root, "htdocs", &archive).await.expect("tar");
        assert!(archive.exists());
        assert!(bytes > 0, "non-empty archive");
        let head = std::fs::read(&archive).expect("read")[..2].to_vec();
        // gzip magic bytes
        assert_eq!(head, [0x1f, 0x8b]);
    }

    #[tokio::test]
    #[ignore = "requires mariadb-dump on PATH"]
    async fn dump_mariadb_round_trip() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("d.sql");
        let _ = dump_mariadb("information_schema", &p).await.expect("dump");
        assert!(p.exists());
    }
}
