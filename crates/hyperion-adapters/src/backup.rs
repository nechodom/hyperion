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
    // `--` ends option parsing so a `source_subdir` that ever begins with `-`
    // can't be reinterpreted as a tar flag (tar's --use-compress-program /
    // --to-command / --checkpoint-action=exec would be RCE as root). Callers
    // pass the literal "htdocs" today; this keeps it safe for future callers.
    cmd::run(
        "/usr/bin/tar",
        &[
            "-czf",
            &archive_str,
            "-C",
            &source_root_str,
            "--",
            source_subdir,
        ],
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
            // `--` so a db name beginning with `-` can't become a client option.
            "--",
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
    let archive = archive.to_path_buf();
    let target_root = target_root.to_path_buf();
    // Extraction is synchronous (flate2 + tar) and security-sensitive, so run it
    // on a blocking thread with full member validation.
    tokio::task::spawn_blocking(move || extract_tar_gz_sandboxed(&archive, &target_root))
        .await
        .map_err(|e| AdapterError::Other(format!("restore task join: {e}")))?
}

/// Extract a gzip-compressed tar over `target_root`, refusing any member that
/// would escape the root.
///
/// SECURITY: backup archives can be fully attacker-controlled — a tenant can
/// upload a `.tar.gz` to restore over their own hosting, and cross-node /clone
/// imports download a bundle whose integrity digest the attacker also controls.
/// This runs as **root** on the worker, so a bare `tar -xzf` honouring `../`
/// members, absolute paths, or a symlink-then-write-through-it sequence would be
/// an arbitrary root-level file write (→ full node + cross-tenant compromise).
/// We therefore:
///   * reject members with absolute paths or any `..`/root/prefix component;
///   * reject symlink/hardlink members whose target is absolute or contains `..`;
///   * re-check the joined destination stays under the canonical root, and rely
///     on `tar`'s own `unpack_in` escape guard as a second layer;
///   * NOT preserve permissions/ownership from the archive, so a crafted
///     setuid-root file or attacker uid can't be planted (the service layer
///     re-chowns the restored tree to the hosting's own user afterwards).
fn extract_tar_gz_sandboxed(archive: &Path, target_root: &Path) -> Result<u64, AdapterError> {
    use std::path::Component;

    let archive_len = std::fs::metadata(archive)?.len();
    let target_canon = std::fs::canonicalize(target_root)
        .map_err(|e| AdapterError::Other(format!("restore target canonicalize: {e}")))?;

    let file = std::fs::File::open(archive)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut ar = tar::Archive::new(gz);
    // Do NOT trust archive-recorded perms/owner/setuid bits.
    ar.set_preserve_permissions(false);
    ar.set_preserve_mtime(true);
    ar.set_overwrite(true);

    let entries = ar
        .entries()
        .map_err(|e| AdapterError::Other(format!("restore read entries: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| AdapterError::Other(format!("restore entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| AdapterError::Other(format!("restore member path: {e}")))?
            .into_owned();

        let unsafe_component = |p: &Path| {
            p.is_absolute()
                || p.components().any(|c| {
                    matches!(
                        c,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
        };
        if unsafe_component(&path) {
            return Err(AdapterError::Other(format!(
                "refused unsafe archive member: {}",
                path.display()
            )));
        }
        // Symlink/hardlink targets must also stay inside the root.
        if matches!(
            entry.header().entry_type(),
            tar::EntryType::Symlink | tar::EntryType::Link
        ) {
            if let Ok(Some(link)) = entry.link_name() {
                if unsafe_component(&link) {
                    return Err(AdapterError::Other(format!(
                        "refused unsafe link member: {} -> {}",
                        path.display(),
                        link.display()
                    )));
                }
            }
        }
        // Belt-and-braces: the joined path must remain under the canonical root.
        if !target_canon.join(&path).starts_with(&target_canon) {
            return Err(AdapterError::Other(format!(
                "archive member escapes target root: {}",
                path.display()
            )));
        }
        // `unpack_in` applies its own traversal guard and returns Ok(false) if it
        // would have written outside the destination.
        let unpacked = entry
            .unpack_in(&target_canon)
            .map_err(|e| AdapterError::Other(format!("restore unpack: {e}")))?;
        if !unpacked {
            return Err(AdapterError::Other(format!(
                "tar refused member as out-of-bounds: {}",
                path.display()
            )));
        }
    }
    Ok(archive_len)
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
    // `--` so a db name beginning with `-` can't become a mariadb client option.
    crate::cmd::run_with_stdin("/usr/bin/mariadb", &["--", db_name], &sql_bytes).await?;
    Ok(())
}

/// Remote backup destination — FTP/FTPS/SFTP via curl. Passwords are
/// passed through `--user user:pass` (so they appear in argv; we run
/// this only inside the agent process, no shell on argv).
#[derive(Debug, Clone)]
pub struct RemoteUpload<'a> {
    /// "ftp", "ftps", or "sftp".
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub password: &'a str,
    /// Path on the remote (the basename of the local file is appended).
    pub remote_dir: &'a str,
}

/// Push a local file to a remote destination via curl. Returns the URL
/// the file landed at.
pub async fn upload_remote(file: &Path, upload: &RemoteUpload<'_>) -> Result<String, AdapterError> {
    let scheme = match upload.scheme {
        "ftp" | "ftps" | "sftp" => upload.scheme,
        other => {
            return Err(AdapterError::Other(format!(
                "unsupported remote scheme: {other}"
            )))
        }
    };
    let filename = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AdapterError::Other("file has no name".into()))?;
    // Normalise to a single leading slash + no trailing slash. Operator
    // config may give a base_path without a leading '/' (e.g. "backups"),
    // which would otherwise produce "ftp://host:21backups/..." — curl
    // reads "21backups" as the port and every push fails.
    let dir = format!("/{}", upload.remote_dir.trim_matches('/'));
    let url = format!(
        "{scheme}://{host}:{port}{dir}/{filename}",
        host = upload.host,
        port = upload.port,
    );
    let creds = format!("{}:{}", upload.user, upload.password);
    let args: Vec<&str> = vec![
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "300",
        // FTP: create missing remote directories.
        "--ftp-create-dirs",
        "--user",
        &creds,
        "--upload-file",
        file.to_str()
            .ok_or_else(|| AdapterError::Other("file path not utf8".into()))?,
        &url,
    ];
    cmd::run("/usr/bin/curl", &args).await?;
    Ok(url)
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

    #[tokio::test]
    async fn restore_archive_round_trips_a_clean_tree() {
        let d = tempfile::tempdir().expect("dir");
        let src = d.path().join("source");
        std::fs::create_dir_all(src.join("htdocs/sub")).expect("mkdir");
        std::fs::write(src.join("htdocs/index.php"), b"<?php echo 1;").expect("w");
        std::fs::write(src.join("htdocs/sub/a.txt"), b"hello").expect("w");
        let archive = d.path().join("b.tar.gz");
        make_archive(&src, "htdocs", &archive)
            .await
            .expect("archive");

        let target = d.path().join("restore");
        std::fs::create_dir_all(&target).expect("mkdir target");
        let n = restore_archive(&archive, &target).await.expect("restore");
        assert!(n > 0);
        assert_eq!(
            std::fs::read(target.join("htdocs/index.php")).expect("read"),
            b"<?php echo 1;"
        );
        assert_eq!(
            std::fs::read(target.join("htdocs/sub/a.txt")).expect("read"),
            b"hello"
        );
    }

    #[tokio::test]
    async fn restore_archive_refuses_parent_traversal_symlink() {
        // The `tar` crate's Builder refuses to *write* a `..` in a regular
        // member path, so we exercise the same `ParentDir` guard via a symlink
        // whose target escapes upward (link names are not sanitised on write).
        let d = tempfile::tempdir().expect("dir");
        let archive = d.path().join("evil.tar.gz");
        {
            let f = std::fs::File::create(&archive).expect("create");
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            let mut b = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_mode(0o777);
            h.set_cksum();
            b.append_link(&mut h, "htdocs/evil", "../../../../etc/cron.d/x")
                .expect("append link");
            b.finish().expect("finish");
        }
        let target = d.path().join("victim/inner");
        std::fs::create_dir_all(&target).expect("mkdir");
        let res = restore_archive(&archive, &target).await;
        assert!(res.is_err(), "`..` symlink target must be refused");
        assert!(
            !target.join("evil").exists(),
            "escaping symlink should not have been created"
        );
    }

    #[tokio::test]
    async fn restore_archive_refuses_absolute_symlink_member() {
        let d = tempfile::tempdir().expect("dir");
        let archive = d.path().join("evil2.tar.gz");
        {
            let f = std::fs::File::create(&archive).expect("create");
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            let mut b = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_mode(0o777);
            h.set_cksum();
            b.append_link(&mut h, "htdocs/evil", "/etc/passwd")
                .expect("append link");
            b.finish().expect("finish");
        }
        let target = d.path().join("victim");
        std::fs::create_dir_all(&target).expect("mkdir");
        let res = restore_archive(&archive, &target).await;
        assert!(res.is_err(), "absolute symlink member must be refused");
        assert!(
            !target.join("evil").exists(),
            "escaping symlink should not have been created"
        );
    }
}
