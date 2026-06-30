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
/// would escape the root. Public wrapper over [`extract_archive_sandboxed`]
/// (gzip-decoded). Signature unchanged so existing callers keep working.
///
/// SECURITY: backup archives can be fully attacker-controlled — a tenant can
/// upload a `.tar.gz` to restore over their own hosting, and cross-node /clone
/// imports download a bundle whose integrity digest the attacker also controls.
/// This runs as **root** on the worker, so a bare `tar -xzf` honouring `../`
/// members, absolute paths, or a symlink-then-write-through-it sequence would be
/// an arbitrary root-level file write (→ full node + cross-tenant compromise).
/// See [`extract_archive_sandboxed`] for the per-member containment checks.
pub fn extract_tar_gz_sandboxed(archive: &Path, target_root: &Path) -> Result<u64, AdapterError> {
    let archive_len = std::fs::metadata(archive)?.len();
    let file = std::fs::File::open(archive)?;
    let gz = flate2::read::GzDecoder::new(file);
    extract_archive_sandboxed(gz, target_root)?;
    Ok(archive_len)
}

/// Extract a *plain* (non-gzip) tar over `target_root`, refusing any member that
/// would escape the root. Same containment guarantees as
/// [`extract_tar_gz_sandboxed`]; used for uncompressed bundle archives (the
/// panel-import outer `bundle.tar`).
pub fn extract_tar_sandboxed(archive: &Path, target_root: &Path) -> Result<u64, AdapterError> {
    let archive_len = std::fs::metadata(archive)?.len();
    let file = std::fs::File::open(archive)?;
    extract_archive_sandboxed(file, target_root)?;
    Ok(archive_len)
}

/// Core sandboxed tar extractor. Reads tar entries from `reader` (already
/// decompressed if needed) and unpacks them under `target_root`, applying the
/// full per-member containment validation. Returns the number of members
/// unpacked.
///
/// SECURITY (this runs as **root** on the worker against attacker-controlled
/// archives, so a bare `tar` would be an arbitrary root file write):
///   * reject members with absolute paths or any `..`/root/prefix component;
///   * reject symlink/hardlink members whose target is absolute or contains `..`;
///   * re-check the joined destination stays under the canonical root, and rely
///     on `tar`'s own `unpack_in` escape guard as a second layer;
///   * NOT preserve permissions/ownership from the archive, so a crafted
///     setuid-root file or attacker uid can't be planted (the service layer
///     re-chowns the restored tree to the hosting's own user afterwards).
fn extract_archive_sandboxed<R: std::io::Read>(
    reader: R,
    target_root: &Path,
) -> Result<u64, AdapterError> {
    use std::path::Component;

    let target_canon = std::fs::canonicalize(target_root)
        .map_err(|e| AdapterError::Other(format!("restore target canonicalize: {e}")))?;

    let mut ar = tar::Archive::new(reader);
    // Do NOT trust archive-recorded perms/owner/setuid bits.
    ar.set_preserve_permissions(false);
    ar.set_preserve_mtime(true);
    ar.set_overwrite(true);

    let mut count = 0u64;
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
        count += 1;
    }
    Ok(count)
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

// ── S3-compatible off-site upload (Wasabi / B2 / Minio / AWS) ────────────────

const AWS_BIN: &str = "/usr/bin/aws";
const AGE_BIN: &str = "/usr/bin/age";

/// A resolved S3 destination — the secret is already read from its 0600 file,
/// so this is the upload-ready view. `age_recipient` set ⇒ the object is
/// age-encrypted client-side, STREAMED (`age | aws`) so no plaintext-encrypted
/// copy ever touches local disk (matters when the disk is tight).
pub struct S3UploadTarget<'a> {
    pub endpoint: &'a str,
    pub bucket: &'a str,
    pub region: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub age_recipient: Option<&'a str>,
}

/// Confirm the CLIs the runner shells out to are installed, with a friendly
/// message pointing at the apt packages. `need_age` only when encrypting.
pub fn ensure_s3_tools(need_age: bool) -> Result<(), AdapterError> {
    if !Path::new(AWS_BIN).exists() {
        return Err(AdapterError::Other(format!(
            "{AWS_BIN} not found — run `apt install awscli` on this node to enable S3 backups"
        )));
    }
    if need_age && !Path::new(AGE_BIN).exists() {
        return Err(AdapterError::Other(format!(
            "{AGE_BIN} not found — run `apt install age` (the target has an age recipient set)"
        )));
    }
    Ok(())
}

/// `aws s3 cp` argv. Credentials NEVER ride here — they go via env so they
/// can't leak to `/proc/<pid>/cmdline`. `src` is "-" for a stdin stream or a
/// local path.
fn aws_s3_cp_args(src: &str, remote_uri: &str, endpoint: &str) -> Vec<String> {
    vec![
        "--endpoint-url".into(),
        endpoint.to_string(),
        "s3".into(),
        "cp".into(),
        "--only-show-errors".into(),
        src.to_string(),
        remote_uri.to_string(),
    ]
}

fn aws_env(t: &S3UploadTarget<'_>) -> [(&'static str, String); 3] {
    [
        ("AWS_ACCESS_KEY_ID", t.access_key_id.to_string()),
        ("AWS_SECRET_ACCESS_KEY", t.secret_access_key.to_string()),
        (
            "AWS_DEFAULT_REGION",
            if t.region.trim().is_empty() {
                "us-east-1".to_string()
            } else {
                t.region.to_string()
            },
        ),
    ]
}

/// Upload one local file to `s3://<bucket>/<remote_key>`. When the target has
/// an age recipient the object is encrypted on the fly (`.age` is appended to
/// the key) by streaming `age -o - <file> | aws s3 cp - <uri>` — no temp file.
/// Returns the final object key.
pub async fn upload_s3(
    local_file: &Path,
    remote_key: &str,
    t: &S3UploadTarget<'_>,
) -> Result<String, AdapterError> {
    use std::process::Stdio;
    let recipient = t.age_recipient.map(str::trim).filter(|r| !r.is_empty());
    ensure_s3_tools(recipient.is_some())?;

    let key = match recipient {
        Some(_) => format!("{}.age", remote_key.trim_start_matches('/')),
        None => remote_key.trim_start_matches('/').to_string(),
    };
    let remote_uri = format!("s3://{}/{}", t.bucket.trim_matches('/'), key);
    let env = aws_env(t);

    if let Some(recipient) = recipient {
        // Stream: age reads the archive, writes ciphertext to stdout; aws reads
        // that on stdin. age stderr → null so a chatty stderr can't deadlock the
        // pipe; its exit code is the source of truth.
        let infile = std::fs::File::open(local_file)
            .map_err(|e| AdapterError::Other(format!("open {}: {e}", local_file.display())))?;
        let mut age = tokio::process::Command::new(AGE_BIN)
            .args(["-r", recipient, "-o", "-"])
            .stdin(Stdio::from(infile))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| AdapterError::Other(format!("spawn age: {e}")))?;
        let age_out = age
            .stdout
            .take()
            .ok_or_else(|| AdapterError::Other("age stdout unavailable".into()))?;
        let age_stdio: Stdio = age_out
            .try_into()
            .map_err(|e| AdapterError::Other(format!("age stdout → stdio: {e}")))?;
        let args = aws_s3_cp_args("-", &remote_uri, t.endpoint);
        let mut cmd = tokio::process::Command::new(AWS_BIN);
        cmd.args(&args).stdin(age_stdio);
        for (k, v) in &env {
            cmd.env(k, v);
        }
        let aws_out = cmd
            .output()
            .await
            .map_err(|e| AdapterError::Other(format!("spawn aws: {e}")))?;
        let age_status = age
            .wait()
            .await
            .map_err(|e| AdapterError::Other(format!("wait age: {e}")))?;
        if !age_status.success() {
            return Err(AdapterError::Other(format!(
                "age encryption failed (exit {:?})",
                age_status.code()
            )));
        }
        if !aws_out.status.success() {
            return Err(AdapterError::Other(format!(
                "aws upload failed: {}",
                String::from_utf8_lossy(&aws_out.stderr).trim()
            )));
        }
    } else {
        let src = local_file
            .to_str()
            .ok_or_else(|| AdapterError::Other("file path not utf8".into()))?;
        let args = aws_s3_cp_args(src, &remote_uri, t.endpoint);
        let mut cmd = tokio::process::Command::new(AWS_BIN);
        cmd.args(&args);
        for (k, v) in &env {
            cmd.env(k, v);
        }
        let out = cmd
            .output()
            .await
            .map_err(|e| AdapterError::Other(format!("spawn aws: {e}")))?;
        if !out.status.success() {
            return Err(AdapterError::Other(format!(
                "aws upload failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    Ok(key)
}

/// Extract the unix-timestamp a backup file was named with. Files are
/// `<domain>-<unixts>.<ext>[.age]` (the ts follows the LAST dash, before the
/// first dot), so this is robust to dashes/dots inside the domain.
fn parse_backup_ts(key: &str) -> Option<i64> {
    let name = key.rsplit('/').next().unwrap_or(key);
    let after_dash = name.rsplit_once('-')?.1;
    let digits: String = after_dash
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<i64>().ok()
}

/// Remote retention: keep the newest `keep` backup timestamps under `prefix`,
/// deleting every object belonging to older ones. `keep == 0` ⇒ no-op (keep
/// everything). Best-effort: parse/list failures return an error the caller
/// downgrades to a note — never fatal to the backup itself. Returns the number
/// of objects deleted.
pub async fn s3_prune_keep_latest(
    prefix: &str,
    keep: usize,
    t: &S3UploadTarget<'_>,
) -> Result<u64, AdapterError> {
    if keep == 0 {
        return Ok(0);
    }
    let env = aws_env(t);
    let prefix = prefix.trim_start_matches('/');
    let mut cmd = tokio::process::Command::new(AWS_BIN);
    cmd.args([
        "--endpoint-url",
        t.endpoint,
        "s3api",
        "list-objects-v2",
        "--bucket",
        t.bucket,
        "--prefix",
        prefix,
        "--output",
        "json",
    ]);
    for (k, v) in &env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .await
        .map_err(|e| AdapterError::Other(format!("spawn aws list: {e}")))?;
    if !out.status.success() {
        return Err(AdapterError::Other(format!(
            "aws list-objects failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let listing: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| AdapterError::Other(format!("parse list-objects json: {e}")))?;
    let contents = listing
        .get("Contents")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    // (key, ts) for every object that parses a ts.
    let mut keyed: Vec<(String, i64)> = contents
        .iter()
        .filter_map(|o| {
            let key = o.get("Key").and_then(|k| k.as_str())?.to_string();
            let ts = parse_backup_ts(&key)?;
            Some((key, ts))
        })
        .collect();
    if keyed.is_empty() {
        return Ok(0);
    }
    // Distinct timestamps, newest first; everything past the keep window dies.
    let mut tss: Vec<i64> = keyed.iter().map(|(_, ts)| *ts).collect();
    tss.sort_unstable_by(|a, b| b.cmp(a));
    tss.dedup();
    let doomed: std::collections::HashSet<i64> = tss.into_iter().skip(keep).collect();
    if doomed.is_empty() {
        return Ok(0);
    }
    keyed.retain(|(_, ts)| doomed.contains(ts));
    let mut deleted = 0u64;
    for (key, _) in &keyed {
        let mut dc = tokio::process::Command::new(AWS_BIN);
        dc.args([
            "--endpoint-url",
            t.endpoint,
            "s3api",
            "delete-object",
            "--bucket",
            t.bucket,
            "--key",
            key,
        ]);
        for (k, v) in &env {
            dc.env(k, v);
        }
        match dc.output().await {
            Ok(o) if o.status.success() => deleted += 1,
            _ => { /* best-effort; leave it for the next run */ }
        }
    }
    Ok(deleted)
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

    /// Build a plain `.tar` at `path` from `(name, kind, body_or_linktarget)`
    /// members. `kind` is "file" or "symlink".
    fn build_plain_tar(path: &Path, members: &[(&str, &str, &str)]) {
        let f = std::fs::File::create(path).expect("create tar");
        let mut b = tar::Builder::new(f);
        for (name, kind, payload) in members {
            if *kind == "symlink" {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                h.set_mode(0o777);
                b.append_link(&mut h, name, payload)
                    .expect("append symlink");
            } else {
                let mut h = tar::Header::new_gnu();
                h.set_size(payload.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, payload.as_bytes())
                    .expect("append file");
            }
        }
        b.finish().expect("finish tar");
    }

    #[test]
    fn extract_tar_sandboxed_happy_path() {
        let d = tempfile::tempdir().expect("dir");
        let tar = d.path().join("bundle.tar");
        build_plain_tar(&tar, &[("ok/inside.txt", "file", "hello")]);
        let dest = d.path().join("dest");
        std::fs::create_dir_all(&dest).expect("dest");
        let n = extract_tar_sandboxed(&tar, &dest).expect("extract");
        assert!(n > 0);
        assert_eq!(
            std::fs::read_to_string(dest.join("ok/inside.txt")).unwrap(),
            "hello"
        );
    }

    /// Write a single-member tar by hand, so we can plant a `..` path that
    /// `tar::Builder` would otherwise refuse to encode (mirrors a real attacker
    /// who hand-crafts the bytes, which is exactly the threat the extractor
    /// guards against).
    fn build_raw_traversal_tar(path: &Path, member: &str, body: &[u8]) {
        let mut header = [0u8; 512];
        let name = member.as_bytes();
        header[..name.len()].copy_from_slice(name);
        // mode "0000644\0"
        header[100..108].copy_from_slice(b"0000644\0");
        // uid/gid
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        // size (octal, 11 digits + space)
        let size = format!("{:011o} ", body.len());
        header[124..136].copy_from_slice(size.as_bytes());
        // mtime
        header[136..148].copy_from_slice(b"00000000000 ");
        // typeflag '0' = regular file
        header[156] = b'0';
        // ustar magic
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // checksum: 8 spaces while computing, then octal sum.
        for b in &mut header[148..156] {
            *b = b' ';
        }
        let sum: u32 = header.iter().map(|&b| b as u32).sum();
        let cksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(cksum.as_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        // pad body to 512
        let pad = (512 - (body.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        // two zero blocks = end of archive
        out.extend(std::iter::repeat_n(0u8, 1024));
        std::fs::write(path, &out).expect("write raw tar");
    }

    #[test]
    fn extract_tar_sandboxed_rejects_traversal() {
        let d = tempfile::tempdir().expect("dir");
        let tar = d.path().join("bundle.tar");
        build_raw_traversal_tar(&tar, "../escape.txt", b"pwn");
        let dest = d.path().join("dest");
        std::fs::create_dir_all(&dest).expect("dest");
        let err = extract_tar_sandboxed(&tar, &dest).unwrap_err();
        assert!(
            format!("{err:?}").contains("unsafe archive member")
                || format!("{err:?}").contains("escapes target root"),
            "got: {err:?}"
        );
        assert!(!d.path().join("escape.txt").exists());
    }

    #[test]
    fn extract_tar_sandboxed_rejects_absolute_symlink() {
        let d = tempfile::tempdir().expect("dir");
        let tar = d.path().join("bundle.tar");
        // Symlink member pointing outside the root (the panel-import zip-slip class).
        build_plain_tar(&tar, &[("leak", "symlink", "/etc/passwd")]);
        let dest = d.path().join("dest");
        std::fs::create_dir_all(&dest).expect("dest");
        let err = extract_tar_sandboxed(&tar, &dest).unwrap_err();
        assert!(
            format!("{err:?}").contains("unsafe link member"),
            "got: {err:?}"
        );
        assert!(!dest.join("leak").exists());
    }

    #[test]
    fn parse_backup_ts_handles_dashes_and_extensions() {
        assert_eq!(
            parse_backup_ts("user/my-site.cz-1700000000.tar.gz"),
            Some(1700000000)
        );
        assert_eq!(
            parse_backup_ts("user/my-site.cz-1700000000.tar.gz.age"),
            Some(1700000000)
        );
        assert_eq!(parse_backup_ts("a-1.cz-1699999999.sql"), Some(1699999999));
        assert_eq!(
            parse_backup_ts("user/site.cz-1700000000.manifest.json"),
            Some(1700000000)
        );
        assert_eq!(parse_backup_ts("no-timestamp-here.txt"), None);
    }

    #[test]
    fn aws_cp_args_carry_endpoint_and_never_secrets() {
        let args = aws_s3_cp_args("-", "s3://b/k.age", "https://s3.example.com");
        assert!(args.iter().any(|a| a == "--endpoint-url"));
        assert!(args.contains(&"https://s3.example.com".to_string()));
        assert!(args.contains(&"s3://b/k.age".to_string()));
        // Credentials must travel via env, never argv.
        assert!(!args
            .iter()
            .any(|a| a.contains("SECRET") || a.starts_with("AKIA")));
    }

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
