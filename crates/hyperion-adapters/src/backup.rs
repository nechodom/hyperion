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
    // NOT cmd::run: that treats any non-zero exit as failure, and tar's exit
    // codes are not a simple success/failure pair.
    //
    //   0 — everything archived
    //   1 — "some files differ": a file changed or vanished WHILE being read.
    //       The archive is complete and restorable; the affected file just
    //       holds its pre-change contents.
    //   2 — fatal.
    //
    // On a live WordPress site the tar takes minutes once the tree is large,
    // and in minutes something always changes — a page cache, a session file,
    // a log. So exit 1 is the NORMAL outcome for a big site and the abnormal
    // one for a small one, which is exactly why backups "started failing when
    // the site got big". Treating it as failure threw away a perfectly good
    // archive and told the operator their backup was broken.
    let out = tokio::process::Command::new("/usr/bin/tar")
        .args([
            "-czf",
            &archive_str,
            "-C",
            &source_root_str,
            "--",
            source_subdir,
        ])
        .output()
        .await?;
    let code = out.status.code().unwrap_or(-1);
    if code != 0 && code != 1 {
        return Err(AdapterError::Command {
            cmd: format!("tar -czf {archive_str}"),
            code,
            stderr_tail: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    if code == 1 {
        // Accepted on the exit CODE, not on the message text.
        //
        // GNU tar's contract is explicit: 1 means "some files differ" — the
        // archive was written completely, some members just do not match
        // what was on disk by the end. 2 is the fatal code that aborts the
        // archive. Matching on wording instead looked safer and was not: the
        // first version of this listed "changed as we read it" and friends,
        // and CI immediately produced a case it did not cover — "File shrank
        // by 7701504 bytes; padding with zeros". There is no closed set of
        // sentences to match, and every one missed turns a good backup into
        // a reported failure. The exit code is the interface.
        tracing::info!(
            archive = %archive_str,
            detail = %String::from_utf8_lossy(&out.stderr)
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join("; "),
            "tar reported changed files during the archive — expected on a live site; \
             the archive is complete"
        );
    }
    let meta = tokio::fs::metadata(archive_path).await?;
    // A zero-length archive is a failure whatever tar said.
    if meta.len() == 0 {
        return Err(AdapterError::Other(format!(
            "tar produced an empty archive at {archive_str}"
        )));
    }
    Ok(meta.len())
}

/// Dump a MariaDB database into `path`. Caller owns mariadb-client install.
pub async fn dump_mariadb(db_name: &str, path: &Path) -> Result<u64, AdapterError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    // Streamed straight into the file. `.output()` would collect the WHOLE
    // dump in memory first — for a large site that is gigabytes of RSS in one
    // spike, which on a modest VPS is an OOM kill dressed up as "the backup
    // failed". stderr is still captured, because it is small and it is the
    // only thing worth reporting.
    dump_to_file(
        "/usr/bin/mariadb-dump",
        &[
            "--single-transaction",
            "--routines",
            "--triggers",
            "--events",
            // `--` so a db name beginning with `-` can't become a client option.
            "--",
            db_name,
        ],
        path,
        &format!("mariadb-dump {db_name}"),
    )
    .await
}

/// Run `program` with its stdout going DIRECTLY to `path`, never through a
/// buffer in this process.
async fn dump_to_file(
    program: &str,
    args: &[&str],
    path: &Path,
    label: &str,
) -> Result<u64, AdapterError> {
    let file = std::fs::File::create(path)?;
    // `.spawn()` + `wait_with_output()`, NOT `.output()`. `.output()`
    // overrides stdout with a pipe of its own — so it silently undoes the
    // redirection and buffers the whole dump in memory anyway, which is the
    // exact thing being fixed here.
    let child = tokio::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::from(file))
        .stderr(std::process::Stdio::piped())
        .spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => {
            // File::create already made the file; do not leave an empty one
            // behind to be mistaken for a real dump.
            let _ = tokio::fs::remove_file(path).await;
            return Err(e.into());
        }
    };
    let out = match child.wait_with_output().await {
        Ok(o) => o,
        Err(e) => {
            let _ = tokio::fs::remove_file(path).await;
            return Err(e.into());
        }
    };
    if !out.status.success() {
        // Leave no half-written dump behind to be mistaken for a good one.
        let _ = tokio::fs::remove_file(path).await;
        return Err(AdapterError::Command {
            cmd: label.to_string(),
            code: out.status.code().unwrap_or(-1),
            stderr_tail: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    let meta = tokio::fs::metadata(path).await?;
    if meta.len() == 0 {
        let _ = tokio::fs::remove_file(path).await;
        return Err(AdapterError::Other(format!(
            "{label} produced an empty dump"
        )));
    }
    Ok(meta.len())
}

/// Dump a PostgreSQL database into `path` using `sudo -u postgres pg_dump`.
pub async fn dump_postgres(db_name: &str, path: &Path) -> Result<u64, AdapterError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    // Streamed, for the same reason as the MariaDB dump.
    dump_to_file(
        "/usr/bin/sudo",
        &["-u", "postgres", "/usr/bin/pg_dump", "-Fc", db_name],
        path,
        &format!("pg_dump {db_name}"),
    )
    .await
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

/// Read one small member out of a plain tar WITHOUT unpacking the archive.
///
/// The panel import needs the bundle's `manifest.json` *before* it commits the
/// disk that unpacking costs, because the sizes recorded in that manifest are
/// what say whether the unpack can fit at all. Reading it back after extraction
/// would be reading it after the damage.
///
/// Safe against a hostile bundle by construction: nothing is written to disk
/// (so no path traversal is even expressible here), the member is matched by
/// exact name against both `name` and `./name` — the form `tar cf -C dir .`
/// produces — and it is truncated at `max_bytes`, so a manifest inflated to
/// gigabytes cannot become an allocation of its own size.
///
/// `None` for any failure at all: not a tar, member absent, unreadable. The
/// caller must treat that as "no information", never as "empty".
pub fn read_tar_member(archive: &Path, name: &str, max_bytes: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(archive).ok()?;
    let mut ar = tar::Archive::new(file);
    for entry in ar.entries().ok()? {
        let mut entry = entry.ok()?;
        let matches = entry
            .path()
            .ok()
            .map(|p| {
                let p = p.to_string_lossy();
                p == name || p.strip_prefix("./") == Some(name)
            })
            .unwrap_or(false);
        if !matches {
            continue;
        }
        let mut buf = Vec::new();
        entry.by_ref().take(max_bytes).read_to_end(&mut buf).ok()?;
        return Some(buf);
    }
    None
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

/// Remote backup destination — FTP/FTPS/SFTP via curl.
///
/// The password does NOT go on argv. It used to, with the reasoning that
/// there is no shell involved — which answers shell injection and not the
/// actual exposure: `/proc/<pid>/cmdline` is world-readable, so every tenant
/// with shell, FTP or PHP on this node could read it. And this is the
/// node-wide backup account: one read gives an attacker every other tenant's
/// archives and database dumps, and the ability to delete them. A push of a
/// several-hundred-megabyte archive holds that argv for minutes, on a
/// schedule, so no race was even needed.
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
    let local = file
        .to_str()
        .ok_or_else(|| AdapterError::Other("file path not utf8".into()))?;
    // Every interpolated value is escaped: a password containing a quote
    // would otherwise close the value and be read as further directives.
    let config = format!(
        concat!(
            "user = \"{user}:{password}\"\n",
            "upload-file = \"{local}\"\n",
            "url = \"{url}\"\n",
            "fail\n",
            "silent\n",
            "show-error\n",
            "max-time = 300\n",
            // FTP: create missing remote directories.
            "ftp-create-dirs\n",
        ),
        user = cmd::curl_config_quote(upload.user),
        password = cmd::curl_config_quote(upload.password),
        local = cmd::curl_config_quote(local),
        url = cmd::curl_config_quote(&url),
    );
    cmd::curl_with_config(&config).await?;
    Ok(url)
}

/// Is the file really on the remote, at the right size?
///
/// A zero exit from the upload means the transfer returned success. It does
/// not mean the bytes are on the far side: a full disk, a quota, a proxy that
/// buffered and dropped, an FTP server that accepted and discarded — all of
/// those can produce a clean upload and no file. The only way to know is to
/// look, so this asks the server for the size and compares it.
///
/// Three answers, and they must stay three. `Ok(Some(true))` is "we looked and
/// it is there at the right size". `Ok(Some(false))` is "we looked and it is
/// not". `Ok(None)` and `Err` are both "we could not look" — the server did
/// not answer with a size we can read, or we could not reach it at all — and
/// neither may be recorded as failure, because the upload may well be fine.
pub async fn verify_remote(
    file: &Path,
    upload: &RemoteUpload<'_>,
) -> Result<Option<bool>, AdapterError> {
    let want = tokio::fs::metadata(file)
        .await
        .map_err(|e| AdapterError::Other(format!("stat {}: {e}", file.display())))?
        .len();
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
    let dir = format!("/{}", upload.remote_dir.trim_matches('/'));
    let url = format!(
        "{scheme}://{host}:{port}{dir}/{filename}",
        host = upload.host,
        port = upload.port,
    );
    // `head` over FTP asks for SIZE rather than transferring anything, and
    // `write-out` hands back just the number so nothing has to parse a
    // protocol-specific listing format.
    let config = format!(
        concat!(
            "user = \"{user}:{password}\"\n",
            "url = \"{url}\"\n",
            "head\n",
            "fail\n",
            "silent\n",
            "show-error\n",
            "max-time = 60\n",
            "write-out = \"%{{size_download}} %{{size_upload}} %{{filename_effective}}\"\n",
        ),
        user = cmd::curl_config_quote(upload.user),
        password = cmd::curl_config_quote(upload.password),
        url = cmd::curl_config_quote(&url),
    );
    // curl reports an FTP SIZE response in `Content-Length`, which it exposes
    // through the header block rather than through size_download on a HEAD.
    // Parse whichever of the two carries a number.
    let out = cmd::curl_with_config(&config).await?;
    // THREE answers, not two. `None` is "the server answered but not with a
    // size we could read" — plenty of FTP servers do that — and folding it
    // into `false` told the operator a perfectly good backup was missing.
    // The doc comment above already promised three states; the code returned
    // two.
    Ok(parse_remote_size(&out).map(|seen| seen == want))
}

/// Pull a byte count out of curl's HEAD output for an FTP URL.
///
/// Servers differ: some answer a real `Content-Length`, some only emit the
/// raw `213 <size>` of the SIZE command. Both shapes are read, and anything
/// unrecognised yields `None` — which the caller treats as "could not look",
/// never as "not there".
pub fn parse_remote_size(out: &str) -> Option<u64> {
    for line in out.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("Content-Length:") {
            if let Ok(n) = rest.trim().parse::<u64>() {
                return Some(n);
            }
        }
        // `213 1234` — the FTP SIZE reply.
        if let Some(rest) = l.strip_prefix("213 ") {
            if let Ok(n) = rest.trim().parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

/// One file on the remote store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub bytes: u64,
}

/// What is actually on the remote for this site.
///
/// The half that never existed. Until this, everything the panel knew about
/// the off-site copy came from the moment of upload — so a file deleted,
/// truncated or never written by the far side was invisible, and an operator
/// whose node was gone had no way to find out what they still had.
pub async fn list_remote(upload: &RemoteUpload<'_>) -> Result<Vec<RemoteEntry>, AdapterError> {
    let scheme = match upload.scheme {
        "ftp" | "ftps" | "sftp" => upload.scheme,
        other => {
            return Err(AdapterError::Other(format!(
                "unsupported remote scheme: {other}"
            )))
        }
    };
    let dir = format!("/{}", upload.remote_dir.trim_matches('/'));
    // The trailing slash is what makes curl LIST a directory rather than
    // retrieve a file of that name.
    let url = format!(
        "{scheme}://{host}:{port}{dir}/",
        host = upload.host,
        port = upload.port,
    );
    let config = format!(
        concat!(
            "user = \"{user}:{password}\"\n",
            "url = \"{url}\"\n",
            "fail\n",
            "silent\n",
            "show-error\n",
            "max-time = 120\n",
        ),
        user = cmd::curl_config_quote(upload.user),
        password = cmd::curl_config_quote(upload.password),
        url = cmd::curl_config_quote(&url),
    );
    Ok(parse_ftp_listing(&cmd::curl_with_config(&config).await?))
}

/// Parse the `LIST` output curl returns for an FTP directory.
///
/// Unix-style `ls -l`, which is what essentially every FTP server emits:
/// `-rw-r--r-- 1 user group 12345 Jan  1 00:00 name.tar.gz`. Anything that
/// does not look like that is skipped rather than guessed at — a wrong size
/// here would make `verify` call a good backup broken.
pub fn parse_ftp_listing(out: &str) -> Vec<RemoteEntry> {
    let mut v = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Directories and symlinks are not backups.
        if f.len() < 9 || !line.starts_with('-') {
            continue;
        }
        let Ok(bytes) = f[4].parse::<u64>() else {
            continue;
        };
        // The name is everything from field 8 on, so a filename containing
        // spaces survives.
        let name = f[8..].join(" ");
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        v.push(RemoteEntry { name, bytes });
    }
    v
}

/// Fetch one file off the remote into `dest`.
///
/// `dest` is chosen by the caller and must be somewhere the restore is allowed
/// to read from — this function does not decide that, and deliberately does
/// not take the file name from the remote listing without the caller having
/// validated it, because a remote server is not a trusted source of paths.
pub async fn download_remote(
    filename: &str,
    dest: &Path,
    upload: &RemoteUpload<'_>,
    max_bytes: u64,
) -> Result<u64, AdapterError> {
    // A name from a listing is attacker-influenced if the remote store is,
    // and it is interpolated into a URL — so curl will PERCENT-DECODE it
    // before asking for a path. Rejecting a literal `/` was not enough:
    // `%2f` and `%2e%2e%2f` sail through a substring check and arrive at the
    // server as `../`, which walks out of this site's directory and into
    // another tenant's.
    //
    // So the rule is an allow-list, not a deny-list. A backup file name is
    // ASCII letters, digits, dot, dash and underscore — anything else,
    // including a percent sign, is refused rather than reasoned about.
    let plain = !filename.is_empty()
        && filename.len() <= 255
        && filename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && !filename.contains("..")
        && !filename.starts_with('.')
        && !filename.starts_with('-');
    if !plain {
        return Err(AdapterError::Other(format!(
            "refusing a remote file name that is not a plain backup file name: {filename:?}"
        )));
    }
    let scheme = match upload.scheme {
        "ftp" | "ftps" | "sftp" => upload.scheme,
        other => {
            return Err(AdapterError::Other(format!(
                "unsupported remote scheme: {other}"
            )))
        }
    };
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| AdapterError::Other(format!("create {}: {e}", parent.display())))?;
    }
    let dir = format!("/{}", upload.remote_dir.trim_matches('/'));
    let url = format!(
        "{scheme}://{host}:{port}{dir}/{filename}",
        host = upload.host,
        port = upload.port,
    );
    let local = dest
        .to_str()
        .ok_or_else(|| AdapterError::Other("destination path not utf8".into()))?;
    let config = format!(
        concat!(
            "user = \"{user}:{password}\"\n",
            "url = \"{url}\"\n",
            "output = \"{local}\"\n",
            "fail\n",
            "silent\n",
            "show-error\n",
            // A restore of a large site is not a 300-second job.
            "max-time = 3600\n",
            // A remote that serves an endless stream would otherwise fill the
            // node's disk and take every site on it down. curl aborts past
            // this, and the caller's own free-space check decides the number.
            "max-filesize = {cap}\n",
        ),
        cap = max_bytes,
        user = cmd::curl_config_quote(upload.user),
        password = cmd::curl_config_quote(upload.password),
        url = cmd::curl_config_quote(&url),
        local = cmd::curl_config_quote(local),
    );
    cmd::curl_with_config(&config).await?;
    let n = tokio::fs::metadata(dest)
        .await
        .map_err(|e| AdapterError::Other(format!("stat {}: {e}", dest.display())))?
        .len();
    if n == 0 {
        // curl can exit 0 having written nothing at all.
        let _ = tokio::fs::remove_file(dest).await;
        return Err(AdapterError::Other(
            "the remote file downloaded as zero bytes".into(),
        ));
    }
    Ok(n)
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

    /// A wrong size here would make a good backup look broken, so anything
    /// not recognised must yield None rather than a guess.
    #[test]
    fn remote_size_is_read_from_either_shape_or_not_at_all() {
        assert_eq!(
            super::parse_remote_size("Content-Length: 4096\r\n"),
            Some(4096)
        );
        assert_eq!(super::parse_remote_size("213 12345\r\n"), Some(12345));
        // Not a number, not a size line, empty: all "could not look".
        assert_eq!(super::parse_remote_size("Content-Length: big"), None);
        assert_eq!(super::parse_remote_size("550 Not Found"), None);
        assert_eq!(super::parse_remote_size(""), None);
    }

    #[test]
    fn ftp_listing_takes_files_and_skips_everything_else() {
        let out = "drwxr-xr-x 2 u g 4096 Jan  1 00:00 subdir\n\
                   -rw-r--r-- 1 u g 12345 Jan  1 00:00 site-1700000000.tar.gz\n\
                   lrwxrwxrwx 1 u g 7 Jan  1 00:00 link -> target\n\
                   -rw-r--r-- 1 u g 42 Jan  1 00:00 name with spaces.sql\n\
                   garbage\n";
        let v = super::parse_ftp_listing(out);
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!(v[0].name, "site-1700000000.tar.gz");
        assert_eq!(v[0].bytes, 12345);
        // A filename with spaces survives, because the name is everything
        // from the ninth field on.
        assert_eq!(v[1].name, "name with spaces.sql");
    }

    /// A remote store is not a trusted source of paths. A listing entry that
    /// escapes its directory must never become a write target.
    /// The allow-list, stated as the property it protects: whatever survives
    /// the check must still be a plain file name AFTER a percent-decode,
    /// because curl decodes the URL before asking the server for a path.
    #[test]
    fn an_accepted_name_cannot_decode_into_a_path() {
        fn accepted(name: &str) -> bool {
            !name.is_empty()
                && name.len() <= 255
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
                && !name.contains("..")
                && !name.starts_with('.')
                && !name.starts_with('-')
        }
        // The shapes that defeated the old substring check.
        for escape in ["%2f", "%2F", "%2e%2e%2f", "..%2f", "%00", "/", "\\", ".."] {
            let name = format!("site{escape}x.tar.gz");
            assert!(!accepted(&name), "would have accepted {name:?}");
        }
        // An ordinary backup name still works, or the feature is useless.
        assert!(accepted("example.cz-1700000000.tar.gz"));
        assert!(accepted("example_cz-1700000000.sql"));
    }

    #[test]
    fn verify_keeps_could_not_look_apart_from_not_there() {
        // The server answered, but not with a size anyone can read. That is
        // not evidence the file is missing, and folding it into `false` told
        // the operator a good backup had failed.
        assert_eq!(super::parse_remote_size("550 Permission denied"), None);
        assert_eq!(super::parse_remote_size("Content-Length: 10"), Some(10));
    }

    #[tokio::test]
    async fn a_remote_file_name_that_is_a_path_is_refused() {
        let up = super::RemoteUpload {
            scheme: "ftp",
            host: "example.invalid",
            port: 21,
            user: "u",
            password: "p",
            remote_dir: "/backups",
        };
        let dest = std::path::Path::new("/tmp/hyperion-test-never-written");
        // curl percent-DECODES the URL before asking the server for a path,
        // so a substring check for '/' never saw `%2f`. These are the names
        // that walked out of one tenant's directory and into another's.
        for bad in [
            "../../etc/passwd",
            "/etc/passwd",
            "a/b",
            "..",
            "",
            "%2f%2e%2e%2fother",
            "%2e%2e%2fsite.tar.gz",
            "..%2fsite.tar.gz",
            "a%00b",
            "-oflag",
            ".hidden",
            "name with spaces.tar.gz",
        ] {
            assert!(
                super::download_remote(bad, dest, &up, 1024).await.is_err(),
                "accepted {bad:?}"
            );
        }
        assert!(!dest.exists(), "a refused name still wrote something");
    }
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

    /// The import reads the bundle's manifest BEFORE unpacking, to decide
    /// whether the unpack can fit. So the reader has to find the member under
    /// the `./` prefix `tar cf -C dir .` writes, and has to answer `None` —
    /// never an empty body — for anything it cannot produce, because the
    /// caller reads `None` as "no figure, skip the check".
    #[test]
    fn read_tar_member_finds_the_manifest_and_says_none_otherwise() {
        let d = tempfile::tempdir().expect("dir");
        let tar = d.path().join("bundle.tar");
        build_plain_tar(
            &tar,
            &[
                ("./manifest.json", "file", r#"{"hostings":[]}"#),
                (
                    "./sites/a.cz/docroot.tar.gz",
                    "file",
                    "not really a tarball",
                ),
            ],
        );

        let got = read_tar_member(&tar, "manifest.json", 8 * 1024 * 1024).expect("manifest");
        assert_eq!(String::from_utf8_lossy(&got), r#"{"hostings":[]}"#);

        // Absent member, and a path that is not a tar at all.
        assert!(read_tar_member(&tar, "nope.json", 4096).is_none());
        let bogus = d.path().join("missing.tar");
        assert!(read_tar_member(&bogus, "manifest.json", 4096).is_none());

        // The cap truncates rather than allocating whatever the archive claims.
        let capped = read_tar_member(&tar, "manifest.json", 4).expect("capped");
        assert_eq!(capped.len(), 4);
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

#[cfg(test)]
mod large_backup_tests {
    use super::*;

    /// tar exits 1 for "some files differ" — a file changed or vanished while
    /// being read. The archive is complete and restorable.
    ///
    /// This is the NORMAL outcome on a live site big enough that the tar
    /// takes minutes, because in minutes something always changes: a page
    /// cache, a session, a log. Treating it as failure is why backups
    /// "started failing when the site got big" while small sites were fine.
    #[tokio::test]
    async fn a_file_changing_mid_archive_still_produces_a_backup() {
        let d = tempfile::tempdir().expect("tmp");
        let src = d.path().join("site");
        std::fs::create_dir_all(src.join("htdocs")).expect("mk");
        // A file big enough that tar is still reading it when we truncate.
        std::fs::write(src.join("htdocs/big.bin"), vec![b'x'; 8 * 1024 * 1024]).expect("w");
        for i in 0..50 {
            std::fs::write(src.join(format!("htdocs/f{i}.txt")), "hello").expect("w");
        }
        let archive = d.path().join("out.tar.gz");

        let changer = {
            let p = src.join("htdocs/big.bin");
            std::thread::spawn(move || {
                // Rewrite it repeatedly while tar runs.
                for _ in 0..40 {
                    let _ = std::fs::write(&p, vec![b'y'; 8 * 1024 * 1024]);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            })
        };
        let res = make_archive(&src, "htdocs", &archive).await;
        let _ = changer.join();

        // Either tar won the race (exit 0) or it saw the change (exit 1 —
        // "file changed", "File shrank by …", any of the wordings GNU tar
        // uses). All must produce a usable archive, never an error.
        let size = res.expect("a changed file must not fail the backup");
        assert!(size > 0, "archive is empty");
        assert!(archive.exists());
    }

    /// A genuinely fatal tar (exit >= 2) must still be an error — the
    /// tolerance above must not swallow a real failure.
    ///
    /// Linux-only, and that is the point: the tolerance is written against
    /// GNU tar's exit-code contract (1 = some files differ, 2 = fatal), which
    /// is what ships on the Debian nodes. bsdtar on a macOS dev box returns 1
    /// where GNU returns 2, so running this there would assert a contract
    /// that is not the one in production.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_missing_source_is_still_an_error() {
        let d = tempfile::tempdir().expect("tmp");
        let archive = d.path().join("out.tar.gz");
        let err = make_archive(d.path(), "does-not-exist", &archive).await;
        assert!(
            err.is_err(),
            "tar failing to find its source must not be reported as a good backup"
        );
    }

    /// The dumps must never be buffered in this process: `.output()` on a
    /// multi-gigabyte dump is an OOM kill reported as "the backup failed".
    #[tokio::test]
    async fn dumps_stream_to_disk_without_buffering() {
        let d = tempfile::tempdir().expect("tmp");
        let out = d.path().join("dump.sql");
        // 16 MiB through the pipe. The assertion that matters is not the
        // size — it is that the bytes land in the file without this process
        // collecting them.
        let n = dump_to_file(
            "/usr/bin/env",
            &["dd", "if=/dev/zero", "bs=1048576", "count=16"],
            &out,
            "dd",
        )
        .await
        .expect("stream");
        assert_eq!(n, 16 * 1024 * 1024);
        assert_eq!(std::fs::metadata(&out).expect("stat").len(), n);
    }

    /// A failed dump must not leave a half-written file that a later restore
    /// would treat as a real one.
    #[tokio::test]
    async fn a_failed_dump_leaves_no_file_behind() {
        let d = tempfile::tempdir().expect("tmp");
        let out = d.path().join("dump.sql");
        let err = dump_to_file("/usr/bin/env", &["false"], &out, "false").await;
        assert!(err.is_err());
        assert!(!out.exists(), "a failed dump must not leave a file");
    }
}
