//! Bounded, security-paranoid filesystem browser for hosting files.
//!
//! All accesses are scoped to one "jail" directory (the hosting's
//! htdocs root). Symlinks are refused — we never follow them out of
//! the jail. Path components are validated client-supplied; even after
//! canonicalisation the result MUST still live inside the jail or we
//! refuse. Read size is capped at MAX_INLINE_BYTES.

use crate::AdapterError;
use std::path::{Component, Path, PathBuf};

/// Hard cap on inline-rendered file size. Browsing a 100 MiB log file
/// would OOM the agent + clog the RPC pipe. Operators wanting full
/// files use the legacy hosting_logs / scp paths.
pub const MAX_INLINE_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Reject any path component that's empty, `.`, `..`, or contains
/// `/` (already split, but defensive), NUL or another control character.
///
/// Control characters too: resolved paths end up in generated config
/// (an extra FTP login's `local_root=` line in its vsftpd user file), where
/// a newline in a directory name the site user created would start a
/// directive of their choosing.
fn safe_component(c: &str) -> bool {
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.contains('/')
        && !c.contains('\\')
        && !c.chars().any(char::is_control)
}

/// Join `rel_path` under `jail`, refusing anything that escapes
/// (`..`, absolute, symlink, NUL byte). Returns the canonicalised
/// absolute path inside the jail. `rel_path` is treated as forward-
/// slash separated for portability with UI-supplied values.
pub async fn resolve_inside_jail(jail: &Path, rel_path: &str) -> Result<PathBuf, AdapterError> {
    // The jail path itself lives under tenant-owned directories
    // (`/home/<user>/<domain>/htdocs`): the site user owns its home, so it can
    // replace `htdocs` — or the `<domain>` directory — with a symlink. The
    // `canonicalize(jail)` below follows links, which would relocate the whole
    // jail to an attacker-chosen tree (e.g. `/`), and every containment check
    // afterwards is then measured against that followed root. The per-component
    // walk further down only covers segments *below* the jail, so it never
    // sees this. Refuse a symlink at any component of the jail path first.
    //
    // This closes the demonstrated jail-root swap. The deeper fix — returning a
    // verified O_DIRECTORY|O_NOFOLLOW descriptor and performing every read/
    // write/chown/rename openat2-relative to it, instead of handing back a path
    // string the sinks re-open by name — is tracked separately; the check-then-
    // use window on the returned path remains until that refactor lands.
    //
    // We lstat the two tenant-ownable components — the jail itself (`htdocs`)
    // and its parent (`<domain>`) — rather than every ancestor: system
    // ancestors above the home are root-controlled and are not the swap
    // vector, and walking them would trip over legitimately symlinked system
    // directories (e.g. `/var` on some platforms).
    for p in [Some(jail), jail.parent()].into_iter().flatten() {
        let md = tokio::fs::symlink_metadata(p)
            .await
            .map_err(|e| AdapterError::Other(format!("jail not accessible: {e}")))?;
        if md.file_type().is_symlink() {
            return Err(AdapterError::Other(
                "refusing jail: jail root or its parent is a symlink".into(),
            ));
        }
    }

    let jail_canon = tokio::fs::canonicalize(jail)
        .await
        .map_err(|e| AdapterError::Other(format!("jail not accessible: {e}")))?;

    if rel_path.contains('\0') {
        return Err(AdapterError::Other("invalid path (NUL byte)".into()));
    }
    // Split on forward slash. Empty rel_path means "the jail root".
    let mut candidate = jail_canon.clone();
    for raw in rel_path.split('/') {
        if raw.is_empty() {
            // Collapse double-slash + leading-slash gracefully.
            continue;
        }
        if !safe_component(raw) {
            return Err(AdapterError::Other(format!(
                "invalid path component: {raw:?}"
            )));
        }
        candidate.push(raw);
    }
    // Refuse symlinks FIRST — check the candidate path (before
    // canonicalize, which would resolve them). Also walk every
    // intermediate ancestor between the jail and the candidate to
    // refuse symlinked path segments (e.g. /jail/realdir/link.txt
    // where realdir is a symlink).
    {
        let mut walker = jail_canon.clone();
        let suffix = candidate
            .strip_prefix(&jail_canon)
            .unwrap_or(Path::new(""))
            .to_path_buf();
        for c in suffix.components() {
            if let Component::Normal(seg) = c {
                walker.push(seg);
                if let Ok(md) = tokio::fs::symlink_metadata(&walker).await {
                    if md.file_type().is_symlink() {
                        return Err(AdapterError::Other(
                            "refusing to follow symlink in path".into(),
                        ));
                    }
                }
            }
        }
    }

    // canonicalize() resolves symlinks (we already refused those
    // above, so this is a no-op for legitimate paths). If the target
    // doesn't exist yet (browsing into a missing directory), fall
    // back to a logical-component containment check.
    let final_path = match tokio::fs::canonicalize(&candidate).await {
        Ok(p) => p,
        Err(_) => candidate.clone(),
    };

    // Defense in depth — walking components of the canonicalised path
    // must never produce a `..` AND the canonicalised path must start
    // with the jail.
    for c in final_path.components() {
        if matches!(c, Component::ParentDir) {
            return Err(AdapterError::Other("path escapes jail".into()));
        }
    }
    if !final_path.starts_with(&jail_canon) {
        return Err(AdapterError::Other("path escapes jail".into()));
    }
    Ok(final_path)
}

/// MIME guess from file extension. Returns text-y MIMEs for things
/// the UI can render inline; `application/octet-stream` for everything
/// else. Used to gate inline viewing.
pub fn guess_mime(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    let ext = std::path::Path::new(&lower)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    match ext {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" | "cjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "txt" | "text" => "text/plain",
        "md" => "text/markdown",
        "log" => "text/plain",
        "php" | "phtml" => "application/x-php",
        "py" => "text/x-python",
        "rb" => "text/x-ruby",
        "rs" => "text/x-rust",
        "go" => "text/x-go",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "ini" | "conf" | "cfg" => "text/plain",
        "sh" | "bash" | "zsh" => "application/x-sh",
        "sql" => "application/sql",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        // Common binary types — return MIME but UI won't inline.
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

/// Whether the UI should offer inline rendering for a MIME.
pub fn is_inline_text(mime: &str) -> bool {
    mime.starts_with("text/")
        || matches!(
            mime,
            "application/json"
                | "application/xml"
                | "application/yaml"
                | "application/toml"
                | "application/javascript"
                | "application/x-sh"
                | "application/sql"
                | "application/x-php"
        )
}

/// Types nobody reads as text. The listing offers "open" for everything else
/// up to the inline cap — `.htaccess`, `.env`, `Makefile` and every other
/// name whose extension says nothing — and the read then looks at the bytes.
pub fn is_known_binary(mime: &str) -> bool {
    mime.starts_with("image/") && mime != "image/svg+xml"
        || mime.starts_with("font/")
        || matches!(
            mime,
            "application/pdf" | "application/zip" | "application/gzip"
        )
}

/// A NUL in the first 8 KiB: the same test `grep` and `git` use to call a
/// file binary. Text in a legacy encoding passes, which is what we want —
/// it can be shown, just not saved back.
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8 * 1024).any(|b| *b == 0)
}

/// Resolve the directory entry `rel_path` names WITHOUT following it.
///
/// `resolve_inside_jail` refuses a symlink at the last component, which is
/// right for reading and writing through a path and wrong for the two
/// operations that act on the entry itself: unlinking a symlink and renaming
/// one never touch what it points at. The parent still goes through the full
/// resolver, so every directory on the way is a real one inside the jail.
pub async fn resolve_entry_in_jail(jail: &Path, rel_path: &str) -> Result<PathBuf, AdapterError> {
    let trimmed = rel_path.trim_matches('/');
    let (parent, name) = match trimmed.rfind('/') {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("", trimmed),
    };
    if !safe_component(name) {
        return Err(AdapterError::Other(format!(
            "invalid path component: {name:?}"
        )));
    }
    let dir = resolve_inside_jail(jail, parent).await?;
    let md = tokio::fs::symlink_metadata(&dir)
        .await
        .map_err(|e| AdapterError::Other(format!("stat: {e}")))?;
    if !md.is_dir() {
        return Err(AdapterError::Other("parent is not a directory".into()));
    }
    Ok(dir.join(name))
}

/// What a file looked like when it was read: modification time to the
/// nanosecond, and length. Opaque to the caller, who hands it back with a
/// save so an edit made elsewhere in between is noticed, not overwritten.
pub fn file_version(md: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "{}-{}",
        md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128,
        md.len()
    )
}

/// Conditions on a write.
#[derive(Debug, Clone, Default)]
pub struct WriteOpts {
    /// Refuse unless the file on disk still has this [`file_version`].
    pub expect_version: Option<String>,
    /// Refuse when anything already has this name.
    pub create_only: bool,
}

/// Hard cap on the size of a single uploaded/written file. 64 MiB
/// is comfortable for plugin ZIPs + WordPress backups without
/// letting an operator (or an attacker with a valid session) fill
/// the disk in one request.
pub const MAX_WRITE_BYTES: u64 = 64 * 1024 * 1024;

/// Atomically write bytes to a file inside the jail. Resolves the
/// path through `resolve_inside_jail` so all the symlink / traversal
/// rules apply. The parent directory is created on demand (one
/// level only — operators can't create deeply-nested paths in one
/// shot, which would invite typos like "newdiir/file.txt" being
/// silently created).
pub async fn write_file_in_jail(
    jail: &std::path::Path,
    rel_path: &str,
    bytes: &[u8],
    opts: &WriteOpts,
) -> Result<(), AdapterError> {
    if bytes.len() as u64 > MAX_WRITE_BYTES {
        return Err(AdapterError::Other(format!(
            "file too large ({} bytes > {} cap)",
            bytes.len(),
            MAX_WRITE_BYTES
        )));
    }
    let abs = resolve_inside_jail(jail, rel_path).await?;
    if abs
        == tokio::fs::canonicalize(jail)
            .await
            .unwrap_or_else(|_| jail.to_path_buf())
    {
        return Err(AdapterError::Other(
            "refusing to write the jail root itself".into(),
        ));
    }
    if let Some(parent) = abs.parent() {
        // Parent must exist already — refuse implicit deep mkdir.
        if !parent.exists() {
            return Err(AdapterError::Other(format!(
                "parent directory does not exist: {}",
                parent.display()
            )));
        }
    }
    // Atomic write through a fresh, exclusive, no-follow temp file. The
    // directory belongs to the site user: a predictable `<name>.tmp` opened
    // by path was a place to plant a symlink and have root write these
    // bytes wherever it pointed.
    //
    // The mode is the existing file's: a save must not turn a 0600
    // wp-config.php world-readable or strip the x from a script. Only the
    // permission bits — never setuid/setgid from a tenant's tree.
    let mut mode = 0o644;
    match tokio::fs::symlink_metadata(&abs).await {
        Ok(md) => {
            if opts.create_only {
                return Err(AdapterError::Other("path already exists".into()));
            }
            if !md.is_file() {
                return Err(AdapterError::Other("not a regular file".into()));
            }
            if let Some(want) = &opts.expect_version {
                if *want != file_version(&md) {
                    return Err(AdapterError::Other(
                        "changed on disk since it was opened".into(),
                    ));
                }
            }
            use std::os::unix::fs::PermissionsExt;
            mode = md.permissions().mode() & 0o777;
        }
        Err(_) => {
            if opts.expect_version.is_some() {
                return Err(AdapterError::Other(
                    "changed on disk since it was opened (the file is gone)".into(),
                ));
            }
        }
    }
    crate::fs::atomic_write(&abs, bytes, mode)
        .await
        .map_err(|e| AdapterError::Other(format!("write: {e}")))
}

/// Chown a path inside the jail to `owner:owner`. Called after the
/// panel File Manager creates or overwrites a file/dir: the agent runs
/// as root, so the new inode is root-owned, and the hosting's PHP /
/// WordPress and its FTP account (both running AS the system user) can
/// then no longer modify or delete it (e.g. editing wp-config.php via
/// the panel would lock WordPress out of rewriting it). Best-effort at
/// the call site.
pub async fn chown_in_jail(
    jail: &std::path::Path,
    rel_path: &str,
    owner: &str,
) -> Result<(), AdapterError> {
    let abs = resolve_inside_jail(jail, rel_path).await?;
    let spec = format!("{owner}:{owner}");
    // `-h` even though the resolver already refused a symlinked path: the
    // check and the chown are two syscalls apart, and the directory between
    // them belongs to the tenant.
    crate::cmd::run(
        "/usr/bin/chown",
        &["-h", &spec, abs.to_string_lossy().as_ref()],
    )
    .await?;
    Ok(())
}

/// Delete one entry inside the jail: a file, a symlink (the link, never its
/// target), or a directory. A directory that still has contents is refused
/// unless `recursive` — the caller asks for that only after the operator
/// typed the folder's name.
pub async fn delete_in_jail(
    jail: &std::path::Path,
    rel_path: &str,
    recursive: bool,
) -> Result<(), AdapterError> {
    if rel_path.trim_matches('/').is_empty() {
        return Err(AdapterError::Other(
            "refusing to delete the jail root".into(),
        ));
    }
    let abs = resolve_entry_in_jail(jail, rel_path).await?;
    let md = tokio::fs::symlink_metadata(&abs)
        .await
        .map_err(|e| AdapterError::Other(format!("stat: {e}")))?;
    if !md.is_dir() {
        // Files and symlinks alike: unlink acts on the entry.
        return tokio::fs::remove_file(&abs)
            .await
            .map_err(|e| AdapterError::Other(format!("unlink: {e}")));
    }
    if recursive {
        // std's remove_dir_all walks by descriptor and unlinks symlinks it
        // meets instead of descending into them, so a link the tenant plants
        // mid-walk cannot steer root's delete out of this tree.
        return tokio::task::spawn_blocking(move || std::fs::remove_dir_all(&abs))
            .await
            .map_err(|e| AdapterError::Other(format!("delete task: {e}")))?
            .map_err(|e| AdapterError::Other(format!("delete: {e}")));
    }
    match tokio::fs::remove_dir(&abs).await {
        Ok(()) => Ok(()),
        // ENOTEMPTY on Linux; some platforms answer EEXIST for the same thing.
        Err(e)
            if [rustix::io::Errno::NOTEMPTY, rustix::io::Errno::EXIST]
                .iter()
                .any(|n| e.raw_os_error() == Some(n.raw_os_error())) =>
        {
            Err(AdapterError::Other(
                "refusing to delete non-empty directory — empty it first".into(),
            ))
        }
        Err(e) => Err(AdapterError::Other(format!("rmdir: {e}"))),
    }
}

/// Create one directory inside the jail. Parent must exist already
/// (no `mkdir -p` behaviour — same rationale as `write_file_in_jail`).
pub async fn mkdir_in_jail(jail: &std::path::Path, rel_path: &str) -> Result<(), AdapterError> {
    if rel_path.is_empty() || rel_path == "/" {
        return Err(AdapterError::Other(
            "refusing to mkdir the jail root".into(),
        ));
    }
    let abs = resolve_inside_jail(jail, rel_path).await?;
    if abs.exists() {
        return Err(AdapterError::Other("path already exists".into()));
    }
    if let Some(parent) = abs.parent() {
        if !parent.exists() {
            return Err(AdapterError::Other(format!(
                "parent directory does not exist: {}",
                parent.display()
            )));
        }
    }
    tokio::fs::create_dir(&abs)
        .await
        .map_err(|e| AdapterError::Other(format!("mkdir: {e}")))?;
    Ok(())
}

/// Rename or move a path inside the jail. Both `from` and `to` are
/// resolved through `resolve_inside_jail`, so cross-jail moves are
/// impossible. `to` must not exist (no silent overwrite).
pub async fn rename_in_jail(
    jail: &std::path::Path,
    from: &str,
    to: &str,
) -> Result<(), AdapterError> {
    if from.is_empty() || to.is_empty() {
        return Err(AdapterError::Other("rename: empty path".into()));
    }
    // Both ends are entries, not what they point at: a symlink is renamed
    // as a link, and a dangling link at the destination still counts as
    // "exists" (`Path::exists` follows and would say no).
    let from_abs = resolve_entry_in_jail(jail, from).await?;
    let to_abs = resolve_entry_in_jail(jail, to).await?;
    if tokio::fs::symlink_metadata(&to_abs).await.is_ok() {
        return Err(AdapterError::Other("destination already exists".into()));
    }
    if tokio::fs::symlink_metadata(&from_abs).await.is_err() {
        return Err(AdapterError::Other("source does not exist".into()));
    }
    tokio::fs::rename(&from_abs, &to_abs)
        .await
        .map_err(|e| AdapterError::Other(format!("rename: {e}")))?;
    Ok(())
}

/// Read raw bytes from a file in the jail. Used by the download
/// endpoint; differs from the inline-text path in that it accepts
/// binaries up to MAX_WRITE_BYTES. The CALLER is responsible for
/// streaming to the response — we read fully into memory here for
/// simplicity, capped at MAX_WRITE_BYTES.
pub async fn read_raw_in_jail(
    jail: &std::path::Path,
    rel_path: &str,
) -> Result<(Vec<u8>, String), AdapterError> {
    let abs = resolve_inside_jail(jail, rel_path).await?;
    let md = tokio::fs::metadata(&abs)
        .await
        .map_err(|e| AdapterError::Other(format!("stat: {e}")))?;
    if md.is_dir() {
        return Err(AdapterError::Other("path is a directory".into()));
    }
    if md.len() > MAX_WRITE_BYTES {
        return Err(AdapterError::Other(format!(
            "file too large ({} bytes > {} cap)",
            md.len(),
            MAX_WRITE_BYTES
        )));
    }
    let bytes = tokio::fs::read(&abs)
        .await
        .map_err(|e| AdapterError::Other(format!("read: {e}")))?;
    let name = abs
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    Ok((bytes, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_parent_dir_traversal() {
        let d = tempfile::tempdir().expect("tmp");
        let r = resolve_inside_jail(d.path(), "../etc/passwd").await;
        assert!(r.is_err(), "must reject ../");
    }

    #[tokio::test]
    async fn rejects_absolute_path() {
        let d = tempfile::tempdir().expect("tmp");
        // An absolute-looking string with leading slash should be
        // parsed component-wise and the absolute leading-empty piece
        // collapses; the result is the jail root, which is fine.
        // BUT an embedded /etc piece would resolve to jail/etc — also
        // fine because we never compose absolute paths. Verify the
        // jail-escape check via a deeper traversal.
        let r = resolve_inside_jail(d.path(), "/etc/../../etc/passwd").await;
        assert!(r.is_err(), "must reject embedded ..");
    }

    #[tokio::test]
    async fn rejects_nul_byte() {
        let d = tempfile::tempdir().expect("tmp");
        let r = resolve_inside_jail(d.path(), "ok/file\0name").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn empty_path_resolves_to_jail() {
        let d = tempfile::tempdir().expect("tmp");
        let p = resolve_inside_jail(d.path(), "").await.expect("ok");
        let canon = std::fs::canonicalize(d.path()).expect("c");
        assert_eq!(p, canon);
    }

    #[tokio::test]
    async fn happy_path_resolves_inside() {
        let d = tempfile::tempdir().expect("tmp");
        let sub = d.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        let f = sub.join("hello.txt");
        std::fs::write(&f, "hi").expect("write");
        let p = resolve_inside_jail(d.path(), "sub/hello.txt")
            .await
            .expect("ok");
        let canon_f = std::fs::canonicalize(&f).expect("c");
        assert_eq!(p, canon_f);
    }

    #[tokio::test]
    async fn refuses_symlink_inside_jail() {
        let d = tempfile::tempdir().expect("tmp");
        let target = d.path().join("real.txt");
        std::fs::write(&target, "x").expect("write");
        let link = d.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        // The link IS inside the jail, but symlinks are still refused
        // by policy — we never want to deal with the question of where
        // they point.
        let r = resolve_inside_jail(d.path(), "link.txt").await;
        assert!(r.is_err(), "must refuse symlinks");
    }

    #[tokio::test]
    async fn refuses_symlink_pointing_outside_jail() {
        let d = tempfile::tempdir().expect("tmp");
        let outside = tempfile::tempdir().expect("tmp2");
        let target = outside.path().join("secret.txt");
        std::fs::write(&target, "x").expect("write");
        let link = d.path().join("evil.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let r = resolve_inside_jail(d.path(), "evil.txt").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn refuses_jail_root_symlink() {
        // The site user owns its home and can replace `htdocs` (the jail root)
        // with a symlink; canonicalize would then follow it out of the tree.
        let base = tempfile::tempdir().expect("tmp");
        let real = base.path().join("real_htdocs");
        std::fs::create_dir(&real).expect("mkdir");
        std::fs::write(real.join("f.txt"), "x").expect("write");
        let jail = base.path().join("htdocs");
        std::os::unix::fs::symlink(&real, &jail).expect("symlink");
        let r = resolve_inside_jail(&jail, "f.txt").await;
        assert!(r.is_err(), "a symlinked jail root must be refused");
    }

    #[tokio::test]
    async fn refuses_jail_parent_symlink() {
        // The `<domain>` directory (the jail's parent) is equally swappable.
        let base = tempfile::tempdir().expect("tmp");
        let real_domain = base.path().join("real_domain");
        std::fs::create_dir(&real_domain).expect("mkdir");
        std::fs::create_dir(real_domain.join("htdocs")).expect("mkdir htdocs");
        let domain_link = base.path().join("domain");
        std::os::unix::fs::symlink(&real_domain, &domain_link).expect("symlink");
        let jail = domain_link.join("htdocs");
        let r = resolve_inside_jail(&jail, "").await;
        assert!(r.is_err(), "a symlinked jail parent must be refused");
    }

    #[test]
    fn mime_guesses_match_common_files() {
        assert_eq!(guess_mime("index.html"), "text/html");
        assert_eq!(guess_mime("style.css"), "text/css");
        assert_eq!(guess_mime("app.js"), "application/javascript");
        assert_eq!(guess_mime("config.toml"), "application/toml");
        assert_eq!(guess_mime("error.log"), "text/plain");
        assert_eq!(guess_mime("avatar.png"), "image/png");
        assert_eq!(guess_mime("font.woff2"), "font/woff2");
        assert_eq!(guess_mime("unknown.xyz"), "application/octet-stream");
        // Case-insensitive on the extension.
        assert_eq!(guess_mime("INDEX.HTML"), "text/html");
    }

    #[test]
    fn is_inline_text_matches_textual_mimes() {
        assert!(is_inline_text("text/html"));
        assert!(is_inline_text("application/json"));
        assert!(is_inline_text("application/javascript"));
        assert!(!is_inline_text("image/png"));
        assert!(!is_inline_text("application/octet-stream"));
    }

    #[tokio::test]
    async fn write_file_creates_and_round_trips() {
        let d = tempfile::tempdir().expect("tmp");
        write_file_in_jail(d.path(), "hello.txt", b"world", &WriteOpts::default())
            .await
            .expect("write");
        let (bytes, name) = read_raw_in_jail(d.path(), "hello.txt").await.expect("read");
        assert_eq!(bytes, b"world");
        assert_eq!(name, "hello.txt");
    }

    #[tokio::test]
    async fn write_file_refuses_oversized() {
        let d = tempfile::tempdir().expect("tmp");
        let huge = vec![0u8; (MAX_WRITE_BYTES + 1) as usize];
        let r = write_file_in_jail(d.path(), "big.bin", &huge, &WriteOpts::default()).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn write_file_refuses_traversal() {
        let d = tempfile::tempdir().expect("tmp");
        let r = write_file_in_jail(d.path(), "../escape.txt", b"x", &WriteOpts::default()).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn delete_file_works_but_refuses_root() {
        let d = tempfile::tempdir().expect("tmp");
        write_file_in_jail(d.path(), "junk.txt", b"x", &WriteOpts::default())
            .await
            .unwrap();
        delete_in_jail(d.path(), "junk.txt", false)
            .await
            .expect("delete");
        // Root refusal:
        let r = delete_in_jail(d.path(), "", false).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn delete_dir_refuses_non_empty() {
        let d = tempfile::tempdir().expect("tmp");
        mkdir_in_jail(d.path(), "stuff").await.expect("mkdir");
        write_file_in_jail(d.path(), "stuff/inner.txt", b"x", &WriteOpts::default())
            .await
            .expect("write");
        let r = delete_in_jail(d.path(), "stuff", false).await;
        assert!(r.is_err(), "must refuse non-empty dir");
        // Once we delete the file the dir is empty and removable.
        delete_in_jail(d.path(), "stuff/inner.txt", false)
            .await
            .unwrap();
        delete_in_jail(d.path(), "stuff", false)
            .await
            .expect("empty dir ok");
    }

    #[tokio::test]
    async fn mkdir_refuses_existing() {
        let d = tempfile::tempdir().expect("tmp");
        mkdir_in_jail(d.path(), "alpha").await.expect("mkdir");
        let r = mkdir_in_jail(d.path(), "alpha").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn rename_round_trips_and_refuses_overwrite() {
        let d = tempfile::tempdir().expect("tmp");
        write_file_in_jail(d.path(), "a.txt", b"x", &WriteOpts::default())
            .await
            .unwrap();
        rename_in_jail(d.path(), "a.txt", "b.txt")
            .await
            .expect("rename");
        // b.txt now exists, a.txt doesn't.
        assert!(d.path().join("b.txt").exists());
        assert!(!d.path().join("a.txt").exists());
        // Refuse overwrite.
        write_file_in_jail(d.path(), "c.txt", b"y", &WriteOpts::default())
            .await
            .unwrap();
        let r = rename_in_jail(d.path(), "c.txt", "b.txt").await;
        assert!(r.is_err());
    }

    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).expect("stat").permissions().mode() & 0o7777
    }

    #[tokio::test]
    async fn write_keeps_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().expect("tmp");
        let f = d.path().join("wp-config.php");
        std::fs::write(&f, "old").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        write_file_in_jail(d.path(), "wp-config.php", b"new", &WriteOpts::default())
            .await
            .expect("write");
        assert_eq!(std::fs::read(&f).expect("read"), b"new");
        assert_eq!(mode_of(&f), 0o600, "a save must not widen the mode");

        let run = d.path().join("run.sh");
        std::fs::write(&run, "#!/bin/sh").expect("write");
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        write_file_in_jail(d.path(), "run.sh", b"#!/bin/sh\n", &WriteOpts::default())
            .await
            .expect("write");
        assert_eq!(mode_of(&run), 0o755, "nor strip the x");
    }

    #[tokio::test]
    async fn write_new_file_is_0644() {
        let d = tempfile::tempdir().expect("tmp");
        write_file_in_jail(d.path(), "new.txt", b"", &WriteOpts::default())
            .await
            .expect("an empty file is a file");
        assert_eq!(mode_of(&d.path().join("new.txt")), 0o644);
    }

    #[tokio::test]
    async fn write_create_only_refuses_existing() {
        let d = tempfile::tempdir().expect("tmp");
        std::fs::write(d.path().join("a.txt"), "keep").expect("write");
        let opts = WriteOpts {
            create_only: true,
            ..Default::default()
        };
        let r = write_file_in_jail(d.path(), "a.txt", b"", &opts).await;
        assert!(r.is_err());
        assert_eq!(
            std::fs::read(d.path().join("a.txt")).expect("read"),
            b"keep"
        );
        write_file_in_jail(d.path(), "b.txt", b"", &opts)
            .await
            .expect("a free name is fine");
    }

    #[tokio::test]
    async fn write_checks_the_version_it_was_given() {
        let d = tempfile::tempdir().expect("tmp");
        let f = d.path().join("a.txt");
        std::fs::write(&f, "one").expect("write");
        let seen = file_version(&std::fs::metadata(&f).expect("stat"));
        // Someone else saves a longer file in between.
        std::fs::write(&f, "one and more").expect("write");
        let stale = WriteOpts {
            expect_version: Some(seen),
            ..Default::default()
        };
        let err = write_file_in_jail(d.path(), "a.txt", b"mine", &stale)
            .await
            .expect_err("stale version must be refused");
        assert!(err.to_string().contains("changed on disk"), "{err}");
        assert_eq!(std::fs::read(&f).expect("read"), b"one and more");

        let current = WriteOpts {
            expect_version: Some(file_version(&std::fs::metadata(&f).expect("stat"))),
            ..Default::default()
        };
        write_file_in_jail(d.path(), "a.txt", b"mine", &current)
            .await
            .expect("current version is accepted");
        assert_eq!(std::fs::read(&f).expect("read"), b"mine");
    }

    #[tokio::test]
    async fn write_refuses_a_directory() {
        let d = tempfile::tempdir().expect("tmp");
        std::fs::create_dir(d.path().join("dir")).expect("mkdir");
        let r = write_file_in_jail(d.path(), "dir", b"x", &WriteOpts::default()).await;
        assert!(r.is_err());
        assert!(d.path().join("dir").is_dir());
    }

    #[tokio::test]
    async fn delete_unlinks_symlink_and_keeps_target() {
        let d = tempfile::tempdir().expect("tmp");
        let outside = tempfile::tempdir().expect("tmp2");
        let target = outside.path().join("keep.txt");
        std::fs::write(&target, "x").expect("write");
        std::os::unix::fs::symlink(&target, d.path().join("link")).expect("symlink");
        delete_in_jail(d.path(), "link", false)
            .await
            .expect("a link can be removed");
        assert!(std::fs::symlink_metadata(d.path().join("link")).is_err());
        assert!(target.exists(), "the target is not ours to delete");
    }

    #[tokio::test]
    async fn delete_recursive_removes_tree_but_not_symlink_target() {
        let d = tempfile::tempdir().expect("tmp");
        let outside = tempfile::tempdir().expect("tmp2");
        std::fs::write(outside.path().join("keep.txt"), "x").expect("write");
        std::fs::create_dir_all(d.path().join("cache/a/b")).expect("mkdir");
        std::fs::write(d.path().join("cache/a/b/f.txt"), "x").expect("write");
        std::os::unix::fs::symlink(outside.path(), d.path().join("cache/a/out")).expect("symlink");
        delete_in_jail(d.path(), "cache", true)
            .await
            .expect("recursive delete");
        assert!(!d.path().join("cache").exists());
        assert!(
            outside.path().join("keep.txt").exists(),
            "a link inside the tree is unlinked, not descended into"
        );
    }

    #[tokio::test]
    async fn delete_refuses_root_in_every_spelling() {
        let d = tempfile::tempdir().expect("tmp");
        std::fs::write(d.path().join("f"), "x").expect("write");
        for root in ["", "/", "//"] {
            assert!(delete_in_jail(d.path(), root, true).await.is_err());
        }
        assert!(d.path().join("f").exists());
    }

    #[tokio::test]
    async fn rename_moves_a_symlink_and_sees_a_dangling_destination() {
        let d = tempfile::tempdir().expect("tmp");
        std::fs::write(d.path().join("real.txt"), "x").expect("write");
        std::os::unix::fs::symlink(d.path().join("real.txt"), d.path().join("link"))
            .expect("symlink");
        rename_in_jail(d.path(), "link", "link2")
            .await
            .expect("a link is renamed as a link");
        assert!(std::fs::symlink_metadata(d.path().join("link2"))
            .expect("stat")
            .file_type()
            .is_symlink());
        // A dangling link still occupies its name.
        std::os::unix::fs::symlink(d.path().join("nowhere"), d.path().join("dangling"))
            .expect("symlink");
        let r = rename_in_jail(d.path(), "real.txt", "dangling").await;
        assert!(r.is_err(), "must not rename over a dangling link");
    }

    #[tokio::test]
    async fn entry_resolver_refuses_root_traversal_and_linked_parents() {
        let d = tempfile::tempdir().expect("tmp");
        let outside = tempfile::tempdir().expect("tmp2");
        std::os::unix::fs::symlink(outside.path(), d.path().join("out")).expect("symlink");
        for bad in ["", "/", "..", "a/..", "../x", "out/x"] {
            assert!(
                resolve_entry_in_jail(d.path(), bad).await.is_err(),
                "{bad:?} must be refused"
            );
        }
        // The link itself is an entry we may name.
        resolve_entry_in_jail(d.path(), "out").await.expect("entry");
    }

    #[test]
    fn binary_is_decided_by_bytes_and_known_types() {
        assert!(looks_binary(b"GIF89a\0\0"));
        assert!(!looks_binary(b"RewriteEngine On\n"));
        // Windows-1250 "příloha": not UTF-8, still text.
        assert!(!looks_binary(&[0x70, 0xF8, 0xED, 0x6C, 0x6F, 0x68, 0x61]));
        assert!(is_known_binary("image/png"));
        assert!(is_known_binary("font/woff2"));
        assert!(is_known_binary("application/zip"));
        assert!(!is_known_binary("image/svg+xml"));
        // No extension tells us nothing, so the bytes get to decide.
        assert!(!is_known_binary(guess_mime(".htaccess")));
        assert!(!is_known_binary(guess_mime("Makefile")));
    }
}
