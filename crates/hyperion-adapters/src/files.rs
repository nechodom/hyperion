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
/// `/` (already split, but defensive) or NUL.
fn safe_component(c: &str) -> bool {
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.contains('/')
        && !c.contains('\\')
        && !c.contains('\0')
}

/// Join `rel_path` under `jail`, refusing anything that escapes
/// (`..`, absolute, symlink, NUL byte). Returns the canonicalised
/// absolute path inside the jail. `rel_path` is treated as forward-
/// slash separated for portability with UI-supplied values.
pub async fn resolve_inside_jail(
    jail: &Path,
    rel_path: &str,
) -> Result<PathBuf, AdapterError> {
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
        "woff" | "woff2" => "font/woff",
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
) -> Result<(), AdapterError> {
    if bytes.len() as u64 > MAX_WRITE_BYTES {
        return Err(AdapterError::Other(format!(
            "file too large ({} bytes > {} cap)",
            bytes.len(),
            MAX_WRITE_BYTES
        )));
    }
    let abs = resolve_inside_jail(jail, rel_path).await?;
    if abs == tokio::fs::canonicalize(jail).await.unwrap_or_else(|_| jail.to_path_buf()) {
        return Err(AdapterError::Other("refusing to write the jail root itself".into()));
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
    // Atomic write — write to .tmp sibling, then rename.
    let tmp = abs.with_extension(format!(
        "{}.tmp",
        abs.extension().and_then(|s| s.to_str()).unwrap_or("")
    ));
    tokio::fs::write(&tmp, bytes)
        .await
        .map_err(|e| AdapterError::Other(format!("write: {e}")))?;
    tokio::fs::rename(&tmp, &abs)
        .await
        .map_err(|e| AdapterError::Other(format!("rename: {e}")))?;
    Ok(())
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
    crate::cmd::run("/usr/bin/chown", &[&spec, abs.to_string_lossy().as_ref()]).await?;
    Ok(())
}

/// Delete one file OR one empty directory inside the jail.
/// Refuses non-empty directories — operator must clear contents first.
/// (Operators expecting `rm -rf` semantics get a clean error instead
/// of accidentally nuking wp-content/.)
pub async fn delete_in_jail(
    jail: &std::path::Path,
    rel_path: &str,
) -> Result<(), AdapterError> {
    if rel_path.is_empty() || rel_path == "/" {
        return Err(AdapterError::Other("refusing to delete the jail root".into()));
    }
    let abs = resolve_inside_jail(jail, rel_path).await?;
    let md = tokio::fs::symlink_metadata(&abs)
        .await
        .map_err(|e| AdapterError::Other(format!("stat: {e}")))?;
    if md.is_dir() {
        // Refuse non-empty + symlinks
        let mut rd = tokio::fs::read_dir(&abs)
            .await
            .map_err(|e| AdapterError::Other(format!("read_dir: {e}")))?;
        if rd
            .next_entry()
            .await
            .map_err(|e| AdapterError::Other(format!("read_dir: {e}")))?
            .is_some()
        {
            return Err(AdapterError::Other(
                "refusing to delete non-empty directory — empty it first".into(),
            ));
        }
        tokio::fs::remove_dir(&abs)
            .await
            .map_err(|e| AdapterError::Other(format!("rmdir: {e}")))?;
    } else {
        tokio::fs::remove_file(&abs)
            .await
            .map_err(|e| AdapterError::Other(format!("unlink: {e}")))?;
    }
    Ok(())
}

/// Create one directory inside the jail. Parent must exist already
/// (no `mkdir -p` behaviour — same rationale as `write_file_in_jail`).
pub async fn mkdir_in_jail(
    jail: &std::path::Path,
    rel_path: &str,
) -> Result<(), AdapterError> {
    if rel_path.is_empty() || rel_path == "/" {
        return Err(AdapterError::Other("refusing to mkdir the jail root".into()));
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
    let from_abs = resolve_inside_jail(jail, from).await?;
    // `to` may not exist yet → resolve_inside_jail still works (it
    // falls back to logical containment check on missing targets).
    let to_abs = resolve_inside_jail(jail, to).await?;
    if to_abs.exists() {
        return Err(AdapterError::Other("destination already exists".into()));
    }
    if !from_abs.exists() {
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

    #[test]
    fn mime_guesses_match_common_files() {
        assert_eq!(guess_mime("index.html"), "text/html");
        assert_eq!(guess_mime("style.css"), "text/css");
        assert_eq!(guess_mime("app.js"), "application/javascript");
        assert_eq!(guess_mime("config.toml"), "application/toml");
        assert_eq!(guess_mime("error.log"), "text/plain");
        assert_eq!(guess_mime("avatar.png"), "image/png");
        assert_eq!(guess_mime("font.woff2"), "font/woff");
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
        write_file_in_jail(d.path(), "hello.txt", b"world")
            .await
            .expect("write");
        let (bytes, name) = read_raw_in_jail(d.path(), "hello.txt")
            .await
            .expect("read");
        assert_eq!(bytes, b"world");
        assert_eq!(name, "hello.txt");
    }

    #[tokio::test]
    async fn write_file_refuses_oversized() {
        let d = tempfile::tempdir().expect("tmp");
        let huge = vec![0u8; (MAX_WRITE_BYTES + 1) as usize];
        let r = write_file_in_jail(d.path(), "big.bin", &huge).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn write_file_refuses_traversal() {
        let d = tempfile::tempdir().expect("tmp");
        let r = write_file_in_jail(d.path(), "../escape.txt", b"x").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn delete_file_works_but_refuses_root() {
        let d = tempfile::tempdir().expect("tmp");
        write_file_in_jail(d.path(), "junk.txt", b"x").await.unwrap();
        delete_in_jail(d.path(), "junk.txt").await.expect("delete");
        // Root refusal:
        let r = delete_in_jail(d.path(), "").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn delete_dir_refuses_non_empty() {
        let d = tempfile::tempdir().expect("tmp");
        mkdir_in_jail(d.path(), "stuff").await.expect("mkdir");
        write_file_in_jail(d.path(), "stuff/inner.txt", b"x")
            .await
            .expect("write");
        let r = delete_in_jail(d.path(), "stuff").await;
        assert!(r.is_err(), "must refuse non-empty dir");
        // Once we delete the file the dir is empty and removable.
        delete_in_jail(d.path(), "stuff/inner.txt").await.unwrap();
        delete_in_jail(d.path(), "stuff").await.expect("empty dir ok");
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
        write_file_in_jail(d.path(), "a.txt", b"x").await.unwrap();
        rename_in_jail(d.path(), "a.txt", "b.txt").await.expect("rename");
        // b.txt now exists, a.txt doesn't.
        assert!(d.path().join("b.txt").exists());
        assert!(!d.path().join("a.txt").exists());
        // Refuse overwrite.
        write_file_in_jail(d.path(), "c.txt", b"y").await.unwrap();
        let r = rename_in_jail(d.path(), "c.txt", "b.txt").await;
        assert!(r.is_err());
    }
}
