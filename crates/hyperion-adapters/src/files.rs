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
}
