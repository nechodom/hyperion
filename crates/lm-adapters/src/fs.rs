//! Filesystem helpers: atomic write, ensure_dir, no-symlink-traversal.

use crate::AdapterError;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs;

/// Atomic file write: write to `<path>.tmp`, set mode, rename to target.
/// Caller owns the bytes; parent dir is created if missing.
pub async fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AdapterError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).await?;
        }
    }
    let tmp = with_extension(path, "tmp");
    fs::write(&tmp, bytes).await?;
    fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).await?;
    fs::rename(&tmp, path).await?;
    Ok(())
}

/// Idempotent directory creation. Refuses to use symlinks (TOCTOU-safe).
pub async fn ensure_dir(path: &Path, mode: u32) -> Result<(), AdapterError> {
    if let Ok(md) = fs::symlink_metadata(path).await {
        if md.file_type().is_symlink() {
            return Err(AdapterError::Other(format!(
                "refusing to use symlink: {}",
                path.display()
            )));
        }
        if md.file_type().is_dir() {
            fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
            return Ok(());
        }
        return Err(AdapterError::Other(format!(
            "path exists and is not a directory: {}",
            path.display()
        )));
    }
    fs::create_dir_all(path).await?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    Ok(())
}

/// Remove a directory tree if it exists.
pub async fn remove_dir_all(path: &Path) -> Result<(), AdapterError> {
    if fs::symlink_metadata(path).await.is_ok() {
        fs::remove_dir_all(path).await?;
    }
    Ok(())
}

fn with_extension(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn atomic_write_creates_parent_and_file() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("a/b/c.txt");
        atomic_write(&p, b"hi", 0o644).await.expect("write");
        let s = fs::read_to_string(&p).await.expect("read");
        assert_eq!(s, "hi");
        let m = fs::metadata(&p).await.expect("md").permissions().mode() & 0o777;
        assert_eq!(m, 0o644);
    }

    #[tokio::test]
    async fn atomic_write_overwrites_existing() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("a.txt");
        atomic_write(&p, b"v1", 0o644).await.expect("v1");
        atomic_write(&p, b"v2", 0o644).await.expect("v2");
        assert_eq!(fs::read_to_string(&p).await.expect("read"), "v2");
    }

    #[tokio::test]
    async fn ensure_dir_is_idempotent() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("x/y");
        ensure_dir(&p, 0o750).await.expect("first");
        ensure_dir(&p, 0o750).await.expect("second");
        let m = fs::metadata(&p).await.expect("md").permissions().mode() & 0o777;
        assert_eq!(m, 0o750);
    }

    #[tokio::test]
    async fn ensure_dir_refuses_symlink() {
        let d = tempfile::tempdir().expect("tempdir");
        let target = d.path().join("real");
        std::fs::create_dir_all(&target).expect("mkdir");
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = ensure_dir(&link, 0o750).await.unwrap_err();
        match err {
            AdapterError::Other(m) => assert!(m.contains("symlink"), "got: {m}"),
            other => panic!("wrong: {other:?}"),
        }
    }

    #[tokio::test]
    async fn ensure_dir_refuses_when_path_is_file() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("aaa");
        std::fs::write(&p, "x").expect("write");
        let err = ensure_dir(&p, 0o750).await.unwrap_err();
        match err {
            AdapterError::Other(m) => assert!(m.contains("not a directory"), "got: {m}"),
            other => panic!("wrong: {other:?}"),
        }
    }

    #[tokio::test]
    async fn remove_dir_all_is_idempotent() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("absent");
        remove_dir_all(&p).await.expect("first ok (no-op)");
        ensure_dir(&p, 0o750).await.expect("mkdir");
        remove_dir_all(&p).await.expect("remove");
        assert!(!p.exists());
    }
}
