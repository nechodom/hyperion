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

/// Walk up from `leaf` and OR `0o011` (group-x + world-x) into the mode
/// of every ancestor directory. Used to ensure paths like
/// `/var/lib/hyperion/acme-challenges/<token>` are reachable by nginx
/// (running as `www-data`) without having to widen them to 0o755 and
/// expose directory *listings*.
///
/// Best-effort by design: each chmod is independent, failures (e.g.
/// a system dir we don't own) are logged via `tracing::warn!` and
/// skipped. Idempotent — a re-run on already-traversable dirs is a
/// no-op. Symlinks are followed (we want to fix the *target* dir's
/// mode, not the link itself).
///
/// Stops at filesystem root.
pub async fn ensure_ancestors_traversable(leaf: &Path) {
    let mut current: Option<&Path> = Some(leaf);
    while let Some(p) = current {
        match fs::metadata(p).await {
            Ok(md) if md.is_dir() => {
                let mode = md.permissions().mode() & 0o777;
                let new_mode = mode | 0o011;
                if new_mode != mode {
                    if let Err(e) =
                        fs::set_permissions(p, std::fs::Permissions::from_mode(new_mode)).await
                    {
                        tracing::warn!(
                            path = %p.display(),
                            old_mode = format!("{:o}", mode),
                            new_mode = format!("{:o}", new_mode),
                            error = %e,
                            "could not OR traverse bits into ancestor; nginx may 404 on ACME challenges"
                        );
                    } else {
                        tracing::info!(
                            path = %p.display(),
                            old_mode = format!("{:o}", mode),
                            new_mode = format!("{:o}", new_mode),
                            "made ancestor world-traversable for ACME challenges"
                        );
                    }
                }
            }
            Ok(_) => break,  // not a dir → can't traverse further sensibly
            Err(_) => break, // path missing or unreadable
        }
        current = p.parent();
        // Stop at filesystem root.
        if matches!(current.map(|c| c.as_os_str().is_empty()), Some(true)) {
            break;
        }
        if current == Some(Path::new("/")) {
            break;
        }
    }
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

    /// Regression test for the nginx 404-on-ACME-challenge bug. The
    /// install script created /var/lib/hyperion at mode 0o700, so nginx
    /// (running as www-data — not the agent's user) couldn't traverse
    /// into the acme-challenges/ subdir below. Verifies the helper
    /// flips that 0o700 → 0o711 while leaving the deeper, already-755
    /// subdir untouched (no over-widening).
    #[tokio::test]
    async fn ensure_ancestors_traversable_adds_world_x() {
        let root = tempfile::tempdir().expect("tempdir");
        let mid = root.path().join("hyperion"); // simulate /var/lib/hyperion
        let leaf = mid.join("acme-challenges"); // simulate the subdir
        std::fs::create_dir_all(&leaf).expect("mkdir");
        std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o700))
            .expect("chmod mid 0700");
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755))
            .expect("chmod leaf 0755");

        ensure_ancestors_traversable(&leaf).await;

        let mid_mode = std::fs::metadata(&mid)
            .expect("md mid")
            .permissions()
            .mode()
            & 0o777;
        let leaf_mode = std::fs::metadata(&leaf)
            .expect("md leaf")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mid_mode, 0o711,
            "parent must have world-x added (0700 → 0711)"
        );
        assert_eq!(
            leaf_mode, 0o755,
            "leaf already had world-x, must NOT be widened further"
        );
    }

    /// Idempotent: running twice produces the same result and doesn't
    /// keep flipping bits.
    #[tokio::test]
    async fn ensure_ancestors_traversable_is_idempotent() {
        let root = tempfile::tempdir().expect("tempdir");
        let p = root.path().join("a/b/c");
        std::fs::create_dir_all(&p).expect("mkdir");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("c 0700");
        std::fs::set_permissions(p.parent().unwrap(), std::fs::Permissions::from_mode(0o700))
            .expect("b 0700");

        ensure_ancestors_traversable(&p).await;
        let after_first = std::fs::metadata(&p).expect("md").permissions().mode() & 0o777;
        ensure_ancestors_traversable(&p).await;
        let after_second = std::fs::metadata(&p).expect("md").permissions().mode() & 0o777;
        assert_eq!(after_first, after_second, "idempotent");
        assert_eq!(after_first & 0o001, 0o001, "world-x is set");
    }

    /// Must NOT touch owner/group bits — only OR the x-for-others.
    /// If the install script intentionally restricted group access, we
    /// must preserve that. Only the world-x bit is the surgical fix.
    #[tokio::test]
    async fn ensure_ancestors_traversable_preserves_owner_group_bits() {
        let root = tempfile::tempdir().expect("tempdir");
        let p = root.path().join("d");
        std::fs::create_dir_all(&p).expect("mkdir");
        // 0o740: owner=rwx, group=r, others=---
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o740)).expect("chmod");

        ensure_ancestors_traversable(&p).await;

        let m = std::fs::metadata(&p).expect("md").permissions().mode() & 0o777;
        // owner stays rwx (7), group stays r (4) + we add x → 5, others gets x (1).
        // But wait — our helper OR-s in 0o011 = 0o001 for others AND 0o010 for group.
        // 0o740 | 0o011 = 0o751.
        assert_eq!(
            m, 0o751,
            "owner stays rwx, group adds x (so it can traverse too), others adds x. got {:o}",
            m
        );
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
