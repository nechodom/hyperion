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
/// Can `user` actually create a directory inside `dir`?
///
/// Performs the real operation instead of inferring it from modes, because
/// "could not create directory" has several causes that look identical from
/// the outside and only one of them is a permission:
///
///   * the disk quota is exhausted (EDQUOT),
///   * the filesystem is out of inodes (ENOSPC with bytes still free),
///   * the mount went read-only (EROFS),
///   * `open_basedir`, SELinux or AppArmor refuses the path,
///   * ownership or mode really is wrong.
///
/// A mode-based check reports "looks fine" for the first four and sends the
/// operator hunting for a permission bug that does not exist. mkdir answers
/// the question the operator actually asked.
///
/// Runs as `user` via sudo, so it tests the uid WordPress runs under rather
/// than root's view — root can write into a directory the site user cannot.
pub async fn write_probe(user: &str, dir: &str) -> Result<(), String> {
    if user.is_empty() || user.contains([':', '\n', '\r', '\0']) {
        return Err("illegal user name".into());
    }
    if dir.is_empty() || dir.contains(['\n', '\r', '\0']) {
        return Err("illegal directory path".into());
    }
    let probe = format!("{dir}/.hyperion-write-probe");
    // Remove a leftover from an interrupted earlier run first, so a stale
    // directory cannot make every later probe report EEXIST as a failure.
    let _ = crate::cmd::run("/usr/bin/sudo", &["-u", user, "/bin/rmdir", "--", &probe]).await;
    let made = crate::cmd::run("/usr/bin/sudo", &["-u", user, "/bin/mkdir", "--", &probe]).await;
    // Clean up whatever happened — never leave the probe behind.
    let _ = crate::cmd::run("/usr/bin/sudo", &["-u", user, "/bin/rmdir", "--", &probe]).await;
    made.map(|_| ()).map_err(|e| e.to_string())
}

/// Free space and free inodes on the filesystem holding `path`, as
/// (bytes_free, inodes_free). Either is `None` when `df` could not say.
///
/// Inodes are asked about separately on purpose: a filesystem with
/// gigabytes free but no inodes left fails every mkdir, and looking only at
/// bytes makes that look impossible.
pub async fn filesystem_headroom(path: &str) -> (Option<u64>, Option<u64>) {
    let parse = |out: String| -> Option<u64> {
        // `df -P` guarantees one record per line; field 4 is "available".
        out.lines()
            .nth(1)?
            .split_whitespace()
            .nth(3)?
            .parse::<u64>()
            .ok()
    };
    let bytes = crate::cmd::run("/usr/bin/df", &["-Pk", path])
        .await
        .ok()
        .and_then(parse)
        .map(|kib| kib * 1024);
    let inodes = crate::cmd::run("/usr/bin/df", &["-Pi", path])
        .await
        .ok()
        .and_then(parse);
    (bytes, inodes)
}

/// One entry from [`scan_tree`]: what it is, its mode, its owner, its path.
#[derive(Debug, Clone)]
pub struct TreeEntry {
    /// `find`'s `%y`: `d` directory, `f` regular file, `l` symlink, …
    pub kind: char,
    /// Permission bits (octal, from `%m`).
    pub mode: u32,
    /// Owning uid (`%U`).
    pub uid: u32,
    pub path: String,
}

/// Walk a site tree once and return type, mode, owner and path for every
/// entry, so a diagnosis can ask many questions from a single pass.
///
/// One walk, not one per question. Each permission check wants a different
/// predicate over the same entries, and `find … -quit` only short-circuits
/// on a HIT — so a healthy site (the common case) would pay the full cost of
/// every separate walk.
///
/// Bounded on purpose: depth 3, one filesystem, and the two directories that
/// are unbounded in practice are pruned. `uploads` and `cache` are pruned by
/// PATH rather than by name, because a `-name` prune never tests the pruned
/// directory itself — and the mode of `uploads` is one of the things worth
/// knowing.
pub async fn scan_tree(root: &str) -> Result<Vec<TreeEntry>, AdapterError> {
    if root.is_empty() || root.contains(['\n', '\r', '\0']) {
        return Err(AdapterError::Other("illegal tree path".into()));
    }
    // `-printf` and `-quit` are both GNU findutils; the repo already depends
    // on `-quit` elsewhere, so this adds no new assumption.
    let out = crate::cmd::run(
        "/usr/bin/find",
        &[
            root,
            "-xdev",
            "-maxdepth",
            "3",
            "-path",
            "*/wp-content/uploads/*",
            "-prune",
            "-o",
            "-path",
            "*/wp-content/cache/*",
            "-prune",
            "-o",
            "-name",
            "node_modules",
            "-prune",
            "-o",
            "-name",
            ".git",
            "-prune",
            "-o",
            "-printf",
            "%y %m %U %p\n",
        ],
    )
    .await?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let mut it = l.splitn(4, ' ');
            let kind = it.next()?.chars().next()?;
            let mode = u32::from_str_radix(it.next()?, 8).ok()?;
            let uid = it.next()?.parse().ok()?;
            let path = it.next()?.to_string();
            Some(TreeEntry {
                kind,
                mode,
                uid,
                path,
            })
        })
        .collect())
}

/// Read-only counterpart to [`ensure_ancestors_traversable`]: is every
/// directory from `leaf` up to `/` world-traversable?
///
/// Same 0o001 predicate the rest of the codebase uses. Kept next to the
/// mutator so the two cannot drift apart — a check that disagreed with its
/// own repair would either flag forever or never flag at all.
pub async fn ancestors_traversable(leaf: &Path) -> bool {
    let mut current: Option<&Path> = Some(leaf);
    while let Some(p) = current {
        match fs::metadata(p).await {
            Ok(md) if md.is_dir() => {
                if md.permissions().mode() & 0o001 == 0 {
                    return false;
                }
            }
            // Unreadable or not a directory: not something this predicate can
            // judge, and not something the repair would change either.
            _ => break,
        }
        current = p.parent();
        if matches!(current.map(|c| c.as_os_str().is_empty()), Some(true))
            || current == Some(Path::new("/"))
        {
            break;
        }
    }
    true
}

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

#[cfg(test)]
mod scan_tree_tests {
    /// A symlink's mode is unconditionally 0777 on Linux, and `chmod` cannot
    /// change it (there is no `lchmod`). A world-writable check that does not
    /// exclude symlinks therefore reports every Composer `vendor/bin` link as
    /// a permanent finding behind a button that can never clear it.
    #[test]
    fn symlinks_are_excluded_from_the_world_writable_rule() {
        let world_writable = |kind: char, mode: u32| kind != 'l' && mode & 0o002 != 0;
        assert!(world_writable('f', 0o666), "a 0666 file is a real finding");
        assert!(world_writable('d', 0o777), "a 0777 dir is a real finding");
        assert!(
            !world_writable('l', 0o777),
            "a symlink is always 0777 and cannot be chmod-ed — flagging it \
             would be a finding no repair can clear"
        );
    }

    /// Creating an entry inside a directory needs write AND search, so the
    /// writability test is 0o300, not 0o200. A 0600 plugins directory
    /// satisfies "owner can write" and still fails every plugin install.
    #[test]
    fn directory_writability_needs_write_and_search() {
        let can_create = |mode: u32| mode & 0o300 == 0o300;
        assert!(can_create(0o755));
        assert!(can_create(0o700));
        assert!(!can_create(0o600), "no search bit — creation still fails");
        assert!(!can_create(0o500), "no write bit");
    }

    /// `find -printf '%y %m %U %p'` output must parse, including paths that
    /// contain spaces — the path is the LAST field for exactly that reason.
    #[test]
    fn printf_lines_parse_including_paths_with_spaces() {
        let parse = |l: &str| {
            let mut it = l.splitn(4, ' ');
            let kind = it.next()?.chars().next()?;
            let mode = u32::from_str_radix(it.next()?, 8).ok()?;
            let uid: u32 = it.next()?.parse().ok()?;
            Some((kind, mode, uid, it.next()?.to_string()))
        };
        assert_eq!(
            parse("d 755 1001 /home/u/site/htdocs"),
            Some(('d', 0o755, 1001, "/home/u/site/htdocs".to_string()))
        );
        assert_eq!(
            parse("f 644 1001 /home/u/site/htdocs/my file.txt"),
            Some((
                'f',
                0o644,
                1001,
                "/home/u/site/htdocs/my file.txt".to_string()
            ))
        );
        assert_eq!(parse("garbage"), None);
    }
}
