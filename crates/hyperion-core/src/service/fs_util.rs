//! Filesystem helpers shared by the domains: sizes, modes, no-follow opens.

pub(super) async fn du_bytes(path: &std::path::Path) -> Result<i64, std::io::Error> {
    let out = tokio::process::Command::new("/usr/bin/du")
        .args(["-sb"])
        .arg(path)
        .output()
        .await?;
    if !out.status.success() {
        // du failing (permission denied, vanished path) currently surfaces as
        // "0 B used", which masks a real filesystem problem. Keep the 0 return
        // (callers expect i64) but log so it doesn't fail silently.
        tracing::warn!(
            path = %path.display(),
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "du failed — reporting 0 bytes (disk usage may be inaccurate)"
        );
        return Ok(0);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0))
}

/// Inode count of the tree at `path`, via `du --inodes -s`. The per-hosting
/// "Inodes used" used to be hardcoded 0; this fills it with the real number so
/// inode exhaustion (the many-tiny-files outage) is actually visible. Returns
/// 0 on any failure (caller treats unknown as 0, same as du_bytes).
pub(super) async fn du_inodes(path: &std::path::Path) -> i64 {
    let out = tokio::process::Command::new("/usr/bin/du")
        .args(["--inodes", "-s"])
        .arg(path)
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0),
        _ => 0,
    }
}

/// `(used, total)` bytes of the filesystem that holds `path`, via `df -P -B1`
/// (2nd column = Size, 3rd = Used). `used` is the REAL disk usage — OS,
/// databases under /var/lib, logs, backups and the panel DB included — unlike
/// summing per-hosting `du`, which only sees tenant home dirs and badly
/// under-reports. `total` is the volume capacity, for an "X / Y (Z%)" readout.
/// `None` on any exec/parse failure (caller falls back to the du sum).
pub(super) async fn fs_used_total_bytes(path: &std::path::Path) -> Option<(u64, u64)> {
    let out = tokio::process::Command::new("/usr/bin/df")
        .args(["-P", "-B1", "--", &path.display().to_string()])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // `df -P` data line: Filesystem  Size  Used  Available  Capacity  Mounted-on
    let text = String::from_utf8_lossy(&out.stdout);
    let cols: Vec<&str> = text.lines().nth(1)?.split_whitespace().collect();
    let total = cols.get(1)?.parse::<u64>().ok()?;
    let used = cols.get(2)?.parse::<u64>().ok()?;
    Some((used, total))
}

/// Detect a WordPress install at `<root_dir>` by checking for the
/// two files that any WP install (Hyperion-managed, SSH-installed,
/// migrated, restored from backup) MUST have: `wp-config.php` and
/// `wp-includes/version.php`. Returns the version string parsed
/// out of version.php's `$wp_version = '<x.y.z>'` line, or
/// `"unknown"` when both files are present but the version line
/// can't be parsed (corrupt install, custom fork, etc.).
///
/// Returns `None` when either file is missing or unreadable —
/// strict "no WP here" answer. Never panics. Never errors out
/// (the caller treats `None` as "no install" the same way it
/// treats an empty DB row).
/// Open a path for metadata changes without following a final symlink.
/// Directories are allowed here — `site_dirs` tightens logs/ and tmp/.
pub(super) fn rustix_open_no_follow(path: &str) -> Result<std::fs::File, String> {
    hyperion_adapters::fs::open_path_no_follow(std::path::Path::new(path))
        .map_err(|e| e.to_string())
}

/// chmod a single path, reporting failure rather than swallowing it.
pub(super) async fn chmod_path(path: &str, mode: u32) -> Result<(), String> {
    if path.is_empty() || path.contains(['\n', '\r', '\0']) {
        return Err("illegal path".into());
    }
    // O_NOFOLLOW on the way in, then fchmod the descriptor. `set_permissions`
    // takes a PATH and follows links, and every path this is called with sits
    // inside a directory the SITE USER owns — so pointing wp-config.php at
    // /etc/passwd and pressing "Tighten wp-config.php" on your own site would
    // chmod that instead.
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let file = match rustix_open_no_follow(path) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };
    let md = file.metadata().map_err(|e| format!("stat {path}: {e}"))?;
    let ft = md.file_type();
    if ft.is_file() {
        // A second link to a regular file is the attack: the site user
        // hardlinks a root-owned file into their own tree and has this chmod
        // it for them. One link means the name we opened is the only one.
        if md.nlink() != 1 {
            return Err(format!(
                "{path} has {} hard links — refusing to chmod it",
                md.nlink()
            ));
        }
    } else if !ft.is_dir() {
        // O_NOFOLLOW already excludes symlinks; this excludes devices,
        // sockets and fifos, which have no business being chmod'ed here.
        return Err(format!(
            "{path} is neither a regular file nor a directory — refusing to chmod it"
        ));
    }
    // NOTE for directories: the link count is NOT checked, and must not be.
    // Every directory has at least two links — its own name in the parent and
    // the `.` entry inside it — plus one more per subdirectory. Applying the
    // file rule here refused EVERY directory, always, with "logs has 2 hard
    // links", which is how a permission repair reported a perfectly ordinary
    // tree as an attack. Nothing is given up by skipping it: Linux does not
    // allow hard links to directories at all.
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {mode:o} {path}: {e}"))
}

/// The numeric uid of `user`, or `None` when there is no such account.
///
/// Compared numerically rather than by name: `find -printf %U` reports uids,
/// and resolving those back to names for every entry would be a lookup per
/// file on a tree with thousands of them.
pub(super) async fn uid_of_user(user: &str) -> Option<u32> {
    if user.is_empty() || user.contains([':', '\n', '\r', '\0']) {
        return None;
    }
    let out = hyperion_adapters::cmd::run("/usr/bin/getent", &["passwd", user])
        .await
        .ok()?;
    out.split(':').nth(2)?.trim().parse().ok()
}

/// `chmod` a directory, as a hard error.
///
/// Every caller here is protecting a plaintext copy of a customer's data on a
/// box full of other tenants, so a failed chmod is a refusal, never a warning.
pub(super) async fn set_dir_mode(path: &std::path::Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
        .map_err(|e| format!("chmod {:o} {}: {e}", mode, path.display()))
}

pub(super) fn join_absolute(target: &std::path::Path, absolute: &str) -> std::path::PathBuf {
    target.join(absolute.trim_start_matches('/'))
}

/// Available bytes on the filesystem that holds `path`, via `df -P -B1`.
/// `None` on any exec/parse failure — the caller treats unknown as "don't
/// block the backup".
pub(super) async fn fs_avail_bytes(path: &std::path::Path) -> Option<u64> {
    let out = tokio::process::Command::new("/usr/bin/df")
        .args(["-P", "-B1", "--", &path.display().to_string()])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // `df -P` output: a header line, then one data line whose 4th column is
    // "Available" (in 1-byte blocks because of -B1).
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1)?;
    line.split_whitespace().nth(3)?.parse::<u64>().ok()
}

/// Apparent size in bytes of the tree at `path`, via `du -sb`. Capped by a
/// 60 s timeout so a huge/slow tree can't stall a backup; `None` on
/// failure/timeout (caller treats unknown as "don't block").
pub(super) async fn dir_size_bytes(path: &std::path::Path) -> Option<u64> {
    let fut = tokio::process::Command::new("/usr/bin/du")
        .args(["-sb", "--", &path.display().to_string()])
        .output();
    let out = tokio::time::timeout(std::time::Duration::from_secs(60), fut)
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace().next()?.parse::<u64>().ok()
}

/// Write a sensitive blob to disk with restrictive permissions
/// (0600, root-owned via the agent's pre-existing root mode).
/// Creates the parent dir if needed. Used by the backup-target
/// secret storage so the access key never ends up in audit logs
/// or shell history.
pub(super) async fn write_secret_file(path: &str, content: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let pb = std::path::PathBuf::from(path);
    if let Some(parent) = pb.parent() {
        tokio::fs::create_dir_all(parent).await?;
        let mut perms = tokio::fs::metadata(parent).await?.permissions();
        perms.set_mode(0o700);
        let _ = tokio::fs::set_permissions(parent, perms).await;
    }
    tokio::fs::write(&pb, content).await?;
    let mut perms = tokio::fs::metadata(&pb).await?.permissions();
    perms.set_mode(0o600);
    tokio::fs::set_permissions(&pb, perms).await?;
    Ok(())
}

#[cfg(test)]
mod chmod_path_tests {
    use super::chmod_path;
    use crate::service::read_performance_section;
    use std::os::unix::fs::PermissionsExt;

    /// A directory has two links before it contains anything — its name in
    /// the parent, and its own `.` — and one more per subdirectory. The
    /// hard-link guard is a rule about regular FILES, and applying it here
    /// refused every directory a permission repair touched, reporting an
    /// ordinary site tree as an attack: "logs has 2 hard links".
    #[tokio::test]
    async fn a_directory_is_chmod_able_despite_its_link_count() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("logs");
        std::fs::create_dir(&dir).expect("create logs");
        // Give it a subdirectory so the count is 3, not merely 2.
        std::fs::create_dir(dir.join("sub")).expect("create sub");
        let path = dir.to_string_lossy().into_owned();

        chmod_path(&path, 0o750).await.expect("directory refused");
        let mode = std::fs::metadata(&dir).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o750);
    }

    /// The guard itself must survive: a second link to a regular file is how
    /// a tenant gets a root-owned file chmod'ed on their behalf.
    #[tokio::test]
    async fn a_hardlinked_file_is_still_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("wp-config.php");
        std::fs::write(&real, b"<?php\n").expect("write");
        let link = tmp.path().join("hardlink.php");
        std::fs::hard_link(&real, &link).expect("hard_link");

        let err = chmod_path(&link.to_string_lossy(), 0o600)
            .await
            .expect_err("a hardlinked file must be refused");
        assert!(err.contains("hard links"), "{err}");

        // And a plain file with one link still goes through.
        let plain = tmp.path().join("alone.php");
        std::fs::write(&plain, b"<?php\n").expect("write");
        chmod_path(&plain.to_string_lossy(), 0o640)
            .await
            .expect("a single-link file should be allowed");
    }

    /// The auto-measure interval reads from `[performance] cwv_interval_days`,
    /// defaults to weekly (7) when absent — NOT 0, which would silently stop
    /// auto-measuring for anyone who set a source before this field existed —
    /// and clamps out-of-range values.
    #[test]
    fn cwv_interval_reads_from_toml_and_defaults_to_weekly() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("agent.toml");

        std::fs::write(
            &path,
            "[performance]\ncwv_source = \"psi\"\ncwv_interval_days = 14\n",
        )
        .expect("write");
        let cfg = read_performance_section(Some(&path));
        assert_eq!(cfg.cwv_interval_days, 14);
        assert_eq!(cfg.cwv_source, "psi");

        // Absent → weekly default, so an upgrade keeps the old behaviour.
        std::fs::write(&path, "[performance]\ncwv_source = \"psi\"\n").expect("write");
        assert_eq!(read_performance_section(Some(&path)).cwv_interval_days, 7);

        // 0 = never (a real, distinct choice from the default).
        std::fs::write(&path, "[performance]\ncwv_interval_days = 0\n").expect("write");
        assert_eq!(read_performance_section(Some(&path)).cwv_interval_days, 0);

        // Out of range clamps rather than panicking.
        std::fs::write(&path, "[performance]\ncwv_interval_days = 9999\n").expect("write");
        assert_eq!(read_performance_section(Some(&path)).cwv_interval_days, 365);
    }
}
