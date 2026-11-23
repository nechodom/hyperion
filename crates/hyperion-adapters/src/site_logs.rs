//! Rotation of each site's own nginx logs, `/home/<user>/<domain>/logs/`.
//!
//! These logs were never rotated: every visitor's IP address stayed on disk
//! for the life of the site. They are rotated here by the agent rather than
//! by a logrotate rule because the directory belongs to the SITE USER. A
//! root logrotate working there by path follows whatever the tenant puts in
//! the way — swap `logs/` for a link to `/var/log/nginx` and root truncates
//! and rewrites files there; logrotate's `su` would avoid that, but the live
//! files are nginx's (root or www-data), which the site user cannot truncate.
//!
//! So every step here goes through directory descriptors: `/home` is opened
//! once, and each component below it with `O_NOFOLLOW | O_DIRECTORY`, so a
//! link anywhere in the chain is refused by the kernel rather than checked
//! and then raced. Files are opened `O_NOFOLLOW`, proven regular and singly
//! linked, renamed and removed relative to the `logs/` descriptor.
//!
//! The scheme is logrotate's `daily` + `copytruncate` + `delaycompress`,
//! which is what the readers already expect: `access.log.1` is the plain
//! copy of the last rotation (the traffic sampler reads it for the hour a
//! rotation splits), `access.log.N.gz` the older ones, kept `days` copies
//! and never longer than `days` days.

use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

use crate::AdapterError;

/// The logs a vhost writes into the site's `logs/` directory.
pub const LOG_NAMES: [&str; 2] = ["access.log", "error.log"];

/// A log whose `.1` is younger than this is not rotated again. The tick runs
/// hourly, so a log is rotated once a day give or take an hour, and an agent
/// restarting all afternoon does not rotate it ten times.
pub const MIN_INTERVAL_SECS: i64 = 20 * 3600;

/// Free space a rotation leaves beyond the copy itself.
const COPY_HEADROOM: u64 = 256 * 1024 * 1024;

/// What one pass did to one site.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// Live logs copied to `.1` and truncated.
    pub rotated: u32,
    /// Old copies deleted (past the window, or past the count).
    pub removed: u32,
}

fn err(what: &str, e: impl std::fmt::Display) -> AdapterError {
    AdapterError::Other(format!("{what}: {e}"))
}

/// One path component the agent trusts to name a directory: no separator,
/// no `.`/`..`, no NUL.
fn component_ok(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains('/') && !s.contains('\0')
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// `name` inside `dir` as a directory, never through a link. `Ok(None)` when
/// it does not exist.
fn open_dir_at(dir: impl AsFd, name: &str) -> Result<Option<OwnedFd>, AdapterError> {
    match rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::NOTDIR) => Err(AdapterError::Other(
            format!("{name} is not a plain directory — refusing to rotate through it"),
        )),
        Err(e) => Err(err(&format!("open {name}"), e)),
    }
}

/// `name` in `dir`, read-only or read-write, as a regular file with one link.
/// `Ok(None)` when absent; an error for anything else in its place.
fn open_file_at(
    dir: impl AsFd,
    name: &str,
    write: bool,
) -> Result<Option<(std::fs::File, rustix::fs::Stat)>, AdapterError> {
    let mode = if write { OFlags::RDWR } else { OFlags::RDONLY };
    // NONBLOCK: a FIFO in the log's place must not hang the tick.
    let flags = mode | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(err(&format!("open {name}"), e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| err(&format!("stat {name}"), e))?;
    if FileType::from_raw_mode(st.st_mode as _) != FileType::RegularFile || st.st_nlink != 1 {
        return Err(AdapterError::Other(format!(
            "{name} is not a plain singly-linked file — leaving it alone"
        )));
    }
    Ok(Some((std::fs::File::from(fd), st)))
}

/// `st_mtime` of `name` in `dir`, not following a link. `None` when absent.
fn mtime_at(dir: impl AsFd, name: &str) -> Option<i64> {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
        .ok()
        .map(|st| st.st_mtime)
}

/// The archive name for copy `n`.
fn archive(base: &str, n: u32, gz: bool) -> String {
    if gz {
        format!("{base}.{n}.gz")
    } else {
        format!("{base}.{n}")
    }
}

/// `base.N` / `base.N.gz` → `(N, gz)`.
fn parse_archive(base: &str, name: &str) -> Option<(u32, bool)> {
    let rest = name.strip_prefix(base)?.strip_prefix('.')?;
    let (num, gz) = match rest.strip_suffix(".gz") {
        Some(n) => (n, true),
        None => (rest, false),
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u32 = num.parse().ok()?;
    (n >= 1).then_some((n, gz))
}

/// Copy the source's owner, mode and modification time onto `dst`, so a
/// copy reads like the file it came from (and `maxage` dates it by its
/// content, not by when it was made).
fn copy_identity(dst: &std::fs::File, st: &rustix::fs::Stat) {
    let _ = rustix::fs::fchown(
        dst,
        Some(rustix::fs::Uid::from_raw(st.st_uid)),
        Some(rustix::fs::Gid::from_raw(st.st_gid)),
    );
    let _ = rustix::fs::fchmod(dst, Mode::from_raw_mode((st.st_mode as u32 & 0o666) as _));
}

fn set_mtime(dst: &std::fs::File, secs: i64) {
    let ts = rustix::fs::Timespec {
        tv_sec: secs as _,
        tv_nsec: 0,
    };
    let _ = rustix::fs::futimens(
        dst,
        &rustix::fs::Timestamps {
            last_access: ts,
            last_modification: ts,
        },
    );
}

/// Rotate one site's logs: drop copies past `days`, and copy-and-truncate a
/// live log that has something in it and was not rotated in the last
/// [`MIN_INTERVAL_SECS`]. Blocking; run it off the async runtime.
///
/// A site with no `logs/` is nothing to do. A link anywhere from `<user>`
/// down is an error and nothing is touched.
pub fn rotate(
    home_root: &Path,
    user: &str,
    domain: &str,
    days: u32,
    now: i64,
) -> Result<Outcome, AdapterError> {
    if !component_ok(user) || !component_ok(domain) {
        return Err(AdapterError::Other(format!(
            "{user}/{domain} is not a site directory name"
        )));
    }
    let days = days.max(1);
    let root = rustix::fs::open(
        home_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| err(&format!("open {}", home_root.display()), e))?;
    let Some(u) = open_dir_at(&root, user)? else {
        return Ok(Outcome::default());
    };
    let Some(d) = open_dir_at(&u, domain)? else {
        return Ok(Outcome::default());
    };
    let Some(logs) = open_dir_at(&d, "logs")? else {
        return Ok(Outcome::default());
    };

    let names: Vec<String> = {
        let dup = rustix::io::dup(&logs).map_err(|e| err("dup logs/", e))?;
        let mut dir = rustix::fs::Dir::read_from(dup).map_err(|e| err("read logs/", e))?;
        let mut v = Vec::new();
        while let Some(entry) = dir.read() {
            let entry = entry.map_err(|e| err("read logs/", e))?;
            v.push(entry.file_name().to_string_lossy().into_owned());
        }
        v
    };

    let cutoff = now - i64::from(days) * 86_400;
    let mut out = Outcome::default();
    for base in LOG_NAMES {
        // Old copies first: past the window by date, or past the count.
        let mut kept: Vec<(u32, bool)> = Vec::new();
        for name in &names {
            let Some((n, gz)) = parse_archive(base, name) else {
                continue;
            };
            let expired = mtime_at(&logs, name).is_some_and(|m| m < cutoff);
            if n >= days || expired {
                if rustix::fs::unlinkat(&logs, name.as_str(), AtFlags::empty()).is_ok() {
                    out.removed += 1;
                }
            } else {
                kept.push((n, gz));
            }
        }

        let Some((live, st)) = open_file_at(&logs, base, true)? else {
            continue;
        };
        if st.st_size == 0 {
            continue;
        }
        let last = kept
            .iter()
            .filter(|(n, _)| *n == 1)
            .filter_map(|(n, gz)| mtime_at(&logs, &archive(base, *n, *gz)))
            .max();
        if last.is_some_and(|m| m > now - MIN_INTERVAL_SECS) {
            continue;
        }

        // The copy needs room for the whole file. A site whose log was never
        // rotated can hold years of it; filling the disk to rotate it would
        // take every site on the node down with it.
        if let Ok(vfs) = rustix::fs::fstatvfs(&logs) {
            let free = vfs.f_bavail.saturating_mul(vfs.f_frsize);
            let need = (st.st_size as u64).saturating_add(COPY_HEADROOM);
            if free < need {
                tracing::warn!(
                    log = base,
                    size = st.st_size,
                    free,
                    "site log: not enough free space to rotate it"
                );
                continue;
            }
        }

        // Make room: .N → .N+1, highest first so nothing is overwritten.
        kept.sort_unstable_by_key(|k| std::cmp::Reverse(k.0));
        for (n, gz) in &kept {
            rustix::fs::renameat(
                &logs,
                archive(base, *n, *gz).as_str(),
                &logs,
                archive(base, n + 1, *gz).as_str(),
            )
            .map_err(|e| err(&format!("rename {base}.{n}"), e))?;
        }

        // Copy, then truncate the live file in place: nginx keeps writing to
        // the same inode with O_APPEND, so nothing has to reopen it.
        let one = archive(base, 1, false);
        let fd = rustix::fs::openat(
            &logs,
            one.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| err(&format!("create {one}"), e))?;
        let mut copy = std::fs::File::from(fd);
        std::io::copy(&mut &live, &mut copy).map_err(|e| err(&format!("copy {base}"), e))?;
        copy.flush().map_err(|e| err(&format!("write {one}"), e))?;
        copy_identity(&copy, &st);
        live.set_len(0)
            .map_err(|e| err(&format!("truncate {base}"), e))?;
        out.rotated += 1;

        // delaycompress: .1 stays plain for the readers; .2 and up are gzip.
        for (n, gz) in &kept {
            if *gz {
                continue;
            }
            if let Err(e) = compress(&logs, &archive(base, n + 1, false)) {
                tracing::warn!(error = %e, "site log: could not compress an old copy");
            }
        }
    }
    Ok(out)
}

/// `name` → `name.gz` in `dir`, keeping owner, mode and date.
fn compress(dir: &OwnedFd, name: &str) -> Result<(), AdapterError> {
    let Some((mut src, st)) = open_file_at(dir, name, false)? else {
        return Ok(());
    };
    let gz_name = format!("{name}.gz");
    let fd = rustix::fs::openat(
        dir,
        gz_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| err(&format!("create {gz_name}"), e))?;
    let dst = std::fs::File::from(fd);
    let mut enc = flate2::write::GzEncoder::new(&dst, flate2::Compression::default());
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = src
            .read(&mut buf)
            .map_err(|e| err(&format!("read {name}"), e))?;
        if n == 0 {
            break;
        }
        enc.write_all(&buf[..n])
            .map_err(|e| err(&format!("write {gz_name}"), e))?;
    }
    enc.finish()
        .map_err(|e| err(&format!("write {gz_name}"), e))?;
    copy_identity(&dst, &st);
    set_mtime(&dst, st.st_mtime);
    rustix::fs::unlinkat(dir, name, AtFlags::empty())
        .map_err(|e| err(&format!("remove {name}"), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn site(tmp: &tempfile::TempDir) -> std::path::PathBuf {
        let logs = tmp.path().join("u_cz").join("u.cz").join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        logs
    }

    fn age(path: &Path, secs_ago: i64) {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs((NOW - secs_ago) as u64);
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(t).unwrap();
    }

    fn run(tmp: &tempfile::TempDir, days: u32) -> Outcome {
        rotate(tmp.path(), "u_cz", "u.cz", days, NOW).expect("rotate")
    }

    #[test]
    fn a_live_log_is_copied_to_dot_one_and_truncated_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = site(&tmp);
        std::fs::write(logs.join("access.log"), "1.2.3.4 GET /\n").unwrap();
        let ino = std::os::unix::fs::MetadataExt::ino(
            &std::fs::metadata(logs.join("access.log")).unwrap(),
        );
        assert_eq!(
            run(&tmp, 30),
            Outcome {
                rotated: 1,
                removed: 0
            }
        );
        assert_eq!(
            std::fs::read_to_string(logs.join("access.log.1")).unwrap(),
            "1.2.3.4 GET /\n"
        );
        let md = std::fs::metadata(logs.join("access.log")).unwrap();
        assert_eq!(md.len(), 0);
        // Same inode: nginx's open descriptor keeps working.
        assert_eq!(std::os::unix::fs::MetadataExt::ino(&md), ino);
        // An empty error.log is left alone (notifempty), as is a missing one.
        assert!(!logs.join("error.log.1").exists());
    }

    #[test]
    fn a_second_pass_the_same_day_does_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = site(&tmp);
        std::fs::write(logs.join("access.log"), "a\n").unwrap();
        run(&tmp, 30);
        age(&logs.join("access.log.1"), 3600);
        std::fs::write(logs.join("access.log"), "b\n").unwrap();
        assert_eq!(run(&tmp, 30), Outcome::default());
        assert_eq!(
            std::fs::read_to_string(logs.join("access.log")).unwrap(),
            "b\n"
        );
    }

    #[test]
    fn old_copies_shift_compress_and_fall_off_the_end() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = site(&tmp);
        std::fs::write(logs.join("access.log"), "today\n").unwrap();
        std::fs::write(logs.join("access.log.1"), "yesterday\n").unwrap();
        age(&logs.join("access.log.1"), 86_400);
        std::fs::write(logs.join("access.log.2.gz"), "x").unwrap();
        age(&logs.join("access.log.2.gz"), 2 * 86_400);
        // Copy 3 is past a 3-day window's count once shifted.
        std::fs::write(logs.join("access.log.3.gz"), "x").unwrap();
        age(&logs.join("access.log.3.gz"), 2 * 86_400);
        let out = run(&tmp, 3);
        assert_eq!(
            out,
            Outcome {
                rotated: 1,
                removed: 1
            }
        );
        assert_eq!(
            std::fs::read_to_string(logs.join("access.log.1")).unwrap(),
            "today\n"
        );
        assert!(
            !logs.join("access.log.2").exists(),
            "the old .1 is compressed"
        );
        let mut gz = flate2::read::GzDecoder::new(
            std::fs::File::open(logs.join("access.log.2.gz")).unwrap(),
        );
        let mut s = String::new();
        gz.read_to_string(&mut s).unwrap();
        assert_eq!(s, "yesterday\n");
        // The compressed copy keeps the date of what is in it.
        let m = std::fs::metadata(logs.join("access.log.2.gz")).unwrap();
        assert_eq!(std::os::unix::fs::MetadataExt::mtime(&m), NOW - 86_400);
        assert!(
            logs.join("access.log.3.gz").exists(),
            "old .2.gz shifted to .3.gz"
        );
        assert!(!logs.join("access.log.4.gz").exists());
    }

    #[test]
    fn copies_older_than_the_window_go_even_when_the_log_is_quiet() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = site(&tmp);
        // A quiet site: nothing to rotate, but last month's copy must go.
        std::fs::write(logs.join("error.log"), "").unwrap();
        std::fs::write(logs.join("error.log.1"), "old\n").unwrap();
        age(&logs.join("error.log.1"), 31 * 86_400);
        std::fs::write(logs.join("error.log.2.gz"), "x").unwrap();
        age(&logs.join("error.log.2.gz"), 5 * 86_400);
        assert_eq!(
            run(&tmp, 30),
            Outcome {
                rotated: 0,
                removed: 1
            }
        );
        assert!(!logs.join("error.log.1").exists());
        assert!(logs.join("error.log.2.gz").exists());
        // Files that only look like copies are not ours.
        std::fs::write(logs.join("access.log.old"), "x").unwrap();
        std::fs::write(logs.join("access.log.1x"), "x").unwrap();
        age(&logs.join("access.log.old"), 400 * 86_400);
        run(&tmp, 30);
        assert!(logs.join("access.log.old").exists());
        assert!(logs.join("access.log.1x").exists());
    }

    #[test]
    fn a_linked_logs_dir_is_refused_and_nothing_outside_is_touched() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("access.log"), "not yours\n").unwrap();
        let site_dir = tmp.path().join("u_cz").join("u.cz");
        std::fs::create_dir_all(&site_dir).unwrap();
        std::os::unix::fs::symlink(&outside, site_dir.join("logs")).unwrap();
        assert!(rotate(tmp.path(), "u_cz", "u.cz", 30, NOW).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.join("access.log")).unwrap(),
            "not yours\n"
        );
        assert!(!outside.join("access.log.1").exists());
    }

    #[test]
    fn a_linked_site_dir_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("elsewhere");
        std::fs::create_dir_all(outside.join("logs")).unwrap();
        std::fs::write(outside.join("logs").join("access.log"), "x\n").unwrap();
        std::fs::create_dir_all(tmp.path().join("u_cz")).unwrap();
        std::os::unix::fs::symlink(&outside, tmp.path().join("u_cz").join("u.cz")).unwrap();
        assert!(rotate(tmp.path(), "u_cz", "u.cz", 30, NOW).is_err());
        assert!(!outside.join("logs").join("access.log.1").exists());
    }

    #[test]
    fn a_linked_log_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let logs = site(&tmp);
        let target = tmp.path().join("secret");
        std::fs::write(&target, "root only\n").unwrap();
        std::os::unix::fs::symlink(&target, logs.join("access.log")).unwrap();
        assert!(run_err(&tmp));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "root only\n");
        // A hard link is refused too.
        std::fs::remove_file(logs.join("access.log")).unwrap();
        std::fs::hard_link(&target, logs.join("access.log")).unwrap();
        assert!(run_err(&tmp));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "root only\n");
    }

    fn run_err(tmp: &tempfile::TempDir) -> bool {
        rotate(tmp.path(), "u_cz", "u.cz", 30, NOW).is_err()
    }

    #[test]
    fn a_missing_site_is_nothing_to_do_and_bad_names_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            rotate(tmp.path(), "nobody", "x.cz", 30, NOW).unwrap(),
            Outcome::default()
        );
        assert!(rotate(tmp.path(), "..", "x.cz", 30, NOW).is_err());
        assert!(rotate(tmp.path(), "u", "a/b", 30, NOW).is_err());
    }

    #[test]
    fn archive_names_parse_strictly() {
        assert_eq!(
            parse_archive("access.log", "access.log.1"),
            Some((1, false))
        );
        assert_eq!(
            parse_archive("access.log", "access.log.12.gz"),
            Some((12, true))
        );
        assert_eq!(parse_archive("access.log", "access.log"), None);
        assert_eq!(parse_archive("access.log", "access.log.0"), None);
        assert_eq!(parse_archive("access.log", "access.log.gz"), None);
        assert_eq!(parse_archive("access.log", "access.log.-1"), None);
        assert_eq!(parse_archive("access.log", "error.log.1"), None);
    }
}
