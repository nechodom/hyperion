//! Safe walk over a tenant's document root.
//!
//! The site user owns every directory below (and above) the root and can swap
//! any of them for a symlink at any moment. So the root itself is opened with
//! `O_NOFOLLOW` and everything else is reached relative to a directory fd:
//! `openat(O_DIRECTORY|O_NOFOLLOW)` to descend, `statat(AT_SYMLINK_NOFOLLOW)`
//! to classify. A path string is never re-resolved, and a file is never opened
//! by the walk itself (a FIFO would hang the scanner).

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{fstat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat, CWD};
use rustix::io::Errno;

pub struct WalkOpts {
    pub max_files: u64,
    /// Relative directory paths (`wp-content/cache`) that are not descended into.
    pub prune: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    pub rel: String,
    pub size: u64,
    pub ctime: i64,
    pub mode: u32,
    pub uid: u32,
    pub nlink: u64,
}

pub enum WalkEvent<'a> {
    File(&'a FileMeta),
    Skipped { rel: String, why: SkipReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    Symlink,
    NotRegular,
    HardLinked,
    Unreadable,
    NonUtf8Name,
    Vanished,
    FileCapReached,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkStats {
    pub files: u64,
    pub skipped: u64,
    pub capped: bool,
}

/// Deepest directory level descended into. Each level holds one open fd, and a
/// tenant can nest directories far past anything a real site has.
const MAX_DEPTH: usize = 128;

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Open `name` (relative to `at`) as a directory without following a symlink.
fn open_dir<Fd: AsFd>(at: Fd, name: impl rustix::path::Arg) -> io::Result<OwnedFd> {
    openat(at, name, DIR_FLAGS, Mode::empty()).map_err(io::Error::from)
}

/// What a failed `open_dir` of an entry that was just seen as a directory means.
fn skip_for_open_error(e: io::Error) -> SkipReason {
    match Errno::from_io_error(&e) {
        // Replaced between the stat and the open: by a symlink (ELOOP, or
        // ENOTDIR with O_DIRECTORY on some kernels) or by a non-directory.
        Some(Errno::LOOP) => SkipReason::Symlink,
        Some(Errno::NOTDIR) => SkipReason::NotRegular,
        Some(Errno::NOENT) => SkipReason::Vanished,
        _ => SkipReason::Unreadable,
    }
}

// The `Stat` field widths differ per platform (macOS: u16 mode/nlink, i32 dev).
#[allow(clippy::unnecessary_cast)]
fn file_meta(rel: String, st: &Stat) -> FileMeta {
    FileMeta {
        rel,
        size: st.st_size.max(0) as u64,
        ctime: st.st_ctime as i64,
        mode: st.st_mode as u32,
        uid: st.st_uid as u32,
        nlink: st.st_nlink as u64,
    }
}

#[allow(clippy::unnecessary_cast)]
fn dev_of(st: &Stat) -> u64 {
    st.st_dev as u64
}

struct Walker<'o, F> {
    opts: &'o WalkOpts,
    visit: F,
    stats: WalkStats,
    root_dev: u64,
    done: bool,
}

impl<F: FnMut(WalkEvent<'_>)> Walker<'_, F> {
    fn skip(&mut self, rel: String, why: SkipReason) {
        self.stats.skipped += 1;
        (self.visit)(WalkEvent::Skipped { rel, why });
    }

    /// Classify one directory entry. Returns the child directory to descend
    /// into, if any.
    fn entry(
        &mut self,
        dirfd: BorrowedFd<'_>,
        parent: &str,
        name: &CStr,
        depth: usize,
    ) -> Option<Frame> {
        let bytes = name.to_bytes();
        let Ok(name_str) = std::str::from_utf8(bytes) else {
            // `rel` is a String, so a name it can't hold can't be re-opened
            // later either: report it, don't look inside.
            let rel = join_rel(parent, &String::from_utf8_lossy(bytes));
            self.skip(rel, SkipReason::NonUtf8Name);
            return None;
        };
        let rel = join_rel(parent, name_str);
        let st = match statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::NOENT) => {
                self.skip(rel, SkipReason::Vanished);
                return None;
            }
            Err(_) => {
                self.skip(rel, SkipReason::Unreadable);
                return None;
            }
        };
        match FileType::from_raw_mode(st.st_mode) {
            FileType::Symlink => self.skip(rel, SkipReason::Symlink),
            FileType::Directory => {
                if self.opts.prune.contains(&rel) {
                    return None;
                }
                // A different st_dev is a mount point (or a bind mount a
                // tenant can't make): not part of this site.
                if dev_of(&st) != self.root_dev {
                    return None;
                }
                if depth >= MAX_DEPTH {
                    self.skip(rel, SkipReason::Unreadable);
                    return None;
                }
                let fd = match open_dir(dirfd, name) {
                    Ok(fd) => fd,
                    Err(e) => {
                        self.skip(rel, skip_for_open_error(e));
                        return None;
                    }
                };
                // Check the directory we actually opened, not the one we stat'ed.
                match fstat(&fd) {
                    Ok(st) if dev_of(&st) == self.root_dev => {}
                    Ok(_) => return None,
                    Err(_) => {
                        self.skip(rel, SkipReason::Unreadable);
                        return None;
                    }
                }
                match Dir::new(fd) {
                    Ok(dir) => return Some(Frame { dir, rel }),
                    Err(_) => self.skip(rel, SkipReason::Unreadable),
                }
            }
            FileType::RegularFile => {
                // A directory always has nlink >= 2; a FILE with several names
                // may be a tenant's link to something it must not make us read.
                if st.st_nlink > 1 {
                    self.skip(rel, SkipReason::HardLinked);
                } else if self.stats.files >= self.opts.max_files {
                    self.stats.capped = true;
                    self.done = true;
                    self.skip(rel, SkipReason::FileCapReached);
                } else {
                    self.stats.files += 1;
                    (self.visit)(WalkEvent::File(&file_meta(rel, &st)));
                }
            }
            _ => self.skip(rel, SkipReason::NotRegular),
        }
        None
    }
}

struct Frame {
    dir: Dir,
    rel: String,
}

fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// Walk `root`, reporting every regular file and everything that was not
/// looked at. Only failing to open the root is an error. The walk never
/// leaves the root's filesystem and never follows a symlink.
pub fn walk(
    root: &Path,
    opts: &WalkOpts,
    visit: impl FnMut(WalkEvent<'_>),
) -> io::Result<WalkStats> {
    let root_fd = open_dir(CWD, root)?;
    let root_dev = dev_of(&fstat(&root_fd).map_err(io::Error::from)?);
    let mut w = Walker {
        opts,
        visit,
        stats: WalkStats::default(),
        root_dev,
        done: false,
    };
    let mut stack = vec![Frame {
        dir: Dir::new(root_fd).map_err(io::Error::from)?,
        rel: String::new(),
    }];
    while !w.done {
        let depth = stack.len();
        let Some(frame) = stack.last_mut() else { break };
        let child = match frame.dir.read() {
            None => {
                stack.pop();
                continue;
            }
            Some(Err(_)) => {
                // Reading this directory failed part-way: drop the rest of it.
                let f = stack.pop();
                w.skip(f.map(|f| f.rel).unwrap_or_default(), SkipReason::Unreadable);
                continue;
            }
            Some(Ok(ent)) => {
                let name = ent.file_name();
                if name == c"." || name == c".." {
                    continue;
                }
                match frame.dir.fd() {
                    Ok(dirfd) => w.entry(dirfd, &frame.rel, name, depth),
                    Err(_) => {
                        let f = stack.pop();
                        w.skip(f.map(|f| f.rel).unwrap_or_default(), SkipReason::Unreadable);
                        continue;
                    }
                }
            }
        };
        if let Some(c) = child {
            stack.push(c);
        }
    }
    Ok(w.stats)
}

/// Open the regular file `rel` under `root` for reading, the way `walk`
/// reached it: every component relative to a directory fd with `O_NOFOLLOW`,
/// so a parent swapped for a symlink since the walk is refused rather than
/// followed. Also refuses anything that is not a regular file with one name.
pub fn open_file_at(root: &Path, rel: &str) -> io::Result<File> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
    if rel.is_empty() || rel.contains('\0') || rel.starts_with('/') {
        return Err(bad("invalid relative path"));
    }
    let comps: Vec<&str> = rel.split('/').collect();
    if comps
        .iter()
        .any(|c| c.is_empty() || *c == "." || *c == "..")
    {
        return Err(bad("invalid path component"));
    }
    let (leaf, parents) = comps.split_last().ok_or_else(|| bad("empty path"))?;
    let mut cur = open_dir(CWD, root)?;
    for c in parents {
        cur = open_dir(&cur, *c)?;
    }
    // NONBLOCK so a FIFO swapped in since the walk cannot hang the open;
    // it has no effect on a regular file.
    let fd = openat(
        &cur,
        *leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let st = fstat(&fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(bad("not a regular file"));
    }
    if st.st_nlink > 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hard-linked file",
        ));
    }
    Ok(File::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::time::Duration;

    #[derive(Default)]
    struct Seen {
        files: Vec<FileMeta>,
        skipped: Vec<(String, SkipReason)>,
    }

    fn run(root: &Path, opts: &WalkOpts) -> (Seen, io::Result<WalkStats>) {
        let mut seen = Seen::default();
        let r = walk(root, opts, |ev| match ev {
            WalkEvent::File(m) => seen.files.push(m.clone()),
            WalkEvent::Skipped { rel, why } => seen.skipped.push((rel, why)),
        });
        (seen, r)
    }

    fn opts() -> WalkOpts {
        WalkOpts {
            max_files: 1_000,
            prune: Vec::new(),
        }
    }

    fn rels(seen: &Seen) -> Vec<&str> {
        let mut v: Vec<&str> = seen.files.iter().map(|m| m.rel.as_str()).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn walks_nested_files_with_relative_names() {
        let t = tempfile::tempdir().expect("tmp");
        std::fs::create_dir_all(t.path().join("a/b")).expect("mkdir");
        std::fs::write(t.path().join("index.php"), b"<?php").expect("w");
        std::fs::write(t.path().join("a/b/x.php"), b"hello").expect("w");
        let (seen, r) = run(t.path(), &opts());
        let stats = r.expect("walk");
        assert_eq!(rels(&seen), vec!["a/b/x.php", "index.php"]);
        assert_eq!(stats.files, 2);
        assert_eq!(stats.skipped, 0);
        assert!(!stats.capped);
        let x = seen.files.iter().find(|m| m.rel == "a/b/x.php").expect("x");
        assert_eq!(x.size, 5);
        assert_eq!(x.nlink, 1);
    }

    #[test]
    fn symlink_to_outside_is_reported_not_followed() {
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret.php"), b"x").expect("w");
        let t = tempfile::tempdir().expect("tmp");
        std::os::unix::fs::symlink(outside.path(), t.path().join("dirlink")).expect("ln");
        std::os::unix::fs::symlink(outside.path().join("secret.php"), t.path().join("filelink"))
            .expect("ln");
        let (seen, r) = run(t.path(), &opts());
        let stats = r.expect("walk");
        assert!(seen.files.is_empty(), "followed a link: {:?}", seen.files);
        let mut s = seen.skipped.clone();
        s.sort();
        assert_eq!(
            s,
            vec![
                ("dirlink".to_string(), SkipReason::Symlink),
                ("filelink".to_string(), SkipReason::Symlink)
            ]
        );
        assert_eq!(stats.skipped, 2);
    }

    #[test]
    fn root_that_is_a_symlink_is_refused() {
        let real = tempfile::tempdir().expect("real");
        let t = tempfile::tempdir().expect("tmp");
        let link = t.path().join("htdocs");
        std::os::unix::fs::symlink(real.path(), &link).expect("ln");
        let (_, r) = run(&link, &opts());
        assert!(r.is_err(), "a symlinked root must not be walked");
    }

    #[test]
    fn fifo_does_not_hang() {
        let t = tempfile::tempdir().expect("tmp");
        let fifo = t.path().join("pipe");
        let ok = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo")
            .success();
        assert!(ok);
        std::fs::write(t.path().join("real.php"), b"x").expect("w");
        let (tx, rx) = std::sync::mpsc::channel();
        let root = t.path().to_path_buf();
        std::thread::spawn(move || {
            let (seen, r) = run(&root, &opts());
            let _ = tx.send((seen, r.is_ok()));
        });
        let (seen, ok) = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("walk hung on a fifo");
        assert!(ok);
        assert_eq!(rels(&seen), vec!["real.php"]);
        assert_eq!(
            seen.skipped,
            vec![("pipe".to_string(), SkipReason::NotRegular)]
        );
    }

    #[test]
    fn hard_linked_file_is_skipped() {
        let t = tempfile::tempdir().expect("tmp");
        std::fs::write(t.path().join("a.php"), b"x").expect("w");
        std::fs::hard_link(t.path().join("a.php"), t.path().join("b.php")).expect("link");
        std::fs::create_dir(t.path().join("d")).expect("mkdir");
        std::fs::write(t.path().join("d/ok.php"), b"x").expect("w");
        let (seen, r) = run(t.path(), &opts());
        r.expect("walk");
        // Both names of the pair carry nlink 2: neither is trusted. The
        // directories (nlink >= 2 by construction) are not an attack.
        assert_eq!(rels(&seen), vec!["d/ok.php"]);
        let mut s = seen.skipped.clone();
        s.sort();
        assert_eq!(
            s,
            vec![
                ("a.php".to_string(), SkipReason::HardLinked),
                ("b.php".to_string(), SkipReason::HardLinked)
            ]
        );
    }

    #[test]
    fn non_utf8_name_is_reported() {
        let t = tempfile::tempdir().expect("tmp");
        let bad = t.path().join(std::ffi::OsStr::from_bytes(b"bad\xff.php"));
        if let Err(e) = std::fs::write(&bad, b"x") {
            // macOS (APFS) refuses names that are not valid UTF-8 outright.
            assert_eq!(e.raw_os_error(), Some(92), "EILSEQ expected, got {e}");
            return;
        }
        std::fs::write(t.path().join("good.php"), b"x").expect("w");
        let (seen, r) = run(t.path(), &opts());
        r.expect("walk");
        assert_eq!(rels(&seen), vec!["good.php"]);
        assert_eq!(seen.skipped.len(), 1);
        assert_eq!(seen.skipped[0].1, SkipReason::NonUtf8Name);
        assert!(seen.skipped[0].0.starts_with("bad"));
    }

    #[test]
    fn symlink_swapped_for_dir_is_not_entered() {
        // The walk stats an entry as a directory, then opens it. If the tenant
        // swaps it for a symlink in between, the open must refuse.
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret.php"), b"x").expect("w");
        let t = tempfile::tempdir().expect("tmp");
        std::os::unix::fs::symlink(outside.path(), t.path().join("d")).expect("ln");
        let root = open_dir(rustix::fs::CWD, t.path()).expect("root");
        let name = std::ffi::CString::new("d").expect("cstr");
        let err = open_dir(&root, name.as_c_str()).expect_err("must not follow");
        // Linux answers ELOOP or ENOTDIR for a trailing symlink, macOS ENOTDIR.
        let why = skip_for_open_error(err);
        assert!(
            matches!(why, SkipReason::Symlink | SkipReason::NotRegular),
            "{why:?}"
        );
    }

    #[test]
    fn open_file_at_reads_a_regular_file() {
        use std::io::Read;
        let t = tempfile::tempdir().expect("tmp");
        std::fs::create_dir(t.path().join("a")).expect("mkdir");
        std::fs::write(t.path().join("a/f.php"), b"body").expect("w");
        let mut s = String::new();
        open_file_at(t.path(), "a/f.php")
            .expect("open")
            .read_to_string(&mut s)
            .expect("read");
        assert_eq!(s, "body");
    }

    #[test]
    fn open_file_at_refuses_symlinked_parent() {
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret.php"), b"x").expect("w");
        let t = tempfile::tempdir().expect("tmp");
        std::os::unix::fs::symlink(outside.path(), t.path().join("a")).expect("ln");
        assert!(open_file_at(t.path(), "a/secret.php").is_err());
    }

    #[test]
    fn open_file_at_refuses_leaf_symlink_dotdot_fifo_and_hard_link() {
        let t = tempfile::tempdir().expect("tmp");
        std::fs::write(t.path().join("f.php"), b"x").expect("w");
        std::os::unix::fs::symlink(t.path().join("f.php"), t.path().join("l.php")).expect("ln");
        assert!(open_file_at(t.path(), "l.php").is_err(), "leaf symlink");
        assert!(open_file_at(t.path(), "../f.php").is_err(), "..");
        assert!(open_file_at(t.path(), "/etc/passwd").is_err(), "absolute");
        assert!(open_file_at(t.path(), "").is_err(), "empty");
        assert!(open_file_at(t.path(), "a\0b").is_err(), "NUL");
        std::fs::create_dir(t.path().join("dir")).expect("mkdir");
        assert!(open_file_at(t.path(), "dir").is_err(), "directory");
        let fifo = t.path().join("pipe");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo")
            .success());
        assert!(open_file_at(t.path(), "pipe").is_err(), "fifo");
        std::fs::hard_link(t.path().join("f.php"), t.path().join("h.php")).expect("link");
        assert!(open_file_at(t.path(), "h.php").is_err(), "hard link");
    }

    #[test]
    fn file_cap_sets_capped() {
        let t = tempfile::tempdir().expect("tmp");
        for i in 0..5 {
            std::fs::write(t.path().join(format!("f{i}.php")), b"x").expect("w");
        }
        let o = WalkOpts {
            max_files: 3,
            prune: Vec::new(),
        };
        let (seen, r) = run(t.path(), &o);
        let stats = r.expect("walk");
        assert!(stats.capped);
        assert_eq!(stats.files, 3);
        assert_eq!(seen.files.len(), 3);
        assert!(seen
            .skipped
            .iter()
            .any(|(_, w)| *w == SkipReason::FileCapReached));
        // Exactly at the cap is not capped.
        let o = WalkOpts {
            max_files: 5,
            prune: Vec::new(),
        };
        let (_, r) = run(t.path(), &o);
        assert!(!r.expect("walk").capped);
    }

    #[test]
    fn pruned_directory_is_not_walked() {
        let t = tempfile::tempdir().expect("tmp");
        std::fs::create_dir_all(t.path().join("wp-content/cache")).expect("mkdir");
        std::fs::write(t.path().join("wp-content/cache/c.php"), b"x").expect("w");
        std::fs::write(t.path().join("wp-content/keep.php"), b"x").expect("w");
        let o = WalkOpts {
            max_files: 100,
            prune: vec!["wp-content/cache".into()],
        };
        let (seen, r) = run(t.path(), &o);
        r.expect("walk");
        assert_eq!(rels(&seen), vec!["wp-content/keep.php"]);
        assert!(seen.skipped.is_empty());
    }

    #[test]
    fn unreadable_directory_is_skipped_and_walk_continues() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            return; // root reads everything; nothing to observe
        }
        let t = tempfile::tempdir().expect("tmp");
        let locked = t.path().join("locked");
        std::fs::create_dir(&locked).expect("mkdir");
        std::fs::write(locked.join("x.php"), b"x").expect("w");
        std::fs::write(t.path().join("ok.php"), b"x").expect("w");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let (seen, r) = run(t.path(), &opts());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        r.expect("walk");
        assert_eq!(rels(&seen), vec!["ok.php"]);
        assert_eq!(
            seen.skipped,
            vec![("locked".to_string(), SkipReason::Unreadable)]
        );
    }

    #[test]
    fn missing_root_is_an_error() {
        let t = tempfile::tempdir().expect("tmp");
        let (_, r) = run(&t.path().join("nope"), &opts());
        assert!(r.is_err());
    }

    #[test]
    fn deep_tree_does_not_overflow_the_stack() {
        // Explicit stack, not recursion. 100 levels is under the depth cap.
        let t = tempfile::tempdir().expect("tmp");
        let mut p = t.path().to_path_buf();
        for _ in 0..100 {
            p.push("d");
        }
        std::fs::create_dir_all(&p).expect("mkdir");
        std::fs::write(p.join("deep.php"), b"x").expect("w");
        let (seen, r) = run(t.path(), &opts());
        r.expect("walk");
        assert_eq!(seen.files.len(), 1);
    }

    #[test]
    fn too_deep_tree_is_reported_not_fatal() {
        let t = tempfile::tempdir().expect("tmp");
        let mut p = t.path().to_path_buf();
        for _ in 0..(MAX_DEPTH + 20) {
            p.push("d");
        }
        // Build with relative chdir-free steps: create_dir_all on a long
        // absolute path can hit PATH_MAX on macOS, so build level by level.
        let mut cur = rustix::fs::openat(
            rustix::fs::CWD,
            t.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .expect("open");
        for _ in 0..(MAX_DEPTH + 20) {
            rustix::fs::mkdirat(&cur, "d", rustix::fs::Mode::from_raw_mode(0o755))
                .expect("mkdirat");
            cur = rustix::fs::openat(
                &cur,
                "d",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .expect("openat");
        }
        let (seen, r) = run(t.path(), &opts());
        let stats = r.expect("walk");
        assert!(seen.files.is_empty());
        assert_eq!(stats.skipped, 1);
        assert_eq!(seen.skipped[0].1, SkipReason::Unreadable);
    }

    #[test]
    fn ctime_not_mtime_is_reported() {
        use rustix::fs::{utimensat, AtFlags, Timespec, Timestamps, CWD};
        let t = tempfile::tempdir().expect("tmp");
        let f = t.path().join("old.php");
        std::fs::write(&f, b"x").expect("w");
        // 2024-01-01: an attacker can backdate mtime at will, ctime follows
        // the real change time.
        let ts = Timespec {
            tv_sec: 1_704_067_200,
            tv_nsec: 0,
        };
        utimensat(
            CWD,
            &f,
            &Timestamps {
                last_access: ts,
                last_modification: ts,
            },
            AtFlags::empty(),
        )
        .expect("utimensat");
        let (seen, r) = run(t.path(), &opts());
        r.expect("walk");
        let m = &seen.files[0];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        assert!(
            (now - m.ctime).abs() < 300,
            "ctime {} should be about now {now}, not the 2024 mtime",
            m.ctime
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stays_on_one_filesystem() {
        // `/proc` is always its own mount. Walk `/` but prune every other
        // top-level directory so only the mount boundary is exercised.
        let mut prune = Vec::new();
        for e in std::fs::read_dir("/").expect("read /") {
            let e = e.expect("entry");
            if e.file_name() != "proc" && e.file_type().expect("type").is_dir() {
                prune.push(e.file_name().to_string_lossy().into_owned());
            }
        }
        let o = WalkOpts {
            max_files: 100_000,
            prune,
        };
        let (seen, r) = run(Path::new("/"), &o);
        r.expect("walk");
        assert!(
            !seen.files.iter().any(|m| m.rel.starts_with("proc/")),
            "crossed into /proc"
        );
    }
}
