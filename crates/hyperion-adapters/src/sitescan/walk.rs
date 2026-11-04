//! Safe walk over a tenant's document root.
//!
//! The site user owns every directory below the root, and the parent of the
//! root (`/home/<user>/<domain>`), and can swap any of them for a symlink at
//! any moment. So `TenantRoot::open` resolves the root once, component by
//! component from `/` with `openat(O_NOFOLLOW)` (a symlink is accepted only
//! when root owns both the link and its directory, which a tenant cannot
//! create), and pins the result as a directory fd. Walking and re-opening
//! work only from that fd: `openat(O_DIRECTORY|O_NOFOLLOW)` to descend,
//! `statat(AT_SYMLINK_NOFOLLOW)` to classify. The root path is never resolved
//! again, and a file is never opened by the walk itself (a FIFO would hang
//! the scanner).

use std::collections::VecDeque;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use rustix::fs::{
    fstat, openat, readlinkat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat, CWD,
};
use rustix::io::Errno;

pub struct WalkOpts {
    /// Directory entries of any kind (files, links, directories, ...) looked
    /// at before the walk stops with `capped` set. Bounds the work, not just
    /// the number of files reported.
    pub max_entries: u64,
    /// Relative directory paths (`wp-content/cache`) that are not descended into.
    pub prune: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    pub rel: String,
    pub size: u64,
    pub ctime: i64,
    /// Nanosecond part of `ctime`: a same-size rewrite within one second
    /// still changes it.
    pub ctime_nsec: i64,
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
    /// A directory on another device than the root (a mount point, or a
    /// btrfs subvolume): not part of this site, not looked at.
    OtherFilesystem,
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

/// Symlinks followed while resolving the root path.
const MAX_ROOT_LINKS: usize = 8;

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
        ctime_nsec: st.st_ctime_nsec as i64,
        mode: st.st_mode as u32,
        uid: st.st_uid as u32,
        nlink: st.st_nlink as u64,
    }
}

#[allow(clippy::unnecessary_cast)]
fn dev_of(st: &Stat) -> u64 {
    st.st_dev as u64
}

/// A directory only root can change: owned by uid 0 and not writable by
/// others, unless sticky (then entries can't be replaced by non-owners).
#[allow(clippy::unnecessary_cast)]
fn root_controlled_dir(st: &Stat) -> bool {
    let mode = st.st_mode as u32;
    st.st_uid == 0 && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}

fn refuse(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg.to_string())
}

/// A tenant's document root, pinned as a directory fd. See the module docs.
#[derive(Debug)]
pub struct TenantRoot {
    fd: OwnedFd,
    dev: u64,
}

impl TenantRoot {
    /// Resolve `root` (absolute) from `/` without trusting any component a
    /// tenant could have swapped. A symlink component is followed only when
    /// both the link and its directory are root-owned (macOS `/var`, an
    /// admin's `/home -> /data/home`); any other symlink is refused.
    pub fn open(root: &Path) -> io::Result<TenantRoot> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
        if !root.is_absolute() {
            return Err(bad("root must be an absolute path"));
        }
        let mut pending: VecDeque<OsString> = VecDeque::new();
        for c in root.components() {
            match c {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(n) => pending.push_back(n.to_os_string()),
                _ => return Err(bad("root must not contain `..`")),
            }
        }
        let mut cur = open_dir(CWD, "/")?;
        let mut links = 0;
        while let Some(name) = pending.pop_front() {
            let err = match open_dir(&cur, name.as_os_str()) {
                Ok(next) => {
                    cur = next;
                    continue;
                }
                Err(e) => e,
            };
            if !matches!(
                Errno::from_io_error(&err),
                Some(Errno::LOOP | Errno::NOTDIR)
            ) {
                return Err(err);
            }
            let link = statat(&cur, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)?;
            if FileType::from_raw_mode(link.st_mode) != FileType::Symlink {
                return Err(err);
            }
            let parent = fstat(&cur).map_err(io::Error::from)?;
            if link.st_uid != 0 || !root_controlled_dir(&parent) {
                return Err(refuse("refusing root: a path component is a symlink"));
            }
            links += 1;
            if links > MAX_ROOT_LINKS {
                return Err(refuse("too many symlinks in root path"));
            }
            let target = readlinkat(&cur, name.as_os_str(), Vec::new()).map_err(io::Error::from)?;
            let target = Path::new(OsStr::from_bytes(target.to_bytes()));
            let mut comps = Vec::new();
            for c in target.components() {
                match c {
                    Component::RootDir | Component::CurDir => {}
                    Component::Normal(n) => comps.push(n.to_os_string()),
                    _ => return Err(refuse("unsupported symlink target in root path")),
                }
            }
            if target.is_absolute() {
                cur = open_dir(CWD, "/")?;
            }
            for c in comps.into_iter().rev() {
                pending.push_front(c);
            }
        }
        let dev = dev_of(&fstat(&cur).map_err(io::Error::from)?);
        Ok(TenantRoot { fd: cur, dev })
    }

    /// Walk the tree, reporting every regular file and everything that was not
    /// looked at. Only failing to open the root fd is an error. The walk never
    /// leaves the root's filesystem and never follows a symlink.
    pub fn walk(&self, opts: &WalkOpts, visit: impl FnMut(WalkEvent<'_>)) -> io::Result<WalkStats> {
        let mut w = Walker {
            opts,
            visit,
            stats: WalkStats::default(),
            root_dev: self.dev,
            entries: 0,
            done: false,
        };
        // A fresh descriptor, so the pinned one stays usable for more walks.
        let top = open_dir(&self.fd, ".")?;
        let mut stack = vec![Frame {
            dir: Dir::new(top).map_err(io::Error::from)?,
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

    /// Open the directory at `comps` (relative to the root) by descending one
    /// `O_NOFOLLOW` component at a time, checking each stays on the root's
    /// filesystem. No components gives a fresh descriptor for the root.
    fn descend(&self, comps: &[&str]) -> io::Result<OwnedFd> {
        let mut held = open_dir(&self.fd, ".")?;
        for c in comps {
            let next = open_dir(&held, *c)?;
            if dev_of(&fstat(&next).map_err(io::Error::from)?) != self.dev {
                return Err(refuse("directory is on another filesystem"));
            }
            held = next;
        }
        Ok(held)
    }

    /// Open the regular file `rel` for reading, the way `walk` reached it:
    /// every component relative to a directory fd with `O_NOFOLLOW`, so a
    /// parent swapped for a symlink since the walk is refused rather than
    /// followed. Also refuses a directory on another filesystem, and anything
    /// that is not a regular file with one name.
    pub fn open_file(&self, rel: &str) -> io::Result<File> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
        let comps = split_rel(rel, false)?;
        let (leaf, parents) = comps.split_last().ok_or_else(|| bad("empty path"))?;
        let parent = self.descend(parents)?;
        // NONBLOCK so a FIFO swapped in since the walk cannot hang the open;
        // it has no effect on a regular file.
        let fd = openat(
            &parent,
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
            return Err(refuse("hard-linked file"));
        }
        Ok(File::from(fd))
    }

    /// The names directly inside the directory `rel` ("" is the root), reached
    /// like `open_file` reaches a file. Entries are classified without
    /// following links and are not opened. At most `max_entries` are returned
    /// (`truncated` says more existed), in directory order; names that can't be
    /// listed count toward the cap.
    pub fn list_dir(&self, rel: &str, max_entries: usize) -> io::Result<DirListing> {
        let comps = split_rel(rel, true)?;
        let mut dir = Dir::new(self.descend(&comps)?).map_err(io::Error::from)?;
        let mut out = DirListing::default();
        let mut seen = 0usize;
        while let Some(ent) = dir.read() {
            let ent = ent.map_err(io::Error::from)?;
            let name = ent.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            // Every name looked at counts, listed or not, so a directory of
            // unlistable names is bounded too.
            if seen >= max_entries {
                out.truncated = true;
                break;
            }
            seen += 1;
            let Ok(name_str) = std::str::from_utf8(name.to_bytes()) else {
                out.non_utf8 += 1;
                continue;
            };
            let kind = match statat(
                dir.fd().map_err(io::Error::from)?,
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(st) => match FileType::from_raw_mode(st.st_mode) {
                    FileType::RegularFile => EntryKind::File,
                    FileType::Directory => EntryKind::Dir,
                    FileType::Symlink => EntryKind::Symlink,
                    _ => EntryKind::Other,
                },
                // Gone since it was listed.
                Err(Errno::NOENT) => continue,
                Err(_) => EntryKind::Other,
            };
            out.entries.push(DirEntryInfo {
                name: name_str.to_string(),
                kind,
            });
        }
        Ok(out)
    }
}

/// Split a relative path into components, refusing anything that could leave
/// the root. `allow_empty` accepts "" as the root itself.
fn split_rel(rel: &str, allow_empty: bool) -> io::Result<Vec<&str>> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
    if rel.is_empty() && allow_empty {
        return Ok(Vec::new());
    }
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
    Ok(comps)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    /// A FIFO, socket, device or anything else that is not a plain file.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    pub kind: EntryKind,
}

#[derive(Debug, Default)]
pub struct DirListing {
    pub entries: Vec<DirEntryInfo>,
    /// More entries existed than the cap asked for.
    pub truncated: bool,
    /// Entries whose name is not UTF-8: not listed, as they can't be re-opened.
    pub non_utf8: u64,
}

struct Walker<'o, F> {
    opts: &'o WalkOpts,
    visit: F,
    stats: WalkStats,
    root_dev: u64,
    entries: u64,
    done: bool,
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
        if self.entries >= self.opts.max_entries {
            self.stats.capped = true;
            self.done = true;
            let rel = join_rel(parent, &String::from_utf8_lossy(bytes));
            self.skip(rel, SkipReason::FileCapReached);
            return None;
        }
        self.entries += 1;
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
                if dev_of(&st) != self.root_dev {
                    self.skip(rel, SkipReason::OtherFilesystem);
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
                    Ok(_) => {
                        self.skip(rel, SkipReason::OtherFilesystem);
                        return None;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::time::Duration;

    #[derive(Default)]
    struct Seen {
        files: Vec<FileMeta>,
        skipped: Vec<(String, SkipReason)>,
    }

    fn run(root: &Path, opts: &WalkOpts) -> (Seen, io::Result<WalkStats>) {
        let mut seen = Seen::default();
        let r = TenantRoot::open(root).and_then(|r| {
            r.walk(opts, |ev| match ev {
                WalkEvent::File(m) => seen.files.push(m.clone()),
                WalkEvent::Skipped { rel, why } => seen.skipped.push((rel, why)),
            })
        });
        (seen, r)
    }

    fn opts() -> WalkOpts {
        WalkOpts {
            max_entries: 100_000,
            prune: Vec::new(),
        }
    }

    fn rels(seen: &Seen) -> Vec<&str> {
        let mut v: Vec<&str> = seen.files.iter().map(|m| m.rel.as_str()).collect();
        v.sort_unstable();
        v
    }

    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    /// A symlink the way a tenant makes one: not owned by root. Tests that run
    /// as root (a container) would otherwise create root-owned links, which
    /// `TenantRoot::open` rightly trusts.
    fn tenant_symlink(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).expect("ln");
        if is_root() {
            rustix::fs::chownat(
                CWD,
                link,
                Some(rustix::fs::Uid::from_raw(1000)),
                None,
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .expect("lchown");
        }
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
        tenant_symlink(outside.path(), &t.path().join("dirlink"));
        tenant_symlink(
            &outside.path().join("secret.php"),
            &t.path().join("filelink"),
        );
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
        tenant_symlink(real.path(), &link);
        let (_, r) = run(&link, &opts());
        assert!(r.is_err(), "a symlinked root must not be walked");
    }

    /// /home/u/<domain>/htdocs where tenant u swaps `<domain>` for a link to
    /// tenant v's `<domain>`: refused at open, nothing of v is ever read.
    #[test]
    fn symlinked_parent_of_root_is_refused_at_open() {
        let t = tempfile::tempdir().expect("tmp");
        let v = t.path().join("home/v/other.org/htdocs");
        std::fs::create_dir_all(&v).expect("mkdir");
        std::fs::write(v.join("wp-config.php"), b"VICTIM_DB_PASSWORD").expect("w");
        let u = t.path().join("home/u");
        std::fs::create_dir_all(&u).expect("mkdir");
        tenant_symlink(&t.path().join("home/v/other.org"), &u.join("evil.com"));
        let err = TenantRoot::open(&u.join("evil.com/htdocs")).expect_err("must refuse");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn swapping_the_domain_after_open_does_not_move_the_walk() {
        let t = tempfile::tempdir().expect("tmp");
        let mine = t.path().join("home/u/evil.com/htdocs");
        std::fs::create_dir_all(&mine).expect("mkdir");
        std::fs::write(mine.join("mine.php"), b"mine").expect("w");
        let theirs = t.path().join("home/v/other.org");
        std::fs::create_dir_all(theirs.join("htdocs")).expect("mkdir");
        std::fs::write(theirs.join("htdocs/wp-config.php"), b"VICTIM_DB_PASSWORD").expect("w");

        let root = TenantRoot::open(&mine).expect("open");
        // The tenant swaps <domain> for a link to another tenant's site.
        let dom = t.path().join("home/u/evil.com");
        std::fs::rename(&dom, t.path().join("home/u/evil.old")).expect("mv");
        tenant_symlink(&theirs, &dom);

        let mut files = Vec::new();
        root.walk(&opts(), |ev| {
            if let WalkEvent::File(m) = ev {
                files.push(m.rel.clone());
            }
        })
        .expect("walk");
        assert_eq!(files, vec!["mine.php"]);
        let mut s = String::new();
        root.open_file("mine.php")
            .expect("open_file")
            .read_to_string(&mut s)
            .expect("read");
        assert_eq!(s, "mine");
        assert!(root.open_file("wp-config.php").is_err());
    }

    /// A link that root owns, in a directory only root can change, is the
    /// admin's own (macOS `/var -> private/var`, Debian `/bin -> usr/bin`) and
    /// must be followed.
    #[test]
    fn root_owned_symlink_in_root_owned_dir_is_followed() {
        use std::os::unix::fs::MetadataExt;
        let mut followed = 0;
        for link in ["/var", "/bin"] {
            let Ok(st) = std::fs::symlink_metadata(link) else {
                continue;
            };
            if !st.file_type().is_symlink() || st.uid() != 0 {
                continue;
            }
            let root = TenantRoot::open(Path::new(link)).expect("root-owned link is followed");
            root.walk(
                &WalkOpts {
                    max_entries: 20,
                    prune: Vec::new(),
                },
                |_| {},
            )
            .expect("walk through the link");
            followed += 1;
        }
        assert!(followed > 0, "no root-owned symlink on this system to try");
        // And a path that runs through one (macOS tempdirs live under /var).
        let t = tempfile::tempdir().expect("tmp");
        std::fs::write(t.path().join("a.php"), b"x").expect("w");
        let (seen, r) = run(t.path(), &opts());
        r.expect("walk");
        assert_eq!(rels(&seen), vec!["a.php"]);
    }

    #[test]
    fn relative_root_is_refused() {
        assert!(TenantRoot::open(Path::new("htdocs")).is_err());
        assert!(TenantRoot::open(Path::new("/tmp/../etc")).is_err());
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

    /// The directory is replaced by a link to an outside tree while the walk
    /// is under way (swap done from the visit callback, so it is
    /// deterministic). Whichever side of the swap the walk was on, nothing from
    /// the outside tree may be reported, and a later `open_file` through the
    /// swapped name is refused.
    #[test]
    fn symlink_swapped_for_dir_is_not_entered() {
        let outside = tempfile::tempdir().expect("outside");
        for n in ["one.php", "two.php", "three.php"] {
            std::fs::write(outside.path().join(n), b"secret").expect("w");
        }
        let t = tempfile::tempdir().expect("tmp");
        for d in ["a", "b"] {
            std::fs::create_dir(t.path().join(d)).expect("mkdir");
            for n in ["one.php", "two.php", "three.php"] {
                std::fs::write(t.path().join(d).join(n), b"x").expect("w");
            }
        }
        let root = TenantRoot::open(t.path()).expect("open");
        let mut swapped = false;
        let mut files = Vec::new();
        root.walk(&opts(), |ev| {
            if let WalkEvent::File(m) = ev {
                files.push(m.clone());
                if !swapped {
                    swapped = true;
                    // Swap the directory the walk is NOT currently in, and the
                    // one it is in: both names now point outside.
                    for d in ["a", "b"] {
                        let p = t.path().join(d);
                        std::fs::rename(&p, t.path().join(format!("{d}.moved"))).expect("mv");
                        tenant_symlink(outside.path(), &p);
                    }
                }
            }
        })
        .expect("walk");
        assert!(!files.is_empty());
        for m in &files {
            assert_eq!(m.size, 1, "{} came from the outside tree", m.rel);
        }
        assert!(root.open_file("a/two.php").is_err());
        assert!(root.open_file("b/two.php").is_err());
    }

    /// The stat said "directory"; by the time of the open it is a link.
    #[test]
    fn open_dir_refuses_a_link() {
        let outside = tempfile::tempdir().expect("outside");
        let t = tempfile::tempdir().expect("tmp");
        tenant_symlink(outside.path(), &t.path().join("d"));
        let root = TenantRoot::open(t.path()).expect("open");
        let err = open_dir(&root.fd, "d").expect_err("must not follow");
        // Linux answers ELOOP or ENOTDIR for a trailing symlink, macOS ENOTDIR.
        let why = skip_for_open_error(err);
        assert!(
            matches!(why, SkipReason::Symlink | SkipReason::NotRegular),
            "{why:?}"
        );
    }

    #[test]
    fn entries_vanishing_mid_walk_are_reported() {
        let t = tempfile::tempdir().expect("tmp");
        for i in 0..20 {
            std::fs::write(t.path().join(format!("f{i}.php")), b"x").expect("w");
        }
        let dir = t.path().to_path_buf();
        let mut first = true;
        let mut seen = Seen::default();
        let root = TenantRoot::open(t.path()).expect("open");
        let stats = root
            .walk(&opts(), |ev| match ev {
                WalkEvent::File(m) => {
                    seen.files.push(m.clone());
                    if first {
                        first = false;
                        // The directory was already listed; every entry goes
                        // away before the walk gets to it.
                        for i in 0..20 {
                            let _ = std::fs::remove_file(dir.join(format!("f{i}.php")));
                        }
                    }
                }
                WalkEvent::Skipped { rel, why } => seen.skipped.push((rel, why)),
            })
            .expect("walk");
        assert_eq!(seen.files.len(), 1);
        assert_eq!(seen.skipped.len(), 19, "{:?}", seen.skipped);
        assert!(seen.skipped.iter().all(|(_, w)| *w == SkipReason::Vanished));
        assert_eq!(stats.skipped, 19);
        assert!(!stats.capped);
    }

    #[test]
    fn open_file_reads_a_regular_file() {
        let t = tempfile::tempdir().expect("tmp");
        std::fs::create_dir(t.path().join("a")).expect("mkdir");
        std::fs::write(t.path().join("a/f.php"), b"body").expect("w");
        let root = TenantRoot::open(t.path()).expect("open");
        let mut s = String::new();
        root.open_file("a/f.php")
            .expect("open")
            .read_to_string(&mut s)
            .expect("read");
        assert_eq!(s, "body");
    }

    #[test]
    fn open_file_refuses_symlinked_parent() {
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret.php"), b"x").expect("w");
        let t = tempfile::tempdir().expect("tmp");
        let root = TenantRoot::open(t.path()).expect("open");
        tenant_symlink(outside.path(), &t.path().join("a"));
        assert!(root.open_file("a/secret.php").is_err());
    }

    #[test]
    fn list_dir_classifies_entries_without_following() {
        let outside = tempfile::tempdir().expect("outside");
        let t = tempfile::tempdir().expect("tmp");
        std::fs::create_dir_all(t.path().join("p/a")).expect("mkdir");
        std::fs::write(t.path().join("p/f.php"), b"x").expect("w");
        tenant_symlink(outside.path(), &t.path().join("p/l"));
        let root = TenantRoot::open(t.path()).expect("open");
        let mut got = root.list_dir("p", 100).expect("list").entries;
        got.sort_by(|a, b| a.name.cmp(&b.name));
        let got: Vec<(&str, EntryKind)> = got.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert_eq!(
            got,
            vec![
                ("a", EntryKind::Dir),
                ("f.php", EntryKind::File),
                ("l", EntryKind::Symlink)
            ]
        );
        // "" is the root itself.
        assert_eq!(root.list_dir("", 100).expect("root").entries.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn list_dir_cap_counts_names_it_cannot_list() {
        let t = tempfile::tempdir().expect("tmp");
        for i in 0..5u8 {
            let bytes = [b'b', 0xff, b'0' + i];
            let name = std::ffi::OsStr::from_bytes(&bytes);
            std::fs::write(t.path().join(name), b"x").expect("w");
        }
        std::fs::write(t.path().join("ok.php"), b"x").expect("w");
        let root = TenantRoot::open(t.path()).expect("open");
        let l = root.list_dir("", 3).expect("list");
        assert!(l.truncated);
        assert!(l.entries.len() as u64 + l.non_utf8 <= 3);
    }

    #[test]
    fn list_dir_refuses_symlinked_parent_and_bad_paths() {
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret.php"), b"x").expect("w");
        let t = tempfile::tempdir().expect("tmp");
        let root = TenantRoot::open(t.path()).expect("open");
        tenant_symlink(outside.path(), &t.path().join("a"));
        assert!(root.list_dir("a", 100).is_err());
        assert!(root.list_dir("../x", 100).is_err());
        assert!(root.list_dir("/etc", 100).is_err());
    }

    #[test]
    fn list_dir_is_capped_and_counts_non_utf8_names() {
        let t = tempfile::tempdir().expect("tmp");
        for i in 0..5 {
            std::fs::write(t.path().join(format!("f{i}.php")), b"x").expect("w");
        }
        let root = TenantRoot::open(t.path()).expect("open");
        let l = root.list_dir("", 3).expect("list");
        assert_eq!(l.entries.len(), 3);
        assert!(l.truncated);
        let all = root.list_dir("", 100).expect("list");
        assert_eq!(all.entries.len(), 5);
        assert!(!all.truncated);

        let bad = t.path().join(std::ffi::OsStr::from_bytes(b"bad\xff.php"));
        if let Err(e) = std::fs::write(&bad, b"x") {
            // macOS (APFS) refuses names that are not valid UTF-8 outright.
            assert_eq!(e.raw_os_error(), Some(92), "EILSEQ expected, got {e}");
            return;
        }
        let all = root.list_dir("", 100).expect("list");
        assert_eq!(all.entries.len(), 5);
        assert_eq!(all.non_utf8, 1);
    }

    #[test]
    fn open_file_refuses_leaf_symlink_dotdot_fifo_and_hard_link() {
        let t = tempfile::tempdir().expect("tmp");
        std::fs::write(t.path().join("f.php"), b"x").expect("w");
        tenant_symlink(&t.path().join("f.php"), &t.path().join("l.php"));
        let root = TenantRoot::open(t.path()).expect("open");
        assert!(root.open_file("l.php").is_err(), "leaf symlink");
        assert!(root.open_file("../f.php").is_err(), "..");
        assert!(root.open_file("/etc/passwd").is_err(), "absolute");
        assert!(root.open_file("").is_err(), "empty");
        assert!(root.open_file("a\0b").is_err(), "NUL");
        std::fs::create_dir(t.path().join("dir")).expect("mkdir");
        assert!(root.open_file("dir").is_err(), "directory");
        let fifo = t.path().join("pipe");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo")
            .success());
        assert!(root.open_file("pipe").is_err(), "fifo");
        std::fs::hard_link(t.path().join("f.php"), t.path().join("h.php")).expect("link");
        assert!(root.open_file("h.php").is_err(), "hard link");
    }

    #[test]
    fn file_cap_sets_capped() {
        let t = tempfile::tempdir().expect("tmp");
        for i in 0..5 {
            std::fs::write(t.path().join(format!("f{i}.php")), b"x").expect("w");
        }
        let o = WalkOpts {
            max_entries: 3,
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
            max_entries: 5,
            prune: Vec::new(),
        };
        let (_, r) = run(t.path(), &o);
        assert!(!r.expect("walk").capped);
    }

    /// Directories emit no events, so only `capped` shows whether they are
    /// counted: a tree of nothing but empty directories must hit the cap.
    #[test]
    fn cap_counts_directories_alone() {
        let t = tempfile::tempdir().expect("tmp");
        for i in 0..1000 {
            std::fs::create_dir(t.path().join(format!("d{i}"))).expect("mkdir");
        }
        let o = WalkOpts {
            max_entries: 50,
            prune: Vec::new(),
        };
        let (seen, r) = run(t.path(), &o);
        let stats = r.expect("walk");
        assert!(stats.capped, "empty directories were not counted");
        assert_eq!(stats.files, 0);
        // The walk stopped at the cap: one marker, nothing after it.
        assert_eq!(
            seen.skipped,
            vec![(seen.skipped[0].0.clone(), SkipReason::FileCapReached)]
        );
        // Under the cap is not capped.
        let o = WalkOpts {
            max_entries: 1000,
            prune: Vec::new(),
        };
        assert!(!run(t.path(), &o).1.expect("walk").capped);
    }

    /// Links, hard links and empty directories are entries too: they count
    /// against the cap, so a tree of them can't keep the walk busy.
    #[test]
    fn cap_counts_every_kind_of_entry() {
        let t = tempfile::tempdir().expect("tmp");
        std::fs::write(t.path().join("f.php"), b"x").expect("w");
        for i in 0..1000 {
            std::os::unix::fs::symlink("/nonexistent", t.path().join(format!("l{i}"))).expect("ln");
            std::fs::hard_link(t.path().join("f.php"), t.path().join(format!("h{i}")))
                .expect("link");
            std::fs::create_dir(t.path().join(format!("d{i}"))).expect("mkdir");
        }
        for (max, most_events) in [(0u64, 1usize), (50, 51)] {
            let o = WalkOpts {
                max_entries: max,
                prune: Vec::new(),
            };
            let (seen, r) = run(t.path(), &o);
            let stats = r.expect("walk");
            assert!(stats.capped, "max_entries={max}");
            let events = seen.files.len() + seen.skipped.len();
            // Empty directories are entries but report nothing.
            assert!(events <= most_events, "max_entries={max}: {events} events");
            assert_eq!(
                seen.skipped
                    .iter()
                    .filter(|(_, w)| *w == SkipReason::FileCapReached)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn pruned_directory_is_not_walked() {
        let t = tempfile::tempdir().expect("tmp");
        std::fs::create_dir_all(t.path().join("wp-content/cache")).expect("mkdir");
        std::fs::write(t.path().join("wp-content/cache/c.php"), b"x").expect("w");
        std::fs::write(t.path().join("wp-content/keep.php"), b"x").expect("w");
        let o = WalkOpts {
            max_entries: 100,
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
        if is_root() {
            // Root reads every directory regardless of mode, so there is no
            // unreadable directory to observe when the suite runs as root
            // (e.g. in a container).
            return;
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
        // Build level by level: one long absolute path can hit PATH_MAX.
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
        use rustix::fs::{utimensat, Timespec, Timestamps};
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
        assert!(
            (0..1_000_000_000).contains(&m.ctime_nsec),
            "{}",
            m.ctime_nsec
        );
    }

    /// `/proc` is always its own mount. Walk `/` but prune every other
    /// top-level directory so only the mount boundary is exercised.
    #[cfg(target_os = "linux")]
    #[test]
    fn stays_on_one_filesystem() {
        let mut prune = Vec::new();
        for e in std::fs::read_dir("/").expect("read /") {
            let e = e.expect("entry");
            if e.file_name() != "proc" && e.file_type().expect("type").is_dir() {
                prune.push(e.file_name().to_string_lossy().into_owned());
            }
        }
        let o = WalkOpts {
            max_entries: 100_000,
            prune,
        };
        let (seen, r) = run(Path::new("/"), &o);
        let stats = r.expect("walk");
        assert!(
            !seen.files.iter().any(|m| m.rel.starts_with("proc/")),
            "crossed into /proc"
        );
        assert!(
            seen.skipped
                .contains(&("proc".to_string(), SkipReason::OtherFilesystem)),
            "mount point not reported: {:?}",
            seen.skipped
        );
        assert!(stats.skipped >= 1);
    }

    /// The same boundary on the re-open path: a directory component on another
    /// device is refused (leaf files are not checked, overlayfs differs).
    #[cfg(target_os = "linux")]
    #[test]
    fn open_file_refuses_other_filesystem() {
        let root = TenantRoot::open(Path::new("/")).expect("open /");
        assert!(root.open_file("proc/version").is_err());
        assert!(root.open_file("etc/passwd").is_ok());
    }
}
