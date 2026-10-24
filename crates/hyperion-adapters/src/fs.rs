//! Filesystem helpers: atomic write, ensure_dir, no-symlink-traversal.

use crate::AdapterError;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs;

/// Atomic file write: write a fresh temp file beside `path`, set its mode,
/// rename it over the target. Caller owns the bytes; parent dir is created
/// if missing.
///
/// The temp file is created with `O_CREAT|O_EXCL|O_NOFOLLOW` under an
/// unpredictable name, with `mode` applied at creation and again through
/// the open descriptor. Several callers write into directories a site user
/// can write (`~/.ssh`, a site's own tree): a fixed `<path>.tmp` name opened
/// by path let that user plant a symlink there and have root write — and
/// later chmod/chown — whatever it pointed at. A secret is also never
/// readable at the default mode in the moment before a chmod.
pub async fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AdapterError> {
    write_then_rename(path, bytes, mode, None).await
}

/// [`atomic_write`], also handing the file to `uid:gid` — through the open
/// descriptor, before it gets its final name. A path-based `chown` after the
/// rename would follow whatever the directory's owner swapped in.
pub async fn atomic_write_owned(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), AdapterError> {
    write_then_rename(path, bytes, mode, Some((uid, gid))).await
}

async fn write_then_rename(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<(), AdapterError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).await?;
        }
    }
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || write_then_rename_blocking(&path, &bytes, mode, owner))
        .await
        .map_err(|e| AdapterError::Other(format!("atomic write task: {e}")))?
}

fn write_then_rename_blocking(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<(), AdapterError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = unique_temp_sibling(path)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&tmp)?;
    let result = (|| -> Result<(), AdapterError> {
        f.write_all(bytes)?;
        if let Some((uid, gid)) = owner {
            rustix::fs::fchown(
                &f,
                Some(rustix::fs::Uid::from_raw(uid)),
                Some(rustix::fs::Gid::from_raw(gid)),
            )
            .map_err(|e| AdapterError::Other(format!("fchown {}: {e}", tmp.display())))?;
        }
        // Again through the fd: the umask may have narrowed it at creation,
        // and fchown clears setuid bits a caller might have asked for.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// `<dir>/.<name>.<random>.tmp` — beside `path` so the rename stays on one
/// filesystem, and unguessable so nobody can occupy the name in advance.
fn unique_temp_sibling(path: &Path) -> Result<PathBuf, AdapterError> {
    use rand::Rng;
    let name = path
        .file_name()
        .ok_or_else(|| AdapterError::Other(format!("no file name in {}", path.display())))?;
    let tag: u64 = rand::thread_rng().gen();
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{tag:016x}.tmp"));
    Ok(path.with_file_name(tmp_name))
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
/// Open a path for reading WITHOUT following a symlink at the final
/// component, and prove it is a regular file.
///
/// The root agent reads and writes inside directories the SITE USER owns —
/// `logs/`, `wp-content/`, the whole document tree. Opening those by name
/// means the tenant decides what the name resolves to: replace
/// `logs/access.log` with a link to `/etc/shadow`, click "Logs" in the panel,
/// and root reads it out for them. `O_NOFOLLOW` refuses at the kernel, so
/// there is no window to race.
///
/// `st_nlink == 1` on top: a hardlink to a root-owned file cannot be refused
/// by O_NOFOLLOW (it is not a symlink), and a tenant who can create one in a
/// directory they own would otherwise get the same read.
pub fn open_no_follow(path: &Path) -> Result<std::fs::File, AdapterError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt;

    // NONBLOCK: a FIFO in place of the log would otherwise block the open
    // itself — before the regular-file check below could refuse it — and
    // hang whichever loop asked. It changes nothing for a regular file.
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| {
        // ELOOP is the interesting one: it means the final component IS a
        // symlink, i.e. someone put it there.
        if e == rustix::io::Errno::LOOP {
            AdapterError::Other(format!(
                "{} is a symlink — refusing to read through it as root",
                path.display()
            ))
        } else {
            AdapterError::Other(format!("open {}: {e}", path.display()))
        }
    })?;
    let file = std::fs::File::from(fd);
    let md = file
        .metadata()
        .map_err(|e| AdapterError::Other(format!("stat {}: {e}", path.display())))?;
    if !md.is_file() {
        return Err(AdapterError::Other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if md.nlink() != 1 {
        return Err(AdapterError::Other(format!(
            "{} has {} hard links — refusing to read it as root",
            path.display(),
            md.nlink()
        )));
    }
    Ok(file)
}

/// Open a path (file OR directory) without following a final symlink, for
/// metadata operations like `fchmod`.
///
/// Separate from [`open_no_follow`], which insists on a regular file: the
/// permission repair legitimately tightens directories.
pub fn open_path_no_follow(path: &Path) -> Result<std::fs::File, AdapterError> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        // RDONLY, not PATH: an O_PATH descriptor cannot be fchmod-ed, and
        // read-only opens work for directories as well as files. NONBLOCK so
        // a FIFO planted at the name cannot hang the open.
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| {
        if e == rustix::io::Errno::LOOP {
            AdapterError::Other(format!(
                "{} is a symlink — refusing to change its permissions as root",
                path.display()
            ))
        } else {
            AdapterError::Other(format!("open {}: {e}", path.display()))
        }
    })?;
    Ok(std::fs::File::from(fd))
}

/// Truncate a file to zero WITHOUT following a symlink, and without creating
/// it if it is not there.
///
/// `File::create` opens with O_CREAT|O_TRUNC and follows links, so pointing
/// `wp-content/debug.log` at a root-owned file and asking the panel to clear
/// it truncates that file instead. The tenant owns wp-content, so they can
/// place the link; the button is on their own site's page.
pub fn truncate_no_follow(path: &Path) -> Result<(), AdapterError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt;

    let fd = rustix::fs::open(
        path,
        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        if e == rustix::io::Errno::LOOP {
            AdapterError::Other(format!(
                "{} is a symlink — refusing to truncate through it as root",
                path.display()
            ))
        } else if e == rustix::io::Errno::NOENT {
            // Nothing to clear is success: the caller asked for an empty log.
            AdapterError::Other(String::new())
        } else {
            AdapterError::Other(format!("open {}: {e}", path.display()))
        }
    });
    let file = match fd {
        Ok(f) => std::fs::File::from(f),
        Err(AdapterError::Other(m)) if m.is_empty() => return Ok(()),
        Err(e) => return Err(e),
    };
    let md = file
        .metadata()
        .map_err(|e| AdapterError::Other(format!("stat {}: {e}", path.display())))?;
    if !md.is_file() || md.nlink() != 1 {
        return Err(AdapterError::Other(format!(
            "{} is not a plain single-linked file — refusing to truncate it",
            path.display()
        )));
    }
    file.set_len(0)
        .map_err(|e| AdapterError::Other(format!("truncate {}: {e}", path.display())))
}

/// Rewrite a text file in place as root WITHOUT following a symlink and
/// without creating it: `edit` gets the current content and returns the new
/// one, or `None` to leave the file alone. Returns whether it was written.
///
/// For files in a tree the site user owns (wp-config.php after an import):
/// opening by name with `tokio::fs::write` follows whatever link the tenant
/// left there. The descriptor is opened O_NOFOLLOW, proven a single-linked
/// regular file, and written through — owner and mode stay the tenant's.
/// A missing file is `Ok(false)`.
pub fn rewrite_no_follow(
    path: &Path,
    edit: impl FnOnce(&str) -> Option<String>,
) -> Result<bool, AdapterError> {
    use rustix::fs::{Mode, OFlags};
    use std::io::{Read, Seek, Write};
    use std::os::unix::fs::MetadataExt;

    let fd = match rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(rustix::io::Errno::LOOP) => {
            return Err(AdapterError::Other(format!(
                "{} is a symlink — refusing to rewrite through it as root",
                path.display()
            )))
        }
        Err(e) => return Err(AdapterError::Other(format!("open {}: {e}", path.display()))),
    };
    let mut file = std::fs::File::from(fd);
    let md = file
        .metadata()
        .map_err(|e| AdapterError::Other(format!("stat {}: {e}", path.display())))?;
    if !md.is_file() || md.nlink() != 1 {
        return Err(AdapterError::Other(format!(
            "{} is not a plain single-linked file — refusing to rewrite it",
            path.display()
        )));
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| AdapterError::Other(format!("read {}: {e}", path.display())))?;
    let Some(new) = edit(&content) else {
        return Ok(false);
    };
    file.set_len(0)
        .and_then(|()| file.rewind())
        .and_then(|()| file.write_all(new.as_bytes()))
        .map_err(|e| AdapterError::Other(format!("write {}: {e}", path.display())))?;
    Ok(true)
}

/// The last `lines` lines of a file, read safely as root.
///
/// Replaces shelling out to `tail`, which takes a PATH and therefore resolves
/// it again — after any check the caller made, and as root.
/// What [`read_appended`] found: the new text plus where to resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    pub text: String,
    pub ino: u64,
    pub offset: u64,
}

/// Read what was appended to a log since `(ino, offset)`, the way `tail -F`
/// would, opened through [`open_no_follow`] (the logs live in a directory
/// the site user owns).
///
/// * First sight (`ino == 0`): nothing is returned and the position is set
///   to the end — history is not news.
/// * Rotated (inode changed) or truncated (shorter than `offset`): read the
///   new file from its start.
/// * More than `max` bytes new: only the newest `max` are read.
///
/// The returned offset stops after the last complete line, so a line nginx
/// is still writing is read whole next time instead of half now.
pub fn read_appended(
    path: &Path,
    ino: u64,
    offset: u64,
    max: u64,
) -> Result<Appended, AdapterError> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;

    let mut file = open_no_follow(path)?;
    let md = file
        .metadata()
        .map_err(|e| AdapterError::Other(format!("stat: {e}")))?;
    let (cur_ino, len) = (md.ino(), md.len());
    if ino == 0 {
        return Ok(Appended {
            text: String::new(),
            ino: cur_ino,
            offset: len,
        });
    }
    let from = if cur_ino != ino || len < offset {
        0
    } else {
        offset
    };
    let start = from.max(len.saturating_sub(max));
    if start >= len {
        return Ok(Appended {
            text: String::new(),
            ino: cur_ino,
            offset: len,
        });
    }
    file.seek(SeekFrom::Start(start))
        .map_err(|e| AdapterError::Other(format!("seek: {e}")))?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    file.take(len - start)
        .read_to_end(&mut buf)
        .map_err(|e| AdapterError::Other(format!("read: {e}")))?;
    let complete = buf.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    buf.truncate(complete);
    Ok(Appended {
        text: String::from_utf8_lossy(&buf).into_owned(),
        ino: cur_ino,
        offset: start + complete as u64,
    })
}

pub async fn tail_lines(path: &Path, lines: usize) -> Result<String, AdapterError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = open_no_follow(path)?;
    let len = file
        .metadata()
        .map_err(|e| AdapterError::Other(format!("stat: {e}")))?
        .len();
    // Read a bounded window from the END. A tenant controls how big their own
    // log is, so reading the whole file would be a memory-exhaustion lever as
    // well as a slow one.
    const WINDOW: u64 = 1024 * 1024;
    let start = len.saturating_sub(WINDOW);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| AdapterError::Other(format!("seek: {e}")))?;
    let mut buf = Vec::with_capacity(WINDOW.min(len) as usize);
    file.take(WINDOW)
        .read_to_end(&mut buf)
        .map_err(|e| AdapterError::Other(format!("read: {e}")))?;
    let text = String::from_utf8_lossy(&buf);
    // A partial first line when the window cut mid-line.
    let text = if start > 0 {
        text.split_once('\n').map(|(_, rest)| rest).unwrap_or("")
    } else {
        &text
    };
    let all: Vec<&str> = text.lines().collect();
    let from = all.len().saturating_sub(lines);
    Ok(all[from..].join("\n"))
}

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

/// OR the traverse bits (0o011) into `leaf` and every ancestor up to `/`,
/// so nginx — running as another user — can path-resolve down to it.
///
/// Callers hand in paths inside site trees, whose directories the site user
/// can replace. So a path that does not resolve to itself (some component is
/// a symlink) is left alone entirely, and each directory is changed through
/// a descriptor opened with `O_NOFOLLOW|O_DIRECTORY`: a chmod by name would
/// follow a link swapped in after the check and widen whatever directory it
/// pointed at.
pub async fn ensure_ancestors_traversable(leaf: &Path) {
    let leaf = leaf.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || ensure_ancestors_traversable_blocking(&leaf)).await;
}

fn ensure_ancestors_traversable_blocking(leaf: &Path) {
    use rustix::fs::{Mode, OFlags};
    match std::fs::canonicalize(leaf) {
        Ok(c) if c == leaf => {}
        Ok(c) => {
            tracing::warn!(
                path = %leaf.display(),
                resolves_to = %c.display(),
                "not making ancestors traversable: the path goes through a symlink"
            );
            return;
        }
        Err(_) => return, // missing or unreadable: nothing to do
    }
    let mut current: Option<&Path> = Some(leaf);
    while let Some(p) = current {
        let Ok(fd) = rustix::fs::open(
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            break; // not a directory (or a link now): can't traverse further sensibly
        };
        let Ok(st) = rustix::fs::fstat(&fd) else {
            break;
        };
        let mode = st.st_mode & 0o777;
        let new_mode = mode | 0o011;
        if new_mode != mode {
            match rustix::fs::fchmod(&fd, Mode::from_raw_mode(new_mode as _)) {
                Err(e) => tracing::warn!(
                    path = %p.display(),
                    old_mode = format!("{:o}", mode),
                    new_mode = format!("{:o}", new_mode),
                    error = %e,
                    "could not OR traverse bits into ancestor; nginx may 404 on ACME challenges"
                ),
                Ok(()) => tracing::info!(
                    path = %p.display(),
                    old_mode = format!("{:o}", mode),
                    new_mode = format!("{:o}", new_mode),
                    "made ancestor world-traversable for ACME challenges"
                ),
            }
        }
        current = p.parent();
        // Stop at filesystem root.
        if matches!(current.map(|c| c.as_os_str().is_empty()), Some(true))
            || current == Some(Path::new("/"))
        {
            break;
        }
    }
}

/// Tighten `logs/` and `tmp/` under a hosting's site directory
/// (`/home/<user>/<domain>`) to mode 0750 owned by the site user, following no
/// tenant-planted symlink at the `<domain>` component or at either leaf.
///
/// The site user owns its home, so `<domain>` — and the two leaf directories —
/// can be swapped for symlinks between a path-based check and a path-based
/// chmod/chown. The old repair opened only the leaf `O_NOFOLLOW` and then ran
/// `chown -R <user> <site_dir>/<leaf>`, so a `<domain>` symlink steered both
/// the chmod and the *recursive* chown onto an arbitrary directory (e.g.
/// `/tmp`) as root. Here `<domain>` is opened `O_DIRECTORY|O_NOFOLLOW` once and
/// every chmod/chown is performed `*at()`-relative on that one descriptor — no
/// recursion, and no component re-resolved by name after the check.
///
/// Returns the leaf names that were present and repaired.
pub async fn repair_site_dirs_no_follow(
    site_dir: &Path,
    uid: u32,
    gid: u32,
) -> Result<Vec<&'static str>, AdapterError> {
    let site_dir = site_dir.to_path_buf();
    tokio::task::spawn_blocking(move || repair_site_dirs_no_follow_blocking(&site_dir, uid, gid))
        .await
        .map_err(|e| AdapterError::Other(format!("join: {e}")))?
}

fn repair_site_dirs_no_follow_blocking(
    site_dir: &Path,
    uid: u32,
    gid: u32,
) -> Result<Vec<&'static str>, AdapterError> {
    use rustix::fs::{Gid, Mode, OFlags, Uid};
    // Open `<domain>` itself without following a link — this is the component
    // the tenant can swap. A symlink here (or a non-directory) is refused, so
    // the leaf opens below can only land inside the real site directory.
    let site = rustix::fs::open(
        site_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        if e == rustix::io::Errno::LOOP || e == rustix::io::Errno::NOTDIR {
            AdapterError::Other("site directory is not a real directory".into())
        } else {
            AdapterError::Other(format!("open {}: {e}", site_dir.display()))
        }
    })?;
    let mut done = Vec::new();
    for name in ["logs", "tmp"] {
        let fd = match rustix::fs::openat(
            &site,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(f) => f,
            Err(rustix::io::Errno::NOENT) => continue, // leaf absent: nothing to do
            Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::NOTDIR) => {
                return Err(AdapterError::Other(format!(
                    "{name} is not a real directory — refusing to repair it"
                )));
            }
            Err(e) => return Err(AdapterError::Other(format!("open {name}: {e}"))),
        };
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o750))
            .map_err(|e| AdapterError::Other(format!("chmod {name}: {e}")))?;
        rustix::fs::fchown(&fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
            .map_err(|e| AdapterError::Other(format!("chown {name}: {e}")))?;
        done.push(name);
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// logs/ and tmp/ under a real site dir are tightened to 0750 and the
    /// present leaves are reported. chown targets the current uid/gid so the
    /// test needs no privilege.
    #[tokio::test]
    async fn repair_site_dirs_tightens_present_leaves() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let site = tempfile::tempdir().expect("tmp");
        for name in ["logs", "tmp"] {
            let d = site.path().join(name);
            std::fs::create_dir(&d).expect("mkdir");
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        // chown to the dir's existing owner so the fchown is a privilege-free
        // no-op (the test does not run as root); the chmod is what we assert.
        let md = std::fs::metadata(site.path()).expect("stat");
        let done = repair_site_dirs_no_follow(site.path(), md.uid(), md.gid())
            .await
            .expect("repair");
        assert_eq!(done, vec!["logs", "tmp"]);
        for name in ["logs", "tmp"] {
            let m = std::fs::metadata(site.path().join(name)).expect("stat");
            assert_eq!(m.permissions().mode() & 0o777, 0o750, "{name}");
        }
    }

    /// A `<domain>` swapped for a symlink is refused: the site dir is opened
    /// O_NOFOLLOW, so root never chmods/chowns through the link.
    #[tokio::test]
    async fn repair_site_dirs_refuses_swapped_domain() {
        let base = tempfile::tempdir().expect("tmp");
        let real = base.path().join("real_domain");
        std::fs::create_dir(&real).expect("mkdir");
        std::fs::create_dir(real.join("tmp")).expect("mkdir tmp");
        let link = base.path().join("domain");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let uid = rustix::process::getuid().as_raw();
        let r = repair_site_dirs_no_follow(&link, uid, uid).await;
        assert!(r.is_err(), "a symlinked site dir must be refused");
    }

    /// A missing leaf is simply skipped, not an error.
    #[tokio::test]
    async fn repair_site_dirs_skips_absent_leaves() {
        use std::os::unix::fs::MetadataExt;
        let site = tempfile::tempdir().expect("tmp");
        std::fs::create_dir(site.path().join("logs")).expect("mkdir");
        let md = std::fs::metadata(site.path()).expect("stat");
        let done = repair_site_dirs_no_follow(site.path(), md.uid(), md.gid())
            .await
            .expect("repair");
        assert_eq!(done, vec!["logs"]);
    }

    /// A link already sitting at the target name is REPLACED, never written
    /// through, and nothing is left behind but the file itself.
    #[tokio::test]
    async fn atomic_write_replaces_a_planted_link_instead_of_following_it() {
        let dir = tempfile::tempdir().expect("tmp");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").expect("victim");
        let target = dir.path().join("authorized_keys");
        std::os::unix::fs::symlink(&victim, &target).expect("link");

        atomic_write(&target, b"new", 0o600).await.expect("write");

        assert_eq!(std::fs::read(&victim).expect("read"), b"untouched");
        let md = std::fs::symlink_metadata(&target).expect("stat");
        assert!(md.file_type().is_file());
        assert_eq!(md.permissions().mode() & 0o7777, 0o600);
        assert_eq!(std::fs::read(&target).expect("read"), b"new");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("ls")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names.len(), 2, "temp file left behind: {names:?}");
    }

    #[test]
    fn rewrite_no_follow_edits_in_place_and_refuses_links() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("wp-config.php");
        std::fs::write(&p, "old longer content").expect("write");
        assert!(rewrite_no_follow(&p, |s| Some(s.replace("old longer ", "new "))).expect("ok"));
        assert_eq!(std::fs::read_to_string(&p).expect("read"), "new content");
        // `None` leaves it alone; a missing file is not an error.
        assert!(!rewrite_no_follow(&p, |_| None).expect("ok"));
        assert!(!rewrite_no_follow(&d.path().join("absent"), |_| Some("x".into())).expect("ok"));

        // A symlink planted in place of the file is refused, target untouched.
        let target = d.path().join("shadow");
        std::fs::write(&target, "secret").expect("write");
        let link = d.path().join("link.php");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(rewrite_no_follow(&link, |_| Some("pwned".into())).is_err());
        // So is a hard link to someone else's file.
        let hard = d.path().join("hard.php");
        std::fs::hard_link(&target, &hard).expect("hardlink");
        assert!(rewrite_no_follow(&hard, |_| Some("pwned".into())).is_err());
        assert_eq!(std::fs::read_to_string(&target).expect("read"), "secret");
    }

    #[test]
    fn read_appended_follows_a_growing_log() {
        use std::io::Write;
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("error.log");
        std::fs::write(&p, "old line\n").expect("write");

        // First sight: history is skipped.
        let a = read_appended(&p, 0, 0, 1 << 20).expect("read");
        assert_eq!(a.text, "");
        assert_eq!(a.offset, 9);

        // Appended text, with a half-written last line held back.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .expect("open");
        f.write_all(b"one\ntwo\npart").expect("append");
        let b = read_appended(&p, a.ino, a.offset, 1 << 20).expect("read");
        assert_eq!(b.text, "one\ntwo\n");
        assert_eq!(b.offset, 17);

        // The finished line arrives next time.
        f.write_all(b"ial\n").expect("append");
        let c = read_appended(&p, b.ino, b.offset, 1 << 20).expect("read");
        assert_eq!(c.text, "partial\n");

        // Truncated (rotation by copytruncate): read from the start.
        std::fs::write(&p, "fresh\n").expect("write");
        let e = read_appended(&p, c.ino, c.offset, 1 << 20).expect("read");
        assert_eq!(e.text, "fresh\n");

        // A burst larger than `max`: only the newest part.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .expect("open");
        f.write_all(b"aaaaaaaaaa\nbbbb\n").expect("append");
        let g = read_appended(&p, e.ino, e.offset, 8).expect("read");
        assert_eq!(g.text, "aa\nbbbb\n");
    }

    #[test]
    fn read_appended_refuses_a_symlink() {
        let d = tempfile::tempdir().expect("tempdir");
        let target = d.path().join("secret");
        std::fs::write(&target, "x\n").expect("write");
        let link = d.path().join("error.log");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(read_appended(&link, 1, 0, 1 << 20).is_err());
    }

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
        // Canonical: the helper refuses a path that goes through a link,
        // and a temp dir often does (macOS /var -> /private/var).
        let base = std::fs::canonicalize(root.path()).expect("canon");
        let mid = base.join("hyperion"); // simulate /var/lib/hyperion
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
        // Canonical: the helper refuses a path that goes through a link,
        // and a temp dir often does (macOS /var -> /private/var).
        let base = std::fs::canonicalize(root.path()).expect("canon");
        let p = base.join("a/b/c");
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
        // Canonical: the helper refuses a path that goes through a link,
        // and a temp dir often does (macOS /var -> /private/var).
        let base = std::fs::canonicalize(root.path()).expect("canon");
        let p = base.join("d");
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
    /// A path through a symlink is left alone: the directories at the far
    /// end are not ours to widen.
    #[tokio::test]
    async fn ensure_ancestors_traversable_refuses_a_path_through_a_link() {
        let root = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(root.path()).expect("canon");
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("leaf")).expect("mkdir");
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        std::os::unix::fs::symlink(&elsewhere, base.join("site")).expect("link");

        ensure_ancestors_traversable(&base.join("site/leaf")).await;

        let m = std::fs::metadata(&elsewhere)
            .expect("md")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o700, "a directory reached through a link was changed");
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

#[cfg(test)]
mod no_follow_tests {
    use super::*;

    /// The attack this exists to stop: `logs/` is owned by the site user, so
    /// the tenant replaces access.log with a link to a root-only file and
    /// clicks "Logs" in their own panel.
    #[tokio::test]
    async fn a_symlinked_log_is_refused() {
        let d = tempfile::tempdir().expect("tmp");
        let secret = d.path().join("shadow");
        std::fs::write(&secret, "root:$6$verysecret:::\n").expect("w");
        let logs = d.path().join("logs");
        std::fs::create_dir_all(&logs).expect("mk");
        let link = logs.join("access.log");
        std::os::unix::fs::symlink(&secret, &link).expect("plant link");

        let err = tail_lines(&link, 10)
            .await
            .expect_err("reading through a planted symlink must be refused");
        assert!(
            format!("{err}").contains("symlink"),
            "wrong refusal reason: {err}"
        );
    }

    /// A hardlink is not a symlink, so O_NOFOLLOW cannot refuse it — the
    /// link count is what catches that case.
    #[tokio::test]
    async fn a_hardlinked_log_is_refused() {
        let d = tempfile::tempdir().expect("tmp");
        let secret = d.path().join("shadow");
        std::fs::write(&secret, "root:$6$verysecret:::\n").expect("w");
        let logs = d.path().join("logs");
        std::fs::create_dir_all(&logs).expect("mk");
        let link = logs.join("access.log");
        std::fs::hard_link(&secret, &link).expect("plant hardlink");

        let err = tail_lines(&link, 10)
            .await
            .expect_err("reading a hardlink to a root file must be refused");
        assert!(
            format!("{err}").contains("hard link"),
            "wrong refusal reason: {err}"
        );
    }

    /// An ordinary log still reads, and only the last N lines come back.
    #[tokio::test]
    async fn an_ordinary_log_still_tails() {
        let d = tempfile::tempdir().expect("tmp");
        let p = d.path().join("access.log");
        let body: String = (1..=50).map(|i| format!("line {i}\n")).collect();
        std::fs::write(&p, body).expect("w");

        let out = tail_lines(&p, 5).await.expect("tail");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5, "{out}");
        assert_eq!(lines[4], "line 50");
        assert_eq!(lines[0], "line 46");
    }

    /// A tenant controls how big their own log is, so the read must be
    /// bounded rather than pulling the whole file into memory.
    #[tokio::test]
    async fn a_huge_log_does_not_read_the_whole_file() {
        let d = tempfile::tempdir().expect("tmp");
        let p = d.path().join("access.log");
        // 4 MiB — comfortably past the 1 MiB window.
        let body: String = (1..=200_000).map(|i| format!("line {i}\n")).collect();
        assert!(body.len() > 2 * 1024 * 1024);
        std::fs::write(&p, &body).expect("w");

        let out = tail_lines(&p, 3).await.expect("tail");
        assert_eq!(out.lines().count(), 3);
        assert!(out.ends_with("line 200000"), "{out}");
    }
}
