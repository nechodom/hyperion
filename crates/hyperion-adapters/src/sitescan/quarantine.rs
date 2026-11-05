//! Moving a flagged file out of a tenant's tree, and back.
//!
//! This runs as root and the tenant owns every directory involved, so nothing
//! here resolves a path below the docroot by name: [`TenantRoot`] pins the root
//! and every step is relative to a directory fd, with `O_NOFOLLOW`. A move is a
//! copy, never a rename: the quarantine is usually another mount. The copy is
//! taken from the descriptor that was checked, and the name goes only if it is
//! still that same file.
//!
//! Each held file is `<quarantine>/<hosting>/<id>`, with `<id>.json` beside it.
//! `id` is random hex, so no tenant text ever names anything in here.

use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{fchown, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::UNIX_EPOCH;

use hyperion_types::{FindingKind, QuarantineList, QuarantinedFile, WpMalwareHit};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::scan::metadata_hash;
use super::walk::TenantRoot;
use crate::AdapterError;

/// The refusal for an item that isn't what the scan reported any more.
pub const CHANGED_SINCE_SCAN: &str = "this changed since the last scan; scan again";
/// Bigger files stay where they are.
pub const MAX_FILE_BYTES: u64 = 2 * GIB;
/// What quarantine may take up. The copies are real and outside any disk quota,
/// and a tenant can make a large sparse file for free. Sizes are apparent sizes.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Held for one site.
    hosting_bytes: u64,
    /// Held for all of them.
    node_bytes: u64,
    /// Free space a copy must leave behind on the quarantine's disk.
    min_free_bytes: u64,
}

const GIB: u64 = 1024 * 1024 * 1024;
const LIMITS: Limits = Limits {
    hosting_bytes: 8 * GIB,
    node_bytes: 32 * GIB,
    min_free_bytes: 5 * GIB,
};
/// One move at a time on this node, from the check of the limits to the end of the
/// copy, or two at once could each see room for one.
static MOVING: Mutex<()> = Mutex::new(());
/// Held files are removed this long after they came in.
pub const PURGE_AFTER_SECS: i64 = 90 * 86_400;

const GONE: &str = "this file is no longer in quarantine";
const COPY_BUF_BYTES: usize = 64 * 1024;
/// More than any record can need: a name is at most 1 KiB, six bytes a character
/// when escaped.
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const ID_BYTES: usize = 16;
const RECORD_SUFFIX: &str = ".json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRequest {
    /// The docroot.
    pub root: PathBuf,
    pub quarantine_dir: PathBuf,
    pub hosting_id: String,
    pub rel: String,
    /// What the scan reported. A file too large to read has its metadata's hash
    /// here, and that is checked instead of its content.
    pub sha256: String,
    pub kind: FindingKind,
    pub rule_id: Option<String>,
    pub now: i64,
    /// ClamAV's hits on this file, kept with it: restoring it brings them back.
    #[serde(default)]
    pub malware: Vec<WpMalwareHit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRequest {
    /// The docroot.
    pub root: PathBuf,
    pub quarantine_dir: PathBuf,
    pub hosting_id: String,
    pub id: String,
}

fn refused(msg: impl Into<String>) -> AdapterError {
    AdapterError::Conflict(msg.into())
}

/// One name in the root-owned quarantine directory.
fn valid_hosting_id(id: &str) -> bool {
    !id.is_empty() && !id.starts_with('.') && !id.contains('/') && !id.contains('\0')
}

/// Could this name a held file? Only what [`quarantine_file`] makes does.
pub fn valid_id(id: &str) -> bool {
    id.len() == ID_BYTES * 2 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn new_id() -> String {
    hex::encode(rand::random::<[u8; ID_BYTES]>())
}

fn hosting_dir(base: &Path, hosting_id: &str) -> Result<PathBuf, AdapterError> {
    if !valid_hosting_id(hosting_id) {
        return Err(refused("not a hosting's quarantine"));
    }
    Ok(base.join(hosting_id))
}

/// The hosting's folder, made root-only whatever it was before.
fn prepare_dir(base: &Path, hosting_id: &str) -> Result<PathBuf, AdapterError> {
    let dir = hosting_dir(base, hosting_id)?;
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    for d in [base, dir.as_path()] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn record_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}{RECORD_SUFFIX}"))
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// A root-only file that wasn't there before.
fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn read_record(dir: &Path, id: &str) -> Option<QuarantinedFile> {
    let mut raw = Vec::new();
    File::open(record_path(dir, id))
        .ok()?
        .take(MAX_RECORD_BYTES)
        .read_to_end(&mut raw)
        .ok()?;
    let rec: QuarantinedFile = serde_json::from_slice(&raw).ok()?;
    (rec.id == id).then_some(rec)
}

/// Every record with its file, unordered. A folder that isn't there holds nothing.
fn held_records(dir: &Path) -> io::Result<Vec<QuarantinedFile>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_suffix(RECORD_SUFFIX)) else {
            continue;
        };
        if !valid_id(id) || !dir.join(id).exists() {
            continue;
        }
        if let Some(rec) = read_record(dir, id) {
            out.push(rec);
        }
    }
    Ok(out)
}

fn remove_held(dir: &Path, id: &str) {
    // The file first: a record with no file isn't listed, and a file with no
    // record ages out by itself.
    let _ = fs::remove_file(dir.join(id));
    let _ = fs::remove_file(record_path(dir, id));
    let _ = fs::remove_file(dir.join(format!(".{id}.tmp")));
    let _ = fs::remove_file(dir.join(format!(".{id}.json.tmp")));
}

/// Why `open_file` said no, in words for the card. No path in them: a tenant
/// chose those.
fn open_refusal(e: &io::Error) -> AdapterError {
    match Errno::from_io_error(e) {
        Some(Errno::LOOP | Errno::NOTDIR) => refused(
            "this is a symlink or has one in its path, so it isn't moved; remove it over SFTP",
        ),
        Some(Errno::NOENT) => refused(CHANGED_SINCE_SCAN),
        _ if e.to_string().contains("hard-linked") => {
            refused("this file has other hard links, so it isn't moved; remove it over SFTP")
        }
        _ => refused(format!("this file can't be moved: {e}")),
    }
}

fn restore_refusal(e: &io::Error) -> AdapterError {
    match Errno::from_io_error(e) {
        Some(Errno::EXIST) => refused("something is already at that path; move it away first"),
        Some(Errno::NOENT) => {
            refused("the folder this file was in no longer exists; create it first")
        }
        Some(Errno::LOOP | Errno::NOTDIR) => {
            refused("a folder on that path is now a symlink or a file, so nothing was written")
        }
        _ => refused(format!("this file can't be put back: {e}")),
    }
}

fn open_root(root: &Path) -> Result<TenantRoot, AdapterError> {
    TenantRoot::open(root)
        .map_err(|e| refused(format!("the site's document root can't be opened: {e}")))
}

/// Has the file been touched since `before`? Size and ctime, on the same inode.
fn unchanged(before: &Metadata, now: &Metadata) -> bool {
    before.ino() == now.ino()
        && before.dev() == now.dev()
        && before.len() == now.len()
        && before.ctime() == now.ctime()
        && before.ctime_nsec() == now.ctime_nsec()
}

/// Copy `from` to `to`, up to `limit` bytes, and say what went across.
fn copy_hashing(mut from: &File, to: &mut File, limit: u64) -> io::Result<(u64, [u8; 32])> {
    let mut sha = Sha256::new();
    let mut buf = vec![0u8; COPY_BUF_BYTES];
    let mut copied = 0u64;
    loop {
        let room = usize::try_from(limit - copied)
            .unwrap_or(COPY_BUF_BYTES)
            .min(COPY_BUF_BYTES);
        if room == 0 {
            break;
        }
        let n = match from.read(&mut buf[..room]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        to.write_all(&buf[..n])?;
        sha.update(&buf[..n]);
        copied += n as u64;
    }
    Ok((copied, sha.finalize().into()))
}

/// The copy and its record, durable, before anything happens to the original.
fn place_copy(
    src: &File,
    before: &Metadata,
    req: &QuarantineRequest,
    dir: &Path,
    id: &str,
) -> Result<QuarantinedFile, AdapterError> {
    let by_metadata = req.sha256
        == hex::encode(metadata_hash(
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ));
    let tmp = dir.join(format!(".{id}.tmp"));
    let mut out = create_private(&tmp)?;
    let (_, sha) = copy_hashing(src, &mut out, MAX_FILE_BYTES)?;
    // One read for the check and the copy: what's held is what was checked.
    if !by_metadata && hex::encode(sha) != req.sha256 {
        return Err(refused(CHANGED_SINCE_SCAN));
    }
    if !unchanged(before, &src.metadata()?) {
        return Err(refused(CHANGED_SINCE_SCAN));
    }
    out.sync_all()?;
    drop(out);

    let rec = QuarantinedFile {
        id: id.to_string(),
        rel: req.rel.clone(),
        sha256: req.sha256.clone(),
        size: before.len(),
        mode: before.mode(),
        uid: before.uid(),
        gid: before.gid(),
        time: req.now,
        kind: req.kind,
        rule_id: req.rule_id.clone(),
        malware: req.malware.clone(),
    };
    let tmp_record = dir.join(format!(".{id}.json.tmp"));
    let body = serde_json::to_vec(&rec).map_err(|e| AdapterError::Other(e.to_string()))?;
    let mut f = create_private(&tmp_record)?;
    f.write_all(&body)?;
    f.sync_all()?;
    fs::rename(&tmp_record, record_path(dir, id))?;
    fs::rename(&tmp, dir.join(id))?;
    sync_dir(dir)?;
    Ok(rec)
}

/// Is there room for `size` more? Everything said here ends the same way: the file
/// stays, and SFTP is how to be rid of it.
fn check_room(base: &Path, dir: &Path, size: u64, limits: &Limits) -> Result<(), AdapterError> {
    let total = |d: &Path| -> io::Result<u64> {
        Ok(held_records(d)?
            .iter()
            .fold(0u64, |sum, r| sum.saturating_add(r.size)))
    };
    if total(dir)?.saturating_add(size) > limits.hosting_bytes {
        return Err(refused(
            "this site's quarantine is full; restore or wait for older files to expire, or remove this one over SFTP",
        ));
    }
    let mut node = size;
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            node = node.saturating_add(total(&entry.path())?);
        }
    }
    if node > limits.node_bytes {
        return Err(refused(
            "this server's quarantine is full; remove this file over SFTP",
        ));
    }
    let st = rustix::fs::statvfs(dir)
        .map_err(|e| refused(format!("the free disk space can't be read: {e}")))?;
    let free = st.f_bavail.saturating_mul(st.f_frsize);
    if free < size.saturating_add(limits.min_free_bytes) {
        return Err(refused(
            "this server would run too low on free disk space to hold a copy; remove this file over SFTP",
        ));
    }
    Ok(())
}

/// Move one file into quarantine: check it is what the scan reported, hold a
/// durable copy, remove the original.
pub fn quarantine_file(req: &QuarantineRequest) -> Result<QuarantinedFile, AdapterError> {
    quarantine_with_limits(req, &LIMITS)
}

fn quarantine_with_limits(
    req: &QuarantineRequest,
    limits: &Limits,
) -> Result<QuarantinedFile, AdapterError> {
    let root = open_root(&req.root)?;
    let src = root.open_file(&req.rel).map_err(|e| open_refusal(&e))?;
    let before = src.metadata()?;
    if before.len() > MAX_FILE_BYTES {
        return Err(refused(
            "this file is over 2 GiB, too large to quarantine; remove it over SFTP",
        ));
    }
    // A panic in here left nothing behind that the next caller's checks get wrong.
    let _moving = MOVING.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = prepare_dir(&req.quarantine_dir, &req.hosting_id)?;
    check_room(&req.quarantine_dir, &dir, before.len(), limits)?;
    let id = new_id();
    let done = place_copy(&src, &before, req, &dir, &id).and_then(|rec| {
        // Still the same inode, and on a name reached without following anything.
        root.unlink(&req.rel, &src).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                refused(CHANGED_SINCE_SCAN)
            } else {
                open_refusal(&e)
            }
        })?;
        Ok(rec)
    });
    if done.is_err() {
        remove_held(&dir, &id);
    }
    done
}

/// Write the held copy to `out`, then its mode and owner, then make it and its name
/// durable. Never the setuid or setgid bit: a tenant can't have set those for root's
/// benefit, and root is the one writing this back.
fn write_back(
    held: &File,
    out: &mut File,
    parent: &File,
    rec: &QuarantinedFile,
) -> Result<(), AdapterError> {
    let (copied, _) = copy_hashing(held, out, MAX_FILE_BYTES)?;
    if copied != rec.size {
        return Err(refused(
            "the quarantined copy is damaged; it was not put back",
        ));
    }
    out.set_permissions(fs::Permissions::from_mode(rec.mode & 0o777))?;
    fchown(&*out, Some(rec.uid), Some(rec.gid))?;
    out.sync_all()?;
    parent.sync_all()?;
    Ok(())
}

/// Put a held file back where it was, with its owner and mode. Refuses a path
/// that is occupied and a parent that is gone, rather than making either fit.
pub fn restore_file(req: &RestoreRequest) -> Result<QuarantinedFile, AdapterError> {
    let dir = hosting_dir(&req.quarantine_dir, &req.hosting_id)?;
    if !valid_id(&req.id) {
        return Err(refused(GONE));
    }
    let rec = read_record(&dir, &req.id).ok_or_else(|| refused(GONE))?;
    let held = File::open(dir.join(&req.id)).map_err(|_| refused(GONE))?;
    let root = open_root(&req.root)?;
    let (mut out, parent) = root.create_new(&rec.rel).map_err(|e| restore_refusal(&e))?;
    // Only once this is on disk can the held copy go.
    if let Err(e) = write_back(&held, &mut out, &parent, &rec) {
        let _ = root.unlink(&rec.rel, &out);
        return Err(e);
    }
    remove_held(&dir, &req.id);
    sync_dir(&dir)?;
    Ok(rec)
}

/// What a hosting holds, newest first, at most `cap` of it. Metadata only.
pub fn list_quarantine(
    base: &Path,
    hosting_id: &str,
    cap: usize,
) -> Result<QuarantineList, AdapterError> {
    let dir = hosting_dir(base, hosting_id)?;
    let mut items = held_records(&dir)?;
    let total = u64::try_from(items.len()).unwrap_or(u64::MAX);
    items.sort_by(|a, b| b.time.cmp(&a.time).then_with(|| a.id.cmp(&b.id)));
    items.truncate(cap);
    Ok(QuarantineList { items, total })
}

/// When an entry of a hosting's folder came in: by its record, or failing that
/// (a lost record, a temp from a crash) by its own clock.
fn came_in_at(dir: &Path, name: &str, path: &Path) -> Option<i64> {
    let id = name.strip_suffix(RECORD_SUFFIX).unwrap_or(name);
    if let Some(rec) = valid_id(id).then(|| read_record(dir, id)).flatten() {
        return Some(rec.time);
    }
    let modified = fs::symlink_metadata(path).ok()?.modified().ok()?;
    let secs = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(secs).ok()
}

/// Remove what has been held for 90 days, from every hosting. Returns the number
/// of files removed. Runs in root's own tree: nothing here is a tenant's.
pub fn purge_quarantine(base: &Path, now: i64) -> u64 {
    let Ok(hostings) = fs::read_dir(base) else {
        return 0;
    };
    let mut removed = 0;
    for hosting in hostings.flatten() {
        let dir = hosting.path();
        if !hosting.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        // Records go last, so each file is still dated by its own.
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort_by_key(|n| n.ends_with(RECORD_SUFFIX));
        for name in names {
            let path = dir.join(&name);
            let Some(at) = came_in_at(&dir, &name, &path) else {
                continue;
            };
            if now.saturating_sub(at) < PURGE_AFTER_SECS {
                continue;
            }
            if fs::remove_file(&path).is_ok() && valid_id(&name) {
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTING: &str = "H1";

    struct Site {
        _t: tempfile::TempDir,
        root: PathBuf,
        dir: PathBuf,
    }

    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    fn tenant_symlink(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).expect("ln");
        if is_root() {
            rustix::fs::chownat(
                rustix::fs::CWD,
                link,
                Some(rustix::fs::Uid::from_raw(1000)),
                None,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .expect("lchown");
        }
    }

    fn sha(body: &[u8]) -> String {
        hex::encode(Sha256::digest(body))
    }

    /// The real limits, on whatever disk the tests happen to have.
    fn roomy() -> Limits {
        Limits {
            min_free_bytes: 0,
            ..LIMITS
        }
    }

    impl Site {
        fn new() -> Site {
            let t = tempfile::tempdir().expect("tmp");
            let root = t.path().join("htdocs");
            fs::create_dir_all(&root).expect("mkdir");
            let dir = t.path().join("quarantine");
            Site { _t: t, root, dir }
        }

        fn write(&self, rel: &str, body: &[u8]) -> PathBuf {
            let p = self.root.join(rel);
            fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            fs::write(&p, body).expect("write");
            p
        }

        fn request(&self, rel: &str, sha256: &str) -> QuarantineRequest {
            QuarantineRequest {
                root: self.root.clone(),
                quarantine_dir: self.dir.clone(),
                hosting_id: HOSTING.to_string(),
                rel: rel.to_string(),
                sha256: sha256.to_string(),
                kind: FindingKind::RuleHit,
                rule_id: Some("php.eval_post".to_string()),
                now: 1_000,
                malware: Vec::new(),
            }
        }

        fn quarantine(&self, rel: &str, sha256: &str) -> Result<QuarantinedFile, AdapterError> {
            quarantine_with_limits(&self.request(rel, sha256), &roomy())
        }

        fn restore(&self, id: &str) -> Result<QuarantinedFile, AdapterError> {
            restore_file(&RestoreRequest {
                root: self.root.clone(),
                quarantine_dir: self.dir.clone(),
                hosting_id: HOSTING.to_string(),
                id: id.to_string(),
            })
        }

        fn held(&self) -> PathBuf {
            self.dir.join(HOSTING)
        }

        fn held_names(&self) -> Vec<String> {
            match fs::read_dir(self.held()) {
                Ok(rd) => rd
                    .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
    }

    fn refusal(r: Result<QuarantinedFile, AdapterError>) -> String {
        match r {
            Err(AdapterError::Conflict(m)) => m,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn quarantine_moves_file_and_records_metadata() {
        let s = Site::new();
        let p = s.write("wp-content/uploads/a.php", b"<?php evil();");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).expect("chmod");
        let before = fs::metadata(&p).expect("stat");

        let rec = s
            .quarantine("wp-content/uploads/a.php", &sha(b"<?php evil();"))
            .expect("quarantine");

        assert!(!p.exists(), "the source is gone");
        assert_eq!(rec.id.len(), 32);
        assert!(rec.id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(rec.rel, "wp-content/uploads/a.php");
        assert_eq!(rec.sha256, sha(b"<?php evil();"));
        assert_eq!(rec.size, 13);
        assert_eq!(rec.mode & 0o7777, 0o640);
        assert_eq!(rec.uid, before.uid());
        assert_eq!(rec.gid, before.gid());
        assert_eq!(rec.time, 1_000);
        assert_eq!(rec.kind, FindingKind::RuleHit);
        assert_eq!(rec.rule_id.as_deref(), Some("php.eval_post"));

        let held = s.held().join(&rec.id);
        assert_eq!(fs::read(&held).expect("held"), b"<?php evil();");
        assert_eq!(fs::metadata(&held).expect("stat").mode() & 0o777, 0o600);
        let meta = s.held().join(format!("{}.json", rec.id));
        assert_eq!(fs::metadata(&meta).expect("stat").mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(s.held()).expect("stat").mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&s.dir).expect("stat").mode() & 0o777, 0o700);
        let parsed: QuarantinedFile =
            serde_json::from_slice(&fs::read(&meta).expect("meta")).expect("json");
        assert_eq!(parsed, rec);
        // Nothing left over from the way there.
        assert_eq!(s.held_names().len(), 2, "{:?}", s.held_names());
    }

    #[test]
    fn quarantine_refuses_symlink_and_path_escape() {
        let s = Site::new();
        let outside = tempfile::tempdir().expect("outside");
        fs::write(outside.path().join("secret.php"), b"secret").expect("w");
        let hash = sha(b"secret");
        tenant_symlink(&outside.path().join("secret.php"), &s.root.join("l.php"));
        tenant_symlink(outside.path(), &s.root.join("d"));

        let m = refusal(s.quarantine("l.php", &hash));
        assert!(m.contains("SFTP"), "{m}");
        let m = refusal(s.quarantine("d/secret.php", &hash));
        assert!(m.contains("SFTP"), "{m}");
        for bad in [
            "../secret.php",
            "a/../../secret.php",
            "/etc/passwd",
            "",
            "a\0b",
        ] {
            assert!(s.quarantine(bad, &hash).is_err(), "{bad}");
        }
        assert!(outside.path().join("secret.php").exists());
        assert!(s.held_names().is_empty());
    }

    #[test]
    fn hard_links_are_left_for_sftp() {
        let s = Site::new();
        let a = s.write("a.php", b"x");
        fs::hard_link(&a, s.root.join("b.php")).expect("link");
        let m = refusal(s.quarantine("a.php", &sha(b"x")));
        assert!(m.contains("SFTP"), "{m}");
        assert!(a.exists());
    }

    #[test]
    fn quarantine_refuses_when_hash_changed_since_scan() {
        let s = Site::new();
        let p = s.write("a.php", b"new content");
        let m = refusal(s.quarantine("a.php", &sha(b"what the scan read")));
        assert_eq!(m, CHANGED_SINCE_SCAN);
        assert_eq!(fs::read(&p).expect("read"), b"new content");
        assert!(s.held_names().is_empty(), "{:?}", s.held_names());
    }

    /// Gone since the scan: the same answer, not an I/O error.
    #[test]
    fn stale_hash_is_refused() {
        let s = Site::new();
        assert_eq!(
            refusal(s.quarantine("gone.php", &sha(b"x"))),
            CHANGED_SINCE_SCAN
        );
    }

    #[test]
    fn over_two_gib_is_refused_clearly() {
        let s = Site::new();
        let p = s.write("big.bin", b"");
        let f = fs::OpenOptions::new().write(true).open(&p).expect("open");
        f.set_len(MAX_FILE_BYTES + 1).expect("sparse");
        let m = refusal(s.quarantine("big.bin", &sha(b"")));
        assert!(m.contains("2 GiB"), "{m}");
        assert!(p.exists());
        assert!(s.held_names().is_empty());
    }

    /// A tenant can make a huge sparse file for free, and quarantine holds a
    /// real copy outside its quota.
    #[test]
    fn what_a_site_holds_is_capped() {
        let s = Site::new();
        let first = s.quarantine_small("a.php", b"first");
        // Pretend what's held is almost at the limit.
        let meta = s.held().join(format!("{}.json", first.id));
        let mut rec = first.clone();
        rec.size = LIMITS.hosting_bytes - 2;
        fs::write(&meta, serde_json::to_vec(&rec).expect("json")).expect("w");

        let p = s.write("b.php", b"xxxx");
        let m = refusal(s.quarantine("b.php", &sha(b"xxxx")));
        assert!(m.contains("restore or wait") && m.contains("SFTP"), "{m}");
        assert!(p.exists());
        assert_eq!(s.held_names().len(), 2, "{:?}", s.held_names());
    }

    #[test]
    fn the_limits_are_what_was_decided() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(LIMITS.hosting_bytes, 8 * GIB);
        assert_eq!(LIMITS.node_bytes, 32 * GIB);
        assert_eq!(LIMITS.min_free_bytes, 5 * GIB);
    }

    /// Every site at its own limit can still fill a disk.
    #[test]
    fn what_a_node_holds_is_capped() {
        let s = Site::new();
        let limits = Limits {
            node_bytes: 100,
            ..roomy()
        };
        // Another site's, with room left on this one's own limit.
        let other = s.dir.join("H2");
        fs::create_dir_all(&other).expect("mkdir");
        let id = "0".repeat(32);
        fs::write(other.join(&id), b"x").expect("w");
        let rec = QuarantinedFile {
            id: id.clone(),
            rel: "x.php".into(),
            size: 98,
            ..Default::default()
        };
        fs::write(
            other.join(format!("{id}.json")),
            serde_json::to_vec(&rec).expect("json"),
        )
        .expect("w");

        let p = s.write("a.php", b"xxxx");
        let m = refusal(quarantine_with_limits(
            &s.request("a.php", &sha(b"xxxx")),
            &limits,
        ));
        assert!(m.contains("server") && m.contains("SFTP"), "{m}");
        assert!(p.exists());
        assert!(s.held_names().is_empty(), "{:?}", s.held_names());

        // Exactly at it is allowed.
        let q = s.write("b.php", b"xx");
        quarantine_with_limits(&s.request("b.php", &sha(b"xx")), &limits).expect("fits");
        assert!(!q.exists());
    }

    #[test]
    fn a_disk_that_would_run_low_is_refused() {
        let s = Site::new();
        let p = s.write("a.php", b"xxxx");
        let limits = Limits {
            min_free_bytes: u64::MAX,
            ..roomy()
        };
        let m = refusal(quarantine_with_limits(
            &s.request("a.php", &sha(b"xxxx")),
            &limits,
        ));
        assert!(m.contains("free") && m.contains("SFTP"), "{m}");
        assert!(p.exists());
        assert!(s.held_names().is_empty(), "{:?}", s.held_names());
    }

    /// Two at once can't both see room for one.
    #[test]
    fn the_check_and_the_copy_are_one_step() {
        let s = Site::new();
        for i in 0..8 {
            s.write(&format!("f{i}.php"), b"xxxx");
        }
        let limits = Limits {
            hosting_bytes: 12,
            ..roomy()
        };
        let moved: usize = std::thread::scope(|scope| {
            let runs: Vec<_> = (0..8)
                .map(|i| {
                    let (s, limits) = (&s, &limits);
                    scope.spawn(move || {
                        let req = s.request(&format!("f{i}.php"), &sha(b"xxxx"));
                        quarantine_with_limits(&req, limits).is_ok()
                    })
                })
                .collect();
            runs.into_iter()
                .map(|r| usize::from(r.join().expect("join")))
                .sum()
        });
        assert_eq!(moved, 3);
    }

    /// A ClamAV hit goes with the file and comes back with it, so two clicks can't
    /// clear it. What goes on the record is what the caller said.
    #[test]
    fn a_clamav_hit_travels_in_the_record() {
        let s = Site::new();
        s.write("a.php", b"x");
        let hit = hyperion_types::WpMalwareHit {
            path: "/home/u/htdocs/a.php".into(),
            signature: "Php.Trojan.Webshell-1".into(),
        };
        let mut req = s.request("a.php", &sha(b"x"));
        req.malware = vec![hit.clone()];
        let rec = quarantine_with_limits(&req, &roomy()).expect("q");
        assert_eq!(rec.malware, std::slice::from_ref(&hit));
        let on_disk: QuarantinedFile = serde_json::from_slice(
            &fs::read(s.held().join(format!("{}.json", rec.id))).expect("record"),
        )
        .expect("json");
        assert_eq!(on_disk.malware, std::slice::from_ref(&hit));
        assert_eq!(s.restore(&rec.id).expect("restore").malware, [hit]);
    }

    impl Site {
        fn quarantine_small(&self, rel: &str, body: &[u8]) -> QuarantinedFile {
            self.write(rel, body);
            self.quarantine(rel, &sha(body)).expect("quarantine")
        }
    }

    /// An item too large to read is verified by its metadata instead.
    #[test]
    fn metadata_item_is_verified_by_metadata() {
        let s = Site::new();
        let p = s.write("big.php", b"body");
        let st = fs::metadata(&p).expect("stat");
        let meta = hex::encode(metadata_hash(st.len(), st.ctime(), st.ctime_nsec()));

        // Touched since the scan: its ctime moved, so this isn't what was reported.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(refusal(s.quarantine("big.php", &meta)), CHANGED_SINCE_SCAN);
        assert!(p.exists());

        let st = fs::metadata(&p).expect("stat");
        let meta = hex::encode(metadata_hash(st.len(), st.ctime(), st.ctime_nsec()));
        let rec = s.quarantine("big.php", &meta).expect("quarantine");
        assert_eq!(rec.sha256, meta);
        assert!(!p.exists());
    }

    /// What was copied is what goes: another file put at that name since isn't
    /// removed.
    #[test]
    fn swapped_inode_isnt_unlinked() {
        let s = Site::new();
        let p = s.write("a.php", b"copied");
        let root = TenantRoot::open(&s.root).expect("open");
        let copied = root.open_file("a.php").expect("open");
        // The tenant swaps the name for something else.
        let other = s.write("other.php", b"another file");
        fs::rename(&other, &p).expect("swap");

        let err = root.unlink("a.php", &copied).expect_err("must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&p).expect("read"), b"another file");

        // And with the same entry it goes.
        let same = root.open_file("a.php").expect("open");
        root.unlink("a.php", &same).expect("unlink");
        assert!(!p.exists());
    }

    #[test]
    fn symlinked_parent_refused_on_unlink() {
        let s = Site::new();
        let outside = tempfile::tempdir().expect("outside");
        let victim = outside.path().join("a.php");
        fs::write(&victim, b"x").expect("w");
        let local = s.write("real/a.php", b"x");
        let root = TenantRoot::open(&s.root).expect("open");
        let copied = root.open_file("real/a.php").expect("open");
        drop(local);
        fs::rename(s.root.join("real"), s.root.join("moved")).expect("mv");
        tenant_symlink(outside.path(), &s.root.join("real"));

        assert!(root.unlink("real/a.php", &copied).is_err());
        assert!(victim.exists(), "root followed the tenant's link");
        // Nor a symlink as the leaf, whatever it leads to.
        tenant_symlink(&victim, &s.root.join("leaf.php"));
        assert!(root.unlink("leaf.php", &copied).is_err());
        assert!(s.root.join("leaf.php").symlink_metadata().is_ok());
    }

    #[test]
    fn restore_refuses_occupied_path() {
        let s = Site::new();
        let rec = s.quarantine_small("a.php", b"original");
        let p = s.write("a.php", b"someone put this here");
        let m = refusal(s.restore(&rec.id));
        assert!(m.contains("already"), "{m}");
        assert_eq!(fs::read(&p).expect("read"), b"someone put this here");
        // Still held, for when the path is free.
        assert!(s.held().join(&rec.id).exists());
        fs::remove_file(&p).expect("rm");
        // A symlink in the way is occupied too, and isn't written through.
        let outside = tempfile::tempdir().expect("outside");
        tenant_symlink(&outside.path().join("new.php"), &p);
        assert!(s.restore(&rec.id).is_err());
        assert!(!outside.path().join("new.php").exists());
    }

    #[test]
    fn restore_keeps_owner_and_mode() {
        let s = Site::new();
        let p = s.write("d/a.php", b"original");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).expect("chmod");
        // chown needs root: the container run covers it, a laptop run keeps its
        // own owner and checks the same thing.
        let (uid, gid) = if is_root() {
            std::os::unix::fs::chown(&p, Some(1234), Some(2345)).expect("chown");
            (1234, 2345)
        } else {
            let st = fs::metadata(&p).expect("stat");
            (st.uid(), st.gid())
        };
        let rec = s.quarantine("d/a.php", &sha(b"original")).expect("q");
        assert_eq!((rec.uid, rec.gid), (uid, gid));
        assert!(!p.exists());

        let back = s.restore(&rec.id).expect("restore");
        assert_eq!(back.rel, "d/a.php");
        assert_eq!(fs::read(&p).expect("read"), b"original");
        let st = fs::metadata(&p).expect("stat");
        assert_eq!(st.mode() & 0o7777, 0o640);
        assert_eq!((st.uid(), st.gid()), (uid, gid));
        // Nothing left of it in quarantine.
        assert!(s.held_names().is_empty(), "{:?}", s.held_names());
    }

    #[test]
    fn setuid_bit_not_restored() {
        let s = Site::new();
        let p = s.write("a.php", b"original");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o6755)).expect("chmod");
        let rec = s.quarantine("a.php", &sha(b"original")).expect("q");
        // Recorded as it was, and what comes back has only the permission bits.
        assert_eq!(rec.mode & 0o7777, 0o6755);
        s.restore(&rec.id).expect("restore");
        assert_eq!(fs::metadata(&p).expect("stat").mode() & 0o7777, 0o755);
    }

    #[test]
    fn restore_through_symlinked_parent_refused() {
        let s = Site::new();
        let rec = s.quarantine_small("d/a.php", b"original");
        let outside = tempfile::tempdir().expect("outside");
        fs::remove_dir(s.root.join("d")).expect("rmdir");
        tenant_symlink(outside.path(), &s.root.join("d"));
        let m = refusal(s.restore(&rec.id));
        assert!(m.contains("symlink"), "{m}");
        assert!(!outside.path().join("a.php").exists());
        assert!(s.held().join(&rec.id).exists());
    }

    #[test]
    fn restore_says_when_the_folder_is_gone() {
        let s = Site::new();
        let rec = s.quarantine_small("d/e/a.php", b"original");
        fs::remove_dir_all(s.root.join("d")).expect("rm");
        let m = refusal(s.restore(&rec.id));
        assert!(m.contains("folder"), "{m}");
        assert!(s.held().join(&rec.id).exists());
    }

    /// `id` comes from a form. It names one entry of this hosting's own folder.
    #[test]
    fn form_cant_reach_arbitrary_path() {
        let s = Site::new();
        let rec = s.quarantine_small("a.php", b"mine");
        // Another hosting's file, one directory over.
        let other = s.dir.join("H2");
        fs::create_dir_all(&other).expect("mkdir");
        fs::write(other.join(&rec.id), b"theirs").expect("w");
        fs::write(
            other.join(format!("{}.json", rec.id)),
            serde_json::to_vec(&rec).expect("json"),
        )
        .expect("w");

        for id in [
            "",
            ".",
            "..",
            "../H2/00000000000000000000000000000000",
            "/etc/passwd",
            "0123",
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        ] {
            assert!(s.restore(id).is_err(), "{id}");
        }
        for hosting in ["", "..", "../H1", "a/b", "."] {
            let r = restore_file(&RestoreRequest {
                root: s.root.clone(),
                quarantine_dir: s.dir.clone(),
                hosting_id: hosting.to_string(),
                id: rec.id.clone(),
            });
            assert!(r.is_err(), "{hosting}");
        }
        assert!(other.join(&rec.id).exists());
        assert!(s.held().join(&rec.id).exists());
    }

    /// Metadata that names a path can't reach further than a scan's item could.
    #[test]
    fn a_damaged_record_cant_write_outside_the_root() {
        let s = Site::new();
        let mut rec = s.quarantine_small("a.php", b"mine");
        let outside = tempfile::tempdir().expect("outside");
        rec.rel = format!("../../{}/x.php", outside.path().display());
        fs::write(
            s.held().join(format!("{}.json", rec.id)),
            serde_json::to_vec(&rec).expect("json"),
        )
        .expect("w");
        assert!(s.restore(&rec.id).is_err());
        assert!(!outside.path().join("x.php").exists());
    }

    #[test]
    fn list_gives_metadata_newest_first_up_to_the_cap() {
        let s = Site::new();
        assert_eq!(
            list_quarantine(&s.dir, HOSTING, 50).expect("empty"),
            hyperion_types::QuarantineList::default()
        );
        for (i, now) in [100i64, 300, 200].into_iter().enumerate() {
            let rel = format!("f{i}.php");
            s.write(&rel, b"x");
            let mut req = s.request(&rel, &sha(b"x"));
            req.now = now;
            quarantine_with_limits(&req, &roomy()).expect("q");
        }
        // A copy with no record, and a half-written temp, aren't listed.
        fs::write(s.held().join("0".repeat(32)), b"x").expect("w");
        fs::write(s.held().join(".abc.tmp"), b"x").expect("w");

        let all = list_quarantine(&s.dir, HOSTING, 50).expect("list");
        assert_eq!(all.total, 3);
        let got: Vec<i64> = all.items.iter().map(|i| i.time).collect();
        assert_eq!(got, vec![300, 200, 100]);
        let cut = list_quarantine(&s.dir, HOSTING, 2).expect("list");
        assert_eq!(cut.total, 3);
        assert_eq!(cut.items.len(), 2);
    }

    #[test]
    fn purge_after_90_days() {
        let s = Site::new();
        s.write("old.php", b"old");
        let mut req = s.request("old.php", &sha(b"old"));
        req.now = 1_000;
        let old = quarantine_with_limits(&req, &roomy()).expect("q");
        s.write("new.php", b"new");
        let mut req = s.request("new.php", &sha(b"new"));
        req.now = 1_000 + 80 * 86_400;
        let new = quarantine_with_limits(&req, &roomy()).expect("q");

        let day_89 = 1_000 + 89 * 86_400;
        assert_eq!(purge_quarantine(&s.dir, day_89), 0);
        assert!(s.held().join(&old.id).exists());

        let day_90 = 1_000 + 90 * 86_400;
        assert_eq!(purge_quarantine(&s.dir, day_90), 1);
        assert!(!s.held().join(&old.id).exists());
        assert!(!s.held().join(format!("{}.json", old.id)).exists());
        assert!(s.held().join(&new.id).exists());
        assert!(s.held().join(format!("{}.json", new.id)).exists());

        // Nothing there yet is nothing to do.
        assert_eq!(purge_quarantine(&s.dir.join("nope"), day_90), 0);
    }

    /// A copy whose record was lost, or a temp from a crash, still ages out.
    #[test]
    fn purge_takes_leftovers_by_their_own_age() {
        let s = Site::new();
        fs::create_dir_all(s.held()).expect("mkdir");
        fs::write(s.held().join("0".repeat(32)), b"x").expect("w");
        fs::write(s.held().join(".abc.tmp"), b"x").expect("w");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        assert_eq!(purge_quarantine(&s.dir, now), 0);
        assert_eq!(purge_quarantine(&s.dir, now + 91 * 86_400), 1);
        assert!(s.held_names().is_empty(), "{:?}", s.held_names());
    }
}
