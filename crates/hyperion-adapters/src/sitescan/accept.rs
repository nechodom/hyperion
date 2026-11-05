//! What a writer of ours (a git deploy, a restore) put in the tree, by the hash of
//! each file.
//!
//! The writer's own list is what the scan may accept, never a time window: a
//! restore chmods and chowns the whole tree, so every change time in it is new,
//! and a window would bless whatever sat there waiting for review. A file is
//! accepted when its content hashes to what was recorded for its path right after
//! the writer finished, and when the rules find nothing in it.
//!
//! The hashing runs in the capped worker under its own unit, and the record sits
//! in a root-only directory the agent reads when a scan starts. Names the agent
//! passes in come from tools that ran as the site user, so they are only paths to
//! open through [`TenantRoot`], like any other name in a tenant's tree.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::ops::ControlFlow;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::scan::{is_layer_b_code, WriterAccepted, WriterKind};
use super::walk::{TenantRoot, WalkEvent, WalkOpts};
use crate::AdapterError;

/// A record this old is not about anything still pending.
pub const ACCEPT_TTL_SECS: i64 = 7 * 24 * 3600;
/// Directory entries a hash of the whole tree looks at.
const WALK_MAX_ENTRIES: u64 = 300_000;
/// Files listed in one record. Past it the rest isn't listed, so it is reviewed.
const LISTED_MAX: usize = 100_000;
/// A bigger file isn't hashed, and so isn't accepted.
const FILE_READ_MAX: u64 = 64 * 1024 * 1024;
/// Bytes one job reads, like the scan's.
const READ_BUDGET: u64 = 8 * 1024 * 1024 * 1024;
const PAUSE_EVERY_FILES: u64 = 256;
/// A record bigger than this isn't read.
const RECORD_MAX_BYTES: u64 = 48 * 1024 * 1024;

/// Which files a writer's hash covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriterPaths {
    /// Every code file in the tree: the writer can't say what it changed.
    All,
    /// These, relative to the docroot.
    List(Vec<String>),
}

/// What the worker writes, one per hosting. Hashes are hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedRecord {
    pub kind: WriterKind,
    pub written_at: i64,
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hashed {
    pub listed: u64,
    /// A cap or a stop left files unlisted.
    pub partial: bool,
}

fn unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

struct Hasher {
    buf: Vec<u8>,
    budget: u64,
    partial: bool,
}

impl Hasher {
    /// The hash of `rel`, or `None` when it isn't a code file or can't be read.
    fn hash(&mut self, root: &TenantRoot, rel: &str) -> Option<[u8; 32]> {
        if !is_layer_b_code(rel) {
            return None;
        }
        // One open, through the descriptor, so the size and the bytes are the
        // same file whatever the tenant does meanwhile.
        let mut f = root.open_file(rel).ok()?;
        let size = f.metadata().ok()?.len();
        if size > FILE_READ_MAX {
            return None;
        }
        if size > self.budget {
            self.partial = true;
            return None;
        }
        let mut sha = Sha256::new();
        let mut read = 0u64;
        loop {
            match f.read(&mut self.buf) {
                Ok(0) => break,
                Ok(n) => {
                    read += n as u64;
                    if read > FILE_READ_MAX {
                        return None;
                    }
                    sha.update(&self.buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        self.budget = self.budget.saturating_sub(read);
        Some(sha.finalize().into())
    }
}

/// Hash what a writer left and store it at `out`, replacing the record there, or
/// adding to it when it is a fresh one from the same kind of writer (two pushes
/// before a scan). Atomic and root-only.
pub fn writer_hash(
    root: &Path,
    kind: WriterKind,
    paths: &WriterPaths,
    out: &Path,
    pause: &dyn Fn() -> bool,
) -> Result<Hashed, AdapterError> {
    let tenant = TenantRoot::open(root)?;
    let mut h = Hasher {
        buf: vec![0; 64 * 1024],
        budget: READ_BUDGET,
        partial: false,
    };
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    match paths {
        WriterPaths::List(names) => {
            for (i, rel) in names.iter().enumerate() {
                if i as u64 % PAUSE_EVERY_FILES == 0 && pause() {
                    h.partial = true;
                    break;
                }
                if files.len() >= LISTED_MAX {
                    h.partial = true;
                    break;
                }
                if let Some(sha) = h.hash(&tenant, rel) {
                    files.insert(rel.clone(), hex::encode(sha));
                }
            }
        }
        WriterPaths::All => {
            let opts = WalkOpts {
                max_entries: WALK_MAX_ENTRIES,
                prune: Vec::new(),
            };
            let mut seen = 0u64;
            let stats = tenant.walk_until(&opts, |ev| {
                let WalkEvent::File(m) = ev else {
                    return ControlFlow::Continue(());
                };
                seen += 1;
                if seen % PAUSE_EVERY_FILES == 0 && pause() {
                    h.partial = true;
                    return ControlFlow::Break(());
                }
                if files.len() >= LISTED_MAX {
                    h.partial = true;
                    return ControlFlow::Break(());
                }
                if let Some(sha) = h.hash(&tenant, &m.rel) {
                    files.insert(m.rel.clone(), hex::encode(sha));
                }
                ControlFlow::Continue(())
            })?;
            h.partial |= stats.capped;
        }
    }

    let now = unix_secs();
    let mut merged = match read_record(out) {
        Some(old) if old.kind == kind && now - old.written_at < ACCEPT_TTL_SECS => old.files,
        _ => BTreeMap::new(),
    };
    merged.extend(files);
    if merged.len() > LISTED_MAX {
        if let Some(k) = merged.keys().nth(LISTED_MAX).cloned() {
            merged.split_off(&k);
        }
        h.partial = true;
    }
    let listed = merged.len() as u64;
    write_record(
        out,
        &AcceptedRecord {
            kind,
            written_at: now,
            files: merged,
        },
    )?;
    Ok(Hashed {
        listed,
        partial: h.partial,
    })
}

fn read_record(path: &Path) -> Option<AcceptedRecord> {
    let f = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    f.take(RECORD_MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > RECORD_MAX_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn write_record(out: &Path, rec: &AcceptedRecord) -> Result<(), AdapterError> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = out
        .parent()
        .ok_or_else(|| AdapterError::Other("no directory for the record".into()))?;
    fs::create_dir_all(dir)?;
    let name = out.file_name().map(|n| n.to_string_lossy().into_owned());
    // Unique per write, so two writers never share a temp file.
    let tag = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = dir.join(format!(".{}.tmp{tag}", name.unwrap_or_default()));
    let _ = fs::remove_file(&tmp);
    let body = serde_json::to_vec(rec).map_err(|e| AdapterError::Other(e.to_string()))?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&body)?;
    f.sync_all()?;
    fs::rename(&tmp, out).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    Ok(())
}

/// Which version of a record was read, so only that one is deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
}

fn stamp_of(path: &Path) -> Option<Stamp> {
    let md = fs::metadata(path).ok()?;
    Some(Stamp {
        len: md.len(),
        modified: md.modified().ok(),
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Loaded {
    /// No record, or one that can't be read: nothing is accepted.
    Nothing,
    Found(WriterAccepted, Stamp),
}

/// The record at `path` as a scan takes it. One older than seven days is removed
/// and counts as none; so does one that can't be read, which is left for a
/// writer to replace.
pub fn load_accepted(path: &Path, now: i64) -> Loaded {
    let Some(stamp) = stamp_of(path) else {
        return Loaded::Nothing;
    };
    let Some(rec) = read_record(path) else {
        return Loaded::Nothing;
    };
    if now - rec.written_at >= ACCEPT_TTL_SECS {
        let _ = fs::remove_file(path);
        return Loaded::Nothing;
    }
    let files = rec
        .files
        .into_iter()
        .filter_map(|(rel, h)| {
            let bytes: [u8; 32] = hex::decode(h).ok()?.try_into().ok()?;
            Some((rel, bytes))
        })
        .collect();
    Loaded::Found(
        WriterAccepted {
            kind: rec.kind,
            files,
        },
        stamp,
    )
}

/// A complete scan has stored its result: the record it read is spent. A newer
/// one, written meanwhile, stays.
pub fn spend_accepted(path: &Path, read: &Stamp) {
    if stamp_of(path).as_ref() == Some(read) {
        let _ = fs::remove_file(path);
    }
}

/// Records in `dir` last written over seven days ago, for a site nothing scans any
/// more. Returns how many went.
pub fn purge_expired(dir: &Path, now: i64) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for ent in entries.flatten() {
        let old = ent
            .metadata()
            .ok()
            .filter(|m| m.is_file())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .is_some_and(|d| {
                now - i64::try_from(d.as_secs()).unwrap_or(i64::MAX) >= ACCEPT_TTL_SECS
            });
        if old && fs::remove_file(ent.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}
