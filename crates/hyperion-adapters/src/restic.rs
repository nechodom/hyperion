//! Snapshot backups: content-addressed, deduplicated, and able to say what
//! changed between two of them.
//!
//! # Why this exists beside the archive backups
//!
//! Hyperion's original backup is a `tar.gz` of the site plus a database
//! dump. It is simple, it restores anywhere, and it is completely opaque:
//! thirty daily backups of a 4 GB site are 120 GB of almost identical bytes,
//! and nothing can answer "what did last night's plugin update actually
//! change?" — the question an operator asks every time a site breaks after
//! an update.
//!
//! A snapshot repository answers both. Restic chunks file content, stores
//! each chunk once, and keeps every snapshot as a reference to chunks it
//! shares with its neighbours; `restic diff` then prints the added, removed
//! and modified paths between any two. Thirty days of a site that barely
//! changes costs a little more than one copy of it.
//!
//! # What this module deliberately does NOT do
//!
//! It does not replace the archive path. A `tar.gz` needs nothing but tar to
//! restore and can be handed to a customer leaving for another host; a
//! restic repository needs restic and its password. Snapshots are an engine
//! a site can be switched to, not a migration everybody is dragged through.
//!
//! # The password
//!
//! One per repository, generated here, written 0600, never on a command
//! line. `/proc/<pid>/cmdline` is world-readable and every tenant on the box
//! is a local user, so `--password-file` is the only acceptable way to hand
//! it to restic — `RESTIC_PASSWORD` in the environment is better than argv
//! but still visible to root-owned tooling that dumps environs.
//!
//! Losing the password means losing every snapshot in that repository. It
//! lives beside the repo rather than in the database for exactly that
//! reason: a restore has to be possible from the filesystem alone, by
//! somebody who has lost the panel.

use crate::cmd;
use crate::AdapterError;
use std::path::{Path, PathBuf};

/// Where a node keeps its snapshot repositories, one directory per hosting.
pub const REPO_BASE: &str = "/var/lib/hyperion/snapshots";

/// One site's repository and the file holding its password.
#[derive(Debug, Clone)]
pub struct Repo {
    pub path: PathBuf,
    pub password_file: PathBuf,
}

impl Repo {
    /// Paths for one hosting under `base` (normally [`REPO_BASE`]).
    pub fn for_hosting(base: &str, hosting_id: &str) -> Repo {
        let path = Path::new(base).join(hosting_id);
        let password_file = path.join(".password");
        Repo {
            path,
            password_file,
        }
    }

    /// The arguments every restic invocation needs. Separate so no call site
    /// can forget the password file and fall back to a prompt that never
    /// comes on a daemon.
    fn base_args(&self) -> Vec<String> {
        vec![
            "-r".to_string(),
            self.path.to_string_lossy().to_string(),
            "--password-file".to_string(),
            self.password_file.to_string_lossy().to_string(),
            // A backup daemon has no terminal; without this restic emits
            // progress escape codes into the log.
            "--no-cache".to_string(),
        ]
    }
}

/// Is restic installed?
///
/// Checked rather than assumed: the snapshot engine is opt-in, and a node
/// that has never used it will not have the binary. Every caller turns a
/// `false` here into "this site cannot use the snapshot engine", not into a
/// failed backup.
pub async fn available() -> bool {
    cmd::run("/usr/bin/env", &["restic", "version"])
        .await
        .is_ok()
}

/// Create the repository if it is not there yet, generating a password the
/// first time.
///
/// Idempotent: an existing repository is left alone, and an existing
/// password file is never overwritten — rewriting it would orphan every
/// snapshot already in the repository.
pub async fn ensure_repo(base: &str, hosting_id: &str) -> Result<Repo, AdapterError> {
    let repo = Repo::for_hosting(base, hosting_id);
    tokio::fs::create_dir_all(&repo.path)
        .await
        .map_err(|e| AdapterError::Other(format!("create {}: {e}", repo.path.display())))?;
    // 0700: the repository holds a copy of the site, including wp-config.php
    // and therefore the database password.
    let _ = set_mode(&repo.path, 0o700).await;

    if !tokio::fs::try_exists(&repo.password_file)
        .await
        .unwrap_or(false)
    {
        let secret = generate_password()?;
        write_secret(&repo.password_file, &secret).await?;
    }
    // `cat config` is restic's own "is this initialised?" — cheaper than
    // `snapshots`, and it does not lock the repository.
    let mut args = repo.base_args();
    args.push("cat".into());
    args.push("config".into());
    if cmd::run("/usr/bin/env", &as_env_args("restic", &args))
        .await
        .is_ok()
    {
        return Ok(repo);
    }
    let mut init = repo.base_args();
    init.push("init".into());
    cmd::run("/usr/bin/env", &as_env_args("restic", &init)).await?;
    Ok(repo)
}

/// One snapshot as the panel lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    /// RFC3339 as restic prints it.
    pub time: String,
    pub tags: Vec<String>,
}

/// Take a snapshot of `paths`, tagged so a later `forget` can keep the ones
/// that matter.
///
/// Returns the new snapshot's short id. `--tag` values are ours, never a
/// customer's input.
pub async fn backup(repo: &Repo, paths: &[String], tags: &[&str]) -> Result<String, AdapterError> {
    let mut args = repo.base_args();
    args.push("backup".into());
    args.push("--json".into());
    for t in tags {
        args.push("--tag".into());
        args.push((*t).to_string());
    }
    for p in paths {
        args.push(p.clone());
    }
    let out = cmd::run("/usr/bin/env", &as_env_args("restic", &args)).await?;
    Ok(snapshot_id_from_json(&out).unwrap_or_default())
}

/// List snapshots, newest last.
pub async fn snapshots(repo: &Repo) -> Result<Vec<Snapshot>, AdapterError> {
    let mut args = repo.base_args();
    args.push("snapshots".into());
    args.push("--json".into());
    let out = cmd::run("/usr/bin/env", &as_env_args("restic", &args)).await?;
    Ok(parse_snapshots(&out))
}

/// Apply retention, then reclaim the space.
///
/// `keep_days` and `keep_last` map straight onto the operator's existing
/// `[backup_retention]` settings, so a site switching engines keeps the
/// retention it already had rather than silently getting restic's defaults.
/// Both are floors, not ceilings: restic keeps a snapshot matching EITHER
/// rule, which is what stops a quiet fortnight deleting the only copy.
pub async fn forget_prune(repo: &Repo, keep_days: i64, keep_last: i64) -> Result<(), AdapterError> {
    let mut args = repo.base_args();
    args.push("forget".into());
    args.push("--prune".into());
    if keep_days > 0 {
        args.push("--keep-within".into());
        args.push(format!("{keep_days}d"));
    }
    if keep_last > 0 {
        args.push("--keep-last".into());
        args.push(keep_last.to_string());
    }
    // Neither rule set would delete everything. Refuse instead: an empty
    // retention policy is a misconfiguration, and "delete every backup" is
    // not a reasonable reading of it.
    if keep_days <= 0 && keep_last <= 0 {
        return Err(AdapterError::Other(
            "refusing to prune with no retention rule — that would delete every snapshot".into(),
        ));
    }
    cmd::run("/usr/bin/env", &as_env_args("restic", &args)).await?;
    Ok(())
}

/// What changed between two snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffStat {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    /// A few paths, for the operator to read. Not the whole list: a core
    /// update touches thousands of files and nobody reads that.
    pub sample: Vec<String>,
}

/// `restic diff a b`, summarised.
pub async fn diff(repo: &Repo, from: &str, to: &str) -> Result<DiffStat, AdapterError> {
    let mut args = repo.base_args();
    args.push("diff".into());
    args.push(from.to_string());
    args.push(to.to_string());
    let out = cmd::run("/usr/bin/env", &as_env_args("restic", &args)).await?;
    Ok(parse_diff(&out, 12))
}

/// Restore one snapshot into `target`.
///
/// `target` is a directory restic writes the snapshot's absolute paths
/// under, so restoring `/home/u/site/htdocs` into `/tmp/x` lands in
/// `/tmp/x/home/u/site/htdocs`. Callers move it into place; that is
/// deliberate, because restoring straight over a live site is not something
/// this function should be able to do by itself.
pub async fn restore(repo: &Repo, snapshot: &str, target: &str) -> Result<(), AdapterError> {
    let mut args = repo.base_args();
    args.push("restore".into());
    args.push(snapshot.to_string());
    args.push("--target".into());
    args.push(target.to_string());
    cmd::run("/usr/bin/env", &as_env_args("restic", &args)).await?;
    Ok(())
}

/// Total size of the repository on disk, in bytes.
pub async fn repo_size(repo: &Repo) -> u64 {
    fn walk(p: &Path) -> u64 {
        let Ok(rd) = std::fs::read_dir(p) else {
            return 0;
        };
        rd.flatten()
            .map(|e| match e.file_type() {
                Ok(t) if t.is_dir() => walk(&e.path()),
                Ok(_) => e.metadata().map(|m| m.len()).unwrap_or(0),
                Err(_) => 0,
            })
            .sum()
    }
    let path = repo.path.clone();
    tokio::task::spawn_blocking(move || walk(&path))
        .await
        .unwrap_or(0)
}

// ── helpers ────────────────────────────────────────────────────────────

/// `env restic <args…>` — `cmd::run` takes `&[&str]`, and every restic call
/// here builds its arguments as owned `String`s.
fn as_env_args<'a>(program: &'a str, args: &'a [String]) -> Vec<&'a str> {
    let mut v: Vec<&str> = Vec::with_capacity(args.len() + 1);
    v.push(program);
    v.extend(args.iter().map(|s| s.as_str()));
    v
}

/// 32 bytes of randomness, hex. Read from the OS, never derived from
/// anything guessable: this is the only thing between a stolen backup disk
/// and every site on it.
///
/// A failure here is an ERROR, never a fallback. There is no weaker source
/// worth reaching for — a repository password that came from the clock is
/// not a password — so the repository simply is not created.
fn generate_password() -> Result<String, AdapterError> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    // `/dev/urandom` directly rather than a crate: this is the only
    // randomness this crate needs.
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| AdapterError::Other(format!("open /dev/urandom: {e}")))?;
    f.read_exact(&mut buf)
        .map_err(|e| AdapterError::Other(format!("read /dev/urandom: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

async fn write_secret(path: &Path, secret: &str) -> Result<(), AdapterError> {
    use std::os::unix::fs::OpenOptionsExt;
    // Created 0600 from the start: a write-then-chmod leaves the key
    // world-readable for as long as the umask says, and every tenant on this
    // box is a local user.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| AdapterError::Other(format!("create {}: {e}", path.display())))?;
    use std::io::Write;
    f.write_all(secret.as_bytes())
        .map_err(|e| AdapterError::Other(format!("write {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| AdapterError::Other(format!("sync {}: {e}", path.display())))?;
    Ok(())
}

async fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await
}

/// Pull `"snapshot_id":"…"` out of `restic backup --json`'s final summary
/// line.
///
/// The output is newline-delimited JSON with progress objects first, so the
/// LAST line carrying the key is the summary. Parsed by hand because this
/// crate has no JSON dependency and one field does not justify adding one.
pub fn snapshot_id_from_json(out: &str) -> Option<String> {
    out.lines()
        .rev()
        .find_map(|l| field(l, "snapshot_id"))
        .map(|s| s.chars().take(8).collect())
}

/// Extract a string field's value from one line of JSON. Handles neither
/// escapes nor nesting — every value it is used on is a hex id or an
/// RFC3339 timestamp.
fn field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Parse `restic snapshots --json`.
pub fn parse_snapshots(out: &str) -> Vec<Snapshot> {
    // One array on one line, objects separated by `},{`. Splitting on that
    // is enough for the three flat fields we want and keeps this crate free
    // of a JSON dependency.
    let trimmed = out.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed
        .split("},{")
        .filter_map(|chunk| {
            let id = field(chunk, "short_id").or_else(|| field(chunk, "id"))?;
            Some(Snapshot {
                id: id.chars().take(8).collect(),
                time: field(chunk, "time").unwrap_or_default(),
                tags: tags_of(chunk),
            })
        })
        .collect()
}

fn tags_of(chunk: &str) -> Vec<String> {
    let Some(start) = chunk.find("\"tags\":[") else {
        return Vec::new();
    };
    let rest = &chunk[start + "\"tags\":[".len()..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse `restic diff`'s human output.
///
/// Lines are `+    /path`, `-    /path`, `M    /path`. The trailing summary
/// block is ignored: counting the marked lines is exact and does not depend
/// on restic's wording, which has changed between releases.
pub fn parse_diff(out: &str, sample_limit: usize) -> DiffStat {
    let mut d = DiffStat::default();
    for line in out.lines() {
        let mut chars = line.chars();
        let marker = chars.next();
        // The path starts after whitespace; a summary line like
        // "Files: 3 new, 1 removed" has no leading marker+space shape.
        let rest = line.get(1..).unwrap_or("").trim_start();
        if rest.is_empty() || !rest.starts_with('/') {
            continue;
        }
        match marker {
            Some('+') => d.added += 1,
            Some('-') => d.removed += 1,
            Some('M') => d.modified += 1,
            _ => continue,
        }
        if d.sample.len() < sample_limit {
            d.sample.push(line.trim().to_string());
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_paths_are_per_hosting_and_the_key_sits_beside_them() {
        let r = Repo::for_hosting("/var/lib/hyperion/snapshots", "01H8");
        assert_eq!(r.path.to_string_lossy(), "/var/lib/hyperion/snapshots/01H8");
        // Beside the repository, not in the database: a restore has to be
        // possible from the filesystem alone, by somebody who has lost the
        // panel.
        assert!(r.password_file.starts_with(&r.path));
    }

    #[test]
    fn the_password_never_reaches_a_command_line() {
        let r = Repo::for_hosting("/base", "h");
        let args = r.base_args();
        assert!(args.contains(&"--password-file".to_string()));
        // /proc/<pid>/cmdline is world-readable and every tenant is a local
        // user. A password among these would be readable by all of them.
        assert!(
            !args
                .iter()
                .any(|a| a.len() == 64 && a.chars().all(|c| c.is_ascii_hexdigit())),
            "a secret-looking value is on the argv: {args:?}"
        );
    }

    #[test]
    fn generated_passwords_are_long_and_not_repeated() {
        let a = generate_password().expect("urandom");
        let b = generate_password().expect("urandom");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn a_snapshot_id_comes_off_the_summary_line() {
        let out = "{\"message_type\":\"status\",\"percent_done\":0.5}\n\
                   {\"message_type\":\"summary\",\"snapshot_id\":\"9f86d081884c7d65\"}\n";
        assert_eq!(snapshot_id_from_json(out).as_deref(), Some("9f86d081"));
    }

    #[test]
    fn no_summary_line_yields_nothing_rather_than_a_wrong_id() {
        assert_eq!(snapshot_id_from_json("{\"percent_done\":1}"), None);
        assert_eq!(snapshot_id_from_json(""), None);
    }

    #[test]
    fn snapshots_parse_with_ids_times_and_tags() {
        let out = r#"[{"time":"2026-09-01T03:00:00Z","tags":["daily","pre-update"],"short_id":"aabbccdd","id":"aabbccddeeff"},{"time":"2026-09-02T03:00:00Z","tags":[],"short_id":"11223344","id":"1122334455"}]"#;
        let s = parse_snapshots(out);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].id, "aabbccdd");
        assert_eq!(s[0].tags, vec!["daily", "pre-update"]);
        assert_eq!(s[1].time, "2026-09-02T03:00:00Z");
        assert!(s[1].tags.is_empty());
    }

    #[test]
    fn diff_counts_each_marker_and_keeps_a_short_sample() {
        let out = "+    /home/u/site/htdocs/wp-content/plugins/new/file.php\n\
                   -    /home/u/site/htdocs/old.php\n\
                   M    /home/u/site/htdocs/wp-config.php\n\
                   M    /home/u/site/htdocs/index.php\n\
                   Files:  1 new,  1 removed,  2 changed\n";
        let d = parse_diff(out, 2);
        assert_eq!((d.added, d.removed, d.modified), (1, 1, 2));
        // The summary line has no leading marker+path and must not be
        // counted as a change.
        assert_eq!(d.sample.len(), 2);
    }

    #[test]
    fn diff_ignores_lines_that_are_not_paths() {
        let d = parse_diff("comparing snapshot a to b\n\nFiles: 0 new\n", 5);
        assert_eq!(d, DiffStat::default());
    }

    /// The one prune that must never run.
    #[tokio::test]
    async fn pruning_with_no_retention_rule_is_refused() {
        let repo = Repo::for_hosting("/nonexistent", "h");
        let err = forget_prune(&repo, 0, 0).await.expect_err("must refuse");
        assert!(err.to_string().contains("delete every snapshot"), "{err}");
    }
}
