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

/// Tag marking a snapshot that carries a database dump as well as files.
///
/// Defined in `hyperion-types` and re-exported here: the PANEL is the other
/// reader, and the web binary does not link this crate. One definition, so a
/// snapshot cannot be tagged with a string the panel does not recognise.
pub use hyperion_types::SNAPSHOT_TAG_WITH_DB as TAG_WITH_DB;

/// Where a site's database dump is staged so it can go INTO the snapshot.
///
/// Deliberately not inside the site: `htdocs` is served by nginx, so a `.sql`
/// written there is downloadable by anyone who guesses the name for as long as
/// it exists, and the site's own unix user could read or replace it. This sits
/// beside the repositories instead, root-owned and 0700, and is removed as
/// soon as restic has read it.
/// Beside the repositories, NOT under [`REPO_BASE`]: a directory in there is
/// addressed by hosting id, and a staging dir sharing that namespace is one
/// unlucky id away from being mistaken for a repository.
pub const DB_STAGE_BASE: &str = "/var/lib/hyperion/snapshot-db-staging";

/// The directory a hosting's dumps are staged in.
pub fn db_stage_dir(hosting_id: &str) -> PathBuf {
    Path::new(DB_STAGE_BASE).join(hosting_id)
}

/// A dump path unique to ONE snapshot run.
///
/// Deliberately not a stable per-hosting name. Two snapshots of the same site
/// can overlap — the nightly sweep and the operator's button — and a shared
/// path means one run truncating the file the other is still reading, which
/// puts a half-written dump inside a snapshot tagged as carrying a whole one.
/// A restore finds the dump by looking in the directory rather than by
/// predicting its name.
pub fn db_stage_path(hosting_id: &str, token: &str) -> PathBuf {
    db_stage_dir(hosting_id).join(format!("{token}.sql"))
}

/// Create the staging directory 0700 and hand back the path for `hosting_id`.
///
/// The mode is a HARD error for the same reason `ensure_repo`'s is: what lands
/// here is a full database dump, and publishing every tenant's data at 0755
/// because one chmod quietly failed is not a degraded mode worth having.
pub async fn ensure_db_stage(hosting_id: &str, token: &str) -> Result<PathBuf, AdapterError> {
    for dir in [
        Path::new(DB_STAGE_BASE).to_path_buf(),
        db_stage_dir(hosting_id),
    ] {
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| AdapterError::Other(format!("create {}: {e}", dir.display())))?;
        set_mode(&dir, 0o700)
            .await
            .map_err(|e| AdapterError::Other(format!("chmod {}: {e}", dir.display())))?;
    }
    Ok(db_stage_path(hosting_id, token))
}

/// Remove a staged dump. Best-effort: the snapshot already holds the only copy
/// that matters, and a leftover file is caught by the next `ensure_db_stage`.
///
/// Called on EVERY exit path, including the failures — a dump left behind is a
/// plaintext copy of the customer's database sitting on disk indefinitely.
pub async fn clear_db_stage(path: &Path) {
    let _ = tokio::fs::remove_file(path).await;
}

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
    // The BASE directory is created by whichever repo is made first, and
    // `create_dir_all` uses the umask — on a default 022 that is 0755, so
    // every tenant on the node can list which sites have snapshots. Tighten
    // it too, not just the leaf.
    if let Some(base_dir) = repo.path.parent() {
        tokio::fs::create_dir_all(base_dir)
            .await
            .map_err(|e| AdapterError::Other(format!("create {}: {e}", base_dir.display())))?;
        set_mode(base_dir, 0o700)
            .await
            .map_err(|e| AdapterError::Other(format!("chmod {}: {e}", base_dir.display())))?;
    }
    tokio::fs::create_dir_all(&repo.path)
        .await
        .map_err(|e| AdapterError::Other(format!("create {}: {e}", repo.path.display())))?;
    // 0700: the repository holds a copy of the site, including wp-config.php
    // and therefore the database password. A HARD error, not best-effort —
    // publishing every tenant's database credentials at 0755 because one
    // chmod quietly failed is not a degraded mode worth having.
    set_mode(&repo.path, 0o700)
        .await
        .map_err(|e| AdapterError::Other(format!("chmod {}: {e}", repo.path.display())))?;

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

/// Take a snapshot WITHOUT applying retention afterwards.
///
/// A snapshot is normally followed by retention, but a restore takes a safety
/// snapshot first — and applying retention at that moment can delete the very
/// snapshot the operator is about to restore, because one more can push the
/// oldest past `keep_last`. The restore calls this instead and leaves
/// retention to the next ordinary snapshot or the daily sweep.
pub async fn backup_no_prune(
    repo: &Repo,
    paths: &[String],
    tags: &[&str],
) -> Result<String, AdapterError> {
    backup(repo, paths, tags).await
}

/// List snapshots, newest last.
pub async fn snapshots(repo: &Repo) -> Result<Vec<Snapshot>, AdapterError> {
    let mut args = repo.base_args();
    args.push("snapshots".into());
    args.push("--json".into());
    let out = cmd::run("/usr/bin/env", &as_env_args("restic", &args)).await?;
    Ok(parse_snapshots(&out))
}

/// Delete the named snapshots and reclaim the space they held.
///
/// `forget` alone only unlinks: the data stays in the pack files until a
/// `prune` rewrites them, so deleting without pruning frees nothing and the
/// operator watches the disk not move. They are one operation here for that
/// reason.
///
/// Explicit ids, never a policy. Which snapshots are old is decided by the
/// caller from the times restic reports (see
/// `hyperion_types::SnapshotRetention`), because restic's `--keep-within`
/// measures from the newest snapshot rather than from now. And "delete all"
/// is the full list of ids, not `--keep-last 0 --unsafe-allow-remove-all`:
/// that flag does not exist in the restic Debian 12 ships (0.14) and is
/// refused without a host or tag filter by the one Debian 13 ships (0.18).
///
/// restic exits 0 for an id it does not know ("Ignoring …"), so success here
/// does not prove anything was deleted. Callers list again to check.
pub async fn forget_ids(repo: &Repo, ids: &[String]) -> Result<(), AdapterError> {
    if ids.is_empty() {
        return Ok(());
    }
    // Hex only. These reach a command line, and `--keep-last` or `latest`
    // smuggled in as an "id" would change what the command does.
    for id in ids {
        if !is_snapshot_id(id) {
            return Err(AdapterError::Other(format!("not a snapshot id: {id:?}")));
        }
    }
    let mut args = repo.base_args();
    args.push("forget".into());
    args.push("--prune".into());
    args.extend(ids.iter().cloned());
    cmd::run("/usr/bin/env", &as_env_args("restic", &args)).await?;
    Ok(())
}

/// Is this a restic snapshot id (short or full)?
pub fn is_snapshot_id(id: &str) -> bool {
    (8..=64).contains(&id.len()) && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Remove STALE locks from the repository.
///
/// A restic process killed mid-run (the agent restarting after a settings
/// save does exactly that) leaves its lock behind, and every later operation
/// on the repository fails with "repository is already locked". Plain
/// `unlock` only removes locks whose process is gone; a lock held by a live
/// restic is left alone.
pub async fn unlock_stale(repo: &Repo) -> Result<(), AdapterError> {
    let mut args = repo.base_args();
    args.push("unlock".into());
    cmd::run("/usr/bin/env", &as_env_args("restic", &args)).await?;
    Ok(())
}

/// Did a restic call fail only because the repository was locked?
pub fn is_lock_error(e: &AdapterError) -> bool {
    let text = e.to_string();
    text.contains("repository is already locked") || text.contains("unable to create lock")
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
        // Hyperion's own database dump is in every snapshot and differs in
        // every one of them, so it would be reported as a modified file on
        // every diff — an answer to "what did the update change?" that is
        // always wrong and always the same. It is not part of the site.
        if rest.starts_with(DB_STAGE_BASE) {
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
    /// The dump is Hyperion's own bookkeeping, not something an operator
    /// changed. It must never appear in "what changed between these two".
    #[test]
    fn the_internal_dump_is_not_reported_as_a_site_change() {
        let out = "+    /home/u/example.cz/htdocs/wp-content/plugins/new.php\n\
                   M    /var/lib/hyperion/snapshot-db-staging/h1/abc.sql\n\
                   M    /home/u/example.cz/htdocs/wp-config.php\n";
        let d = super::parse_diff(out, 10);
        assert_eq!((d.added, d.modified, d.removed), (1, 1, 0));
        assert!(
            !d.sample.iter().any(|p| p.contains("snapshot-db-staging")),
            "{:?}",
            d.sample
        );
    }

    /// Two snapshots of one site can overlap. They must not write the same
    /// file — one truncating the other puts half a dump in a snapshot tagged
    /// as carrying a whole one.
    #[test]
    fn each_run_stages_its_dump_under_its_own_name() {
        let a = super::db_stage_path("h1", "token-a");
        let b = super::db_stage_path("h1", "token-b");
        assert_ne!(a, b);
        assert!(a.starts_with(super::DB_STAGE_BASE));
        // And per hosting, so one site's dump is never another's.
        assert_ne!(
            super::db_stage_path("h1", "t"),
            super::db_stage_path("h2", "t")
        );
    }

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

    #[tokio::test]
    async fn only_snapshot_ids_reach_the_command_line() {
        let repo = Repo::for_hosting("/nonexistent", "h");
        for bad in ["latest", "--keep-last", "abc", "0123456g", ""] {
            let err = forget_ids(&repo, &[bad.to_string()])
                .await
                .expect_err("must refuse");
            assert!(
                err.to_string().contains("not a snapshot id"),
                "{bad}: {err}"
            );
        }
        assert!(is_snapshot_id("3b37bfc4"));
        assert!(is_snapshot_id(
            "3b37bfc4a71e3843ecdcf488125e531dbcd669b9a7ef79510d767d9f776064d0"
        ));
        // Nothing to delete is not an error, and runs nothing.
        forget_ids(&repo, &[]).await.expect("empty is a no-op");
    }

    #[test]
    fn a_lock_error_is_recognised() {
        let e = AdapterError::Command {
            cmd: "restic forget".into(),
            code: 1,
            stderr_tail: "unable to create lock in backend: repository is already locked by PID 7"
                .into(),
        };
        assert!(is_lock_error(&e));
        assert!(!is_lock_error(&AdapterError::Other(
            "wrong password".into()
        )));
    }
}

/// Against a real restic binary. Run inside a Linux box that has restic:
/// `HYPERION_RESTIC_IT=1 cargo test -p hyperion-adapters restic::real -- --ignored`
#[cfg(test)]
mod real {
    use super::*;

    fn enabled() -> bool {
        std::env::var("HYPERION_RESTIC_IT").is_ok()
    }

    async fn repo_with_snapshots(n: usize) -> (tempfile::TempDir, Repo, std::path::PathBuf) {
        let base = tempfile::tempdir().expect("tmp");
        let site = base.path().join("site");
        std::fs::create_dir_all(&site).expect("site dir");
        let repo = ensure_repo(base.path().to_str().expect("utf8"), "h1")
            .await
            .expect("init");
        for i in 0..n {
            std::fs::write(site.join(format!("f{i}")), format!("content {i}")).expect("write");
            backup(&repo, &[site.display().to_string()], &["manual"])
                .await
                .expect("backup");
        }
        (base, repo, site)
    }

    #[tokio::test]
    #[ignore]
    async fn deleting_by_short_id_removes_exactly_those_snapshots() {
        if !enabled() {
            return;
        }
        let (_base, repo, _site) = repo_with_snapshots(3).await;
        let before = snapshots(&repo).await.expect("list");
        assert_eq!(before.len(), 3);
        forget_ids(&repo, &[before[0].id.clone()])
            .await
            .expect("forget");
        let after = snapshots(&repo).await.expect("list");
        assert_eq!(after.len(), 2);
        assert!(!after.iter().any(|s| s.id == before[0].id));
        // An id that is not there: restic says "Ignoring" and exits 0.
        forget_ids(&repo, &["deadbeef".to_string()])
            .await
            .expect("unknown id is not an error to restic");
        assert_eq!(snapshots(&repo).await.expect("list").len(), 2);
    }

    #[tokio::test]
    #[ignore]
    async fn deleting_every_listed_id_empties_the_repository_and_frees_space() {
        if !enabled() {
            return;
        }
        let (_base, repo, _site) = repo_with_snapshots(3).await;
        let full = repo_size(&repo).await;
        let ids: Vec<String> = snapshots(&repo)
            .await
            .expect("list")
            .into_iter()
            .map(|s| s.id)
            .collect();
        forget_ids(&repo, &ids).await.expect("forget all");
        assert!(snapshots(&repo).await.expect("list").is_empty());
        assert!(
            repo_size(&repo).await < full,
            "prune must reclaim the data, not only unlink it"
        );
        // Empty repository still works for the next snapshot.
        unlock_stale(&repo).await.expect("unlock on a clean repo");
    }

    #[tokio::test]
    #[ignore]
    async fn listed_times_feed_the_retention_rule() {
        if !enabled() {
            return;
        }
        let (_base, repo, _site) = repo_with_snapshots(2).await;
        let listed: Vec<hyperion_types::SnapshotSummary> = snapshots(&repo)
            .await
            .expect("list")
            .into_iter()
            .map(|s| hyperion_types::SnapshotSummary {
                id: s.id,
                time: s.time,
                tags: s.tags,
            })
            .collect();
        assert!(listed.iter().all(|s| s.taken_at().is_some()), "{listed:?}");
        let now = listed[1].taken_at().expect("time");
        let rule = hyperion_types::SnapshotRetention {
            keep_days: 1,
            keep_last: 0,
        };
        assert!(
            rule.expired(&listed, now).is_empty(),
            "nothing is a day old"
        );
        assert_eq!(rule.expired(&listed, now + 2 * 86_400).len(), 2);
    }
}
