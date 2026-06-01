# Sub-project 5 — Backups — Design Spec

| Field | Value |
|---|---|
| Sub-project | 5 of N — Backups |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation, Controller (1.5), Suspend (3 — for clean pre-backup state optional) |
| Enables | Sub-project 4 (final-backup before auto-delete), 5.5 (migration) |

## 1. Summary

Per-hosting **backups** combining filesystem snapshot (htdocs + logs +
configs) and **database dump** (mysqldump / pg_dump). Stored locally and
optionally pushed to one or more remote **targets**: SFTP, S3-compatible,
FTP/FTPS (via rclone), or another local mount.

Backups use **restic** for filesystem snapshots (content-addressed,
encrypted, deduplicated, incremental). DB dumps are produced by the
respective tool, written to a temp dir, and ingested into the restic
repository as just-another-file (so dedup catches repeated dumps).

**Restore** is supported from any snapshot in any target and from an
**operator-uploaded archive** (single-file `.tar.zst` containing both
htdocs and a `db.sql` file). Restore reuses provisioning primitives —
re-creates user/pool/DB if missing, then writes content + imports SQL.

## 2. Goals

1. `lm hosting backup now <id>` produces a snapshot in the default local
   repository in under N seconds (where N scales with site size; for
   1 GiB sites ≤ 30 s on common SSD).
2. `lm backup target add` configures a remote target (SFTP, S3, FTP, or
   local-mount). `lm hosting backup policy <id> --target <name>
   --schedule daily-04:00 --retention 7d-4w-12m` applies a policy.
3. The scheduler (sub-project 4) drives policy-based backups; per-hosting
   override schedules are allowed.
4. `lm hosting restore <id> --snapshot <id> [--target <name>]`
   restores to a fresh state (overwrites). `--dry-run` prints diff.
5. `lm hosting restore-from-upload <hostings-id-or-new-domain>
   --archive /path/to/upload.tar.zst` restores from an operator-uploaded
   archive; can resurrect a deleted site or seed a new one.
6. Backup integrity is verifiable: `lm backup verify <repo> --quick`
   runs `restic check`.
7. All backup repos are **encrypted**; passwords live in
   `/etc/hyperion/secrets/repo-passwords/`.

## 3. Non-Goals

- Application-aware backups (WordPress maintenance mode, etc.) — sub-
  project 7 may layer this on top.
- Cross-region replication beyond the target list operator configures.
- Long-term archival to cold storage (Glacier) — operator can use S3
  target whose backend has lifecycle rules; we do not orchestrate.
- Server-side encryption beyond what restic provides.
- Real-time / continuous backup. Schedule-based only.

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **restic** as the backup engine | Mature, audited, content-addressed, dedup, encrypted, multi-backend, single binary |
| D2 | Restic binary is a system dependency (`apt install restic`) declared in `hyperion-agent.deb` | Avoid re-implementing |
| D3 | One restic repo **per target**, multi-hosting; restic dedup helps if many sites share PHP/WP files | Lower mgmt overhead than per-hosting repos |
| D4 | DB dumps run before fs snapshot so `htdocs/...` is consistent enough; site put into MAINT mode is sub-project 7 | Defensive sequencing |
| D5 | DB dump location: per-snapshot temp dir under `/var/lib/hyperion/backup-tmp/`, ingested by restic, removed | Streamed dedup |
| D6 | Restic password = random 64-byte high-entropy string per repo | Strong, opaque |
| D7 | FTP/FTPS support via `rclone` mounted as filesystem with restic `local:` backend; SFTP / S3 / local use restic native | rclone bridges legacy FTP |
| D8 | Retention policy notation: `N-d`, `M-w`, `K-m`, `Y-y` (e.g. `7d-4w-12m-3y`) | Industry idiom |
| D9 | Per-target rate limit (bytes/sec) configurable | Avoid saturating links |
| D10 | Upload-restore archive format: `<hosting>.tar.zst` containing `htdocs/`, `db.sql`, `manifest.json` | Operator-friendly; we provide a `lm backup pack` helper |
| D11 | Concurrent backups on one agent capped at 2 by default | Avoid IO storm |

## 5. State Schema Additions

### 5.1 Agent-side

```sql
CREATE TABLE backup_targets (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,         -- 'local', 'offsite-s3', etc.
    backend         TEXT NOT NULL CHECK (backend IN
                       ('local','sftp','s3','ftp','ftps','rclone')),
    config_json     TEXT NOT NULL,                -- backend-specific config
    repo_password_id TEXT NOT NULL UNIQUE,        -- ref to secret file
    created_at      INTEGER NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE backup_policies (
    hosting_id      TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    target_id       INTEGER NOT NULL REFERENCES backup_targets(id),
    schedule        TEXT NOT NULL,                -- e.g. 'daily-04:00', 'hourly:30'
    retention       TEXT NOT NULL,                -- e.g. '7d-4w-12m'
    last_run_at     INTEGER,
    last_snapshot_id TEXT,
    next_run_at     INTEGER,
    PRIMARY KEY (hosting_id, target_id)
);

CREATE TABLE backup_runs (
    id              INTEGER PRIMARY KEY,
    hosting_id      TEXT NOT NULL REFERENCES hostings(id),
    target_id       INTEGER NOT NULL REFERENCES backup_targets(id),
    started_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    state           TEXT NOT NULL CHECK (state IN ('running','ok','failed','pruned')),
    snapshot_id     TEXT,
    bytes_added     INTEGER,
    bytes_total     INTEGER,
    error_message   TEXT
);
CREATE INDEX backup_runs_hosting_state ON backup_runs(hosting_id, state);
```

### 5.2 Controller-side mirror

The controller mirrors `backup_targets` and `backup_policies` at the
`controller_hostings` level so operators can configure policies across
many agents from one place. Each policy stored on controller has an
authoritative copy; periodic reconcile pushes them to agents.

```sql
CREATE TABLE controller_backup_targets (
    -- same shape as agent's table; deployed to each agent
    -- ...
);
```

## 6. RPC Additions

### 6.1 AgentApi

```rust
async fn backup_target_add(&self, t: BackupTargetSpec) -> Result<BackupTarget, RpcError>;
async fn backup_target_list(&self) -> Result<Vec<BackupTarget>, RpcError>;
async fn backup_target_remove(&self, name: String) -> Result<(), RpcError>;

async fn backup_policy_set(&self, sel: HostingSelector, p: BackupPolicy)
    -> Result<(), RpcError>;
async fn backup_policy_clear(&self, sel: HostingSelector, target: String)
    -> Result<(), RpcError>;

async fn backup_now(&self, sel: HostingSelector, target: String)
    -> Result<BackupRunSummary, RpcError>;
async fn backup_list_snapshots(&self, sel: HostingSelector, target: String)
    -> Result<Vec<SnapshotInfo>, RpcError>;
async fn backup_verify(&self, target: String, quick: bool)
    -> Result<VerifyReport, RpcError>;

async fn restore_from_snapshot(&self, sel: HostingSelector,
                               target: String, snapshot_id: String,
                               opts: RestoreOpts)
    -> Result<(), RpcError>;
async fn restore_from_upload(&self, dest: RestoreDest, archive_handle: UploadHandle)
    -> Result<(), RpcError>;
```

The upload itself uses a side-channel (HTTP multipart to the controller
which streams to the agent, or direct mTLS RPC chunk-stream — preferred,
defined as a new framed stream type in `hyperion-rpc`).

## 7. Backup Composition

A snapshot of hosting `H` includes:

```
restic backup --tag hosting=<H.id> --tag domain=<H.domain> \
              --files-from <list>
where <list> contains:
  /home/<u>/<H.domain>/htdocs/
  /home/<u>/<H.domain>/logs/
  /var/lib/hyperion/backup-tmp/<run-id>/db.sql   (dump)
  /var/lib/hyperion/backup-tmp/<run-id>/manifest.json
```

`manifest.json`:
```json
{
  "hosting_id": "...",
  "domain": "example.cz",
  "system_user": "example_cz",
  "php_version": "8.3",
  "database": {"engine": "mariadb", "name": "...", "user": "..."},
  "limits": { /* hosting_limits row */ },
  "schema_version": 1,
  "backup_started_at": 1717142400,
  "files_total": 1843,
  "bytes_total": 1284213
}
```

This manifest is what `restore_from_upload` reads first.

## 8. Backup Flow

### 8.1 `backup_now`

```text
01 acquire per-hosting backup lock (so two concurrent runs collapse)
02 INSERT backup_runs (state='running', started_at=now)
03 mkdir /var/lib/hyperion/backup-tmp/<run-id>/
04 if hosting has DB:
     mariadb: mysqldump --single-transaction --routines --triggers \
                        --events --add-drop-database -B <db> > db.sql
     postgres: pg_dump -Fc <db> > db.dump
05 write manifest.json with hosting metadata
06 spawn restic backup with --files-from list
07 capture restic's JSON output (--json) → snapshot_id, bytes_added, bytes_total
08 UPDATE backup_runs (state='ok', finished_at, snapshot_id, bytes_*)
09 rm -rf temp dir
10 audit append
11 if policy has retention: restic forget --keep-daily --keep-weekly --keep-monthly
                                          --prune
12 update backup_policies.last_run_at / last_snapshot_id / next_run_at
```

Failure at any step:
- DB dump fails → backup_runs(state='failed', error_message=<truncated>), cleanup temp
- restic fails → same
- Lock contention → previous run continues; this call returns
  `RpcError::Conflict("backup already running")`

### 8.2 `restore_from_snapshot`

```text
01 fetch hosting; if not exists, REFUSE (use restore_from_upload for new)
02 read manifest from snapshot: restic dump <snap> manifest.json
03 validate compatibility: PHP version installable, DB engine matches
04 hosting_suspend(reason='restore-in-progress')   — clean state
05 restic restore <snap>:htdocs → /home/<u>/<domain>/htdocs/  (overwrite)
06 if DB present: drop existing DB content (DROP DATABASE ... CREATE)
                   import db.sql / db.dump
07 chown -R <u>:<u> /home/<u>/<domain>/
08 hosting_resume
09 audit append (restore.ok, snapshot_id)
```

Failures: `hosting_resume` happens in a `finally` block. If restore left
partial state, the hosting is brought back online with WHATEVER state
the FS+DB are in, plus a warning in audit. Operator can re-try.

### 8.3 `restore_from_upload`

```text
01 accept upload via UploadHandle (chunked stream over RPC, with SHA-256
   computed as bytes arrive); writes to /var/lib/hyperion/uploads/<id>.tar.zst
02 once complete, extract into temp dir under /var/lib/.../restore-tmp/<id>/
03 read manifest.json
04 if dest specifies an existing hosting_id: same as restore_from_snapshot
   starting from step 03
05 if dest specifies a NEW domain: run an inline hosting_create with the
   manifest's parameters (PHP ver, DB engine), then proceed with restore
06 cleanup temp + upload
07 audit append
```

Max upload size: 8 GiB by default (configurable). For larger sites,
operator pushes to remote backup target out-of-band, then runs
`restore_from_snapshot`.

## 9. Schedule Parser

Supported strings:

```
hourly:MM             at MM minutes past each hour
daily-HH:MM           at HH:MM each day (in [scheduler].timezone)
weekly-DAY-HH:MM      DAY = mon..sun
monthly-DOM-HH:MM     DOM = 01..28 (29-31 collapses to last day of month)
custom-cron "<cron>"  full 5-field cron
```

`next_run_at` is recomputed after each successful run (and via a periodic
reconciler in the scheduler).

## 10. Configuration Additions

```toml
[backup]
local_repo_root            = "/var/lib/hyperion/backups/local"
backup_tmp                 = "/var/lib/hyperion/backup-tmp"
upload_tmp                 = "/var/lib/hyperion/uploads"
max_upload_bytes           = 8589934592    # 8 GiB
concurrent_runs            = 2
restic_path                = "/usr/bin/restic"
rclone_path                = "/usr/bin/rclone"
default_target             = "local"

[backup.rate_limit]
default_kbps_up            = 0             # 0 = unlimited
```

### 10.1 Target config examples

SFTP:
```json
{ "host":"backup.example.com", "port":22, "user":"backup",
  "key_path":"/etc/hyperion/agent/sftp-key",
  "remote_path":"/backups/<agent-hostname>" }
```

S3:
```json
{ "endpoint":"s3.eu-central-1.amazonaws.com", "bucket":"my-backups",
  "prefix":"<agent-hostname>/", "region":"eu-central-1",
  "access_key_id":"...", "secret_access_key_id":"<secret_id>" }
```

FTP/FTPS:
```json
{ "host":"ftp.example.com", "port":21, "user":"u", "pass_id":"<secret_id>",
  "secure":"ftps", "remote_path":"/backups/<agent-hostname>" }
```

Local mount:
```json
{ "mount_path":"/mnt/backup-nas",
  "remote_path":"<agent-hostname>" }
```

## 11. CLI

```
lm backup target add --name offsite-s3 --backend s3 --config @s3.json
lm backup target list
lm backup target remove offsite-s3

lm hosting backup policy <id> --target offsite-s3 \
    --schedule daily-04:30 --retention 7d-4w-12m
lm hosting backup policy clear <id> --target offsite-s3

lm hosting backup now <id> --target offsite-s3
lm hosting backup snapshots <id> --target offsite-s3
lm hosting restore <id> --snapshot 2a8c... --target offsite-s3
lm hosting restore-from-upload <new-or-existing-hosting> \
    --archive /tmp/site.tar.zst
lm backup verify offsite-s3 --quick
```

UI surfaces equivalents in sub-project 2.

## 12. Testing

- Unit: schedule parser; retention spec parser; manifest serde.
- Integration (testcontainers): local backup + restore on
  testcontainers-managed Debian; SFTP backup against `linuxserver/openssh`
  container; S3 against `minio/minio` container.
- e2e: nightly VM does full backup-now + restore-from-snapshot on a 1 GB
  WordPress fixture, asserts byte-equal `htdocs` and table-row-count
  match.
- Failure injection: kill restic mid-run; assert backup_runs goes to
  `failed` and next call cleans up tmp.

## 13. Security Notes

- Each repo password lives at
  `/etc/hyperion/secrets/repo-passwords/<repo_password_id>` (0600).
- DB dumps land in the secrets-mode-equivalent tmp dir
  (`/var/lib/hyperion/backup-tmp/` mode 0700, root-only); deleted
  promptly.
- Upload size cap enforced both at HTTP receiver and via `prlimit` on
  the writer process.
- Uploads validated: archive magic check, manifest schema check, path
  traversal protection (`tar` extracted via `tokio-tar` with
  per-entry path normalization).
- Restic operations never run as the hosting's user; agent runs them as
  root then chowns restored files.

## 14. Open Questions

1. **Database engine for restore archive.** If operator uploads a
   MariaDB dump but the hosting was provisioned with Postgres, fail
   loudly. **Proposal:** strict manifest check, exit early.
2. **Cross-version DB restore** (e.g. MariaDB 10.6 → 11.2). **Proposal:**
   trust mariadb-dump's portability; surface mysql errors verbatim if
   import fails.
3. **Per-file change detection vs full FS scan.** restic does its own
   change detection. Inotify-based caching is YAGNI.
4. **Quota interaction.** Restic temp + DB dump consume disk under
   `/var/lib/hyperion/backup-tmp/`. This is NOT under the
   hosting's quota. **Proposal:** acknowledge; operator sizes the
   agent's root FS accordingly.

## 15. Glossary Additions

| Term | Meaning |
|---|---|
| Target | A named destination for snapshots (local, sftp, s3, ftp, rclone) |
| Repository | A restic repo, identified by URL; one per target |
| Snapshot | One `restic backup` output, identified by a short id |
| Policy | A (hosting, target) tuple with schedule + retention |
| Run | One execution of a backup; recorded in `backup_runs` |
| Upload-restore | Restore initiated from an operator-supplied archive |

---

*End of spec.*
