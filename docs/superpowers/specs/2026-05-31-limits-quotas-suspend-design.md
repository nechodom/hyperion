# Sub-project 3 — Limits, Quotas, Suspend — Design Spec

| Field | Value |
|---|---|
| Sub-project | 3 of N — Limits/Quotas/Suspend |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation |
| Used by | Sub-projects 4 (expiration → suspend), 6 (client view of usage) |

## 1. Summary

Enforces per-hosting resource limits and provides a clean **suspend / resume**
lifecycle. Limits cover **disk** (ext4 user quotas, optional XFS prjquota),
**PHP runtime** (per-pool memory/timeout/concurrency), **bandwidth**
(nftables byte counters per system user), and **DB connections** (per-user
`max_user_connections`).

Suspend is an atomic, reversible state change: hosting stays in SQLite, but
serving stops cleanly with a configurable status page; SFTP/SSH access is
denied; PHP/Node processes are killed; DB user is locked.

## 2. Goals

1. `lm hosting set-limits <id> --disk 5G --php-mem 512M --php-children 10 --bw-month 50G`
   applies and persists.
2. `lm hosting suspend <id>` puts the hosting into a state where:
   - HTTP requests return a custom **suspended** page (HTTP 503).
   - SFTP/SSH login is refused.
   - PHP-FPM workers for the pool are terminated and the pool is removed
     from FPM until resume.
   - DB user is `ALTER USER ... ACCOUNT LOCK`'d (MariaDB) / `NOLOGIN`'d
     (Postgres).
3. `lm hosting resume <id>` undoes all of the above; site is serving
   again within 10 seconds.
4. Usage counters (disk used, bandwidth this period, PHP request count)
   are collected hourly and exposed via `hosting_get`.
5. Over-quota responses are deterministic: disk full → write fails as
   normal (kernel enforces); bandwidth over → suspend or throttle
   (operator choice per hosting); PHP over → request fails with the
   configured PHP error page.

## 3. Non-Goals

- Per-process CPU pinning.
- IO throttling (blk-io controllers); deferred — measure first.
- Network QoS / shaping.
- Real-time charts in UI (sub-project 2 may render simple counters).
- Per-Node.js-app limits (sub-project 8).

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Disk: **ext4 `usrquota`** as default, XFS `prjquota` if `/home` is XFS | Debian 12 default FS is ext4; one system user per hosting makes user quotas natural |
| D2 | PHP: per-pool `memory_limit`, `max_execution_time`, `pm.max_children`, `pm.max_requests` | Built-in FPM, no cgroup acrobatics |
| D3 | Bandwidth: **nftables** per-uid byte counters in `inet filter` table; sampled hourly | Cheap, kernel-level; one counter per system user |
| D4 | DB connections: MariaDB `max_user_connections` per grant; Postgres `CONNECTION LIMIT` per role | Built-in DB primitives |
| D5 | Suspend semantics: change nginx vhost to a "suspended" snippet; lock DB user; stop FPM pool | Reversible, no data loss |
| D6 | Customizable suspended page via operator template + per-hosting override | Agencies want branding |
| D7 | Resource usage collector runs every 60 minutes (cron-style task in agent) | Hourly granularity is enough for billing/alerting |
| D8 | Bandwidth period: calendar month (`YYYY-MM`); counter resets at month rollover | Standard hosting model |
| D9 | Over-bandwidth policy per hosting: `suspend` or `throttle` (nginx `limit_rate`) | Operator chooses; default `suspend` |
| D10 | Disk soft limit + hard limit (ext4 quota standard) — 1 week grace | Standard quota behavior |

## 5. State Schema Additions

```sql
-- Per-hosting limits
CREATE TABLE hosting_limits (
    hosting_id          TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    disk_soft_bytes     INTEGER,                   -- NULL = unlimited
    disk_hard_bytes     INTEGER,
    inode_soft          INTEGER,
    inode_hard          INTEGER,
    php_memory_mb       INTEGER NOT NULL DEFAULT 256,
    php_max_exec_secs   INTEGER NOT NULL DEFAULT 60,
    php_max_children    INTEGER NOT NULL DEFAULT 5,
    php_max_requests    INTEGER NOT NULL DEFAULT 1000,
    db_max_connections  INTEGER NOT NULL DEFAULT 25,
    bw_monthly_bytes    INTEGER,                   -- NULL = unlimited
    over_bw_policy      TEXT NOT NULL DEFAULT 'suspend'
                        CHECK (over_bw_policy IN ('suspend','throttle')),
    throttle_kbps       INTEGER                    -- used if over_bw_policy='throttle'
);

-- Usage observations
CREATE TABLE hosting_usage (
    hosting_id          TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    period              TEXT NOT NULL,             -- 'YYYY-MM-DD-HH' (hourly bucket)
    disk_used_bytes     INTEGER NOT NULL,
    inodes_used         INTEGER NOT NULL,
    bw_in_bytes         INTEGER NOT NULL,
    bw_out_bytes        INTEGER NOT NULL,
    php_requests        INTEGER NOT NULL,
    PRIMARY KEY (hosting_id, period)
);
CREATE INDEX hosting_usage_period ON hosting_usage(period);

-- Suspended state metadata
CREATE TABLE hosting_suspension (
    hosting_id          TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    suspended_at        INTEGER NOT NULL,
    suspended_by        TEXT NOT NULL,             -- 'manual' | 'over-bandwidth' | 'expired'
    reason_message      TEXT,                      -- shown on suspended page if visible
    custom_page_html    TEXT                       -- nullable; per-hosting override
);
```

Extend `hostings.state` CHECK to allow `'suspended'`:
```sql
-- migration 003 (after 1.5 and 2 if applied) updates the CHECK constraint
ALTER TABLE hostings RENAME TO hostings_old;
CREATE TABLE hostings (..., state TEXT NOT NULL CHECK (
    state IN ('provisioning','active','suspended','failed','deleting')
));
INSERT INTO hostings SELECT * FROM hostings_old;
DROP TABLE hostings_old;
```

## 6. RPC Additions

```rust
#[async_trait]
pub trait AgentApi {
    // ... existing methods ...

    async fn hosting_set_limits(&self, sel: HostingSelector, lim: HostingLimits)
        -> Result<HostingLimits, RpcError>;
    async fn hosting_suspend(&self, sel: HostingSelector, reason: SuspendReason)
        -> Result<(), RpcError>;
    async fn hosting_resume(&self, sel: HostingSelector) -> Result<(), RpcError>;
    async fn hosting_usage(&self, sel: HostingSelector, range: TimeRange)
        -> Result<Vec<HostingUsageBucket>, RpcError>;
}
```

## 7. Adapter Additions

### 7.1 `quota.rs` (new)

- `detect_backend() -> QuotaBackend` — inspects `/home` mount in
  `/proc/self/mounts`; returns `Ext4User`, `XfsProject`, or `None`.
- `ensure_enabled() -> Result<(), AdapterError>` — verifies kernel has
  the right module and quotas are on; refuses limit-set if not.
- `set_user_quota(uid, soft, hard, inode_soft, inode_hard)`
  - ext4: `setquota -u <uid> soft hard isoft ihard /home`
  - XFS: project ID assigned per hosting; `xfs_quota -x -c 'limit ...'`
- `get_usage(uid) -> Usage { bytes, inodes }`

### 7.2 `phpfpm.rs` (extend)

- `apply_limits(pool_user, ver, lim)` — re-renders pool config with new
  values; atomic write; FPM reload.
- `stop_pool(pool_user, ver)` — comments out the pool include
  (`mv pool.conf pool.conf.suspended`); FPM reload. Idempotent.

### 7.3 `nftables.rs` (new)

- Maintain a single managed nftables include file
  `/etc/nftables.d/lm-bw-counters.nft`, written atomically.
- For each system user with an active hosting, add **two** named counters
  (one in, one out) keyed by `meta skuid <uid>`:
  ```
  table inet lm-bw {
      counter user_<uid>_in  {}
      counter user_<uid>_out {}
      chain input  { type filter hook input  priority 0; ct state new,established
                     meta skuid <uid> counter name user_<uid>_in   accept; }
      chain output { type filter hook output priority 0; ct state new,established
                     meta skuid <uid> counter name user_<uid>_out  accept; }
  }
  ```
- `sample_all() -> HashMap<Uid, (in_bytes, out_bytes)>` — runs
  `nft -j list counters table inet lm-bw`, parses JSON.
- `reset_counters()` — `nft reset counters table inet lm-bw`.

### 7.4 `mariadb.rs` (extend)

- `set_user_max_connections(user, n)` — `GRANT USAGE ... WITH MAX_USER_CONNECTIONS n`.
- `lock_user(user)` — `ALTER USER 'u'@'localhost' ACCOUNT LOCK;`.
- `unlock_user(user)` — `ALTER USER 'u'@'localhost' ACCOUNT UNLOCK;`.

### 7.5 `postgres.rs` (extend)

- `set_role_connection_limit(role, n)` — `ALTER ROLE x CONNECTION LIMIT n;`.
- `lock_role(role)` — `ALTER ROLE x NOLOGIN;`.
- `unlock_role(role)` — `ALTER ROLE x LOGIN;`.

### 7.6 `nginx.rs` (extend)

- Template variants per state:
  - `nginx-vhost.conf.j2` (active) — existing
  - `nginx-vhost-suspended.conf.j2` — returns 503 with custom page
- `apply_suspended(domain)` — switch site config to suspended variant,
  reload.
- `apply_throttle(domain, kbps)` — re-render active variant with
  `limit_rate <kbps>k`, reload.

### 7.7 `linux-user.rs` (extend)

- `lock_login(user)` — `usermod -L <user>`; sets shell to
  `/usr/sbin/nologin`. Stored old shell in rollback for resume.
- `unlock_login(user)` — `usermod -U <user>`; restore shell.

## 8. Flows

### 8.1 `hosting_set_limits`

```text
01 validate input ranges (positive ints; sane upper bounds)
02 UPSERT hosting_limits row
03 quota: set_user_quota(uid, disk_*, inode_*)
04 phpfpm: apply_limits(user, ver, lim)  → reload pool
05 mariadb / postgres: set_*_connection_limit if hosting has DB
06 nftables: ensure counters exist for uid (creates if absent)
07 nginx: if over_bw_policy=='throttle', apply_throttle(domain, throttle_kbps)
08 audit append
```

Rollback: previous `hosting_limits` row restored, adapters re-applied.

### 8.2 `hosting_suspend`

Atomic: nothing reverts on partial failure; instead, idempotent retry.

```text
01 UPDATE hostings SET state='suspended', updated_at=now
02 INSERT hosting_suspension (..., suspended_by, reason_message)
03 nginx: apply_suspended(domain)   — serves 503 page
04 phpfpm: stop_pool(user, ver)
05 mariadb / postgres: lock_user(db_user)
06 linux-user: lock_login(system_user)
07 kill all processes owned by system_user (pkill -KILL -u <uid>)
08 audit append (suspend, with reason)
```

Failures in 03-07 log WARN but do not revert state — operator is
expected to retry; suspend is the safer state.

### 8.3 `hosting_resume`

```text
01 read hosting_suspension row (assert exists)
02 linux-user: unlock_login
03 mariadb / postgres: unlock_user
04 phpfpm: re-render pool config from hosting_limits + ensure_pool
05 nginx: write_vhost (active variant), reload
06 UPDATE hostings SET state='active'
07 DELETE hosting_suspension
08 audit append (resume)
```

### 8.4 Hourly usage collector

A background task in `lm-agent` (tokio interval, top of each hour, with
randomized 0–60s jitter so multiple agents don't synchronize):

```text
01 for each active hosting:
     - quota::get_usage(uid) → (disk_used, inodes_used)
02 nftables::sample_all() → bandwidth deltas
   (compare to last sample, write delta to hosting_usage for this period)
03 read php-fpm pool status (ping pool's status URI) → request counter
04 INSERT hosting_usage rows
05 for each hosting:
     - if bw_monthly_bytes set:
        sum_in_out = SELECT SUM(bw_in+bw_out) FROM hosting_usage
                       WHERE hosting_id=? AND period LIKE 'YYYY-MM-%'
        if sum > bw_monthly_bytes:
          if over_bw_policy='suspend': hosting_suspend(over-bandwidth)
          if over_bw_policy='throttle': nginx apply_throttle()
06 month rollover: nftables reset_counters() at first hour of new month
```

## 9. Configuration Additions

```toml
[limits]
default_php_memory_mb     = 256
default_php_max_exec_secs = 60
default_php_max_children  = 5
default_php_max_requests  = 1000
default_db_max_conn       = 25

[quota]
home_mount    = "/home"
backend       = "auto"     # auto | ext4 | xfs-project | none

[bandwidth]
collector_interval = "60m"
month_reset_hour   = 0     # at 00:00 of day 1, reset nftables counters

[suspended_page]
template_path     = "/etc/linux-manager/templates/suspended.html"
# variables: {{ domain }}, {{ reason_message }}, {{ contact_email }}
```

## 10. Suspended Page Template

`/etc/linux-manager/templates/suspended.html`:

```html
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>{{ domain }} is suspended</title>
<style>body{font:14px system-ui;margin:4rem auto;max-width:40rem;color:#333}</style>
</head><body>
<h1>This site is temporarily unavailable.</h1>
<p>{{ reason_message }}</p>
<p>If you are the site owner, please contact your hosting provider.</p>
</body></html>
```

Per-hosting overrides stored in `hosting_suspension.custom_page_html` and
written to `/etc/linux-manager/suspended-pages/<hosting_id>.html` on
suspend; nginx serves that file via `try_files` when set.

## 11. Testing

- Unit: `lm-validate` covers limit value ranges; serde round-trip for
  `HostingLimits`.
- Adapter integration (testcontainers):
  - quota adapter against ext4 image (Loop-mounted ext4 with usrquota).
  - phpfpm adapter: apply limits, assert pool config matches.
  - nftables adapter: install nft, apply rules, parse counters.
  - mariadb / postgres adapters: lock + verify connection refusal.
- e2e (nightly): create hosting, set 10 MiB disk limit, dd 11 MiB → write
  fails. Set 1 MiB bandwidth, curl 2 MiB → suspended.

## 12. Security Notes

- `quota`, `nftables`, `usermod` are all root-only; safely confined to
  `lm-adapters`.
- Bandwidth counter exposure: agents only expose their own uid counters
  via `hosting_usage` joined to `hostings` — never raw nft output.
- Suspended page never reflects input back into HTML without escaping
  (use askama autoescape).

## 13. Open Questions

1. **Bandwidth attribution to nginx vs PHP-FPM vs SFTP traffic.**
   The `meta skuid` approach counts everything owned by that uid,
   including SSH/SFTP traffic. **Proposal:** accept this; bandwidth is
   bandwidth.
2. **What if the operator changes a hosting's system_user later** (rare).
   Nftables counters need re-keying. **Proposal:** disallow user rename
   in 3; if ever supported, treat as new hosting for bandwidth purposes.
3. **Disk usage caching.** `repquota` is fast but not free. **Proposal:**
   only run during the hourly collector; expose `usage()` RPC returns
   the last recorded value, not a live count.

## 14. Glossary Additions

| Term | Meaning |
|---|---|
| Suspend | A state that stops serving + access without deleting data |
| Throttle | Bandwidth limit enforced via nginx `limit_rate` |
| Over-bandwidth policy | Per-hosting choice: suspend vs throttle when monthly cap is hit |
| Hourly bucket | The unit of time used by `hosting_usage`; key `YYYY-MM-DD-HH` |

---

*End of spec.*
