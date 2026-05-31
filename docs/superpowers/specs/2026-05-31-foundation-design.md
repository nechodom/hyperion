# Foundation — Design Spec

| Field | Value |
|---|---|
| Sub-project | 1 of N — Foundation |
| Status | Draft, awaiting user review |
| Date | 2026-05-31 |
| Project | linux-manager (multi-node Linux hosting control panel) |
| Language | Rust 2024 (MSRV 1.80) |
| Target OS | Debian 12+ |

## 1. Summary

Foundation provides the **core agent + CLI** for provisioning, listing, inspecting,
and deleting hostings on a single Debian 12 node. It is the substrate on which all
later sub-projects (controller, admin UI, quotas, expiration, backups, client portal,
WordPress installer, Node.js stack, hardening) are built.

The deliverable is a working **`lm-agent`** root daemon (Unix-socket RPC),
an **`lm`** unprivileged CLI client, a SQLite state store, a typed RPC trait
that is transport-agnostic (so the same trait will later be served over mTLS for
multi-node), and the system adapters needed for nginx, PHP-FPM, MariaDB,
PostgreSQL, and Let's Encrypt.

No web UI, no remote access, no quotas, no expiration, no backups, no application
templates. Those live in their own sub-projects.

## 2. Goals

1. `lm hosting create <domain> [--php <ver>] [--db mariadb|postgres] [--static]`
   provisions a working PHP or static website with TLS in under 60 seconds on a
   2-vCPU Debian 12 VPS.
2. `lm hosting list`, `lm hosting get <id|domain>`, `lm hosting delete <id|domain>`
   round out CRUD.
3. `lm cert renew` renews all certificates within 30 days of expiry.
4. All privileged operations are confined to a small, audit-ready surface
   (`lm-agent`'s RPC handlers + `lm-adapters` crate). The CLI runs unprivileged.
5. Every provisioning step is **idempotent** and supports **LIFO rollback** on
   partial failure.
6. SQLite state is the single source of truth on the node; on-disk artifacts
   (nginx configs, FPM pools, certs) are derivable from SQLite.
7. Integration tests run in disposable Debian 12 containers via testcontainers.

## 3. Non-Goals (Anti-Scope for Foundation)

Explicitly NOT in Foundation. Each is its own sub-project, listed in the project
decomposition. Listing here so scope cannot drift:

- HTTP/HTTPS web UI of any kind.
- mTLS / TCP transport for RPC; agent listens only on a local Unix socket.
- Multi-node, controller, agent enrollment, mTLS CA, inventory.
- Client portal, billing, user-facing self-service.
- Disk quotas, cgroups CPU/RAM limits, traffic limits.
- Hosting suspend/resume state transitions (entity may carry the state column,
  but no behavior).
- Expiration dates, scheduler, time-based actions.
- Backups, restore, remote backup targets.
- WordPress installer, plugin/theme bundles, app marketplace.
- Node.js / Python / static-site-generator runtime stacks (Foundation supports
  PHP-FPM + raw static only).
- ModSecurity / WAF, fail2ban, advanced firewall integration.
- Email, DNS provisioning, FTP-only users, webmail.
- SFTP chroot UX beyond Debian's stock OpenSSH `ChrootDirectory` setup.

## 4. Decisions Recap (from brainstorming)

| # | Decision | Rationale |
|---|---|---|
| D1 | Rust 2024, single workspace, multi-crate | Memory safety for root daemon, single binary deploy, fast compile in dev via crate split |
| D2 | Split: `lm-agent` (root) + `lm` CLI (unpriv.) over Unix socket | Smallest privileged surface; web/UI later cannot escalate |
| D3 | RPC trait is transport-agnostic | Same `AgentApi` will be served over mTLS for remote agents (sub-project 1.5) without refactor |
| D4 | SQLite via `sqlx` for state | Zero-deps, file-backed, transactional, good for single-node |
| D5 | nginx as web server | Standard for this panel class; mature; `nginx -t` validates before reload |
| D6 | PHP 8.1/8.2/8.3/8.4 via `deb.sury.org` repo | Apt-native, signed, supports multi-version coexistence |
| D7 | MariaDB + PostgreSQL as managed DB engines | MariaDB for WordPress-class workloads; Postgres for app stacks |
| D8 | TLS via `instant-acme` crate (in-process ACME client) | No external `certbot`/`acme.sh` dep; auditable; no extra privileged process |
| D9 | Filesystem layout: `/home/<system_user>/<domain>/htdocs` | CloudPanel-like; one Linux user per hosting; SFTP-friendly |
| D10 | Binary names: `linux-manager` (full) with `lm` symlink for CLI; `lm-agent` for daemon | Discoverable + short |
| D11 | Hash-chain audit log (BLAKE3) | Tamper-evident |
| D12 | Secrets stored in `/etc/linux-manager/secrets/<id>.json` mode 0600 | Never in SQLite; survives DB compromise |
| D13 | LIFO rollback stack per orchestrated operation | Partial failures recover without manual cleanup |

## 5. Architecture

```
                    ┌─────────────────────────────────────────┐
                    │            Debian 12 host               │
                    │                                         │
   /run/linux-      │   ┌─────────────┐    ┌──────────────┐   │
   manager.sock ◄───┼───┤  lm-agent   │    │ lm  (CLI)    │   │
   (0660, root:lm-  │   │  (root)     │◄──►│ uid != 0     │   │
    admin)          │   │             │    │ in lm-admin  │   │
                    │   └──────┬──────┘    └──────────────┘   │
                    │          │                              │
                    │          ▼                              │
                    │   ┌─────────────────────────────────┐   │
                    │   │  lm-core (orchestration)        │   │
                    │   │   + lm-state (SQLite)           │   │
                    │   │   + lm-adapters                 │   │
                    │   └────┬─────┬─────┬─────┬─────┬────┘   │
                    │        ▼     ▼     ▼     ▼     ▼        │
                    │     useradd nginx phpfpm mariadb acme   │
                    │              postgres                   │
                    └─────────────────────────────────────────┘
```

### 5.1 Process model

- **`lm-agent`** runs as `root` via systemd unit. It is the only process with
  privilege.
- It listens on a Unix domain socket `/run/linux-manager.sock`,
  owned `root:lm-admin`, mode `0660`. Membership in `lm-admin` group grants
  the right to issue RPC requests.
- **`lm`** CLI runs as the invoking user. It connects to the socket, sends
  a JSON request frame, reads a JSON response frame, exits.

### 5.2 Trust boundary

- The socket peer is identified via `SO_PEERCRED`. The agent logs the
  caller's effective UID into the audit log on every request.
- Group membership is enforced by socket permissions (kernel-level).
- No further authorization in Foundation: any member of `lm-admin` can
  perform any RPC. Per-action RBAC is sub-project 2.

## 6. Workspace Layout

```
linux-manager/
├── Cargo.toml                          # workspace
├── rust-toolchain.toml                 # pin MSRV
├── deny.toml                           # cargo-deny config (license, advisories)
├── crates/
│   ├── lm-types/                       # shared serde types
│   ├── lm-validate/                    # input parsers (regex whitelists)
│   ├── lm-rpc/                         # AgentApi trait + wire types + RpcError
│   ├── lm-rpc-server/                  # Unix-socket server framing + dispatcher
│   ├── lm-rpc-client/                  # Unix-socket client (later: mtls://)
│   ├── lm-state/                       # SQLite layer (sqlx) + migrations
│   ├── lm-adapters/                    # thin wrappers around system tools
│   └── lm-core/                        # HostingService, orchestration, RollbackStack
├── bin/
│   ├── lm-agent/                       # daemon
│   └── lm/                             # CLI
├── packaging/
│   ├── debian/                         # source for .deb (dh-cargo)
│   ├── systemd/lm-agent.service
│   └── nginx-snippets/                 # reusable include files
├── tests/
│   ├── adapters/                       # testcontainers-rs integration tests
│   └── e2e/                            # nightly VM tests (libvirt)
└── docs/
    ├── superpowers/specs/
    └── runbook.md                      # later
```

### 6.1 Why this split

- `lm-types`, `lm-rpc`, `lm-validate` are leaf crates with zero IO; pure data.
  They compile fast and are heavily fuzzed.
- `lm-state`, `lm-adapters` each own one external dependency surface (SQLite,
  system tools). Failures and rollbacks are local to one crate.
- `lm-core` is the orchestrator. It is the only crate that imports
  `lm-state + lm-adapters`. Business rules live here.
- `lm-rpc-server` and `lm-rpc-client` are symmetric; replacing the transport
  later (mTLS TCP) is a new crate, not a rewrite.
- `bin/` crates are thin: parse args / config, wire up tokio, hand off.

## 7. Public RPC API

### 7.1 Trait

```rust
// crates/lm-rpc/src/api.rs
#[async_trait::async_trait]
pub trait AgentApi: Send + Sync + 'static {
    async fn agent_info(&self) -> Result<AgentInfo, RpcError>;

    async fn hosting_create(
        &self, req: HostingCreateReq,
    ) -> Result<HostingCreated, RpcError>;

    async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError>;

    async fn hosting_get(
        &self, sel: HostingSelector,
    ) -> Result<HostingDetail, RpcError>;

    async fn hosting_delete(
        &self, sel: HostingSelector, opts: DeleteOpts,
    ) -> Result<(), RpcError>;

    async fn cert_issue(&self, domain: Domain) -> Result<CertInfo, RpcError>;
    async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError>;
}
```

### 7.2 Wire-types (excerpt)

```rust
#[derive(Serialize, Deserialize)]
pub struct HostingCreateReq {
    pub domain: Domain,                          // validated
    pub aliases: Vec<Domain>,
    pub php_version: Option<PhpVersion>,         // None => static
    pub database: Option<DbProvision>,           // None => no DB
    pub system_user: Option<SystemUserName>,     // None => auto-derived
}

#[derive(Serialize, Deserialize)]
pub enum DbProvision { MariaDB, Postgres }

#[derive(Serialize, Deserialize)]
pub enum HostingSelector { Id(HostingId), Domain(Domain) }

#[derive(Serialize, Deserialize)]
pub struct DeleteOpts {
    pub keep_user: bool,        // default false: also userdel + rm -r home
    pub keep_database: bool,    // default false
}

#[derive(Serialize, Deserialize)]
pub struct HostingCreated {
    pub id: HostingId,
    pub system_user: SystemUserName,
    pub root_dir: PathBuf,
    pub db: Option<DbCredentials>,   // returned ONCE; never reread from agent
    pub cert: CertInfo,
}
```

```rust
#[derive(Serialize, Deserialize)]
pub struct CertInfo {
    pub domain: Domain,
    pub sans: Vec<Domain>,
    pub issuer: String,
    pub not_after: i64,           // unix epoch seconds
    pub fingerprint_sha256: String,
}

#[derive(Serialize, Deserialize)]
pub struct CertRenewResult {
    pub domain: Domain,
    pub outcome: CertRenewOutcome,
}

#[derive(Serialize, Deserialize)]
pub enum CertRenewOutcome {
    Renewed { new_not_after: i64 },
    Skipped { reason: String },         // e.g. "not yet expiring"
    Failed { error: String },
}

#[derive(Serialize, Deserialize)]
pub struct HostingDetail {
    pub id: HostingId,
    pub domain: Domain,
    pub aliases: Vec<Domain>,
    pub state: HostingState,
    pub system_user: SystemUserName,
    pub php_version: Option<PhpVersion>,
    pub root_dir: PathBuf,
    pub database: Option<DbSummary>,
    pub cert: Option<CertInfo>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct DbSummary {
    pub engine: DbProvision,       // MariaDB | Postgres
    pub db_name: String,
    pub db_user: String,
    // password is never returned after creation; reset would be a separate RPC
}

#[derive(Serialize, Deserialize)]
pub enum HostingState { Provisioning, Active, Failed, Deleting }
```

### 7.3 Error type

```rust
#[derive(Debug, Serialize, Deserialize, thiserror::Error)]
pub enum RpcError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("entity already exists: {kind} {id}")]
    AlreadyExists { kind: String, id: String },
    #[error("not found: {kind} {id}")]
    NotFound { kind: String, id: String },
    #[error("provisioning failed at stage '{stage}': {reason}")]
    ProvisioningFailed { stage: String, reason: String },
    #[error("system command failed: {cmd} exit {code}")]
    SystemCommand { cmd: String, code: i32, stderr_tail: String },
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error")]
    Internal,    // detail goes to agent log, not wire
}
```

### 7.4 Wire framing

- Each frame is `u32be length || JSON body`.
- Max body size 4 MiB (configurable, enforced both sides).
- One request/response per connection in Foundation. Streaming RPC is YAGNI
  here and added if/when needed (e.g. backup progress in sub-project 5).

## 8. SQLite State Schema

### 8.1 Migrations

Migrations live in `crates/lm-state/migrations/NNN_name.sql`, applied
in lexicographic order via `sqlx::migrate!`. `schema_version` table
mirrors `_sqlx_migrations`; queries can assert minimum version.

### 8.2 DDL (migration 001)

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE system_users (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,              -- ^[a-z][a-z0-9_]{2,31}$
    uid          INTEGER NOT NULL UNIQUE,
    home_dir     TEXT NOT NULL,
    shell        TEXT NOT NULL DEFAULT '/usr/sbin/nologin',
    created_at   INTEGER NOT NULL                   -- unix epoch seconds
);

CREATE TABLE hostings (
    id                TEXT PRIMARY KEY,             -- UUID v7
    domain            TEXT NOT NULL UNIQUE,
    state             TEXT NOT NULL CHECK (
        state IN ('provisioning','active','failed','deleting')
    ),
    system_user_id    INTEGER NOT NULL REFERENCES system_users(id),
    php_version       TEXT,                         -- '8.1'..'8.4' or NULL
    root_dir          TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE INDEX hostings_state ON hostings(state);

CREATE TABLE hosting_aliases (
    hosting_id        TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    alias_domain      TEXT NOT NULL UNIQUE,
    PRIMARY KEY (hosting_id, alias_domain)
);

CREATE TABLE databases (
    id           INTEGER PRIMARY KEY,
    hosting_id   TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    engine       TEXT NOT NULL CHECK (engine IN ('mariadb','postgres')),
    db_name      TEXT NOT NULL,
    db_user      TEXT NOT NULL,
    -- secret_id references file at /etc/linux-manager/secrets/<id>.json
    secret_id    TEXT NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    UNIQUE (engine, db_name)
);

CREATE TABLE certificates (
    id           INTEGER PRIMARY KEY,
    domain       TEXT NOT NULL UNIQUE,
    issued_at    INTEGER NOT NULL,
    not_after    INTEGER NOT NULL,
    cert_path    TEXT NOT NULL,                     -- /etc/linux-manager/certs/<domain>/fullchain.pem
    key_path     TEXT NOT NULL,
    issuer       TEXT NOT NULL CHECK (issuer IN ('letsencrypt','self-signed'))
);
CREATE INDEX certificates_not_after ON certificates(not_after);

CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    actor_uid    INTEGER NOT NULL,                  -- from SO_PEERCRED
    actor_label  TEXT NOT NULL,                     -- 'cli:root', 'cli:user42'
    action       TEXT NOT NULL,                     -- 'hosting.create' etc
    target       TEXT,                              -- entity id (nullable)
    payload_json TEXT NOT NULL,                     -- redacted args
    result       TEXT NOT NULL,                     -- 'ok' or 'error:<code>'
    prev_hash    TEXT NOT NULL,                     -- BLAKE3 of previous row_hash
    row_hash     TEXT NOT NULL                      -- BLAKE3 of canonical fields
);
CREATE INDEX audit_log_ts ON audit_log(ts);
```

### 8.3 Invariants

- One `hostings.domain` maps to exactly one `system_users.id`; the user is
  derived from the domain (`example.cz` → `example_cz`) unless overridden.
- `hostings.root_dir` is always `home_dir + "/" + domain + "/htdocs"`. Code
  computes it; it is stored for fast read.
- `databases.secret_id` is a ULID, used as filename for the secrets file;
  the password is never in SQLite.
- `audit_log` is append-only; no `UPDATE` or `DELETE` queries exist in
  `lm-state`. Integrity verified on agent startup.

## 9. Filesystem Layout

```
/etc/linux-manager/
├── agent.toml                          # config (paths, ACME account, listen socket)
├── secrets/                            # mode 0700
│   └── <secret_id>.json                # mode 0600, root:root
└── certs/<domain>/
    ├── fullchain.pem
    └── privkey.pem

/var/lib/linux-manager/
├── state.db                            # SQLite (mode 0600)
└── state.db-wal, state.db-shm          # SQLite WAL files

/var/log/linux-manager/
└── agent.log                           # JSON Lines

/run/linux-manager.sock                 # Unix socket (0660 root:lm-admin)

/home/<system_user>/
├── .ssh/authorized_keys                # set up by user; agent does not touch
└── <domain>/
    ├── htdocs/                         # webroot, owned by <system_user>
    ├── logs/                           # nginx + php-fpm logs for this site
    └── tmp/                            # PHP tmp/session dir

/etc/nginx/sites-available/<domain>.conf       # owned root, generated
/etc/nginx/sites-enabled/<domain>.conf         # symlink to above
/etc/php/<version>/fpm/pool.d/<system_user>.conf
```

## 10. System Adapters

Each adapter is a struct in `lm-adapters` with these obligations:

1. **No shell interpolation.** Always `Command::new(...).arg(...)`; no
   `sh -c`, no string-formatted commands.
2. **Validate arguments at the call boundary.** Adapters refuse any input
   that did not pass through `lm-validate`. Types like `SystemUserName`
   carry their validation proof.
3. **Idempotency.** "Ensure X" semantics: if X exists and matches the spec,
   no-op; if X exists but mismatches, return `RpcError::Conflict` (do not
   silently mutate); if absent, create.
4. **Rollback tokens.** Every mutating operation returns a `RollbackToken`
   that, when invoked, undoes the operation if possible. Returned tokens
   are pushed onto a `RollbackStack` in `lm-core`.
5. **Captured stderr on failure.** The last 4 KiB of stderr is included in
   `RpcError::SystemCommand`.

### 10.1 Users adapter (`users.rs`)

- `ensure_user(spec) -> RollbackToken`
  - Checks `getent passwd <name>`; if exists, asserts uid+home+shell match.
  - Creates via `useradd -m -d <home> -s /usr/sbin/nologin -U <name>`.
  - Rollback: `userdel -r <name>` (if and only if we created the user).
- `delete_user(name)` — removes user + home; refuses if `/home/<name>`
  contains files not owned by the user (safety).

### 10.2 Filesystem adapter (`fs.rs`)

- `ensure_dir(path, mode, owner)` — `mkdir` if absent, `chmod` + `chown` to
  match. Refuses if `path` is a symlink (TOCTOU-safe).
- All paths constructed via `Path::join`; no string concatenation.
- Helpers for atomic file write (`tempfile + rename`).

### 10.3 Nginx adapter (`nginx.rs`)

- `write_vhost(hosting) -> RollbackToken`
  - Renders askama template `nginx-vhost.conf.j2` with hosting data.
  - If `/etc/nginx/sites-available/<domain>.conf` already exists, copy it
    to a backup path `<domain>.conf.bak-<timestamp>` (memorized in
    rollback token).
  - Atomic write of rendered bytes to `<domain>.conf.tmp`, then `rename`
    to `<domain>.conf` (atomic on same filesystem).
  - Create symlink `/etc/nginx/sites-enabled/<domain>.conf ->
    ../sites-available/<domain>.conf` if absent.
  - Run `nginx -t`. This now tests the live config including our vhost.
    - On failure: restore backup (rename `.bak-<ts>` back, or remove
      `<domain>.conf` if there was no prior config) and remove our
      symlink if we created it. Return
      `ProvisioningFailed{stage: "nginx-test", reason: <stderr_tail>}`.
  - `systemctl reload nginx` with 5s timeout.
  - Rollback token: restore backup OR remove file, remove symlink if we
    created it, reload.
- `delete_vhost(domain)` — remove symlink, remove sites-available file,
  reload. Idempotent (safe if files already absent).
- `reload()` — `systemctl reload nginx` with 5s timeout.

### 10.4 PHP-FPM adapter (`phpfpm.rs`)

- `ensure_pool(system_user, php_version) -> RollbackToken`
  - Validates `php_version` against `lm-validate::PhpVersion` (whitelist).
  - Renders `phpfpm-pool.conf.j2` (per-pool socket at
    `/run/php/<version>/<system_user>.sock`, `listen.owner = system_user`).
  - Atomic write to `/etc/php/<ver>/fpm/pool.d/<user>.conf`.
  - `systemctl reload php<ver>-fpm`.
- `delete_pool(system_user, php_version)`.

### 10.5 MariaDB adapter (`mariadb.rs`)

- Connects via Unix socket as root via `/var/run/mysqld/mysqld.sock` (default
  Debian socket auth, no password needed).
- `create_db_and_user(hosting_id) -> (DbCredentials, RollbackToken)`
  - Generates db_name `lm_<hash6>_<short_domain>`, user `lm_<hash6>_u`,
    32-char random password (CSPRNG, `[A-Za-z0-9]`).
  - `CREATE DATABASE`, `CREATE USER`, `GRANT ALL ON db.* TO user@'localhost'`.
  - Writes password to `/etc/linux-manager/secrets/<secret_id>.json`
    (mode 0600).
  - Rollback: `DROP USER`, `DROP DATABASE`, `rm secret file`.

### 10.6 PostgreSQL adapter (`postgres.rs`)

- Analogous to MariaDB; connects via `peer` auth as `postgres` system user
  through `pg_hba.conf` standard Debian setup.
- Generates roles + DB with random password; stores in secrets dir.

### 10.7 ACME adapter (`acme.rs`)

- Uses `instant-acme` crate against Let's Encrypt production directory
  (configurable to staging in `agent.toml`).
- Account key persisted at `/etc/linux-manager/acme-account.key` (mode 0600).
- HTTP-01 challenge served via a temporary nginx vhost stanza in a snippet
  file included by every vhost (resolves
  `/.well-known/acme-challenge/<token>` from a shared directory). Adapter
  writes the token, requests verification, removes the token.
- Returns cert + key written to `/etc/linux-manager/certs/<domain>/`.
- `renew_all()` selects certs where `not_after - now < 30 days`.

## 11. Orchestrated Flows

### 11.1 `hosting_create`

Implemented in `lm-core::HostingService::create`. Order respects the
`hostings.system_user_id NOT NULL` FK constraint by creating the user
before inserting the hosting row.

```text
01 lm-validate Domain, aliases, php_version, database
02 derive system_user name (from domain or override)
03 ensure_user(spec)  -> returns system_users.id                      [R1: userdel]
04 ensure_dir /home/<u>/<domain>/htdocs, mode 0750, owner u           [R2: rm -r]
05 ensure_dir /home/<u>/<domain>/logs,   mode 0750, owner u           [R2 same handle]
06 ensure_dir /home/<u>/<domain>/tmp,    mode 0750, owner u           [R2 same handle]
07 lm-state BEGIN; INSERT hostings (state='provisioning',
        system_user_id=<id from step 03>, returns hosting_id);
   INSERT hosting_aliases; COMMIT                                      [R3: DELETE row]
08 if php_version is Some: phpfpm ensure_pool(u, ver)                  [R4: del pool]
09 if database == MariaDB:  mariadb create_db_and_user(hosting_id)     [R5a: drop+rm]
10 if database == Postgres: postgres create_db_and_user(hosting_id)    [R5b: drop+rm]
11 acme issue_cert(domain + aliases)                                   [R6: rm cert]
12 nginx write_vhost(hosting_detail) — includes nginx -t + reload      [R7: restore/remove]
13 lm-state: UPDATE hostings SET state='active', updated_at=now WHERE id=?
14 audit_log append (success)
15 return HostingCreated to caller (includes db credentials returned ONCE)
```

Rollback semantics on any error after step 03:
- LIFO pop of rollback tokens; each is best-effort, failures are logged
  WARN but do not stop subsequent rollbacks.
- If we already inserted the hosting row (step 07+), instead of
  `DELETE` we update `state='failed'` for forensics; row is cleaned up
  by a subsequent explicit `hosting_delete` or the boot cleanup task.

On any error after step 02:
- Pop rollback stack LIFO; each rollback logs its outcome.
- Set `hostings.state = 'failed'` (do not delete row — needed for audit /
  inspection).
- Append audit_log entry with full error chain.
- Return `RpcError::ProvisioningFailed { stage, reason }`.

A separate **cleanup-on-startup** task in `lm-agent` scans for
`state = 'provisioning'` rows at boot, treats them as crashed, and runs
the full rollback (using stored on-disk evidence — system users + dirs +
DBs + certs + vhost files; each adapter has a `find_orphans` helper).

### 11.2 `hosting_list`

`SELECT id, domain, state, php_version, created_at FROM hostings ORDER BY domain`.
No side effects. Pagination YAGNI for Foundation (a node will not exceed
a few thousand hostings).

### 11.3 `hosting_get`

Resolves selector (id or domain), joins users + databases + aliases + cert.
Does **not** read secret files (passwords are write-only — returned at
create time, never again).

### 11.4 `hosting_delete`

```text
01 resolve hosting; require state in (active, failed)
02 lm-state: UPDATE state=deleting
03 audit append (delete.start)
04 nginx: remove sites-enabled symlink, remove sites-available file, reload
05 acme: revoke + delete cert files (best-effort; failures logged not fatal)
06 if DB exists and !opts.keep_database: drop DB + user + remove secret file
07 phpfpm: remove pool file, reload
08 fs: rm -rf /home/<u>/<domain>/   (the per-domain dir, not the home)
09 if !opts.keep_user and no other hostings for u: users delete_user
10 lm-state: DELETE hostings row (CASCADE cleans aliases + databases)
11 audit append (delete.ok)
```

Delete is **best-effort idempotent**: each step is safe to re-run if a
previous attempt failed mid-way. Re-running `lm hosting delete` continues
from where it stopped.

### 11.5 `cert_renew_all`

Cron-like; for Foundation it is called by a systemd timer
(`lm-agent-cert-renew.timer`) twice daily. The agent itself does not have
a scheduler in Foundation.

## 12. Error Handling & Rollback

- `thiserror` for typed errors in every library crate.
- `anyhow` permitted only in `bin/lm-agent/src/main.rs` and
  `bin/lm/src/main.rs` (top-level).
- `clippy::unwrap_used = "deny"` and `clippy::expect_used = "deny"` in all
  library crates. Acceptable in `bin/main.rs` only for startup invariants.
- `RollbackStack` is a `Vec<Box<dyn RollbackAction>>`. On error path, popped
  in LIFO order; each action's failure is logged at WARN but does not abort
  rollback of remaining actions.
- Internal errors that should not leak to the wire are mapped to
  `RpcError::Internal` after logging full chain to `agent.log`.

## 13. Security Model

- The agent is the only privileged process.
- The CLI talks over a Unix socket; peer credentials are checked
  (`SO_PEERCRED`); audit log records the caller's UID.
- Group `lm-admin` grants socket access. Group is created at package install.
- All secrets live outside SQLite, in mode 0600 files under
  `/etc/linux-manager/secrets/`.
- All shell-invoked commands use argv form; arguments validated by
  `lm-validate` regexes before being passed to `Command::new`.
- Audit log is append-only with BLAKE3 hash chain; agent verifies the
  chain on startup and refuses to start if broken (operator must rotate
  the log explicitly).
- Outbound network access is limited to ACME endpoints (Let's Encrypt).
  No other network egress is needed by Foundation.
- nginx vhost templates use safe defaults: HSTS on, secure ciphers
  (ssl_protocols TLSv1.2 TLSv1.3), no server tokens.

## 14. Configuration

`/etc/linux-manager/agent.toml`:

```toml
[agent]
socket_path        = "/run/linux-manager.sock"
socket_group       = "lm-admin"
state_db           = "/var/lib/linux-manager/state.db"
secrets_dir        = "/etc/linux-manager/secrets"
log_path           = "/var/log/linux-manager/agent.log"

[acme]
directory_url      = "https://acme-v02.api.letsencrypt.org/directory"
contact_email      = "you@example.com"
account_key_path   = "/etc/linux-manager/acme-account.key"
challenge_dir      = "/var/lib/linux-manager/acme-challenges"

[nginx]
sites_available    = "/etc/nginx/sites-available"
sites_enabled      = "/etc/nginx/sites-enabled"
reload_cmd_timeout = "5s"

[php]
versions_enabled   = ["8.1","8.2","8.3","8.4"]

[mariadb]
admin_socket       = "/var/run/mysqld/mysqld.sock"

[postgres]
admin_user         = "postgres"
```

Config validation runs at agent startup; agent fails to start with a clear
error if any required path is missing or wrong-permissioned.

## 15. Logging & Audit

- **`agent.log`** — JSON-lines structured log via `tracing` +
  `tracing-subscriber`. Levels: `error`, `warn`, `info`, `debug`. Default
  `info`. Fields: `ts`, `level`, `event`, `request_id`, payload.
- **Audit log** is in SQLite (`audit_log` table). Every RPC handler call
  appends one start record and one result record. Sensitive args
  (passwords, private keys) are redacted via a `Redact` newtype before
  serializing into `payload_json`.

## 16. Testing Strategy

### 16.1 Unit tests

- `lm-validate`: property tests via `proptest` for every parser; check that
  every accepted string survives a round-trip and every rejected string
  produces a clear error.
- `lm-state`: in-memory SQLite per test; each query function has at least
  one test for the happy path and one for each constraint it enforces.
- `lm-rpc`: serde round-trip for every wire type.
- `lm-core`: orchestration tests with fake adapters (`mockall` traits)
  to exercise rollback paths without touching the system.

### 16.2 Adapter integration tests

- `tests/adapters/` driven by `testcontainers-rs` with a custom
  `debian:bookworm-slim` image preinstalled with nginx, PHP-FPM 8.3,
  MariaDB, PostgreSQL, OpenSSH.
- Each test runs one adapter operation against the live container and
  asserts both the side effect (file present, user exists, service
  reloads) and the rollback (undo restores original state).
- Tests are tagged `#[ignore]` by default; CI runs them via
  `cargo test -- --ignored`.

### 16.3 End-to-end

- `tests/e2e/` runs nightly. Boots a fresh Debian 12 VM via libvirt, installs
  the .deb, runs `lm hosting create` for several configurations, hits each
  resulting site over HTTPS, asserts cert chain.

### 16.4 Fuzzing

- `cargo-fuzz` targets: each `lm-validate` parser; the `lm-rpc` deserializer.
- Goal: zero panics on arbitrary input.
- Runs nightly with a 30-minute budget.

### 16.5 Coverage targets

- 90%+ on `lm-validate`, `lm-state`, `lm-core`.
- Adapters measured by integration coverage (% of public API touched).
- No coverage target on `bin/` (thin wiring).

## 17. Build & Packaging

- `cargo build --release` produces `lm-agent`, `linux-manager`, `lm`
  (symlink installed by deb).
- Stripped binaries via `[profile.release] strip = "symbols"`.
- Static linkage against musl is **not** required; `glibc` build is fine
  for Debian-only targeting.
- `cargo-deny` enforces license + advisory checks in CI.
- `.deb` built with `cargo-deb`; installs:
  - binaries under `/usr/sbin/lm-agent`, `/usr/bin/lm`
  - systemd unit at `/lib/systemd/system/lm-agent.service`
  - timer at `/lib/systemd/system/lm-agent-cert-renew.timer`
  - default config under `/etc/linux-manager/agent.toml`
  - postinst creates `lm-admin` group, creates `/var/lib/linux-manager/`
    (mode 0700, root:root), enables and starts the service.
- Migrations are compiled into the agent binary via the `sqlx::migrate!`
  macro and applied on agent startup (idempotent). No `sqlx` CLI is
  required at runtime.

## 18. Open Questions

These are flagged for resolution before implementation begins (or
explicitly deferred):

1. **Multi-PHP version reload coalescing.** If many hostings are created in
   rapid succession, naive per-pool reload causes repeated `systemctl reload
   php<ver>-fpm` calls. **Proposal:** batch reloads via a 500 ms debounce
   per service inside `lm-core`. Deferred — measure first.
2. **PostgreSQL coexistence on the same node as MariaDB.** Both daemons
   running is the default; we do not stop or constrain either. No question
   here — explicit acknowledgement.
3. **IPv6.** nginx vhost template should bind both v4 and v6 by default
   (`listen 80; listen [::]:80;`). Not negotiable; including for clarity.
4. **`hosting_get` cert info vs SNI multi-cert.** Aliases share the same
   cert today (request all SANs in one ACME order). YAGNI separate certs.

## 19. Glossary

| Term | Meaning |
|---|---|
| Hosting | One website served by this node, identified by primary domain |
| System user | Linux user account dedicated to one hosting |
| Adapter | Module in `lm-adapters` wrapping a single external system tool |
| Orchestrator | `lm-core::HostingService`, coordinates adapters + state |
| RollbackToken | Closure-like handle that undoes one adapter step |
| Rollback stack | LIFO of tokens accumulated during a multi-step operation |
| Secret file | JSON file under `secrets/`, mode 0600, holds passwords / keys |
| Audit log | Append-only hash-chained record of all RPC calls |
| `lm-admin` | Unix group whose members can talk to the agent socket |

---

*End of spec. Next step after user approval: invoke `writing-plans` skill
to produce the step-by-step implementation plan for Foundation.*
