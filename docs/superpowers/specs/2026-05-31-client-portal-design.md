# Sub-project 6 — Client Portal — Design Spec

| Field | Value |
|---|---|
| Sub-project | 6 of N — Client Portal |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation, Controller (1.5), Admin UI (2), Limits/Suspend (3), Expiration (4), Backups (5) |

## 1. Summary

A self-service **portal for end clients** of an agency: client logs in,
sees the hostings they own, current cost, expiration date, resource
usage, and can manage their own **SFTP/FTP login accounts** for each
hosting. Optional **TOTP** as second factor. Optional **restore-from-
snapshot** by the client themselves (off by default, opt-in per hosting).

Lives in the same `lm-controller` process as the admin UI, served under
`/client/*` with a separate auth realm and separate cookie name.

## 2. Goals

1. `lmc client create --email kevin@example.cz --hosting node1:example.cz`
   sends an invite email; client clicks → sets password → optionally
   sets up TOTP → lands on dashboard.
2. Client dashboard shows, per owned hosting: domain, expiration, days
   remaining, monthly price, disk used/quota, bandwidth used/quota,
   recent snapshots count.
3. Client can add additional SFTP/FTP users to a hosting (each gets its
   own chroot under the hosting's webroot) and revoke them. Cap of 5 by
   default (operator-configurable).
4. Client can change own password / TOTP / contact email.
5. Client cannot: delete hosting, change limits, move hosting, see
   other clients' data, manipulate billing fields.
6. Optional per-hosting **client_can_restore** flag: when on, client may
   trigger `restore_from_snapshot` from snapshots tied to their hosting.
7. All client actions are audited; emails to client are logged.

## 3. Non-Goals

- Billing engine, invoice generation, payment processing. Display only.
- Multi-tenant agencies (one operator's clients only).
- Marketplace / add-ons.
- Live chat / support tickets.
- "Switch language" UI; English + Czech static translations only in v1.

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Same `lm-controller` process, `/client/*` route prefix | Reuse template engine, mailer, DB; one TLS cert |
| D2 | Separate `clients` and `client_sessions` tables; distinct cookie name (`lm_client`) | Realm separation; no privilege confusion |
| D3 | Password + TOTP (TOTP optional but encouraged via UI nudge) | Friction balance for end clients |
| D4 | Invitation flow: admin creates client → email with single-use 7-day token → client sets password | No self-registration |
| D5 | SFTP user mgmt: each "client SFTP user" is a real Debian user in a sub-group; OpenSSH chroot to hosting root | Standard, robust |
| D6 | Client-triggered restore: gated by `client_can_restore` per hosting; OFF by default | Safe default |
| D7 | UI language picked from `Accept-Language` (Czech, English) with manual override in profile | Common UX |
| D8 | Email visual identity is operator-brandable via theme files | Agency branding |
| D9 | No password reset by email out of the box; admin-reset only | Phishing-resistant; reset via email can be added later |
| D10 | Client can view audit entries scoped to their hostings | Transparency |

## 5. State Schema Additions (Controller)

```sql
CREATE TABLE clients (
    id              INTEGER PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    display_name    TEXT,
    password_hash   TEXT,                            -- NULL until first set
    totp_secret_enc TEXT,                            -- NULL until set
    created_at      INTEGER NOT NULL,
    last_login_at   INTEGER,
    disabled        INTEGER NOT NULL DEFAULT 0,
    locale          TEXT NOT NULL DEFAULT 'en'       -- 'en' | 'cs'
);

CREATE TABLE client_invitations (
    token_hash      TEXT PRIMARY KEY,
    client_id       INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    expires_at      INTEGER NOT NULL,
    consumed_at     INTEGER
);

CREATE TABLE client_hostings (
    client_id       INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    agent_id        TEXT NOT NULL REFERENCES agents(id),
    hosting_id      TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'owner'
                    CHECK (role IN ('owner','collaborator')),
    can_restore     INTEGER NOT NULL DEFAULT 0,
    can_manage_sftp INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (client_id, agent_id, hosting_id)
);

CREATE TABLE client_sessions (
    id              TEXT PRIMARY KEY,
    client_id       INTEGER NOT NULL REFERENCES clients(id),
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    ip_first_seen   TEXT NOT NULL,
    revoked_at      INTEGER
);

-- per-hosting additional SFTP users; lives on AGENT side
-- (controller mirrors for display, but agent is authoritative)
```

## 5.1 Agent-side schema

```sql
CREATE TABLE sftp_users (
    id              INTEGER PRIMARY KEY,
    hosting_id      TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    username        TEXT NOT NULL UNIQUE,            -- e.g. 'example_cz_sftp1'
    uid             INTEGER NOT NULL UNIQUE,
    -- linux user is a *member* of the hosting's primary group
    -- chrooted to /home/<owner>/<domain>/ via OpenSSH Match block
    public_key      TEXT,                            -- optional; password also allowed
    password_hash   TEXT,                            -- yescrypt or argon2 (for FTP/SFTP password auth)
    created_at      INTEGER NOT NULL,
    created_by      TEXT NOT NULL                    -- 'admin' | 'client:<id>'
);
```

## 6. RPC Additions

### 6.1 ControllerApi

```rust
async fn client_create(&self, req: ClientCreateReq) -> Result<ClientSummary, RpcError>;
async fn client_invite(&self, id: ClientId) -> Result<InviteHandle, RpcError>;
async fn client_list(&self) -> Result<Vec<ClientSummary>, RpcError>;
async fn client_attach_hosting(&self, link: ClientHostingLink) -> Result<(), RpcError>;
async fn client_detach_hosting(&self, link: ClientHostingLink) -> Result<(), RpcError>;
async fn client_set_flags(&self, link: ClientHostingLink, flags: ClientHostingFlags)
    -> Result<(), RpcError>;
async fn client_reset_password(&self, id: ClientId) -> Result<InviteHandle, RpcError>;
async fn client_disable(&self, id: ClientId) -> Result<(), RpcError>;
```

### 6.2 AgentApi additions

```rust
async fn sftp_user_list(&self, sel: HostingSelector) -> Result<Vec<SftpUser>, RpcError>;
async fn sftp_user_create(&self, sel: HostingSelector, spec: SftpUserSpec)
    -> Result<SftpUser, RpcError>;
async fn sftp_user_update(&self, id: SftpUserId, patch: SftpUserPatch)
    -> Result<(), RpcError>;
async fn sftp_user_delete(&self, id: SftpUserId) -> Result<(), RpcError>;
```

`SftpUserSpec { username: SystemUserName, auth: SftpAuth }` where
`SftpAuth { password: Option<String>, ssh_public_key: Option<String> }`.

## 7. Adapter Additions

### 7.1 `linux-user.rs` (extend)

- `ensure_sftp_user(spec, owner_uid, hosting_root)` —
  `useradd -M -d <hosting_root> -s /usr/sbin/nologin -g <owner_group> <name>`,
  set password via `chpasswd` if specified, write `.ssh/authorized_keys`
  under the user's HOME (which is the hosting root or a dedicated
  per-user sub-path) if public key specified. Adds to `lm-sftp-users`
  Debian group (for OpenSSH Match block).

### 7.2 `openssh.rs` (new)

- Manages a single drop-in file `/etc/ssh/sshd_config.d/50-lm.conf`
  containing:

  ```sshd_config
  Match Group lm-sftp-users
    ChrootDirectory %h
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
  ```
- Idempotent ensure on agent start.

## 8. Client UI Routes

```
GET  /client/                redirect → /client/dashboard or /client/login
GET  /client/login           email + password form
POST /client/login           credentials → step 2 (TOTP if set up)
GET  /client/login/totp      TOTP form
POST /client/login/totp
POST /client/logout
GET  /client/invite/:token   accept invite, set initial password, opt TOTP

GET  /client/dashboard       cards per hosting (price, expiry, usage)
GET  /client/hostings/:agent/:id  hosting detail
GET  /client/hostings/:agent/:id/sftp   list SFTP users
POST /client/hostings/:agent/:id/sftp   create
POST /client/hostings/:agent/:id/sftp/:user/delete
GET  /client/hostings/:agent/:id/backups  list snapshots (if visible)
POST /client/hostings/:agent/:id/restore  (only if client_can_restore)
GET  /client/hostings/:agent/:id/audit    scoped audit entries

GET  /client/me              account settings
POST /client/me/password
POST /client/me/totp/enable  shows QR
POST /client/me/totp/disable
POST /client/me/email-change request
```

## 9. Dashboard Card Contents

For each owned hosting:

```
┌──────────────────────────────────────────────────────────────┐
│  example.cz                                             [⚙]  │
│  status: active   expires: 2027-06-30 (395 days)             │
│  price: 1490 Kč / year                                       │
│  disk:  427 MiB / 5 GiB                          [▓░░░░ 8%]  │
│  bw:    3.2 GiB / 50 GiB this month              [▓░░░░ 6%]  │
│  backups: last @ 2026-05-31 04:00, 14 snapshots              │
└──────────────────────────────────────────────────────────────┘
```

Data sources: controller's `controller_hostings` (price/expiry) + agent's
`hosting_get` (live limits + last `hosting_usage` row).

## 10. SFTP User Self-Service Flow

```text
Client navigates to /client/hostings/n1/example.cz/sftp
- Render existing sftp_users; "Add user" button visible if
  count < max_sftp_users_per_hosting (default 5)

POST /client/hostings/.../sftp  with form fields:
  - username (auto-prefixed: example_cz_sftp<N>)
  - auth method: password OR ssh key
  - password (if chosen): server enforces zxcvbn score >= 3
  - public key (if chosen): validated as ssh-rsa | ed25519

Controller -> proxy to agent: sftp_user_create
  - validates input
  - creates Linux user member of hosting's group + lm-sftp-users group
  - inserts row in sftp_users
  - writes authorized_keys if public key

Response: rendered HTMX partial showing the new user.
```

## 11. Client-Triggered Restore (opt-in)

Only when `client_hostings.can_restore = 1`.

```
GET /client/hostings/n1/example.cz/backups
  shows snapshot list with timestamps + sizes; "Restore" button.

POST .../restore { snapshot_id, target_target }
  - server confirms via TOTP (re-auth)
  - controller proxies to agent: restore_from_snapshot
  - returns progress page; polled via HTMX every 2s

Restrictions:
  - cannot restore to a different hosting
  - cannot restore an aborted/failed migration's source snapshot
```

## 12. Configuration Additions

```toml
[client]
max_sftp_users_per_hosting = 5
invite_ttl                 = "7d"
require_totp               = false   # if true, dashboard refuses access until set up
locale_default             = "cs"
```

## 13. Email Templates

```
client_invite.subject.txt        "{{ operator_name }} – přístup k portálu hostingu"
client_invite.html.j2            single-use link, expires in 7 days
client_invite.txt.j2

client_password_changed.{html,txt}.j2

client_sftp_created.{html,txt}.j2
```

## 14. Testing

- Unit: invite token mint/verify; zxcvbn integration; SFTP username
  validator.
- Integration: drive controller with `reqwest` cookie jar via `/client/*`;
  assert RBAC isolation (client A cannot view client B's hosting).
- Adapter: testcontainers with OpenSSH; create SFTP user; assert
  chroot-restricted login via plain `ssh` client.
- e2e: nightly VM full path: admin invites client → client sets password
  + TOTP → creates SFTP user → logs in via SFTP and lists files.

## 15. Security Notes

- `clients` and `admin_users` are strictly separate tables; cookie names
  differ; middleware refuses any cross-realm access (admin endpoints
  reject client cookie and vice versa).
- Client cookies have a shorter idle TTL (default 2 h) than admin (8 h).
- Per-hosting authorization checked on every request: a row in
  `client_hostings` must exist for `(authenticated_client_id, agent_id,
  hosting_id)`.
- SFTP user passwords stored via `chpasswd` (system shadow), not in
  SQLite.
- Invite tokens hashed (BLAKE3) before persistence; transmitted via
  HTTPS only.
- CSRF protection identical to admin UI.

## 16. Open Questions

1. **Allowing client to download backup archives directly.** Convenient
   but exposes ~GB streams to the client portal. **Proposal:** off in v1;
   operator can email a presigned URL for an S3 target if asked.
2. **Email change verification.** Two-step (current email confirms,
   new email confirms) or one-step admin approval. **Proposal:**
   two-step automatic in v1; defer admin approval gate to settings.
3. **Multiple owners per hosting.** Schema allows `role=collaborator`
   but UI surfaces only owner. **Proposal:** collaborator UI is YAGNI
   in v1; schema is forward-compat.

## 17. Glossary Additions

| Term | Meaning |
|---|---|
| Client | An end customer of the operator; logs in to view their hostings |
| Realm | A separate auth context: `admin` realm vs `client` realm |
| Invite | A one-time link to set initial credentials |
| SFTP user | A Linux user attached to a hosting for file access |
| Self-restore | A client-triggered `restore_from_snapshot` (opt-in per hosting) |

---

*End of spec.*
