# Sub-project 2 — Admin UI + Auth + Audit Viewer — Design Spec

| Field | Value |
|---|---|
| Sub-project | 2 of N — Admin UI |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation, Controller (1.5) |
| Enables | Sub-projects 3–9 having a UI surface |

## 1. Summary

Adds the **web admin UI** for the controller. Server-rendered HTML
(`askama`) with `HTMX` for partial-page interactivity — no SPA, no
JavaScript build pipeline. Authentication via **password + TOTP**, sessions
in signed HttpOnly cookies, **RBAC** roles (Admin / Operator / Viewer),
and a **searchable audit log viewer** across both controller and agents.

Runs as a new `hyperion-controller-web` binary (or as an in-process axum module
of `hyperion-controller`; see D2 decision below).

## 2. Goals

1. Operator logs in at `https://master.example.com/` with username +
   password + TOTP and lands on a dashboard listing all agents.
2. From any agent's detail page, operator can:
   - list hostings on that agent
   - create / view / delete a hosting
   - view recent audit log
3. From `/audit`, operator can search audit log by actor, action, time
   range, target, and result.
4. UI uses 0 KB of bundled JavaScript beyond HTMX (≈14 KB) and a tiny
   CSS file (≈ 8 KB after gzip).
5. All requests are CSRF-protected, all forms validated server-side.
6. RBAC enforced at handler entry. Viewer role can read; Operator can
   mutate hostings; Admin can manage other admin users + invite agents.
7. Sessions are short (8h sliding) with mandatory re-auth (TOTP only)
   for destructive actions (hosting delete, agent remove).

## 3. Non-Goals

- Client portal (sub-project 6).
- SSO / OAuth / LDAP (out of scope; can be added later as auth module).
- Real-time updates (no WebSockets; periodic HTMX polling for status
  is sufficient).
- Mobile-native app.
- File manager (deferred or never).

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | axum + tower-http for HTTP | Async, type-safe, idiomatic Rust |
| D2 | UI lives in **`hyperion-controller`** binary (same process) | One TLS cert; no extra IPC; controller already has state DB connection. The Unix socket interface for `lmc` CLI remains. |
| D3 | askama templates compiled-in | Compile-time HTML checking; no runtime template parse cost |
| D4 | HTMX for partials | No build step; server stays source of truth; tiny payload |
| D5 | CSS: vanilla, single file, dark+light via prefers-color-scheme | No Tailwind/build complexity |
| D6 | Sessions: signed cookies (Ed25519 key from `/etc/hyperion-controller/session.key`) | No server-side session table for the cookie itself; revocation via `admin_sessions` table |
| D7 | Password hashing: argon2id, params `m=64MiB t=3 p=1` | OWASP recommended |
| D8 | TOTP: `totp-rs`, 30s window, 1 step skew | RFC 6238 |
| D9 | CSRF: double-submit token + Origin/Sec-Fetch-Site check | Standard, no extra storage |
| D10 | RBAC: 3 roles fixed in code: Admin / Operator / Viewer | YAGNI custom roles |
| D11 | Re-auth-for-destructive: confirm by TOTP only (not password again) | Lower friction, still strong |
| D12 | Audit viewer queries both controller log and individual agent logs | Operator wants one place |

## 5. Architecture

```
hyperion-controller binary
├── controller-core (existing)
│   ├── ControllerApi impl
│   ├── state DB
│   ├── CA + agents inventory
│   └── HTTPS server (existing /enroll, /install, /apt)
└── controller-web (NEW in 2)
    ├── axum routes (login, dashboard, agents, hostings, audit)
    ├── askama templates
    ├── HTMX partials
    └── auth middleware (session cookie → AdminId; RBAC check)
```

### 5.1 New crates

```
crates/
├── hyperion-auth/                    password + TOTP + session token primitives
├── hyperion-controller-web/          axum routes, templates, middleware
└── hyperion-csrf/                    tiny crate: token mint + verify
```

### 5.2 Routes

```
GET  /                         redirect to /dashboard or /login
GET  /login                    login form
POST /login                    submit credentials → step 2
GET  /login/totp               TOTP form
POST /login/totp               verify TOTP, set session cookie, redirect
POST /logout                   clear session

GET  /dashboard                agent overview cards
GET  /agents                   table view
GET  /agents/:id               agent detail (hostings, health, audit tail)
POST /agents/invite            (Admin only) create invitation → display token
POST /agents/:id/remove        (Admin only) needs TOTP reconfirm

GET  /hostings                 cross-agent hostings list (joined view)
GET  /hostings/:agent_id/:id   hosting detail
GET  /hostings/new             create form (select agent)
POST /hostings                 submit create, calls AgentApi::hosting_create
POST /hostings/:agent/:id/delete  needs TOTP reconfirm

GET  /audit                    audit search form + results table
GET  /audit/:agent_id          tail one agent's audit log

GET  /admin/users              (Admin only) list admin users
POST /admin/users              (Admin only) create
POST /admin/users/:id/reset    (Admin only) reset password

GET  /me                       account: change password, rotate TOTP
POST /me/password
POST /me/totp/rotate
```

## 6. State Schema Additions (Controller)

```sql
CREATE TABLE admin_users (
    id              INTEGER PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,            -- ^[a-z][a-z0-9_]{2,31}$
    password_hash   TEXT NOT NULL,                   -- argon2id PHC string
    totp_secret_enc TEXT NOT NULL,                   -- AES-GCM(secret), key in /etc/...
    role            TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
    created_at      INTEGER NOT NULL,
    last_login_at   INTEGER,
    disabled        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE admin_sessions (
    id              TEXT PRIMARY KEY,                -- ULID, embedded in cookie
    admin_user_id   INTEGER NOT NULL REFERENCES admin_users(id),
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,                -- sliding 8h
    ip_first_seen   TEXT NOT NULL,
    revoked_at      INTEGER
);
CREATE INDEX admin_sessions_admin ON admin_sessions(admin_user_id);

CREATE TABLE login_attempts (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    username_tried  TEXT NOT NULL,
    ip              TEXT NOT NULL,
    result          TEXT NOT NULL                    -- 'ok' | 'bad_password' | 'bad_totp' | 'locked'
);
CREATE INDEX login_attempts_ip_ts ON login_attempts(ip, ts);
CREATE INDEX login_attempts_user_ts ON login_attempts(username_tried, ts);
```

Initial admin user is created by `lmc admin bootstrap` (run once on
install) — outputs a one-time URL containing a setup token; operator
opens it, sets password, scans TOTP QR.

## 7. Auth Flows

### 7.1 Login

```text
GET /login                → render template
POST /login (user, pwd)   → rate-limit by IP + username
                            (Postgres-style: 5 in 5 min → 1 min lockout
                            with exponential backoff per IP)
                          → fetch admin_users row; verify argon2 hash
                          → if OK, mint a short-lived pre-session
                            cookie (5 min, role=pre_totp, admin_id)
                          → redirect to /login/totp
GET /login/totp           → render template
POST /login/totp (code)   → verify pre-session, verify TOTP code
                          → INSERT admin_sessions; set HttpOnly Secure
                            SameSite=Lax cookie with signed payload
                          → redirect to original dest or /dashboard
```

### 7.2 Session validation middleware

On every request:
1. Read cookie, verify Ed25519 signature.
2. Lookup `admin_sessions.id`; check not revoked, not expired.
3. Slide `last_seen_at`; extend `expires_at = max(expires_at, now+8h)`
   if last extension > 30 min ago (cheap).
4. Attach `AdminContext { admin_id, username, role }` to request
   extensions.
5. RBAC: each handler declares required role via a `RequireRole` extractor.

### 7.3 Destructive action re-auth

For hosting_delete and agent_remove handlers:
1. POST arrives; handler renders confirm page with TOTP input,
   embedded CSRF token, hidden form fields preserving original POST.
2. User enters TOTP; second POST verifies code (against the
   admin's secret, fresh — not the session) and proceeds.

## 8. CSRF

- Each form embeds `<input type="hidden" name="_csrf" value="...">`.
- Token = HMAC(session_id, form_id, timestamp); validity 30 min.
- Middleware checks Origin / Sec-Fetch-Site == same-origin in addition.
- HTMX requests carry the token via `HX-CSRF` header (configured globally
  in the base template).

## 9. RBAC Matrix

| Action | Admin | Operator | Viewer |
|---|---|---|---|
| View dashboard / agents / hostings / audit | ✓ | ✓ | ✓ |
| Create hosting | ✓ | ✓ | – |
| Delete hosting | ✓ | ✓ (with TOTP) | – |
| Invite agent | ✓ | – | – |
| Remove agent | ✓ (with TOTP) | – | – |
| Manage admin users | ✓ | – | – |
| Change own password / TOTP | ✓ | ✓ | ✓ |

## 10. Templates Layout

```
crates/hyperion-controller-web/templates/
├── base.html                  layout shell: header, nav, flash, footer
├── login.html
├── login_totp.html
├── dashboard.html
├── agents/
│   ├── list.html
│   └── detail.html            HTMX partials for tabs
├── hostings/
│   ├── list.html
│   ├── detail.html
│   ├── new.html
│   └── _row.html              HTMX swap target
├── audit/
│   ├── search.html
│   └── _row.html
├── admin/
│   ├── users.html
│   └── user_edit.html
└── me/
    ├── password.html
    └── totp.html
```

CSS lives in a single `static/app.css` served with strong cache headers.
HTMX is vendored at `static/htmx.min.js`.

## 11. Audit Viewer

`GET /audit` accepts query params:
- `actor=<uid|label>`
- `action=<glob>` (e.g. `hosting.*`)
- `from=<iso8601>`, `to=<iso8601>`
- `result=ok|error|all`
- `agent=<id>` (default = controller only; `all` joins all agents)

When `agent=all`, the controller fans out a `audit_query` RPC call to
every active agent, merges results in memory, and renders a single
paginated table. Pagination is keyset by `(ts, id)` — `GET /audit?cursor=...`.

New RPC method on `AgentApi`:
```rust
async fn audit_query(&self, q: AuditQuery)
    -> Result<Vec<AuditEntry>, RpcError>;
```

## 12. Configuration Additions

```toml
[web]
listen          = "0.0.0.0:443"
public_hostname = "master.example.com"
session_key_path = "/etc/hyperion-controller/session.key"
totp_kek_path    = "/etc/hyperion-controller/totp-kek.key"
session_idle_ttl = "8h"
session_abs_ttl  = "30d"
totp_kek_path    = "/etc/hyperion-controller/totp-kek.key"

[web.rate_limit]
login_attempts_window = "5m"
login_attempts_max    = 5
ip_block_after        = 20
```

## 13. Testing

- Unit: argon2 verify, TOTP verify, CSRF mint/verify (proptest on
  cookie tamper).
- Integration: spin up `hyperion-controller` in a test fixture, drive it with
  `reqwest` cookie jar; flow tests for login + role gating.
- e2e: `playwright` over a real browser hitting nightly VM
  (headless Chromium) — login, create hosting on a test agent, delete.
- Fuzzing: cookie deserializer, CSRF token verifier.

## 14. Security Notes

- Session cookie payload: `<base64(session_id || created_at)>.<sig>`.
- TOTP secrets encrypted at rest with a Key-Encryption-Key (KEK) at
  `/etc/hyperion-controller/totp-kek.key` (mode 0600). KEK rotation
  is a future operator runbook; not required for sub-project 2.
- All cookies have `Secure; HttpOnly; SameSite=Lax`.
- CSP: `default-src 'self'; img-src 'self' data:; style-src 'self';
  script-src 'self'; connect-src 'self'; frame-ancestors 'none'`.
- HSTS: `max-age=31536000; includeSubDomains; preload`.
- Per-IP rate limit on `/login*` and `/me/totp/rotate`.

## 15. Open Questions

1. **Password reset by another admin** vs self-serve "forgot password"
   via email. **Proposal:** Admin-only reset in 2; email-based reset is
   future (requires email infra; deferred).
2. **WebAuthn / passkeys** instead of TOTP. **Proposal:** TOTP is plenty
   for an internal admin panel; passkeys can be added as a second factor
   later without breaking the schema (table `admin_webauthn_credentials`).
3. **Localization.** English only in v1 (template language tag = `en`).
   Czech/etc. via standard i18n later.

## 16. Glossary Additions

| Term | Meaning |
|---|---|
| Admin user | A row in `admin_users`; identity for the web UI |
| Pre-session | Short cookie after password, before TOTP |
| Session | A long cookie after TOTP; revocable via `admin_sessions` |
| KEK | Key Encryption Key used to encrypt TOTP secrets at rest |
| Re-auth | Per-action TOTP confirmation for destructive operations |

---

*End of spec.*
