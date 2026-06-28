# Custom roles (granular RBAC) + profile rename — design

**Status:** approved (design) · **Date:** 2026-06-28 · **Branch:** `feat/custom-roles`

## Goal

Two features:

1. **Profile rename** — let an admin change a hosting profile's name from the
   edit form (small; the backend already persists it).
2. **Custom roles** — let a super-admin build a role by ticking granular
   capabilities ("what it can and can't do") plus a scope, on top of the
   existing five built-in roles, which keep working unchanged.

## Background (current state)

- Roles are a fixed enum `WebRole { SuperAdmin, Admin, Operator, Customer, Viewer }`
  (`crates/hyperion-state/src/web_users.rs`), stored as a string in `web_users.role`
  and carried in the signed `Session` (`crates/hyperion-auth/src/session.rs`).
- Authorization is ~120 hardcoded checks in the web layer:
  `is_super_admin` (~38), `is_admin_or_higher` (~60), `is_read_only` (~5),
  and `require_hosting_access(...)` (~18, per-hosting tenant scope via
  `web_user_hosting_access`).
- Two orthogonal axes already exist implicitly: **capabilities** (what actions)
  and **scope** (`sees_all_hostings` vs tenant-scoped `is_tenant_scoped`).

## Decisions (locked)

- **Approach:** capability layer *alongside* the built-ins. Built-ins keep
  working; a capability system is added underneath; custom roles are defined
  purely by their checked capabilities. No big-bang rewrite.
- **Granularity:** grouped capabilities (~30, by area) + a scope toggle.
- **Roles page:** dedicated `/roles`, super-admin only, linked near Users.

## 1. Capability model

`Capability` — a `#[repr(u64)]`-style bitflag enum (one bit each), grouped for
the UI. Stored/serialized as a `u64` bitmask (`CapSet`). Groups + members:

- **Hosting:** `HostingView`, `HostingCreate`, `HostingDelete`, `HostingSuspend`,
  `HostingEditConfig`, `HostingFiles`, `HostingDatabases`, `HostingCron`,
  `HostingMigrateClone`
- **WordPress:** `WpManage`, `WpVulnView`
- **Backups:** `BackupRun`, `BackupRestore`, `BackupTargets`
- **TLS:** `CertManage`
- **Security:** `SecurityManage` (WAF, fail2ban/bans, firewall dashboard)
- **Monitoring:** `MonitoringView`, `MonitoringManage`
- **Cluster:** `NodesView`, `NodesManage` (enroll/revoke/update/install),
  `ServicesView`, `ServicesManage` (restart, ROFS fix)
- **Platform:** `UsersManage`, `RolesManage`, `SettingsManage`, `ProfilesManage`,
  `AuditView`, `EmailLogView`, `PanelImport`, `TrashManage`

Lives in `hyperion-state` (next to `WebRole`) with a `groups()` metadata table
(group label → ordered caps + human labels) that the builder UI renders from, so
the checkbox page and the enum can never drift.

### Scope axis (separate from caps)

A role also carries `scope_all_hostings: bool`:
- `true` → sees/acts on all hostings (admin-like; `sees_all_hostings`).
- `false` → only hostings granted via `web_user_hosting_access` (tenant-like;
  `is_tenant_scoped`).

## 2. Built-ins as capability presets

`WebRole::capabilities() -> CapSet` and `WebRole::scope_all() -> bool` define a
fixed preset per built-in. **Built-in behavior must be byte-for-byte unchanged**
(asserted by unit tests on the capsets + the existing web e2e):

| Built-in    | Scope     | Capabilities |
|-------------|-----------|--------------|
| SuperAdmin  | all       | everything (all 30) |
| Admin       | all       | everything **except** `UsersManage`, `RolesManage` |
| Operator    | assigned  | all Hosting + WP + `BackupRun`/`BackupRestore` + `CertManage` + `SecurityManage` + `MonitoringView`/`MonitoringManage` |
| Customer    | assigned  | `HostingView`, `HostingFiles`, `HostingDatabases`, `WpManage`, `WpVulnView`, `BackupRun`, `BackupRestore`, `CertManage`, `MonitoringView` (slim nav) |
| Viewer      | assigned  | `*View` caps only (`HostingView`, `WpVulnView`, `MonitoringView`), read-only |

(Exact operator/customer sets are tuned during Phase 4 to match today's gates;
parity is the acceptance bar.)

Built-ins render in the UI as read-only presets with a **"Clone to custom role"**
button that pre-fills the builder.

## 3. Storage

- Migration `NNN_custom_roles.sql`:
  - `custom_roles (id INTEGER PK, name TEXT UNIQUE NOT NULL, capabilities INTEGER NOT NULL, scope_all_hostings INTEGER NOT NULL, created_at INTEGER, updated_at INTEGER)`.
  - `ALTER TABLE web_users ADD COLUMN custom_role_id INTEGER NULL REFERENCES custom_roles(id)`.
- A user's effective role: if `custom_role_id` is set → custom role's caps+scope;
  else → built-in from `role` string. `role` for a custom-role user is stored as
  the sentinel `"custom"` (keeps the column non-null + the existing display path
  working through a label lookup).
- `hyperion-state::custom_roles`: `create`, `list`, `get`, `update`, `delete`,
  `count_in_use` (mirrors `profiles`), with a duplicate-name guard.

## 4. Enforcement

- At login the agent resolves the user's **`CapSet` + `scope_all`** and stamps
  them into the signed `Session` (new fields `caps: u64`, `scope_all: bool`).
  Signed → tamper-proof. Sessions minted before the upgrade lack the fields →
  `AuthCtx` falls back to deriving caps from the built-in `role` string, so live
  sessions keep working across the deploy.
- `AuthCtx::can(Capability) -> bool` (and `require_cap(Capability) -> Result`)
  read the session caps.
- The existing helpers are **re-expressed** via caps for the fallback/derivation,
  and the ~120 gates are converted **area-by-area** from coarse role checks to
  `ctx.can(Cap::X)`. Built-ins carry the matching caps so behavior is identical;
  custom roles are then governed purely by their checkboxes. **Default-deny:** a
  custom role gets only what is ticked.
- `require_hosting_access` keeps its per-hosting grant logic but consults
  `scope_all` (all-scope roles bypass the grant table) + the relevant cap
  (view vs manage).

## 5. UI — the role builder

- **`/roles`** (super-admin only; sidebar → Cluster group): table of built-in
  (read-only, with Clone) + custom roles (Edit/Delete), each showing scope + a
  capability count.
- **New / Edit / Clone** → builder form: name, scope radio (all / assigned), and
  the capability checkboxes rendered from `Capability::groups()` with a
  "select all in group" toggle per group. CSRF via `_csrf`.
- **User create/edit** role `<select>` gains an optgroup of custom roles.

## 6. Safety guards

- **`RolesManage` is super-admin-only in v1** (not delegatable) — it is the keys
  to the kingdom. The `/roles` routes gate on `is_super_admin()`.
- **No privilege escalation:** a non-super-admin with `UsersManage` cannot
  create/elevate a super-admin, nor assign a role carrying caps they don't hold.
- **In-use guard:** a custom role assigned to ≥1 user can't be deleted
  (mirrors `profiles::count_in_use`); the UI shows the count.
- **Last-super-admin guard:** existing protection preserved (can't demote/delete
  the final super-admin).
- Built-in roles cannot be edited or deleted.

## 7. Profile rename (bundled)

Add a `name` text input to `profile_edit.html`; `post_update` reads it into the
`ProfileRow` it already passes to `profiles::update()` (which persists `name`).
Trim + reuse the create-form's duplicate-name handling. ~10 lines + template.

## 8. Implementation phases

1. **Capability model** — `Capability` + `CapSet` + `groups()` + built-in
   presets in `hyperion-state`; unit tests (bitmask round-trip, preset contents).
2. **Storage** — migration + `custom_roles` CRUD + duplicate/in-use guards;
   `web_users.custom_role_id` + effective-role resolution; RPC
   (`RoleCreate/List/Update/Delete`) + dispatch + agent impl.
3. **Session + AuthCtx** — resolve caps+scope at login, add to `Session`,
   `AuthCtx::can`/`require_cap`, helper re-expression + pre-upgrade fallback.
4. **Enforce** — convert authz gates area-by-area to `can(Cap)`; keep built-ins
   identical (parity is the bar).
5. **UI** — `/roles` list + builder, user role dropdown, guards.
6. **Profile rename.**
7. **Verify** — `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, `cargo fmt --all --check`, web build; PR.

## 9. Testing

- Unit: each built-in `WebRole::capabilities()` equals its documented set;
  `CapSet` u64 round-trip; `scope_all` per role.
- Authz: a `HostingView`-only custom role is refused create/delete/suspend; an
  all-scope custom role bypasses the grant table; a custom role without
  `UsersManage` 403s on `/users`.
- Guards: delete-in-use refused; non-super-admin can't reach `/roles`;
  escalation attempt (grant cap you lack / create super-admin) refused.
- Existing `web_e2e` continues to pass (built-in admin/viewer flows).

## 10. Out of scope (v1)

- Delegatable role management (RolesManage stays super-admin-only).
- Per-capability *per-hosting* overrides (caps are role-wide; per-hosting stays
  the existing view/manage grant).
- CLI (`hctl`) role management (RPC exists; UI is the surface).
