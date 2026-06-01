# Sub-project 7 — WordPress + App Templates — Design Spec

| Field | Value |
|---|---|
| Sub-project | 7 of N — WP / Templates |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation, Controller (1.5), Admin UI (2), Backups (5) |

## 1. Summary

**One-click WordPress install** with admin-curated **packs** (bundles of
plugins + themes that auto-install on every new site of the chosen type).
Admins upload custom plugin/theme zips into a pack via the admin UI; the
controller distributes them to agents on demand. Optional **auto-update**
of WP core and plugins on a schedule. App-template concept generalized so
future engines (Joomla, Ghost) could plug in, but only WordPress ships
in v1.

Implementation uses **`wp-cli`** as the trusted operator-side tool, invoked
by the agent under the hosting's system user.

## 2. Goals

1. From the admin UI: "Create hosting → Install WordPress → Use pack
   'Agency Default'" → site is fully installed and reachable within
   ≈ 60 seconds.
2. `lm hosting wp install <id> --pack agency-default --site-url https://example.cz --admin-email kevin@x.cz`
   from CLI does the same.
3. Admin can upload a pack: name + list of plugin zips + list of theme
   zips + post-install wp-cli command list. Packs are versioned; updates
   to packs apply prospectively (existing sites unaffected unless
   explicit `apply pack` requested).
4. `lm hosting wp update <id> [--core] [--plugins] [--themes]` runs the
   updates; opt-in auto-update schedule per hosting.
5. Built-in safeguards: pre-update backup (sub-project 5); rollback on
   wp-cli failure; site put into maintenance mode during update.

## 3. Non-Goals

- Multi-site WordPress (WP Multisite). Single-site installs only in v1.
- Theme/plugin marketplace UI, ratings, search. Operator curates.
- Visual page builder integration.
- License key vending for premium plugins. Operator embeds the
  pre-licensed zip in the pack manually.
- Non-WP engines (Joomla, Drupal, Ghost). Architecture allows future add.

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | `wp-cli` invoked via `sudo -u <hosting_user>` from agent | Runs file ops with correct ownership |
| D2 | `wp-cli` binary is installed via .deb dep (`wp-cli` not in Debian stable, so we vendor it ourselves: download release tarball into /usr/local/bin during postinst, pinned by SHA-256) | Trusted distribution |
| D3 | WP core downloaded from wordpress.org by wp-cli; cached on the agent under `/var/lib/hyperion/wp-cache/` | Avoid repeat downloads; integrity-checked |
| D4 | Packs stored on controller; distributed to agent via mTLS RPC (chunked stream) on first use; cached agent-side | One source of truth for assets |
| D5 | Each pack is content-hashed (`SHA-256` of canonical manifest + asset hashes); agents pull by hash | Immutable, idempotent install |
| D6 | Auto-update default OFF; opt-in per hosting | Conservative safety default |
| D7 | Maintenance mode toggled via `.maintenance` file as wp-cli does | Standard WP behavior |
| D8 | Pre-update backup is mandatory if a backup target exists; if none configured, prompt warn | Recoverable updates |
| D9 | Plugin/theme upload size limit 64 MiB per file (operator override) | Reasonable bound |
| D10 | DB credentials handed to WP via `wp-config.php` written by agent (not by wp-cli's prompt flow) | Avoid interactive surface |

## 5. State Schema Additions

### 5.1 Controller-side

```sql
CREATE TABLE app_packs (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL CHECK (kind IN ('wordpress')),
    description     TEXT,
    manifest_json   TEXT NOT NULL,                    -- pack manifest
    content_hash    TEXT NOT NULL,                    -- SHA-256
    created_at      INTEGER NOT NULL,
    created_by      INTEGER NOT NULL REFERENCES admin_users(id),
    disabled        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE app_pack_assets (
    pack_id         INTEGER NOT NULL REFERENCES app_packs(id) ON DELETE CASCADE,
    asset_id        TEXT NOT NULL,                    -- ULID
    kind            TEXT NOT NULL CHECK (kind IN ('plugin','theme')),
    filename        TEXT NOT NULL,                    -- e.g. 'akismet.zip'
    sha256          TEXT NOT NULL,
    bytes           INTEGER NOT NULL,
    stored_path     TEXT NOT NULL,                    -- /var/lib/hyperion-controller/packs/<asset_id>.zip
    PRIMARY KEY (pack_id, asset_id)
);
```

Manifest JSON (stored in `app_packs.manifest_json`):

```json
{
  "kind": "wordpress",
  "name": "Agency Default",
  "wp_core": { "version": "latest", "locale": "cs_CZ" },
  "plugins": [
    { "asset_id": "01J7...", "filename": "akismet.zip", "activate": true },
    { "from_repo": "wp-super-cache", "activate": true }
  ],
  "themes": [
    { "asset_id": "01J7...", "filename": "agency-theme.zip", "activate": true }
  ],
  "options": {
    "WP_DEBUG": false,
    "DISABLE_WP_CRON": true,
    "WP_AUTO_UPDATE_CORE": "minor"
  },
  "wpcli_post_install": [
    "rewrite structure '/%postname%/'",
    "rewrite flush --hard",
    "option update blogdescription 'Agency Site'"
  ]
}
```

Plugins can be either `from_repo` (wp-cli downloads from wp.org) or
`asset_id` referencing an uploaded zip.

### 5.2 Agent-side

```sql
CREATE TABLE wp_installs (
    hosting_id           TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    site_url             TEXT NOT NULL,
    wp_version           TEXT NOT NULL,
    installed_at         INTEGER NOT NULL,
    last_pack_hash       TEXT NOT NULL,                -- hash of applied pack at install time
    auto_update_core     TEXT NOT NULL DEFAULT 'off'   -- 'off'|'minor'|'major'
                         CHECK (auto_update_core IN ('off','minor','major')),
    auto_update_plugins  INTEGER NOT NULL DEFAULT 0,
    auto_update_themes   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE wp_update_runs (
    id           INTEGER PRIMARY KEY,
    hosting_id   TEXT NOT NULL REFERENCES hostings(id),
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    scope        TEXT NOT NULL,                       -- 'core'|'plugins'|'themes'|'all'
    state        TEXT NOT NULL,                       -- 'running'|'ok'|'failed'|'rolled-back'
    pre_backup_run_id  INTEGER REFERENCES backup_runs(id),
    output_tail  TEXT
);
```

## 6. RPC Additions

### 6.1 ControllerApi

```rust
async fn pack_create(&self, req: PackCreateReq) -> Result<AppPack, RpcError>;
async fn pack_list(&self) -> Result<Vec<AppPackSummary>, RpcError>;
async fn pack_get(&self, name: String) -> Result<AppPack, RpcError>;
async fn pack_disable(&self, name: String) -> Result<(), RpcError>;
async fn pack_upload_asset(&self, pack: String, asset: AssetSpec, stream: UploadHandle)
    -> Result<AppPackAsset, RpcError>;
async fn pack_remove_asset(&self, pack: String, asset_id: String) -> Result<(), RpcError>;
```

### 6.2 AgentApi

```rust
async fn wp_install(&self, sel: HostingSelector, req: WpInstallReq)
    -> Result<WpInstallSummary, RpcError>;
async fn wp_update(&self, sel: HostingSelector, scope: WpUpdateScope)
    -> Result<WpUpdateSummary, RpcError>;
async fn wp_apply_pack(&self, sel: HostingSelector, pack_name: String, opts: ApplyPackOpts)
    -> Result<WpUpdateSummary, RpcError>;
async fn wp_status(&self, sel: HostingSelector) -> Result<WpStatus, RpcError>;

// Asset distribution: agent pulls assets from controller as needed
async fn pack_fetch(&self, pack_name: String, version_hash: String)
    -> Result<PackBundle, RpcError>;     // streams zips
```

`WpInstallReq { pack_name: Option<String>, site_url: String, admin_user: String,
admin_email: String, admin_password: Option<String>, locale: String }`.
Admin password auto-generated and returned ONCE if not supplied.

## 7. wp-cli Adapter (`wpcli.rs`)

- `core_download(target_dir, locale, version)` — `wp core download
  --path=<target_dir> --locale=<locale> --version=<v>`.
- `core_config(target_dir, db_*)` — writes wp-config.php from a hardened
  template (askama), embedding random salts via `wp config shuffle-salts`
  after init.
- `core_install(target_dir, site_url, title, admin_*)` —
  `wp core install ...`.
- `plugin_install(target_dir, source)` — source is either a URL (from
  wp.org) or a local zip path (from pack cache).
- `theme_install(target_dir, source)`.
- `plugin_activate(target_dir, slug)`, `theme_activate(target_dir, slug)`.
- `cli_run(target_dir, args[])` — generic; used for post-install scripts.
  Args are pre-validated against a regex whitelist
  (`^[a-zA-Z0-9 _.\-/:]+$`) to refuse shell-meta.

All invocations run under `sudo -u <hosting_user>` with `HOME` set to
`/home/<user>/` and `WP_CLI_ALLOW_ROOT=false`.

## 8. Install Flow

```text
01 hosting must exist and be 'active' with a DB attached (refuse otherwise)
02 controller resolves pack_name → AppPack with manifest + assets
03 controller calls agent's wp_install with WpInstallReq
04 agent inserts wp_installs row (provisional)
05 agent fetches pack via pack_fetch (cached by content_hash)
06 wpcli.core_download(/home/<u>/<dom>/htdocs)
07 wpcli.core_config writes wp-config.php with the hosting's DB creds
08 wpcli.core_install with site_url, admin user, generated admin password
09 for each plugin in manifest:
     if from_repo: wpcli.plugin_install(slug)
     else: wpcli.plugin_install(path_to_cached_zip)
     if activate: wpcli.plugin_activate
10 same for themes
11 for each cmd in wpcli_post_install: wpcli.cli_run
12 wpcli set options from manifest.options into wp-config.php (via wp config)
13 take an immediate backup if a 'default' backup policy exists for this hosting
14 update wp_installs (finalize last_pack_hash, wp_version)
15 audit + return WpInstallSummary { admin_url, admin_user, admin_password (one-shot) }
```

Failures roll back: directories created during install removed; DB
contents truncated; wp_installs row marked failed and removed.

## 9. Update Flow

```text
01 verify hosting is active and not currently in another update run
02 if a backup target is configured: backup_now(default-or-pre-update-target)
   else if config[wp.update_requires_backup]=true: refuse
03 INSERT wp_update_runs (state='running', pre_backup_run_id)
04 wpcli `maintenance-mode activate`
05 wpcli `core update` if scope includes core
06 wpcli `plugin update --all` if scope includes plugins
07 wpcli `theme update --all` if scope includes themes
08 wpcli `core update-db`
09 wpcli `maintenance-mode deactivate`
10 health probe: HTTP GET / and check 200
11 UPDATE wp_update_runs state='ok'
12 audit append
```

If any step fails after step 04: maintenance-mode deactivates,
operator alert, run state='failed'. If health probe fails after a
successful update, run `restore_from_snapshot` with pre_backup_run_id's
snapshot; mark state='rolled-back'; alert.

## 10. Admin UI

- `/admin/packs` — list, create, disable. Form to create pack: name +
  textarea for manifest (with JSON schema validation) + drag-drop zip
  uploads.
- `/admin/packs/:name` — detail + add/remove assets + clone.
- Hosting create form gains "Install WordPress" toggle and a pack
  picker.
- Hosting detail page gains a "WordPress" tab showing version,
  installed plugins/themes, auto-update toggles, "Update now" button.

## 11. Configuration Additions

```toml
[wp]
wpcli_path               = "/usr/local/bin/wp"
wpcli_sha256             = "..."          # pinned at install
core_cache               = "/var/lib/hyperion/wp-cache"
update_requires_backup   = true
max_asset_size_bytes     = 67108864       # 64 MiB
auto_update_check_interval = "24h"
```

## 12. Auto-Update Scheduler

A background task in `hyperion-agent` runs daily (configurable):

```text
- select wp_installs where any auto_update_* is enabled
- for each: call wp_update with corresponding scope
- aggregate results into a daily summary, email operator (admin)
  with successes + failures
```

## 13. Testing

- Unit: manifest schema validator; wp-cli argument whitelist; pack
  hash determinism.
- Integration: testcontainer with WP-friendly Debian image. Run a full
  install with a small synthetic pack; verify `/wp-admin/` reachable.
- e2e: nightly VM provisions a hosting + installs WP with the "Agency
  Default" pack, drives logout/login on admin panel via headless
  Chromium, then runs `wp_update` and asserts success.

## 14. Security Notes

- `wp-cli` runs as the hosting's system user, NOT root. The agent's
  privilege boundary stays root-only-for-system-ops.
- Uploaded plugin/theme zips are virus-scanned (clamav) if configured;
  warning otherwise. Path traversal protection during unzip (no `..`).
- Operator-supplied pack manifest JSON validated against a strict
  JSON Schema; rejects unknown keys.
- wp-config.php contains DB password; permissions `0640 root:<user>` so
  the FPM pool can read but the user cannot leak via PHP `var_dump`
  (the file itself is excluded from PHP open_basedir? No — needs to be
  readable; instead we rely on PHP not exposing the file contents in
  responses, which is standard WP).
- `WP_CLI_ALLOW_ROOT=false` enforced.
- Admin password returned at install **once**; not persisted on agent.

## 15. Open Questions

1. **Premium plugin licensing.** Some bundles require activation keys.
   **Proposal:** packs may include a `wpcli_post_install` step like
   `wpcli.cli_run("option update <key> <value>")`; the operator owns
   compliance.
2. **WP multisite.** Not in v1. Architecture allows but UI does not
   surface.
3. **Plugins that need FTP/network at install time.** wp-cli + filesystem
   direct access avoids this; FS_METHOD = direct enforced.
4. **What if pack changes after sites use it.** Packs are versioned by
   content hash; `wp_installs.last_pack_hash` records what was applied.
   "Apply new pack" is an explicit action.

## 16. Glossary Additions

| Term | Meaning |
|---|---|
| Pack | A versioned bundle: WP core version + plugins + themes + post-install scripts |
| Asset | A plugin or theme zip uploaded into a pack |
| Maintenance mode | WP's stock `.maintenance` flag |
| Pre-update backup | Backup taken automatically before `wp_update` |

---

*End of spec.*
