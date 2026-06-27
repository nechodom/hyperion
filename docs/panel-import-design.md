# Hyperion Panel Import — design & implementation plan

**Status:** design proposal (approved direction; implementation starting at P0). Free-time project — ship incrementally, MVP first.
**Date:** 2026-06-27
**Origin:** GitHub issue #1 (HestiaCP migration support) + CloudPanel import; maintainer requirement: import must run **agent-side on the node**, including in-place conversion of a live Hestia/CloudPanel box.

---

## Decisions for v1 (answers to the open questions)

1. **CloudPanel archive format** — we WILL define our own export tar (per-site `htdocs` tar + cert `.crt`/`.key` + crontab lines + SQLite-derived metadata JSON + per-DB `.sql.gz`), produced by a small `hctl` helper run on the source box. **Not in P0** (P0 is in-place only); archive mode lands in P1.
2. **DB credentials** — v1 **resets** the DB password (`hosting_create` mints fresh + `db_reset_password`) and **rewrites the app config** (`wp-config.php` etc.) during file staging. Carrying MySQL/PG auth hashes is **P2** (for non-WP apps that can't be config-rewritten).
3. **Domain conflict** — v1 ships **Skip-on-conflict only**. "Rename alias" → P1; guarded "overwrite" → P2.
4. **Remote SSH key** — handled **ephemerally**: written to a `0600` temp file for the job, deleted on completion, **never persisted to the DB**; if a field is unavoidable on the wire it goes through `RedactedFields`. Remote mode is P1.
5. **Mail & DNS — permanently out of scope (maintainer decision).** Hyperion will not implement email or DNS-server management, so the importer never imports mail or DNS and builds **no** export tooling for them. It only *reports* that they exist (e.g. "this Hestia box had N mailboxes / N zones — migrate them separately"). No mail/DNS code, in any phase.
6. **Node/Python/proxy sites** — map to Hyperion `kind="reverse_proxy"` + `proxy_upstream_url`. **P0 covers PHP + static only**; proxy-type sites are flagged `Unsupported` in the P0 dry-run and added in P1.

---

## 1. Goal & scope

### In scope (whole feature)
- Read a source panel's state (live box / remote over SSH / uploaded export) and recreate the equivalent hostings in Hyperion **on the node itself**, **reusing** `hosting_create` + `backup_restore` rather than re-implementing provisioning.
- Two source adapters (`HestiaAdapter`, `CloudPanelAdapter`) behind a common trait → panel-neutral intermediate representation (IR).
- Three source-location modes: **in-place**, **remote (ssh/rsync pull)**, **archive (uploaded export)**.
- A **dry-run plan** previewing create/skip/conflict/unsupported before any write.

### Explicitly OUT for v1
- **Mail — out of scope, permanently.** Hyperion will not implement email management (maintainer decision). CloudPanel manages no mail anyway; Hestia's Exim/Dovecot mailboxes are **not** imported and no export tooling is built — the importer only notes they exist.
- **Authoritative DNS — out of scope, permanently.** Hyperion will not run or manage a DNS server (maintainer decision). Neither panel's zones are recreated or exported; the importer only notes that DNS lives elsewhere and must be migrated separately.
- FTP accounts, multi-mailbox, billing-from-source, source audit trail, atomic whole-box convert.

### Honesty rule (in the UI)
CloudPanel source → state plainly "mail & DNS were never managed by CloudPanel" (not "0 mailboxes/zones"). Hestia source with mail/DNS → "exported to report, not imported (unsupported in v1)".

---

## 2. Architecture

```
 source panel │ SourceAdapter (trait): HestiaAdapter / CloudPanelAdapter
              │   detect() → extract() → ImportIR
              ▼ ImportIR (panel-neutral)
 target side  │ ImportPlanner → ImportPlan (dry-run)
              │ ImportEngine.apply(plan) ON THE NODE
              │   reuse HostingService::create() + backup_restore(FilesAndDb)
```

The adapter knows only the source panel; the engine knows only Hyperion; the IR is the contract. A third adapter (cPanel/Plesk) is then a pure additive change.

### Data flow (4 stages)
1. **detect** — `SourceAdapter::detect(&Location) -> Option<SourcePanelInfo{kind, version, subsystems_enabled}>`. Hestia: `/usr/local/hestia/conf/hestia.conf` (+ Vesta variant), read `*_SYSTEM` flags to skip disabled subsystems. CloudPanel: `/home/clp/htdocs/app/data/db.sq3`, `clpctl --version` for v1-vs-v2 CLI drift.
2. **extract → IR** — CLI-preferred, flat-file/SQLite fallback. **No writes to target.** DB dumps produced lazily at apply (avoid 2× disk → `du`/`df` preflight, like `backup_now`).
3. **dry-run plan** — `ImportPlanner::plan(ir, opts) -> ImportPlan`: one `PlannedHosting` per source site with the exact `HostingCreateReq`, the DBs, conflict status vs existing hostings, per-item `Action ∈ {Create, Skip, Conflict, Unsupported}`. The key safety feature.
4. **apply on node** — `ImportEngine::apply(plan)` as a background job (`job_start`/`job_progress`/`job_finish`): per hosting → build `HostingCreateReq` → `HostingService::create()` in-process → stage files + DB dump into a restore archive → `backup_restore(mode=FilesAndDb)` → re-apply crontab → `chown` fixups → cert/SSH. Rollback on failure = delete the half-created hosting (same as `hosting_import`). Batch continues past a failed item.

### Source-location modes
| Mode | Adapter reads from | How files/DBs reach the node |
|---|---|---|
| **in-place** | local FS of *this* node (`/usr/local/hestia/…`, `/home/clp/…`, `v-*`/`clpctl`) | already local — no transfer |
| **remote** | SSH into source; same detect/extract over the wire; `rsync -aHAX --numeric-ids` + dump-over-ssh | staged under `/var/lib/hyperion/migration/<job>/`; **node initiates the pull, never the master** |
| **archive** | uploaded export tar staged on node | already in staging dir |

### Mapping onto Hyperion's real model
Import engine lives in `hyperion-core`, runs **inside the agent** (same place `create()`/`backup_restore` run) → satisfies "agent-side, not master-proxied". New RPCs `hosting_import_panel` + `hosting_import_panel_plan` on the `AgentApi` trait (`hyperion-rpc/src/api.rs`) + `codec.rs` variants (no secrets in the variant; paths/creds by reference to on-node files; `RedactedFields` if unavoidable). Web wizard dispatches via `dispatch_to_node()` (`bin/hyperion-web/src/dispatcher.rs:90`) with `target_node_id` = the node being converted; for remote sources the *node* opens the SSH pull. **Reuse:** `hosting_create`, `backup_restore(FilesAndDb)`, `db_reset_password`, `cert_upload`, `cert_issue_acme`, the `job_*` family, `dispatch_to_node()`.

---

## 3. Entity mapping (S = reuse existing · N = new Hyperion feature · O = out v1)

### HestiaCP → Hyperion
| Source entity | Source of truth | Hyperion target | v1 |
|---|---|---|---|
| Web site/vhost | `data/users/<u>/web.conf` / `v-list-web-domains` | `HostingCreate` | S |
| PHP version | `web.conf BACKEND` (`PHP-8_2`→`php8.2`) | `HostingCreateReq.php_version` | S |
| Docroot | `/home/<u>/web/<d>/public_html` | staged → `backup_restore` + chown | S |
| Database (+charset) | `db.conf` (DB/TYPE/CHARSET, `<user>_` prefix) | `HostingCreateReq.database` | S |
| DB user/grants | `db.conf DBUSER/MD5` | implicit at create; fresh pw + `db_reset_password` | S |
| DB data | `v-backup-user` or `mysqldump --default-character-set=utf8mb4` | `backup_restore` | S |
| Cron | `cron.conf` / `/var/spool/cron/crontabs/<u>` | re-applied (filter Hestia `admin` crons) | S |
| SSL (real) | `data/users/<u>/ssl/<d>.pem` + `.key` | `cert_upload` | S |
| SSL (`LETSENCRYPT=yes`) | — | re-issue via `cert_issue_acme` | S |
| Mail / DNS | — | none — **permanently out of scope** | O (note only; never imported or exported) |
| FTP / SSH keys | `web.conf FTP_*` / `~/.ssh/authorized_keys` | `sftp_set` (needs hosting first) | N (P1) |

### CloudPanel → Hyperion
| Source entity | Source of truth | Hyperion target | v1 |
|---|---|---|---|
| Site/vhost | `db.sq3` `site` + `/etc/nginx/sites-enabled/<d>.conf` | `HostingCreate` (type php/static; node/python/proxy→`reverse_proxy`) | S (proxy P1) |
| PHP version | `db.sq3` `php_settings` | `php_version` | S |
| Docroot | `/home/<site-user>/htdocs/<domain>/<root>` | staged → `backup_restore` + chown (multi-domain per user!) | S |
| Database (+charset) | `db.sq3` `database`/`database_server` join | `database` at create | S |
| DB user/grants | `db.sq3` `database_user` (pw encrypted) | implicit + `db_reset_password` | S |
| DB data | `clpctl db:export` (v2) / `db:backup` (v1) → `.sql.gz` | `backup_restore` (version-gate CLI) | S |
| Cron | `/var/spool/cron/crontabs/<u>` **and** `/etc/cron.d/<u>` | re-applied | S |
| SSL | `/etc/nginx/ssl-certificates/<d>.crt` + `.key` (flat dir) | `cert_upload` (`openssl x509 -noout` first — `\n\n` bug) | S |
| SSH keys | `db.sq3` `ssh_user` + `~/.ssh/authorized_keys` | `sftp_set` (post-create) | N (P1) |
| Mail / DNS / FTP | — | **N/A — never managed by CloudPanel** | O (state to operator) |

---

## 4. New code

New crate **`crates/hyperion-import/`**:
- `ir.rs` — `ImportIR`, `IrHosting`, `IrDatabase`, `IrCron`, `IrCert`, `IrUnsupported{mail,dns,ftp}` (so the report enumerates skips).
- `adapter.rs` — `trait SourceAdapter { fn detect(&Location) -> Option<SourcePanelInfo>; fn extract(&Location) -> Result<ImportIR>; }` + `enum Location { InPlace, Remote(SshTarget), Archive(PathBuf) }`.
- `cloudpanel.rs` — `CloudPanelAdapter` (sqlite + vhost parse + version gate).
- `hestia.rs` — `HestiaAdapter` (CLI + flat-file fallback; Vesta variant).
- `planner.rs` — `ImportPlanner`, `ImportPlan`, `PlannedHosting`, `Action`, conflict detection.
- `engine.rs` — `ImportEngine::apply(plan, &HostingService, &JobHandle)` — orchestrates create→stage→restore→cron→chown→cert/ssh; **calls into `hyperion-core`, never duplicates it.**

Touched:
- `hyperion-rpc/src/{api.rs,codec.rs,wire.rs}` — `hosting_import_panel` + `hosting_import_panel_plan`, wire types (`ImportPanelReq{source_kind, location_mode, location_ref, options}`, `ImportPlan`, `ImportPanelResult{job_id, created, skipped, unsupported_report_path}`), no secret variant fields.
- `hyperion-core/src/service.rs` — thin `import_panel_plan()` / `import_panel_apply()` driving `hyperion-import` + existing `create()`/`backup_restore`.
- `hyperion-core/src/agent.rs` — wire the two trait methods on the AgentImpl adapter.
- `bin/hctl/src/main.rs` — `hctl hosting import-panel --source hestia|cloudpanel --mode inplace|remote|archive [--ssh user@host --key …] [--archive path] [--dry-run]`.
- `bin/hyperion-web/src/handlers/import.rs` (new) — wizard: pick node + source + mode → run `*_plan` → render dry-run table with per-row action + honesty banner → confirm → `*_apply` → live job cards. Follows `ui-keep-design-fix-ia` (no restyle) + `create-renders-in-place-no-prg` (confirm POST redirects to the job view).

---

## 5. Edge cases & data integrity

- **Passwords are one-way (both panels).** Reset DB password + rewrite app config (v1); hash-transplant is P2. Never attempt plaintext recovery.
- **UID/GID + ownership (the #1 silent-failure class).** New `useradd` → new uid; restored trees keep source uid → after restore `chown -R <newuser>:<newuser>` the tree + ensure ancestor traversability (`o+x` on `/home`, `/home/<user>`). This is exactly our own `restore-archive-no-chown` + `debian-useradd-home-0700` bugs.
- **Charset/collation.** Capture per-DB charset in IR; dump `utf8mb4`; create DB with matching charset before load, else silent mojibake. Hestia mail IDN punycode dirs irrelevant in v1 (mail out).
- **Large dumps / disk.** Stream dumps + rsync docroots, not one 2× tarball; `du`/`df` preflight (reuse `backup_now` pattern).
- **Idempotency / resume.** Dry-run recomputed each run; apply per-hosting + resumable (already-created → `Conflict`/`Skip`). Stable source key `<panel>:<user>:<domain>` recorded on the created hosting.
- **Partial failure.** Per-hosting rollback; batch continues + reports.
- **Conflict.** `hosting_create` refuses existing domain; planner detects pre-apply → `Conflict`; v1 = Skip.
- **CloudPanel cert sanity.** `openssl x509 -noout` before `cert_upload` (catch literal-`\n\n` corruption, issue #293); fall back to ACME re-issue.
- **Hestia `admin` user.** Filter Hestia's own maintenance crons + the panel UI cert; never import these.

---

## 6. Testing strategy (lima VMs)

Two throwaway source VMs (real panels) + one Hyperion target; assert parity from the mac host.
- **HestiaCP VM:** `hst-install.sh`; seed 2 users, each a WordPress site, MariaDB + Postgres DBs with non-ASCII rows, SSL (LE on one, self-signed on the other), 2 crons, plus 1 mail domain + 1 BIND zone (to test the skip/export path).
- **CloudPanel VM:** CE v2 installer; seed 2 site-users, 3 domains (one user hosting 2 domains — multi-domain case), 1 PHP + 1 reverse-proxy site, 2 MySQL DBs (utf8mb4 + non-ASCII), uploaded cert + LE cert, crontab in **both** `/var/spool/cron/crontabs` and `/etc/cron.d`.
- **Hyperion target VM:** standalone single node.

**Matrix:** archive, remote, and **in-place** (install Hyperion agent onto the CloudPanel VM itself, `--mode inplace`).
**Parity assertions (scripted):** site reachable (`curl -H Host:`), DB row count + non-ASCII string byte-identical, `wp-config.php` has the new minted password and WP connects, crons present (Hestia `admin` crons absent), certs validate / LE re-issued, the report explicitly lists mail/DNS as exported-or-never-managed (not "0"), re-run apply → all `Skip` (idempotent).

---

## 7. Phasing

- **P0 (MVP, ~1–1.5 wk): CloudPanel sites + DBs, in-place.** Highest value, lowest risk (clean SQLite source, no mail/DNS). Crate skeleton + IR + `CloudPanelAdapter` (in-place) + planner + dry-run + apply (create/restore + chown + `db_reset_password` + wp-config rewrite). `hctl` only, no web UI. Ships independently.
- **P1 (~2–3 wk):** `HestiaAdapter` (CLI + flat-file, Vesta) gated on `*_SYSTEM`; remote + archive modes; web wizard; `cert_upload` + ACME re-issue; `sftp_set` for SSH keys; "rename alias" conflict option; proxy-type sites.
- **P2 (as appetite allows):** DB auth-hash transplant (skip the forced password reset for non-WP apps); overwrite-on-conflict; profile-apply at import time; source audit-trail fields on imported hostings. **Mail and DNS are NOT here — they are permanently out of scope.**

Each phase is independently shippable; P0 alone closes the most common request ("I'm on CloudPanel, get me onto Hyperion").

---

## Appendix A — HestiaCP source-data reference

- **Detect:** `/usr/local/hestia/conf/hestia.conf` (Vesta: `/usr/local/vesta/...`); `v-` CLIs in `/usr/local/hestia/bin/`. Version: `/usr/local/hestia/VERSION` / `v-about`. Subsystem flags in `hestia.conf`: `WEB_SYSTEM, DNS_SYSTEM, MAIL_SYSTEM, IMAP_SYSTEM, DB_SYSTEM, FTP_SYSTEM`.
- **Model:** every user = a real Linux account; data under `/home/<user>/`, authoritative metadata in flat `key='value'` files under `/usr/local/hestia/data/users/<user>/`. No central SQL for panel state.
- **Web:** `data/users/<u>/web.conf` (DOMAIN, ALIAS, TPL, SSL, LETSENCRYPT, BACKEND=PHP pool/version, FTP_USER/FTP_MD5, PROXY). Docroot `/home/<u>/web/<d>/public_html`. Enumerate: `v-list-web-domains <u> json`.
- **DB:** `data/users/<u>/db.conf` (DB, DBUSER, MD5=hash, TYPE, HOST, CHARSET; `<user>_` prefix mandatory). Admin creds for dumps in `/usr/local/hestia/conf/{mysql,pgsql}.conf`. Enumerate: `v-list-databases <u> json`.
- **Mail (skip if MAIL_SYSTEM empty):** `mail.conf` + `mail/<d>.conf` (ACCOUNT, ALIAS, FWD, MD5={BLF-CRYPT}/{ARGON2ID}/{MD5}); live `passwd` at `/home/<u>/conf/mail/<d>/passwd`; maildirs `/home/<u>/mail/<d_idn>/<acct>/`.
- **DNS (skip if DNS_SYSTEM empty):** `dns.conf` + `dns/<d>.conf` (ID, RECORD, TYPE, PRIORITY, VALUE). `v-list-dns-records <u> <d> json`.
- **SSL:** `data/users/<u>/ssl/<d>.{crt,key,ca,pem}` (use `.pem` = leaf+CA). LETSENCRYPT='yes' → re-issue ok.
- **Cron/SSH/FTP:** `cron.conf` / `/var/spool/cron/crontabs/<u>`; SSH = real user shell + `~/.ssh/authorized_keys`; FTP accounts in `web.conf` FTP_* (hashed).
- **Canonical export:** `v-backup-user <u>` → one self-describing `/backup/<u>.<ts>.tar` (`./hestia/`, `./pam/passwd` [orig uid!], `./web`, `./dns`, `./mail`, `./db/<db>.<type>.sql.gz`, `./cron`); parseable fully offline. Compression gz or zstd — detect per file.
- **Dumps:** `mysqldump --single-transaction --routines --triggers --default-character-set=utf8mb4 …` / `pg_dump -Fc`.

## Appendix B — CloudPanel source-data reference

- **Detect:** `/home/clp/htdocs/app/` + the SQLite store `/home/clp/htdocs/app/data/db.sq3`; `clpctl` on PATH. Version differs (v1 `/etc/cloudpanel/configs/`, v2 `/var/lib/cloudpanel/secrets/`) → CLI flags are version-sensitive; detect before scripting. **Re-run `.schema` on the box — columns are version-dependent.**
- **Manages:** web vhosts (PHP/static/Node/Python/reverse-proxy), nginx, per-site Linux users + docroots, PHP-FPM, MySQL/MariaDB DBs + users, TLS (self-signed/uploaded/LE), per-site cron, SSH/SFTP, nightly mysqldump. **Does NOT manage: email, authoritative DNS, FTP daemon, firewall/billing.**
- **Sites** (schema validated live on CloudPanel CE 6.x, 2026-06-27): `db.sq3` `site` (`id, type, domain_name, root_directory, user`=site-user, `reverse_proxy_url`, `ssh_keys` [CLOB, inline], `php_settings_id`, `certificate_id`, `application`) + `php_settings(site_id, php_version, …)`. **Docroot = `/home/<site-user>/htdocs/<root_directory>`** (root_directory defaults to the domain, may be e.g. `<domain>/public`; confirmed via the vhost `root` directive — it is NOT `/htdocs/<domain>/<root>`). `type` is lowercase (`php`, `static`, `reverse-proxy`, `nodejs`, `python`). Multiple domains per site-user. SSH keys + proxy upstream are columns on `site` (no vhost parse needed); parse `/etc/nginx/sites-enabled/<domain>.conf` only for extra `server_name` aliases.
- **DB:** `db.sq3` join `database` ⋈ `database_server` ⋈ `site` ⋈ `database_user` (passwords encrypted — don't read raw). Master creds via `clpctl db:show:master-credentials` (v2) / `db:show:credentials` (v1). Dump: `clpctl db:export --databaseName=<db> --file=<db>.sql.gz`.
- **SSL:** flat dir `/etc/nginx/ssl-certificates/<domain>.crt` (full chain) + `.key`; map by basename = domain; `openssl x509 -noout` sanity check (`\n\n` bug, issue #293).
- **Cron:** read BOTH `/var/spool/cron/crontabs/<user>` and `/etc/cron.d/<user>` (orphans common, issue #758); map to a live site/user.
- **SSH/SFTP:** `db.sq3` `ssh_user` (user_name, ssh_keys, site_id) + `~/.ssh/authorized_keys`; FTP == these SFTP users (no FTP daemon).
- **Mail/DNS:** none. Surface to operator (don't report "0").
- **Schema inspect:** `sqlite3 /home/clp/htdocs/app/data/db.sq3 ".schema site"`; snapshot safely with `.backup '/root/clp-db.sq3'`; query with `sqlite3 -json`.
