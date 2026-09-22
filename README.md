<div align="center">

# Hyperion

**A self-hosted, multi-node hosting control panel, written in Rust.**

One agent binary per server, one web UI on the master. Hyperion provisions
PHP, static, and reverse-proxy sites end to end — Linux user, nginx vhost,
PHP-FPM pool, database, TLS, WordPress — in a single transaction that rolls
back cleanly if any step fails. Drive a fleet of servers from one screen, a
scriptable HTTP API, and a CLI — and import what you already run on HestiaCP
or CloudPanel.

[![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](#license)
[![Debian](https://img.shields.io/badge/debian-12%2B-red?logo=debian)](#install)
[![API](https://img.shields.io/badge/API-OpenAPI_3-purple)](#remote-api)
[![Status](https://img.shields.io/badge/status-beta-orange)](#status)

[Install](#install) · [Features](#features) · [Remote API](#remote-api) · [Import](#import-from-another-panel) · [Architecture](#architecture) · [Status](#status)

</div>

---

> [!WARNING]
> **Young project — not yet proven at scale.** Hyperion compiles cleanly, its
> test suite is green, and it has run real customer sites since v0.10 — but it
> has not been exercised across a large fleet, and the multi-node path has seen
> far less traffic than the single-node one. Run it on servers you can afford to
> rebuild, keep backups, and report anything that breaks. Testers and reviewers
> are the most valuable contribution right now.

---

## Screenshots

| Dashboard | Cluster stats |
| --- | --- |
| [![Dashboard](docs/screenshots/dashboard.png)](docs/screenshots/dashboard.png) | [![Stats](docs/screenshots/stats.png)](docs/screenshots/stats.png) |
| KPI tiles, load and bandwidth sparklines, audit feed. | Cluster and per-node metrics, sampled every 5 minutes. |

---

## Why Hyperion

Most open-source panels are PHP wrappers around templated shell — thousands of
lines of string-concatenated commands running as root, where a domain with an
odd character can turn a config write into unintended shell. Hyperion does the
same job from a small, security-first Rust core: every system command is built
from typed, pre-validated arguments, never interpolated into a shell, so the
worst a bad input earns is a compile or type error rather than a root exploit.
It also scales across servers out of the box.

| | HestiaCP / Vesta / aapanel | **Hyperion** |
| --- | --- | --- |
| Memory-safe language | PHP + bash | Rust, `#![forbid(unsafe_code)]` |
| Multi-node cluster | single node | master + N workers, signed RPC |
| Atomic provisioning | partial | rollback on every step |
| Scriptable HTTP API (OpenAPI) + CLI | partial / unofficial | `/api/v1` + `hctl remote` |
| Live progress for long operations | — | job page on every operation |
| Tamper-evident audit log | — | BLAKE3 hash chain |
| Off-site backups | FTP only | S3 + age encryption, multi-target |
| Import from HestiaCP / CloudPanel | — | in-place or over SSH |

---

## Install

A fresh Debian 12+ VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/install-master.sh | sudo bash
```

It pipes a script into root — read it first. In a few minutes it runs a port
pre-flight and an interactive configurator, installs the chosen packages plus
PHP 8.3, builds Hyperion from source, writes `/etc/hyperion/*.toml`, installs
and starts the systemd units, and prompts for an admin password.

```
Web UI:  https://<your-host>:8443
CLI:     hctl info
```

```bash
sudo usermod -aG hyperion-admin "$USER"   # log out and back in, then open the URL
```

**Worker node** — in the UI, **Nodes → Generate invite**, then paste the printed
one-liner on another Debian 12+ VPS. It enrolls in about 30 seconds and appears
in the Nodes table; from then on you provision hostings on it from the master.

**Update** — `sudo /opt/hyperion/packaging/install/update.sh`, or from the UI at
**/install**. While the panel restarts, its vhost serves a self-refreshing
"updating…" page instead of a bare error, and returns automatically.

The installer is configurable through environment variables (component and port
selection, non-interactive mode, private-repo and air-gapped sources). See
[`docs/RUNBOOK.md`](docs/RUNBOOK.md) for the full list and manual deploys.

---

## Features

**Hosting**
- One-click create — Linux user, PHP-FPM pool, database, nginx vhost, and cert
  in one transaction; any failure rolls back the rest, leaving no orphans.
- PHP 8.1–8.4 side by side, static sites, and a reverse-proxy mode for Node.js,
  Python, or Docker upstreams.
- Suspend and resume, expiration with grace and auto-suspend, and reusable
  profiles that stamp limits, plugins, and DB engine onto many sites at once.
- Kernel-enforced disk quotas, per-pool PHP memory limits, bandwidth alerts.
- Let's Encrypt certificates: one-click HTTP-01 with auto-renewal, plus guided
  DNS-01 wildcards. The DNS pre-check queries the domain's authoritative
  nameservers, not just the local resolver.
- Every slow action (create, backup, restore, migration, cert issuance, WP
  install) runs as a background job with a live progress page that survives a
  browser disconnect.

**WordPress**
- Plugin and theme manager over `wp-cli`, bulk updates, per-plugin auto-update.
- Keyless update detection against public WordPress.org data, with one-click
  minor/patch auto-updates; "couldn't check" is never reported as "all clear".
- Staging copy and push-to-production, taking a safety backup of prod first.
- Site-health probe that reproduces a fatal error and names the plugin at fault,
  offering to park it by renaming — the only remedy once WordPress won't boot.
- File-permission self-check with a real write probe, core-file repair, and a
  full reinstall gated behind a backup that must succeed first.

**Backups**
- Local tar.gz plus a database dump, and off-site S3 with client-side age
  encryption across multiple targets, each with its own retention. Legacy
  FTP/FTPS/SFTP push is still supported.
- Granular restore (full, database-only, or files-only), chunked download, and
  restore into a new domain with WordPress URLs rewritten.

**Security**
- `#![forbid(unsafe_code)]` in every crate; Argon2id passwords; Ed25519-signed
  session cookies with a database-backed revocation ledger.
- TOTP two-factor auth (enforced for admins), native brute-force protection via
  an `nftables` ban set, per-hosting WAF-lite and wp-admin IP allowlists, and
  key-only chrooted SFTP.
- Tamper-evident audit log (BLAKE3 hash chain with a verify button), per-form
  CSRF tokens, and a strict security-header set on every response.
- Each tenant is a real Linux user, so isolation rests on uids and file modes;
  privileged file operations inside a tenant tree resolve symlinks
  component-by-component, because the agent is root and a path under a customer
  webroot is attacker-controlled input.

**Multi-node**
- Master plus workers. The master holds the UI, audit log, and node registry;
  workers run an agent it drives over a signed RPC channel (Ed25519 envelope
  over HTTPS on port 9443, IP-based — no DNS dependency).
- Per-page node switcher, load-aware auto-placement, one-click migration and
  clone across nodes with live progress, and remote node updates.

**Operator UI**
- axum + Askama + HTMX, no JavaScript build step, single binary. Role-aware
  navigation, dark and light themes, type-the-domain confirmations for
  destructive actions, and template lints in CI that catch broken forms, dead
  routes, and unreachable pages before they ship.
- Five built-in roles (super-admin, admin, operator, customer, viewer) with
  per-hosting access grants, plus custom roles built from a granular capability
  set.

---

## Remote API

A scriptable HTTP API at `/api/v1` — provision and operate the whole cluster
from CI, cron, or your own tooling.

- **Auth** — a Bearer key minted in **Settings → API keys**, carrying a
  capability set clamped to its owner and re-checked live on every call (lock or
  demote the owner and the key loses power immediately).
- **Hardening** — optional per-key IP allowlist and rate limit.
- **Contract** — `GET /api/v1/openapi.json` is a generated OpenAPI 3 document;
  `GET /api/v1/docs` renders it in a self-hosted viewer.
- **Conventions** — list endpoints paginate; slow mutations return
  `202 {job_id}` you poll at `/api/v1/jobs/:id`; errors are a JSON envelope.

`hctl remote` is the official CLI over that API:

```bash
hctl remote --url https://panel.example.com --key hyp_… login
hctl remote list --state active | jq '.items[].domain'
hctl remote create --domain new.example.com --php v8_3
hctl remote backup new.example.com --wait
```

For the "ssh in and poke it" path when a node is too broken for the web to help,
`hctl` also talks to the local agent over its Unix socket (`hctl info`,
`hctl hosting create`, `hctl audit`, `hctl ftp …`).

---

## Import from another panel

Move existing sites off HestiaCP or CloudPanel without a weekend of manual work.
Wizard at **/import** (admin) or `hctl hosting import-panel`.

- Reads the source panel's own state directly (Hestia `*.conf`, CloudPanel
  SQLite) — no scraping.
- In-place, or remote over SSH with a key used for that one run and then deleted.
- A dry run shows created / skipped / conflict before anything is touched; an
  existing domain is skipped, never overwritten.
- Sites and databases, WordPress included (`wp-config.php` auto-repointed). Mail
  and DNS are reported, never migrated — Hyperion runs neither.

---

## Architecture

Two processes per box:

- **`hyperion-agent`** runs as root and owns all system state — users,
  directories, nginx vhosts, FPM pools, databases, certs, FTP, cron, backups.
  It listens on a local Unix socket, and on workers also on `:9443` for signed
  RPC from the master.
- **`hyperion-web`** (master only) is the axum + Askama + HTMX UI and the
  `/api/v1` edge. It runs unprivileged and owns the audit log, web users,
  session ledger, node registry, and the Ed25519 master signing key.

```
      web browser (cookie)        API client (Bearer hyp_…)
              │                            │
              ▼                            ▼
   ┌──────────────────────────────────────────────┐
   │  hyperion-web  (master only)                 │
   │  axum + Askama + HTMX  ·  /api/v1 (OpenAPI)   │
   └────┬─────────────────────────┬───────────────┘
        │ local Unix socket       │ signed RPC / HTTPS
        ▼                         ▼
 ┌────────────────┐       ┌────────────────┐
 │ hyperion-agent │       │ hyperion-agent │
 │   (master)     │       │  (each worker) │
 │  HostingService│  ···  │  HostingService│
 │  SQLite state  │       │  SQLite state  │
 │  adapters:     │       │  adapters:     │
 │  fs users nginx│       │  fs users nginx│
 │  php db acme   │       │  php db acme   │
 │  wp ftp        │       │  wp ftp        │
 └────────────────┘       └────────────────┘
```

Every adapter takes typed, pre-validated arguments and shells out only through
`Command::new(..).arg(..)` — never `format!()` into a shell. The RPC envelope is
Ed25519-signed canonical JSON over self-signed HTTPS (integrity comes from the
signature, not the TLS).

### Project layout

```
crates/
  hyperion-types/       newtype IDs + DTOs (no I/O)
  hyperion-validate/    domain + system-user parsers
  hyperion-rpc[-server/-client]/  trait, wire types, codec, transport
  hyperion-state/       SQLite, migrations, audit chain, api keys
  hyperion-adapters/    system-tool wrappers (nginx/php/db/acme/ftp/…)
  hyperion-core/        orchestration + secrets + RealAdapter
  hyperion-import/      HestiaCP / CloudPanel importers
  hyperion-auth/        Argon2id + Ed25519 sessions + CSRF
bin/
  hyperion-agent/       privileged daemon + background scheduler
  hyperion-web/         axum admin UI + /api/v1 (single binary)
  hyperion-export/      static-musl exporter served by the import wizard
  hctl/                 CLI (local socket + remote HTTP)
packaging/install/      install-master.sh · install-node.sh · update.sh
```

---

## Status

**Beta, with production mileage.** Everything is unit-tested, and the panel has
run real customer sites since v0.10. Read the feature list as "shipped and
exercised on a real box", not "proven at scale": it has not been run across a
large fleet, and multi-node has had less real traffic than single-node.

**Shipped (single node):** hosting CRUD across PHP/static/reverse-proxy with
DB + TLS · multi-version PHP + MariaDB/PostgreSQL · suspend/resume, limits,
kernel quotas · profiles, clone, expiration · local + off-site backups with
granular restore · Let's Encrypt HTTP-01 + DNS-01 wildcard · WordPress
management, keyless updates, staging, Redis cache · site-health and permission
self-checks + repair · FTP + chrooted SFTP · WAF-lite, allowlists, nftables
fail2ban · audit chain, 2FA, session revocation · panel import (HestiaCP +
CloudPanel) · remote API with keys, OpenAPI, IP allowlist, rate limit ·
per-hosting DKIM/SPF and mail checks · care packages and customer reports ·
monitoring with live gauges, PSI, and OOM detection · custom roles.

**Shipped (cluster):** node enrollment · master↔worker signed RPC · per-page
node switcher and cluster stats · auto-placement, migration, clone across
nodes · remote node update with live logs · test-node mode · installer
pre-flight and configurator.

**Roadmap:** HA control plane (warm standby + state replication) · per-tenant
API keys · restic/borg backup targets · SSO/OIDC login.

---

## Development

```bash
git clone https://github.com/nechodom/hyperion && cd hyperion
cargo build --release --workspace     # → target/release/{hyperion-agent,hyperion-web,hctl}

cargo test --workspace                # ~1,400 tests, green, run in seconds
cargo clippy --workspace --all-targets   # clean under -D warnings
```

Integration tests that need a real Debian (`useradd`, `mariadb-dump`,
`systemctl reload nginx`) are `#[ignore]`d; run them on a node with
`cargo test --workspace -- --ignored`. `bin/hyperion-web/tests/web_e2e.rs`
drives the whole stack — login, CSRF, hosting create, the API — against a real
socket-backed agent with mocked adapters.

Adding a new system effect follows one path: adapter (typed args, no shell
interpolation) → mockable `AdapterPort` method → orchestration in
`HostingService` with a LIFO rollback step → RPC variant and handler → CLI / UI
/ API surface → tests at every layer. Multi-node handlers never touch the local
socket directly — they go through `dispatcher::dispatch_to_node`.

Every binary stamps its own version at build time, so `--version` reports the
exact commit. Cut a release with `git tag vX.Y.Z && git push --tags`; CI builds
a named GitHub release. A `rolling` release ships on every push to `main`.

---

## License

[AGPL-3.0-only](LICENSE). Built as an open-source alternative to CloudPanel,
HestiaCP, and Plesk — Rust instead of templated PHP, multi-node and API-driven
from the start, with a security model that does not rely on trusting shell
templating. For commercial use or to fund a feature, get in touch.

<div align="center">

Built in Czechia by [@nechodom](https://github.com/nechodom). Contributions and
bug reports welcome.

</div>
