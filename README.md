# 🦅 Hyperion

> A Rust hosting control panel for Debian 12+. One binary on each
> server, one web UI on the master. Provisions PHP / static / Node.js
> sites end-to-end (nginx + FPM pool + database + TLS), runs the
> whole cluster from one screen, and never quietly half-creates
> anything.

[![Rust](https://img.shields.io/badge/rust-stable-orange)](#)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](#license)

---

## What you get out of the box

### Hosting

- **One-click create** — Linux user, PHP-FPM pool, MariaDB or Postgres DB, nginx vhost, self-signed cert, all in one transaction. If any step fails the rollback unwinds the rest — no orphan rows, no zombie users.
- **PHP 8.1 / 8.2 / 8.3 / 8.4** side by side via deb.sury.org. Static-only sites work too, and there's a reverse-proxy mode for Node.js / Python / containers behind nginx.
- **Suspend / resume** — 503 page, FPM stop, DB lock, killed user processes. Fully reversible — operator can resume and the site picks up where it left off.
- **Per-hosting limits** — PHP memory, max children, exec time, DB connections, disk hard cap, monthly bandwidth quota. Profiles let you stamp the same set onto a hundred sites in one click.
- **Expiration + grace** — schedule notifications, auto-suspend on the due date, grace window before auto-delete. Operator can opt out per hosting.
- **Backups** — tar.gz of htdocs + mysqldump / pg_dump + JSON manifest, kept on local disk by default. Optional push to an off-site FTP / FTPS / SFTP target after every backup. Retention policy: max age + minimum N per hosting.

### Per-hosting controls

The hosting detail page exposes operator-level knobs that map directly
to nginx, FPM, and the WordPress install. Every save runs through
`nginx -t` (or `wp config set`) before commit — rollback on any
failure with the verbatim daemon error surfaced in the UI.

- **HTTP basic auth** — bcrypt htpasswd, ACME bypass so LE renewals don't 401.
- **HSTS** with a presets dropdown (1h → 2y), `force HTTPS` toggle.
- **Custom nginx snippet** appended inside the HTTPS `server { }` (32 KiB cap, validated).
- **Maintenance mode** — 503 page with ACME bypass.
- **Redirect-only hosting kind** — separate template, no FPM/htdocs; 301/302/307/308 + preserve-path toggle.
- **Per-hosting FastCGI page cache** — per-id zone in `conf.d/`, bypasses logged-in/PHPSESSID cookies.
- **WP debug toggle** (`WP_DEBUG` / `WP_DEBUG_LOG` / `WP_DEBUG_DISPLAY`) plus a "rotate debug.log" button.
- **Per-hosting Redis object cache** — auto-allocated DB slot, dedicated ACL user, `WP_REDIS_*` written to `wp-config.php`.
- **Vhost auto-heal** — when nginx-write detects missing cert files it bootstraps a self-signed cert so `nginx -t` always passes (the LE cert is re-issued on the next renewal tick).

### File manager

- **Browse + upload + download + delete + mkdir + rename** under `htdocs/`.
- **Inline editor** for text files — textarea + Save, no SCP round-trip.
- **Symlinks refused** at the adapter layer; path traversal refused after canonicalisation; 64 MB write cap.
- **3-dot per-row menu** with type-the-name delete confirmation for safety.

### Cluster / multi-node

- **Master + worker model.** Master holds the web UI, audit log, and enrolled-nodes registry. Workers run an agent that the master drives via a signed RPC channel (Ed25519 envelope over self-signed HTTPS on port 9443). No DNS dependency between master and workers — IP-based.
- **Per-page node switcher.** Service health, stats, install — all pages have a "View on node:" dropdown. Picking a worker shows that worker's services and metrics, not the master's.
- **Auto-placement** — when creating a hosting, pick "★ auto" and the master scores every node (load + memory + hosting count, normalised) and chooses the best-fit. Falls back to master if no workers are online.
- **One-click migrate** between any two nodes (master ↔ worker, worker → worker). Snapshot on source, master proxies bundle bytes when source is a worker, target fetches via signed URL, source gets suspended (not deleted) so you can verify before pulling the trigger.
- **Remote node update** from the master UI. Pick a worker, tick "System packages" and/or "Hyperion", click Start — apt-get + update.sh run on the worker in the background, log streams live into the panel.
- **Connectivity test button** on each enrolled node.
- **Cluster-wide stats** as the default `/stats` view. Drop down to a single node for per-node sparklines.
- **Cluster monitoring overview** at `/monitoring` — every hosting with monitor enabled across the cluster, sorted alerting-first.
- **Test-node mode** — designate certain nodes as test-only via Settings. Test hostings get auto-generated subdomains from a template (`test.{name}.{node}.testovaciverze.cz`), prod hostings refuse to land there + vice versa, WP installs on test nodes get `blog_public = 0` (no-index).
- **Master-as-control-plane toggle** (Settings → Cluster) — when on, the master refuses new hosting creates and the Target-node dropdown hides it.

### RBAC + multi-tenancy

Five roles: **super_admin** (god mode + user management), **admin** (sees everything, can't manage users), **operator** (internal staff with CRUD on assigned hostings), **customer** (end-user / tenant — slim nav, only their own hostings), **viewer** (read-only on granted hostings).

- **Per-hosting access grants** for operator/customer/viewer roles.
- **2FA (TOTP)** with backup codes.
- **Profile pictures** — upload PNG/JPG/WEBP avatars (server detects format from magic bytes, not just Content-Type).
- **Notification bell** — in-app feed of cert renewal failures, monitor alerts, etc. Per-user fan-out, mark-read + mark-all-read.
- **Audit log** with BLAKE3 hash chain.

### Multi-node cluster

- **Master + worker model.** Master holds the web UI, audit log, and enrolled-nodes registry. Workers run an agent that the master drives via a signed RPC channel (Ed25519 envelope over self-signed HTTPS on port 9443). No DNS dependency between master and workers — IP-based.
- **Per-page node switcher.** Service health, stats, install — all pages have a "View on node:" dropdown. Picking a worker shows that worker's services and metrics, not the master's.
- **One-click hosting migrate** master → worker. Snapshot the source, target fetches via signed URL, source gets suspended (not deleted) so you can verify before pulling the trigger. Manual-export fallback for SSH-only or off-cluster targets.
- **Remote node update** from the master UI. Pick a worker, tick "System packages" and/or "Hyperion", click Start — apt-get + update.sh run on the worker in the background, log streams live into the panel. No more ssh-and-baby-sit.
- **Connectivity test button** on each enrolled node. Master signs an AgentInfo envelope, posts to the worker's public IP, reports back: reachable / connection refused / signature failed. Replaces the "ssh in + curl" debug ritual.
- **Cluster-wide stats** as the default `/stats` view. Hostings, disk, bandwidth, requests summed across the whole cluster. Drop down to a single node for per-node sparklines.
- **Master-as-control-plane toggle** (Settings → Cluster). When on, the master refuses new hosting creates and the Target-node dropdown hides it — useful when you want a dedicated control box without tenant data.

### Operator UI

- **axum + askama + HTMX**, no JS build step, single binary. Dark + light themes via `prefers-color-scheme`, plus an auto toggle in the sidebar.
- **Role-aware navigation.** Operators and viewers don't see Users / Nodes / Settings in the sidebar at all — no more click-then-403. Defense in depth: server still enforces RBAC for anyone who bypasses the JS.
- **Themed confirm modals** for destructive actions, not the browser-native confirm() prompt that looked like a phishing dialog on macOS. Each one explains in plain words what will actually happen.
- **Live service-install progress.** Clicking "Install" on a missing service no longer freezes the page for 5 minutes — `apt-get install` runs in the background and the log tail streams into the panel. The page also drops `-qq` from apt so when something fails you see *what* failed, not just "dpkg returned an error code 1".
- **Per-hosting actions follow the hosting.** Suspend / delete / set-limits / backup all dispatch to the node the hosting actually lives on — the listing aggregates across master + workers and tags each row with its node.

### Security

- **`#![forbid(unsafe_code)]`** in every crate. No `sh -c`, every command shells out via `Command::new("/usr/bin/foo").arg(...)` with regex-validated arguments.
- **Argon2id passwords** at OWASP-recommended parameters. **Ed25519-signed session cookies**, **per-session+form CSRF tokens** with a wildcard fallback for HTMX-driven swaps. Constant-time username comparison on login.
- **Per-IP rate limits** on `/api/enroll`, `/api/heartbeat`, `/settings/email-test`. Token bucket per (endpoint, IP), in-process, no extra deps.
- **Tamper-evident audit log** — BLAKE3 hash chain over every state change. Broken chain refuses to start the agent.
- **Two-factor auth** — TOTP enrolment from the user profile, scratch codes generated at enrol time.
- **Invite tokens stored hashed**, plaintext displayed exactly once, hidden in the install command by default with a Reveal / Copy button so screenshots don't leak credentials.
- **Constant-time secret compare** on every heartbeat — masters can't be used as a node-id oracle by timing requests.

---

## 🚀 Install

### One-liner (Debian 12+ master)

On a fresh Debian 12 VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/install-master.sh \
  | sudo bash
```

The script:

1. Verifies you're on Debian 12+
2. apt installs nginx + MariaDB + PostgreSQL + PHP 8.3 (via deb.sury.org)
3. Installs Rust (rustup, minimal) if missing
4. Builds Hyperion from source, drops binaries into `/usr/sbin` and `/usr/bin`
5. Lays down `/etc/hyperion/{agent,web}.toml`
6. Installs systemd units + enables `hyperion-agent` and `hyperion-web`
7. Prompts for an admin password and bootstraps the web user

After ~3-5 minutes you get:

```
============================================================
  ✓ Hyperion master installed
  ----------------------------------------
  Web UI:   https://your-host:8443
  CLI:      hctl info
============================================================
```

Add yourself to the admin group and log out / in:

```bash
sudo usermod -aG hyperion-admin "$USER"
```

#### Non-interactive install (CI / Terraform / Ansible)

```bash
curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/install-master.sh \
  | sudo HYPERION_ADMIN_PASS="<strong>" \
         HYPERION_LISTEN="0.0.0.0:8443" \
         HYPERION_ACME_EMAIL="ops@example.com" \
         bash
```

All env knobs: `HYPERION_REF` (git branch, default `main`),
`HYPERION_INSTALL_DIR` (default `/opt/hyperion`),
`HYPERION_ADMIN_USER` (default `admin`), `HYPERION_ADMIN_PASS`,
`HYPERION_LISTEN`, `HYPERION_ACME_EMAIL`.

#### Installing from a private repository

Both `install-master.sh` and `install-node.sh` ship with four ways to
fetch the source. Pick whichever fits your secret-management story —
the script's behaviour is identical from step 6 onwards.

**1 · HTTPS with a Personal Access Token** (recommended for one-off
installs on machines you control). Create a fine-scoped PAT with
`repo:read` and feed it through the environment — the token goes into
git's askpass helper, **never** into the URL or `argv` (so it doesn't
show up in `ps`):

```bash
curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/install-master.sh \
  -o /tmp/install-master.sh
sudo HYPERION_GIT_TOKEN='ghp_xxxxxxxxxxxxxxxxxxxx' \
     HYPERION_GIT_URL='https://github.com/nechodom/hyperion' \
     bash /tmp/install-master.sh
```

**2 · SSH with deploy key / ssh-agent forwarding** (recommended for
multi-server fleets — one deploy key per host, no token rotation
pain):

```bash
# On a box that has the deploy key (or your laptop with -A forwarding):
sudo HYPERION_GIT_URL='git@github.com:nechodom/hyperion' \
     bash /tmp/install-master.sh
```

**3 · Pre-cloned source** (Ansible-friendly — let your config
management lay down the source tree, then drive the installer):

```bash
sudo -E git clone git@github.com:nechodom/hyperion /opt/hyperion
sudo HYPERION_SKIP_CLONE=1 bash /tmp/install-master.sh
# The script reuses /opt/hyperion as-is and only does the build + setup.
```

**4 · Offline / air-gapped from a tarball** (download once on a
networked box, ship the artifact, run on an isolated host):

```bash
# On a networked box:
git clone --depth=1 git@github.com:nechodom/hyperion /tmp/hyperion-src
tar -czf hyperion.tar.gz -C /tmp/hyperion-src .

# On the target (no GitHub access needed):
sudo HYPERION_LOCAL_TARBALL=/root/hyperion.tar.gz bash install-master.sh
```

**Curl-pipe-bash caveat.** With a private repo you cannot `curl` the
script from `raw.githubusercontent.com` unauthenticated either —
download it once over an authenticated channel (PAT / SSH) and invoke
it from disk, as shown above. Or self-host the script on your own
HTTPS endpoint and reference that.

### Adding a node

On the master:

1. Open the web UI → **Nodes** in the sidebar.
2. Fill the label (e.g. `node5.example.com`) + TTL → click **Generate invite**.
3. The token is shown once, hidden behind a Reveal button. Click **Copy install command** — it bundles the token + master URL into one curl pipe.

On the new Debian 12+ VPS, paste as root:

```bash
curl -fsSL https://<master>/install/install-node.sh \
  | sudo bash -s -- --token=ABCD-EFGH-… --master=https://<master>
```

The script installs the apt deps, builds `hyperion-agent` + `hctl`,
writes the token + master URL to `/etc/hyperion/agent.toml`, opens
port 9443 in ufw (if active), and starts the agent. The agent enrolls
with the master on first boot, the master persists the per-node
secret (hashed), and the node shows up in the Nodes table within a
few seconds.

From that point on:

- Master → worker actions go over the **signed RPC channel** (port 9443, Ed25519 envelope) — no DNS needed between them, master uses the worker's public IP.
- Click **Test** on the worker's row to verify reachability.
- Click **Update…** to apt-upgrade + rebuild Hyperion on the worker without ssh-ing in.
- Provision hostings directly onto the worker from `/hostings/new` (Target node dropdown).

For a **private repo**, the node script honours the same four source
modes as the master script:

```bash
# PAT in env (the master URL + token still ride on argv; that's by design —
# the master URL is non-secret and the invite token is single-use).
sudo HYPERION_GIT_TOKEN='ghp_xxx' \
     HYPERION_GIT_URL='https://github.com/nechodom/hyperion' \
     bash install-node.sh --token=ABCD-… --master=https://<master>

# Or stage a tarball via your config-management layer:
sudo HYPERION_LOCAL_TARBALL=/root/hyperion.tar.gz \
     bash install-node.sh --token=ABCD-… --master=https://<master>
```

### Updating an existing install

Once you've installed Hyperion, in-place updates use `update.sh`:

```bash
# Public repo, the default install path /opt/hyperion:
sudo /opt/hyperion/packaging/install/update.sh

# Or piped from GitHub:
curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/update.sh \
  | sudo bash

# Private repo: pass the PAT through env:
sudo HYPERION_GIT_TOKEN='ghp_xxx' /opt/hyperion/packaging/install/update.sh

# After a failed `hosting create` left orphan provisioning rows behind,
# clean them up as part of the update:
sudo /opt/hyperion/packaging/install/update.sh --repair
```

The script stops services, fast-forwards `/opt/hyperion` to
`origin/$HYPERION_REF` (refuses if your working tree is dirty), rebuilds
`hyperion-agent` / `hyperion-web` / `hctl`, reinstalls binaries, refreshes
systemd unit files **only if they changed**, materializes any missing
session/CSRF keys, starts services back up, and tails `journalctl` for
you if anything fails its health check.

`--repair` drops rows in `hostings.state IN ('provisioning','failed','deleting')`
— it does **not** touch on-disk artefacts (system users, nginx vhosts,
databases); the script prints the diagnostic commands to inspect those.

### Local development (macOS / dev VPS)

You only need Rust:

```bash
git clone https://github.com/nechodom/hyperion
cd hyperion
cargo build --release --workspace
```

Three binaries land in `target/release/`:
`hyperion-agent`, `hyperion-web`, `hctl`.

For a local single-node dev environment without root:

```bash
mkdir -p /tmp/hyp-dev
cat > /tmp/hyp-dev/agent.toml <<EOF
[agent]
socket_path = "/tmp/hyp-dev/agent.sock"
state_db    = "/tmp/hyp-dev/state.db"
secrets_dir = "/tmp/hyp-dev/secrets"
log_path    = "/tmp/hyp-dev/agent.log"
home_root   = "/tmp/hyp-dev/home"
backup_root = "/tmp/hyp-dev/backups"

[acme]
contact_email = "dev@example.com"
challenge_dir = "/tmp/hyp-dev/acme"
EOF

cat > /tmp/hyp-dev/web.toml <<EOF
[web]
listen           = "127.0.0.1:8443"
agent_socket     = "/tmp/hyp-dev/agent.sock"
admin_user_file  = "/tmp/hyp-dev/admin.json"
session_key_file = "/tmp/hyp-dev/sess.key"
csrf_key_file    = "/tmp/hyp-dev/csrf.key"
secure_cookies   = false
EOF

# Bootstrap admin, then run both daemons:
./target/release/hyperion-web --config /tmp/hyp-dev/web.toml bootstrap \
  --username admin --password "your-dev-password"
./target/release/hyperion-agent --config /tmp/hyp-dev/agent.toml &
./target/release/hyperion-web   --config /tmp/hyp-dev/web.toml &

open http://127.0.0.1:8443
```

Hosting create on macOS will fail at `useradd` — that's expected.
The state, RPC, web, scheduler, audit, backup orchestration etc.
all work for local exploration.

For full production deploy notes (systemd hardening, MariaDB
secure-install, ufw etc.) see [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

---

## Multi-node cookbook

A handful of recipes for the common cluster operations. All of these
are doable from the web UI on the master — `hctl` works too if you
prefer the CLI on the node itself.

### Provision a hosting on a specific worker

`/hostings/new` → **Target node** dropdown at the top of the page →
pick `stav`. The banner above shows where it'll land (changes colour
when you pick a remote target). Submit → the master signs an envelope
and dispatches `HostingCreate` to the worker; the worker provisions
everything locally and returns the detail. Verify in journalctl on
the master with `journalctl -u hyperion-web -g dispatch`.

### Move an existing hosting from master to a worker

`/hostings/<domain>` → **Migration** tab → **One-click migrate** card
(only visible when source is the master AND at least one worker is
enrolled). Pick target → confirm. Hyperion takes a full backup on
the master, the worker fetches it over a signed URL, restores into
a fresh hosting. The source is **suspended** (not deleted) so you can
update DNS, verify, then delete the original from the Danger tab.

### Update a worker (apt + Hyperion)

`/install` → row for the worker → **Update…** button. Tick *System
packages* and/or *Hyperion*, click **Start**. The job runs in the
background on the worker; the log tail streams into the panel every
3 seconds. apt-get + update.sh log lines show prefixed with
`[apt-upgrade]` / `[hyperion-update]`. You can navigate away — when
you come back the panel shows the latest state.

### See what's actually breaking on a worker

`/services?node=<id>` shows that worker's systemd units. Click
**Install** on a missing service (e.g. `php8.4-fpm`) → a panel below
the table polls progress every 2 s. apt now runs WITHOUT `-qq` so
when dpkg breaks you see *which* postinst script failed, not just
the wrapper.

`/stats?node=<id>` for that worker's load average + memory + per-
hosting bandwidth + request count sparklines. Default `/stats` view
aggregates everything across the whole cluster.

### Turn the master into a control-plane-only node

Settings → **Cluster** tab → uncheck "Allow new hostings on master"
→ Save. New hosting creates from the UI now require picking a
worker; existing hostings on the master stay put. Persisted in
`[cluster] master_accepts_hostings = false` in `agent.toml`.

---

## 📸 Tour

### Web UI — Dashboard

```
hyp·erion           Dashboard  Hostings  Audit  Install              signed in as kevin

┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Agent        │  │ Hostings     │  │ You          │
│ master.cz    │  │ 12           │  │ kevin        │
│ v0.1.0       │  │ across this  │  │ admin · solo │
└──────────────┘  └──────────────┘  └──────────────┘

Recent hostings                                        [+ New hosting]
DOMAIN              PHP    STATE        CREATED
example.com          8.3    ● active     2 hours ago
blog.example.com       8.4    ● active     yesterday
staging.example.com   8.3    ⚠ suspended  3 days ago
```

### CLI — `hctl`

```
$ hctl info
agent: master.example.com version=0.1.0 schema=2 hostings=12

$ hctl hosting create example.com --php 8.3 --db mariadb
✓ created example_com (id=01K4Z…)
  root: /home/example_com/example.com/htdocs
  db:   lm_a8c_examplecz (user=lm_a8c_u, password=Hx9k…RnG2)
  cert: issuer=self-signed, not_after=2027-06-01

$ hctl hosting suspend example.com --reason="payment overdue"
✓ suspended

$ hctl hosting backup-now example.com
✓ backup 17 ok
  archive: /var/lib/hyperion/backups/local/example_com/example.com-1764672000.tar.gz
  db_dump: /var/lib/hyperion/backups/local/example_com/example.com-1764672000.sql
  bytes:   148373921

$ hctl audit --limit 5
   ID TS                 ACTOR          ACTION                  RESULT
   42 1764672135         agent          hosting.backup          ok
   41 1764672120         agent          hosting.suspend         ok
   40 1764672110         cli:root       hosting.set_limits      ok
   …
```

---

## Architecture

Two layers, on every box:

- **`hyperion-agent`** runs as root, manages all system state — users, dirs, nginx vhosts, FPM pools, DBs, certs, FTP, cron, backups. Speaks JSON over a local Unix socket (`/run/hyperion.sock`, 0660, `hyperion-admin` group). On worker nodes it also listens on `0.0.0.0:9443` for signed RPC from the master.
- **`hyperion-web`** (master only) — axum + askama + HTMX, runs unprivileged in the `hyperion-admin` group so it can talk to the local agent's socket. Holds the audit log, the web users, the enrolled-nodes registry, the master's Ed25519 signing key.

`hctl` is a thin CLI that uses the same Unix socket as the web UI —
it's the "ssh in and poke" path when something on the node is too
broken for the web to help.

For multi-node, the master signs every outbound RPC with an Ed25519
private key (kept at `/etc/hyperion/master-rpc.key`, 0600 root). The
public half is shipped to each worker at enrolment time and re-sent
on every heartbeat ack. The envelope covers `(node_id, ts, nonce,
body_hash)` so the worker can verify the request hasn't been
tampered with or replayed.

```
                                        web user
                                            │
                                            ▼
                  ┌─────────────────────────────────────────────────┐
                  │  hyperion-web (master only)                     │
                  │  axum + askama + HTMX                           │
                  │  └─ holds master-rpc.key (Ed25519 signer)       │
                  └────┬───────────────────────┬────────────────────┘
                       │ local Unix socket     │ signed RPC over HTTPS
                       │ /run/hyperion.sock    │ (port 9443, IP-based)
                       │ 0660 hyperion-admin   │
                       ▼                       ▼
            ┌──────────────────┐     ┌──────────────────┐
            │ hyperion-agent   │     │ hyperion-agent   │
            │ (master)         │     │ (each worker)    │
            │  ┌─────────────┐ │     │  ┌─────────────┐ │
            │  │ HostingSvc  │ │     │  │ HostingSvc  │ │
            │  └──────┬──────┘ │     │  └──────┬──────┘ │
            │  ┌──────┴──────┐ │     │  ┌──────┴──────┐ │
            │  │ State DB    │ │     │  │ State DB    │ │
            │  │ Adapters    │ │     │  │ Adapters    │ │
            │  │  fs/users   │ │     │  │  fs/users   │ │
            │  │  nginx/php  │ │     │  │  nginx/php  │ │
            │  │  mysql/pg   │ │     │  │  mysql/pg   │ │
            │  │  acme/bkup  │ │     │  │  acme/bkup  │ │
            │  │  wp/ftp     │ │     │  │  wp/ftp     │ │
            │  └─────────────┘ │     │  └─────────────┘ │
            └──────────────────┘     └──────────────────┘
              also runs:               background loops:
              · web UI                  · 60s heartbeat to master
              · audit chain             · scheduler tick / 5 min
              · nodes registry          · cert renewal
              · master signer           · backup retention prune
```

Every adapter takes pre-validated typed arguments and shells out
only via `Command::new(..).arg(..)`. The `AdapterPort` trait is
mocked end-to-end so the orchestrator's rollback paths are unit-
tested in isolation. Wire protocol is `u32be length || JSON`,
max frame 4 MiB.

---

## 📂 Project layout

```
hyperion/
├── Cargo.toml                     # workspace
├── rust-toolchain.toml            # stable
├── crates/
│   ├── hyperion-types/            # newtype IDs + DTOs
│   ├── hyperion-validate/         # Domain + SystemUserName parsers
│   ├── hyperion-rpc/              # trait + wire types + codec
│   ├── hyperion-rpc-server/       # Unix-socket server
│   ├── hyperion-rpc-client/       # Unix-socket client
│   ├── hyperion-state/            # SQLite + 7 migrations + audit chain
│   ├── hyperion-adapters/         # system tool wrappers (12 modules)
│   ├── hyperion-core/             # orchestration + secrets + RealAdapter
│   └── hyperion-auth/             # argon2id + Ed25519 sessions + CSRF
├── bin/
│   ├── hyperion-agent/            # privileged daemon (+ background scheduler)
│   ├── hyperion-web/              # axum admin UI (single binary, embedded HTMX)
│   └── hctl/                      # CLI
├── packaging/
│   ├── install/install-master.sh  # Debian 12 master bootstrap
│   ├── install/install-node.sh    # Debian 12 node bootstrap
│   └── systemd/hyperion-agent.service
└── docs/
    ├── RUNBOOK.md                 # production deploy + ops
    └── superpowers/
        ├── specs/                 # 11 design specs (Foundation + 10 subs)
        ├── plans/                 # Foundation implementation plan
        └── DEFERRED.md            # 1.5 / 5.5 / 9 + ACME + remote backups
```

---

## Status

### Shipped — single node

| Capability | Surface |
|---|---|
| Hosting CRUD (PHP + static + reverse-proxy + DB + TLS) | UI · CLI · RPC |
| Multi-version PHP (8.1 / 8.2 / 8.3 / 8.4) | UI · CLI · RPC |
| MariaDB / PostgreSQL provisioning | UI · CLI · RPC |
| Suspend / resume with full cascade | UI · CLI · RPC |
| Per-hosting limits (PHP + DB + disk + bandwidth) | UI · CLI · RPC |
| Hosting profiles (apply template to many hostings) | UI · RPC |
| Expiration with grace + scheduler | UI · CLI · RPC |
| Local backups (tar.gz + DB dump + manifest) | UI · CLI · RPC |
| Off-site backup push (FTP / FTPS / SFTP) | UI · RPC |
| Real Let's Encrypt HTTP-01 issuing + renewal | UI · CLI · RPC |
| Per-hosting cron editing | UI · RPC |
| Per-hosting log tail (access + error) | UI · RPC |
| Monitor probes (HTTP / TCP) with alerts | UI · RPC |
| WordPress install + plugin manage + admin reset | UI · RPC |
| FTP per-hosting (vsftpd, chroot to home) | UI · RPC |
| Audit log with BLAKE3 hash chain | UI · CLI · RPC |
| Web admin UI with login, 2FA, CSRF, RBAC | — |
| Per-IP rate limits on public endpoints | — |
| Per-hosting + cluster-wide email notifications | UI · RPC |

### Shipped — multi-node cluster

| Capability | Surface |
|---|---|
| Node enrollment (mint / list / revoke invite tokens) | UI · CLI · RPC |
| Master → worker signed RPC channel (Ed25519 envelope) | — |
| Per-page node switcher (services, stats, install) | UI |
| One-click hosting migrate master → worker | UI · RPC |
| Manual export / import bundle (URL + token) | UI · CLI · RPC |
| Connectivity test button per node | UI |
| Remote node update (apt + hyperion) with live log tail | UI · RPC |
| Cluster-wide stats aggregation (totals + per-node) | UI |
| Email test from any node | UI |
| Per-hosting actions (suspend/delete/limits/…) follow the hosting | UI |
| Master-as-control-plane-only toggle | UI · agent.toml |
| Auto-prune of old migration bundles (>7 days) | — |
| Self-heal: nginx start retry + apt install of missing pkgs | — |

### Designed, not yet shipped

- **Security hardening** — managed nftables rules, fail2ban integration, ModSecurity, SSH/sysctl baseline check, compliance dashboard.
- **Worker-as-source migrations** — currently the one-click migrate flow needs the master to be the source (so the master can serve the bundle). Worker→X needs the master to proxy bundle bytes via signed RPC; the work is small and queued.
- **Restic / S3 backup targets** — the off-site push path takes FTP / FTPS / SFTP today; restic + S3 are the next two.
- **Per-node secret rotation** — operator-triggered, agent re-keys on next heartbeat. The infrastructure (hashed secret, constant-time compare) is in place.

---

## Testing

```bash
cargo test --workspace                    # whole suite, runs in seconds on macOS
cargo fmt --all                           # format clean
cargo clippy --workspace --all-targets    # warnings-only
```

A handful of integration tests are gated `#[ignore]` because they
need a real Debian (`useradd`, `mariadb-dump`, `pg_dump`, `systemctl
reload nginx`). To run them on a node:

```bash
cargo test --workspace -- --ignored
```

The web crate's e2e suite drives the entire stack — login flow, CSRF
round-trip, hosting create via form, audit-log render — against a
real Unix-socket-backed agent with mocked adapters. New flows added
to the UI generally land with a matching e2e.

---

## 📚 Documentation

- **[`docs/RUNBOOK.md`](docs/RUNBOOK.md)** — manual production deploy on Debian (apt deps, configs, systemd, MariaDB hardening, troubleshooting, backup, updates, removal).
- **[`docs/superpowers/specs/`](docs/superpowers/specs/)** — 11 design specs (Foundation + 10 sub-projects, each with goals, anti-scope, RPC additions, flows, security model).
- **[`docs/superpowers/plans/`](docs/superpowers/plans/)** — Foundation implementation plan (every task → file paths → code → tests → commit).
- **[`docs/superpowers/DEFERRED.md`](docs/superpowers/DEFERRED.md)** — what's deferred, what's already in place, exact shape of the follow-on work.

---

## Contributing

Spotted a bug or have a feature in mind? Open an issue or PR. Each
crate has a single clear responsibility (the names are descriptive)
so onboarding takes an afternoon.

When adding a new system effect:

1. Adapter function in `hyperion-adapters` — typed args, no shell interpolation, always `Command::new("/usr/bin/foo").arg(...)`.
2. Method on `AdapterPort` trait in `hyperion-core::service` — mockable for unit tests.
3. Orchestration in `HostingService` with a rollback step pushed onto the LIFO stack if it mutates state.
4. RPC variant in `hyperion-rpc::codec` + handler in `AgentApi` + dispatch in `hyperion-rpc-server`.
5. CLI subcommand in `hctl` + UI handler + template in `hyperion-web` if user-facing.
6. Tests at every layer. Pure-logic ones unconditional; the rare integration test that wants `useradd` or `systemctl` gets `#[ignore]`.

For multi-node features specifically:

- Per-hosting actions: read the hosting's `target_node` (via `find_hosting_anywhere`), pass it to `dispatcher::dispatch_to_node` — never go straight to the local socket.
- Forms in the detail page get `target_node` injected as a hidden input by the JS shim at the bottom of `hostings_detail.html`. The matching `Form` struct on the handler just needs `target_node: String`.
- Any RPC the UI calls should be implementable on workers too — i.e. avoid baking master-only assumptions into agent code.

---

## License

[AGPL-3.0-only](#license).

Built as the next-generation alternative to CloudPanel / HestiaCP — Rust
instead of templated PHP, multi-node orchestration built-in from day one,
and a security model that doesn't require trust in panel-level shell
templating.
