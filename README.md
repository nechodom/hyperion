# 🦅 Hyperion

> A Rust-based hosting control panel for Debian 12+. Build, suspend,
> back up, schedule expiration of WordPress / PHP / static / Node.js
> sites — one binary, one Unix socket, one web UI. Designed for
> agencies who host their clients.

[![Tests](https://img.shields.io/badge/tests-233%20passing-success)](#testing)
[![Rust](https://img.shields.io/badge/rust-stable-orange)](#)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](#license)

---

## ✨ What you get out of the box

- 🏠 **One-command hosting CRUD** — Linux user, PHP-FPM pool, MariaDB/Postgres DB, nginx vhost, TLS cert. Atomic with LIFO rollback on failure.
- 🌐 **PHP 8.1 / 8.2 / 8.3 / 8.4** in parallel via deb.sury.org. Static-only sites supported. Node.js stack scaffolding ready.
- 🛡 **Suspend / resume** with cascade: 503 page, FPM stop, DB lock, login lock, kill user processes. Fully reversible.
- 📊 **Per-pool limits** — memory, exec time, max children, DB connections — clamped before storage.
- ⏰ **Expiration + background scheduler** — pre-expiry notifications, auto-suspend, grace window, auto-delete with safety net.
- 💾 **Local backups** — tar.gz of htdocs + mysqldump/pg_dump + JSON manifest. Restic + SFTP/S3 targets planned.
- 🧱 **Tamper-evident audit log** — BLAKE3 hash chain, broken-chain refusal at startup.
- 🔐 **Auth done right** — argon2id passwords (OWASP params), Ed25519 signed cookies, CSRF tokens scoped per session+form, constant-time username compare.
- 🖥 **Modern web UI** — axum + askama + HTMX, dark + light via `prefers-color-scheme`, zero JS build, single binary.
- 🎟 **Multi-node enrollment** — invite tokens minted in the UI, install-node.sh one-liner with the token embedded. Plaintext shown once; only hash persisted.
- 🦀 **`#![forbid(unsafe_code)]` everywhere.** No `shell -c`, every command is `Command::new(..).arg(..)` with regex-validated arguments.

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

### Adding a node

1. Log in to the master's web UI → **Install** in the navigation
2. Fill the label (e.g. `node5.example.com`) and TTL, click **Generate invite**
3. Copy the one-liner shown — it embeds the freshly-minted token. **The plaintext is displayed exactly once**; only its hash is persisted server-side.
4. Run it on the new VPS as root:

```bash
curl -fsSL https://<master>/install/install-node.sh \
  | sudo bash -s -- --token=ABCD-EFGH-… --master=https://<master>
```

The node bootstraps with the same apt deps, builds `hyperion-agent` +
`hctl`, writes the token + master URL into `/etc/hyperion/agent.toml`,
and starts the agent. Once the controller's mTLS enrollment loop ships
(sub-project 1.5), the agent rolls into the cluster automatically.

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
example.cz          8.3    ● active     2 hours ago
blog.kevin.cz       8.4    ● active     yesterday
staging.client.cz   8.3    ⚠ suspended  3 days ago
```

### CLI — `hctl`

```
$ hctl info
agent: master.example.cz version=0.1.0 schema=2 hostings=12

$ hctl hosting create example.cz --php 8.3 --db mariadb
✓ created example_cz (id=01K4Z…)
  root: /home/example_cz/example.cz/htdocs
  db:   lm_a8c_examplecz (user=lm_a8c_u, password=Hx9k…RnG2)
  cert: issuer=self-signed, not_after=2027-06-01

$ hctl hosting suspend example.cz --reason="payment overdue"
✓ suspended

$ hctl hosting backup-now example.cz
✓ backup 17 ok
  archive: /var/lib/hyperion/backups/local/example_cz/example.cz-1764672000.tar.gz
  db_dump: /var/lib/hyperion/backups/local/example_cz/example.cz-1764672000.sql
  bytes:   148373921

$ hctl audit --limit 5
   ID TS                 ACTOR          ACTION                  RESULT
   42 1764672135         agent          hosting.backup          ok
   41 1764672120         agent          hosting.suspend         ok
   40 1764672110         cli:root       hosting.set_limits      ok
   …
```

---

## 🏗 Architecture

```
                         ┌──────────────────────────┐
                         │    Unix socket           │
                         │    /run/hyperion.sock    │
                         │    (0660, hyperion-admin)│
                         └─────┬───────────┬────────┘
                               │           │
            Privileged ◀───────┘           └───────▶ Unprivileged
                               │           │
            ┌──────────────────┴┐         ┌┴───────────────────────┐
            │  hyperion-agent   │         │  hctl      hyperion-web│
            │  (root daemon)    │         │  (CLI)     (web UI)    │
            │                   │         │  in hyperion-admin grp │
            │  ┌──────────────┐ │         └────────────────────────┘
            │  │ hyperion-rpc │ │           Transport-agnostic
            │  │   -server    │ │           AgentApi + JSON codec.
            │  └──────┬───────┘ │           Future: mTLS variant
            │  ┌──────▼───────┐ │           with same trait.
            │  │ HostingSvc   │ │
            │  └──────┬───────┘ │           Background loops:
            │   ┌─────┴──────┐  │             • scheduler tick / 5 min
            │   │ State DB   │  │             • cert renewal (planned)
            │   │ Adapters   │  │             • backup retention
            │   │  fs/users  │  │
            │   │  nginx/php │  │           Audit chain verified on
            │   │  mysql/pg  │  │           every startup; broken
            │   │  acme/bkup │  │           chain refuses to start.
            │   │  nodejs/wp │  │
            │   └────────────┘  │
            └───────────────────┘
```

Every adapter takes pre-validated typed arguments and shells out only
via `Command::new(..).arg(..)`. Mass-mocked via the `AdapterPort`
trait so the orchestrator's rollback paths are unit-tested in
isolation. Wire protocol is `u32be length || JSON`, max frame 4 MiB.

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

## ✅ Status

### Shipped today (single-node end-to-end)

| Capability | Surface |
|---|---|
| Hosting CRUD (PHP + static + DB + cert) | UI · CLI · RPC |
| Multi-version PHP (8.1 / 8.2 / 8.3 / 8.4) | UI · CLI · RPC |
| MariaDB / PostgreSQL provisioning | UI · CLI · RPC |
| Suspend / resume with full cascade | UI · CLI · RPC |
| Per-pool limits (PHP + DB) | UI · CLI · RPC |
| Expiration with grace + scheduler | CLI · RPC |
| Local backups (tar.gz + DB dump + manifest) | CLI · RPC |
| Audit log with BLAKE3 hash chain | UI · CLI · RPC |
| Web admin UI with auth + CSRF | — |
| Node enrollment tokens (mint / list / revoke) | UI · CLI · RPC |
| `install-master.sh` / `install-node.sh` | — |

### Designed, deferred until first Debian deploy

These have **full design specs + integration paths documented**; they
require real Linux system tools to test meaningfully. See
[`docs/superpowers/DEFERRED.md`](docs/superpowers/DEFERRED.md).

- **1.5** Controller + multi-node mTLS enrollment (rcgen CA, rustls TLS, `hyperion-controller` binary). Invite token storage already in place.
- **5.5** Inter-agent migration (depends on 1.5)
- **9** Security hardening: nftables management, fail2ban, ModSecurity, SSH/sysctl hardening, 30-point compliance check
- Real ACME HTTP-01 loop (rcgen self-signed today; `instant-acme` crate already imported)
- Remote backup targets (restic + SFTP / S3 / FTP via rclone)

---

## 🧪 Testing

```bash
cargo test --workspace           # 233 tests pass on macOS
cargo fmt --all                  # format clean
cargo clippy --workspace --all-targets   # warnings-only
```

4 integration tests are gated `#[ignore]` (they require `useradd` /
`mariadb-dump` / `pg_dump` / `systemctl reload`). To run them on
Debian:

```bash
cargo test --workspace -- --ignored
```

The web UI ships with **12 full-flow end-to-end tests** that drive
the entire stack — login flow, CSRF token round-trip, hosting create
via form, audit log render — against a real Unix-socket-backed agent
fixture with mocked adapters.

---

## 📚 Documentation

- **[`docs/RUNBOOK.md`](docs/RUNBOOK.md)** — manual production deploy on Debian (apt deps, configs, systemd, MariaDB hardening, troubleshooting, backup, updates, removal).
- **[`docs/superpowers/specs/`](docs/superpowers/specs/)** — 11 design specs (Foundation + 10 sub-projects, each with goals, anti-scope, RPC additions, flows, security model).
- **[`docs/superpowers/plans/`](docs/superpowers/plans/)** — Foundation implementation plan (every task → file paths → code → tests → commit).
- **[`docs/superpowers/DEFERRED.md`](docs/superpowers/DEFERRED.md)** — what's deferred, what's already in place, exact shape of the follow-on work.

---

## 🤝 Contributing

Spotted a bug or have a feature in mind? Open an issue or PR — the
codebase is small (~13 000 LOC of Rust) and each crate has a single
clear responsibility, so onboarding is fast.

When adding a new system effect, follow the existing pattern:

1. Adapter function in `hyperion-adapters` (typed args, no shell interpolation)
2. Method on `AdapterPort` trait in `hyperion-core::service`
3. Orchestration in `HostingService` with rollback if it mutates state
4. RPC variant in `hyperion-rpc::codec` + handler in `AgentApi`
5. CLI subcommand in `hctl` + UI handler in `hyperion-web` if user-facing
6. Tests at every layer; integration tests `#[ignore]` if they need root

---

## 📜 License

[AGPL-3.0-only](#license).

Built as the next-generation alternative to CloudPanel / HestiaCP, but
in Rust, with multi-node orchestration baked in from day one and a
security model that doesn't require trust in panel-level shell
templating.
