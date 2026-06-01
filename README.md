# linux-manager

A Rust-based hosting control panel for Debian 12+. Built as a privileged
agent daemon (`lm-agent`) plus an unprivileged CLI client (`lm`) and a
modern axum web UI (`lm-web`), communicating over a local Unix-socket
RPC. Designed to grow into a multi-node setup (controller + N agents
over mTLS) — see the design specs under
[`docs/superpowers/specs/`](docs/superpowers/specs/).

## Status

| Phase | Component | Tests | Status |
|---|---|---|---|
| A | Workspace + `lm-types` + `lm-validate` + `lm-rpc` | 49 | ✅ |
| B | `lm-state` (SQLite + hash-chain audit) | 48 | ✅ |
| C | `lm-rpc-server` + `lm-rpc-client` (Unix socket) | 6 | ✅ |
| D | `lm-adapters` (fs, users, nginx, phpfpm, mariadb, postgres, acme) | 40+4⁻ | ✅ |
| E | `lm-core` (orchestrator + secrets + RealAdapter) | 25 | ✅ |
| F | `lm-agent` daemon + `lm` CLI | 7 | ✅ |
| G | End-to-end socket+state+orchestrator integration | 4 | ✅ |
| H | `lm-auth` (argon2id + Ed25519 sessions + CSRF + keys) | 21 | ✅ |
| I | `lm-web` (axum + askama + HTMX modern admin UI) | 4 unit | ✅ |
| J | lm-web full-flow tests (login, dashboard, hosting CRUD) | 12 e2e | ✅ |
| K | Limits + quotas + suspend/resume (sub-project 3) | 13 | ✅ |
| L | Expiration + background scheduler (sub-project 4) | 10 | ✅ |
| M | Audit log viewer | covered by 12 e2e | ✅ |
| N | Local backups (tar.gz + mysqldump/pg_dump) (sub-project 5) | 5+3⁻ | ✅ |
| O | Node.js stack (sub-project 8) | 8 | ✅ |
| P | WordPress installer + app packs (sub-project 7) | 8 | ✅ |
| Q | Workspace verification + docs | — | ✅ |

⁻ = integration tests gated `#[ignore]` (need root + Debian system tools).

**Total: 224 tests passing on macOS** without any privileged
operations. Real Debian integration tests run with `--ignored`.

## Features

### Hosting management
- Create / list / get / delete hostings via CLI or web UI
- Per-domain Linux user, chrooted home, dedicated PHP-FPM pool, MariaDB
  or PostgreSQL DB, Let's Encrypt or self-signed cert, nginx vhost
- Multi-version PHP (8.1 / 8.2 / 8.3 / 8.4) via deb.sury.org
- Static-only sites (no PHP)
- Aliases with shared cert (SANs)

### Operational
- **Suspend / resume** — nginx 503 page + FPM stop + DB lock +
  login lock + kill user procs; fully reversible
- **Per-pool limits** — memory, max execution time, max_children,
  max_requests, DB max_connections; range-clamped before storage
- **Expiration** — per-hosting expires_at + grace_days + warning
  offsets; controller-side scheduler fires notifications, auto-suspend
  on expiry, auto-delete after grace
- **Background scheduler** — tokio interval task in lm-agent runs every
  5 minutes; reconciles missing rows from live hostings; pending
  actions retried 3× with mark_failed_or_retry

### Data safety
- LIFO rollback stack on multi-step provisioning
- Hash-chain audit log (BLAKE3) with tamper detection
- Local backups: tar.gz of htdocs + DB dump + JSON manifest
- Secret files in `/etc/linux-manager/secrets/` (mode 0600)
- No shell interpolation anywhere; every `Command::new(..).arg(..)`
- `#![forbid(unsafe_code)]` on every crate

### Web UI (`lm-web`)
- Modern axum + askama + HTMX admin panel
- Single-user bootstrap auth, argon2id passwords, Ed25519-signed
  session cookies, CSRF tokens scoped per session+form
- Dashboard with agent + hostings cards, hosting CRUD with form
  validation feedback, limits form, suspend/resume buttons, audit log
  viewer
- Dark + light theme via `prefers-color-scheme`, ~6 KB hand-written
  CSS, HTMX 2.0.4 embedded into the binary (no JS build)

### CLI (`lm`)
- `lm info` / `lm hosting create|list|get|delete`
- `lm hosting suspend|resume`
- `lm hosting set-limits|get-limits|usage`
- `lm hosting set-expiry|get-expiry|upcoming-expiries`
- `lm hosting backup-now|backup-list`
- `lm audit`
- `--json` flag on every subcommand for machine consumption

## Architecture

```
                  ┌──────────────────────────┐
                  │  Unix socket             │
                  │  /run/linux-manager.sock │
                  │  (mode 0660, lm-admin)   │
                  └────────┬─────────┬───────┘
                           │         │
       Server side ▲       │         │       ▼ Client side
                           │         │
   ┌───────────────────────┴┐       ┌┴──────────────────────────┐
   │  lm-agent              │       │  lm  (CLI) │ lm-web       │
   │  (root daemon)         │       │  unprivileged, in         │
   │                        │       │  lm-admin group           │
   │  ┌───────────────────┐ │       └───────────────────────────┘
   │  │ lm-rpc-server     │ │
   │  └────────┬──────────┘ │
   │  ┌────────▼──────────┐ │
   │  │ AgentImpl         │ │       lm-rpc:
   │  │  → HostingService │ │       transport-agnostic
   │  └────────┬──────────┘ │       AgentApi trait
   │   ┌───────┴──────────┐ │       + length-prefixed JSON codec.
   │   │ lm-state (SQLite) │ │
   │   │ lm-adapters       │ │       Background:
   │   │   fs/users/nginx  │ │       - scheduler_tick every 5 min
   │   │   phpfpm/mariadb  │ │         (expiration → suspend → delete)
   │   │   postgres/acme   │ │       - audit chain verified on startup
   │   │   backup/wpcli    │ │
   │   │   nodejs          │ │
   │   └───────────────────┘ │
   └────────────────────────┘
```

## Build

```bash
git clone <this repo> linux-manager
cd linux-manager
cargo build --release --workspace
```

Binaries land in `target/release/{lm-agent, lm, lm-web}`.

## Develop

```bash
cargo test --workspace            # 224 tests
cargo fmt --all                   # format
cargo clippy --workspace --all-targets   # lint
```

Integration tests that require root (useradd) or system services
(mariadb-dump / pg_dump) are gated `#[ignore]`. Run them on a fresh
Debian VM:

```bash
cargo test --workspace -- --ignored
```

## Try It Locally (no root)

```bash
# Terminal A — run the agent
mkdir -p /tmp/lm-demo
cat > /tmp/lm-demo/agent.toml <<EOF
[agent]
socket_path = "/tmp/lm-demo/agent.sock"
state_db    = "/tmp/lm-demo/state.db"
secrets_dir = "/tmp/lm-demo/secrets"
log_path    = "/tmp/lm-demo/agent.log"
home_root   = "/tmp/lm-demo/home"
backup_root = "/tmp/lm-demo/backups"

[acme]
contact_email = "you@example.com"
challenge_dir = "/tmp/lm-demo/acme"
EOF
cargo run --bin lm-agent -- --config /tmp/lm-demo/agent.toml &

# Terminal B — run the web UI
cat > /tmp/lm-demo/web.toml <<EOF
[web]
listen = "127.0.0.1:8443"
agent_socket = "/tmp/lm-demo/agent.sock"
admin_user_file = "/tmp/lm-demo/admin.json"
session_key_file = "/tmp/lm-demo/sess.key"
csrf_key_file = "/tmp/lm-demo/csrf.key"
secure_cookies = false   # plain HTTP in dev
EOF
cargo run --bin lm-web -- --config /tmp/lm-demo/web.toml bootstrap \
    --username kevin --password "your-strong-password"
cargo run --bin lm-web -- --config /tmp/lm-demo/web.toml

# Browser
open http://127.0.0.1:8443/         # → /login

# CLI alternative
target/debug/lm --socket /tmp/lm-demo/agent.sock info
target/debug/lm --socket /tmp/lm-demo/agent.sock hosting list
target/debug/lm --socket /tmp/lm-demo/agent.sock audit
# Note: hosting create on macOS will fail at `useradd` — see RUNBOOK.md.
```

For production deployment on Debian, see [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## Project Layout

```
linux-manager/
├── Cargo.toml                     # workspace
├── rust-toolchain.toml            # stable
├── crates/
│   ├── lm-types/                  # newtype IDs + DTOs (limits/expiry/backup)
│   ├── lm-validate/               # Domain + SystemUserName parsers
│   ├── lm-rpc/                    # trait + wire + codec
│   ├── lm-rpc-server/             # Unix socket server
│   ├── lm-rpc-client/             # Unix socket client
│   ├── lm-state/                  # SQLite + 6 migrations + audit chain
│   │                              # + limits / scheduler / backups /
│   │                              #   nodejs / wordpress
│   ├── lm-adapters/               # system tool wrappers (10 modules)
│   ├── lm-core/                   # orchestration + secrets + RealAdapter
│   └── lm-auth/                   # argon2id + Ed25519 sessions + CSRF
├── bin/
│   ├── lm-agent/                  # daemon (background scheduler too)
│   ├── lm/                        # CLI
│   └── lm-web/                    # axum admin UI
└── docs/
    ├── RUNBOOK.md                 # Debian 12 deployment runbook
    └── superpowers/
        ├── specs/                 # 11 design specs (Foundation + 10 subs)
        ├── plans/                 # Foundation implementation plan
        └── DEFERRED.md            # 1.5 / 5.5 / 9 deferred to Linux deploy
```

## Roadmap

Sub-projects 1.5 (controller mTLS + multi-node), 5.5 (inter-agent
migration), and 9 (security hardening with nftables / fail2ban /
ModSecurity) require Linux-only system features and are deferred until
the panel runs against a real Debian deploy. See
[`docs/superpowers/DEFERRED.md`](docs/superpowers/DEFERRED.md) for the
specific tasks and dependencies. Each one has a complete design spec
already and a clear implementation surface — they will land as
follow-on commits when a Debian CI runner is wired in.

| # | Sub-project | Status |
|---|---|---|
| 1 | Foundation | shipped (phases A–G) |
| 1.5 | Controller + agent enrollment (mTLS, CA, multi-node) | spec done, deferred |
| 2 | Admin UI + auth + audit | shipped (phases H–J, M) |
| 3 | Limits / quotas / suspend | shipped (phase K) |
| 4 | Expiration + scheduler | shipped (phase L) |
| 5 | Local backups (tar+gzip+dump) | shipped (phase N); remote targets + restic deferred |
| 5.5 | Inter-agent migration | spec done, depends on 1.5 + remote 5 |
| 6 | Client portal | spec done, deferred |
| 7 | WordPress + templates | shipped (phase P) — orchestration loop wires to wpcli wrapper |
| 8 | Node.js stack | shipped (phase O) — orchestration loop wires to nodejs/systemd module |
| 9 | Security hardening | spec done, deferred |

## License

AGPL-3.0-only.
