# linux-manager

A Rust-based hosting control panel for Debian 12+. Built as a privileged
agent daemon (`lm-agent`) plus an unprivileged CLI client (`lm`),
communicating over a local Unix-socket RPC. Designed to grow into a
multi-node setup (controller + N agents over mTLS) — see the design
specs under [`docs/superpowers/specs/`](docs/superpowers/specs/).

This repository currently contains **sub-project 1 (Foundation)** —
the core agent capable of provisioning hostings (PHP-FPM + nginx +
MariaDB/PostgreSQL + Let's Encrypt). All later phases (controller,
admin UI, quotas, expiration, backups, migration, client portal,
WordPress installer, Node.js stack, hardening) have full design specs
and will land in subsequent sub-projects.

## Status

| Phase | Component | Tests | Status |
|---|---|---|---|
| A | Workspace + `lm-types` + `lm-validate` + `lm-rpc` | 49 | ✅ |
| B | `lm-state` (SQLite + audit chain) | 26 | ✅ |
| C | `lm-rpc-server` + `lm-rpc-client` (Unix socket) | 6 | ✅ |
| D | `lm-adapters` (fs, users, nginx, phpfpm, mariadb, postgres, acme) | 35+3⁻ | ✅ |
| E | `lm-core` (orchestrator + secrets) | 16 | ✅ |
| F | `lm-agent` daemon + `lm` CLI | 7 | ✅ |
| G | End-to-end socket+state+orchestrator integration | 4 | ✅ |

⁻ = 3 integration tests gated `#[ignore]` (require root + Debian system tools).

**Total: 143 tests passing on macOS** (CI matrix for Debian integration
tests is part of sub-project 9).

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
   ┌───────────────────────┴┐       ┌┴──────────────────────┐
   │  lm-agent              │       │  lm  (CLI)            │
   │  (root daemon)         │       │  uid != 0,            │
   │                        │       │  in lm-admin group    │
   │  ┌───────────────────┐ │       └───────────────────────┘
   │  │ lm-rpc-server     │ │
   │  └────────┬──────────┘ │
   │  ┌────────▼──────────┐ │
   │  │ AgentImpl         │ │       lm-rpc:
   │  │  → HostingService │ │       transport-agnostic
   │  └────────┬──────────┘ │       AgentApi trait
   │   ┌───────┴──────────┐ │       + JSON frame codec.
   │   │ lm-state (SQLite) │ │
   │   │ lm-adapters       │ │
   │   │   fs / users      │ │
   │   │   nginx / phpfpm  │ │
   │   │   mariadb /pg/acme│ │
   │   └───────────────────┘ │
   └────────────────────────┘
```

## Build

```bash
git clone <this repo> linux-manager
cd linux-manager
cargo build --release --workspace
```

Binaries land in `target/release/{lm-agent, lm}`.

## Develop

```bash
cargo test --workspace            # 143 tests
cargo fmt --all                   # format
cargo clippy --workspace --all-targets   # lint
```

Integration tests that require root (useradd) or system services
(mariadb/postgres) are gated `#[ignore]`. Run them on a fresh Debian VM:

```bash
cargo test --workspace -- --ignored
```

## Try It Locally (no root)

```bash
# Terminal A — run the agent with a temp config
mkdir -p /tmp/lm-state
cat > /tmp/agent.toml <<EOF
[agent]
socket_path = "/tmp/lm-agent.sock"
state_db    = "/tmp/lm-state/state.db"
secrets_dir = "/tmp/lm-state/secrets"
log_path    = "/tmp/lm-state/agent.log"
home_root   = "/tmp/lm-state/home"

[acme]
contact_email = "you@example.com"
challenge_dir = "/tmp/lm-state/acme"
EOF

cargo run --bin lm-agent -- --config /tmp/agent.toml &

# Terminal B
target/debug/lm --socket /tmp/lm-agent.sock info
target/debug/lm --socket /tmp/lm-agent.sock hosting list
# Note: hosting create on macOS will fail at `useradd` — see RUNBOOK.md.
```

For production deployment on Debian, see [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## Project Layout

```
linux-manager/
├── Cargo.toml                     # workspace
├── rust-toolchain.toml            # stable
├── crates/
│   ├── lm-types/                  # newtype IDs + DTOs (12 tests)
│   ├── lm-validate/               # Domain + SystemUserName parsers (16)
│   ├── lm-rpc/                    # trait + wire + codec (21)
│   ├── lm-rpc-server/             # Unix socket server (5+4 e2e)
│   ├── lm-rpc-client/             # Unix socket client (1)
│   ├── lm-state/                  # SQLite + audit chain (26)
│   ├── lm-adapters/               # system tool wrappers (35+3⁻)
│   └── lm-core/                   # orchestration + secrets (16)
├── bin/
│   ├── lm-agent/                  # daemon (2)
│   └── lm/                        # CLI (5)
└── docs/
    └── superpowers/
        ├── specs/                 # 11 design specs (Foundation + 10 sub-projects)
        └── plans/                 # Foundation implementation plan
```

## Roadmap

The remaining sub-projects (each with a full design spec under
`docs/superpowers/specs/`) build on Foundation:

| # | Sub-project | Purpose |
|---|---|---|
| 1.5 | Controller + agent enrollment | mTLS, CA, multi-node management, one-liner installer |
| 2 | Admin UI + auth + audit | axum + askama + HTMX web admin with TOTP login |
| 3 | Limits / quotas / suspend | Disk quotas, FPM limits, nftables bandwidth, suspend/resume |
| 4 | Expiration + scheduler | Per-hosting expiry, pre-warning emails, auto-suspend, grace |
| 5 | Backups | restic + SFTP/S3/FTP, restore from upload |
| 5.5 | Site migration | Inter-agent migrations with short downtime + rollback window |
| 6 | Client portal | End-user portal with self-service FTP user management |
| 7 | WordPress + templates | 1-click WP installer with admin-curated plugin/theme bundles |
| 8 | Node.js stack | systemd-managed Node apps with nginx reverse proxy |
| 9 | Security hardening | nftables, fail2ban, ModSecurity, hardening checklist |

## License

AGPL-3.0-only.
