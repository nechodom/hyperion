# Setup wizard — implementation plan

Spec: `docs/superpowers/specs/2026-10-07-setup-wizard-design.md`

## Track A — scripts (independent of the Rust work, shared contract below)

A1. `packaging/install/components.sh`
  - `components.sh --prepare` → sury repo for this suite (moved from the installer).
  - `components.sh [--ftp-port N] COMPONENT...` with the allow-list from the spec.
  - Canonical order: php*, mariadb, postgresql, redis, vsftpd, phpmyadmin.
  - `HYP_PROGRESS_FILE`: lines `<component> <pending|running|done|failed>`,
    rewritten atomically on every change.
  - Records each finished component in `/etc/hyperion/components`.
  - Continues past a failed component, exits 1 if any failed, 2 on bad usage.
A2. `install-master.sh` rewrite per spec (wizard mode + unattended mode).
A3. `update.sh` heals only listed components when `/etc/hyperion/components` exists.
A4. `hyperion` wrapper: `setup-link`.

Contract with Track B:
  `hyperion-web --config /etc/hyperion/web.toml setup-init --port P [--san ADDR]...`
  and `... setup-link [--host ADDR]` print `KEY=VALUE` lines:
  `SETUP_URL`, `SETUP_CODE`, `CERT_SHA256`, `EXPIRES_HOURS`. Exit 3 = already set up.

## Track B — Rust

B1. hyperion-types: `SetupStackStatus`, `SetupComponentProgress`.
B2. hyperion-adapters: `setup_stack` (transient unit, embeds components.sh +
    phpmyadmin.sh, progress parse) and `system_identity` (hostname, /etc/hosts,
    time zone; pure validation + rewrite helpers with tests).
B3. RPC: `SetupStackStart`, `SetupStackStatus`, `SetupSystemApply` through
    codec, api, rpc-server, agent, service. Service install appends to the
    components file.
B4. hyperion-web core: `setup` module (state file, code mint/verify, gate
    middleware, hand-off map), optional `web-admin.json`, IP SANs, fingerprint,
    `setup-init` / `setup-link` subcommands.
B5. hyperion-web wizard: handlers + templates + CSS for the nine steps.
B6. Tests: unit + e2e per spec; template_lint stays green.

## Verification

`cargo test --workspace --all-targets`, `cargo clippy --workspace --all-targets`,
`bash -n` + shellcheck on scripts, dev-panel walk through the wizard.
