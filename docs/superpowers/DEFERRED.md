# Deferred sub-projects

These sub-projects have complete design specs under
[`specs/`](specs/) but their implementation requires Linux-only system
facilities (mTLS PKI infrastructure with apt-repo distribution, real
nftables tables, ModSecurity loaded by nginx, fail2ban running, etc.)
that can't be exercised meaningfully from macOS unit tests. They are
deferred until the panel runs against a Debian deploy with a CI runner
that has the relevant system tools available.

Every deferred item lists what's already in place, what's missing, and
the exact shape of the follow-on work.

---

## Sub-project 1.5 — Controller + Multi-agent Enrollment

**Spec:** [2026-05-31-controller-enrollment-design.md](specs/2026-05-31-controller-enrollment-design.md)

**What's already in place:**
- The `AgentApi` trait is transport-agnostic; `hyperion-rpc-server` over a
  Unix socket works today. A future `hyperion-rpc-tls` crate that serves the
  same trait over mTLS TCP is a drop-in.
- The wire codec (`u32be length || JSON body`, max 4 MiB) doesn't change.
- `hyperion-auth` already has Ed25519 session signing and a `keys::load_or_init`
  helper that's the right shape for storing the controller's CA key.

**What's missing for a working controller:**
1. **`hyperion-ca` crate** — rcgen-based CA: generate root, sign agent CSRs,
   publish the root cert + (optional) CRL.
2. **`hyperion-rpc-tls` crate** — rustls-based server + client speaking the
   same `AgentApi` trait. Pinning the agent leaf cert SHA-256 on
   connect.
3. **`hyperion-controller` binary** — controller daemon. Has its own SQLite
   (`agents`, `agent_invites`, `ca_state`, `crl_entries`,
   `controller_audit_log`). HTTP server with `POST /enroll`, `GET
   /install` (serves the bash one-liner), `GET /apt/*` (apt repo).
   Background reconcilers for agent health-check + cert renewal.
3. **`lmc` CLI** — controller-side CLI: `agent invite/list/show/
   remove/health`.
4. **Apt repo packaging** — `hyperion-agent.deb` built by `cargo-deb` and
   published into the controller's `/apt` endpoint.
5. **One-liner installer** — bash script template at
   `crates/hyperion-controller-core/templates/install.sh.j2` that gets
   stamped with the public hostname and served from `GET /install`.

**Pre-conditions for tests:**
- libvirt / qemu with at least two Debian 12 VMs (controller + agent)
- public DNS or `/etc/hosts` overrides so the controller cert resolves
- Let's Encrypt staging access (or just rcgen self-signed for tests)

## Sub-project 5.5 — Inter-agent migration

**Spec:** [2026-05-31-migration-design.md](specs/2026-05-31-migration-design.md)

**Depends on:** 1.5 (controller) and remote backup targets from
extended Sub-project 5.

**What's in place:**
- `HostingService::backup_now` produces a tar.gz + DB dump archive.
  This is the source-side artifact a migration consumes.
- The `hosting_set_domain` RPC stub is documented in the spec.

**What's missing:**
1. `migrations` table on the controller (state machine:
   preparing → prepared → cutting-over → cut-over → committed).
2. Three controller RPC calls: `migration_start`, `migration_cutover`,
   `migration_commit` (+ `migration_abort`).
3. Shared transit target requirement — `backup_targets` extended to
   register the same offsite repo on both source + target agents.
4. `hosting_set_domain` RPC on the agent: rename the hosting row, swap
   the nginx vhost file, re-issue cert for the real domain, atomic.

**Pre-conditions for tests:**
- Two agents reachable from the controller
- A shared S3-compatible bucket (or just SFTP target) both agents trust

## Sub-project 9 — Security hardening

**Spec:** [2026-05-31-security-hardening-design.md](specs/2026-05-31-security-hardening-design.md)

**What's in place:**
- `hyperion-adapters/templates/nginx-vhost.conf.j2` already emits HSTS,
  strict ciphers, X-Frame-Options, server_tokens off.
- `hyperion-rpc-server` sets socket mode 0660, group hyperion-admin.
- `hyperion-core::HostingService` audit-logs every state-changing operation;
  the chain is BLAKE3 + can be verified on startup.
- All adapter modules forbid `unsafe_code` and use only
  `Command::new().arg()`.

**What's missing:**
1. **nftables management** — a small DSL for `inet lm` table (already
   sketched for sub-project 3's bandwidth counters); plus default-DROP
   policy, fail2ban `blocked_ips_v4/v6` sets, agent mTLS port allow.
2. **fail2ban integration** — jail templates + custom filters for
   nginx-4xx + hyperion-admin-login + nftables banaction.
3. **ModSecurity v3** — apt install + per-vhost `modsecurity on;` /
   `modsecurity_rules 'SecRuleEngine DetectionOnly';` template
   variant. WAF mode is already a per-hosting flag in the spec.
4. **SSH hardening** — `/etc/ssh/sshd_config.d/50-lm.conf` writer.
5. **sysctl hardening** — `/etc/sysctl.d/50-lm.conf` writer.
6. **`lm hardening apply/check`** — implement the 30-point checklist
   trait.

**Pre-conditions for tests:**
- A Debian 12 VM with nginx + libnginx-mod-http-modsecurity + fail2ban
- A peer VM to run nmap / curl against the hardened one

---

## What about real ACME?

The current `RealAdapter::acme_issue` generates a self-signed cert via
rcgen so the pipeline (DB + nginx + state) works end-to-end on day one.
A real HTTP-01 ACME loop is a small lm-adapter extension on top of the
existing `instant-acme` dependency — but tying it correctly to the
nginx temp-vhost dance is best tested on a real public host where
Let's Encrypt's validation can hit `/.well-known/acme-challenge/`.
Operators replace certs via `hctl cert renew` once the loop ships.

## What about real remote backup targets?

Phase N ships a local `tar.gz + mysqldump` target. Adding SFTP / S3 /
restic targets is mechanical:

1. Extend `backup_targets` (table is already in the spec for sub-project 5).
2. Add `hyperion-adapters::restic` wrapping `restic backup` with a repo URL
   per target.
3. Per-policy scheduling via the existing `scheduler` infrastructure
   from phase L (add `BackupNow` as a new `ScheduledKind`).
4. Restore-from-upload: chunked stream RPC (already designed as
   `UploadHandle` in the spec).

Each layer is independently testable against `minio/minio` and
`linuxserver/openssh` containers.
