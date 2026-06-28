# Self-service server-to-server import wizard

**Date:** 2026-06-28 · **Status:** design — awaiting review before build
**Builds on:** the export-bundle backend (`2026-06-28-export-bundle-import-design.md`, shipped 99af91b)

## Goal / UX
An operator who can `sudo` on a source CloudPanel/HestiaCP box — but won't hand
Hyperion an SSH key, and won't shuttle a 50 GB bundle through their laptop —
imports it with **one pasted command** and a **progress bar**:

1. In Hyperion: `/import` → "Remote panel (self-service)" wizard → pick the
   **target node** + source panel kind → Hyperion shows a one-liner:
   ```
   curl -fsSL https://<hyperion>/import/agent/<token> | sudo bash
   ```
2. Operator pastes it on the **source** server. The script downloads the
   exporter, exports the panel, and **pushes the bundle straight to the target
   node** over HTTPS (server→server; nothing through the browser).
3. The target imports it as a **background job**; the wizard shows a progress
   bar at `/jobs/<id>`. Closing the browser changes nothing.

## Architecture (push: source → target)
- **Token** (one-time, ~256-bit, short TTL e.g. 2 h, scoped to {target_node,
  source_kind}, created_by user): new migration `import_tokens` table storing the
  token **hash** (never the plaintext), scope, `expires_at`, `used_at`,
  `received_bytes`, `job_id`, `status`.
- **`GET /import/agent/<token>`** → returns a **bash bootstrap script** (text):
  detects arch (x86_64/arm64), downloads the matching `hyperion-agent` from the
  **GitHub release**, runs `export-bundle --kind <k> --out -` (stream to stdout)
  and pipes it straight into `curl -T - https://<hyperion>/import/ingest/<token>`
  — so the bundle never fully lands on the source disk either. Auditable: the
  operator can `curl …/agent/<token>` (without `| bash`) and read it first.
- **`POST /import/ingest/<token>`** → bearer-token-authed (NO session — the token
  IS the credential). Streams the body to `…/migration/bundle-<token>.tar`
  (chunked, never buffered in RAM), enforces a **disk preflight** (reject early
  if free space < incoming size when known, else guard mid-stream), marks the
  token `used`, then `spawn_job("panel_import", …)` → the existing archive import
  (`Location::Archive`). Returns the job id; the wizard already polls it.
- **Exporter:** the chosen form is **bash bootstrap → GitHub-release binary**
  (reuses the Rust adapters; robust to CloudPanel schema variants). Requires
  cutting a release that includes `export-bundle` (`git tag vX.Y.Z`); the
  release CI must publish `hyperion-agent-{x86_64,aarch64}-linux`.

## Security model (the crux — review this)
- **Wizard mint** requires an authenticated session with `Capability::PanelImport`
  (admin). Only that path creates tokens.
- **The token is a bearer credential** for `agent`+`ingest` (no session there, so
  the source box needs no Hyperion login). Therefore: high entropy, **single
  active use** (consumed on first ingest), **short TTL**, **scoped** to one target
  node + source kind, **rate-limited**, and **revocable** (wizard shows
  "waiting…" with a cancel that deletes the token). Token plaintext shown once in
  the wizard; only its hash is stored.
- **Ingest writes to disk + triggers provisioning** → treat the tar as untrusted:
  extract with **zip-slip/path-traversal hardening** (`tar` with
  `--no-same-owner`, reject `..`/absolute members; reuse the SEC-2 restore
  hardening posture), into a per-token temp dir, removed after import.
- **`curl | sudo bash` runs as root on the source** — the operator trusts their
  own Hyperion's served script (it's their panel). The script is plain + short +
  auditable; it pins the release URL + verifies the binary checksum before run.
- TLS required end to end; the token only ever travels over HTTPS. No secrets in
  the job payload (the [[long-actions-are-background-jobs]] rule).

## Reachability
The **source must reach the target Hyperion's public HTTPS URL** (outbound from
source → works through source-side NAT/firewall). The target's panel URL is
configured (the cert/hostname Hyperion already serves). Self-hosted localhost-only
Hyperion can't be a target for a remote source (stated limit).

## Components / touch points
1. migration `0NN_import_tokens.sql` + `hyperion-state` token CRUD.
2. web: wizard template + `GET /import/agent/:token` (script) + `POST
   /import/ingest/:token` (streamed, `DefaultBodyLimit` raised/disabled for that
   route) + token mint/cancel handlers; nav already gated on PanelImport.
3. reuse: `export-bundle` (stdout streaming variant `--out -`), `Location::Archive`
   import, `spawn_job`.
4. release: publish multi-arch `hyperion-agent` (build workflow).

## Testing plan
- Unit: token lifecycle (mint → one-time consume → expiry → revoke).
- Leg 1: `GET /import/agent/<token>` returns a valid script; bad/expired token → 404.
- Leg 2: `POST /import/ingest/<token>` with a real bundle (curl -T) → streamed to
  disk, preflight, import job created, token consumed; replay → rejected.
- E2E: on a reachable pair (cloudpanel VM → a target reachable from it), run the
  actual one-liner and watch the job to completion. (lima NAT makes a true
  cross-VM test awkward; will arrange a reachable target or simulate the source
  leg with a local curl push.)

## Out of scope (v1)
Resumable/Chunked-with-resume uploads (a dropped 50 GB push restarts); multi-source
batch; progress % of the *export* step on the source (show received-bytes +
import-job progress instead).
