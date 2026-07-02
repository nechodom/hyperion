# Scriptable remote management API — design

Status: approved (2026-07-02). Builds on the P1/P1b API already shipped
(`2026-06-30-remote-management-api-design.md`). Driver: make `/api/v1`
genuinely scriptable/automatable — "chtěl bych propracovanou, aby se to tím
dalo nascriptovat."

## Goal

Turn today's read-plus-lifecycle `/api/v1` into a **complete, documented,
scriptable** control surface an operator can drive from CI, cron, or their own
tooling — provisioning new sites and running ops on existing ones — with a
machine-readable contract (OpenAPI) and an official CLI (`hctl remote`).

## Decisions (locked by the brainstorm)

- **Use cases:** provisioning / IaC **and** ops on existing sites. (Monitoring
  export and per-tenant billing are out of scope for this design.)
- **Contract & tooling:** OpenAPI 3 spec **plus** a thin `hctl remote` CLI.
- **Auth reach:** admin `scope_all` keys **only** (the mint gate stays), plus
  per-key hardening (IP allowlist + rate limit). No per-tenant keys → tenant
  read-scoping stays deferred; every key sees the whole cluster.
- **Pace:** full spec up front, then ship endpoint groups slice-by-slice, each
  a versioned PR.

## Current state (shipped)

- Bearer `hyp_…` keys; SHA-256 stored; owner-clamped caps + `scope_all`;
  live owner enforcement (`api_keys::clamp_to_owner`).
- `GET /api/v1/{me, hostings, hostings/:id, nodes, jobs/:id}`.
- `POST /api/v1/hostings/:id/{suspend,resume}`, `DELETE /api/v1/hostings/:id`
  (→ 202 job), authorized via `resolve_manage` → `require_hosting_access`.
- Errors: `{"error":{"code","message"}}` with correct status.

## Cross-cutting conventions

The contract that makes the surface scriptable. All apply cluster-wide (every
key is `scope_all`).

### Base
`/api/v1`, JSON in/out, `Authorization: Bearer hyp_…`. **Additive-only within
v1** — no field is removed or repurposed; breaking changes would open `/api/v2`.

### List envelope + pagination
`GET /api/v1/hostings` returns:
```json
{ "items": [ /* HostingSummary */ ], "next_cursor": "<opaque>|null", "total": 123 }
```
Query params:
- `limit` — 1..200, default 50.
- `cursor` — opaque keyset cursor (base64 of the last item's id); absent = first page.
- `state` — `active` | `suspended` filter.
- `node` — node id filter.
- `q` — case-insensitive domain substring.

The list is aggregated in-memory across nodes (existing `list_hostings`), so
pagination is a keyset slice on id after filtering — stable and cheap at panel
scale.

### Error catalog
`{"error":{"code","message"}}` + HTTP status:

| code | status | when |
|---|---|---|
| `unauthorized` | 401 | missing / invalid / expired / revoked key |
| `forbidden` | 403 | valid key lacking the capability (or outside IP allowlist) |
| `validation` | 400 | malformed body / bad param |
| `not_found` | 404 | unknown hosting / job / node |
| `conflict` | 409 | e.g. create for a domain that already exists |
| `rate_limited` | 429 | per-key rate limit exceeded (+ `Retry-After`) |
| `upstream_error` | 502 | agent RPC failure |

### Async operations
Slow mutations (delete, backup, restore, cert issue, WP install) return
`202 { "job_id", "status": "accepted" }` with `Location: /api/v1/jobs/<id>`.
`GET /api/v1/jobs/:id` returns a stable shape:
```json
{ "id","kind","state":"running|succeeded|failed","progress":0-100,"message","error":null }
```
Fast mutations (suspend, resume, config PATCHes) are synchronous and return the
affected resource / new state directly.

### Idempotency
Lean on natural guarantees rather than an idempotency-key store (YAGNI):
- **create** is guarded by `UNIQUE(domain)` → a repeat returns `409 conflict`;
  a script treats that as "already exists".
- **suspend/resume** are no-ops when already in the target state → 200.
Documented per endpoint in the OpenAPI descriptions.

### Discovery
- `GET /api/v1/openapi.json` — the generated OpenAPI 3 document (no auth; it's
  a public contract, leaks nothing).
- `GET /api/v1/docs` — a self-hosted rendered view of that spec.

## Auth hardening (per key)

Two optional constraints stored on `api_keys`, set at mint time in Settings and
enforced on every `/api/v1` request:

- **IP allowlist** — a list of CIDRs; empty = allow all. A request whose peer IP
  is outside the list → `403 forbidden`. Enforced in the `ApiAuth` extractor
  (peer IP already available for the rate-limit bucket).
- **Rate limit** — requests/min per key; 0 = unlimited. Exceeding → `429` with
  `Retry-After`. Reuses the existing `ratelimit::RateLimiter` keyed by key id.

Schema: `ALTER TABLE api_keys ADD COLUMN ip_allowlist TEXT` (JSON array, default
`[]`) `+ rate_limit_per_min INTEGER NOT NULL DEFAULT 0`. Both surfaced +
editable in the Settings → API keys card.

## OpenAPI generation

Generate from the code with **`utoipa`** (derive-based → the spec can't drift
from the handlers). Response/request bodies get `#[derive(ToSchema)]`; each
handler an `#[utoipa::path(...)]`. Types that live in `hyperion-types` are
either annotated behind a feature flag or mirrored by thin API DTOs in
`hyperion-web` (decided per-type in the plan; prefer annotating in place to
avoid parallel structs). Served at `/api/v1/openapi.json`; `/api/v1/docs`
serves a vendored single-file viewer (no CDN dependency on the box).

A drift test asserts every registered `/api/v1` route appears in the generated
document (and vice-versa), so a new endpoint without a spec entry fails CI.

## Endpoint surface (full target)

Read (shipped): `GET /me`, `GET /hostings` (gains pagination/filter),
`GET /hostings/:id`, `GET /nodes`, `GET /jobs/:id`.

### Provisioning (Slice B)
- `POST /api/v1/hostings` — create. Body: `{domain, php_version?, stack?
  (php|static|node), database? (bool|opts), node? (placement), limits?}`. The
  base provision is synchronous (mirrors the UI's `HostingCreate` dispatch) →
  `201 { hosting }`; `409` if the domain exists. Cap `HostingCreate`.
- `PATCH /api/v1/hostings/:id/limits` — disk/traffic/process limits. Cap manage.
- `PATCH /api/v1/hostings/:id/php` — php version + php.ini overrides. Cap manage.
- `PATCH /api/v1/hostings/:id/vhost` — force-https, basic-auth, maintenance,
  redirect, fastcgi cache. Cap manage.

### Ops on existing (Slice C)
- `POST /api/v1/hostings/:id/backup` → 202 job; `GET …/backups` (list);
  `POST …/restore {backup_id}` → 202 job.
- `POST /api/v1/hostings/:id/cert {kind: staging|production|wildcard}` → 202 job;
  `POST /api/v1/certs/renew-all` → 202 job.
- `POST /api/v1/hostings/:id/wp/install {…}` → 202 job.
- `PATCH /api/v1/hostings/:id/expiry`, `PATCH …/quota`, `PUT …/notes`.

All reuse the RPCs the UI handlers already call; per-hosting manage access via
the shared `resolve_manage` gate; audited as actor `apikey:<label>`.

### CLI — `hctl remote` (Slice D)
`hctl` gains a `remote` subcommand group that talks to the **HTTP** API (not the
local RPC socket) with a stored key:
- Config `~/.config/hyperion/remote.toml`: `{ url, key }` (or `--url/--key/env`).
- `hctl remote hostings list|get|create|suspend|resume|delete`,
  `hctl remote hosting backup|restore|cert|wp-install`, `hctl remote jobs get`,
  `hctl remote nodes list`, `hctl remote openapi`.
- A hand-written thin `reqwest` client mapping subcommands → HTTP calls, sharing
  the request/response types with the server crate where practical. Long ops
  print the job id and offer `--wait` to poll to completion.

## Slice sequencing (one PR each, versioned + tagged)

- **A — contract & hardening:** list pagination/filter + error catalog +
  `openapi.json`/`docs` + IP allowlist + rate limit. Makes *today's* surface
  fully documented and safe to automate.
- **B — provisioning:** create + config PATCHes.
- **C — ops:** backup/restore/cert/wp/expiry/quota.
- **D — CLI:** `hctl remote`.

## Testing

- **Per slice:** e2e via the existing `web_e2e` harness (real RPC server + mock
  adapters). Seed an `api_keys` row + owner `web_user` to obtain a valid key,
  then exercise happy path + authz (401/403/404/409) + hardening (429,
  allowlist 403).
- **OpenAPI:** the document parses as valid OpenAPI 3 and covers every
  registered `/api/v1` route (drift guard).
- **CLI:** unit tests on arg→request mapping; a smoke test against a local app.

## Out of scope (tracked, not this design)

- Per-tenant scoped keys + `/api/v1/hostings` tenant read-scoping (needs the
  mint gate lifted first).
- Webhooks / push notifications for job completion (polling suffices).
- Monitoring/metrics export endpoints and billing/tenant-lifecycle endpoints.
