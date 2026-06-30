# Remote management API — design

Status: proposed (2026-06-30). Driver: issue #1 follow-up (@LaAlexita): "it didn't
have an API to manage it remotely."

## Goal

A stable, authenticated **HTTP/JSON API** so Hyperion can be driven
programmatically (scripts, CI, third-party tools) without the browser UI —
without opening a second authorization model or re-implementing business logic.

## Current state (the gap)

- A rich typed API already exists *internally*: `hyperion-rpc` (~195 methods —
  `hosting_create/list/get/delete`, suspend/resume, quotas, backups, certs, …).
- It is reachable only via the **local unix socket** (`hctl`, the web tier) and
  **master↔worker mTLS RPC (9443)**.
- The web `/api/*` routes are **session-cookie** authenticated (browser AJAX).
- There is **no API-key/bearer auth and no public programmatic surface.**

So the building blocks (typed methods, dispatch-to-node, background jobs, RBAC,
audit) are all present; what's missing is an *authenticated external edge* over
them.

## Design

### Auth: API keys carrying a capability set

Reuse the **RBAC `CapSet`** (custom-roles work) — an API key *is* a scoped
capability bundle, so the **same gates hardened in the 2026-06-30 security
audit apply unchanged** (incl. tenant-scoping / `scope_all`). One policy path.

**`api_keys` table (migration 053, master-only — like `web_sessions`/`web_users`):**

| col | type | notes |
|---|---|---|
| `id` | INTEGER PK | |
| `key_hash` | TEXT | SHA-256 of the raw key (never store raw) |
| `key_prefix` | TEXT | first ~8 chars (`hyp_a1b2…`) for display only |
| `label` | TEXT | operator-supplied |
| `owner_user_id` | INTEGER | the web user that owns/created it |
| `caps` | INTEGER | CapSet u64 (≤ the owner's caps) |
| `scope_all` | INTEGER | 0/1 — tenant scope (never exceeds owner) |
| `created_at` | INTEGER | |
| `last_used_at` | INTEGER NULL | touched on use (best-effort) |
| `expires_at` | INTEGER NULL | optional hard expiry |
| `revoked_at` / `revoked_by` | INTEGER NULL | |

- Key format `hyp_<32 bytes base62>` (CSPRNG). Returned **once** on creation,
  stored hashed. A key can never grant more than its owner holds (clamp `caps &=
  owner_caps`, `scope_all &= owner_scope_all`) — so revoking/altering the owner
  bounds the key.
- State module `api_keys.rs`: `create` (returns raw once) · `resolve_active`
  (by hash; rejects revoked/expired) · `list` (own / all for admin) · `touch` ·
  `revoke`. RPC ops `ApiKey{Create,List,Revoke,Resolve}` mirror `web_session_*`
  (master-only table → goes over RPC, not a worker-local read).

### Edge: `/api/v1` with a Bearer extractor

- New router branch `/api/v1/*` with a **Bearer auth layer** (NOT the
  session `require_auth`, NOT `check_csrf` — API keys are not cookies, so no CSRF
  and no ambient-authority risk). HTTPS only.
- `Authorization: Bearer hyp_…` → SHA-256 → `ApiKeyResolve` → build the **same
  `AuthCtx`** the UI uses, with `caps`/`scope_all`/`username` from the key
  (`session: None`, new `api_key: Some(ApiKeyCtx{…})`; `AuthCtx::caps()` reads it
  exactly like a session's stamped caps). Every existing `ctx.can(cap)` /
  `require_hosting_access(cap)` gate then works verbatim.
- Errors: JSON envelope `{ "error": { "code", "message" } }` + correct status
  (401 missing/invalid/expired key · 403 capability denied · 404 · 409 conflict ·
  422 validation · 429 rate-limited). Addresses are redacted as in the web tier.

### Endpoints (Phase 1)

| Method + path | RPC reused | Cap |
|---|---|---|
| `GET /api/v1/me` | (key identity) | any valid key |
| `GET /api/v1/hostings` | `hosting_list` | HostingView |
| `GET /api/v1/hostings/{id}` | `hosting_get` | HostingView |
| `POST /api/v1/hostings` | `hosting_create` | HostingCreate |
| `DELETE /api/v1/hostings/{id}` | `hosting_delete` | HostingDelete |
| `POST /api/v1/hostings/{id}/suspend` · `/resume` | suspend/resume | HostingSuspend |
| `GET /api/v1/nodes` | `node list` | NodesView |
| `GET /api/v1/jobs/{id}` | job view | (owner/any valid key) |

- **Long operations already run as background jobs** → create/delete return
  `202 { job_id }`; clients poll `GET /api/v1/jobs/{id}`. No new async model.
- JSON shapes are the existing serde types (`HostingSummary`, `HostingDetail`,
  `JobView`) serialized directly — no parallel DTOs.

### Settings UI

An "API keys" card in Settings: create (label + capability-scope picker reusing
the roles capability *groups*, + optional expiry) → reveal the raw key **once**;
list (prefix · label · caps summary · last used · expires) + revoke. Gated by a
new `ApiKeysManage` capability (admins; a user may manage only ≤ their own caps).

### Cross-cutting

- **Audit:** every mutating call appends to the existing audit chain with
  `actor = "apikey:<label>"`.
- **Rate-limit:** reuse `ratelimit` per-key (sensible default, configurable).
- **Observability:** never log the raw key or the hash; log the prefix + method.
- **`hctl`:** later gains `--remote <url> --api-key …` and becomes a remote
  client (the local unix-socket path stays the default).
- **OpenAPI:** serve `/api/v1/openapi.json` + a short docs page; examples in README.

## Phasing

- **P1 (this work):** `api_keys` + Settings UI + Bearer auth + the table above +
  job polling + tests.
- **P2:** broaden coverage (backups, certs, quotas, profiles, import), per-key IP
  allowlist, webhooks, generated OpenAPI, `hctl --remote`.

## Testing

- Unit: key hash/format, `resolve_active` (revoked/expired rejected), caps clamp
  to owner.
- e2e: valid key → 200; missing key → 401; under-capability → 403; tenant scope
  enforced; create → 202 + job; revoke → subsequent 401.
- Migration test (053 applies on `--workspace`, force-rebuild hyperion-state).

## Open questions for the maintainer

1. Per-key **IP allowlist** in P1, or P2?
2. Keys scoped to **specific hostings** (an explicit allow-list) in addition to
   capability scope — needed for P1, or is CapSet + tenant-scope enough?
3. Default per-key **rate limit** (req/min)?
4. Should a non-admin user be allowed to mint keys (≤ own caps), or admins only
   in P1?
