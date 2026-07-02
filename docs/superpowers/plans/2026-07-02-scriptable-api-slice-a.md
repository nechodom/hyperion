# Scriptable API — Slice A (contract & hardening) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make today's `/api/v1` surface fully documented and safe to automate — paginated/filterable list, a complete error catalog, per-key IP allowlist + rate limit, and a generated OpenAPI 3 contract served from the box.

**Architecture:** Two PRs. **A1** adds list pagination/filter, the error catalog, and per-key hardening (columns on `api_keys`, enforced in the `ApiAuth` extractor, edited in Settings). **A2** adds OpenAPI generation via `utoipa` (schemas feature-gated in `hyperion-types`, `#[utoipa::path]` on the handlers), served at `/api/v1/openapi.json` + `/api/v1/docs`, guarded by a route-drift test. All authz/RPC reuse is unchanged.

**Tech Stack:** Rust, axum, sqlx (SQLite), utoipa (A2), the existing `web_e2e` test harness.

**Reference types (already exist):**
- `hyperion_types::HostingSummary { id: HostingId, domain: String, state: HostingState, php_version: Option<PhpVersion>, created_at: i64, node_id: Option<String>, maintenance_mode: bool }` — the list item.
- `ratelimit::RateLimiter::check(endpoint: &'static str, ip: IpAddr, bucket: Bucket) -> bool`; `Bucket::per_minute(capacity: u32)`.
- `api_keys` table (migration 053); resolver `api_keys::resolve_active` → `ResolvedKey`; core `api_key_resolve` folds owner standing via `clamp_to_owner`.
- Error helpers in `handlers/api_v1.rs`: `err/unauthorized/forbidden/not_found/upstream`.

---

## PR A1 — conventions & hardening

### File structure
- `crates/hyperion-state/migrations/054_api_key_hardening.sql` — new columns.
- `crates/hyperion-state/src/api_keys.rs` — carry `ip_allowlist` + `rate_limit_per_min` through `ResolvedKey`, `create`, `list`, and a new `set_hardening`.
- `crates/hyperion-types/src/*` — add the two fields to `ApiKeyResolved` + the created/list wire types.
- `crates/hyperion-core/src/service.rs` — thread the fields through `api_key_resolve` / `api_key_create`.
- `bin/hyperion-web/src/auth.rs` — `ApiKeyCtx` carries the two fields.
- `bin/hyperion-web/src/handlers/api_v1.rs` — enforce allowlist + rate limit; paginate/filter `get_hostings`; add `conflict`/`rate_limited` error helpers.
- `bin/hyperion-web/src/handlers/settings.rs` + `templates/settings.html` — mint form gains allowlist + rate-limit inputs; list shows them.
- `bin/hyperion-web/tests/web_e2e.rs` — e2e coverage.

### Task 1: migration + state layer for the two hardening columns

**Files:**
- Create: `crates/hyperion-state/migrations/054_api_key_hardening.sql`
- Modify: `crates/hyperion-state/src/api_keys.rs`
- Test: same file (`#[cfg(test)] mod tests`)

- [ ] **Step 1 — migration.** Write `054_api_key_hardening.sql`:
```sql
-- Per-key hardening for the /api/v1 remote API. Both optional:
--   ip_allowlist      — JSON array of CIDR strings; [] = allow any peer IP.
--   rate_limit_per_min — requests/min; 0 = unlimited.
ALTER TABLE api_keys ADD COLUMN ip_allowlist TEXT NOT NULL DEFAULT '[]';
ALTER TABLE api_keys ADD COLUMN rate_limit_per_min INTEGER NOT NULL DEFAULT 0;
```

- [ ] **Step 2 — failing test.** Add to `api_keys.rs` tests: create a key with `ip_allowlist=["10.0.0.0/8"]`, `rate_limit_per_min=60`, then `resolve_active` returns them; `set_hardening` updates them; `list` surfaces them. Run `cargo test -p hyperion-state api_keys` → FAIL (fields/methods absent).

- [ ] **Step 3 — implement.** In `api_keys.rs`:
  - Add `pub ip_allowlist: Vec<String>` + `pub rate_limit_per_min: i64` to `ResolvedKey` and `ApiKeyRow`.
  - `resolve_active`: add `ip_allowlist, rate_limit_per_min` to the SELECT; parse the JSON text with `serde_json::from_str::<Vec<String>>(...).unwrap_or_default()`.
  - `create`: accept the two params, bind them (serialize the Vec with `serde_json::to_string`).
  - New `pub async fn set_hardening(pool, id, ip_allowlist: &[String], rate_limit_per_min: i64, now) -> Result<bool>` — `UPDATE api_keys SET ip_allowlist=?, rate_limit_per_min=?, updated... WHERE id=?` (no updated_at column on api_keys — omit).
  - `list`: add the two columns to its SELECT + row mapping.
- [ ] **Step 4 — run tests** `cargo test -p hyperion-state api_keys` → PASS.
- [ ] **Step 5 — commit** `feat(api): api_keys carry per-key ip_allowlist + rate_limit`.

### Task 2: thread fields to the web AuthCtx + enforce in ApiAuth

**Files:**
- Modify: `crates/hyperion-types` (`ApiKeyResolved` gains the two fields), `crates/hyperion-core/src/service.rs` (`api_key_resolve`/`api_key_create` pass them through), `bin/hyperion-web/src/auth.rs` (`ApiKeyCtx` fields + build), `bin/hyperion-web/src/handlers/api_v1.rs` (enforce).

- [ ] **Step 1 — types + core.** Add `ip_allowlist: Vec<String>` + `rate_limit_per_min: i64` to `hyperion_types::ApiKeyResolved`. `api_key_resolve` copies them from the `ResolvedKey`; `clamp_to_owner` is unchanged (hardening is not owner-clamped). `api_key_create` forwards new params from the RPC.
- [ ] **Step 2 — auth.rs.** `ApiKeyCtx` gains the two fields; the Bearer branch copies them from the resolved key.
- [ ] **Step 3 — enforce (failing e2e first, see Task 6).** In `api_v1.rs`, extend `ApiAuth::from_request_parts`:
  - After building the api-key ctx, read the peer IP from `parts.extensions.get::<ConnectInfo<SocketAddr>>()` (the router already injects it). If `ip_allowlist` is non-empty and the peer IP matches no CIDR → return `forbidden`-style 403 (`err(FORBIDDEN, "forbidden", "source IP not allowed")`). Parse CIDRs with the `ipnet` crate (add dep) — `cidr.parse::<ipnet::IpNet>()?.contains(&ip)`.
  - If `rate_limit_per_min > 0`, call a process-global `RateLimiter` keyed by the key id: `limiter.check("api_v1", peer_ip, Bucket::per_minute(rate_limit_per_min))` — but the existing limiter buckets by (endpoint, ip); extend with a key-scoped bucket, or add `check_key(key_id, bucket)`. Simplest: add `RateLimiter::check_key(&self, key_id: i64, bucket: Bucket) -> bool` using an `i64` map. On false → `err(429, "rate_limited", "rate limit exceeded")` with a `Retry-After: 60` header.
- [ ] **Step 4 — commit** `feat(api): enforce per-key IP allowlist + rate limit on /api/v1`.

### Task 3: pagination + filtering for GET /hostings

**Files:** Modify `bin/hyperion-web/src/handlers/api_v1.rs`.

- [ ] **Step 1 — failing e2e** (Task 6) for `?limit=1` returning `{items,next_cursor,total}` and `?state=suspended` filtering.
- [ ] **Step 2 — implement.** Add `#[derive(Deserialize)] struct HostingsQuery { limit: Option<usize>, cursor: Option<String>, state: Option<String>, node: Option<String>, q: Option<String> }`. In `get_hostings`:
  - fetch the full `Vec<HostingSummary>` via `list_hostings`.
  - filter by `state` (`HostingState` string match), `node` (node_id eq), `q` (domain contains, case-insensitive).
  - sort by `id` (stable); decode `cursor` (base64 of last id) → drop everything ≤ cursor; take `limit.clamp(1,200)` (default 50); `next_cursor` = base64(last id) when a full page was returned else null; `total` = filtered count.
  - return `{items, next_cursor, total}`.
- [ ] **Step 3 — commit** `feat(api): paginate + filter GET /api/v1/hostings`.

### Task 4: error catalog helpers

**Files:** Modify `bin/hyperion-web/src/handlers/api_v1.rs`.

- [ ] **Step 1 — add** `fn conflict(msg)` → `err(409,"conflict",msg)` and `fn rate_limited()` → `err(429,"rate_limited",...)` (used by Tasks 2 & Slice B). Keep the existing helpers. No new behavior beyond the constants.
- [ ] **Step 2 — commit** `chore(api): error-code helpers (conflict, rate_limited)`.

### Task 5: Settings UI for the two knobs

**Files:** Modify `bin/hyperion-web/src/handlers/settings.rs`, `templates/settings.html`.

- [ ] **Step 1 — mint form** gains an optional "Allowed IPs (CIDR, comma-separated)" text input + "Rate limit (req/min, 0 = off)" number input. `post_api_key_create` parses them (split/trim the CIDRs, validate each parses as `ipnet::IpNet` → else flash error) and passes them to `Request::ApiKeyCreate`.
- [ ] **Step 2 — list** shows each key's allowlist + rate limit (read from the `ApiKeyRow`).
- [ ] **Step 3 — commit** `feat(api): set IP allowlist + rate limit when minting a key`.

### Task 6: e2e tests (write first per TDD, land last as a group)

**Files:** Modify `bin/hyperion-web/tests/web_e2e.rs`. Seed a key by inserting into the agent's `api_keys` + a `web_user` owner (scope_all, unlocked) directly via the state layer against the harness DB, or via the `ApiKeyCreate` RPC.

- [ ] **Step 1 — helper** `async fn mint_test_key(pool/socket, allowlist, rate) -> String` returning the raw key.
- [ ] **Step 2 — tests:**
  - `api_v1_hostings_paginates_and_filters` — seed 3 hostings, assert `?limit=2` → 2 items + non-null `next_cursor`; follow the cursor → the rest; `?state=suspended` filters.
  - `api_v1_ip_allowlist_blocks_outside_peer` — key with allowlist `["10.0.0.0/8"]`, MockConnectInfo peer `127.0.0.1` → 403 `forbidden`.
  - `api_v1_rate_limit_returns_429` — key with `rate_limit_per_min=1` → 2nd call within the minute → 429 + `Retry-After`.
- [ ] **Step 3 — run** `cargo test -p hyperion-web --test web_e2e api_v1` → PASS.
- [ ] **Step 4 — commit** `test(api): e2e for pagination, IP allowlist, rate limit`.

**PR A1 gate:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` all green on the lima VM; open PR; CI; squash-merge; tag minor.

---

## PR A2 — OpenAPI contract

### File structure
- `crates/hyperion-types/Cargo.toml` + types — optional `utoipa` dep; `#[cfg_attr(feature="openapi", derive(utoipa::ToSchema))]` on the ~10 API response/request types.
- `bin/hyperion-web/Cargo.toml` — `utoipa` (enable the `openapi` feature on hyperion-types) + `utoipa` for `#[utoipa::path]`.
- `bin/hyperion-web/src/handlers/api_v1.rs` — `#[utoipa::path(...)]` on every handler; a `#[derive(OpenApi)] struct ApiDoc` listing paths + schemas; `get_openapi_json` + `get_docs` handlers.
- `bin/hyperion-web/src/lib.rs` — routes `/api/v1/openapi.json`, `/api/v1/docs` (unauthenticated).
- `bin/hyperion-web/tests/web_e2e.rs` — drift test.

### Task 7: schemas on the wire types (feature-gated)

- [ ] **Step 1 — dep.** In `hyperion-types/Cargo.toml`: `utoipa = { version = "5", optional = true }` and `[features] openapi = ["dep:utoipa"]`.
- [ ] **Step 2 — annotate** the types the API returns/accepts: `HostingSummary`, `HostingDetail` (+ its nested `HostingLimits`, `HostingState`, `PhpVersion`, `HostingExpiry`, etc. reachable from it), `NodeSummary`, the job wire type, `ApiKeyResolved` is internal (skip). Each gets `#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]`. For enums with custom serde, add `#[cfg_attr(feature="openapi", schema(...))]` as needed.
- [ ] **Step 3 — build** `cargo build -p hyperion-types --features openapi` → compiles.
- [ ] **Step 4 — commit** `chore(types): feature-gated utoipa ToSchema on API types`.

### Task 8: ApiDoc + serve openapi.json + docs

- [ ] **Step 1 — deps.** `hyperion-web/Cargo.toml`: `utoipa = "5"`, and depend on `hyperion-types` with `features = ["openapi"]`.
- [ ] **Step 2 — annotate handlers.** Add `#[utoipa::path(method, path="/api/v1/...", responses(...), params(...), security(("bearer"=[])))]` above `get_me/get_hostings/get_hosting/get_nodes/get_job/post_suspend/post_resume/delete_hosting`. Document the list envelope + error responses.
- [ ] **Step 3 — ApiDoc.** `#[derive(utoipa::OpenApi)] #[openapi(paths(...), components(schemas(...)), security_schemes / modifiers for the Bearer scheme)] struct ApiDoc;`
- [ ] **Step 4 — handlers.** `get_openapi_json` → `Json(ApiDoc::openapi())`. `get_docs` → `Html(<vendored single-file viewer that fetches /api/v1/openapi.json>)` — vendor a minimal viewer (e.g. a self-contained HTML that renders the JSON; no external CDN).
- [ ] **Step 5 — routes.** In `lib.rs` add `/api/v1/openapi.json` + `/api/v1/docs` to the `api_v1` router **outside** the `ApiAuth` requirement (they take no `ApiAuth`, so they're already public).
- [ ] **Step 6 — commit** `feat(api): serve generated OpenAPI 3 at /api/v1/openapi.json + /docs`.

### Task 9: drift test

**Files:** Modify `bin/hyperion-web/tests/web_e2e.rs`.

- [ ] **Step 1 — test** `openapi_covers_every_api_v1_route`: build `ApiDoc::openapi()`; collect its path keys; collect the registered `/api/v1` routes from a static list mirrored in the test (or introspect the router if feasible); assert the OpenAPI paths ⊇ the mutating/read endpoints (excluding `openapi.json`/`docs`). Also assert the doc `serde_json`-serializes and `openapi` version starts with `3.`.
- [ ] **Step 2 — run** `cargo test -p hyperion-web --test web_e2e openapi` → PASS.
- [ ] **Step 3 — commit** `test(api): OpenAPI drift guard covers every /api/v1 route`.

**PR A2 gate:** fmt + clippy `-D warnings` + `cargo test --workspace` green on the VM; PR; CI; squash-merge; tag minor.

---

## Self-review (against the spec)

- **List pagination/filter** → Task 3 + e2e Task 6. ✓
- **Error catalog** → Task 4 (helpers) + documented in A2 handler annotations. ✓
- **OpenAPI served + drift test** → Tasks 7-9. ✓
- **IP allowlist + rate limit, stored + Settings-editable** → Tasks 1,2,5 + e2e Task 6. ✓
- **e2e via web_e2e harness** → Task 6, Task 9. ✓
- **Types consistent:** `ip_allowlist: Vec<String>` + `rate_limit_per_min: i64` used identically across api_keys.rs, ApiKeyResolved, ApiKeyCtx, settings. ✓
- New dep `ipnet` (CIDR match) introduced in Task 2 and used in Task 5 — consistent.
