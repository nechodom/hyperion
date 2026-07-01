-- 053_api_keys.sql
--
-- Bearer API keys for the remote management API (`/api/v1`). An API
-- key IS a scoped capability bundle: it carries a `CapSet` bitmask
-- (clamped at creation to ≤ the owning web user's effective caps)
-- plus a tenant `scope_all` flag, so the SAME RBAC gates the browser
-- UI uses apply unchanged. One policy path — no second auth model.
--
-- Master-only, like `web_sessions` / `web_users`: the table lives on
-- the panel master and is reached over the local socket / RPC, never
-- a worker-local read. Workers have no api_keys row.
--
-- Only the SHA-256 of the raw key is stored. The plaintext
-- (`hyp_<32 bytes base62>`) is shown exactly once at creation and is
-- otherwise unrecoverable. `key_prefix` is the first few characters
-- of the raw key, kept for display only (so the operator can tell
-- which key a row is without revealing it).
--
-- See docs/superpowers/specs/2026-06-30-remote-management-api-design.md.
CREATE TABLE api_keys (
    id            INTEGER PRIMARY KEY,
    -- SHA-256 (hex) of the raw key. The bearer extractor hashes the
    -- presented token and looks it up here; the raw key is never
    -- persisted.
    key_hash      TEXT NOT NULL UNIQUE,
    -- Display-only prefix ("hyp_a1b2c3…"). Safe to show; not enough
    -- entropy to be a credential on its own.
    key_prefix    TEXT NOT NULL,
    -- Operator-supplied human label.
    label         TEXT NOT NULL,
    -- The web user that owns/created the key. Revoking or down-scoping
    -- the owner bounds the key (caps are re-clamped only at creation,
    -- but the owner relationship is recorded for audit + future
    -- re-evaluation).
    owner_user_id INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    -- CapSet u64 bitmask. Clamped to `caps & owner_caps` at creation.
    caps          INTEGER NOT NULL,
    -- 0/1 tenant scope. Clamped to `scope_all & owner_scope_all`.
    scope_all     INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    -- Touched (best-effort) on each successful use, for the Settings list.
    last_used_at  INTEGER,
    -- Optional hard expiry. NULL ⇒ never expires.
    expires_at    INTEGER,
    -- NULL ⇒ live. Non-NULL ⇒ revoked by an operator.
    revoked_at    INTEGER,
    revoked_by    INTEGER REFERENCES web_users(id)
);
-- The hot path: hash → row lookup on every Bearer-authenticated request.
CREATE UNIQUE INDEX api_keys_hash ON api_keys(key_hash);
-- Listing the owner's (or all) keys newest-first for the Settings card.
CREATE INDEX api_keys_owner ON api_keys(owner_user_id, created_at DESC);
