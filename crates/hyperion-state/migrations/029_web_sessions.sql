-- 029_web_sessions.sql
--
-- Per-session row backing each signed-cookie token. The cookie
-- already carries `sid` (a ULID minted at login); previously the
-- agent didn't track it at all — every successfully verified
-- token was accepted until `expires_at`. That meant a stolen
-- cookie was good for the full session TTL with no way to kill
-- it from the panel.
--
-- This table closes the gap:
--   * login inserts a row keyed by `sid`
--   * each authenticated request looks up the row; missing or
--     non-null `revoked_at` ⇒ session is killed, treat as anon
--   * /settings/sessions lists rows for the current user with
--     a "Revoke" button per row
--   * Logout flips `revoked_at` for the current sid
--
-- Trade-off: one indexed SELECT per request. SQLite serves an
-- indexed PK lookup in <100 µs on the panel master, so total
-- per-request overhead is negligible vs the existing RPC calls.
CREATE TABLE web_sessions (
    sid          TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    -- Free-text label captured at login. NULL if the request was
    -- missing X-Forwarded-For / X-Real-IP (panel running on
    -- localhost during dev).
    ip           TEXT,
    user_agent   TEXT,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    -- NULL ⇒ session is live. Non-NULL ⇒ killed by /logout, by
    -- the user explicitly revoking it on /settings/sessions, or
    -- by an admin nuke from /admin/users.
    revoked_at   INTEGER,
    revoked_by   INTEGER REFERENCES web_users(id)
);
-- Listing by user (the /settings/sessions page wants user_id's
-- rows newest-first).
CREATE INDEX web_sessions_user ON web_sessions(user_id, created_at DESC);
-- Cheap "is this sid live?" check on every authenticated request.
CREATE INDEX web_sessions_revoked ON web_sessions(sid, revoked_at);
