-- Per-node IP ban list (feature #4 — native fail2ban). The agent's
-- brute-force scanner inserts auto-bans here and mirrors them into the
-- `inet hyperion` nftables `banned` set; operators can also add manual
-- bans from the UI. Rows survive reboots so bans can be re-applied to
-- nftables (whose sets are in-memory) on agent start.

CREATE TABLE IF NOT EXISTS ip_bans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL,
    -- Which hosting's traffic triggered the ban (NULL for node-wide
    -- manual bans). Bans are enforced node-wide regardless.
    hosting_id TEXT,
    reason     TEXT    NOT NULL,
    -- 'auto' (brute-force scanner) | 'manual' (operator).
    source     TEXT    NOT NULL,
    banned_at  INTEGER NOT NULL,
    -- Unix seconds when the ban lapses. 0 = permanent (manual only).
    expires_at INTEGER NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ip_bans_active ON ip_bans(active, expires_at);
-- At most one active ban per IP — re-banning an already-banned IP just
-- refreshes the existing row instead of stacking duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_bans_ip_active
    ON ip_bans(ip) WHERE active = 1;
