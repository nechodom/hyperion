-- Generic per-hosting key/value store.
--
-- For per-hosting feature config that doesn't warrant its own column on
-- the (already large, split-query) hostings table: operator notes +
-- tags, PHP extension/ini overrides, WAF flags, wp-admin IP allowlist,
-- etc. One row per (hosting, key); value is an opaque string (plain
-- text, CSV, or JSON — the feature owns the encoding).
--
-- Rows are removed with the hosting by app-level cleanup (same as the
-- other per-hosting side tables); SQLite has no cascade here since
-- hostings has no FK target enforced.
CREATE TABLE IF NOT EXISTS hosting_kv (
    hosting_id  TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (hosting_id, key)
);
