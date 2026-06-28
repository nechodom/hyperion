-- Self-service import wizard: one-time, scoped, expiring tokens that authorize a
-- source box to fetch the bootstrap script and push an export bundle back to a
-- target node. Only the token HASH is stored (the plaintext is shown once in the
-- wizard). See docs/superpowers/specs/2026-06-28-self-service-import-wizard-design.md
CREATE TABLE IF NOT EXISTS import_tokens (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash     TEXT    NOT NULL UNIQUE,     -- blake3 hex of the plaintext
    target_node    TEXT    NOT NULL,            -- node id ("local" or a worker)
    source_kind    TEXT    NOT NULL,            -- cloudpanel | hestiacp
    created_by     TEXT    NOT NULL,            -- minting username (audit)
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,            -- unix secs; hard cutoff
    used_at        INTEGER,                     -- NULL = unused; set atomically on first ingest
    status         TEXT    NOT NULL DEFAULT 'pending', -- pending|receiving|importing|done|failed|cancelled
    received_bytes INTEGER NOT NULL DEFAULT 0,
    job_id         TEXT                         -- the spawned import job, once known
);
CREATE INDEX IF NOT EXISTS idx_import_tokens_hash ON import_tokens(token_hash);
