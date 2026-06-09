-- 033_audit_chain_anchor.sql
--
-- Enables audit-log retention without breaking `verify_chain`.
--
-- The audit log is a tamper-evident hash chain where each row's
-- `row_hash = BLAKE3(prev_hash || canonical_fields)`. If we just
-- DELETE FROM audit_log WHERE ts < cutoff, the oldest surviving
-- row's `prev_hash` points at a row that no longer exists, and
-- verify_chain fails because GENESIS_HASH no longer matches.
--
-- The anchor table records the hash that the oldest surviving
-- row's prev_hash points to — that becomes the new starting
-- "expected_prev" for verify_chain. We only ever have ONE anchor
-- (single-row pattern via CHECK), updated each time the
-- scheduler's retention sweep purges rows.
--
-- last_purged_id / last_purge_ts are kept for forensics so the
-- operator can answer "did anyone tamper with retention?" by
-- comparing the anchor's update timestamp to the audit log
-- entries that record the retention setting changing.

CREATE TABLE IF NOT EXISTS audit_chain_anchor (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    anchor_hash     TEXT NOT NULL,
    last_purged_id  INTEGER NOT NULL,
    last_purge_ts   INTEGER NOT NULL
);
