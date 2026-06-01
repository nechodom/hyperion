-- 007_node_invites.sql
-- One-time invite tokens used by `install-node.sh` to enroll an agent
-- against this master. Tokens are stored hashed (BLAKE3) so the
-- plaintext is never persisted.

CREATE TABLE node_invites (
    token_hash      TEXT PRIMARY KEY,           -- BLAKE3 hex (64 chars)
    label           TEXT NOT NULL,              -- human label; e.g. 'node5.example.com'
    expires_at      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    consumed_at     INTEGER,                    -- nullable; non-null = used
    consumed_by_ip  TEXT,                       -- caller IP at /enroll time
    consumed_by_id  TEXT                        -- ULID once enrolled
);
CREATE INDEX node_invites_label ON node_invites(label);
CREATE INDEX node_invites_expires ON node_invites(expires_at) WHERE consumed_at IS NULL;
