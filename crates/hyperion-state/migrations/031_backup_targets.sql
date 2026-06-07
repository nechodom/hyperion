-- 031_backup_targets.sql
--
-- Off-site backup destinations. The earlier backup_runs table
-- already had a `target` column with default 'local'; this
-- promotes that to a real foreign key for non-local targets and
-- adds an `s3` target type with everything needed to push an
-- encrypted tarball to a generic S3-compatible endpoint (Wasabi,
-- Backblaze B2, Minio, AWS S3 itself).
--
-- We deliberately do NOT include secret_access_key as plaintext;
-- the agent stores it under /etc/hyperion/secrets/backup-<id>.key
-- with 0600 ownership (root:root) and the row carries only the
-- on-disk path. The path is computed deterministically from the
-- target id so a migration import can rotate keys without changing
-- the table.
--
-- The `age_recipient` column holds the public key the agent
-- encrypts to before uploading — operator keeps the matching
-- private key OFF the node (in a password manager / offline
-- vault). Without that key, the blobs on the cold store can't be
-- decrypted even if the credentials leak.
CREATE TABLE backup_targets (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    kind              TEXT NOT NULL DEFAULT 's3' CHECK (
        kind IN ('s3', 'local-dir')
    ),
    endpoint          TEXT NOT NULL,                  -- https://s3.wasabisys.com
    bucket            TEXT NOT NULL,                  -- hyperion-backups-prod
    region            TEXT NOT NULL DEFAULT 'us-east-1',
    access_key_id     TEXT NOT NULL,
    -- Plaintext NEVER lands here; the SecretId points at a row in
    -- the existing `secrets` table (BLAKE3-keyed off-machine if
    -- the operator chose to use a remote KMS later).
    secret_key_id     TEXT,
    -- age public key (recipient). Operator pastes this once at
    -- setup; the matching identity stays OFF the node.
    age_recipient     TEXT,
    -- Retention policy.
    retention_daily   INTEGER NOT NULL DEFAULT 7,
    retention_weekly  INTEGER NOT NULL DEFAULT 4,
    retention_monthly INTEGER NOT NULL DEFAULT 12,
    -- When enabled = 0 the scheduler skips this target. Useful for
    -- temporarily pausing a destination during incident response.
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE INDEX backup_targets_enabled ON backup_targets(enabled);

-- Extend backup_runs with remote-target metadata. Existing rows
-- with target='local' keep working — the new columns default to
-- NULL / 0 and the local-backup path doesn't fill them in.
ALTER TABLE backup_runs ADD COLUMN target_id INTEGER REFERENCES backup_targets(id) ON DELETE SET NULL;
ALTER TABLE backup_runs ADD COLUMN remote_blob_key TEXT;
ALTER TABLE backup_runs ADD COLUMN encrypted_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE backup_runs ADD COLUMN sha256_hex TEXT;
-- "daily" | "weekly" | "monthly" — drives retention pruning. The
-- scheduler tags each run when it kicks off; ad-hoc runs from the
-- "Backup now" button are tagged "ad-hoc" and exempt from
-- automatic deletion.
ALTER TABLE backup_runs ADD COLUMN cadence TEXT NOT NULL DEFAULT 'ad-hoc';
CREATE INDEX backup_runs_target ON backup_runs(target_id, started_at DESC);
CREATE INDEX backup_runs_cadence ON backup_runs(cadence, started_at DESC);
