-- 004_backups.sql
-- Local backup runs metadata. Real off-site targets / restic integration
-- live on top of this in sub-project 5 (full spec); v1 ships a single
-- local target writing tar.gz archives.

CREATE TABLE backup_runs (
    id              INTEGER PRIMARY KEY,
    hosting_id      TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    target          TEXT NOT NULL DEFAULT 'local',
    started_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    state           TEXT NOT NULL CHECK (state IN ('running','ok','failed')),
    archive_path    TEXT,
    db_dump_path    TEXT,
    bytes_total     INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT
);
CREATE INDEX backup_runs_hosting_state ON backup_runs(hosting_id, state);
CREATE INDEX backup_runs_started ON backup_runs(started_at DESC);
