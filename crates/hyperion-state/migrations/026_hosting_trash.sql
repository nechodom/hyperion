-- Soft-delete / trash for hostings.
--
-- When `cluster.trash_enabled = true` in agent.toml, deleting a
-- hosting suspends it (FPM stop, DB lock, nginx → 503, OS user
-- locked) but DOES NOT remove files / DB / user. The row gets
-- `trashed_at` set to now() and the state column flips to
-- "trashed" (a new variant that the UI filters out of the main
-- list).
--
-- The scheduler tick checks for trashed rows older than
-- `cluster.trash_retention_days` (default 30) and runs the
-- existing hard-delete pipeline on them. Operator can also hit
-- "Delete permanently" on the /trash page to GC immediately,
-- or "Restore" to roll the suspend back into active.
--
-- When `trash_enabled = false` (the default), nothing changes —
-- delete behaves exactly as before.

ALTER TABLE hostings ADD COLUMN trashed_at INTEGER;
CREATE INDEX IF NOT EXISTS idx_hostings_trashed_at ON hostings(trashed_at)
    WHERE trashed_at IS NOT NULL;
