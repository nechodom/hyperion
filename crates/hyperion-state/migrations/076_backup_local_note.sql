-- Why the LOCAL copy of a backup is still on disk when the operator asked for
-- local copies to be dropped once they are verified off-site.
--
-- The drop step re-checks every file off-site before it deletes anything, and
-- keeps the local copy when it cannot confirm one. Until now that refusal was
-- written only to the admin audit log, so the Backups card showed
-- "off-site ✓" next to a local path with nothing to say why the copy stayed —
-- which reads as a broken delete. This column carries the reason to the row
-- itself. NULL/empty = nothing to report (the reasons that follow from the
-- settings, e.g. "the drop option is off", are derived when the list is read,
-- not stored, so they can never go stale).
ALTER TABLE backup_runs ADD COLUMN local_note TEXT;

-- The S3 targets this run's push reached IN FULL (every file uploaded; for an
-- age-encrypted target, age exited 0, so the whole ciphertext streamed), as a
-- JSON array of target names. NULL = none on record.
--
-- An S3 push never wrote `remote_state` (that column is the FTP target's), so
-- nothing on the row said an S3-only backup was off-site at all: the drop-local
-- step could act on such a run only in the minute its own push finished, and a
-- site set to keep its newest local copies never had an older one dropped. An
-- age-encrypted object can only be checked for EXISTENCE later, and existence
-- alone cannot tell a whole ciphertext from a truncated one — this record of a
-- complete push is what makes that check meaningful. A failed re-push to a
-- target removes it from the list.
ALTER TABLE backup_runs ADD COLUMN s3_ok_targets TEXT;
