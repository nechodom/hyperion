-- What we know about a backup's OFF-SITE copy.
--
-- Migration 031 added `target_id`, `remote_blob_key`, `encrypted_bytes` and
-- `sha256_hex` and nothing ever wrote any of them. The panel therefore could
-- not answer the two questions an operator actually asks — "is this backup
-- anywhere but on this box?" and "is it intact?" — and a backfill had nothing
-- to diff against, because `target` is the literal string 'local' at every
-- insert.
--
-- These two finish the set. `remote_state` deliberately distinguishes 'ok'
-- from 'verified': one means the upload returned success, the other means the
-- bytes were listed back and their size matched. Treating those as the same
-- word is how "the backup is off-site" becomes a claim nobody checked.
--
-- Both NULL-able with no default, so an existing row reads as EMPTY — which
-- means "we never recorded this", not "there is no copy". A backfill must be
-- able to tell a run from before this migration apart from one that failed to
-- upload, because the first needs looking at and the second needs retrying.
ALTER TABLE backup_runs ADD COLUMN remote_state TEXT;
ALTER TABLE backup_runs ADD COLUMN remote_error TEXT;
