-- Interactive import wizard: the source script reports the discovered sites
-- (manifest_json) and then waits for the operator to pick which ones to import
-- (selection_json) — both keyed to the one-time import token. Kept separate from
-- `status` so the existing single-use / fetchable guards (which gate on
-- status='pending') stay intact; the UI derives the stage from these columns.
ALTER TABLE import_tokens ADD COLUMN manifest_json TEXT;
ALTER TABLE import_tokens ADD COLUMN selection_json TEXT;
