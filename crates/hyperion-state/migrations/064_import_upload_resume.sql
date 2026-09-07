-- Resumable self-service import uploads.
--
-- The AUTHORITATIVE offset is not in this table: it is the size of the
-- `bundle-<id>.tar.part` file on disk. A number in SQLite and a number of bytes
-- on a filesystem can disagree after a crash, and only one of them is what a
-- resumed upload must append to. These columns exist so the PANEL can render a
-- denominator, a measured rate and an honest ETA — never to decide where the
-- next chunk goes.
--
-- Every column has a default so rows minted by an older version stay valid; an
-- upload that began before this migration simply has expected_bytes = 0, which
-- the UI reads as "total unknown" and renders without a percentage.
ALTER TABLE import_tokens ADD COLUMN expected_bytes INTEGER NOT NULL DEFAULT 0;
-- Hex sha256 the SOURCE promises for the finished bundle. Verified on commit
-- before the import job is spawned; a bundle with no digest is refused outright
-- rather than falling back to `tar tf`, which exits 0 on a zero-padded
-- truncation and silently drops whole sites.
ALTER TABLE import_tokens ADD COLUMN bundle_sha256 TEXT;
-- When received_bytes was last written, and the older sample it is measured
-- against. A rate needs two stamped observations; one counter cannot produce one.
ALTER TABLE import_tokens ADD COLUMN received_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE import_tokens ADD COLUMN rate_ref_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE import_tokens ADD COLUMN rate_ref_at INTEGER NOT NULL DEFAULT 0;
-- What the source says it is doing while it packs. Before this, the panel showed
-- dead air for what is usually the longest phase of the run.
ALTER TABLE import_tokens ADD COLUMN source_progress_json TEXT;
ALTER TABLE import_tokens ADD COLUMN source_progress_at INTEGER NOT NULL DEFAULT 0;
