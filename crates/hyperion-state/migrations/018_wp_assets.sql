-- WordPress asset library + per-profile install lists.
--
-- Operators upload plugin / theme ZIPs to /var/lib/hyperion/wp-assets/<id>/
-- and reference them in hosting profiles. Applying a profile to a
-- WordPress-installed hosting runs `wp plugin install <slug-or-path>`
-- for each line in the profile's wp_plugins / wp_themes lists.

CREATE TABLE wp_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 'plugin' or 'theme'. CHECK ensures we don't get random strings
    -- in here from a bug elsewhere.
    kind            TEXT NOT NULL CHECK (kind IN ('plugin', 'theme')),
    -- Filename the operator uploaded ('akismet.5.3.7.zip'). Display-only.
    original_name   TEXT NOT NULL,
    -- Sanitised on-disk name under /var/lib/hyperion/wp-assets/<id>/.
    -- Stored separately because we want to enforce a deterministic
    -- shape regardless of what the operator named the file.
    stored_filename TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    -- Hex SHA-256 of the ZIP. Used to dedupe and to validate the file
    -- on disk hasn't been silently corrupted before we feed it to
    -- wp-cli.
    sha256          TEXT NOT NULL,
    uploaded_at     INTEGER NOT NULL,
    uploaded_by     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX wp_assets_kind ON wp_assets(kind);

-- Per-profile lists. Stored as plain text (one item per line) on the
-- profile row itself rather than a join table — keeps the API simple
-- (one form textarea per kind) and matches how operators think about
-- "all the plugins this profile installs".
--
-- Syntax per line:
--   <slug>          → wp plugin install <slug>             (from wordpress.org)
--   @asset:<id>     → wp plugin install /path/to/uploaded.zip
--   <slug>!         → trailing '!' = also activate after install
--   @asset:<id>!    → same
--   <empty / #...>  → skipped (allows comments)
--
-- Both columns default to '' so existing profiles keep working.
ALTER TABLE hosting_profiles ADD COLUMN wp_plugins TEXT NOT NULL DEFAULT '';
ALTER TABLE hosting_profiles ADD COLUMN wp_themes  TEXT NOT NULL DEFAULT '';
