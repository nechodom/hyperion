-- 027 — Profile runtime defaults: PHP version + DB engine.
--
-- Operators picking a profile in the new-hosting wizard used to get
-- their profile's LIMITS applied post-create (memory, max_children,
-- DB max connections), but step 3 of the wizard left PHP version
-- and DB engine on the global defaults. A profile bundled as
-- "WordPress Pro" was expected to install PHP 8.4 + MariaDB but the
-- operator had to remember to flip those dropdowns themselves.
--
-- This migration adds two nullable columns to `hosting_profiles`:
--
--   * default_php_version — one of '8.1' / '8.2' / '8.3' / '8.4'
--     or NULL (= no profile-side preference; wizard keeps the
--     global default 8.3).
--   * default_db_engine — 'mariadb' / 'postgres' / 'none' or NULL.
--     'none' is meaningful (static-no-DB profiles); NULL = no
--     preference.
--
-- Both nullable so existing profiles keep working unchanged. The
-- wizard reads them via data attributes on the profile card; when
-- the operator picks a profile that sets either, the corresponding
-- dropdown auto-selects to match.

ALTER TABLE hosting_profiles ADD COLUMN default_php_version TEXT;
ALTER TABLE hosting_profiles ADD COLUMN default_db_engine   TEXT;
