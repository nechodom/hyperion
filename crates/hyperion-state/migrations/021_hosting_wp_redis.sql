-- Bundle 2: WP debug toggle + per-hosting Redis cache.
--
-- WP debug:
--   Flips WP_DEBUG / WP_DEBUG_LOG / WP_DEBUG_DISPLAY in wp-config.php
--   via wp-cli. We track desired state in DB so the UI can show the
--   toggle position without parsing wp-config.php on every page load.
--   wp_debug_log_size_bytes is sampled by the agent each tick so the
--   UI can show "debug log is 23 MB, rotate?" without an extra RPC.
--
-- Per-hosting Redis (FastCGI cache is at the nginx layer; this is the
-- WordPress *object* cache layer — drops query latency on uncached
-- page renders, persists fragment caches across requests):
--   When redis_enabled = 1, the agent assigns a unique Redis DB number
--   (0..15 by default; agent bumps `databases` config when needed) and
--   provisions a Redis ACL user `r_<hosting_id_8>` with password +
--   restricted to that DB only. wp-config.php gets WP_REDIS_HOST /
--   PORT / DATABASE / PASSWORD / KEY_SALT constants so the standard
--   Redis Object Cache plugin Just Works. redis_password_set tells
--   the UI whether to show "rotate password" vs "set password".

ALTER TABLE hostings ADD COLUMN wp_debug_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hostings ADD COLUMN wp_debug_log INTEGER NOT NULL DEFAULT 1;
ALTER TABLE hostings ADD COLUMN wp_debug_display INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hostings ADD COLUMN wp_debug_log_size_bytes INTEGER NOT NULL DEFAULT 0;

ALTER TABLE hostings ADD COLUMN redis_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hostings ADD COLUMN redis_db_number INTEGER;
ALTER TABLE hostings ADD COLUMN redis_password_set INTEGER NOT NULL DEFAULT 0;
