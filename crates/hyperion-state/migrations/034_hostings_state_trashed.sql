-- 034_hostings_state_trashed.sql
--
-- Add 'trashed' to the hostings.state CHECK constraint.
--
-- Migration 026 introduced the trash feature (trashed_at column +
-- state flips to 'trashed') but FORGOT to extend the CHECK — which
-- migration 002 had pinned to
--   ('provisioning','active','suspended','failed','deleting').
-- SQLite can't ALTER a CHECK, so every `UPDATE hostings SET
-- state='trashed'` since then has failed with a constraint
-- violation. The bug stayed invisible for weeks because a separate
-- web-form bug kept flipping cluster.trash_enabled back to false,
-- so deletes always took the hard-delete path. The form bug got
-- fixed → trash stayed enabled → the first real soft-delete blew
-- up with "internal error" (the CHECK violation, swallowed by the
-- Internal_with logger).
--
-- Standard SQLite rebuild: new table with the extended CHECK, copy
-- everything, drop, rename. Same recipe as 002 and 023. Column set
-- = 001/002 originals + every ALTER TABLE hostings ADD COLUMN from
-- migrations 003, 012, 014, 015, 016, 020, 021, 026 — in that
-- order, with their original defaults + inline CHECKs preserved.

PRAGMA foreign_keys = OFF;

CREATE TABLE hostings_new (
    id                TEXT PRIMARY KEY,
    domain            TEXT NOT NULL UNIQUE,
    state             TEXT NOT NULL CHECK (
        state IN ('provisioning','active','suspended','failed','deleting','trashed')
    ),
    system_user_id    INTEGER NOT NULL REFERENCES system_users(id),
    php_version       TEXT,
    root_dir          TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    -- 003_expiration
    expires_at        INTEGER,
    owner_email       TEXT,
    grace_days        INTEGER NOT NULL DEFAULT 30,
    warning_offsets_days TEXT NOT NULL DEFAULT '30,7,1',
    -- 012_per_hosting_acme_email
    acme_contact_email TEXT,
    -- 014_hosting_kind_reverse_proxy
    kind              TEXT NOT NULL DEFAULT 'php'
        CHECK (kind IN ('php', 'static', 'reverse_proxy')),
    proxy_upstream_url TEXT,
    -- 015_per_hosting_monitoring
    monitor_enabled   INTEGER NOT NULL DEFAULT 0,
    monitor_url_path  TEXT,
    monitor_interval_secs INTEGER,
    monitor_alert_after_fails INTEGER,
    monitor_alert_email TEXT,
    monitor_alert_slack_webhook TEXT,
    monitor_alert_webhook_url TEXT,
    monitor_consecutive_fails INTEGER NOT NULL DEFAULT 0,
    monitor_last_alert_at INTEGER,
    monitor_alert_state TEXT NOT NULL DEFAULT 'ok'
        CHECK (monitor_alert_state IN ('ok', 'alerting')),
    -- 016_hosting_node
    node_id           TEXT,
    -- 020_hosting_vhost_options
    basic_auth_enabled INTEGER NOT NULL DEFAULT 0,
    basic_auth_user   TEXT NOT NULL DEFAULT '',
    basic_auth_hash   TEXT NOT NULL DEFAULT '',
    force_https       INTEGER NOT NULL DEFAULT 0,
    hsts_max_age      INTEGER NOT NULL DEFAULT 0,
    custom_nginx_snippet TEXT NOT NULL DEFAULT '',
    maintenance_mode  INTEGER NOT NULL DEFAULT 0,
    fastcgi_cache_enabled INTEGER NOT NULL DEFAULT 0,
    fastcgi_cache_ttl INTEGER NOT NULL DEFAULT 300,
    redirect_url      TEXT NOT NULL DEFAULT '',
    redirect_code     INTEGER NOT NULL DEFAULT 301,
    redirect_preserve_path INTEGER NOT NULL DEFAULT 1,
    -- 021_hosting_wp_redis
    wp_debug_enabled  INTEGER NOT NULL DEFAULT 0,
    wp_debug_log      INTEGER NOT NULL DEFAULT 1,
    wp_debug_display  INTEGER NOT NULL DEFAULT 0,
    wp_debug_log_size_bytes INTEGER NOT NULL DEFAULT 0,
    redis_enabled     INTEGER NOT NULL DEFAULT 0,
    redis_db_number   INTEGER,
    redis_password_set INTEGER NOT NULL DEFAULT 0,
    -- 026_hosting_trash
    trashed_at        INTEGER
);

INSERT INTO hostings_new (
    id, domain, state, system_user_id, php_version, root_dir,
    created_at, updated_at,
    expires_at, owner_email, grace_days, warning_offsets_days,
    acme_contact_email,
    kind, proxy_upstream_url,
    monitor_enabled, monitor_url_path, monitor_interval_secs,
    monitor_alert_after_fails, monitor_alert_email,
    monitor_alert_slack_webhook, monitor_alert_webhook_url,
    monitor_consecutive_fails, monitor_last_alert_at,
    monitor_alert_state,
    node_id,
    basic_auth_enabled, basic_auth_user, basic_auth_hash,
    force_https, hsts_max_age, custom_nginx_snippet,
    maintenance_mode, fastcgi_cache_enabled, fastcgi_cache_ttl,
    redirect_url, redirect_code, redirect_preserve_path,
    wp_debug_enabled, wp_debug_log, wp_debug_display,
    wp_debug_log_size_bytes,
    redis_enabled, redis_db_number, redis_password_set,
    trashed_at
)
SELECT
    id, domain, state, system_user_id, php_version, root_dir,
    created_at, updated_at,
    expires_at, owner_email, grace_days, warning_offsets_days,
    acme_contact_email,
    kind, proxy_upstream_url,
    monitor_enabled, monitor_url_path, monitor_interval_secs,
    monitor_alert_after_fails, monitor_alert_email,
    monitor_alert_slack_webhook, monitor_alert_webhook_url,
    monitor_consecutive_fails, monitor_last_alert_at,
    monitor_alert_state,
    node_id,
    basic_auth_enabled, basic_auth_user, basic_auth_hash,
    force_https, hsts_max_age, custom_nginx_snippet,
    maintenance_mode, fastcgi_cache_enabled, fastcgi_cache_ttl,
    redirect_url, redirect_code, redirect_preserve_path,
    wp_debug_enabled, wp_debug_log, wp_debug_display,
    wp_debug_log_size_bytes,
    redis_enabled, redis_db_number, redis_password_set,
    trashed_at
FROM hostings;

DROP TABLE hostings;
ALTER TABLE hostings_new RENAME TO hostings;

-- Recreate every index the old table carried (001/002, 003, 016, 026).
CREATE INDEX hostings_state ON hostings(state);
CREATE INDEX hostings_system_user ON hostings(system_user_id);
CREATE INDEX hostings_expires_at ON hostings(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX hostings_node ON hostings(node_id);
CREATE INDEX idx_hostings_trashed_at ON hostings(trashed_at) WHERE trashed_at IS NOT NULL;

PRAGMA foreign_keys = ON;
