-- 006_wordpress.sql
-- App packs (curated bundles of WP core + plugins + themes + post-install
-- scripts) + per-hosting WordPress install tracking.

CREATE TABLE app_packs (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL CHECK (kind IN ('wordpress')),
    description     TEXT,
    manifest_json   TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE app_pack_assets (
    pack_id         INTEGER NOT NULL REFERENCES app_packs(id) ON DELETE CASCADE,
    asset_id        TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('plugin','theme')),
    filename        TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    bytes           INTEGER NOT NULL,
    stored_path     TEXT NOT NULL,
    PRIMARY KEY (pack_id, asset_id)
);

CREATE TABLE wp_installs (
    hosting_id           TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    site_url             TEXT NOT NULL,
    wp_version           TEXT NOT NULL,
    installed_at         INTEGER NOT NULL,
    last_pack_hash       TEXT NOT NULL,
    auto_update_core     TEXT NOT NULL DEFAULT 'off'
                         CHECK (auto_update_core IN ('off','minor','major')),
    auto_update_plugins  INTEGER NOT NULL DEFAULT 0,
    auto_update_themes   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE wp_update_runs (
    id           INTEGER PRIMARY KEY,
    hosting_id   TEXT NOT NULL REFERENCES hostings(id),
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    scope        TEXT NOT NULL CHECK (scope IN ('core','plugins','themes','all')),
    state        TEXT NOT NULL CHECK (state IN ('running','ok','failed','rolled-back')),
    output_tail  TEXT
);
