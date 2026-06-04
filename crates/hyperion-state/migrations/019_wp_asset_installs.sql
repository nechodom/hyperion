-- Master-side tracking of "where has each WP asset been installed".
--
-- Populated by the master web handlers post_wp_install_from_asset
-- + bulk install + apply_profile_wp_items so the operator can:
--   1. See on /profiles/wp-assets exactly which hostings have a
--      given asset installed,
--   2. Hit "Re-install on all" to push a freshly-replaced ZIP to
--      every hosting that previously had this asset.
--
-- (Each agent already audits its own installs; this table is the
-- master's per-asset INDEX on top — needed because the master's
-- audit log doesn't see installs that happened on a remote node.)

CREATE TABLE wp_asset_installs (
    asset_id      INTEGER NOT NULL REFERENCES wp_assets(id) ON DELETE CASCADE,
    -- The hosting selector we dispatched to. Stored as string
    -- (`hosting.id` from HostingDetail) so we can re-dispatch even
    -- if the hosting moved between nodes since.
    hosting_id    TEXT NOT NULL,
    -- The node the install was dispatched to (or empty for master
    -- local). Stored as a hint — the re-install path always
    -- re-runs find_hosting_anywhere to handle a hosting that
    -- migrated since.
    node_id       TEXT NOT NULL DEFAULT '',
    -- Whether activate was requested at install time. Used as the
    -- default for re-install (operator can override).
    activate      INTEGER NOT NULL DEFAULT 0,
    last_at       INTEGER NOT NULL,
    PRIMARY KEY (asset_id, hosting_id)
);

CREATE INDEX wp_asset_installs_asset ON wp_asset_installs(asset_id);
CREATE INDEX wp_asset_installs_hosting ON wp_asset_installs(hosting_id);
