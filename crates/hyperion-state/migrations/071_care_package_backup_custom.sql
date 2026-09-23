-- 071_care_package_backup_custom.sql
--
-- Care packages gain the same custom backup FREQUENCY + RETENTION that
-- profiles got in migration 070, so a paid plan can promise one customer a
-- tighter schedule or a longer history without touching the node-wide
-- defaults. Three integer feature columns on BOTH the definition and the
-- activation snapshot (the activation must be self-contained — it is
-- enforced on the node that owns the hosting, where `service_packages` is
-- empty), seeded into the site's hosting_kv on the owning node while the
-- package is active and restored on cancel:
--
--   * feat_backup_interval_days > 0 is used ONLY when the cadence is
--     'custom' (a new value below), and sets the period in days. The
--     presets keep their fixed schedule; 'custom' with no interval is not
--     due, exactly like the profile side.
--   * feat_backup_keep_days / feat_backup_keep_last override the node-wide
--     [backup_retention] rule for a site while a package that pins a
--     cadence is active; 0 = no opinion, the node rule stands.
--
-- Adding 'custom' means widening the definition's feat_backup_cadence CHECK
-- (the activation column was deliberately never CHECKed — see 057). SQLite
-- cannot alter a CHECK in place, so service_packages is rebuilt. Nothing
-- references it by foreign key (package_id on hosting_packages is a plain
-- back-reference, not an FK), so the rebuild touches no other table.

-- ── The activation snapshot: bare ADD COLUMN, no CHECK to fight. ──────────
ALTER TABLE hosting_packages ADD COLUMN feat_backup_interval_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosting_packages ADD COLUMN feat_backup_keep_days     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosting_packages ADD COLUMN feat_backup_keep_last     INTEGER NOT NULL DEFAULT 0;

-- ── The definition: rebuild to widen the cadence CHECK and add the three ──
--    columns in one new shape. The column list reproduces the live schema
--    (057 + letters_lang from 065 + check_items from 066).
CREATE TABLE service_packages_new (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL UNIQUE,
    slug                TEXT NOT NULL UNIQUE,
    description         TEXT NOT NULL DEFAULT '',
    enabled             INTEGER NOT NULL DEFAULT 1,
    price_minor         INTEGER,
    price_currency      TEXT,
    price_interval      TEXT,
    feat_wp_auto_update TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_wp_auto_update IN ('leave','on','off')),
    feat_integrity_scan TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_integrity_scan IN ('leave','on','off')),
    feat_monitoring     TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_monitoring IN ('leave','on','off')),
    feat_hardening      TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_hardening IN ('leave','on','off')),
    -- 'custom' joins the presets: it pins the cadence to "every N days",
    -- where N is feat_backup_interval_days below.
    feat_backup_cadence TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_backup_cadence IN ('leave','off','daily','weekly','monthly','custom')),
    feat_report_cadence TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_report_cadence IN ('leave','off','weekly','monthly','quarterly')),
    -- Custom backup FREQUENCY (days, used only when feat_backup_cadence =
    -- 'custom') and RETENTION overrides, seeded into the site's hosting_kv
    -- on the owning node. 0 = no opinion (preset schedule / node-wide rule).
    feat_backup_interval_days INTEGER NOT NULL DEFAULT 0,
    feat_backup_keep_days     INTEGER NOT NULL DEFAULT 0,
    feat_backup_keep_last     INTEGER NOT NULL DEFAULT 0,
    letters_lang        TEXT NOT NULL DEFAULT '',
    check_items         TEXT NOT NULL DEFAULT '',
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

INSERT INTO service_packages_new
    (id, name, slug, description, enabled, price_minor, price_currency, price_interval,
     feat_wp_auto_update, feat_integrity_scan, feat_monitoring, feat_hardening,
     feat_backup_cadence, feat_report_cadence, letters_lang, check_items,
     created_at, updated_at)
SELECT
     id, name, slug, description, enabled, price_minor, price_currency, price_interval,
     feat_wp_auto_update, feat_integrity_scan, feat_monitoring, feat_hardening,
     feat_backup_cadence, feat_report_cadence, letters_lang, check_items,
     created_at, updated_at
FROM service_packages;

DROP TABLE service_packages;
ALTER TABLE service_packages_new RENAME TO service_packages;
