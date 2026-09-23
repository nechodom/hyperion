-- Per-profile backup FREQUENCY and RETENTION, seeded into the hosting's
-- hosting_kv at apply time (keys 'backup_interval_days', 'backup_keep_days',
-- 'backup_keep_last'). 0 everywhere means "no opinion":
--   * backup_interval_days > 0 is used only when backup_cadence = 'custom',
--     and sets the period in days (the presets keep their fixed schedule).
--   * backup_keep_days / backup_keep_last override the node-wide
--     [backup_retention] rule for sites on this profile; 0 = use the node rule.
ALTER TABLE hosting_profiles ADD COLUMN backup_interval_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosting_profiles ADD COLUMN backup_keep_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosting_profiles ADD COLUMN backup_keep_last INTEGER NOT NULL DEFAULT 0;
