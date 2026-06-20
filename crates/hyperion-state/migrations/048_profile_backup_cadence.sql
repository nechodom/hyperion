-- A profile can now carry a recurring-backup cadence, seeded onto each hosting
-- at apply (into hosting_kv key 'backup_cadence'). 'off' (the default) keeps the
-- prior behaviour — backups only run on demand. 'daily' | 'weekly' | 'monthly'
-- make the per-node scheduled-backup driver run backup_now when a site is due.
ALTER TABLE hosting_profiles ADD COLUMN backup_cadence TEXT NOT NULL DEFAULT 'off';
