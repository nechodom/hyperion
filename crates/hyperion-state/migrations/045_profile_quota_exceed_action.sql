-- Per-profile default for what happens when a hosting exceeds its disk hard
-- cap: 'notify' (send an alert only) or 'suspend' (stop the site + alert).
-- The hosting copies this into hosting_kv (key 'quota_exceed_action') at
-- create time and may override it per-hosting from the Quota card.
ALTER TABLE hosting_profiles
    ADD COLUMN quota_exceed_action TEXT NOT NULL DEFAULT 'notify';
