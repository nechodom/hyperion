-- Snapshot the profile's Slack billing/expiry webhook onto each apply row, the
-- same way price_minor/currency/interval are already snapshotted. billing_sweep
-- previously re-derived the webhook live from profile_id, so deleting a profile
-- (FK sets profile_id NULL) silently lost the per-hosting billing channel. With
-- the snapshot, billing_sweep reads this column first and the channel survives
-- a profile delete exactly like the price does.
ALTER TABLE hosting_profile_apply ADD COLUMN slack_webhook TEXT;
