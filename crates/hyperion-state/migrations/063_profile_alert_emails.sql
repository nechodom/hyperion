-- Operator alert addresses per profile.
--
-- Until now an operational alert (a backup that failed, a certificate that
-- will not renew, a site that stopped answering) went to exactly one place:
-- the cluster-wide `[email] default_to`. That is right for "whoever runs this
-- box" and wrong for everything else — a profile that represents one client's
-- sites has an IT contact who wants to hear about them, and there was nowhere
-- to put them.
--
-- The list is ADDITIVE to the cluster-wide addresses, never a replacement.
-- Replacing would mean adding one address to a profile silently stops the
-- operator receiving alerts they were getting, and an alert that quietly
-- stopped is worse than one too many.
ALTER TABLE hosting_profiles ADD COLUMN alert_emails TEXT NOT NULL DEFAULT '';

-- Snapshotted onto the apply row for the same reason `slack_webhook` was in
-- migration 047: deleting a profile sets `profile_id` NULL, and a live lookup
-- would silently lose the addresses for every site that was on it.
ALTER TABLE hosting_profile_apply ADD COLUMN alert_emails TEXT;
