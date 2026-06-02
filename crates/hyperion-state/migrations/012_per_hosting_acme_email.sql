-- 012_per_hosting_acme_email.sql
--
-- Allow operators to override the ACME contact email per hosting.
-- A NULL value means "fall back to the agent-wide email from
-- [acme] contact_email in /etc/hyperion/agent.toml". Operators
-- typically want this when:
--   - Different end-customers want their own email on their certs.
--   - One hosting is for a domain the operator manages on behalf of
--     a third party who should receive expiry notices directly.
--
-- The agent never sends mail itself for this field — it's handed
-- straight to Let's Encrypt at account-creation time, which uses it
-- only for expiry warnings + ToS notifications.

ALTER TABLE hostings ADD COLUMN acme_contact_email TEXT;
