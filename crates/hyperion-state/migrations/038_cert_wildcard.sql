-- Mark certs issued via DNS-01 as wildcard so the renewal sweep knows
-- NOT to attempt HTTP-01 (which can't validate `*.domain`). Wildcard
-- certs renew via Cloudflare automatically when a token is configured;
-- otherwise the operator is notified to re-run the manual DNS-01 flow
-- from the SSL tab before expiry.
ALTER TABLE certificates ADD COLUMN is_wildcard INTEGER NOT NULL DEFAULT 0;
