-- Per-key hardening for the /api/v1 remote API. Both optional:
--   ip_allowlist       — JSON array of CIDR strings; '[]' = allow any peer IP.
--   rate_limit_per_min — requests/min; 0 = unlimited.
-- Enforced in the web tier's ApiAuth extractor on every /api/v1 request.
ALTER TABLE api_keys ADD COLUMN ip_allowlist TEXT NOT NULL DEFAULT '[]';
ALTER TABLE api_keys ADD COLUMN rate_limit_per_min INTEGER NOT NULL DEFAULT 0;
