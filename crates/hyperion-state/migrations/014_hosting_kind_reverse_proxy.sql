-- 014_hosting_kind_reverse_proxy.sql
--
-- Add support for non-PHP hosting types. Existing rows default to "php"
-- (since that's what we've been provisioning so far). New kinds:
--   php        — nginx + PHP-FPM + (optionally) database (existing behaviour)
--   static     — nginx static files only, no PHP, no DB
--   reverse_proxy — nginx proxies to a configured upstream URL
--                   (single URL, websocket pass on, no auth/headers in MVP)
--
-- For reverse_proxy, the `proxy_upstream_url` column holds the target
-- (e.g. "http://localhost:3000" or "http://10.0.0.5:8080"). Empty/NULL
-- for other kinds.

ALTER TABLE hostings ADD COLUMN kind TEXT NOT NULL DEFAULT 'php'
    CHECK (kind IN ('php', 'static', 'reverse_proxy'));
ALTER TABLE hostings ADD COLUMN proxy_upstream_url TEXT;
