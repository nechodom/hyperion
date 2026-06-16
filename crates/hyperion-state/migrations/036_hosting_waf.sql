-- WAF-lite + wp-admin IP allowlist (feature #6). Two more per-hosting
-- vhost knobs, stored as columns on `hostings` alongside the
-- migration-020 vhost options so the nginx render still reads every
-- knob in one pass.
--
-- Both default to off so existing hostings render an identical vhost
-- until the operator enables them from the Settings tab.

-- When 1, the vhost gets a conservative set of nginx rules: deny
-- direct access to sensitive files (wp-config.php, xmlrpc.php, dumps),
-- block PHP execution in wp-content/uploads + cache, and 403 obvious
-- probe query-strings / scanner user-agents. Deliberately lighter than
-- full ModSecurity to avoid false positives on stock Debian nginx.
ALTER TABLE hostings ADD COLUMN waf_enabled INTEGER NOT NULL DEFAULT 0;

-- Comma/newline-separated list of IPs or CIDRs allowed to reach
-- /wp-admin and /wp-login.php. Empty = no restriction (default).
-- admin-ajax.php stays public so front-end AJAX keeps working.
ALTER TABLE hostings ADD COLUMN wp_admin_allowlist TEXT NOT NULL DEFAULT '';
