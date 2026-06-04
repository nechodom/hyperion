-- Per-hosting nginx vhost knobs the operator can flip from the
-- detail page. All default to "off" so existing hostings keep
-- behaving exactly as before until something is enabled.
--
-- Stored as columns on `hostings` rather than a join table because
-- they're all small scalars and the vhost render needs them all in
-- one pass; a join table would mean an extra query per page render.

ALTER TABLE hostings ADD COLUMN basic_auth_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hostings ADD COLUMN basic_auth_user    TEXT    NOT NULL DEFAULT '';
-- Stored as an Apache htpasswd-compatible line (bcrypt $2y$...).
-- Empty unless basic_auth_enabled = 1. We write the actual
-- /etc/nginx/.htpasswd-<id> file from this so the secret never
-- has to round-trip through a separate file-distribution path.
ALTER TABLE hostings ADD COLUMN basic_auth_hash    TEXT    NOT NULL DEFAULT '';

ALTER TABLE hostings ADD COLUMN force_https        INTEGER NOT NULL DEFAULT 0;
-- HSTS max-age in seconds; 0 = HSTS disabled. Recommended 63072000
-- (2 years) when the operator is confident the site will stay TLS.
ALTER TABLE hostings ADD COLUMN hsts_max_age       INTEGER NOT NULL DEFAULT 0;

-- Arbitrary nginx config snippet injected into the HTTPS server
-- block (after the standard locations). Validated with `nginx -t`
-- before save — bad input is rejected with the actual nginx error.
ALTER TABLE hostings ADD COLUMN custom_nginx_snippet TEXT NOT NULL DEFAULT '';

-- When 1, vhost serves a generic "we'll be back" 503 page for
-- every request. Doesn't suspend the DB / FPM (operator can still
-- ssh in and work). Cert + acme-challenge are still served so
-- renewals don't break.
ALTER TABLE hostings ADD COLUMN maintenance_mode   INTEGER NOT NULL DEFAULT 0;

-- FastCGI page cache. When 1, nginx caches PHP responses for the
-- configured TTL. Per-hosting cache dir under
-- /var/lib/hyperion/fastcgi-cache/<hosting_id>/. Operator can
-- purge from the detail page (Purge button).
ALTER TABLE hostings ADD COLUMN fastcgi_cache_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hostings ADD COLUMN fastcgi_cache_ttl     INTEGER NOT NULL DEFAULT 300;

-- Redirect-only hosting kind (014_hosting_kind_reverse_proxy
-- introduced the `kind` column with 'php'|'static'|'reverse_proxy';
-- this column adds the destination URL when kind = 'redirect').
ALTER TABLE hostings ADD COLUMN redirect_url TEXT NOT NULL DEFAULT '';
ALTER TABLE hostings ADD COLUMN redirect_code INTEGER NOT NULL DEFAULT 301;
-- Whether to preserve the request path in the redirect target
-- (true → /foo/bar → <target>/foo/bar; false → flat /).
ALTER TABLE hostings ADD COLUMN redirect_preserve_path INTEGER NOT NULL DEFAULT 1;
