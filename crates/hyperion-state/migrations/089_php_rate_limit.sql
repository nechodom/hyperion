-- Per-visitor rate limit on PHP requests (hosting's Security card). Off by
-- default: a shared office address or a crawler can look like a flood, so this
-- is a tool for a site under bot load, not a setting every site should carry.
ALTER TABLE hostings ADD COLUMN php_rate_limit_enabled INTEGER NOT NULL DEFAULT 0;
