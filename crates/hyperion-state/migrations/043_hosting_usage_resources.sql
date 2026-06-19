-- Per-hosting live resource usage: memory (RSS of the site's processes) and
-- CPU %. Written to the current period row each sample tick and read as the
-- "latest" snapshot (same pattern as disk_used_bytes). Default 0 so existing
-- rows / old agents stay valid.
ALTER TABLE hosting_usage ADD COLUMN mem_rss_bytes INTEGER NOT NULL DEFAULT 0;  -- sum RSS of procs owned by the hosting's system_user
ALTER TABLE hosting_usage ADD COLUMN cpu_pct_x100  INTEGER NOT NULL DEFAULT 0;  -- busy % * 100 attributed to that user over the sample window
