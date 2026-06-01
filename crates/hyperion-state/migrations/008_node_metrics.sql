-- Per-tick node-wide metrics (load avg, mem, uptime, totals).
-- One row per stats_tick call; keep a rolling window for charts.
CREATE TABLE node_metrics (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    sampled_at          INTEGER NOT NULL,
    hostings_count      INTEGER NOT NULL DEFAULT 0,
    hostings_active     INTEGER NOT NULL DEFAULT 0,
    hostings_suspended  INTEGER NOT NULL DEFAULT 0,
    hostings_failed     INTEGER NOT NULL DEFAULT 0,
    total_disk_bytes    INTEGER NOT NULL DEFAULT 0,
    total_bw_out_24h    INTEGER NOT NULL DEFAULT 0,
    total_requests_24h  INTEGER NOT NULL DEFAULT 0,
    loadavg_1m_x100     INTEGER NOT NULL DEFAULT 0,
    mem_total_kib       INTEGER NOT NULL DEFAULT 0,
    mem_used_kib        INTEGER NOT NULL DEFAULT 0,
    uptime_secs         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX node_metrics_sampled ON node_metrics(sampled_at DESC);
