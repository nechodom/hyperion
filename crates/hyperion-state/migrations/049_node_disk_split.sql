-- Split the node "disk" sample into tenant-footprint vs node-volume figures.
--
-- node_metrics.total_disk_bytes is df-Used of the WHOLE node volume (OS +
-- /var + logs + backups + the panel DB + the sites), but the dashboard
-- labelled it "across all hostings" — wildly overstating tenant usage (e.g.
-- 17 GiB for 3 sites under 100 MB each). Keep total_disk_bytes meaning the
-- node volume's used bytes, and add:
--   * hostings_disk_bytes   — Σ per-hosting `du` on this node (real sites sum)
--   * node_disk_total_bytes — df Size (capacity) of the node's home-root volume
-- so the UI can show "across all sites" and "node disk X / Y (Z%)" separately,
-- each correctly labelled. Default 0 on old rows / old agents.
ALTER TABLE node_metrics ADD COLUMN hostings_disk_bytes   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node_metrics ADD COLUMN node_disk_total_bytes INTEGER NOT NULL DEFAULT 0;
