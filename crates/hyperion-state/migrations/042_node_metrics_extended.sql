-- Node-level monitoring additions: real CPU utilisation, swap, PSI pressure,
-- and network throughput. All default 0 so existing rows + old agents stay
-- valid; the agent backfills real values from /proc on the next sample tick.
ALTER TABLE node_metrics ADD COLUMN cpu_pct_x100   INTEGER NOT NULL DEFAULT 0;  -- busy % * 100 (0..10000)
ALTER TABLE node_metrics ADD COLUMN swap_total_kib INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node_metrics ADD COLUMN swap_used_kib  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node_metrics ADD COLUMN psi_cpu_x100   INTEGER NOT NULL DEFAULT 0;  -- /proc/pressure cpu  "some avg10" * 100
ALTER TABLE node_metrics ADD COLUMN psi_mem_x100   INTEGER NOT NULL DEFAULT 0;  -- /proc/pressure memory "some avg10" * 100
ALTER TABLE node_metrics ADD COLUMN psi_io_x100    INTEGER NOT NULL DEFAULT 0;  -- /proc/pressure io   "some avg10" * 100
ALTER TABLE node_metrics ADD COLUMN net_rx_bps     INTEGER NOT NULL DEFAULT 0;  -- bytes/sec received  (delta over the sample window)
ALTER TABLE node_metrics ADD COLUMN net_tx_bps     INTEGER NOT NULL DEFAULT 0;  -- bytes/sec transmitted
