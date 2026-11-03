-- CPU, load and memory on the high-resolution ring, so those graphs on the
-- stats page move as often as the network one instead of every 5 minutes.
--
-- Rows from before this migration read mem_total_kib = 0, which is how the
-- page tells them apart. They age out of the ring within the hour.
ALTER TABLE net_samples ADD COLUMN cpu_pct_x100    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE net_samples ADD COLUMN loadavg_1m_x100 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE net_samples ADD COLUMN mem_used_kib    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE net_samples ADD COLUMN mem_total_kib   INTEGER NOT NULL DEFAULT 0;
