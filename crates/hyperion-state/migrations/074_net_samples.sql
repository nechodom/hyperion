-- High-resolution network throughput ring.
--
-- The main stats sampler runs every 5 minutes because it also walks a `du`
-- per hosting — far too coarse for a live network graph. This table is fed by
-- a dedicated lightweight sampler (a /proc/net/dev delta, no `du`) every few
-- seconds and kept to a short rolling window, so the stats page can draw a
-- genuinely realtime rx/tx sparkline without touching the heavy sampler.
--
-- Node-local (each agent writes its own); pruned to ~1h by the sampler, so it
-- stays tiny. Rates are bytes/sec at sample time.
CREATE TABLE net_samples (
    at      INTEGER NOT NULL,
    rx_bps  INTEGER NOT NULL,
    tx_bps  INTEGER NOT NULL
);
CREATE INDEX idx_net_samples_at ON net_samples (at);
