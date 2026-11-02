-- Five-minute per-site usage history behind the /stats range picker.
--
-- `hosting_usage` keys on the UTC hour, too coarse to answer "the last 30
-- minutes". One row per site per stats tick; rows sum, so a window's CPU
-- average is SUM(busy)/SUM(total) however long the ticks really were.
--
-- Node-local (each agent writes its own). Pruned to a little over the longest
-- range the page offers, so it stays small. No foreign key: a purged site's
-- rows age out with the rest, and every read is driven from the hostings list.
CREATE TABLE hosting_usage_samples (
    hosting_id        TEXT    NOT NULL,
    at                INTEGER NOT NULL,
    cpu_busy_jiffies  INTEGER NOT NULL DEFAULT 0,  -- charged to the site's user over the tick
    cpu_total_jiffies INTEGER NOT NULL DEFAULT 0,  -- the whole node's capacity over the same tick
    cpu_peak_x100     INTEGER NOT NULL DEFAULT 0,  -- highest one-minute average within the tick
    mem_rss_bytes     INTEGER NOT NULL DEFAULT 0,
    bw_in_bytes       INTEGER NOT NULL DEFAULT 0,
    bw_out_bytes      INTEGER NOT NULL DEFAULT 0,
    requests          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hosting_id, at)
);
CREATE INDEX idx_hosting_usage_samples_at ON hosting_usage_samples (at);
