-- The Protection page (/protection): what the WAF refused and who was
-- banned, cluster-wide. Two facts it needs that were not kept.
--
-- 078 is taken by the CRS branch (#237); this skips it on purpose.

-- Whether a refused request came from a real browser — it sent
-- `Sec-Fetch-Site`, which browsers attach to every request and scanners
-- and scripts do not. A rule refusing mostly browser traffic is the shape
-- of a false positive. Rows recorded before this column read 0.
ALTER TABLE waf_recent ADD COLUMN browser INTEGER NOT NULL DEFAULT 0;

-- How a ban stopped being active: 'expired' (its time ran out), 'lifted'
-- (someone removed it) or 'replaced' (a new ban on the same address took
-- its place). NULL while active — and on rows that ended before this
-- column existed, where it is simply unknown.
ALTER TABLE ip_bans ADD COLUMN ended_at INTEGER;
ALTER TABLE ip_bans ADD COLUMN end_reason TEXT;

-- The ban history reads "every ban raised in the last N days".
CREATE INDEX IF NOT EXISTS idx_ip_bans_banned_at ON ip_bans (banned_at);
