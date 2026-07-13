-- Index for the ban-escalation lookup. `bans::was_banned_since` queries
-- `WHERE ip = ? AND banned_at >= ?` across ALL rows (active or lifted) to
-- decide whether an offender is a repeat — so it can't use the existing
-- partial index `idx_ip_bans_ip_active` (which only covers active = 1).
-- Without this, every auto-ban does a full scan of ip_bans, which grows
-- monotonically (reap_expired flips active = 0, never deletes).
CREATE INDEX IF NOT EXISTS idx_ip_bans_ip_bannedat ON ip_bans(ip, banned_at);
