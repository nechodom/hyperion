-- 084_care_package_firewall.sql
--
-- A care plan's "firewall" stops being one on/off switch:
--
--   feat_firewall_strict  1 = with feat_hardening = 'on', hold the WAF at
--                         Strict rather than "at least Standard". The on/off
--                         half stays in feat_hardening, so an older node reads
--                         what it always read and enforces Standard.
--   feat_crs              the OWASP Core Rule Set tier (ModSecurity v3,
--                         migration 078): 'leave' | 'off' | 'detect' | 'block'.
--   feat_bruteforce       the per-site HTTP brute-force scan, tri-state like
--                         the other booleans: 'leave' | 'on' | 'off'.
--
-- On BOTH tables, like every feature before them: the activation must be
-- self-contained (it is enforced on the node that owns the hosting, where
-- service_packages is empty — see 057). The definition columns carry a CHECK
-- (ADD COLUMN may, and the default satisfies it); the activation columns stay
-- un-CHECKed so a node reading a value a newer master wrote degrades it to
-- 'leave' in Rust instead of refusing the INSERT.
ALTER TABLE service_packages ADD COLUMN feat_firewall_strict INTEGER NOT NULL DEFAULT 0
    CHECK (feat_firewall_strict IN (0, 1));
ALTER TABLE service_packages ADD COLUMN feat_crs TEXT NOT NULL DEFAULT 'leave'
    CHECK (feat_crs IN ('leave','off','detect','block'));
ALTER TABLE service_packages ADD COLUMN feat_bruteforce TEXT NOT NULL DEFAULT 'leave'
    CHECK (feat_bruteforce IN ('leave','on','off'));

ALTER TABLE hosting_packages ADD COLUMN feat_firewall_strict INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosting_packages ADD COLUMN feat_crs TEXT NOT NULL DEFAULT 'leave';
ALTER TABLE hosting_packages ADD COLUMN feat_bruteforce TEXT NOT NULL DEFAULT 'leave';
