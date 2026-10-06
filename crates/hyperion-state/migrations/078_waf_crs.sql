-- WAF phase B: the opt-in OWASP Core Rule Set tier (ModSecurity v3).
--
-- Columns on `hostings` like the rest of the vhost options, so the nginx
-- render still reads every knob in one pass. Off by default: no existing
-- site changes.
ALTER TABLE hostings ADD COLUMN crs_mode TEXT NOT NULL DEFAULT 'off';
ALTER TABLE hostings ADD COLUMN crs_paranoia INTEGER NOT NULL DEFAULT 1;
ALTER TABLE hostings ADD COLUMN crs_threshold INTEGER NOT NULL DEFAULT 5;
ALTER TABLE hostings ADD COLUMN crs_wordpress INTEGER NOT NULL DEFAULT 1;
-- JSON list of {rules:[…], path:""}; empty = none.
ALTER TABLE hostings ADD COLUMN crs_exclusions TEXT NOT NULL DEFAULT '';

-- What a refusal matched beyond its tag — for a CRS decision, the rule ids
-- and the anomaly score. Shown in the activity list; "Allow this" reads it.
ALTER TABLE waf_recent ADD COLUMN detail TEXT NOT NULL DEFAULT '';
