-- Profiles can now express the full enforced disk/memory quota, not just a
-- single (and previously inert) disk hard cap. `disk_soft_mb` seeds the soft
-- (warning) disk threshold and `mem_limit_mib` the per-hosting memory cap;
-- both map into the hosting_quotas row that setquota + the enforce loop read.
ALTER TABLE hosting_profiles ADD COLUMN disk_soft_mb INTEGER;
ALTER TABLE hosting_profiles ADD COLUMN mem_limit_mib INTEGER;
