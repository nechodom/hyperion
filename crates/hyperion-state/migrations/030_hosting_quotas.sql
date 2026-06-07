-- 030_hosting_quotas.sql
--
-- Per-hosting quota policy. Disk caps are pushed into the kernel
-- via `setquota` against the hosting's owner uid; the soft cap
-- triggers the user's grace period, the hard cap stops writes
-- with ENOSPC. Bandwidth is tracked from nginx logs and surfaced
-- here as a soft-warn (no kernel enforcement available cheaply).
-- Memory caps are propagated into the FPM pool template via
-- pm.max_children + memory_limit on next vhost rebuild.
--
-- A row absent from this table ⇒ hosting runs without quotas
-- (the default; matches pre-quota behaviour).
CREATE TABLE hosting_quotas (
    hosting_id        TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    -- Disk: 0 ⇒ no cap. soft <= hard. Both in 1 KiB blocks
    -- (matches the unit setquota writes; the conversion to MiB
    -- for display happens in the UI layer).
    disk_soft_kib     INTEGER NOT NULL DEFAULT 0,
    disk_hard_kib     INTEGER NOT NULL DEFAULT 0,
    -- PHP per-pool memory_limit, in MiB. 0 ⇒ inherit php.ini
    -- default. Plumbed into the FPM pool template's
    -- `php_admin_value[memory_limit]` line on next vhost rebuild.
    mem_limit_mib     INTEGER NOT NULL DEFAULT 0,
    -- Bandwidth budgets (per calendar month), MiB. 0 ⇒ no cap.
    -- Soft fires a notification; hard is advisory only (no
    -- enforcement layer yet, see policy in services).
    bw_soft_mib       INTEGER NOT NULL DEFAULT 0,
    bw_hard_mib       INTEGER NOT NULL DEFAULT 0,
    -- Last successful setquota invocation. NULL ⇒ never applied
    -- (e.g. /etc/fstab missing usrquota mount option).
    applied_at        INTEGER,
    -- Last setquota stderr when applied_at < updated_at — lets
    -- the UI explain "you set this 3 hours ago but the kernel
    -- never accepted it because quotaon isn't enabled".
    last_error        TEXT,
    updated_at        INTEGER NOT NULL
);
CREATE INDEX hosting_quotas_updated ON hosting_quotas(updated_at);
