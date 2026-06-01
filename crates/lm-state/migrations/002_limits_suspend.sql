-- 002_limits_suspend.sql
-- Add 'suspended' to hostings.state CHECK constraint and introduce
-- the limits / suspension / usage tables.

-- SQLite has no ALTER TABLE ... DROP/MODIFY CHECK. We must recreate.
PRAGMA foreign_keys = OFF;

CREATE TABLE hostings_new (
    id                TEXT PRIMARY KEY,
    domain            TEXT NOT NULL UNIQUE,
    state             TEXT NOT NULL CHECK (
        state IN ('provisioning','active','suspended','failed','deleting')
    ),
    system_user_id    INTEGER NOT NULL REFERENCES system_users(id),
    php_version       TEXT,
    root_dir          TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
INSERT INTO hostings_new
    SELECT id, domain, state, system_user_id, php_version, root_dir, created_at, updated_at
    FROM hostings;
DROP TABLE hostings;
ALTER TABLE hostings_new RENAME TO hostings;
CREATE INDEX hostings_state ON hostings(state);
CREATE INDEX hostings_system_user ON hostings(system_user_id);

PRAGMA foreign_keys = ON;

-- Per-hosting resource limits.
CREATE TABLE hosting_limits (
    hosting_id          TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    -- nullable means "no enforced limit"
    disk_soft_bytes     INTEGER,
    disk_hard_bytes     INTEGER,
    inode_soft          INTEGER,
    inode_hard          INTEGER,
    php_memory_mb       INTEGER NOT NULL DEFAULT 256,
    php_max_exec_secs   INTEGER NOT NULL DEFAULT 60,
    php_max_children    INTEGER NOT NULL DEFAULT 5,
    php_max_requests    INTEGER NOT NULL DEFAULT 1000,
    db_max_connections  INTEGER NOT NULL DEFAULT 25,
    bw_monthly_bytes    INTEGER,
    over_bw_policy      TEXT NOT NULL DEFAULT 'suspend'
                        CHECK (over_bw_policy IN ('suspend','throttle')),
    throttle_kbps       INTEGER,
    updated_at          INTEGER NOT NULL
);

-- Per-hosting suspended-state metadata.
CREATE TABLE hosting_suspension (
    hosting_id          TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    suspended_at        INTEGER NOT NULL,
    suspended_by        TEXT NOT NULL,             -- 'manual' | 'expired' | 'over-bandwidth'
    reason_message      TEXT,
    custom_page_html    TEXT
);

-- Per-hosting hourly usage observations.
CREATE TABLE hosting_usage (
    hosting_id          TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    period              TEXT NOT NULL,             -- 'YYYY-MM-DD-HH'
    disk_used_bytes     INTEGER NOT NULL DEFAULT 0,
    inodes_used         INTEGER NOT NULL DEFAULT 0,
    bw_in_bytes         INTEGER NOT NULL DEFAULT 0,
    bw_out_bytes        INTEGER NOT NULL DEFAULT 0,
    php_requests        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hosting_id, period)
);
CREATE INDEX hosting_usage_period ON hosting_usage(period);
