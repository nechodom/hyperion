-- 005_nodejs.sql
-- Node.js hosting type. Each Node hosting has a row here in addition to
-- its normal `hostings` row (php_version stays NULL for Node hostings).

CREATE TABLE node_apps (
    hosting_id          TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    node_version        TEXT NOT NULL CHECK (node_version IN ('18','20','22')),
    app_entry           TEXT NOT NULL,
    listen_port         INTEGER NOT NULL UNIQUE,
    env_vars_secret_id  TEXT NOT NULL UNIQUE,
    memory_mb           INTEGER NOT NULL DEFAULT 256,
    cpu_quota_pct       INTEGER NOT NULL DEFAULT 100,
    tasks_max           INTEGER NOT NULL DEFAULT 200,
    install_state       TEXT NOT NULL
                        CHECK (install_state IN ('pending','installing','ready','failed')),
    last_deploy_at      INTEGER,
    last_deploy_log     TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);
CREATE INDEX node_apps_state ON node_apps(install_state);

CREATE TABLE port_pool (
    port  INTEGER PRIMARY KEY,
    used  INTEGER NOT NULL DEFAULT 0
);
-- Pre-populate 30000..39999 via a recursive CTE.
WITH RECURSIVE p(n) AS (
    SELECT 30000 UNION ALL SELECT n + 1 FROM p WHERE n < 39999
)
INSERT INTO port_pool (port, used) SELECT n, 0 FROM p;
