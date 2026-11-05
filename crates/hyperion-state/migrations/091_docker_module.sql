-- Docker monitoring module: install state and the bookkeeping its ticks keep.
--
-- Read-only towards Docker, so nothing here mirrors container state beyond
-- what an alert needs to remember between ticks (when a project went quiet,
-- which alert is open, how many restarts we saw). The module being off is
-- `node_installed = 0` and every table empty.
--
-- A `*_at` / `*_since` of 0 means "never" / "not now"; there are no NULLs.

-- This node's module state. One row, always present.
CREATE TABLE docker_module (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    -- Master bookkeeping: the operator turned the module on for the cluster.
    cluster_installed INTEGER NOT NULL DEFAULT 0,
    -- This node runs the module (and so may run `docker`).
    node_installed    INTEGER NOT NULL DEFAULT 0,
    -- `docker buildx version` answered when the module was installed.
    buildx            INTEGER NOT NULL DEFAULT 0,
    installed_at      INTEGER NOT NULL DEFAULT 0,
    -- Last `docker system df`, as JSON, and when it was read. It is slow, so
    -- it is cached rather than read on every tick.
    disk_json         TEXT    NOT NULL DEFAULT '',
    disk_at           INTEGER NOT NULL DEFAULT 0
);
INSERT INTO docker_module (id) VALUES (1);

-- Master only: which nodes reported the module installed, and whether a
-- silent one has been alerted about.
CREATE TABLE docker_nodes (
    node_id      TEXT    PRIMARY KEY,
    installed_at INTEGER NOT NULL DEFAULT 0,
    silent_since INTEGER NOT NULL DEFAULT 0,
    alert_state  TEXT    NOT NULL DEFAULT 'ok'
);

-- One row per compose project this node has seen.
CREATE TABLE docker_projects (
    project       TEXT    PRIMARY KEY,
    last_seen_at  INTEGER NOT NULL DEFAULT 0,
    -- When the project's containers all disappeared (0 while present).
    gone_since    INTEGER NOT NULL DEFAULT 0,
    -- When it started having a problem (0 while healthy).
    problem_since INTEGER NOT NULL DEFAULT 0,
    alert_state   TEXT    NOT NULL DEFAULT 'ok',
    last_summary  TEXT    NOT NULL DEFAULT ''
);

-- Restart counting per compose service, to tell a crash loop from one restart.
CREATE TABLE docker_container_watch (
    project             TEXT    NOT NULL,
    service             TEXT    NOT NULL,
    restart_count       INTEGER NOT NULL DEFAULT 0,
    restart_window_json TEXT    NOT NULL DEFAULT '[]',
    PRIMARY KEY (project, service)
);

-- Whether a running image's tag has moved on at its registry. Digests only;
-- Hyperion never holds registry credentials.
CREATE TABLE docker_image_checks (
    image_ref       TEXT    PRIMARY KEY,
    local_digest    TEXT    NOT NULL DEFAULT '',
    remote_digest   TEXT    NOT NULL DEFAULT '',
    state           TEXT    NOT NULL DEFAULT 'unknown',
    checked_at      INTEGER NOT NULL DEFAULT 0,
    -- The remote digest we already told the operator about.
    notified_digest TEXT    NOT NULL DEFAULT '',
    -- Do not ask the registry again before this.
    retry_after     INTEGER NOT NULL DEFAULT 0
);
