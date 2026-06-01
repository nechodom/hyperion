-- Enrolled nodes — populated when a node consumes its invite token
-- via the master's /api/enroll endpoint.
CREATE TABLE nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT NOT NULL UNIQUE,
    label           TEXT NOT NULL,
    master_url      TEXT,
    enrolled_at     INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    agent_version   TEXT NOT NULL DEFAULT '',
    public_ip       TEXT,
    enrolled_via    TEXT NOT NULL              -- token hash that was consumed
);
CREATE INDEX nodes_enrolled_at ON nodes(enrolled_at);
