-- 003_expiration.sql
-- Per-hosting expiry + scheduled actions queue.

-- We extend `hostings` rather than introducing a separate
-- `controller_hostings` overlay table since the agent is single-node here.
ALTER TABLE hostings ADD COLUMN expires_at INTEGER;
ALTER TABLE hostings ADD COLUMN owner_email TEXT;
ALTER TABLE hostings ADD COLUMN grace_days INTEGER NOT NULL DEFAULT 30;
ALTER TABLE hostings ADD COLUMN warning_offsets_days TEXT NOT NULL DEFAULT '30,7,1';
CREATE INDEX hostings_expires_at ON hostings(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE scheduled_actions (
    id           INTEGER PRIMARY KEY,
    hosting_id   TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    action       TEXT NOT NULL CHECK (action IN (
                    'notify_30d','notify_7d','notify_1d',
                    'suspend_expired','delete_expired'
                 )),
    due_at       INTEGER NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('pending','running','done','failed','canceled')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_attempt_at INTEGER,
    last_error   TEXT,
    created_at   INTEGER NOT NULL,
    UNIQUE (hosting_id, action, due_at)
);
CREATE INDEX scheduled_actions_due ON scheduled_actions(state, due_at);
CREATE INDEX scheduled_actions_hosting ON scheduled_actions(hosting_id);
