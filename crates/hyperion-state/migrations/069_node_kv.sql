-- Node-level key/value state: `hosting_kv`'s counterpart for facts about THIS
-- machine rather than about one site on it.
--
-- Added for OS update tracking, which needs to remember one thing across agent
-- restarts: WHEN security updates were first seen pending. An in-memory stamp
-- resets every time the agent restarts, and the agent restarts on every
-- hyperion update — so on an install that updates hyperion more often than the
-- alert threshold, a security update could lie unapplied indefinitely while
-- the "pending for N days" clock kept starting over.
--
-- The value is an opaque string; the feature that owns a key owns its encoding.
CREATE TABLE IF NOT EXISTS node_kv (
    key        TEXT PRIMARY KEY NOT NULL,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
