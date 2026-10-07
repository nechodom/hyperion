-- Notification centre rework.
--
-- 1. Worker alerts reach the bell. A worker has no web users, so every
--    alert its own ticks raised (a broken page, a failed certificate, a
--    read-only filesystem) was fanned out to nobody and dropped. A worker
--    now parks them in `notification_outbox`; the master's panel pulls the
--    outbox and fans each row out to its own admins.
-- 2. `node_id` says which node raised a row ('' = the master itself), and
--    `origin_id` is the outbox row it came from, so a pull that runs twice
--    (panel restart, lost reply) never shows the same alert twice.

ALTER TABLE notifications ADD COLUMN node_id TEXT NOT NULL DEFAULT '';
ALTER TABLE notifications ADD COLUMN origin_id INTEGER;

CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_origin
    ON notifications (user_id, node_id, origin_id)
    WHERE origin_id IS NOT NULL;
-- The retention prune deletes by age alone; without this it scans the table.
CREATE INDEX IF NOT EXISTS idx_notifications_created
    ON notifications (created_at);

-- NODE-LOCAL on a worker: alerts waiting for the master to collect them.
-- Rows are not deleted on collection (the master's cursor moves instead),
-- only by the same age-based prune as the notifications themselves.
CREATE TABLE IF NOT EXISTS notification_outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    severity   TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL DEFAULT '',
    href       TEXT    NOT NULL DEFAULT '/',
    kind       TEXT    NOT NULL DEFAULT 'system',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notification_outbox_created
    ON notification_outbox (created_at);
