-- In-app notification feed for the bell icon in the topbar.
--
-- Notifications are emitted by various subsystems (cert renewal,
-- monitor alert, backup failure, suspend reason, system service
-- down) and persisted here so the operator can see what happened
-- even hours after the event.
--
-- Each notification is per-user — when emitted, it gets fan-out
-- to every user with the relevant role (super_admin/admin see
-- everything; operator sees only hostings they have access to;
-- viewer doesn't receive notifications since they can't act).
--
-- read_at NULL = unread. The bell badge counts unread per user.
--
-- Indexes:
--   - (user_id, read_at) for the bell dropdown query: latest unread
--   - (user_id, created_at) for "show all" pagination

CREATE TABLE IF NOT EXISTS notifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    -- Severity drives the dot colour in the dropdown. Loose set,
    -- not enforced — sub-systems can add new severities without a
    -- migration. Common values: "info" | "warn" | "error".
    severity      TEXT    NOT NULL DEFAULT 'info',
    -- Short noun phrase, ~50 chars: "Backup failed", "Cert renewed",
    -- "Hosting suspended".
    title         TEXT    NOT NULL,
    -- One-line body, ~120 chars. May reference a hosting domain,
    -- node id, error tail, etc.
    body          TEXT    NOT NULL DEFAULT '',
    -- Where the bell-item links to when clicked. Internal route only.
    href          TEXT    NOT NULL DEFAULT '/',
    -- Free-form kind for filtering / dedup in future ("cert.renewed",
    -- "monitor.down", etc.). Not enforced at DB level.
    kind          TEXT    NOT NULL DEFAULT 'system',
    created_at    INTEGER NOT NULL,
    -- NULL = unread.
    read_at       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_unread
    ON notifications (user_id, read_at);
CREATE INDEX IF NOT EXISTS idx_notifications_user_recent
    ON notifications (user_id, created_at DESC);
