-- Kernel OOM-kill events scraped from the journal. When the kernel OOM-kills a
-- worker the site 500s for a moment but RAM% may look recovered seconds later,
-- so these are invisible without a record. The agent appends new ones each
-- sample tick; the panel shows a 24h count + the latest.
CREATE TABLE oom_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,            -- unix seconds (from the journal entry)
    comm      TEXT    NOT NULL DEFAULT '', -- killed process name, e.g. "php-fpm8.3"
    pid       INTEGER NOT NULL DEFAULT 0,
    detail    TEXT    NOT NULL DEFAULT ''  -- trimmed journal message
);
CREATE INDEX oom_events_at ON oom_events(at DESC);
