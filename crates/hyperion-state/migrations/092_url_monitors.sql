-- URL checks run from the master (the Kuma replacement of the Docker module).
--
-- Master only; empty everywhere else. Removing the module for the cluster
-- deletes both tables' rows, history included.

CREATE TABLE url_monitors (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    url                 TEXT    NOT NULL,
    interval_secs       INTEGER NOT NULL DEFAULT 60,
    -- NULL: any answer probe_http calls healthy. Set: exactly this status.
    expected_status     INTEGER,
    alert_after_fails   INTEGER NOT NULL DEFAULT 3,
    alert_email         TEXT,
    -- Both webhooks are bearer credentials: never sent back to a browser.
    alert_slack_webhook TEXT,
    alert_webhook_url   TEXT,
    -- The node the URL's hostname lives on (`local` for the master); NULL
    -- when no hosting matched. `node_manual` = the operator picked it.
    node_id             TEXT,
    node_manual         INTEGER NOT NULL DEFAULT 0,
    alert_state         TEXT    NOT NULL DEFAULT 'ok',
    last_alert_at       INTEGER,
    -- `down` or `up`: decided, not yet handed to the alert sender. Kept
    -- until the web layer acknowledges it, so a restart loses no alert.
    pending_alert       TEXT,
    pending_error       TEXT,
    last_sampled_at     INTEGER NOT NULL DEFAULT 0,
    cert_expires_at     INTEGER,
    cert_checked_at     INTEGER NOT NULL DEFAULT 0,
    -- The threshold (14 or 3 days) last warned about.
    cert_alert_day      INTEGER,
    created_at          INTEGER NOT NULL
);

CREATE TABLE url_monitor_samples (
    monitor_id    INTEGER NOT NULL,
    sampled_at    INTEGER NOT NULL,
    success       INTEGER NOT NULL,
    http_status   INTEGER,
    response_ms   INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);
CREATE INDEX idx_url_monitor_samples_monitor ON url_monitor_samples (monitor_id, sampled_at);
CREATE INDEX idx_url_monitor_samples_at ON url_monitor_samples (sampled_at);
