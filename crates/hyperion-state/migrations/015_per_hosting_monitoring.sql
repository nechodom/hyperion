-- 015_per_hosting_monitoring.sql
--
-- Per-hosting HTTP availability monitoring. The agent's background
-- monitor_tick (one minute cadence) iterates active hostings with
-- `monitor_enabled = 1`, hits the configured path, and records a row
-- in `monitor_samples`. When `monitor_consecutive_fails` >=
-- `monitor_alert_after_fails`, an alert fires via configured
-- channels (email + slack + webhook, any combination).

ALTER TABLE hostings ADD COLUMN monitor_enabled INTEGER NOT NULL DEFAULT 0;
-- Path to probe, e.g. "/" or "/health". Fetched as
-- https://<domain><path>. NULL means use the default "/".
ALTER TABLE hostings ADD COLUMN monitor_url_path TEXT;
-- Probe interval in seconds. Clamped 60..=3600 at use time.
-- NULL = use default 300 (5 min).
ALTER TABLE hostings ADD COLUMN monitor_interval_secs INTEGER;
-- Fail-streak threshold before alerts fire. Default 3 = standard
-- SRE anti-flap.
ALTER TABLE hostings ADD COLUMN monitor_alert_after_fails INTEGER;
-- Optional alert channels. Comma-separated emails, raw Slack webhook
-- URL (incoming webhook), generic webhook URL. Any combination.
ALTER TABLE hostings ADD COLUMN monitor_alert_email TEXT;
ALTER TABLE hostings ADD COLUMN monitor_alert_slack_webhook TEXT;
ALTER TABLE hostings ADD COLUMN monitor_alert_webhook_url TEXT;
-- Running streak counter. Reset to 0 on every successful sample.
ALTER TABLE hostings ADD COLUMN monitor_consecutive_fails INTEGER NOT NULL DEFAULT 0;
-- Timestamp of the most recent alert dispatch, so we don't spam.
-- Alerts fire on threshold crossing; this prevents firing again until
-- a recovery happens.
ALTER TABLE hostings ADD COLUMN monitor_last_alert_at INTEGER;
-- Persisted alert state — "ok" | "alerting". Drives "Resolved" alerts
-- when transitioning back to ok.
ALTER TABLE hostings ADD COLUMN monitor_alert_state TEXT NOT NULL DEFAULT 'ok'
    CHECK (monitor_alert_state IN ('ok', 'alerting'));

-- Per-tick monitor samples. Index for sparkline queries + retention pruning.
CREATE TABLE monitor_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hosting_id      TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    sampled_at      INTEGER NOT NULL,
    success         INTEGER NOT NULL CHECK (success IN (0, 1)),
    http_status     INTEGER,
    response_ms     INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT
);
CREATE INDEX monitor_samples_hosting_time ON monitor_samples(hosting_id, sampled_at DESC);
CREATE INDEX monitor_samples_sampled ON monitor_samples(sampled_at);
