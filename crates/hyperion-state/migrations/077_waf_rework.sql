-- WAF rework: a level + per-rule overrides instead of one bool, and the
-- node-local tables the hit-log ingest fills.
--
-- `waf_enabled` stays and is kept equal to `waf_level != 'off'`, so an older
-- master or node reading the bool still sees a sensible value.
ALTER TABLE hostings ADD COLUMN waf_level TEXT NOT NULL DEFAULT 'off';
-- JSON object of rule id -> bool, e.g. {"xmlrpc":false}. Empty = none.
ALTER TABLE hostings ADD COLUMN waf_overrides TEXT NOT NULL DEFAULT '';
-- The old switch applied exactly what the Standard level applies now.
UPDATE hostings SET waf_level = 'standard' WHERE waf_enabled = 1;

-- Refusals per hosting, rule and UTC hour. Upserted by the ingest; kept 30
-- days. NODE-LOCAL: each node records only the hostings it serves.
CREATE TABLE waf_hits_hourly (
    hosting_id TEXT    NOT NULL,
    hour       INTEGER NOT NULL,
    rule       TEXT    NOT NULL,
    hits       INTEGER NOT NULL,
    PRIMARY KEY (hosting_id, hour, rule)
);
-- The retention prune runs every tick; without this it scans the table.
CREATE INDEX idx_waf_hits_hourly_hour ON waf_hits_hourly (hour);

-- The last refusals per hosting (capped by the ingest), for the panel.
-- uri / ua are attacker-controlled and stored truncated.
CREATE TABLE waf_recent (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    hosting_id TEXT    NOT NULL,
    ts         INTEGER NOT NULL,
    ip         TEXT    NOT NULL,
    rule       TEXT    NOT NULL,
    method     TEXT    NOT NULL,
    uri        TEXT    NOT NULL,
    ua         TEXT    NOT NULL
);
CREATE INDEX idx_waf_recent_hosting ON waf_recent (hosting_id, id);

-- Ban-counted hits per caller and minute: what the auto-ban threshold is
-- measured against. Short-lived; pruned to a day.
CREATE TABLE waf_ip_minute (
    hosting_id TEXT    NOT NULL,
    ip         TEXT    NOT NULL,
    minute     INTEGER NOT NULL,
    hits       INTEGER NOT NULL,
    PRIMARY KEY (hosting_id, ip, minute)
);
CREATE INDEX idx_waf_ip_minute_minute ON waf_ip_minute (minute);
