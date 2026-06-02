-- Hosting profiles — operator-defined templates of limits + expiry
-- policy + pricing + optional Slack webhook. "Apply profile" copies
-- the values onto a hosting and links the two so we can later show
-- "this hosting is on plan Pro".

CREATE TABLE hosting_profiles (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    name                    TEXT NOT NULL UNIQUE,
    description             TEXT NOT NULL DEFAULT '',

    -- HostingLimits mirror (kept inline rather than a JSON blob so
    -- migrations + indexes work cleanly).
    php_memory_mb           INTEGER NOT NULL DEFAULT 256,
    php_max_exec_secs       INTEGER NOT NULL DEFAULT 60,
    php_max_children        INTEGER NOT NULL DEFAULT 10,
    php_max_requests        INTEGER NOT NULL DEFAULT 1000,
    db_max_connections      INTEGER NOT NULL DEFAULT 50,
    disk_hard_mb            INTEGER,
    bw_monthly_mb           INTEGER,

    -- HostingExpiry policy mirror.
    expiry_grace_days       INTEGER NOT NULL DEFAULT 30,
    expiry_warning_offsets  TEXT NOT NULL DEFAULT '30,7,1',

    -- Pricing (optional). Amount stored in MINOR units (e.g. haléře /
    -- cents) to dodge floating-point. Interval: 'monthly' | 'quarterly'
    -- | 'yearly'. Currency: ISO-4217 letters (CZK / EUR / USD).
    price_minor             INTEGER,
    price_currency          TEXT,
    price_interval          TEXT,

    -- Optional Slack incoming webhook. Per-profile so a "Pro" customer
    -- can have a dedicated channel.
    slack_webhook           TEXT,

    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL
);

-- One row per hosting, recording the applied profile + per-hosting
-- billing overrides. Profile rows are reference-only (cascade on
-- profile delete sets profile_id NULL so the hosting still keeps the
-- price it was applied with).
CREATE TABLE hosting_profile_apply (
    hosting_id              TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    profile_id              INTEGER REFERENCES hosting_profiles(id) ON DELETE SET NULL,
    -- Snapshot of the price at apply time. Per-hosting override OK.
    price_minor             INTEGER,
    price_currency          TEXT,
    price_interval          TEXT,
    next_billing_at         INTEGER,
    applied_at              INTEGER NOT NULL
);

CREATE INDEX hosting_profile_apply_next_billing
    ON hosting_profile_apply(next_billing_at);
