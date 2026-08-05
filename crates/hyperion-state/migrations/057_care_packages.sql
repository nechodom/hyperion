-- 057_care_packages.sql
--
-- Care packages ("balíček péče") — the ENTITLEMENT layer over features
-- hyperion already has.
--
-- The operator sells managed WordPress updates, integrity scanning,
-- uptime monitoring, hardening and scheduled backups as a paid add-on.
-- Every one of those already works today; what was missing is a record
-- that the customer PAID for them, and something that keeps them switched
-- on. That is all a package is: a named bundle of feature intents, plus
-- the rows saying which hosting holds which bundle.
--
-- Explicitly NOT a billing system. No invoices, no payments, no ledger.
-- `next_billing_at` means exactly what it means in
-- `hosting_profile_apply`: the date the existing billing sweep sends a
-- REMINDER before. Nothing here charges anyone.
--
-- Why not reuse `hosting_profiles`? Two structural reasons:
--   * `hosting_profile_apply` has hosting_id as its PRIMARY KEY, so a
--     hosting carries exactly ONE profile. Packages must stack — a
--     "Backup" package next to a "Monitoring" package — so an activation
--     here is its own row and a hosting can hold several.
--   * a profile is a SNAPSHOT copied onto the site at apply time and then
--     forgotten. A package is a live binding: the drift tick re-asserts
--     it, so a paid feature switched off by hand comes back.
--
-- Ignorable by design: define no packages and nothing about the panel
-- changes.

-- The DEFINITION an admin creates and sells.
CREATE TABLE service_packages (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL UNIQUE,
    -- URL/API handle derived from the name ("pece-plus"). UNIQUE so
    -- `/api/v1` can address a package by a stable human-readable key;
    -- the web layer must de-duplicate slugs it generates from names that
    -- differ only in case/diacritics.
    slug                TEXT NOT NULL UNIQUE,
    -- Customer-facing text: what the customer is buying, not an operator
    -- note.
    description         TEXT NOT NULL DEFAULT '',
    -- 0 hides the package from the "activate" picker WITHOUT touching
    -- existing activations. Retiring a package must not mean deleting it,
    -- because a delete costs every activation its live feature bundle
    -- (see the FK below).
    enabled             INTEGER NOT NULL DEFAULT 1,

    -- Pricing — same shape and semantics as hosting_profiles: amount in
    -- MINOR units (haléře / cents) to dodge floating-point, currency in
    -- ISO-4217 letters, interval 'monthly' | 'quarterly' | 'yearly'.
    -- Display + reminder cadence only.
    price_minor         INTEGER,
    price_currency      TEXT,
    price_interval      TEXT,

    -- THE FEATURE BUNDLE. Every feature is TRI-STATE, not a boolean:
    --   'on'    force it on and KEEP it on
    --   'off'   force it off and keep it off
    --   'leave' this package has no opinion about this feature
    -- 'leave' is the default and is what makes packages composable: two
    -- packages on the same hosting only collide on features they BOTH
    -- speak about. Columns rather than a JSON blob, for the same reason
    -- hosting_profiles keeps its limits inline (migrations + indexes).
    feat_wp_auto_update TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_wp_auto_update IN ('leave','on','off')),
    feat_integrity_scan TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_integrity_scan IN ('leave','on','off')),
    feat_monitoring     TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_monitoring IN ('leave','on','off')),
    -- WAF-lite + wp-admin lock.
    feat_hardening      TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_hardening IN ('leave','on','off')),
    -- Backups are not a boolean: 'leave' or one of the four cadences the
    -- per-node scheduled-backup driver understands (hosting_kv key
    -- `backup_cadence`). 'off' here is a real instruction ("this package
    -- pins backups off"), distinct from 'leave'.
    feat_backup_cadence TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_backup_cadence IN ('leave','off','daily','weekly','monthly')),
    -- How often the customer gets the CARE REPORT — the periodic e-mail
    -- listing what the package actually did (attacks blocked, updates
    -- applied, backups taken, uptime). Same shape as the backup cadence
    -- and for the same reason: not a boolean, and 'off' ("this package
    -- pins reports off") is a real instruction distinct from 'leave'.
    -- The only feature in this bundle the CUSTOMER ever sees; the rest
    -- are invisible when they work, which is what the report exists to
    -- fix. No 'daily': a daily mail about a quiet site trains people to
    -- filter it, and a report nobody opens justifies no invoice.
    feat_report_cadence TEXT NOT NULL DEFAULT 'leave'
        CHECK (feat_report_cadence IN ('leave','off','weekly','monthly','quarterly')),

    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

-- An ACTIVATION: this hosting holds this package. MANY rows per hosting —
-- deliberately NOT keyed on hosting_id, which is exactly what stops
-- hosting_profile_apply from stacking.
CREATE TABLE hosting_packages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hosting_id       TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    -- A PLAIN reference, deliberately NOT a foreign key. Definitions are
    -- master-only, but an activation is written and enforced on the node
    -- that OWNS the hosting — where `service_packages` is empty. An FK here
    -- would make every activation on a worker fail outright, and resolving
    -- the bundle through it would make the drift tick a silent no-op there.
    -- Kept only to link back to the definition for display/history on the
    -- master; nothing load-bearing may read through it.
    package_id       INTEGER,
    -- Name SNAPSHOT, so an orphaned or renamed activation still says what
    -- the customer bought.
    package_name     TEXT NOT NULL DEFAULT '',

    -- Price SNAPSHOT taken at activation. The definition is free to be
    -- re-priced or deleted afterwards; what an existing customer agreed to
    -- never gets rewritten underneath them. Per-activation override OK.
    price_minor      INTEGER,
    price_currency   TEXT,
    price_interval   TEXT,

    -- FEATURE SNAPSHOT — the bundle as it stood at activation, for exactly
    -- the same reason the price is snapshotted: it is what the customer
    -- bought. This is what the drift tick enforces and what a cancel
    -- reasons about, so an activation is entirely SELF-CONTAINED:
    --   * it works on a worker node, which has no `service_packages` row;
    --   * editing a definition can no longer desynchronise what is enforced
    --     from what a cancel restores;
    --   * deleting a definition leaves the activation still enforceable
    --     (and still cancellable) instead of billable-but-inert.
    -- Re-pricing or re-scoping a package therefore only affects activations
    -- made AFTER the edit — same contract as the price.
    feat_wp_auto_update  TEXT NOT NULL DEFAULT 'leave',
    feat_integrity_scan  TEXT NOT NULL DEFAULT 'leave',
    feat_monitoring      TEXT NOT NULL DEFAULT 'leave',
    feat_hardening       TEXT NOT NULL DEFAULT 'leave',
    feat_backup_cadence  TEXT NOT NULL DEFAULT 'leave',
    -- Deliberately un-CHECKed, like the four above: a worker node may hold
    -- an activation written by a master that already knows a cadence this
    -- node's build does not. A value we cannot parse degrades to 'leave'
    -- in Rust (the package stops having an opinion), which is a far better
    -- failure than an INSERT the node rejects outright.
    feat_report_cadence  TEXT NOT NULL DEFAULT 'leave',
    -- Reminder clock, same contract as hosting_profile_apply: the sweep
    -- advances it after firing so a due package doesn't re-notify forever.
    next_billing_at  INTEGER,

    -- 'active'   = enforced by the drift tick and carrying a billing clock
    -- 'cancelled'= history; prior state already restored, never enforced
    -- Two states on purpose — anything richer (past-due, suspended) is
    -- billing-system machinery this feature does not have.
    state            TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active','cancelled')),
    activated_at     INTEGER NOT NULL,
    cancelled_at     INTEGER,

    -- What each feature this package FORCES was set to immediately BEFORE
    -- the activation touched it, so a cancel restores exactly that and
    -- nothing else. JSON object:
    --
    --   {"v":1,
    --    "wp_auto_update": true,
    --    "monitoring": false,
    --    "backup_cadence": "weekly"}
    --
    -- A key is present ONLY when the package forces that feature; an
    -- absent key means "the package left this alone" and deactivation must
    -- leave it alone too. The four boolean features carry their prior
    -- on/off; `backup_cadence` carries the prior cadence string
    -- ('off'|'daily'|'weekly'|'monthly'). `v` is the shape version.
    --
    -- Without this, cancelling would have to pick between two wrong
    -- answers: leave paid features switched on forever, or blindly switch
    -- off a feature the customer had enabled themselves before they ever
    -- bought a package.
    --
    -- It lives on the ACTIVATION, not the definition, so a cancel still
    -- restores correctly after the definition was edited or deleted. NULL
    -- (or an unparseable value) is read as "restore nothing".
    prior_state_json TEXT
);

-- The per-hosting card + the drift tick both read "packages of this site".
CREATE INDEX hosting_packages_hosting ON hosting_packages(hosting_id, state);
-- The billing sweep scans by due date; cancelled rows have it NULLed.
CREATE INDEX hosting_packages_next_billing
    ON hosting_packages(next_billing_at) WHERE next_billing_at IS NOT NULL;
-- A hosting may hold many packages but not the SAME one twice: a double
-- activation would take a second "prior state" reading of the state the
-- first activation had already forced, and cancelling would then restore
-- the package's own values as if they were the customer's. Partial, so
-- the cancelled history of a package doesn't block re-activating it.
CREATE UNIQUE INDEX hosting_packages_one_active
    ON hosting_packages(hosting_id, package_id) WHERE state = 'active';
