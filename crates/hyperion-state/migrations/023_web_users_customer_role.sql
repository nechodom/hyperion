-- Add the "customer" role to web_users.
--
-- The CHECK constraint in migration 013 hardcoded the four original
-- roles. SQLite has no `ALTER TABLE … DROP CONSTRAINT` so we rebuild
-- the table with the new constraint set. Same column shape; only the
-- CHECK changes. Indexes get recreated at the end.
--
-- Role semantics:
--   super_admin: god-mode + manages users
--   admin:       sees everything, can't manage users
--   operator:    internal staff — manages a subset of hostings via
--                web_user_hosting_access grants
--   customer:    end-user / tenant — same access model as operator
--                (per-hosting grants) but the UI shows a slimmer nav
--                (no Stats/Profiles/Services/Install/Settings) and
--                clearer "Your hostings" framing
--   viewer:      read-only across granted hostings

CREATE TABLE web_users_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (
        role IN ('super_admin','admin','operator','customer','viewer')
    ),
    totp_secret_base32 TEXT,
    totp_enrolled_at   INTEGER,
    totp_required      INTEGER NOT NULL DEFAULT 0,
    locked          INTEGER NOT NULL DEFAULT 0,
    locked_reason   TEXT,
    last_login_at   INTEGER,
    last_login_ip   TEXT,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    failed_locked_at INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

INSERT INTO web_users_new (
    id, username, email, password_hash, role,
    totp_secret_base32, totp_enrolled_at, totp_required,
    locked, locked_reason, last_login_at, last_login_ip,
    failed_logins, failed_locked_at, created_at, updated_at
)
SELECT
    id, username, email, password_hash, role,
    totp_secret_base32, totp_enrolled_at, totp_required,
    locked, locked_reason, last_login_at, last_login_ip,
    failed_logins, failed_locked_at, created_at, updated_at
FROM web_users;

DROP TABLE web_users;
ALTER TABLE web_users_new RENAME TO web_users;

CREATE INDEX web_users_username ON web_users(username);
CREATE INDEX web_users_role     ON web_users(role);
