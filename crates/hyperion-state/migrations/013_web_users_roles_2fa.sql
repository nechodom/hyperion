-- 013_web_users_roles_2fa.sql
--
-- Multi-user admin with roles, per-web access, TOTP 2FA, invites, and
-- password resets. The single bootstrap admin from
-- /etc/hyperion/web-admin.json is migrated into `web_users` as the
-- first super_admin on agent startup if the table is empty (handled
-- by the agent's startup self-heal, not this migration).
--
-- Role semantics:
--   super_admin — full access incl. user management + invites
--   admin      — full access EXCEPT user management
--   operator   — manage hostings, but only those listed in
--                web_user_hosting_access
--   viewer     — read-only, only hostings in web_user_hosting_access

CREATE TABLE web_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL,
    password_hash   TEXT NOT NULL,    -- argon2 PHC string
    role            TEXT NOT NULL CHECK (
        role IN ('super_admin','admin','operator','viewer')
    ),
    -- 2FA state. `secret` is base32-encoded; `enrolled_at` non-NULL
    -- means the user has confirmed enrollment (scanned QR + verified
    -- one code). Until then the secret may exist (pending enrollment)
    -- but 2FA is NOT required at login.
    totp_secret_base32 TEXT,
    totp_enrolled_at   INTEGER,
    -- True if the operator (or self) has flagged 2FA as required for
    -- THIS user. Login refuses if true and not yet enrolled.
    totp_required      INTEGER NOT NULL DEFAULT 0,
    -- Lockout. `locked_reason` is shown at the failed-login screen.
    locked          INTEGER NOT NULL DEFAULT 0,
    locked_reason   TEXT,
    -- Activity tracking.
    last_login_at   INTEGER,
    last_login_ip   TEXT,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    failed_locked_at INTEGER,         -- if locked due to too many failed attempts
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX web_users_username ON web_users(username);
CREATE INDEX web_users_role     ON web_users(role);

-- One backup code per row; one-time use. Hashed (blake3) so we never
-- store the plaintext. `used_at` flips when consumed.
CREATE TABLE web_user_backup_codes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,
    used_at         INTEGER,
    created_at      INTEGER NOT NULL,
    UNIQUE(user_id, code_hash)
);
CREATE INDEX web_user_backup_codes_user ON web_user_backup_codes(user_id);

-- Per-web access for `operator` + `viewer` roles. `super_admin` and
-- `admin` ignore this table — they see all hostings.
-- `level`:
--   read      — viewer-level (read-only)
--   manage    — operator-level (CRUD)
CREATE TABLE web_user_hosting_access (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    hosting_id      TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    level           TEXT NOT NULL CHECK (level IN ('read','manage')),
    granted_by      INTEGER REFERENCES web_users(id),
    granted_at      INTEGER NOT NULL,
    UNIQUE(user_id, hosting_id)
);
CREATE INDEX web_user_hosting_access_user ON web_user_hosting_access(user_id);
CREATE INDEX web_user_hosting_access_hosting ON web_user_hosting_access(hosting_id);

-- Pending invites: super_admin creates, recipient redeems within TTL.
-- The token is stored hashed; the plaintext is shown ONCE at creation.
CREATE TABLE web_invites (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (
        role IN ('super_admin','admin','operator','viewer')
    ),
    created_by      INTEGER REFERENCES web_users(id),
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    accepted_at     INTEGER,
    accepted_user_id INTEGER REFERENCES web_users(id)
);
CREATE INDEX web_invites_email ON web_invites(email);
CREATE INDEX web_invites_expires ON web_invites(expires_at);

-- Password reset tokens. Same shape as invites.
CREATE TABLE web_password_resets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT NOT NULL UNIQUE,
    user_id         INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    consumed_at     INTEGER
);
CREATE INDEX web_password_resets_user ON web_password_resets(user_id);
CREATE INDEX web_password_resets_expires ON web_password_resets(expires_at);
