-- 001_initial.sql
-- Foundation schema for hyperion-agent SQLite state.

CREATE TABLE system_users (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    uid          INTEGER NOT NULL UNIQUE,
    home_dir     TEXT NOT NULL,
    shell        TEXT NOT NULL DEFAULT '/usr/sbin/nologin',
    created_at   INTEGER NOT NULL
);

CREATE TABLE hostings (
    id                TEXT PRIMARY KEY,
    domain            TEXT NOT NULL UNIQUE,
    state             TEXT NOT NULL CHECK (
        state IN ('provisioning','active','failed','deleting')
    ),
    system_user_id    INTEGER NOT NULL REFERENCES system_users(id),
    php_version       TEXT,
    root_dir          TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE INDEX hostings_state ON hostings(state);
CREATE INDEX hostings_system_user ON hostings(system_user_id);

CREATE TABLE hosting_aliases (
    hosting_id        TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    alias_domain      TEXT NOT NULL UNIQUE,
    PRIMARY KEY (hosting_id, alias_domain)
);

CREATE TABLE databases (
    id           INTEGER PRIMARY KEY,
    hosting_id   TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    engine       TEXT NOT NULL CHECK (engine IN ('mariadb','postgres')),
    db_name      TEXT NOT NULL,
    db_user      TEXT NOT NULL,
    secret_id    TEXT NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    UNIQUE (engine, db_name)
);
CREATE INDEX databases_hosting ON databases(hosting_id);

CREATE TABLE certificates (
    id           INTEGER PRIMARY KEY,
    domain       TEXT NOT NULL UNIQUE,
    issued_at    INTEGER NOT NULL,
    not_after    INTEGER NOT NULL,
    cert_path    TEXT NOT NULL,
    key_path     TEXT NOT NULL,
    issuer       TEXT NOT NULL CHECK (issuer IN ('letsencrypt','self-signed'))
);
CREATE INDEX certificates_not_after ON certificates(not_after);

CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    actor_uid    INTEGER NOT NULL,
    actor_label  TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT,
    payload_json TEXT NOT NULL,
    result       TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    row_hash     TEXT NOT NULL
);
CREATE INDEX audit_log_ts ON audit_log(ts);
CREATE INDEX audit_log_action ON audit_log(action);
