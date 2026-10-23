-- Unattended wildcard renewal via acme-dns style CNAME delegation. The
-- operator points `_acme-challenge.<base>` at `<label>.<zone>` once; the
-- master's built-in DNS responder then answers the TXT challenge itself.
-- These tables exist in every agent DB but are only used on the master.

-- Single row (id = 1): the delegated zone and the responder's identity.
CREATE TABLE acme_dns_config (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    zone         TEXT,
    ns_host      TEXT NOT NULL DEFAULT '',
    public_ipv4  TEXT,
    public_ipv6  TEXT,
    enabled      INTEGER NOT NULL DEFAULT 0,
    check_token  TEXT NOT NULL DEFAULT ''
);

-- One random label per delegated base domain. hosting_id NULL = preview base.
CREATE TABLE acme_dns_labels (
    base             TEXT PRIMARY KEY,
    label            TEXT NOT NULL UNIQUE,
    hosting_id       TEXT,
    created_at       INTEGER NOT NULL,
    verified_at      INTEGER,
    last_check_error TEXT
);

-- Live TXT values the responder serves (two at once for apex + wildcard).
CREATE TABLE acme_dns_values (
    label      TEXT NOT NULL,
    value      TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX idx_acme_dns_values_label ON acme_dns_values(label);

ALTER TABLE certificates ADD COLUMN dns01_delegated INTEGER NOT NULL DEFAULT 0;
