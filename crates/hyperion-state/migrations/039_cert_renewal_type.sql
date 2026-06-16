-- Operator-uploaded certificates (private CA, pre-purchased multi-year
-- certs, self-signed bootstrap) need two things the old schema couldn't
-- express:
--
--   1. A free-form issuer. The old `issuer IN ('letsencrypt','self-signed')`
--      CHECK can't hold a real CA's name (e.g. "DigiCert Inc"), and forcing
--      it to 'letsencrypt' would make the ACME renewal sweep try to renew —
--      and overwrite — a manually-installed cert. The CHECK is dropped;
--      issuer is now the cert's actual issuer string.
--
--   2. A `renewal_type` marking whether the ACME sweep may touch the cert.
--      Uploaded certs are 'manual' and are skipped in `cert_renew_tick`, so
--      an operator's cert is never clobbered by an automatic HTTP-01/DNS-01
--      renewal. ACME-issued certs stay 'auto'.
--
-- SQLite can't ALTER a CHECK constraint in place, so the table is rebuilt.
-- Nothing references `certificates` by foreign key, so no FK dance is
-- needed. `is_wildcard` (migration 038) is preserved.

CREATE TABLE certificates_new (
    id           INTEGER PRIMARY KEY,
    domain       TEXT NOT NULL UNIQUE,
    issued_at    INTEGER NOT NULL,
    not_after    INTEGER NOT NULL,
    cert_path    TEXT NOT NULL,
    key_path     TEXT NOT NULL,
    issuer       TEXT NOT NULL,
    is_wildcard  INTEGER NOT NULL DEFAULT 0,
    renewal_type TEXT NOT NULL DEFAULT 'auto' CHECK (renewal_type IN ('auto','manual'))
);

INSERT INTO certificates_new
    (id, domain, issued_at, not_after, cert_path, key_path, issuer, is_wildcard, renewal_type)
SELECT
    id, domain, issued_at, not_after, cert_path, key_path, issuer, is_wildcard, 'auto'
FROM certificates;

DROP TABLE certificates;
ALTER TABLE certificates_new RENAME TO certificates;
CREATE INDEX certificates_not_after ON certificates(not_after);
