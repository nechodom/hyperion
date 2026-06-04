-- 017_email_log.sql
-- Per-hosting email log so operators can audit "did we send the
-- backup-failure alert? what did SMTP say? when did the cert-renew
-- notification go out?" without grepping the cluster-wide audit_log.
--
-- hosting_id is NULL for cluster-wide notifications (billing
-- summaries, master-level alerts). Per-hosting rows cascade-delete
-- with the hosting itself — when an operator deletes a site, its
-- email history disappears too.
--
-- body_preview keeps only the first ~200 chars: enough for "DOWN:
-- example.cz returned 502 after 3 retries" context, not enough to
-- leak passwords / reset tokens / secrets that might appear later
-- in the body. The full body is never persisted by design.

CREATE TABLE email_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hosting_id    TEXT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    to_address    TEXT NOT NULL,
    subject       TEXT NOT NULL,
    body_preview  TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('ok','failed')),
    error         TEXT NULL,
    smtp_code     TEXT NULL,
    sent_at       INTEGER NOT NULL
);

CREATE INDEX email_log_hosting ON email_log(hosting_id);
CREATE INDEX email_log_sent_at ON email_log(sent_at);
