-- Email change with verification.
--
-- When a user requests an email change, the new address is stashed
-- here along with a hashed 6-digit code + expiry. The current
-- `email` column doesn't move until the user confirms by entering
-- the code that was sent to the NEW address (proof of ownership).
--
-- Cleared by the confirm handler on success, or by an explicit
-- cancel POST, or implicitly when the row is overwritten by a
-- second request.
--
-- attempts caps brute-force — 5 wrong codes invalidates the
-- request entirely (operator must request again).

ALTER TABLE web_users ADD COLUMN pending_email TEXT;
ALTER TABLE web_users ADD COLUMN pending_email_code_hash TEXT;
ALTER TABLE web_users ADD COLUMN pending_email_expires_at INTEGER;
ALTER TABLE web_users ADD COLUMN pending_email_attempts INTEGER NOT NULL DEFAULT 0;
