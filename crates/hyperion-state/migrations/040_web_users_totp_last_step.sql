-- TOTP replay protection (RFC 6238 §5.2): the absolute time-step
-- (unix_seconds / 30) of the last TOTP code accepted for this user. A login
-- is refused when the matched code's step is <= this value, so a captured
-- code can't be reused within its ~90s (±1 step) validity window.
-- NULL = no TOTP code accepted yet.
ALTER TABLE web_users ADD COLUMN totp_last_step INTEGER;
