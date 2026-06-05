-- Avatar / profile picture for web_users.
--
-- Stored on disk under `/var/lib/hyperion/avatars/<user_id>.<ext>`
-- (PNG / JPG / WEBP). The DB column carries the basename so the
-- web layer can serve it via /avatar/<user_id> with a cheap
-- existence check + content-type lookup.
--
-- NULL = no avatar uploaded yet → UI falls back to the initial-
-- letter pill.

ALTER TABLE web_users ADD COLUMN avatar_filename TEXT;
