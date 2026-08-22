-- Bot families this hosting refuses, comma-separated: any of
-- 'ai', 'social', 'seo', 'shopping'. Empty = block nothing, which is the
-- behaviour every existing row had before this column existed.
--
-- A TEXT of family NAMES rather than a set of booleans or a free-text
-- user-agent pattern. Booleans would need a migration per family added;
-- free text would let an operator paste a loose regex into the vhost, where
-- a careless one blocks real visitors. The renderer maps these names to the
-- actual user-agent tokens, so the patterns live in exactly one place.
ALTER TABLE hostings ADD COLUMN blocked_bots TEXT NOT NULL DEFAULT '';
