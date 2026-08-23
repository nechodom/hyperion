-- ISO-3166-1 alpha-2 codes this hosting refuses, comma-separated and
-- uppercase (e.g. 'RU,CN'). Empty = block nothing, which is what every
-- existing row did before this column existed.
--
-- Codes rather than a free-text nginx condition: the vhost turns these into
-- a match against $hyperion_country, and letting an operator write that
-- expression directly would put an unvalidated regex in front of every
-- request on the site.
ALTER TABLE hostings ADD COLUMN blocked_countries TEXT NOT NULL DEFAULT '';
