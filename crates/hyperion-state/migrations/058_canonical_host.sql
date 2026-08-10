-- Canonical-host redirect (www vs non-www), one of '' | 'www' | 'non-www'.
-- A TEXT with named values, not a boolean: the operator's actual decision
-- is WHICH spelling is canonical, and a bool cannot carry direction.
-- Lives on hostings like the other vhost options (see 020/036).
ALTER TABLE hostings ADD COLUMN canonical_host TEXT NOT NULL DEFAULT '';
