-- The monthly service checklist, per care plan.
--
-- It was four items fixed in code. The reasoning at the time was that letting
-- an operator invent items PER SITE would give every site a different
-- definition of "checked", so "is this month done?" would have no answer across
-- the estate — and that reasoning still holds. Putting the list on the PLAN
-- keeps it: every site on "Péče Plus" shares one definition, and a dearer plan
-- can honestly promise more checks than a cheap one.
--
-- Stored as a JSON array of {id,label,detail}. Empty means "no opinion", and
-- the built-in four apply — which is what every existing package means.
ALTER TABLE service_packages ADD COLUMN check_items TEXT NOT NULL DEFAULT '';

-- SNAPSHOTTED onto the activation, like the price, the bundle and the letter
-- language before it. The checklist is ticked and rendered on the node that
-- OWNS the hosting, where `service_packages` is empty; resolving through
-- package_id there would silently fall back to the built-in four on every
-- worker while the master showed the operator's own list.
ALTER TABLE hosting_packages ADD COLUMN check_items TEXT NOT NULL DEFAULT '';
