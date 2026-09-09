-- Which language a CUSTOMER's letters are written in, per site.
--
-- Until now `[letters] lang` was one setting for the whole cluster, so an
-- operator with both Czech and foreign customers had to pick which half got
-- letters they could read. The language now resolves per hosting:
--
--   1. the site's own setting            (hosting_kv, key 'letters.lang')
--   2. its care package's default        (the snapshot below)
--   3. the cluster's [letters] lang      (unchanged)
--
-- OPERATOR alerts — Slack, the mail to every admin address — deliberately do
-- NOT follow this. They are read by the operator, not the customer, and one
-- inbox holding messages in whichever language each site happens to be set to
-- is worse than one language throughout.

-- On the DEFINITION, which lives on the master only.
-- Empty means "no opinion", so the cluster setting decides.
ALTER TABLE service_packages ADD COLUMN letters_lang TEXT NOT NULL DEFAULT '';

-- SNAPSHOTTED onto the activation, exactly like package_name and the price
-- already are, and for the same reason: definitions are master-only, but the
-- letter is rendered on the node that OWNS the hosting, where `service_packages`
-- is empty. Reading the definition from there would silently fall back to the
-- cluster language on every worker — the letters would be right on the master
-- and wrong everywhere else, which is the hardest kind of wrong to notice.
ALTER TABLE hosting_packages ADD COLUMN letters_lang TEXT NOT NULL DEFAULT '';
