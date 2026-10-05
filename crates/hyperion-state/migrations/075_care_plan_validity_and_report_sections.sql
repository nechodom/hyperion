-- 075_care_plan_validity_and_report_sections.sql
--
-- Two things an operator needs to control on a care plan that were fixed:
--
--   1. WHEN a plan applies to a site. It was "the moment somebody clicked
--      Activate", which is wrong for a customer who started paying on the 1st
--      and was entered on the 5th, and for one who signed today for a plan that
--      starts next month.
--   2. WHICH SECTIONS of the care report the customer is sent. The letter had
--      eight sections and every plan sent all of them, including the ones the
--      plan does not sell.
--
-- Both are additive columns. Every existing row keeps meaning exactly what it
-- meant: NULL valid_from = activated_at, enforcement_started = 1 (it was
-- enforced at activation), report_omit = '' = every section is sent.

-- (2) The plan's choice. It is the sections LEFT OUT, comma separated, so that
-- empty = send everything and a section added to the product later is sent by
-- default. On BOTH tables: the activation is self-contained (it is read on the
-- node that owns the hosting, where `service_packages` is empty — see 057).
ALTER TABLE service_packages ADD COLUMN report_omit TEXT NOT NULL DEFAULT '';
ALTER TABLE hosting_packages ADD COLUMN report_omit TEXT NOT NULL DEFAULT '';

-- (1) The operator's start date for THIS activation, unix seconds. Per
-- activation and not per plan: the plan is a definition shared by every site
-- on it, the start date is a fact about one customer.
--   in the past   — the first report and the billing clock count from it;
--   in the future — nothing is enforced and no report is sent until then.
ALTER TABLE hosting_packages ADD COLUMN valid_from INTEGER;

-- 0 while an activation waits for its start. The features it forces are NOT
-- captured or applied until it starts: the "prior state" a cancel restores is
-- read at that moment, not weeks earlier when the form was submitted (a setting
-- changed in between would be restored over by a stale snapshot).
-- DEFAULT 1: every row that exists today was enforced when it was created.
ALTER TABLE hosting_packages ADD COLUMN enforcement_started INTEGER NOT NULL DEFAULT 1;
