# Care plan: start date and report sections

Two things an operator could not control on a care plan.

1. **When a plan applies to a site.** It was "the moment somebody clicked Activate".
2. **Which sections of the customer's care report are sent.** The letter has eight
   sections and every plan sent all of them.

Both are additive; every existing row keeps its meaning (migration 075).

## 1. Report sections (on the plan)

- `report_omit` on `service_packages` **and** `hosting_packages` — a comma list of the
  sections the plan **leaves out**. Empty = send everything, so an upgrade changes no
  letter, and a section added to the product later is sent by default.
- Sections (`hyperion_types::report_sections::ReportSection`): `attacks`, `updates`,
  `traffic`, `uptime`, `backups`, `integrity`, `performance`, `service` — the same names
  as the letter's `{placeholders}`.
- Snapshotted onto each activation (the letter is rendered on the node that owns the
  hosting, where `service_packages` is empty) and re-pushed on a plan edit through
  `package_relist`, exactly like `check_items`.
- A plan must send at least one section; to send no report, set the cadence to off.
- Two plans on one site send the **union** (a section is left out only when every
  report-selling plan leaves it out). A plan that sells no report has no say.
- Rendering (`care_report_render_*_omitting`): a left-out section renders as the empty
  string, its bare values (`{attacks_count}`, `{uptime_pct}` …) as `—`, blank-line runs
  are collapsed, and it is **never** reported as "not measured" — the customer did not
  buy it. `CareReport::is_entirely_unmeasured_for(omit)` counts only the sent sections.
- Web: a checkbox group in the plan editor. A hidden `report_sections_form` marker tells
  the server the group was in the form at all, because an unticked box is absent from a
  POST (an older cached form must leave the stored choice alone).

## 2. Start date (on the activation)

- `valid_from` (NULL = `activated_at`) and `enforcement_started` (default 1) on
  `hosting_packages`. A date, not a plan property: the plan is shared by every site on
  it, the start date is a fact about one customer. UTC midnight, 2015-01-01 … +366 days.
- **In the past:** in force at once. The first care report and the billing clock count
  from it (`next_billing_at = advance_billing_date(valid_from, interval, now)`). A report
  already sent is history — the period marker still wins, periods stay contiguous.
- **In the future:** recorded, shown and billed from its date, but not in force —
  `enforcement_started = 0`, nothing captured or forced, no report, no monthly checks, not
  on the care dashboard. `package_enforce_tick` starts due activations first
  (`package_start_due`), capturing the prior state **at that moment** so a cancel never
  restores over changes made in between. Compare-and-set (`mark_started`) keeps two passes
  from both capturing.
- `package_set_valid_from`: earlier always; later only while waiting; a plan already in
  force cannot be pushed into the future (cancel and re-activate). Moving a waiting plan to
  today or earlier starts it immediately.
- Every consumer that **acts** on a plan reads the in-force lists
  (`list_in_force_for_hosting`, `list_all_in_force`); the card reads all held plans.

## Compatibility

New RPC fields are `#[serde(default)]`; `HostingPackage.enforcement_started` defaults to
true. A node that predates this ignores `valid_from` on activate (the web card detects the
missing echo and says so) and ignores `report_omit` on relist (that node keeps sending all
sections until upgraded).

## Out of scope

"Valid until", rewriting already-sent reports, per-site (rather than per-plan) section
overrides.
