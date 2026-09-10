//! The monthly service check: the part of a care plan a machine cannot do.
//!
//! Most of what a care plan sells, hyperion does by itself and can prove —
//! backups ran, updates applied, malware scan came back clean. Some items are
//! not like that. Whether the gallery still renders, whether the contact
//! form's mail actually arrives, whether the site still feels fast, whether
//! last week's plugin update broke a layout: those need a person to look, and
//! a plan that promises them without recording that anybody did is selling
//! something nobody delivers.
//!
//! So each site carries a per-month checklist. It is bookkeeping, not
//! measurement, and it says so: a tick means "an operator confirmed they did
//! this", nothing more. Untouched is UNDONE — never "probably fine" — because
//! the whole point is to make an unlooked-at month visible before the customer
//! finds it.
//!
//! WHICH items are on the list belongs to the CARE PACKAGE, not to the site.
//! Four are built in and are what every plan gets by default; an operator
//! whose plan promises something else — a GDPR review, a stock feed, an
//! uptime report the customer signed for — edits the plan's list, and every
//! site on that plan is asked the same question. That is the point: a list
//! per SITE would give every site its own private definition of "checked",
//! and "is this month done?" would stop having an answer across the estate,
//! which is the one question the dashboard exists to answer.
//!
//! A month, once ticked, keeps the list it was ticked against — see
//! [`CareServiceChecks::applied`]. Editing a plan changes what gets asked
//! next month; it never rescores a month somebody already signed off.
//!
//! Stored as one JSON value in `hosting_kv` under `care_service_checks`, on
//! the node that owns the hosting, which is also where the customer's report
//! is assembled.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The four items the product has always shipped.
///
/// A closed set, and it stays closed: these are the ones the customer letter
/// has translated wording for, and the ones a plan gets when it says nothing.
/// An operator's own items are [`CheckItemDef`]s on the care package — they
/// carry their own label because no letter pack can know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCheckItem {
    /// Main pages render, navigation works, links resolve, the gallery shows.
    Render,
    /// Forms submit AND the message arrives — the half that silently breaks.
    Forms,
    /// Load speed and Core Web Vitals; cache adjusted if it needs it.
    Speed,
    /// The site still works AFTER this month's updates went in.
    PostUpdate,
}

impl ServiceCheckItem {
    pub const ALL: [ServiceCheckItem; 4] = [
        ServiceCheckItem::Render,
        ServiceCheckItem::Forms,
        ServiceCheckItem::Speed,
        ServiceCheckItem::PostUpdate,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ServiceCheckItem::Render => "render",
            ServiceCheckItem::Forms => "forms",
            ServiceCheckItem::Speed => "speed",
            ServiceCheckItem::PostUpdate => "post_update",
        }
    }

    pub fn parse(s: &str) -> Option<ServiceCheckItem> {
        ServiceCheckItem::ALL.into_iter().find(|i| i.as_str() == s)
    }

    /// Short label for the checkbox.
    pub fn label(self) -> &'static str {
        match self {
            ServiceCheckItem::Render => "Pages and navigation",
            ServiceCheckItem::Forms => "Forms and their delivery",
            ServiceCheckItem::Speed => "Speed and Core Web Vitals",
            ServiceCheckItem::PostUpdate => "Still working after updates",
        }
    }

    /// What the operator is confirming they actually did. Spelled out
    /// because "checked" means nothing a month later, and because this is
    /// the text a dispute with a customer comes down to.
    pub fn detail(self) -> &'static str {
        match self {
            ServiceCheckItem::Render => {
                "Opened the main pages, followed the navigation and the links, \
                 and confirmed the gallery still displays."
            }
            ServiceCheckItem::Forms => {
                "Submitted each form and confirmed the message arrived — with \
                 the client where the destination is theirs."
            }
            ServiceCheckItem::Speed => {
                "Measured how long the site takes to load and adjusted the \
                 cache if it needed it."
            }
            ServiceCheckItem::PostUpdate => {
                "Looked over the site after this month's core, theme and \
                 plugin updates went in."
            }
        }
    }
}

/// One tick: who, when, and anything they wanted to record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCheckMark {
    pub at: i64,
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub note: String,
}

/// One item on a care plan's monthly checklist.
///
/// The built-in four are the default; a plan may replace them wholesale. The id
/// is what a tick is stored under and is therefore permanent for that plan: it
/// appears in 24 months of history, so renaming the LABEL is free and changing
/// the id would orphan every mark that used it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckItemDef {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub detail: String,
}

/// Parse a plan's stored `check_items`, falling back to the built-in four.
///
/// Empty, absent or unparseable all mean "the built-in list" — the same answer
/// every package gave before this existed, and the one that cannot silently
/// reduce what an operator promised a customer.
pub fn parse_check_items(raw: &str) -> Vec<CheckItemDef> {
    let kept = parse_check_items_raw(raw);
    if kept.is_empty() {
        return builtin_check_items();
    }
    kept
}

/// Parse without the fallback — an empty result means "this plan says
/// nothing", which is what [`resolve_check_items`] needs to tell apart from
/// "this plan asks for the built-in four".
pub fn parse_check_items_raw(raw: &str) -> Vec<CheckItemDef> {
    let parsed: Vec<CheckItemDef> = serde_json::from_str(raw.trim()).unwrap_or_default();
    parsed
        .into_iter()
        .filter(|i| !i.id.trim().is_empty() && !i.label.trim().is_empty())
        .collect()
}

/// The checklist for a SITE, from the `check_items` of every package it holds.
///
/// A site can hold two packages, so the answer is their union in the order
/// given, first definition of an id winning. Nothing from any of them means
/// the built-in four: a site on a plan is never asked for an empty list, or
/// "0 of 0 checked" would read as a finished month on the dashboard.
pub fn resolve_check_items(snapshots: &[&str]) -> Vec<CheckItemDef> {
    let mut out: Vec<CheckItemDef> = Vec::new();
    for raw in snapshots {
        // `parse_check_items`, WITH the fallback, deliberately: a plan storing
        // "" promises the built-in four, and it goes on promising them when
        // the site also holds a plan that lists its own. Unioning the RAW
        // parse instead would let one custom plan silently cancel every check
        // the other plan sells.
        for item in parse_check_items(raw) {
            if !out.iter().any(|k| k.id == item.id) {
                out.push(item);
            }
        }
    }
    if out.is_empty() {
        return builtin_check_items();
    }
    out
}

/// Turn a list of definitions back into the stored JSON.
pub fn check_items_to_json(items: &[CheckItemDef]) -> String {
    serde_json::to_string(items).unwrap_or_default()
}

/// The four the product has always shipped, as definitions.
pub fn builtin_check_items() -> Vec<CheckItemDef> {
    ServiceCheckItem::ALL
        .into_iter()
        .map(|i| CheckItemDef {
            id: i.as_str().to_string(),
            label: i.label().to_string(),
            detail: i.detail().to_string(),
        })
        .collect()
}

/// Everything ticked in one month, keyed by item id.
pub type ServiceCheckMonth = BTreeMap<String, ServiceCheckMark>;

/// The whole history, keyed by `YYYY-MM`, plus which items each month was
/// measured against.
///
/// It WAS `#[serde(transparent)]` over the bare map. That shape could not carry
/// the frozen item list, and changing it is why `parse` handles both — a
/// silent `unwrap_or_default` on the old shape would have deleted 24 months of
/// record from every site on upgrade.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CareServiceChecks {
    /// The marks themselves, `YYYY-MM` → id → who/when/note. Byte-identical to
    /// what every version since v0.54 wrote.
    pub periods: BTreeMap<String, ServiceCheckMonth>,
    /// WHICH items applied in each period, frozen the first time that period
    /// is ticked.
    ///
    /// Without this, removing an item from a care plan would rewrite history:
    /// a March that read "3 of 4" would silently become "3 of 3" — a record
    /// nobody re-checked, changed after the fact, and the exact thing a
    /// dispute with a customer turns on. A period with no entry here predates
    /// the feature and means the built-in four.
    ///
    /// Whole definitions, not ids: the LABEL is the operator's own wording and
    /// lives on the care package, which may be edited or deleted long before
    /// this month is read back. Storing ids alone would leave a customer's
    /// year-old report naming an item `gdpr-2025` because the only place that
    /// knew what it was called has since changed its mind.
    #[serde(default)]
    pub applied: BTreeMap<String, Vec<CheckItemDef>>,
}

/// What the stored JSON may look like on disk.
///
/// `parse` used to be `from_str(raw).unwrap_or_default()`, which is right for
/// corruption — "nothing has been checked" is the failure that shows up as work
/// outstanding — and catastrophic for a SHAPE CHANGE: every site's 24 months
/// would vanish silently on upgrade. So the legacy shape is a case, not an
/// accident.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredChecks {
    Current(CareServiceChecksRepr),
    /// v0.54 through v0.61: a bare `YYYY-MM` → marks object.
    Legacy(BTreeMap<String, ServiceCheckMonth>),
}

#[derive(Deserialize)]
struct CareServiceChecksRepr {
    periods: BTreeMap<String, ServiceCheckMonth>,
    #[serde(default)]
    applied: BTreeMap<String, Vec<CheckItemDef>>,
}

/// How many months of history to keep.
///
/// Long enough to answer "was this looked at last quarter?" and to survive a
/// customer asking about a year they were billed for; short enough that the
/// value stays a small JSON blob rather than growing without bound.
pub const KEEP_MONTHS: usize = 24;

impl CareServiceChecks {
    /// Parse the stored value. Anything unreadable reads as EMPTY — i.e. as
    /// "nothing has been checked" — because the failure mode has to be the
    /// one that shows up on the dashboard as work outstanding, not the one
    /// that quietly marks a month done.
    pub fn parse(raw: &str) -> Self {
        match serde_json::from_str::<StoredChecks>(raw) {
            Ok(StoredChecks::Current(r)) => Self {
                periods: r.periods,
                applied: r.applied,
            },
            // A blob written before the item list was frozen. Its periods all
            // mean the built-in four, which `items_for` supplies.
            Ok(StoredChecks::Legacy(periods)) => Self {
                periods,
                applied: BTreeMap::new(),
            },
            Err(_) => Self::default(),
        }
    }

    /// Serialise for storage.
    ///
    /// While nothing has been frozen, this writes the PRE-v0.62 shape — the
    /// bare `YYYY-MM` map — and not because it is tidier. A cluster upgrades
    /// one node at a time, and this blob is written by the master into the kv
    /// of the node that owns the site. A v0.61.1 node parses the new shape
    /// with `unwrap_or_default()`, i.e. as "nothing was ever checked", and
    /// then tells the customer so. Emitting the old shape until there is
    /// genuinely something new to say means an install that never edits a
    /// checklist never writes a blob its other nodes cannot read.
    pub fn to_json(&self) -> String {
        if self.applied.is_empty() {
            return serde_json::to_string(&self.periods).unwrap_or_else(|_| "{}".to_string());
        }
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn month(&self, period: &str) -> Option<&ServiceCheckMonth> {
        self.periods.get(period)
    }

    pub fn is_checked(&self, period: &str, item: ServiceCheckItem) -> bool {
        self.month(period)
            .map(|m| m.contains_key(item.as_str()))
            .unwrap_or(false)
    }

    /// The items that applied in `period`.
    ///
    /// The FROZEN list where one was recorded, the built-in four otherwise —
    /// which is what every period written before v0.62 means. This is the only
    /// place that decides what a month was scored against, so a plan edited
    /// today cannot change what March said.
    ///
    /// Note what it does NOT take: the plan's CURRENT list. A caller that
    /// wants "what should this site be asked THIS month" wants
    /// [`Self::items_now`], which falls back to the live list for a month
    /// nobody has ticked yet.
    pub fn items_for(&self, period: &str) -> Vec<CheckItemDef> {
        match self.applied.get(period) {
            Some(items) if !items.is_empty() => items.clone(),
            _ => builtin_check_items(),
        }
    }

    /// What `period` is scored against right now: the frozen list once the
    /// month has been ticked, otherwise `live` — the site's current plan.
    ///
    /// The two cases are the whole design. Before the first tick a month is
    /// still a question, so a plan edited today changes it. After the first
    /// tick it is a record, and nothing edits a record.
    pub fn items_now(&self, period: &str, live: &[CheckItemDef]) -> Vec<CheckItemDef> {
        match self.applied.get(period) {
            Some(items) if !items.is_empty() => items.clone(),
            // MARKS but no frozen list: a month ticked before v0.62, when the
            // list was the built-in four and nothing recorded that. It is a
            // record, not an open question, so the plan as it stands today
            // must not rescore it — the same answer `items_for` gives.
            //
            // Without this arm the first operator to edit a plan after the
            // upgrade rewrites up to 24 months of every site's history: the
            // customer's letter reports four checks that were done, and
            // recorded, as not performed.
            _ if self.periods.contains_key(period) => builtin_check_items(),
            _ if !live.is_empty() => live.to_vec(),
            _ => builtin_check_items(),
        }
    }

    /// Freeze the item list for `period`, once.
    ///
    /// Called the first time a month is ticked. Deliberately does NOT
    /// overwrite: the list is what applied when the work was done, and a plan
    /// edited mid-month must not retroactively add an item nobody was asked to
    /// do — or remove one they already ticked.
    pub fn freeze_items(&mut self, period: &str, items: &[CheckItemDef]) {
        if items.is_empty() {
            return;
        }
        // Freezing the built-in four is already what NO entry means for a
        // month that has marks — `items_for` and `items_now` both answer
        // `builtin_check_items()` for it — so writing it down changes no
        // answer this type can give.
        //
        // Not writing it is what keeps `to_json` on the pre-v0.62 shape for
        // every install that has not customised a checklist. A cluster
        // upgrades one node at a time and this blob is written BY THE MASTER
        // into the owning node's kv; a v0.61.1 node reads an unknown shape as
        // "nothing was ever checked" and tells the customer so. Without this,
        // the very first ordinary tick after the upgrade would write the new
        // shape on a site nobody has customised, and the compatibility this
        // was built for would never apply to anyone.
        if items == builtin_check_items() {
            return;
        }
        self.applied
            .entry(period.to_string())
            .or_insert_with(|| items.to_vec());
    }

    /// Ids still outstanding for `period`, in list order.
    pub fn outstanding_ids(&self, period: &str) -> Vec<String> {
        self.outstanding_defs(period)
            .into_iter()
            .map(|i| i.id)
            .collect()
    }

    /// Items still outstanding for `period`, in list order.
    pub fn outstanding_defs(&self, period: &str) -> Vec<CheckItemDef> {
        let checked = self.month(period);
        self.items_for(period)
            .into_iter()
            .filter(|i| !checked.map(|m| m.contains_key(&i.id)).unwrap_or(false))
            .collect()
    }

    /// Items still outstanding for `period`, scored against `live` while the
    /// month is still open. See [`Self::items_now`].
    pub fn outstanding_now(&self, period: &str, live: &[CheckItemDef]) -> Vec<CheckItemDef> {
        let checked = self.month(period);
        self.items_now(period, live)
            .into_iter()
            .filter(|i| !checked.map(|m| m.contains_key(&i.id)).unwrap_or(false))
            .collect()
    }

    pub fn is_complete(&self, period: &str) -> bool {
        self.outstanding_ids(period).is_empty()
    }

    pub fn done_count(&self, period: &str) -> usize {
        self.items_for(period).len() - self.outstanding_ids(period).len()
    }

    /// How many items the period was measured against — its denominator.
    pub fn total_count(&self, period: &str) -> usize {
        self.items_for(period).len()
    }

    /// Record (or retract) one item, freezing the month if and only if this
    /// submit is a CLAIM of work.
    ///
    /// The single entry point for a tick, and the freeze decision lives here
    /// rather than in the handler on purpose. The same form also saves a note
    /// and retracts a mistake, and both post the whole row; a caller that
    /// froze first would pin the checklist of a month nobody has checked,
    /// putting it beyond the reach of any later plan edit. Leaving that choice
    /// to each call site is how it went wrong once already.
    ///
    /// `live` is the site's CURRENT plan. It is used only when the month has
    /// nothing frozen yet — see [`Self::items_now`].
    pub fn record(
        &mut self,
        period: &str,
        id: &str,
        checked: bool,
        by: &str,
        note: &str,
        now: i64,
        live: &[CheckItemDef],
    ) {
        if checked {
            // `items_now`, NOT `live`. For a month carrying marks but nothing
            // frozen — every month ticked under v0.54..v0.61 — what the month
            // is scored against is the built-in four, and that is what the
            // card just showed the operator and what their click validated
            // against. Freezing the raw plan here would pin today's list onto
            // a month somebody already signed off, which is the exact
            // rescoring `items_now` exists to prevent: the marks stay in the
            // blob, but nothing counts or renders them ever again, and the
            // customer's letter says nobody looked.
            let frozen = self.items_now(period, live);
            self.freeze_items(period, &frozen);
        }
        self.set_id(period, id, checked, by, note, now);
    }

    /// Record (or clear) a mark by raw id, so a custom item works exactly like
    /// a built-in one.
    pub fn set_id(
        &mut self,
        period: &str,
        id: &str,
        checked: bool,
        by: &str,
        note: &str,
        now: i64,
    ) {
        if checked {
            let month = self.periods.entry(period.to_string()).or_default();
            match month.get_mut(id) {
                Some(existing) => existing.note = note.to_string(),
                None => {
                    month.insert(
                        id.to_string(),
                        ServiceCheckMark {
                            at: now,
                            by: by.to_string(),
                            note: note.to_string(),
                        },
                    );
                }
            }
        } else if let Some(m) = self.periods.get_mut(period) {
            m.remove(id);
            if m.is_empty() {
                self.periods.remove(period);
            }
        }
        self.trim();
    }

    /// Record (or clear) one item, then trim the history.
    ///
    /// Un-ticking is deliberately possible and deliberately destructive: the
    /// mark is a claim that somebody looked, and a claim made by mistake has
    /// to be retractable or the record stops meaning anything.
    pub fn set(
        &mut self,
        period: &str,
        item: ServiceCheckItem,
        checked: bool,
        by: &str,
        note: &str,
        now: i64,
    ) {
        if checked {
            let month = self.periods.entry(period.to_string()).or_default();
            match month.get_mut(item.as_str()) {
                // Already ticked: this is a note edit, not a new claim. The
                // record of WHO looked and WHEN is the whole value of the
                // mark, and saving a note must not quietly re-attribute it
                // to whoever typed the note.
                Some(existing) => existing.note = note.to_string(),
                None => {
                    month.insert(
                        item.as_str().to_string(),
                        ServiceCheckMark {
                            at: now,
                            by: by.to_string(),
                            note: note.to_string(),
                        },
                    );
                }
            }
        } else if let Some(m) = self.periods.get_mut(period) {
            m.remove(item.as_str());
            if m.is_empty() {
                self.periods.remove(period);
            }
        }
        self.trim();
    }

    /// Keep only the most recent [`KEEP_MONTHS`] periods. `BTreeMap` orders
    /// `YYYY-MM` keys chronologically, which is the one thing that makes
    /// this a two-line operation rather than a date-parsing exercise.
    fn trim(&mut self) {
        while self.periods.len() > KEEP_MONTHS {
            let Some(oldest) = self.periods.keys().next().cloned() else {
                break;
            };
            self.periods.remove(&oldest);
            self.applied.remove(&oldest);
        }
        // `applied` gets its own bound. Un-ticking a month's last item drops
        // the period but deliberately KEEPS its frozen list, so that a re-tick
        // lands on the same denominator — which means `applied` can outlive
        // `periods` and would otherwise grow without a ceiling.
        //
        // Only ORPHANS are eligible. Taking the oldest key outright would
        // strip the frozen list off a month whose marks are still stored, and
        // that month would silently rescore against the built-in four — the
        // exact rewriting-of-history this map exists to prevent. `periods` is
        // already capped, so dropping orphans alone keeps this bounded.
        while self.applied.len() > KEEP_MONTHS {
            let Some(orphan) = self
                .applied
                .keys()
                .find(|k| !self.periods.contains_key(*k))
                .cloned()
            else {
                break;
            };
            self.applied.remove(&orphan);
        }
    }
}

/// `YYYY-MM` in UTC — the key a month's checks are filed under.
///
/// UTC rather than local time so two operators in different places, or the
/// same operator either side of a DST change, always agree which month a tick
/// belongs to. On the first or last day of a month that can differ from the
/// wall clock by a few hours; a checklist that silently split one month into
/// two would be worse.
pub fn period_key(now: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(now, 0)
        .map(|d| d.format("%Y-%m").to_string())
        // Unreachable from a real clock. A fixed sentinel beats a panic and
        // beats silently filing the tick under the wrong month.
        .unwrap_or_else(|| "0000-00".to_string())
}

/// The month before `period` (`"2026-01"` → `"2025-12"`), for "was last
/// month done?" without another date library at the call site.
pub fn previous_period(period: &str) -> Option<String> {
    let (y, m) = period.split_once('-')?;
    let y: i32 = y.parse().ok()?;
    let m: u32 = m.parse().ok()?;
    if m == 1 {
        Some(format!("{:04}-12", y - 1))
    } else {
        Some(format!("{y:04}-{:02}", m - 1))
    }
}

#[cfg(test)]
mod tests {
    /// A blob written by any version since v0.54 must survive the shape change.
    ///
    /// `parse` was `from_str(raw).unwrap_or_default()` — right for corruption,
    /// catastrophic for a shape change: every site's 24 months would have
    /// vanished on upgrade, silently, with the dashboard simply showing more
    /// work outstanding. Nobody would have noticed until a customer asked about
    /// a month they were billed for.
    #[test]
    fn a_pre_v062_blob_keeps_every_month() {
        let legacy = r#"{
            "2026-03": {"render": {"at": 100, "by": "kevin", "note": "ok"},
                        "forms":  {"at": 101, "by": "kevin", "note": ""}},
            "2026-04": {"speed":  {"at": 200, "by": "kevin", "note": ""}}
        }"#;
        let c = CareServiceChecks::parse(legacy);
        assert_eq!(c.periods.len(), 2, "both months must survive: {c:?}");
        assert!(c.is_checked("2026-03", ServiceCheckItem::Render));
        assert!(c.is_checked("2026-04", ServiceCheckItem::Speed));

        // No frozen list on an old period ⇒ the built-in four, which is what
        // those months were actually measured against.
        assert_eq!(c.total_count("2026-03"), 4);
        assert_eq!(c.done_count("2026-03"), 2);
        assert_eq!(c.done_count("2026-04"), 1);

        // And it round-trips into the new shape without losing anything.
        let again = CareServiceChecks::parse(&c.to_json());
        assert_eq!(again, c, "a save after an upgrade must not drop history");
    }

    /// Build a list of definitions from ids, for tests that only care about
    /// which items applied.
    fn defs(ids: &[&str]) -> Vec<CheckItemDef> {
        ids.iter()
            .map(|id| CheckItemDef {
                id: (*id).to_string(),
                label: id.to_uppercase(),
                detail: String::new(),
            })
            .collect()
    }

    /// Removing an item from a care plan must not rewrite a month nobody
    /// re-checked.
    #[test]
    fn a_frozen_month_keeps_its_denominator_when_the_plan_changes() {
        let mut c = CareServiceChecks::default();
        let march = defs(&["render", "forms", "speed", "post_update"]);
        c.freeze_items("2026-03", &march);
        c.set_id("2026-03", "render", true, "kevin", "", 1);
        c.set_id("2026-03", "forms", true, "kevin", "", 2);
        c.set_id("2026-03", "speed", true, "kevin", "", 3);
        assert_eq!((c.done_count("2026-03"), c.total_count("2026-03")), (3, 4));

        // The operator now trims the plan to two items and adds a custom one.
        let april = defs(&["render", "forms", "backup_drill"]);
        c.freeze_items("2026-04", &april);
        assert_eq!(
            (c.done_count("2026-03"), c.total_count("2026-03")),
            (3, 4),
            "March must still read 3 of 4"
        );
        assert_eq!(c.total_count("2026-04"), 3);

        // Freezing is once-only: a plan edited mid-month cannot retroactively
        // add work nobody was asked to do.
        c.freeze_items("2026-04", &march);
        assert_eq!(
            c.total_count("2026-04"),
            3,
            "the list is frozen, not latest"
        );
    }

    /// A month still open follows the plan; a month already ticked does not.
    #[test]
    fn a_plan_edit_reaches_next_month_and_not_last_month() {
        let mut c = CareServiceChecks::default();
        let old_plan = defs(&["render", "forms"]);
        c.freeze_items("2026-03", &old_plan);
        c.set_id("2026-03", "render", true, "kevin", "", 1);

        let new_plan = defs(&["render", "forms", "gdpr"]);
        assert_eq!(
            c.items_now("2026-03", &new_plan).len(),
            2,
            "a month already ticked keeps its own list"
        );
        assert_eq!(
            c.items_now("2026-04", &new_plan).len(),
            3,
            "a month nobody has touched follows the plan as it stands"
        );
        // And a site on no plan at all still gets asked something: "0 of 0"
        // renders as a finished month.
        assert_eq!(c.items_now("2026-04", &[]).len(), 4);
    }

    /// The frozen list carries the WORDING, so a rename cannot rewrite what a
    /// customer was told last month.
    #[test]
    fn a_frozen_month_keeps_the_wording_it_was_ticked_with() {
        let mut c = CareServiceChecks::default();
        c.freeze_items(
            "2026-03",
            &[CheckItemDef {
                id: "gdpr".into(),
                label: "GDPR review".into(),
                detail: "Checked the cookie banner".into(),
            }],
        );
        c.set_id("2026-03", "gdpr", true, "kevin", "", 1);
        // The plan is reworded — a different label, and the operator may well
        // have deleted the package outright by the time this is read back.
        let items = c.items_for("2026-03");
        assert_eq!(items[0].label, "GDPR review");
        assert_eq!(items[0].detail, "Checked the cookie banner");
        // Including across a save/load, which is where storing bare ids would
        // have lost it.
        let round = CareServiceChecks::parse(&c.to_json());
        assert_eq!(round.items_for("2026-03")[0].label, "GDPR review");
    }

    /// Two plans on one site are asked as one list, without asking twice for
    /// the item they share.
    #[test]
    fn two_plans_on_one_site_make_one_list() {
        let a = check_items_to_json(&defs(&["render", "forms"]));
        let b = check_items_to_json(&defs(&["forms", "gdpr"]));
        let ids: Vec<String> = resolve_check_items(&[&a, &b])
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(ids, vec!["render", "forms", "gdpr"]);

        // Nothing from either plan means the built-ins, never an empty list.
        assert_eq!(resolve_check_items(&["", ""]).len(), 4);
        assert_eq!(resolve_check_items(&[]).len(), 4);
        // Including when the stored value is garbage: an unreadable plan must
        // not silently reduce what it promised.
        assert_eq!(resolve_check_items(&["{oops", "null"]).len(), 4);
    }

    /// `applied` outlives `periods` by design, so it needs its own ceiling.
    #[test]
    fn the_frozen_lists_do_not_grow_without_bound() {
        let mut c = CareServiceChecks::default();
        let items = defs(&["render"]);
        for y in 2000..2010 {
            for m in 1..=12 {
                let p = format!("{y}-{m:02}");
                c.freeze_items(&p, &items);
                c.set_id(&p, "render", true, "kevin", "", 1);
                // Un-tick, which drops the period but keeps the frozen list.
                c.set_id(&p, "render", false, "kevin", "", 2);
            }
        }
        assert!(
            c.applied.len() <= KEEP_MONTHS,
            "120 months of frozen lists survived the trim: {}",
            c.applied.len()
        );
    }

    /// The upgrade case, and the one the whole feature turns on.
    ///
    /// Every site carries months ticked under v0.54..v0.61, when the list was
    /// the built-in four and nothing recorded that. Those months must not be
    /// rescored against whatever the plan says today.
    #[test]
    fn a_month_ticked_before_v062_is_not_rescored_by_a_later_plan_edit() {
        // Exactly what a v0.61 install has on disk: the bare month map.
        let legacy = r#"{"2026-09":{
            "render":{"at":1,"by":"kevin","note":""},
            "forms":{"at":2,"by":"kevin","note":""},
            "speed":{"at":3,"by":"kevin","note":""},
            "post_update":{"at":4,"by":"kevin","note":""}}}"#;
        let c = CareServiceChecks::parse(legacy);
        assert!(c.applied.is_empty(), "a legacy blob freezes nothing");

        // The operator upgrades and does the obvious first thing: replaces the
        // list with their own items.
        let live = defs(&["gdpr", "stock-feed", "uptime"]);
        let scored = c.items_now("2026-09", &live);
        assert_eq!(
            scored.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["render", "forms", "speed", "post_update"],
            "September was ticked against the built-in four and stays scored against them"
        );
        assert!(
            c.outstanding_now("2026-09", &live).is_empty(),
            "all four were done; the customer must not be told otherwise"
        );
        assert_eq!(c.done_count("2026-09"), 4);

        // A month with NO marks is still an open question and follows the plan.
        assert_eq!(c.items_now("2026-10", &live).len(), 3);
    }

    /// An unedited plan does not stop promising the built-in four just because
    /// the site also holds a plan that lists its own.
    #[test]
    fn an_unedited_plan_keeps_promising_the_builtins_alongside_a_custom_one() {
        let custom = check_items_to_json(&defs(&["gdpr"]));
        let ids: Vec<String> = resolve_check_items(&["", &custom])
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(
            ids,
            vec!["render", "forms", "speed", "post_update", "gdpr"],
            "the unedited plan sells four checks and the custom one sells a fifth"
        );
    }

    /// Trimming `applied` must never strip the frozen list off a month whose
    /// marks are still stored — that month would silently rescore.
    #[test]
    fn trim_never_unfreezes_a_month_that_still_has_marks() {
        let mut c = CareServiceChecks::default();
        let five = defs(&["a", "b", "c", "d", "e"]);
        // Fill every kept month with a five-item frozen list...
        for y in 2025..2027 {
            for m in 1..=12 {
                let p = format!("{y}-{m:02}");
                c.freeze_items(&p, &five);
                c.set_id(&p, "a", true, "kevin", "", 1);
            }
        }
        // ...then add orphans: months frozen and then emptied by an untick.
        for m in 1..=6 {
            let p = format!("2024-{m:02}");
            c.freeze_items(&p, &five);
            c.set_id(&p, "a", true, "kevin", "", 1);
            c.set_id(&p, "a", false, "kevin", "", 2);
        }
        for p in c.periods.keys().cloned().collect::<Vec<_>>() {
            assert_eq!(
                c.total_count(&p),
                5,
                "{p} still has marks, so it must still have its frozen list"
            );
        }
        assert!(c.applied.len() <= KEEP_MONTHS * 2, "still bounded");
    }

    /// A cluster upgrades one node at a time, and this blob is written by the
    /// master into the OWNING node's kv. Until something is actually frozen,
    /// keep writing the shape a v0.61 node can still read.
    #[test]
    fn nothing_frozen_still_writes_the_old_shape() {
        let mut c = CareServiceChecks::default();
        c.set_id("2026-09", "render", true, "kevin", "ok", 100);
        let json = c.to_json();
        assert!(
            json.starts_with(r#"{"2026-09":"#),
            "an install that has not edited a checklist must not write a blob              its other nodes cannot read: {json}"
        );
        assert_eq!(CareServiceChecks::parse(&json), c, "and it round-trips");

        // Once a month IS frozen there is something new to say, and the new
        // shape is the only one that can carry it.
        c.freeze_items("2026-09", &defs(&["render", "gdpr"]));
        let json = c.to_json();
        assert!(json.contains(r#""applied""#), "{json}");
        assert_eq!(CareServiceChecks::parse(&json), c);
    }

    /// A month is a record from the moment somebody claims work, and not
    /// before. Saving a note on an unticked row, or retracting a mistake, must
    /// leave the month open to a later plan edit.
    #[test]
    fn only_a_claim_of_work_freezes_the_month() {
        let old_plan = defs(&["render", "forms"]);
        let new_plan = defs(&["render", "forms", "gdpr"]);

        // A note typed into the box of a row nobody ticked.
        let mut c = CareServiceChecks::default();
        c.record(
            "2026-03",
            "render",
            false,
            "kevin",
            "asked client",
            1,
            &old_plan,
        );
        assert!(
            c.applied.is_empty(),
            "nothing was claimed, so nothing is frozen"
        );
        assert_eq!(
            c.items_now("2026-03", &new_plan).len(),
            3,
            "the month is still open and follows the plan"
        );

        // Retracting a tick leaves the month frozen — work WAS claimed once,
        // and the denominator a re-tick lands on has to be the same one.
        let mut c = CareServiceChecks::default();
        c.record("2026-03", "render", true, "kevin", "", 1, &old_plan);
        c.record("2026-03", "render", false, "kevin", "", 2, &old_plan);
        assert_eq!(
            c.items_now("2026-03", &new_plan).len(),
            2,
            "a month that was ticked keeps its list even after the tick is pulled"
        );

        // And a real tick freezes against the plan as it stood, once.
        let mut c = CareServiceChecks::default();
        c.record("2026-03", "render", true, "kevin", "", 1, &old_plan);
        c.record("2026-03", "forms", true, "kevin", "", 2, &new_plan);
        assert_eq!(
            c.total_count("2026-03"),
            2,
            "frozen once, at the first claim"
        );
    }

    /// The regression round 2 found in round 1's own fix.
    ///
    /// Ticking a pre-v0.62 month must freeze what the card SCORED it against
    /// — the built-in four — not the plan as it stands today. Getting this
    /// wrong put the rescoring back one call deeper than where it was fixed,
    /// and made the operator's own click the thing that erased the month.
    #[test]
    fn ticking_a_legacy_month_freezes_what_it_was_scored_against() {
        let legacy = r#"{"2026-09":{
            "render":{"at":1,"by":"kevin","note":""},
            "forms":{"at":2,"by":"kevin","note":""}}}"#;
        let mut c = CareServiceChecks::parse(legacy);
        // The operator has since replaced the plan's list wholesale.
        let live = defs(&["gdpr-review", "stock-feed"]);

        // The card shows the built-in four, 2 of 4, and the operator ticks the
        // third — an id that only exists in the built-in list.
        assert_eq!(c.items_now("2026-09", &live).len(), 4);
        c.record("2026-09", "speed", true, "kevin", "", 10, &live);

        assert_eq!(
            (c.done_count("2026-09"), c.total_count("2026-09")),
            (3, 4),
            "the month the operator was looking at must stay the month they ticked"
        );
        assert!(
            c.is_checked("2026-09", ServiceCheckItem::Render),
            "and the marks already recorded must still COUNT, not merely survive"
        );
        assert_eq!(
            c.outstanding_ids("2026-09"),
            vec!["post_update".to_string()]
        );

        // October, which nobody has touched, still follows the new plan.
        assert_eq!(
            c.items_now("2026-10", &live)
                .into_iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec!["gdpr-review", "stock-feed"]
        );
    }

    /// The compatibility guard has to survive ordinary use, or it protects
    /// nobody: an install that never customises a checklist must never write
    /// a blob its un-upgraded nodes cannot read.
    #[test]
    fn an_install_that_never_customises_never_writes_the_new_shape() {
        let mut c = CareServiceChecks::default();
        let builtins = builtin_check_items();
        // A full year of ordinary ticking on the built-in list.
        for m in 1..=12 {
            let p = format!("2026-{m:02}");
            for item in &builtins {
                c.record(&p, &item.id, true, "kevin", "", 1, &builtins);
            }
        }
        assert!(
            c.applied.is_empty(),
            "the built-in four are what silence means"
        );
        let json = c.to_json();
        assert!(
            !json.contains(r#""applied""#) && !json.contains(r#""periods""#),
            "a v0.61 node has to be able to read this: {json}"
        );
        // And every month still reads back as complete, against four.
        for m in 1..=12 {
            let p = format!("2026-{m:02}");
            assert!(c.is_complete(&p), "{p}");
            assert_eq!(c.total_count(&p), 4);
        }
        assert_eq!(CareServiceChecks::parse(&json), c);

        // The moment a plan genuinely differs, the new shape is the only one
        // that can carry it, and that is when it starts being written.
        c.record("2027-01", "gdpr", true, "kevin", "", 2, &defs(&["gdpr"]));
        assert!(c.to_json().contains(r#""applied""#));
    }

    /// A custom id ticks and unticks exactly like a built-in one.
    #[test]
    fn a_custom_item_behaves_like_a_built_in_one() {
        let mut c = CareServiceChecks::default();
        let items = defs(&["render", "backup_drill"]);
        c.freeze_items("2026-05", &items);
        assert_eq!(
            c.outstanding_ids("2026-05"),
            vec!["render".to_string(), "backup_drill".to_string()]
        );

        c.set_id(
            "2026-05",
            "backup_drill",
            true,
            "kevin",
            "restored to staging",
            9,
        );
        assert_eq!(c.outstanding_ids("2026-05"), vec!["render".to_string()]);
        assert!(!c.is_complete("2026-05"));

        c.set_id("2026-05", "render", true, "kevin", "", 10);
        assert!(c.is_complete("2026-05"));

        // Un-ticking stays destructive and possible — a claim made by mistake
        // has to be retractable or the record stops meaning anything.
        c.set_id("2026-05", "backup_drill", false, "kevin", "", 11);
        assert_eq!(c.done_count("2026-05"), 1);
    }

    use super::*;

    #[test]
    fn unreadable_state_reads_as_nothing_checked() {
        // The important direction: garbage must never mark a month done.
        for raw in ["", "null", "{", "[]", "\"nope\""] {
            let c = CareServiceChecks::parse(raw);
            assert_eq!(c.done_count("2026-09"), 0, "{raw:?}");
            assert!(!c.is_complete("2026-09"), "{raw:?}");
        }
    }

    #[test]
    fn ticking_and_untucking_round_trips() {
        let mut c = CareServiceChecks::default();
        c.set(
            "2026-09",
            ServiceCheckItem::Render,
            true,
            "kevin",
            "ok",
            100,
        );
        assert!(c.is_checked("2026-09", ServiceCheckItem::Render));
        assert_eq!(c.done_count("2026-09"), 1);
        assert_eq!(c.outstanding_ids("2026-09").len(), 3);

        let round = CareServiceChecks::parse(&c.to_json());
        assert_eq!(round, c);

        c.set("2026-09", ServiceCheckItem::Render, false, "kevin", "", 200);
        assert!(!c.is_checked("2026-09", ServiceCheckItem::Render));
        // The month emptied out entirely, so it leaves no husk behind.
        assert!(c.month("2026-09").is_none());
    }

    /// Saving a note on a ticked item keeps who ticked it and when. The
    /// mark is the record; the note is a remark on it.
    #[test]
    fn editing_a_note_does_not_reattribute_the_tick() {
        let mut c = CareServiceChecks::default();
        c.set("2026-09", ServiceCheckItem::Forms, true, "kevin", "", 100);
        c.set(
            "2026-09",
            ServiceCheckItem::Forms,
            true,
            "someone-else",
            "client confirmed",
            999,
        );
        let m = c.month("2026-09").unwrap().get("forms").unwrap();
        assert_eq!(m.by, "kevin");
        assert_eq!(m.at, 100);
        assert_eq!(m.note, "client confirmed");
    }

    #[test]
    fn a_month_is_complete_only_when_all_four_are_ticked() {
        let mut c = CareServiceChecks::default();
        for (n, item) in ServiceCheckItem::ALL.into_iter().enumerate() {
            assert!(!c.is_complete("2026-09"));
            c.set("2026-09", item, true, "kevin", "", 100 + n as i64);
        }
        assert!(c.is_complete("2026-09"));
        // A different month is untouched by it.
        assert!(!c.is_complete("2026-10"));
    }

    #[test]
    fn history_is_trimmed_oldest_first() {
        let mut c = CareServiceChecks::default();
        for y in 2020..2026 {
            for m in 1..=12 {
                c.set(
                    &format!("{y}-{m:02}"),
                    ServiceCheckItem::Render,
                    true,
                    "k",
                    "",
                    1,
                );
            }
        }
        assert_eq!(c.periods.len(), KEEP_MONTHS);
        assert_eq!(c.periods.keys().next().unwrap(), "2024-01");
        assert_eq!(c.periods.keys().next_back().unwrap(), "2025-12");
    }

    #[test]
    fn period_key_is_utc_year_month() {
        // 2026-06-01 00:00:00 UTC
        assert_eq!(period_key(1_780_272_000), "2026-06");
    }

    #[test]
    fn previous_period_crosses_the_year() {
        assert_eq!(previous_period("2026-01").as_deref(), Some("2025-12"));
        assert_eq!(previous_period("2026-09").as_deref(), Some("2026-08"));
        assert_eq!(previous_period("nonsense"), None);
    }

    #[test]
    fn item_ids_round_trip() {
        for i in ServiceCheckItem::ALL {
            assert_eq!(ServiceCheckItem::parse(i.as_str()), Some(i));
        }
        assert_eq!(ServiceCheckItem::parse("gallery"), None);
    }
}

/// One site's care standing, as the dashboard needs it.
///
/// Assembled on the node that OWNS the hosting, because that is the only
/// place both halves live: the activations sit beside their hosting, and the
/// checklist sits in that node's `hosting_kv`. The panel fans out one call
/// per node rather than two per site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CareOverviewRow {
    pub hosting_id: String,
    pub domain: String,
    /// Names of the packages this site holds, for the badge.
    pub packages: Vec<String>,
    /// How many of the monthly items are ticked for the period asked about.
    pub checks_done: usize,
    pub checks_total: usize,
    /// Labels of what is still outstanding, so the card can say WHAT is
    /// missing rather than only that something is.
    pub outstanding: Vec<String>,
    /// Whether the previous month closed with work left — the state worth
    /// surfacing, because it can no longer be fixed.
    pub prev_outstanding: usize,
}

impl CareOverviewRow {
    pub fn is_complete(&self) -> bool {
        self.outstanding.is_empty()
    }
}
