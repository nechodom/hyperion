//! The monthly service check: the part of a care plan a machine cannot do.
//!
//! Most of what a care plan sells, hyperion does by itself and can prove —
//! backups ran, updates applied, malware scan came back clean. Four items on
//! the list are not like that. Whether the gallery still renders, whether the
//! contact form's mail actually arrives, whether the site still feels fast,
//! whether last week's plugin update broke a layout: those need a person to
//! look, and a plan that promises them without recording that anybody did is
//! selling something nobody delivers.
//!
//! So each site carries a per-month checklist. It is bookkeeping, not
//! measurement, and it says so: a tick means "an operator confirmed they did
//! this", nothing more. Untouched is UNDONE — never "probably fine" — because
//! the whole point is to make an unlooked-at month visible before the customer
//! finds it.
//!
//! Stored as one JSON value in `hosting_kv` under `care_service_checks`, on
//! the node that owns the hosting, which is also where the customer's report
//! is assembled.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One thing a person has to look at every month.
///
/// Deliberately a closed set. An operator inventing their own items per site
/// gives every site a different definition of "checked", and then "is this
/// month done?" has no answer across the estate — which is the one question
/// the dashboard has to answer.
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

/// Everything ticked in one month, keyed by item id.
pub type ServiceCheckMonth = BTreeMap<String, ServiceCheckMark>;

/// The whole history, keyed by `YYYY-MM`.
///
/// `#[serde(transparent)]` so the stored JSON is just the map — a shape that
/// stays readable in the database and survives a future field being added
/// beside it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CareServiceChecks(pub BTreeMap<String, ServiceCheckMonth>);

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
        serde_json::from_str(raw).unwrap_or_default()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn month(&self, period: &str) -> Option<&ServiceCheckMonth> {
        self.0.get(period)
    }

    pub fn is_checked(&self, period: &str, item: ServiceCheckItem) -> bool {
        self.month(period)
            .map(|m| m.contains_key(item.as_str()))
            .unwrap_or(false)
    }

    /// Items still outstanding for `period`, in list order.
    pub fn outstanding(&self, period: &str) -> Vec<ServiceCheckItem> {
        ServiceCheckItem::ALL
            .into_iter()
            .filter(|i| !self.is_checked(period, *i))
            .collect()
    }

    pub fn is_complete(&self, period: &str) -> bool {
        self.outstanding(period).is_empty()
    }

    pub fn done_count(&self, period: &str) -> usize {
        ServiceCheckItem::ALL.len() - self.outstanding(period).len()
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
            self.0.entry(period.to_string()).or_default().insert(
                item.as_str().to_string(),
                ServiceCheckMark {
                    at: now,
                    by: by.to_string(),
                    note: note.to_string(),
                },
            );
        } else if let Some(m) = self.0.get_mut(period) {
            m.remove(item.as_str());
            if m.is_empty() {
                self.0.remove(period);
            }
        }
        self.trim();
    }

    /// Keep only the most recent [`KEEP_MONTHS`] periods. `BTreeMap` orders
    /// `YYYY-MM` keys chronologically, which is the one thing that makes
    /// this a two-line operation rather than a date-parsing exercise.
    fn trim(&mut self) {
        while self.0.len() > KEEP_MONTHS {
            let Some(oldest) = self.0.keys().next().cloned() else {
                break;
            };
            self.0.remove(&oldest);
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
        c.set("2026-09", ServiceCheckItem::Render, true, "kevin", "ok", 100);
        assert!(c.is_checked("2026-09", ServiceCheckItem::Render));
        assert_eq!(c.done_count("2026-09"), 1);
        assert_eq!(c.outstanding("2026-09").len(), 3);

        let round = CareServiceChecks::parse(&c.to_json());
        assert_eq!(round, c);

        c.set("2026-09", ServiceCheckItem::Render, false, "kevin", "", 200);
        assert!(!c.is_checked("2026-09", ServiceCheckItem::Render));
        // The month emptied out entirely, so it leaves no husk behind.
        assert!(c.month("2026-09").is_none());
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
        assert_eq!(c.0.len(), KEEP_MONTHS);
        assert_eq!(c.0.keys().next().unwrap(), "2024-01");
        assert_eq!(c.0.keys().next_back().unwrap(), "2025-12");
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
