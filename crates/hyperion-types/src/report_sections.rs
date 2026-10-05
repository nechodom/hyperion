//! Which sections of the care report a plan sends.
//!
//! The customer letter is built from eight sections (`{attacks}`, `{updates}`,
//! …). A plan may not want to send all of them: a cheap plan that sells no
//! uptime monitoring has nothing honest to say under "Availability", and a
//! plan sold on backups alone should not carry a page of attack statistics.
//!
//! The choice is stored as the sections that are LEFT OUT, never the ones that
//! are kept:
//!
//! * empty means "send everything", which is what every plan meant before this
//!   existed — an upgrade changes no letter;
//! * a section added to the product later is sent by default instead of being
//!   silently absent from every plan that already saved a list.
//!
//! Left-out is a deliberate editorial choice by the operator and is NOT the
//! same thing as "not measured". A section the plan leaves out is never
//! mentioned, never counted towards "nothing was measured", and never gets the
//! "we could not measure X" disclosure — the customer did not buy it.
//!
//! The choice lives on the care PACKAGE and is snapshotted onto each activation
//! (see `hosting_packages.report_omit`): the letter is rendered on the node
//! that owns the hosting, where the package definitions do not exist.

use serde::{Deserialize, Serialize};

/// One section of the care report. The wire/stored id is also the name of the
/// `{placeholder}` the section renders into, so there is one spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSection {
    Attacks,
    Updates,
    Traffic,
    Uptime,
    Backups,
    Integrity,
    Performance,
    Service,
}

impl ReportSection {
    /// In the order the built-in letter prints them.
    pub const ALL: [ReportSection; 8] = [
        ReportSection::Attacks,
        ReportSection::Updates,
        ReportSection::Traffic,
        ReportSection::Uptime,
        ReportSection::Backups,
        ReportSection::Integrity,
        ReportSection::Performance,
        ReportSection::Service,
    ];

    /// Stored id and `{placeholder}` name.
    pub fn as_str(self) -> &'static str {
        match self {
            ReportSection::Attacks => "attacks",
            ReportSection::Updates => "updates",
            ReportSection::Traffic => "traffic",
            ReportSection::Uptime => "uptime",
            ReportSection::Backups => "backups",
            ReportSection::Integrity => "integrity",
            ReportSection::Performance => "performance",
            ReportSection::Service => "service",
        }
    }

    pub fn parse(s: &str) -> Option<ReportSection> {
        let s = s.trim();
        ReportSection::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// Operator-facing name, for the plan editor and the plan list.
    pub fn label(self) -> &'static str {
        match self {
            ReportSection::Attacks => "Attacks blocked",
            ReportSection::Updates => "Updates applied",
            ReportSection::Traffic => "Traffic and disk",
            ReportSection::Uptime => "Availability",
            ReportSection::Backups => "Backups",
            ReportSection::Integrity => "Integrity scan",
            ReportSection::Performance => "Speed and Core Web Vitals",
            ReportSection::Service => "Monthly service checks",
        }
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// The set of sections a plan leaves OUT of the customer letter.
///
/// `Default` is the empty set: everything is sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReportOmit(u8);

impl ReportOmit {
    /// Nothing left out — every section is sent.
    pub const NONE: ReportOmit = ReportOmit(0);

    /// Parse a stored comma list. Unknown ids are ignored rather than
    /// rejected: a master that is one release ahead may know a section this
    /// node does not, and failing the whole value would make this node send
    /// the sections the plan meant to leave out.
    pub fn parse(raw: &str) -> Self {
        let mut out = ReportOmit::NONE;
        for part in raw.split(',') {
            if let Some(s) = ReportSection::parse(part) {
                out = out.with(s);
            }
        }
        out
    }

    /// Canonical stored form: known ids in letter order, comma separated.
    /// Empty string for the empty set — which is what an untouched plan
    /// stores, so a plan that never used this keeps a byte-identical row.
    pub fn to_stored(self) -> String {
        ReportSection::ALL
            .into_iter()
            .filter(|s| self.contains(*s))
            .map(ReportSection::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn from_sections(sections: impl IntoIterator<Item = ReportSection>) -> Self {
        sections
            .into_iter()
            .fold(ReportOmit::NONE, ReportOmit::with)
    }

    pub fn with(self, s: ReportSection) -> Self {
        ReportOmit(self.0 | s.bit())
    }

    /// True when `s` is LEFT OUT of the letter.
    pub fn contains(self, s: ReportSection) -> bool {
        self.0 & s.bit() != 0
    }

    /// True when `s` is sent.
    pub fn sends(self, s: ReportSection) -> bool {
        !self.contains(s)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// How many sections the letter carries.
    pub fn sent_count(self) -> usize {
        ReportSection::ALL
            .into_iter()
            .filter(|s| self.sends(*s))
            .count()
    }

    /// Every section is left out — a letter with no body at all. A plan must
    /// never be saved like this; to send no report, set the cadence to off.
    pub fn leaves_out_everything(self) -> bool {
        self.sent_count() == 0
    }

    /// What a site holding several report-selling plans sends: a section goes
    /// out when ANY of them includes it, so it is left out only when EVERY one
    /// leaves it out. Same direction as the cadence fold ("the more generous
    /// promise wins") — a customer who pays for two plans never receives less
    /// than either of them sells.
    ///
    /// No plans at all folds to the empty set: nothing is hidden by a plan
    /// that does not exist.
    pub fn fold_sites(sets: impl IntoIterator<Item = ReportOmit>) -> ReportOmit {
        let mut acc: Option<u8> = None;
        for s in sets {
            acc = Some(acc.map_or(s.0, |a| a & s.0));
        }
        ReportOmit(acc.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_match_the_placeholder_names() {
        for s in ReportSection::ALL {
            assert_eq!(ReportSection::parse(s.as_str()), Some(s));
        }
        assert_eq!(
            ReportSection::parse(" uptime "),
            Some(ReportSection::Uptime)
        );
        assert_eq!(ReportSection::parse("nope"), None);
        assert_eq!(ReportSection::parse(""), None);
    }

    #[test]
    fn empty_stored_value_sends_everything() {
        let o = ReportOmit::parse("");
        assert!(o.is_empty());
        assert_eq!(o.sent_count(), 8);
        assert_eq!(o.to_stored(), "");
    }

    #[test]
    fn stored_form_is_canonical_and_ignores_unknown_ids() {
        // Out of order, duplicated, padded, and one id from a newer release.
        let o = ReportOmit::parse(" uptime ,attacks,uptime,from_the_future,");
        assert_eq!(o.to_stored(), "attacks,uptime");
        assert!(o.contains(ReportSection::Attacks));
        assert!(o.sends(ReportSection::Backups));
        assert_eq!(o.sent_count(), 6);
    }

    #[test]
    fn leaving_out_everything_is_detectable() {
        let all = ReportOmit::from_sections(ReportSection::ALL);
        assert!(all.leaves_out_everything());
        assert!(!ReportOmit::NONE.leaves_out_everything());
        assert!(!all.sends(ReportSection::Service));
    }

    #[test]
    fn two_plans_send_the_union() {
        let a = ReportOmit::parse("attacks,uptime,traffic");
        let b = ReportOmit::parse("uptime,integrity");
        // Left out only where BOTH leave it out.
        assert_eq!(ReportOmit::fold_sites([a, b]).to_stored(), "uptime");
        // A plan that sends everything makes the site send everything.
        assert!(ReportOmit::fold_sites([a, ReportOmit::NONE]).is_empty());
    }

    #[test]
    fn no_plans_hide_nothing() {
        assert!(ReportOmit::fold_sites([]).is_empty());
    }
}
