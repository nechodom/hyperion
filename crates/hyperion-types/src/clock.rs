//! Turning a stored instant into something a person reads.
//!
//! # Why storage stays UTC
//!
//! Every timestamp in hyperion is a Unix second, and every comparison,
//! retention window and period key is computed in UTC. That does not change
//! here and must not: two operators in different places, or the same operator
//! either side of a DST change, have to agree which month a tick belongs to,
//! and a local-time key would silently split one month into two.
//!
//! So this is a DISPLAY concern only. The zone is applied at the last possible
//! moment — the instant a time is rendered — and nowhere else.
//!
//! # Why a real zone and not an offset
//!
//! An operator in Prague is at +01:00 for half the year and +02:00 for the
//! other half. A stored offset would be right when they set it and an hour
//! wrong from late October, in a letter a customer reads, with nothing on
//! screen to explain it.

use serde::{Deserialize, Serialize};

/// The zone times are shown in. Empty or unrecognised means UTC.
///
/// Kept as a string rather than a parsed zone so an unknown name — a typo, or
/// a zone a future tzdata knows and this build does not — round-trips through
/// config instead of being silently rewritten to something else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayZone(pub String);

impl Default for DisplayZone {
    /// UTC, which is what every install did before this existed.
    fn default() -> Self {
        DisplayZone("UTC".to_string())
    }
}

impl DisplayZone {
    pub fn parse(s: &str) -> Self {
        let t = s.trim();
        if t.is_empty() {
            return Self::default();
        }
        DisplayZone(t.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Is this a zone this build actually knows?
    ///
    /// Used to REFUSE a bad value at the settings boundary rather than to
    /// correct it silently: an operator who types `Europe/Praha` should be
    /// told, not quietly given UTC and left wondering why the times are off.
    pub fn is_known(&self) -> bool {
        self.0.parse::<chrono_tz::Tz>().is_ok()
    }

    fn tz(&self) -> chrono_tz::Tz {
        self.0.parse().unwrap_or(chrono_tz::UTC)
    }

    /// `2026-09-14 18:42:07 CEST` — the exact moment, with the zone named.
    ///
    /// The abbreviation is not decoration. Without it the reader cannot tell
    /// whether they are looking at their own wall clock or the server's, and
    /// an hour's ambiguity in a record of who did what and when is the whole
    /// reason this function exists.
    pub fn exact(&self, ts: i64) -> String {
        match chrono::DateTime::from_timestamp(ts, 0) {
            Some(dt) => dt
                .with_timezone(&self.tz())
                .format("%Y-%m-%d %H:%M:%S %Z")
                .to_string(),
            // A timestamp outside the representable range is a bug upstream,
            // and printing an em dash beats printing the epoch.
            None => "—".to_string(),
        }
    }

    /// `14 Sep 2026, 18:42 CEST` — same instant, easier on the eye.
    pub fn friendly(&self, ts: i64) -> String {
        match chrono::DateTime::from_timestamp(ts, 0) {
            Some(dt) => dt
                .with_timezone(&self.tz())
                .format("%-d %b %Y, %H:%M %Z")
                .to_string(),
            None => "—".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DisplayZone;

    /// The reason this is a zone and not an offset: the same zone name gives
    /// different wall clocks in summer and winter, and gets it right by
    /// itself.
    #[test]
    fn a_real_zone_follows_daylight_saving_on_its_own() {
        let prague = DisplayZone("Europe/Prague".into());
        // 2026-01-15 12:00:00 UTC — winter, CET (+01).
        let winter = prague.exact(1_768_478_400);
        // 2026-07-15 12:00:00 UTC — summer, CEST (+02).
        let summer = prague.exact(1_784_116_800);
        assert!(winter.contains("13:00:00 CET"), "{winter}");
        assert!(summer.contains("14:00:00 CEST"), "{summer}");
    }

    /// An unknown zone must be REFUSED at the boundary, not silently turned
    /// into UTC — an operator who mistypes should be told.
    #[test]
    fn an_unknown_zone_is_reported_rather_than_corrected() {
        assert!(DisplayZone("Europe/Prague".into()).is_known());
        assert!(DisplayZone("UTC".into()).is_known());
        assert!(!DisplayZone("Europe/Praha".into()).is_known());
        assert!(!DisplayZone("+02:00".into()).is_known());
        // …but if one ever gets stored, rendering still works rather than
        // panicking, and falls back to UTC.
        let bad = DisplayZone("Nowhere/Nothing".into());
        assert!(bad.exact(1_768_478_400).contains("12:00:00 UTC"));
    }

    #[test]
    fn empty_means_utc_which_is_what_every_install_did_before() {
        assert_eq!(DisplayZone::parse("  "), DisplayZone::default());
        assert_eq!(DisplayZone::default().as_str(), "UTC");
    }
}
