//! The node's ClamAV pass: when it runs, and what it has to show for itself.
//!
//! The pass is one `clamscan` over every scanned site on a node. Its schedule
//! is `[antivirus]` in agent.toml, set on the master and copied to every node
//! by the settings sync; each node reads it when its tick asks whether a pass
//! is due, so a change needs no restart.

use serde::{Deserialize, Serialize};

const DAY_SECS: i64 = 24 * 3600;
const HOUR_SECS: i64 = 3600;

/// `every_days` may be this, inclusive.
pub const EVERY_DAYS_RANGE: std::ops::RangeInclusive<u32> = 1..=30;
/// `min_free_memory_mb` may be this, inclusive. The signature database alone
/// is over a gigabyte once loaded, so less than that can't be asked for.
pub const MIN_FREE_MEMORY_MB_RANGE: std::ops::RangeInclusive<u32> = 1024..=65_536;

/// `[antivirus]`: when a node's ClamAV pass runs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AntivirusSettings {
    /// Off: no scheduled pass. One asked for by hand still runs.
    pub enabled: bool,
    /// A pass this many days after the last one began.
    pub every_days: u32,
    /// The pass may start from this local hour (0–23)...
    pub window_start_hour: u32,
    /// ...until this one, exclusive. Smaller than the start: the window runs
    /// past midnight. Equal to it: any hour.
    pub window_end_hour: u32,
    /// The pass starts only with this much memory available on the node.
    pub min_free_memory_mb: u32,
}

impl Default for AntivirusSettings {
    /// What every node did before the section existed: weekly, 02:00–06:00,
    /// with 2 GiB to spare.
    fn default() -> Self {
        Self {
            enabled: true,
            every_days: 7,
            window_start_hour: 2,
            window_end_hour: 6,
            min_free_memory_mb: 2048,
        }
    }
}

impl AntivirusSettings {
    /// Built from whatever a config file holds: a key that is missing or of
    /// the wrong type is the default, and a number out of range is pulled in.
    pub fn from_lookup(
        flag: impl Fn(&str) -> Option<bool>,
        num: impl Fn(&str) -> Option<i64>,
    ) -> Self {
        let d = Self::default();
        let n = |key: &str, fallback: u32| {
            num(key)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(fallback)
        };
        Self {
            enabled: flag("enabled").unwrap_or(d.enabled),
            every_days: n("every_days", d.every_days),
            window_start_hour: n("window_start_hour", d.window_start_hour),
            window_end_hour: n("window_end_hour", d.window_end_hour),
            min_free_memory_mb: n("min_free_memory_mb", d.min_free_memory_mb),
        }
        .sanitized()
    }

    /// The same settings with every number inside what the pass can honour.
    pub fn sanitized(mut self) -> Self {
        let d = Self::default();
        self.every_days = self
            .every_days
            .clamp(*EVERY_DAYS_RANGE.start(), *EVERY_DAYS_RANGE.end());
        if self.window_start_hour > 23 {
            self.window_start_hour = d.window_start_hour;
        }
        if self.window_end_hour > 23 {
            self.window_end_hour = d.window_end_hour;
        }
        self.min_free_memory_mb = self.min_free_memory_mb.clamp(
            *MIN_FREE_MEMORY_MB_RANGE.start(),
            *MIN_FREE_MEMORY_MB_RANGE.end(),
        );
        self
    }

    /// Whether a pass may start in this local hour.
    pub fn in_window(&self, hour: u32) -> bool {
        let (s, e) = (self.window_start_hour, self.window_end_hour);
        if s == e {
            true
        } else if s < e {
            (s..e).contains(&hour)
        } else {
            hour >= s || hour < e
        }
    }

    /// How long after one pass began the next may. Half a day short of the
    /// interval, so a pass that began late in its window doesn't push the next
    /// one past its night.
    pub fn min_age_secs(&self) -> i64 {
        i64::from(self.every_days) * DAY_SECS - 12 * HOUR_SECS
    }

    pub fn min_free_bytes(&self) -> u64 {
        u64::from(self.min_free_memory_mb) << 20
    }

    /// `2 GiB`, `1.5 GiB`: the memory threshold as people say it.
    pub fn min_free_text(&self) -> String {
        let mb = self.min_free_memory_mb;
        if mb % 1024 == 0 {
            format!("{} GiB", mb / 1024)
        } else {
            format!("{:.1} GiB", f64::from(mb) / 1024.0)
        }
    }

    /// `02:00–06:00`, or `any hour`.
    pub fn window_text(&self) -> String {
        if self.window_start_hour == self.window_end_hour {
            "any hour".into()
        } else {
            format!(
                "{:02}:00–{:02}:00",
                self.window_start_hour, self.window_end_hour
            )
        }
    }

    /// `every day`, `every 7 days`.
    pub fn every_text(&self) -> String {
        if self.every_days == 1 {
            "every day".into()
        } else {
            format!("every {} days", self.every_days)
        }
    }
}

/// How a pass ended, as stored and sent. Text, so an older panel can show a
/// word it has never seen.
pub mod pass_end {
    pub const COMPLETE: &str = "complete";
    pub const PARTIAL: &str = "partial";
    pub const OUT_OF_MEMORY: &str = "out_of_memory";
    pub const TIMED_OUT: &str = "timed_out";
    pub const FAILED: &str = "failed";
    pub const INTERRUPTED: &str = "interrupted";
}

/// One node's answer to `AntivirusOverview`: its ClamAV, its schedule, its
/// last pass and what that found on each site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AntivirusOverview {
    /// `clamscan` is on the node.
    pub installed: bool,
    /// Its signatures are downloaded.
    pub db_present: bool,
    /// `MemAvailable` right now, in bytes.
    pub mem_available: u64,
    /// The schedule as this node reads it.
    pub settings: AntivirusSettings,
    /// Unix seconds the running pass began; 0 when none runs.
    pub running_since: i64,
    /// The last pass that ran to an end: when it began, when it ended and how
    /// (one of [`pass_end`]). All zero / empty when none has.
    pub last_started: i64,
    pub last_finished: i64,
    pub last_end: String,
    /// Sites and files that pass was given, and what it detected.
    pub last_sites: u32,
    pub last_files: u64,
    pub last_hits: u32,
    /// Why a pass that was due (or asked for) did not start, and when that
    /// was decided. Gone once a pass starts.
    pub held: Option<String>,
    pub held_at: i64,
    /// A pass the kernel killed for memory isn't tried again before this.
    pub backoff_until: i64,
    /// Unix seconds the next scheduled pass may start at the earliest; 0 when
    /// none is scheduled (switched off, or ClamAV isn't installed).
    pub next_due_at: i64,
    /// Someone asked for a pass and the tick has not picked it up yet.
    pub run_requested: bool,
    /// Every site the pass covers on this node.
    pub sites: Vec<AntivirusSite>,
}

/// One site, as the pass last left it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AntivirusSite {
    pub hosting_id: String,
    pub domain: String,
    /// Unix seconds of the last pass that covered this site; 0 = never.
    pub covered_at: i64,
    /// What the last pass left out here, or why it said nothing.
    pub note: Option<String>,
    /// Detections, the first [`MAX_HITS_SENT`] of them.
    pub hits: Vec<crate::WpMalwareHit>,
    /// All of them, counted.
    pub hits_total: u32,
    /// What the file scan (not ClamAV) holds against this site: findings, and
    /// changes waiting for a look.
    pub file_findings: u32,
    pub file_review: u32,
}

/// Detections one site sends to the overview. Its own card lists them all.
pub const MAX_HITS_SENT: usize = 50;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_what_nodes_did_before_the_section_existed() {
        let s = AntivirusSettings::default();
        assert!(s.enabled);
        assert_eq!(s.min_age_secs(), 6 * DAY_SECS + 12 * HOUR_SECS);
        assert_eq!(s.min_free_bytes(), 2 << 30);
        assert!(!s.in_window(1) && s.in_window(2) && s.in_window(5) && !s.in_window(6));
        assert_eq!(s.window_text(), "02:00–06:00");
        assert_eq!(s.min_free_text(), "2 GiB");
        assert_eq!(s.every_text(), "every 7 days");
    }

    #[test]
    fn a_window_can_cross_midnight_or_be_the_whole_day() {
        let mut s = AntivirusSettings {
            window_start_hour: 22,
            window_end_hour: 4,
            ..Default::default()
        };
        assert!(s.in_window(22) && s.in_window(23) && s.in_window(0) && s.in_window(3));
        assert!(!s.in_window(4) && !s.in_window(12) && !s.in_window(21));
        s.window_end_hour = 22;
        assert!((0..24).all(|h| s.in_window(h)));
        assert_eq!(s.window_text(), "any hour");
    }

    #[test]
    fn a_hand_edited_file_is_pulled_into_range() {
        let s = AntivirusSettings::from_lookup(
            |_| None,
            |k| match k {
                "every_days" => Some(0),
                "window_start_hour" => Some(99),
                "window_end_hour" => Some(-3),
                "min_free_memory_mb" => Some(64),
                _ => None,
            },
        );
        assert!(s.enabled);
        assert_eq!(s.every_days, 1);
        assert_eq!(s.window_start_hour, 2);
        assert_eq!(s.window_end_hour, 6);
        assert_eq!(s.min_free_memory_mb, 1024);
        assert_eq!(s.every_text(), "every day");
        let odd = AntivirusSettings {
            min_free_memory_mb: 1536,
            ..Default::default()
        };
        assert_eq!(odd.min_free_text(), "1.5 GiB");
    }
}
