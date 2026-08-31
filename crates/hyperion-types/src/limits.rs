//! Public wire types for hosting limits + suspension state.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingLimits {
    /// `None` = no enforced limit.
    pub disk_soft_bytes: Option<i64>,
    pub disk_hard_bytes: Option<i64>,
    pub inode_soft: Option<i64>,
    pub inode_hard: Option<i64>,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub bw_monthly_bytes: Option<i64>,
    pub over_bw_policy: OverBwPolicy,
    pub throttle_kbps: Option<i64>,
}

impl HostingLimits {
    pub fn defaults() -> Self {
        Self {
            disk_soft_bytes: None,
            disk_hard_bytes: None,
            inode_soft: None,
            inode_hard: None,
            php_memory_mb: 256,
            php_max_exec_secs: 60,
            php_max_children: 5,
            php_max_requests: 1000,
            db_max_connections: 25,
            bw_monthly_bytes: None,
            over_bw_policy: OverBwPolicy::Suspend,
            throttle_kbps: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OverBwPolicy {
    Suspend,
    Throttle,
}

impl OverBwPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Throttle => "throttle",
        }
    }
}

impl FromStr for OverBwPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "suspend" => Ok(Self::Suspend),
            "throttle" => Ok(Self::Throttle),
            other => Err(format!("unknown policy: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SuspendReason {
    Manual { message: Option<String> },
    Expired,
    OverBandwidth,
    OverDisk,
}

impl SuspendReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Manual { .. } => "manual",
            Self::Expired => "expired",
            Self::OverBandwidth => "over-bandwidth",
            Self::OverDisk => "over-disk",
        }
    }
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Manual { message } => message.as_deref(),
            Self::Expired => Some("This site has expired."),
            Self::OverBandwidth => Some("This site exceeded its bandwidth allowance."),
            Self::OverDisk => Some("This site exceeded its disk allowance."),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingUsageBucket {
    pub period: String,
    pub disk_used_bytes: i64,
    pub inodes_used: i64,
    pub bw_in_bytes: i64,
    pub bw_out_bytes: i64,
    pub php_requests: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingExpiry {
    /// `None` = no expiry. Otherwise unix-epoch seconds.
    ///
    /// Always in the FUTURE once stored: an operator who types a past date is
    /// naming the day and month the hosting renews on, and the year they took
    /// it on — see [`next_anniversary`].
    pub expires_at: Option<i64>,
    pub owner_email: Option<String>,
    pub grace_days: i64,
    /// CSV like "30,7,1" — days before expiry to send warnings.
    pub warning_offsets_days: String,
    /// The date the operator originally typed, when it was in the past.
    ///
    /// `expires_at` is rolled forward to the next occurrence of that day and
    /// month, which throws the year away — and the year is the useful part:
    /// it says since when the hosting has been with us. Kept so the panel can
    /// show it. `None` when the operator typed a future date, which carries
    /// no such information.
    #[serde(default)]
    pub customer_since: Option<i64>,
}

/// The next occurrence of `entered`'s day and month, at or after `now`.
///
/// The renewal date of a hosting is a day and a month; the year an operator
/// types is how they record when the customer came to us. Typing 2024-03-15
/// in 2026 has to mean "renews on 15 March, with us since 2024" — taken
/// literally it would mean the hosting expired two years ago, and the
/// scheduler would suspend a live customer site the moment it was saved.
///
/// A future date is returned unchanged, so the ordinary case — naming the
/// actual date a contract ends — behaves exactly as it always has. Only a
/// past date changes meaning, and a past date could not previously express
/// anything an operator wanted.
///
/// 29 February falls back to the 28th in a common year rather than skipping
/// to 1 March: the renewal stays in February, which is what someone who chose
/// the end of February meant.
pub fn next_anniversary(entered: i64, now: i64) -> i64 {
    use chrono::{Datelike, NaiveDate, TimeZone, Utc};
    if entered > now {
        return entered;
    }
    let (Some(e), Some(n)) = (
        Utc.timestamp_opt(entered, 0).single(),
        Utc.timestamp_opt(now, 0).single(),
    ) else {
        return entered;
    };
    let (month, day, time) = (e.month(), e.day(), e.time());
    // At most two iterations in practice: this year, else the next. The bound
    // is a backstop so a nonsensical clock cannot spin here.
    for year in n.year()..=n.year().saturating_add(4) {
        let candidate = NaiveDate::from_ymd_opt(year, month, day).or_else(|| {
            (month == 2 && day == 29)
                .then(|| NaiveDate::from_ymd_opt(year, 2, 28))
                .flatten()
        });
        if let Some(d) = candidate {
            let ts = d.and_time(time).and_utc().timestamp();
            if ts > now {
                return ts;
            }
        }
    }
    entered
}

impl HostingExpiry {
    pub fn defaults() -> Self {
        Self {
            expires_at: None,
            owner_email: None,
            customer_since: None,
            grace_days: 30,
            warning_offsets_days: "30,7,1".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpiringHosting {
    pub id: crate::HostingId,
    pub domain: String,
    pub expires_at: i64,
    pub owner_email: Option<String>,
    pub grace_days: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupRunWire {
    pub id: i64,
    pub hosting_id: crate::HostingId,
    pub target: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub state: String,
    pub archive_path: Option<String>,
    pub db_dump_path: Option<String>,
    pub bytes_total: i64,
    pub error_message: Option<String>,
}

/// What a `BackupRestore` should put back. Lets the operator restore
/// just the database (e.g. after a bad plugin update mangled options)
/// without clobbering files they've changed since, or just the files
/// without rolling back the DB.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackupRestoreMode {
    /// Full restore — extract the archive over htdocs AND import the
    /// sibling SQL dump. The historical behaviour.
    #[default]
    FilesAndDb,
    /// Import the SQL dump only; leave htdocs untouched.
    DbOnly,
    /// Extract the archive over htdocs only; leave the database alone.
    FilesOnly,
}

impl BackupRestoreMode {
    pub fn restores_files(self) -> bool {
        matches!(self, Self::FilesAndDb | Self::FilesOnly)
    }
    pub fn restores_db(self) -> bool {
        matches!(self, Self::FilesAndDb | Self::DbOnly)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilesAndDb => "files_and_db",
            Self::DbOnly => "db_only",
            Self::FilesOnly => "files_only",
        }
    }
}

/// One IP ban as shown in the UI / returned over the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IpBanWire {
    pub id: i64,
    pub ip: String,
    pub hosting_id: Option<String>,
    pub reason: String,
    /// "auto" | "manual".
    pub source: String,
    pub banned_at: i64,
    /// 0 = permanent.
    pub expires_at: i64,
}

#[cfg(test)]
mod restore_mode_tests {
    use super::BackupRestoreMode;

    #[test]
    fn mode_gates() {
        assert!(BackupRestoreMode::FilesAndDb.restores_files());
        assert!(BackupRestoreMode::FilesAndDb.restores_db());
        assert!(BackupRestoreMode::DbOnly.restores_db());
        assert!(!BackupRestoreMode::DbOnly.restores_files());
        assert!(BackupRestoreMode::FilesOnly.restores_files());
        assert!(!BackupRestoreMode::FilesOnly.restores_db());
    }

    #[test]
    fn default_is_full() {
        assert_eq!(BackupRestoreMode::default(), BackupRestoreMode::FilesAndDb);
    }

    #[test]
    fn round_trips_snake_case() {
        let j = serde_json::to_string(&BackupRestoreMode::DbOnly).unwrap();
        assert_eq!(j, "\"db_only\"");
        let back: BackupRestoreMode = serde_json::from_str(&j).unwrap();
        assert_eq!(back, BackupRestoreMode::DbOnly);
    }
}

/// One pending node enrollment invite — what the operator sees in /install.
/// The plaintext token is NEVER persisted; it's returned only once when
/// the invite is minted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInviteSummary {
    pub token_hash: String,
    pub label: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// What `invite_create` returns: the freshly-minted plaintext token (so
/// the UI can paste it into the install command) + its hash for revoke.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInviteMint {
    pub token: String,
    pub token_hash: String,
    pub label: String,
    pub expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let l = HostingLimits::defaults();
        assert_eq!(l.php_memory_mb, 256);
        assert_eq!(l.over_bw_policy, OverBwPolicy::Suspend);
        assert!(l.disk_hard_bytes.is_none());
    }

    #[test]
    fn limits_round_trip() {
        let l = HostingLimits::defaults();
        let s = serde_json::to_string(&l).expect("ser");
        let back: HostingLimits = serde_json::from_str(&s).expect("de");
        assert_eq!(l, back);
    }

    #[test]
    fn policy_str_round_trip() {
        for p in [OverBwPolicy::Suspend, OverBwPolicy::Throttle] {
            assert_eq!(OverBwPolicy::from_str(p.as_str()).unwrap(), p);
        }
    }

    #[test]
    fn suspend_reason_round_trip() {
        let r = SuspendReason::Manual {
            message: Some("over quota".into()),
        };
        let s = serde_json::to_string(&r).expect("ser");
        let back: SuspendReason = serde_json::from_str(&s).expect("de");
        assert_eq!(r, back);
        let r = SuspendReason::Expired;
        let s = serde_json::to_string(&r).expect("ser");
        let back: SuspendReason = serde_json::from_str(&s).expect("de");
        assert_eq!(r, back);
    }
}

#[cfg(test)]
mod anniversary_tests {
    use super::next_anniversary;
    use chrono::{NaiveDate, TimeZone, Utc};

    fn ts(y: i32, m: u32, d: u32) -> i64 {
        NaiveDate::from_ymd_opt(y, m, d)
            .expect("valid date")
            .and_hms_opt(0, 0, 0)
            .expect("valid time")
            .and_utc()
            .timestamp()
    }

    fn ymd(t: i64) -> String {
        Utc.timestamp_opt(t, 0)
            .single()
            .expect("valid timestamp")
            .format("%Y-%m-%d")
            .to_string()
    }

    /// The ordinary case is untouched: an operator naming the actual date a
    /// contract ends still gets exactly that date.
    #[test]
    fn a_future_date_is_left_alone() {
        let now = ts(2026, 8, 31);
        for d in [ts(2026, 9, 1), ts(2027, 3, 15), ts(2030, 12, 31)] {
            assert_eq!(next_anniversary(d, now), d, "{} moved", ymd(d));
        }
    }

    /// The point of the change: 2024 means "renews 15 March, with us since
    /// 2024", not "expired two years ago" — which would have suspended a live
    /// customer site as soon as it was saved.
    #[test]
    fn a_past_date_rolls_to_the_next_occurrence_of_its_day_and_month() {
        let now = ts(2026, 8, 31);
        // 15 March has already passed this year, so it is next year's.
        assert_eq!(ymd(next_anniversary(ts(2024, 3, 15), now)), "2027-03-15");
        // 1 December has NOT passed yet, so it is this year's.
        assert_eq!(ymd(next_anniversary(ts(2019, 12, 1), now)), "2026-12-01");
    }

    /// Today is not "still to come": a hosting whose renewal day is today has
    /// already reached it, so the next one is a year out. Returning today
    /// would hand the scheduler a date it treats as due immediately.
    #[test]
    fn todays_date_rolls_to_next_year() {
        let now = ts(2026, 8, 31);
        assert_eq!(ymd(next_anniversary(ts(2020, 8, 31), now)), "2027-08-31");
    }

    /// 29 February exists once every four years. Falling through to 1 March
    /// would move the renewal into another month; the 28th keeps it where the
    /// operator put it.
    #[test]
    fn the_twenty_ninth_of_february_falls_back_to_the_twenty_eighth() {
        assert_eq!(
            ymd(next_anniversary(ts(2024, 2, 29), ts(2026, 6, 1))),
            "2027-02-28"
        );
        // …and is honoured exactly in a leap year.
        assert_eq!(
            ymd(next_anniversary(ts(2024, 2, 29), ts(2027, 6, 1))),
            "2028-02-29"
        );
    }

    /// Whatever goes in, what comes out must be in the future — that is the
    /// invariant the scheduler relies on, and the reason this function exists.
    #[test]
    fn the_result_is_never_in_the_past() {
        let now = ts(2026, 8, 31);
        for y in 1971..=2030 {
            for (m, d) in [(1, 1), (2, 28), (2, 29), (6, 30), (8, 31), (12, 31)] {
                let Some(date) = NaiveDate::from_ymd_opt(y, m, d) else {
                    continue;
                };
                let entered = date
                    .and_hms_opt(0, 0, 0)
                    .expect("valid time")
                    .and_utc()
                    .timestamp();
                let out = next_anniversary(entered, now);
                assert!(
                    out > now,
                    "{} -> {} is not in the future",
                    ymd(entered),
                    ymd(out)
                );
            }
        }
    }
}
