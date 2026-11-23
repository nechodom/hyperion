//! How long each kind of log Hyperion writes is kept.
//!
//! Every class here holds visitors' or users' IP addresses (and often more:
//! user agents, requested URLs, e-mail addresses). Data minimisation under
//! the GDPR says to keep them only as long as they are needed, so every
//! class defaults to [`DEFAULT_DAYS`] and nothing is kept forever.
//!
//! `[log_retention]` in agent.toml, set on the master and copied to every
//! node by the settings sync. Each node reads it when its retention tick
//! runs, so a change needs no restart.

use serde::{Deserialize, Serialize};

/// What every class is kept for unless the operator says otherwise.
pub const DEFAULT_DAYS: u32 = 30;

/// A class may be kept this many days, inclusive. No "forever": a log that
/// is never cut is exactly what the setting exists to prevent.
pub const DAYS_RANGE: std::ops::RangeInclusive<u32> = 1..=3650;

/// One kind of log, as the settings card lists it.
pub struct LogClass {
    /// Key in `[log_retention]`.
    pub key: &'static str,
    /// The card's label.
    pub label: &'static str,
    /// What it is and what in it is personal data.
    pub what: &'static str,
}

/// Every class, in the order the card shows them.
pub const CLASSES: &[LogClass] = &[
    LogClass {
        key: "web_days",
        label: "Web server logs",
        what: "Each site's nginx access.log and error.log (visitor IP, URL, user agent) and PHP slow-request logs.",
    },
    LogClass {
        key: "firewall_days",
        label: "Firewall logs",
        what: "Requests the WAF or ModSecurity refused, as log files and as the samples on the Protection page.",
    },
    LogClass {
        key: "bans_days",
        label: "Ban history",
        what: "Addresses that were banned and when the ban ended. Bans still in force are never removed, nor those a care report not sent yet will count.",
    },
    LogClass {
        key: "audit_days",
        label: "Panel audit log",
        what: "Who changed what in the panel. The hash chain is re-anchored at the oldest entry kept. Kept longer while a care report still has to count its period's updates.",
    },
    LogClass {
        key: "email_days",
        label: "Email log",
        what: "Recipient addresses and subjects of the mail Hyperion sent (alerts, letters, invoices).",
    },
    LogClass {
        key: "sessions_days",
        label: "Panel sign-ins",
        what: "The IP address and browser panel sessions came from. Past the window they are erased; the session itself is kept until it has expired.",
    },
    LogClass {
        key: "notifications_days",
        label: "Notifications",
        what: "The bell's archive. Alerts name banned addresses, customers and recipients.",
    },
    LogClass {
        key: "system_days",
        label: "System journal",
        what: "The node's systemd journal: SSH and FTP logins, mail delivery, service logs (journald MaxRetentionSec).",
    },
];

/// `[log_retention]`: days each class is kept.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogRetention {
    pub web_days: u32,
    pub firewall_days: u32,
    pub bans_days: u32,
    pub audit_days: u32,
    pub email_days: u32,
    pub sessions_days: u32,
    pub notifications_days: u32,
    pub system_days: u32,
}

impl Default for LogRetention {
    fn default() -> Self {
        Self {
            web_days: DEFAULT_DAYS,
            firewall_days: DEFAULT_DAYS,
            bans_days: DEFAULT_DAYS,
            audit_days: DEFAULT_DAYS,
            email_days: DEFAULT_DAYS,
            sessions_days: DEFAULT_DAYS,
            notifications_days: DEFAULT_DAYS,
            system_days: DEFAULT_DAYS,
        }
    }
}

impl LogRetention {
    /// Built from whatever a config file holds. `num` looks a key up in
    /// `[log_retention]`; a key that is missing or not a whole number is the
    /// default, and one out of range is pulled into [`DAYS_RANGE`].
    ///
    /// `legacy_audit_days` is `[cluster] audit_retention_days`, where the
    /// audit window lived before this section. A positive value someone
    /// chose there is kept while `audit_days` is unset; its old default 0
    /// ("forever") is not, so an install that never chose moves to 30 days.
    pub fn from_lookup(num: impl Fn(&str) -> Option<i64>, legacy_audit_days: Option<i64>) -> Self {
        let n = |key: &str| {
            num(key)
                .map(|v| v.clamp(i64::from(*DAYS_RANGE.start()), i64::from(*DAYS_RANGE.end())))
                .map(|v| v as u32)
        };
        let legacy_audit = legacy_audit_days
            .filter(|d| *d > 0)
            .map(|d| d.min(i64::from(*DAYS_RANGE.end())) as u32);
        Self {
            web_days: n("web_days").unwrap_or(DEFAULT_DAYS),
            firewall_days: n("firewall_days").unwrap_or(DEFAULT_DAYS),
            bans_days: n("bans_days").unwrap_or(DEFAULT_DAYS),
            audit_days: n("audit_days").or(legacy_audit).unwrap_or(DEFAULT_DAYS),
            email_days: n("email_days").unwrap_or(DEFAULT_DAYS),
            sessions_days: n("sessions_days").unwrap_or(DEFAULT_DAYS),
            notifications_days: n("notifications_days").unwrap_or(DEFAULT_DAYS),
            system_days: n("system_days").unwrap_or(DEFAULT_DAYS),
        }
    }

    /// The value of class `key` (one of [`CLASSES`]).
    pub fn get(&self, key: &str) -> Option<u32> {
        Some(match key {
            "web_days" => self.web_days,
            "firewall_days" => self.firewall_days,
            "bans_days" => self.bans_days,
            "audit_days" => self.audit_days,
            "email_days" => self.email_days,
            "sessions_days" => self.sessions_days,
            "notifications_days" => self.notifications_days,
            "system_days" => self.system_days,
            _ => return None,
        })
    }

    /// True when every class is at [`DEFAULT_DAYS`].
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The shortest and longest window, for a one-line summary.
    pub fn span(&self) -> (u32, u32) {
        let all = CLASSES.iter().filter_map(|c| self.get(c.key));
        let min = all.clone().min().unwrap_or(DEFAULT_DAYS);
        let max = all.max().unwrap_or(DEFAULT_DAYS);
        (min, max)
    }
}

/// Is `key` a class of `[log_retention]`?
pub fn is_class(key: &str) -> bool {
    CLASSES.iter().any(|c| c.key == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_section_is_thirty_days_everywhere() {
        let r = LogRetention::from_lookup(|_| None, None);
        assert_eq!(r, LogRetention::default());
        for c in CLASSES {
            assert_eq!(r.get(c.key), Some(30), "{}", c.key);
        }
        assert!(r.is_default());
    }

    #[test]
    fn values_are_read_and_pulled_into_range() {
        let r = LogRetention::from_lookup(
            |k| match k {
                "web_days" => Some(14),
                "firewall_days" => Some(0),
                "bans_days" => Some(-5),
                "email_days" => Some(99_999),
                _ => None,
            },
            None,
        );
        assert_eq!(r.web_days, 14);
        assert_eq!(r.firewall_days, 1);
        assert_eq!(r.bans_days, 1);
        assert_eq!(r.email_days, 3650);
        assert_eq!(r.span(), (1, 3650));
    }

    #[test]
    fn the_old_audit_key_counts_only_when_someone_chose_a_window() {
        // Old default 0 = "forever": moves to 30.
        assert_eq!(LogRetention::from_lookup(|_| None, Some(0)).audit_days, 30);
        // A chosen window survives the move...
        assert_eq!(
            LogRetention::from_lookup(|_| None, Some(365)).audit_days,
            365
        );
        // ...until the new key says otherwise.
        let r = LogRetention::from_lookup(|k| (k == "audit_days").then_some(60), Some(365));
        assert_eq!(r.audit_days, 60);
    }

    #[test]
    fn every_class_has_a_getter() {
        let r = LogRetention::default();
        for c in CLASSES {
            assert!(is_class(c.key));
            assert!(r.get(c.key).is_some(), "{}", c.key);
        }
        assert!(!is_class("audit_retention_days"));
    }
}
