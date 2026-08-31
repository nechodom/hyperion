//! PHP version enum — strict allow-list.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhpVersion {
    V8_1,
    V8_2,
    V8_3,
    V8_4,
}

impl PhpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V8_1 => "8.1",
            Self::V8_2 => "8.2",
            Self::V8_3 => "8.3",
            Self::V8_4 => "8.4",
        }
    }

    /// e.g. "php8.3-fpm" — used in `apt install` and `systemctl reload`.
    pub fn service_name(self) -> String {
        format!("php{}-fpm", self.as_str())
    }

    /// Directory containing FPM pool .conf files for this major.minor.
    pub fn pool_dir(self) -> String {
        format!("/etc/php/{}/fpm/pool.d", self.as_str())
    }

    /// Path to the per-user FPM socket.
    pub fn socket_path(self, system_user: &str) -> String {
        format!("/run/php/{}/{}.sock", self.as_str(), system_user)
    }

    pub fn all() -> &'static [PhpVersion] {
        &[Self::V8_1, Self::V8_2, Self::V8_3, Self::V8_4]
    }

    /// The supported version closest to what another panel reported.
    ///
    /// [`FromStr`] is an exact allow-list and must stay one — it guards every
    /// place a version is chosen deliberately. Importing is the opposite
    /// problem: the source names a version we do NOT support, and refusing it
    /// is the worst possible answer. A CloudPanel box running PHP 7.4 or 8.0
    /// is exactly the box people migrate away from, and CloudPanel also
    /// reports patch levels like `8.2.10`, which the allow-list rejects for
    /// being too precise.
    ///
    /// Discarding the value instead — which is what `.parse().ok()` did —
    /// created the site with NO version at all, so every WordPress action
    /// answered "requires a PHP hosting" on a site the import had just
    /// reported as successful.
    ///
    /// Returns the version and whether it had to be substituted, so the
    /// caller can tell the operator that a 7.4 site is now on 8.1 and its
    /// code may need attention. `None` only when nothing numeric is there at
    /// all.
    pub fn nearest_supported(raw: &str) -> Option<(Self, bool)> {
        let cleaned = raw.trim().trim_start_matches("php").trim_start_matches('-');
        let mut parts = cleaned.split('.').map(str::trim);
        let major: u32 = parts.next()?.parse().ok()?;
        // "8" alone means the 8 series; treat the minor as 0 so it lands on
        // the lowest supported 8.x rather than being thrown away.
        let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);

        let exact = match (major, minor) {
            (8, 1) => Some(Self::V8_1),
            (8, 2) => Some(Self::V8_2),
            (8, 3) => Some(Self::V8_3),
            (8, 4) => Some(Self::V8_4),
            _ => None,
        };
        if let Some(v) = exact {
            return Some((v, false));
        }
        // Older than anything supported — 5.x, 7.x, 8.0 — lands on the
        // lowest supported version, which is the least disruptive place for
        // legacy code. Newer than we know lands on the highest.
        Some(if (major, minor) < (8, 1) {
            (Self::V8_1, true)
        } else {
            (Self::V8_4, true)
        })
    }
}

impl fmt::Display for PhpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PhpVersion {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "8.1" => Ok(Self::V8_1),
            "8.2" => Ok(Self::V8_2),
            "8.3" => Ok(Self::V8_3),
            "8.4" => Ok(Self::V8_4),
            _ => Err(format!("unsupported php version: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_versions_accepted() {
        for v in ["8.1", "8.2", "8.3", "8.4"] {
            assert!(PhpVersion::from_str(v).is_ok(), "should accept {v}");
        }
    }

    #[test]
    fn unsupported_versions_rejected() {
        for v in ["7.4", "9.0", "", "8", "8.1.0", " 8.3", "8.3 ", "PHP8.3"] {
            assert!(PhpVersion::from_str(v).is_err(), "should reject: {v}");
        }
    }

    #[test]
    fn paths_shape() {
        let v = PhpVersion::V8_3;
        assert_eq!(v.service_name(), "php8.3-fpm");
        assert_eq!(v.pool_dir(), "/etc/php/8.3/fpm/pool.d");
        assert_eq!(v.socket_path("alice"), "/run/php/8.3/alice.sock");
    }

    #[test]
    fn display_round_trip() {
        for v in PhpVersion::all() {
            assert_eq!(PhpVersion::from_str(&v.to_string()).expect("parse"), *v);
        }
    }
}

#[cfg(test)]
mod nearest_tests {
    use super::PhpVersion;

    /// A version we support is used as-is, however the source spells it.
    #[test]
    fn a_supported_version_is_not_substituted() {
        for (raw, want) in [
            ("8.1", PhpVersion::V8_1),
            ("8.3", PhpVersion::V8_3),
            (" 8.4 ", PhpVersion::V8_4),
            ("php8.2", PhpVersion::V8_2),
            // CloudPanel reports patch levels; the allow-list rejects these.
            ("8.2.10", PhpVersion::V8_2),
            ("8.3.14", PhpVersion::V8_3),
        ] {
            assert_eq!(
                PhpVersion::nearest_supported(raw),
                Some((want, false)),
                "{raw}"
            );
        }
    }

    /// The whole reason this exists: the boxes people migrate off run old
    /// PHP. Refusing them created a site with no PHP at all.
    #[test]
    fn an_old_version_lands_on_the_lowest_supported_one() {
        for raw in ["5.6", "7.0", "7.4", "8.0", "8.0.30", "8"] {
            assert_eq!(
                PhpVersion::nearest_supported(raw),
                Some((PhpVersion::V8_1, true)),
                "{raw} should land on 8.1 and be marked substituted"
            );
        }
    }

    #[test]
    fn a_newer_version_lands_on_the_highest_supported_one() {
        for raw in ["8.5", "9.0", "10.1"] {
            assert_eq!(
                PhpVersion::nearest_supported(raw),
                Some((PhpVersion::V8_4, true)),
                "{raw}"
            );
        }
    }

    #[test]
    fn nothing_numeric_yields_nothing() {
        for raw in ["", "  ", "static", "nodejs", "php", "-"] {
            assert_eq!(PhpVersion::nearest_supported(raw), None, "{raw:?}");
        }
    }
}
