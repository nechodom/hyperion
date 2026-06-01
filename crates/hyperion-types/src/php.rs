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
