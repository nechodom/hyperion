//! Linux system-user name parser + derivation from a domain.
//!
//! POSIX user names are constrained — we use `^[a-z][a-z0-9_]{2,31}$`
//! to stay well within shell-safe + portable limits.

use crate::ValidationError;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

static RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z][a-z0-9_]{2,31}$").unwrap_or_else(|_| {
        panic!("BUG: sysuser regex failed to compile")
    })
});

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SystemUserName(String);

impl SystemUserName {
    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        if !RE.is_match(s) {
            return Err(ValidationError::InvalidSystemUser(
                s.to_string(),
                "must match ^[a-z][a-z0-9_]{2,31}$",
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// Derive a stable, valid system-user name from a domain. Used as a
    /// default when the caller doesn't specify one.
    ///
    /// Algorithm:
    ///   1. Lowercase, replace dots/hyphens with `_`, drop other chars.
    ///   2. If first char is not a letter, prepend `x`.
    ///   3. Collapse consecutive underscores.
    ///   4. Trim to 32 chars; if too short, pad with letters.
    pub fn derive_from_domain(domain: &str) -> Result<Self, ValidationError> {
        let lower = domain.to_ascii_lowercase();
        let mut filtered = String::with_capacity(lower.len());
        for c in lower.chars() {
            match c {
                'a'..='z' | '0'..='9' => filtered.push(c),
                '.' | '-' => filtered.push('_'),
                _ => {} // drop
            }
        }
        if filtered.is_empty() {
            return Err(ValidationError::InvalidSystemUser(
                domain.to_string(),
                "derived empty name",
            ));
        }
        let prefixed = if !filtered.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
            format!("x{filtered}")
        } else {
            filtered
        };
        // Collapse repeats of '_'
        let mut collapsed = String::with_capacity(prefixed.len());
        let mut prev_underscore = false;
        for c in prefixed.chars() {
            if c == '_' && prev_underscore {
                continue;
            }
            prev_underscore = c == '_';
            collapsed.push(c);
        }
        // Trim to 32
        if collapsed.len() > 32 {
            collapsed.truncate(32);
        }
        // Strip trailing underscore (cosmetic + ensures length+1 might fit)
        while collapsed.ends_with('_') && collapsed.len() > 3 {
            collapsed.pop();
        }
        // Pad to minimum length 3
        while collapsed.len() < 3 {
            collapsed.push('x');
        }
        Self::parse(&collapsed)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for SystemUserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SystemUserName {
    type Err = ValidationError;
    fn from_str(s: &str) -> Result<Self, ValidationError> {
        Self::parse(s)
    }
}

impl TryFrom<String> for SystemUserName {
    type Error = ValidationError;
    fn try_from(s: String) -> Result<Self, ValidationError> {
        Self::parse(&s)
    }
}

impl From<SystemUserName> for String {
    fn from(d: SystemUserName) -> Self {
        d.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn accepts_good_names() {
        for s in ["abc", "example_cz", "kev1n_test", "aaa", "a_b_c"] {
            assert!(SystemUserName::parse(s).is_ok(), "should accept {s}");
        }
    }

    #[test]
    fn rejects_bad_names() {
        let too_long = "a".repeat(33);
        let cases: Vec<&str> = vec!["", "ab", "1abc", "_abc", "Abc", "abc!", "abc-def", &too_long];
        for s in cases {
            assert!(SystemUserName::parse(s).is_err(), "should reject {s}");
        }
    }

    #[test]
    fn derive_basic() {
        assert_eq!(
            SystemUserName::derive_from_domain("example.cz").expect("derive").as_str(),
            "example_cz"
        );
        assert_eq!(
            SystemUserName::derive_from_domain("www.example.cz").expect("derive").as_str(),
            "www_example_cz"
        );
        assert_eq!(
            SystemUserName::derive_from_domain("foo-bar.io").expect("derive").as_str(),
            "foo_bar_io"
        );
    }

    #[test]
    fn derive_caps_at_32() {
        let n = SystemUserName::derive_from_domain("a-very-extremely-long-subdomain-name-here.cz")
            .expect("derive");
        assert!(n.as_str().len() <= 32);
    }

    #[test]
    fn derive_leading_digit_prefixed_with_x() {
        let n = SystemUserName::derive_from_domain("123-foo.cz").expect("derive");
        assert!(n.as_str().starts_with('x'));
    }

    #[test]
    fn serde_round_trip() {
        let n = SystemUserName::parse("alice_bob").expect("parse");
        let s = serde_json::to_string(&n).expect("serialize");
        assert_eq!(s, "\"alice_bob\"");
        let back: SystemUserName = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(n, back);
    }

    proptest! {
        #[test]
        fn parse_never_panics(s in "\\PC{0,300}") {
            let _ = SystemUserName::parse(&s);
        }

        #[test]
        fn derive_never_panics(s in "[a-zA-Z0-9.\\-_]{1,80}") {
            let _ = SystemUserName::derive_from_domain(&s);
        }

        #[test]
        fn derived_is_always_valid(s in "[a-z]{1,5}\\.[a-z]{2,4}") {
            let n = SystemUserName::derive_from_domain(&s).expect("valid domain produces valid name");
            assert!(SystemUserName::parse(n.as_str()).is_ok());
        }
    }
}
