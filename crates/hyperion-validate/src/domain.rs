//! RFC-1035-ish domain parser. Strict whitelist; lowercased on parse.

use crate::ValidationError;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// Label: 1..=63 chars, alphanumeric + hyphen, no leading/trailing hyphen.
// Punycode IDN labels (`xn--...`) accepted.
static LABEL_RE: Lazy<Regex> = Lazy::new(|| {
    // Pattern allows single-char labels (matches RFC 1035 minimum) and
    // up to 63 chars total.
    Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap_or_else(|_| {
        // unreachable: regex above is constant; if it ever fails to
        // compile we panic at first use rather than silently mis-validating.
        panic!("BUG: domain LABEL regex failed to compile")
    })
});

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Domain(String);

impl Domain {
    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        let trimmed = s.trim().trim_end_matches('.').to_ascii_lowercase();
        if trimmed.is_empty() {
            return Err(err(&trimmed, "empty"));
        }
        if trimmed.len() > 253 {
            return Err(err(&trimmed, "longer than 253 chars"));
        }
        let labels: Vec<&str> = trimmed.split('.').collect();
        if labels.len() < 2 {
            return Err(err(&trimmed, "needs at least 2 labels"));
        }
        for l in &labels {
            if l.is_empty() {
                return Err(err(&trimmed, "empty label"));
            }
            if l.len() > 63 {
                return Err(err(&trimmed, "label longer than 63 chars"));
            }
            if !LABEL_RE.is_match(l) {
                return Err(err(&trimmed, "label fails regex"));
            }
        }
        // TLD must contain at least one alphabetic character (no all-digit TLDs).
        let tld = labels.last().copied().unwrap_or("");
        if !tld.chars().any(|c| c.is_ascii_alphabetic()) {
            return Err(err(&trimmed, "TLD must contain a letter"));
        }
        Ok(Self(trimmed))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

fn err(s: &str, m: &'static str) -> ValidationError {
    ValidationError::InvalidDomain(s.to_string(), m)
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Domain {
    type Err = ValidationError;
    fn from_str(s: &str) -> Result<Self, ValidationError> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Domain {
    type Error = ValidationError;
    fn try_from(s: String) -> Result<Self, ValidationError> {
        Self::parse(&s)
    }
}

impl From<Domain> for String {
    fn from(d: Domain) -> Self {
        d.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn accepts_common_domains() {
        for d in [
            "example.cz",
            "www.example.cz",
            "sub.do-main.co.uk",
            "xn--bcher-kva.de",
            "a.io",
            "ABC.example.com",
            "example.cz.",
            "1.example.org",
        ] {
            assert!(Domain::parse(d).is_ok(), "should accept: {d}");
        }
    }

    #[test]
    fn rejects_bad_domains() {
        for d in [
            "",
            "example",
            "-bad.cz",
            "bad-.cz",
            ".cz",
            "cz.",
            "exa mple.cz",
            "very-very-very-very-very-very-very-very-very-very-very-very-long-label-no-good.cz",
            "1234",
            ".",
        ] {
            assert!(Domain::parse(d).is_err(), "should reject: {d}");
        }
        let too_long = format!("a.{}", "b".repeat(252));
        assert!(Domain::parse(&too_long).is_err(), "rejects > 253");
    }

    #[test]
    fn lowercased_on_parse() {
        let d = Domain::parse("Example.CZ").expect("parse");
        assert_eq!(d.as_str(), "example.cz");
    }

    #[test]
    fn trailing_dot_stripped() {
        let d = Domain::parse("example.cz.").expect("parse");
        assert_eq!(d.as_str(), "example.cz");
    }

    #[test]
    fn serde_round_trip() {
        let d = Domain::parse("example.cz").expect("parse");
        let s = serde_json::to_string(&d).expect("serialize");
        assert_eq!(s, "\"example.cz\"");
        let back: Domain = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(d, back);
    }

    #[test]
    fn serde_rejects_bad_at_deserialize() {
        let v: Result<Domain, _> = serde_json::from_str("\"bad space.cz\"");
        assert!(v.is_err());
    }

    proptest! {
        #[test]
        fn never_panics_on_random_input(s in "\\PC{0,300}") {
            let _ = Domain::parse(&s);
        }
    }
}
