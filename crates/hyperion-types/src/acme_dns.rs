//! acme-dns style delegation: the zone config and the per-base labels.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AcmeDnsConfig {
    /// Delegated zone, e.g. `acme.panel.example` (lowercase, no trailing dot).
    pub zone: Option<String>,
    /// Name of the responder's NS host; lives in the PARENT zone.
    pub ns_host: String,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub enabled: bool,
    /// Random 32 chars, generated once; proves the responder answers.
    pub check_token: String,
    /// Runtime only: addresses the responder is bound to, filled by the agent.
    #[serde(default)]
    pub listening: Vec<String>,
    /// Runtime only: last responder error.
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AcmeDnsLabel {
    /// Base domain, e.g. `example.com`.
    pub base: String,
    /// 16 chars of `[a-z0-9]`.
    pub label: String,
    /// `None` = a preview base, not owned by a hosting.
    pub hosting_id: Option<String>,
    pub created_at: i64,
    pub verified_at: Option<i64>,
    pub last_check_error: Option<String>,
}

impl AcmeDnsLabel {
    /// The record the operator creates: `_acme-challenge.<base>`.
    pub fn challenge_name(&self) -> String {
        format!("_acme-challenge.{}", self.base)
    }

    /// The CNAME target inside the delegated zone: `<label>.<zone>`.
    pub fn target(&self, zone: &str) -> String {
        format!("{}.{}", self.label, zone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_composed_from_base_label_and_zone() {
        let l = AcmeDnsLabel {
            base: "example.com".into(),
            label: "abcd1234abcd1234".into(),
            hosting_id: None,
            created_at: 0,
            verified_at: None,
            last_check_error: None,
        };
        assert_eq!(l.challenge_name(), "_acme-challenge.example.com");
        assert_eq!(
            l.target("acme.panel.example"),
            "abcd1234abcd1234.acme.panel.example"
        );
    }
}
