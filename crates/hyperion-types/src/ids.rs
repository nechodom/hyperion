//! Newtype identifiers — always serialized as the inner string.

use serde::{Deserialize, Serialize};
use std::fmt;

/// UUID v7 (time-ordered) identifier of a hosting on an agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostingId(pub String);

impl HostingId {
    pub fn new_v7() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for HostingId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// UUID v7 identifier of an agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new_v7() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for AgentId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// ULID for secret-file IDs. Never embeds the secret itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(pub String);

impl SecretId {
    pub fn new() -> Self {
        Self(ulid::Ulid::new().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for SecretId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosting_id_serde_roundtrip() {
        let id = HostingId::new_v7();
        let s = serde_json::to_string(&id).expect("serialize");
        let back: HostingId = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(id, back);
    }

    #[test]
    fn hosting_id_v7_is_time_ordered() {
        let a = HostingId::new_v7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = HostingId::new_v7();
        assert!(a.as_str() < b.as_str(), "{} >= {}", a, b);
    }

    #[test]
    fn agent_id_serde() {
        let a = AgentId::new_v7();
        let s = serde_json::to_string(&a).expect("serialize");
        assert!(s.starts_with('"') && s.ends_with('"'));
        let back: AgentId = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(a, back);
    }

    #[test]
    fn secret_id_uniqueness_over_1000() {
        let mut set = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(set.insert(SecretId::new()));
        }
    }

    #[test]
    fn ids_display_equals_as_str() {
        let h = HostingId::new_v7();
        assert_eq!(format!("{}", h), h.as_str());
        let a = AgentId::new_v7();
        assert_eq!(format!("{}", a), a.as_str());
        let s = SecretId::new();
        assert_eq!(format!("{}", s), s.as_str());
    }
}
