//! SPF DNS check + suggested record.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpfCheckResult {
    pub domain: String,
    /// Every TXT record at the apex that starts with `v=spf1`.
    /// Usually one; multiple is malformed but we surface them all.
    pub existing: Vec<String>,
    pub suggested: String,
    pub our_public_ipv4: Option<String>,
    /// "matches" | "differs" | "missing"
    pub status: String,
}
