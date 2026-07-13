//! DKIM signing status for a hosting's outbound mail.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DkimStatus {
    pub domain: String,
    /// True once a key exists AND the domain is present in the signing tables.
    pub enabled: bool,
    /// Selector (the label left of `._domainkey`). Empty when never enabled.
    pub selector: String,
    /// DNS record name the operator must publish:
    /// `<selector>._domainkey.<domain>`. Empty when disabled.
    pub dns_name: String,
    /// The exact TXT value to publish: `v=DKIM1; k=rsa; p=<pubkey>`.
    /// Empty when disabled.
    pub txt_value: String,
    /// Result of the last DNS verification:
    /// `""` (never checked) | `"verified"` | `"missing"` | `"mismatch"`.
    /// "verified" — a TXT record exists at `dns_name` and its public key
    ///              equals ours. "missing" — no DKIM TXT there yet.
    /// "mismatch" — a record exists but its `p=` differs from our key
    ///              (stale / wrong key pasted).
    #[serde(default)]
    pub verify_status: String,
    /// Unix seconds of the last verification; 0 = never checked.
    #[serde(default)]
    pub verified_at: i64,
    /// True when OpenDKIM isn't installed on the owning node, so signing is
    /// unavailable there regardless of this hosting's setting.
    #[serde(default)]
    pub unavailable: bool,
}
