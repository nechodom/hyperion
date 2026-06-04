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
    /// "matches" | "differs" | "missing" | "multiple"
    ///
    /// "matches"  — at least one of the existing SPF records authorizes
    ///              our public IPv4 (via `ip4:`, `a`, `mx`, `include:`,
    ///              or a `+all`/`?all` catch-all).
    /// "differs"  — an SPF record exists but does NOT authorize our IP.
    /// "missing"  — no SPF TXT record at the apex.
    /// "multiple" — RFC 7208 §3.2 forbids more than one SPF record. The
    ///              domain has 2+ — operator MUST collapse them or
    ///              receivers fall back to "permerror" and outright
    ///              refuse mail.
    pub status: String,
    /// Optional one-line explanation of how the status was reached.
    /// e.g. "ip4:1.2.3.4 matched our public IP" — surfaced in the UI so
    /// the operator doesn't have to manually decode the SPF mechanisms.
    #[serde(default)]
    pub reason: String,
}
