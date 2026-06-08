//! TLS certificate DTOs.

use serde::{Deserialize, Serialize};

/// One row on the cluster-wide /certs overview. Slimmer than
/// `CertInfo` because the list doesn't need full SANs /
/// fingerprint — operator clicks through to hosting detail for
/// the full record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertOverviewItem {
    pub domain: String,
    pub issuer: String,
    pub issued_at: i64,
    pub not_after: i64,
    /// Days until expiry — computed server-side so the template
    /// doesn't need date arithmetic. Negative ⇒ already expired.
    pub days_left: i64,
    /// One of "expired" | "critical" (<7d) | "warning" (<30d) |
    /// "ok". Drives the UI pill colour.
    pub band: String,
    /// Node id this cert lives on. Empty string ⇒ master.
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertInfo {
    pub domain: String,
    pub sans: Vec<String>,
    pub issuer: String,
    pub not_after: i64,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertRenewResult {
    pub domain: String,
    pub outcome: CertRenewOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CertRenewOutcome {
    Renewed { new_not_after: i64 },
    Skipped { reason: String },
    Failed { error: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_info_round_trip() {
        let v = CertInfo {
            domain: "example.cz".into(),
            sans: vec!["www.example.cz".into()],
            issuer: "letsencrypt".into(),
            not_after: 1_900_000_000,
            fingerprint_sha256: "ab".repeat(32),
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: CertInfo = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn renew_outcome_renewed_round_trip() {
        let v = CertRenewResult {
            domain: "x.cz".into(),
            outcome: CertRenewOutcome::Renewed {
                new_not_after: 12345,
            },
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: CertRenewResult = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn renew_outcome_skipped_round_trip() {
        let v = CertRenewResult {
            domain: "x.cz".into(),
            outcome: CertRenewOutcome::Skipped {
                reason: "not yet".into(),
            },
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: CertRenewResult = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn renew_outcome_failed_round_trip() {
        let v = CertRenewResult {
            domain: "x.cz".into(),
            outcome: CertRenewOutcome::Failed {
                error: "boom".into(),
            },
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: CertRenewResult = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }
}
