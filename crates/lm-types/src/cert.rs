//! TLS certificate DTOs.

use serde::{Deserialize, Serialize};

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
            outcome: CertRenewOutcome::Renewed { new_not_after: 12345 },
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: CertRenewResult = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn renew_outcome_skipped_round_trip() {
        let v = CertRenewResult {
            domain: "x.cz".into(),
            outcome: CertRenewOutcome::Skipped { reason: "not yet".into() },
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: CertRenewResult = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn renew_outcome_failed_round_trip() {
        let v = CertRenewResult {
            domain: "x.cz".into(),
            outcome: CertRenewOutcome::Failed { error: "boom".into() },
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: CertRenewResult = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }
}
