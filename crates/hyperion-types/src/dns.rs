//! DNS pre-check + cert-issue request types.
//!
//! The operator clicks "Issue HTTPS cert" → we shell out to `dig` for
//! both A and AAAA records on the domain, fetch our own public IP
//! (configurable or via the public IP discovery URL in agent.toml),
//! and report whether the records actually point here. The cert flow
//! itself refuses to proceed until DNS matches — so we never burn a
//! Let's Encrypt rate-limit slot on a domain that obviously won't
//! validate.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsCheckResult {
    pub domain: String,
    /// IPv4 addresses the public DNS resolves the apex to (empty if NXDOMAIN
    /// or DNS server failed).
    pub resolved_a: Vec<String>,
    pub resolved_aaaa: Vec<String>,
    /// Our agent's externally-visible IPv4, as advertised by the agent's
    /// `[acme] public_ip` config or discovered through a public-IP service.
    pub our_public_ipv4: Option<String>,
    pub our_public_ipv6: Option<String>,
    /// True iff at least one resolved A or AAAA record equals one of our
    /// public IPs — i.e. cert issuance has a real chance of succeeding.
    pub matches: bool,
    /// Human-friendly explanation of the outcome.
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertIssueRequest {
    /// Use Let's Encrypt staging (rate-limit friendly, untrusted CA)
    /// instead of production. Default true on first try; flip off when
    /// you've confirmed staging works.
    #[serde(default)]
    pub staging: bool,
    /// Refuse to proceed unless DNS already points here. Default true;
    /// the operator can override with caution.
    #[serde(default = "default_true")]
    pub require_dns_match: bool,
    /// Extra SANs to put on the cert beyond the hosting's primary
    /// domain. Aliases get folded in here automatically; this field is
    /// reserved for adding domains not already on the hosting.
    #[serde(default)]
    pub extra_sans: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_check_round_trips() {
        let r = DnsCheckResult {
            domain: "example.com".into(),
            resolved_a: vec!["1.2.3.4".into()],
            resolved_aaaa: vec![],
            our_public_ipv4: Some("1.2.3.4".into()),
            our_public_ipv6: None,
            matches: true,
            note: "DNS A record resolves here".into(),
        };
        let s = serde_json::to_string(&r).expect("ser");
        let back: DnsCheckResult = serde_json::from_str(&s).expect("de");
        assert_eq!(r, back);
    }

    #[test]
    fn cert_issue_request_defaults() {
        let r: CertIssueRequest = serde_json::from_str("{}").expect("parse");
        assert!(!r.staging);
        assert!(r.require_dns_match); // safety default
        assert!(r.extra_sans.is_empty());
    }
}
