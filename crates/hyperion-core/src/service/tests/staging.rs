//! Tests for `service::staging`.

use super::*;

#[test]
fn effective_staging_domain_prefers_override() {
    type S = HostingService<MockAdapterPort>;
    // No override ⇒ default prefix.
    assert_eq!(
        S::effective_staging_domain(None, "example.cz"),
        "staging.example.cz"
    );
    // Blank / whitespace override ⇒ default.
    assert_eq!(
        S::effective_staging_domain(Some("  "), "example.cz"),
        "staging.example.cz"
    );
    // Real override wins, trimmed + lower-cased.
    assert_eq!(
        S::effective_staging_domain(Some(" Dev.Example.CZ "), "example.cz"),
        "dev.example.cz"
    );
}
