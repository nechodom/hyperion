//! Tests for `service::net`.

use super::*;

// ============================================================
//  SSRF guard for outbound webhook URLs (is_internal_ip /
//  ssrf_guard_resolve). Blocks loopback/private/link-local +
//  the cloud metadata endpoint; pins curl to the validated IP.
// ============================================================

#[test]
fn is_internal_ip_blocks_loopback_private_and_metadata() {
    use std::net::IpAddr;
    let blocked = [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.5",
        "172.16.9.9",
        "169.254.169.254", // cloud metadata
        "100.64.0.1",      // CGNAT
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1", // v4-mapped loopback
    ];
    for s in blocked {
        let ip: IpAddr = s.parse().expect("ip");
        assert!(is_internal_ip(&ip), "{s} should be internal");
    }
    let public = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"];
    for s in public {
        let ip: IpAddr = s.parse().expect("ip");
        assert!(!is_internal_ip(&ip), "{s} should be public");
    }
}

#[tokio::test]
async fn ssrf_guard_rejects_internal_and_bad_scheme() {
    // Literal internal IP — rejected without DNS.
    assert!(
        ssrf_guard_resolve("http://169.254.169.254/latest/meta-data")
            .await
            .is_err()
    );
    assert!(ssrf_guard_resolve("https://127.0.0.1:8080/x")
        .await
        .is_err());
    // Non-http scheme.
    assert!(ssrf_guard_resolve("file:///etc/passwd").await.is_err());
    // A public literal IP resolves to a pinned --resolve entry.
    let pins = ssrf_guard_resolve("https://1.1.1.1/hook")
        .await
        .expect("public ip ok");
    assert_eq!(pins, vec!["1.1.1.1:443:1.1.1.1".to_string()]);
}

/// A master-minted bundle URL may point at the master's own internal
/// address (Debian maps the FQDN to 127.0.1.1) — that copy used to die
/// with "disallowed (internal) address". Everything else still holds.
#[tokio::test]
async fn master_minted_url_may_be_internal_but_keeps_scheme_check() {
    let own = InternalAddrs::AllowOwnNetwork;
    let pins = resolve_url_pins("https://127.0.1.1:8443/api/migration/bundle/x", own)
        .await
        .expect("internal allowed for a master-minted url");
    assert_eq!(pins, vec!["127.0.1.1:8443:127.0.1.1".to_string()]);
    assert!(resolve_url_pins("https://10.0.0.5:8443/x", own)
        .await
        .is_ok());
    assert!(
        resolve_url_pins("https://127.0.1.1:8443/x", InternalAddrs::Refuse)
            .await
            .is_err()
    );
    // The host comes from a Host header: metadata and friends stay out.
    for bad in [
        "http://169.254.169.254/latest",
        "http://0.0.0.0/x",
        "http://[fe80::1]/x",
        "file:///etc/passwd",
    ] {
        assert!(resolve_url_pins(bad, own).await.is_err(), "{bad}");
    }
}

#[tokio::test]
async fn url_hosts_resolve_without_dns_for_literals() {
    async fn v(u: &str) -> Vec<String> {
        resolve_url_host(u)
            .await
            .iter()
            .map(|i| i.to_string())
            .collect()
    }
    assert_eq!(
        v("https://203.0.113.9:8443/agent-rpc").await,
        vec!["203.0.113.9"]
    );
    assert_eq!(v("https://[2001:db8::9]:9443/x").await, vec!["2001:db8::9"]);
    assert_eq!(v("https://user@198.51.100.4/").await, vec!["198.51.100.4"]);
    assert!(v("").await.is_empty());
}
