//! Tests for `service::mail`.

use super::*;

/// The reject/quarantine decision hangs off this parse, and a DMARC
/// record is operator-typed free text — spacing, order and case all
/// vary in the wild.
#[test]
fn dmarc_policy_parse_handles_wild_records() {
    use super::dmarc_policy_of;
    // The actual record that motivated the whole check (hyperion.com's).
    assert_eq!(
        dmarc_policy_of("v=DMARC1;p=reject;rua=mailto:dmarc_rua@emaildefense.proofpoint.com;fo=1"),
        "reject"
    );
    assert_eq!(dmarc_policy_of("v=DMARC1; p=none;"), "none");
    assert_eq!(dmarc_policy_of("v=DMARC1;  p = quarantine"), ""); // spaces inside kv ⇒ not a p= tag
    assert_eq!(dmarc_policy_of("v=DMARC1; p=QUARANTINE"), "quarantine");
    assert_eq!(
        dmarc_policy_of("v=DMARC1; sp=reject"),
        "",
        "sp= must not read as p="
    );
    assert_eq!(dmarc_policy_of(""), "");
    // pct=100 etc. before p=; order is not guaranteed by anyone.
    assert_eq!(dmarc_policy_of("v=DMARC1; pct=100; p=reject"), "reject");
}

#[test]
fn ip4_matches_exact() {
    let ip: std::net::Ipv4Addr = "1.2.3.4".parse().unwrap();
    assert!(ip4_matches("1.2.3.4", ip));
    assert!(!ip4_matches("1.2.3.5", ip));
}

#[test]
fn ip4_matches_cidr_24() {
    let ip: std::net::Ipv4Addr = "1.2.3.42".parse().unwrap();
    assert!(ip4_matches("1.2.3.0/24", ip));
    assert!(ip4_matches("1.2.3.255/24", ip));
    assert!(!ip4_matches("1.2.4.0/24", ip));
}

#[test]
fn ip4_matches_cidr_edge_cases() {
    let ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    // /0 matches everything
    assert!(ip4_matches("0.0.0.0/0", ip));
    // /32 is exact
    assert!(ip4_matches("10.0.0.1/32", ip));
    assert!(!ip4_matches("10.0.0.2/32", ip));
    // Malformed → false (never accidentally permissive)
    assert!(!ip4_matches("garbage", ip));
    assert!(!ip4_matches("1.2.3.4/33", ip));
    assert!(!ip4_matches("1.2.3.4/abc", ip));
}

#[test]
fn stitch_dig_txt_single_segment() {
    assert_eq!(
        stitch_dig_txt("\"v=spf1 ip4:1.2.3.4 ~all\""),
        "v=spf1 ip4:1.2.3.4 ~all"
    );
}

#[test]
fn stitch_dig_txt_multi_segment() {
    // Long TXT split into two quoted segments — dig prints them
    // back-to-back. The RFC says receivers concatenate as-is.
    assert_eq!(
        stitch_dig_txt("\"v=spf1 ip4:1.2.3.4 \" \"ip4:5.6.7.8 ~all\""),
        "v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 ~all"
    );
}

#[test]
fn stitch_dig_txt_falls_back_to_trim_when_no_quotes() {
    assert_eq!(stitch_dig_txt("  v=spf1 ~all  "), "v=spf1 ~all");
}

/// SPF authorization with the previous bug's exact scenario:
/// the operator's record lists OUR ip alongside another ip + an
/// include — the literal string compare reported "differs",
/// the parser must now report "matches".
#[tokio::test]
async fn spf_authorize_multi_ip_with_include_matches() {
    let our: std::net::Ipv4Addr = "178.105.99.35".parse().unwrap();
    let record = "v=spf1 ip4:1.2.3.4 ip4:178.105.99.35 include:_spf.google.com ~all";
    let r = check_spf_authorizes_no_recurse(record, "example.cz", our).await;
    assert!(matches!(r, SpfMatch::Match { .. }), "got {r:?}");
}

#[tokio::test]
async fn spf_authorize_cidr_block_matches() {
    let our: std::net::Ipv4Addr = "10.0.0.42".parse().unwrap();
    let record = "v=spf1 ip4:10.0.0.0/24 ~all";
    let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
    assert!(matches!(r, SpfMatch::Match { .. }), "got {r:?}");
}

#[tokio::test]
async fn spf_authorize_soft_all_does_not_catchall() {
    // ~all is "softfail" — anyone NOT explicitly listed above
    // is unauthorized but receivers should accept and tag. Our
    // check reports "differs" since our IP isn't in the list.
    let our: std::net::Ipv4Addr = "9.9.9.9".parse().unwrap();
    let record = "v=spf1 ip4:1.2.3.4 ~all";
    let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
    assert!(matches!(r, SpfMatch::None), "got {r:?}");
}

#[tokio::test]
async fn spf_authorize_plus_all_is_catchall() {
    let our: std::net::Ipv4Addr = "9.9.9.9".parse().unwrap();
    let record = "v=spf1 +all";
    let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
    assert!(matches!(r, SpfMatch::CatchAll { .. }), "got {r:?}");
}

#[tokio::test]
async fn spf_authorize_question_all_is_catchall() {
    // `?all` is "neutral" — receivers treat senders as
    // unspecified. From the operator's "does my IP pass"
    // perspective, this means anything ABOVE in the record
    // could pass without an explicit IP listing.
    let our: std::net::Ipv4Addr = "9.9.9.9".parse().unwrap();
    let record = "v=spf1 ?all";
    let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
    assert!(matches!(r, SpfMatch::CatchAll { .. }), "got {r:?}");
}

#[tokio::test]
async fn spf_authorize_minus_all_does_not_catchall() {
    let our: std::net::Ipv4Addr = "9.9.9.9".parse().unwrap();
    let record = "v=spf1 -all";
    let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
    assert!(matches!(r, SpfMatch::None), "got {r:?}");
}

#[tokio::test]
async fn spf_authorize_missing_version_tag_rejected() {
    let our: std::net::Ipv4Addr = "1.2.3.4".parse().unwrap();
    // No leading "v=spf1" — not an SPF record at all.
    let r = check_spf_authorizes_no_recurse("ip4:1.2.3.4 ~all", "x.cz", our).await;
    assert!(matches!(r, SpfMatch::None), "got {r:?}");
}
