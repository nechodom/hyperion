//! Tests for `service::nodes`.

use super::*;

// ============================================================
//  Block B idempotent re-enrollment identity resolution.
//  SECURITY: a presented prior_node_id is reused ONLY on a
//  matching secret — never adopted secret-lessly (that was a
//  node-takeover vector).
// ============================================================

#[tokio::test]
async fn reenroll_never_adopts_unknown_id_without_secret() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let mint = s.invite_create("n".into(), 3600).await.expect("invite");
    // Present a prior_node_id the master has never seen + a garbage secret.
    let (effective, _secret) = s
        .enroll_consume(
            mint.token.clone(),
            "1.2.3.4".into(),
            "candidate_fresh".into(),
            "label".into(),
            "v1".into(),
            Some("9.9.9.9".into()),
            Some("ghost-node".into()),
            Some("garbage".into()),
            None,
            Default::default(),
        )
        .await
        .expect("enroll");
    assert_eq!(
        effective, "candidate_fresh",
        "must NOT adopt the unknown 'ghost-node' id — fresh candidate only"
    );
    assert!(
        hyperion_state::nodes::get_by_node_id(&s.pool, "ghost-node")
            .await
            .unwrap()
            .is_none(),
        "the unknown id must never materialize as a node row"
    );
}

#[tokio::test]
async fn reenroll_reuses_id_when_secret_matches() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let m1 = s.invite_create("n".into(), 3600).await.expect("i1");
    let (id1, secret1) = s
        .enroll_consume(
            m1.token.clone(),
            "1.2.3.4".into(),
            "cand_1".into(),
            "label".into(),
            "v1".into(),
            None,
            None,
            None,
            None,
            Default::default(),
        )
        .await
        .expect("e1");
    assert_eq!(id1, "cand_1");
    // Re-enroll presenting that id + the CORRECT secret → reuse same id.
    let m2 = s.invite_create("n".into(), 3600).await.expect("i2");
    let (id2, secret2) = s
        .enroll_consume(
            m2.token.clone(),
            "1.2.3.4".into(),
            "cand_2".into(),
            "label".into(),
            "v2".into(),
            None,
            Some(id1.clone()),
            Some(secret1.clone()),
            None,
            Default::default(),
        )
        .await
        .expect("e2");
    assert_eq!(id2, "cand_1", "reused the prior id, not the new candidate");
    // The proven secret is kept, so a re-enroll whose response never
    // reaches the node leaves it holding a secret that still works.
    assert_eq!(secret2, secret1, "a proven secret survives the re-enroll");
    s.node_heartbeat(
        id1.clone(),
        secret1.clone(),
        "v2".into(),
        None,
        None,
        Default::default(),
    )
    .await
    .expect("the node's on-disk secret must still heartbeat after a re-enroll");
    assert_eq!(
        hyperion_state::nodes::list(&s.pool).await.unwrap().len(),
        1,
        "no duplicate node row on reuse"
    );
}

#[tokio::test]
async fn reenroll_keeps_the_address_and_label_it_cannot_report() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let m1 = s.invite_create("n".into(), 3600).await.expect("i1");
    let (id, secret) = s
        .enroll_consume(
            m1.token.clone(),
            "1.2.3.4".into(),
            "cand_1".into(),
            "web-01".into(),
            "v1".into(),
            Some("203.0.113.7".into()),
            None,
            None,
            None,
            Default::default(),
        )
        .await
        .expect("e1");
    s.node_set_label(&id, "Prague primary")
        .await
        .expect("rename");
    // Re-enroll from a box whose public-IP probe failed this time.
    let m2 = s.invite_create("n".into(), 3600).await.expect("i2");
    s.enroll_consume(
        m2.token.clone(),
        "1.2.3.4".into(),
        "cand_2".into(),
        "web-01".into(),
        "v2".into(),
        None,
        Some(id.clone()),
        Some(secret),
        None,
        Default::default(),
    )
    .await
    .expect("e2");
    let row = hyperion_state::nodes::get_by_node_id(&s.pool, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.public_ip.as_deref(),
        Some("203.0.113.7"),
        "a missing address must not blank the one on record"
    );
    assert_eq!(row.label, "Prague primary", "the panel's rename survives");
}

#[tokio::test]
async fn enrollment_and_heartbeat_record_where_the_node_listens() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let m = s.invite_create("n".into(), 3600).await.expect("i");
    let (id, secret) = s
        .enroll_consume(
            m.token.clone(),
            "1.2.3.4".into(),
            "cand_1".into(),
            "label".into(),
            "v1".into(),
            // Garbage where an address belongs is dropped, not dialled.
            Some("evil.example/x?".into()),
            None,
            None,
            None,
            hyperion_types::NodeEndpointReport {
                rpc_port: Some(9555),
                external_ip: Some("198.51.100.9".into()),
            },
        )
        .await
        .expect("enroll");
    let n = &s.nodes_list().await.unwrap()[0];
    assert_eq!(n.public_ip, None);
    assert_eq!(n.rpc_port(), 9555);
    assert_eq!(n.customer_host(), Some("198.51.100.9"));
    // A heartbeat moves the port; one that reports nothing keeps it.
    for (port, want) in [(Some(9666), 9666), (None, 9666)] {
        s.node_heartbeat(
            id.clone(),
            secret.clone(),
            "v1".into(),
            None,
            None,
            hyperion_types::NodeEndpointReport {
                rpc_port: port,
                external_ip: Some("not an ip".into()),
            },
        )
        .await
        .expect("heartbeat");
        let n = &s.nodes_list().await.unwrap()[0];
        assert_eq!(n.rpc_port(), want);
        assert_eq!(n.external_ip.as_deref(), Some("198.51.100.9"));
    }
}

#[tokio::test]
async fn reassign_refuses_to_take_sites_from_a_live_node() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let mut ids = Vec::new();
    for cand in ["cand_a", "cand_b"] {
        let m = s.invite_create("n".into(), 3600).await.expect("i");
        let (id, _) = s
            .enroll_consume(
                m.token.clone(),
                "1.2.3.4".into(),
                cand.into(),
                "label".into(),
                "v1".into(),
                None,
                None,
                None,
                None,
                Default::default(),
            )
            .await
            .expect("enroll");
        ids.push(id);
    }
    let err = s
        .node_reassign_hostings(&ids[0], &ids[1])
        .await
        .expect_err("both nodes are alive");
    assert!(err.to_string().contains("still enrolled"), "{err}");
    // A dead id (removed / never seen) is exactly what it is for.
    assert_eq!(s.node_reassign_hostings("gone", &ids[1]).await.unwrap(), 0);
}

#[test]
fn node_addresses_must_be_one_host() {
    for ok in [
        "10.0.0.5",
        "[2a01:4f8::1]",
        "2a01:4f8::1",
        "node1.example.com",
    ] {
        assert!(
            checked_node_addr("n", "f", Some(ok.into())).is_some(),
            "{ok}"
        );
    }
    assert_eq!(
        checked_node_addr("n", "f", Some("[2a01:4f8::1]".into())).as_deref(),
        Some("2a01:4f8::1"),
        "brackets are the dialler's job, not the stored value's"
    );
    for bad in [
        "evil/x?",
        "user@host",
        "1.2.3.4:9443",
        "-a.b",
        "a b",
        "<html>",
    ] {
        assert!(
            checked_node_addr("n", "f", Some(bad.into())).is_none(),
            "{bad}"
        );
    }
    assert!(checked_node_addr("n", "f", Some("  ".into())).is_none());
}

#[tokio::test]
async fn reenroll_with_wrong_secret_gets_fresh_id() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let m1 = s.invite_create("n".into(), 3600).await.expect("i1");
    let (id1, _s1) = s
        .enroll_consume(
            m1.token.clone(),
            "1.2.3.4".into(),
            "cand_1".into(),
            "label".into(),
            "v1".into(),
            None,
            None,
            None,
            None,
            Default::default(),
        )
        .await
        .expect("e1");
    let m2 = s.invite_create("n".into(), 3600).await.expect("i2");
    let (id2, _s2) = s
        .enroll_consume(
            m2.token.clone(),
            "1.2.3.4".into(),
            "cand_2".into(),
            "label".into(),
            "v2".into(),
            None,
            Some(id1.clone()),
            Some("WRONG".into()),
            None,
            Default::default(),
        )
        .await
        .expect("e2");
    assert_eq!(id2, "cand_2", "wrong secret → fresh id, no takeover");
    assert_eq!(
        hyperion_state::nodes::list(&s.pool).await.unwrap().len(),
        2,
        "two distinct node rows — the in-use one was not hijacked"
    );
}

// ============================================================
//  Response-signing pubkey pinning. SECURITY: trust-on-first-
//  use with refuse-on-change. A heartbeat proves possession of
//  the shared secret over a `curl -k` channel, so it may FILL
//  an empty pin but never swap one — otherwise leaking that
//  secret would be enough to install an attacker's signing key
//  and forge every RPC response afterwards.
// ============================================================

#[test]
fn tofu_pin_state_machine() {
    assert_eq!(decide_tofu_pin(None, "pk-a"), TofuPin::Adopt);
    assert_eq!(decide_tofu_pin(Some("pk-a"), "pk-a"), TofuPin::Keep);
    assert_eq!(decide_tofu_pin(Some("pk-a"), "pk-b"), TofuPin::Refuse);
    // Byte-exact: base64 is case-sensitive and a near-miss key is
    // still somebody else's key.
    assert_eq!(decide_tofu_pin(Some("pk-a"), "PK-A"), TofuPin::Refuse);
    // Same rule drives the TLS pin — a changed SPKI pin is refused,
    // never newest-wins, or one forged heartbeat would re-point cert
    // pinning at the attacker's cert.
    assert_eq!(
        decide_tofu_pin(Some("sha256//abc="), "sha256//EVIL="),
        TofuPin::Refuse
    );
}

#[tokio::test]
async fn enroll_pins_pubkey_and_reenrollment_is_the_rotation_path() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let (id, secret) = enroll_node(&s, "cand_1", None, Some("pk-a")).await;
    assert_eq!(
        pinned_key(&s, &id).await.as_deref(),
        Some("pk-a"),
        "pinned at enrollment so the very first RPC response is verifiable"
    );
    // The public key fans out to the panel; the secret hash never does.
    let summary = s.nodes_list().await.expect("list");
    assert_eq!(summary[0].resp_pubkey.as_deref(), Some("pk-a"));
    // Re-enrolling with proven continuity is the sanctioned rotation:
    // upsert_enrollment clears the pin, the new key takes its place.
    let (id2, _s2) = enroll_node(&s, "cand_2", Some((&id, &secret)), Some("pk-b")).await;
    assert_eq!(id2, id, "same identity reused");
    assert_eq!(pinned_key(&s, &id).await.as_deref(), Some("pk-b"));
}

#[tokio::test]
async fn heartbeat_adopts_then_keeps_then_refuses_a_changed_pubkey() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    // Pre-upgrade agent: enrolls without publishing a key.
    let (id, secret) = enroll_node(&s, "cand_1", None, None).await;
    assert_eq!(pinned_key(&s, &id).await, None);
    // Adopt: first key seen wins.
    s.node_heartbeat(
        id.clone(),
        secret.clone(),
        "v2".into(),
        None,
        Some("pk-a".into()),
        Default::default(),
    )
    .await
    .expect("adopt");
    assert_eq!(pinned_key(&s, &id).await.as_deref(), Some("pk-a"));
    // Keep: same key, no-op.
    s.node_heartbeat(
        id.clone(),
        secret.clone(),
        "v2".into(),
        None,
        Some("pk-a".into()),
        Default::default(),
    )
    .await
    .expect("keep");
    assert_eq!(pinned_key(&s, &id).await.as_deref(), Some("pk-a"));
    // Refuse: a changed key must NOT re-key the node — but the
    // heartbeat itself still succeeds, because failing it would let a
    // single forged key report keep a healthy node "offline" forever.
    s.node_heartbeat(
        id.clone(),
        secret.clone(),
        "v2".into(),
        None,
        Some("pk-EVIL".into()),
        Default::default(),
    )
    .await
    .expect("refuse still heartbeats");
    assert_eq!(
        pinned_key(&s, &id).await.as_deref(),
        Some("pk-a"),
        "one MITMed heartbeat must never rotate the trust anchor"
    );
    // Omitting the field (older agent, or remote RPC disabled) likewise
    // leaves the pin alone rather than nulling it.
    s.node_heartbeat(
        id.clone(),
        secret,
        "v2".into(),
        None,
        None,
        Default::default(),
    )
    .await
    .expect("absent");
    assert_eq!(pinned_key(&s, &id).await.as_deref(), Some("pk-a"));
}

/// The TLS SPKI pin gets the SAME treatment as the response pubkey.
/// A newest-wins pin would mean cert-pinning enforcement could be
/// re-aimed at an attacker's cert by one forged heartbeat, at any
/// time — i.e. the enforcement toggle would be decorative.
#[tokio::test]
async fn heartbeat_refuses_a_changed_tls_pin() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let (id, secret) = enroll_node(&s, "cand_1", None, None).await;
    s.node_heartbeat(
        id.clone(),
        secret.clone(),
        "v2".into(),
        Some("sha256//good=".into()),
        None,
        Default::default(),
    )
    .await
    .expect("adopt");
    assert_eq!(pinned_tls(&s, &id).await.as_deref(), Some("sha256//good="));
    // Refuse: heartbeat still succeeds, pin unchanged.
    s.node_heartbeat(
        id.clone(),
        secret,
        "v2".into(),
        Some("sha256//EVIL=".into()),
        None,
        Default::default(),
    )
    .await
    .expect("refuse still heartbeats");
    assert_eq!(
        pinned_tls(&s, &id).await.as_deref(),
        Some("sha256//good="),
        "one MITMed heartbeat must never re-point the TLS pin"
    );
}

#[tokio::test]
async fn heartbeat_with_bad_secret_cannot_pin_a_pubkey() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let (id, _secret) = enroll_node(&s, "cand_1", None, None).await;
    let r = s
        .node_heartbeat(
            id.clone(),
            "WRONG".into(),
            "v2".into(),
            None,
            Some("pk-attacker".into()),
            Default::default(),
        )
        .await;
    assert!(r.is_err(), "bad secret → refused before any write");
    assert_eq!(
        pinned_key(&s, &id).await,
        None,
        "an unauthenticated heartbeat must not seed the pin"
    );
}

#[tokio::test]
async fn node_reset_crypto_unblocks_a_reinstalled_agent() {
    let pool = open_memory().await.expect("db");
    let s = svc(pool, MockAdapterPort::new());
    let (id, secret) = enroll_node(&s, "cand_1", None, Some("pk-a")).await;
    s.node_heartbeat(
        id.clone(),
        secret.clone(),
        "v2".into(),
        Some("sha256//abc=".into()),
        Some("pk-a".into()),
        Default::default(),
    )
    .await
    .expect("beat");
    // The reinstall case: node-id.json (hence node_id + secret) survived,
    // but node-rpc.key and the inbound cert were regenerated. Without
    // this action the node is unverifiable for good.
    assert!(s.node_reset_crypto(&id, 1).await.expect("reset"));
    let row = hyperion_state::nodes::get_by_node_id(&s.pool, &id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.resp_pubkey, None, "response pubkey forgotten");
    assert_eq!(row.tls_spki_pin, None, "TLS pin forgotten too");
    s.node_heartbeat(
        id.clone(),
        secret,
        "v2".into(),
        None,
        Some("pk-b".into()),
        Default::default(),
    )
    .await
    .expect("re-pin");
    assert_eq!(pinned_key(&s, &id).await.as_deref(), Some("pk-b"));
    // Unknown node is a forgiving no-op, matching node_remove.
    assert!(!s.node_reset_crypto("ghost", 1).await.expect("noop"));
}
