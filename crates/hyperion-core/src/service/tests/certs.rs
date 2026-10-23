//! Tests for `service::certs`.

use super::*;

/// A coverage stamp has to describe a STRETCH, not just a start.
/// Protection that stopped and resumed — node down, `[fail2ban]
/// enabled` flipped off and back, agent not running — would otherwise
/// keep its original `since` and back-claim the dark days.
/// A proxied domain's A records are Cloudflare's by design; treating
/// them as "points elsewhere" made the DNS banner a standing false
/// alarm the operator learns to ignore — until the day it is real.
#[test]
fn cloudflare_ranges_classify_real_addresses() {
    use super::{is_cloudflare_ipv4, is_cloudflare_ipv6};
    // Live addresses of the user's own proxied zones.
    for ip in [
        "104.21.0.217",
        "172.67.128.81",
        "188.114.96.9",
        "188.114.97.9",
    ] {
        assert!(is_cloudflare_ipv4(ip), "{ip} is Cloudflare");
    }
    // Direct-hosted addresses must NOT classify.
    for ip in [
        "178.105.99.35",
        "204.168.224.2",
        "185.247.28.72",
        "1.1.1.1",
        "8.8.8.8",
    ] {
        assert!(
            !is_cloudflare_ipv4(ip),
            "{ip} is not a Cloudflare proxy range"
        );
    }
    assert!(is_cloudflare_ipv6("2606:4700:3033::ac43:8051"));
    assert!(!is_cloudflare_ipv6("2001:db8::1"));
    assert!(!is_cloudflare_ipv4("not-an-ip"));
}

/// Regression test for the "every LE cert silently expires at day
/// 90" finding. Three certs are seeded in the DB; the renewal tick
/// is invoked with a `now` that pretends the clock has jumped 80
/// days forward. Only the Let's Encrypt cert that lands inside the
/// 30-day window should be picked up. The actual ACME call fails
/// fast in the test env (placeholder contact email triggers
/// `issue_real_cert`'s validation guard), so the `Failed` outcome
/// is the load-bearing signal that renewal was *attempted* for
/// that domain — and only for that domain.
#[tokio::test]
async fn cert_renew_tick_attempts_renewal_for_expiring_letsencrypt_only() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    // Hosting must exist for `issue_real_cert` to fetch its detail.
    s.create(req("renewable.cz")).await.expect("create");

    let now = now_secs();
    // Pretend 80 days have passed since boot.
    let later = now + 80 * 86_400;

    // renewable.cz : LE,         expires 10d  after `later` → inside window
    // fresh.cz     : LE,         expires 60d  after `later` → outside window
    // bootstrap.cz : self-signed, expires 10d after `later` → wrong issuer
    certificates::upsert(
        &pool,
        "renewable.cz",
        now,
        later + 10 * 86_400,
        "/cert",
        "/key",
        "letsencrypt",
    )
    .await
    .expect("upsert renewable");
    certificates::upsert(
        &pool,
        "fresh.cz",
        now,
        later + 60 * 86_400,
        "/cert",
        "/key",
        "letsencrypt",
    )
    .await
    .expect("upsert fresh");
    certificates::upsert(
        &pool,
        "bootstrap.cz",
        now,
        later + 10 * 86_400,
        "/cert",
        "/key",
        "self-signed",
    )
    .await
    .expect("upsert bootstrap");

    let results = s
        .cert_renew_tick(later, CERT_RENEWAL_WINDOW_DAYS)
        .await
        .expect("tick");

    assert_eq!(
        results.len(),
        1,
        "exactly one LE cert in the renewal window"
    );
    assert_eq!(results[0].domain, "renewable.cz");
    assert!(
        matches!(results[0].outcome, CertRenewOutcome::Failed { .. }),
        "expected Failed renewal in test env (no real ACME), got {:?}",
        results[0].outcome
    );
}

/// A certificate with no hosting behind it — the panel's own is the one
/// that matters — must still be ATTEMPTED, not dropped.
///
/// It used to be routed through `issue_real_cert`, which opens by
/// resolving a hosting, so every tick returned `not found: hosting
/// selector` and the certificate expired regardless. Since the panel
/// vhost sets HSTS for two years, that expiry is a browser interstitial
/// with no click-through on the exact hostname the operator would use to
/// fix it. The outcome here is Failed (the mock cannot really talk to
/// Let's Encrypt) — what this pins is that the reason is no longer a
/// missing hosting.
#[tokio::test]
async fn cert_renew_tick_attempts_a_hosting_less_cert() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let now = now_secs();
    let later = now + 80 * 86_400;

    // No `create()` — deliberately no hosting for this domain.
    certificates::upsert(
        &pool,
        "panel.example.cz",
        now,
        later + 10 * 86_400,
        "/cert",
        "/key",
        "letsencrypt",
    )
    .await
    .expect("upsert panel cert");

    let results = s
        .cert_renew_tick(later, CERT_RENEWAL_WINDOW_DAYS)
        .await
        .expect("tick");
    assert_eq!(results.len(), 1, "the panel cert must be a candidate");
    assert_eq!(results[0].domain, "panel.example.cz");
    match &results[0].outcome {
        CertRenewOutcome::Failed { error } => assert!(
            !error.contains("not found"),
            "must not fail on a missing hosting — that was the bug: {error}"
        ),
        other => panic!("expected an attempt, got {other:?}"),
    }
}

/// A SUSPENDED site still renews. Its vhost serves the ACME challenge
/// above the 503 precisely so this works, so skipping it protected
/// nothing and cost the certificate: a site suspended across its last 30
/// days came back serving an expired one, because the "re-issued on
/// resume" the old comment promised does not exist.
///
/// Critically it must NOT be renewed through `issue_real_cert`, which
/// rewrites the serving vhost and would un-suspend the site as a side
/// effect of a cron tick.
#[tokio::test]
async fn cert_renew_tick_renews_a_suspended_site_without_unsuspending_it() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), suspend_mocks());
    s.create(req("paused.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("paused.cz").unwrap());
    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual {
            message: Some("Unpaid invoice".into()),
        },
    )
    .await
    .expect("suspend");

    let now = now_secs();
    let later = now + 80 * 86_400;
    certificates::upsert(
        &pool,
        "paused.cz",
        now,
        later + 10 * 86_400,
        "/cert",
        "/key",
        "letsencrypt",
    )
    .await
    .expect("upsert");

    let results = s
        .cert_renew_tick(later, CERT_RENEWAL_WINDOW_DAYS)
        .await
        .expect("tick");
    assert_eq!(
        results.len(),
        1,
        "a suspended site's cert must still be a renewal candidate"
    );
    assert!(
        !matches!(results[0].outcome, CertRenewOutcome::Skipped { .. }),
        "a suspended site must be attempted, not skipped: {:?}",
        results[0].outcome
    );
    let after = s.get(sel).await.expect("get");
    assert_eq!(after.state, HostingState::Suspended);

    // NOTE: that renewal takes the direct-issuance branch rather than
    // issue_real_cert — the part that stops a suspended site being
    // silently un-suspended — is NOT asserted here, deliberately. The
    // only observable difference is a call to nginx_write_vhost, which
    // issue_real_cert makes only AFTER its ACME-email check passes; with
    // a valid address the test then talks to the real Let's Encrypt, and
    // no unit test should open orders against a domain we do not own or
    // spend that service's per-hostname failure budget on every CI run.
    // Every other test here relies on the placeholder address for the
    // same reason. The guard is `suspended_like` in cert_renew_tick.
}

/// A subdomain that REUSES a parent wildcard (its cert row shares the
/// wildcard's files) must be skipped by the renewal sweep — the parent
/// renews itself. A sibling with its OWN distinct cert still renews.
#[tokio::test]
async fn cert_renew_tick_skips_wildcard_reference_rows() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let now = now_secs();
    let later = now + 80 * 86_400;
    let exp = later + 10 * 86_400; // inside the renewal window

    // The node wildcard base — flagged wildcard, owns its files.
    certificates::upsert(
        &pool,
        "base.cz",
        now,
        exp,
        "/c/base/f.pem",
        "/c/base/k.pem",
        "letsencrypt",
    )
    .await
    .expect("upsert base");
    certificates::set_wildcard(&pool, "base.cz", true)
        .await
        .expect("flag");
    // A reuse subdomain — same cert files as the parent wildcard.
    certificates::upsert(
        &pool,
        "a.base.cz",
        now,
        exp,
        "/c/base/f.pem",
        "/c/base/k.pem",
        "letsencrypt",
    )
    .await
    .expect("upsert ref");
    // A sibling with its OWN distinct cert — must still renew.
    certificates::upsert(
        &pool,
        "b.base.cz",
        now,
        exp,
        "/c/b.base.cz/f.pem",
        "/c/b.base.cz/k.pem",
        "letsencrypt",
    )
    .await
    .expect("upsert own");

    let results = s
        .cert_renew_tick(later, CERT_RENEWAL_WINDOW_DAYS)
        .await
        .expect("tick");
    let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
    assert!(
        domains.contains(&"base.cz"),
        "wildcard base renews: {domains:?}"
    );
    assert!(
        domains.contains(&"b.base.cz"),
        "own-cert sibling renews: {domains:?}"
    );
    assert!(
        !domains.contains(&"a.base.cz"),
        "reuse reference must be skipped: {domains:?}"
    );
}

#[tokio::test]
async fn cert_renew_tick_with_no_certs_returns_empty() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let r = s.cert_renew_tick(now_secs(), 30).await.expect("tick");
    assert!(r.is_empty());
}

/// DNS-01 finish must not turn a suspended site back into a serving one:
/// `nginx_write_vhost` renders the live vhost.
#[tokio::test]
async fn dns01_install_keeps_a_suspended_site_suspended() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), suspend_mocks());
    s.create(req("paused.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("paused.cz").unwrap());
    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual {
            message: Some("Unpaid invoice".into()),
        },
    )
    .await
    .expect("suspend");
    let detail = s.get(sel.clone()).await.expect("get");

    // Fresh service over the same pool: the serving vhost is forbidden,
    // the suspended re-apply must carry the stored notice + aliases.
    let mut m = MockAdapterPort::new();
    m.expect_nginx_write_vhost().times(0);
    let aliases = detail.aliases.clone();
    m.expect_nginx_apply_suspended()
        .times(1)
        .withf(move |d, a, reason| {
            d == "paused.cz" && *a == aliases && reason.as_deref() == Some("Unpaid invoice")
        })
        .returning(|_, _, _| Ok(()));
    let s = svc(pool.clone(), m);
    s.install_dns01_cert(&detail, &cert_for("paused.cz"))
        .await
        .expect("install");
    assert_eq!(s.get(sel).await.unwrap().state, HostingState::Suspended);
    assert!(certificates::is_wildcard(&pool, "paused.cz").await.unwrap());
}

#[tokio::test]
async fn dns01_install_rewrites_the_serving_vhost_for_an_active_site() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("live.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("live.cz").unwrap());
    let detail = s.get(sel).await.expect("get");

    let mut m = MockAdapterPort::new();
    m.expect_nginx_apply_suspended().times(0);
    m.expect_nginx_write_vhost().times(1).returning(|_| Ok(()));
    let s = svc(pool.clone(), m);
    s.install_dns01_cert(&detail, &cert_for("live.cz"))
        .await
        .expect("install");
    assert!(certificates::is_wildcard(&pool, "live.cz").await.unwrap());
}

/// A wildcard LE cert, `days` from expiry at the returned `now`.
async fn seed_wildcard(
    s: &HostingService<MockAdapterPort>,
    domain: &str,
    days: i64,
    delegated: bool,
) -> i64 {
    let now = now_secs();
    certificates::upsert(
        &s.pool,
        domain,
        now - 60 * 86_400,
        now + days * 86_400 + 3_600,
        "/c/f.pem",
        "/c/k.pem",
        "letsencrypt",
    )
    .await
    .expect("upsert");
    certificates::set_wildcard(&s.pool, domain, true)
        .await
        .expect("flag");
    if delegated {
        certificates::set_delegated(&s.pool, domain, true)
            .await
            .expect("delegate");
    }
    now
}

#[tokio::test]
async fn delegated_wildcard_is_skipped_without_manual_alert() {
    use hyperion_state::web_users::WebRole;
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let me = seed_web_user(&s, "boss", WebRole::Admin).await;
    let now = seed_wildcard(&s, "base.cz", 25, true).await;
    let r = s
        .cert_renew_tick(now, CERT_RENEWAL_WINDOW_DAYS)
        .await
        .expect("tick");
    let CertRenewOutcome::Skipped { reason } = &r[0].outcome else {
        panic!("expected skipped: {:?}", r[0].outcome)
    };
    assert!(reason.contains("delegated"), "{reason}");
    let kinds = manual_kinds(&s, me).await;
    assert!(
        !kinds.iter().any(|k| k.starts_with("cert.wildcard_manual:")),
        "{kinds:?}"
    );
}

#[tokio::test]
async fn delegated_wildcard_alerts_at_14_days() {
    use hyperion_state::web_users::WebRole;
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let me = seed_web_user(&s, "boss", WebRole::Admin).await;
    let now = seed_wildcard(&s, "base.cz", 10, true).await;
    s.cert_renew_tick(now, CERT_RENEWAL_WINDOW_DAYS)
        .await
        .expect("tick");
    assert!(manual_kinds(&s, me)
        .await
        .contains(&"cert.wildcard_manual:base.cz".to_string()));
}

#[tokio::test]
async fn undelegated_wildcard_still_alerts() {
    use hyperion_state::web_users::WebRole;
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let me = seed_web_user(&s, "boss", WebRole::Admin).await;
    let now = seed_wildcard(&s, "base.cz", 25, false).await;
    let r = s
        .cert_renew_tick(now, CERT_RENEWAL_WINDOW_DAYS)
        .await
        .expect("tick");
    let CertRenewOutcome::Skipped { reason } = &r[0].outcome else {
        panic!("expected skipped: {:?}", r[0].outcome)
    };
    assert!(!reason.contains("delegated"), "{reason}");
    assert!(manual_kinds(&s, me)
        .await
        .contains(&"cert.wildcard_manual:base.cz".to_string()));
}
