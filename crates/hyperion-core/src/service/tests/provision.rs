//! Tests for `service::provision`.

use super::*;

/// A vhost template change reaches existing sites once: the first boot
/// rewrites every Active vhost, the next one touches nothing.
#[tokio::test]
async fn stale_vhosts_are_rewritten_once() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    s.create(req("ex.cz")).await.expect("create");
    assert_eq!(s.rerender_stale_vhosts().await, 1);
    assert_eq!(s.rerender_stale_vhosts().await, 0);
}

/// A new hosting whose domain is already another hosting's alias would put
/// one name in two vhosts; nginx only warns and serves whichever it read
/// first. Nothing may be provisioned for it.
#[tokio::test]
async fn create_refuses_a_domain_that_is_another_hostings_alias() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks_many());
    s.create(req("first.cz")).await.expect("create first");
    let first = HostingSelector::Domain(Domain::parse("first.cz").unwrap());
    s.hosting_set_aliases(first, vec![Domain::parse("shop.cz").unwrap()])
        .await
        .expect("alias");

    let err = s
        .create(req("shop.cz"))
        .await
        .expect_err("a domain held as an alias must be refused");
    let msg = err.to_string();
    assert!(msg.contains("shop.cz"), "names the domain: {msg}");
    assert!(msg.contains("alias of first.cz"), "names the owner: {msg}");
    assert!(
        hostings::get_by_domain(&pool, "shop.cz")
            .await
            .expect("lookup")
            .is_none(),
        "no hosting row may be left behind"
    );
}

/// The aliases of a new hosting are held to the same rule as an alias edit:
/// not another hosting's domain, not another hosting's alias.
#[tokio::test]
async fn create_refuses_an_alias_that_belongs_to_another_hosting() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks_many());
    s.create(req("first.cz")).await.expect("create first");
    let first = HostingSelector::Domain(Domain::parse("first.cz").unwrap());
    s.hosting_set_aliases(first, vec![Domain::parse("shop.cz").unwrap()])
        .await
        .expect("alias");

    for (taken, why) in [
        ("first.cz", "domain of another hosting"),
        ("shop.cz", "alias of first.cz"),
    ] {
        let mut r = req("second.cz");
        r.aliases = vec![Domain::parse(taken).unwrap()];
        let err = s
            .create(r)
            .await
            .expect_err("an alias another hosting owns must be refused");
        let msg = err.to_string();
        assert!(msg.contains(taken), "names the alias: {msg}");
        assert!(msg.contains(why), "says why: {msg}");
        assert!(!msg.contains("UNIQUE"), "no raw database text: {msg}");
        assert!(
            hostings::get_by_domain(&pool, "second.cz")
                .await
                .expect("lookup")
                .is_none(),
            "no hosting row may be left behind"
        );
    }
}
