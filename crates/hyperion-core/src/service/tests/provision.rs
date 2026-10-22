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
