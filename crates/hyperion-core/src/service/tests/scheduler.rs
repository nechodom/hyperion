//! Tests for `service::scheduler`.

use super::*;

#[tokio::test]
async fn upcoming_expiries_filters_by_window() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("a.cz")).await.expect("a");
    let sel = HostingSelector::Domain(Domain::parse("a.cz").unwrap());
    let exp = now_secs() + 10 * 86_400;
    let mut e = hyperion_types::HostingExpiry::defaults();
    e.expires_at = Some(exp);
    s.set_expiry(sel, e).await.expect("set");

    let within_5d = s.upcoming_expiries(5 * 86_400).await.expect("up");
    assert!(within_5d.is_empty(), "10d > 5d window");

    let within_30d = s.upcoming_expiries(30 * 86_400).await.expect("up");
    assert_eq!(within_30d.len(), 1);
    assert_eq!(within_30d[0].domain, "a.cz");
}
