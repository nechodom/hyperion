//! Tests for `service::dashboard`.

use super::*;

#[test]
fn cert_alert_links_only_hosting_certs_to_hosting_detail() {
    use super::{cert_alert_href, wildcard_renew_hint};
    assert_eq!(cert_alert_href("a.cz", true, false), "/hostings/a.cz");
    assert_eq!(cert_alert_href("a.cz", true, true), "/hostings/a.cz");
    // A node's preview wildcard has no hosting: /hostings/<base> was a 404.
    assert_eq!(
        cert_alert_href("hosting.nechodom.cz", false, true),
        "/settings/https#preview-wildcard"
    );
    // The panel's own certificate.
    assert_eq!(
        cert_alert_href("panel.a.cz", false, false),
        "/settings/https"
    );
    assert!(wildcard_renew_hint(true).contains("SSL tab"));
    assert!(wildcard_renew_hint(false).contains("Preview certificates"));
}

/// The rest of the node's views of a trashed site: the dashboard, the
/// certificate overview, and the WordPress asset library.
#[tokio::test]
async fn a_trashed_site_raises_no_alert_lists_no_cert_and_runs_no_wp_cli() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let site = hosting_for_packages(&s, "kos.cz").await;
    hyperion_state::hosting_kv::set(
        &pool,
        site.id.as_str(),
        CARE_REPORT_BLOCKED_KEY,
        "kos.cz",
        now_secs(),
    )
    .await
    .expect("marker");
    hyperion_state::certificates::upsert(
        &pool,
        "kos.cz",
        1,
        now_secs() + 60 * 86_400,
        "/c",
        "/k",
        "Let's Encrypt",
    )
    .await
    .expect("cert");
    let blocked =
        |alerts: &[DashboardAlert]| alerts.iter().any(|a| a.kind == "care_report_blocked");
    assert!(blocked(&s.dashboard_alerts().await.expect("alerts")));
    assert!(s
        .cert_overview()
        .await
        .expect("certs")
        .iter()
        .any(|c| c.domain == "kos.cz"));

    hyperion_state::hostings::mark_trashed(&pool, &site.id, now_secs())
        .await
        .expect("trash");

    assert!(
        !blocked(&s.dashboard_alerts().await.expect("alerts")),
        "nothing is owed to a site in the trash"
    );
    assert!(
        !s.cert_overview()
            .await
            .expect("certs")
            .iter()
            .any(|c| c.domain == "kos.cz"),
        "a trashed site's certificate is not one the operator runs"
    );
    let err = s
        .wp_install_from_asset(HostingSelector::Id(site.id.clone()), 1, false)
        .await
        .expect_err("wp-cli must not run for a trashed site");
    assert!(matches!(err, RpcError::Conflict { .. }), "{err:?}");
}
