//! Tests for `service::os_updates`.

use super::*;

#[test]
fn os_security_alert_waits_out_the_grace_period() {
    let now = 10 * 86_400;
    let kinds = |os: &hyperion_types::OsUpdateStatus, dpkg: Option<i64>| -> Vec<String> {
        os_update_alerts(os, now, dpkg)
            .into_iter()
            .map(|a| a.kind)
            .collect()
    };
    // Two days pending: normal for unattended-upgrades, no alert.
    assert!(kinds(&os_status(4, now - 2 * 86_400, now - 60), None).is_empty());
    // Three days: say so.
    assert_eq!(
        kinds(&os_status(4, now - 3 * 86_400, now - 60), None),
        vec!["os_security_updates"]
    );
    // Packages changed after the stored check: the count may be describing
    // updates already installed, so it is not repeated.
    assert!(kinds(&os_status(4, now - 5 * 86_400, now - 600), Some(now - 60)).is_empty());
    // Never checked is not "no updates" and not "updates" either.
    assert!(kinds(&os_status(0, 0, 0), None).is_empty());
}

#[test]
fn os_reboot_and_stale_index_alerts() {
    let now = 10 * 86_400;
    let os = hyperion_types::OsUpdateStatus {
        checked_at: now - 60,
        index_refreshed_at: now - 4 * 86_400,
        reboot_required: true,
        reboot_packages: vec![
            "a".into(),
            "b".into(),
            "c".into(),
            "linux-image-amd64".into(),
        ],
        error: "could not refresh the package index (exit 100)".into(),
        ..Default::default()
    };
    let alerts = os_update_alerts(&os, now, None);
    let reboot = alerts
        .iter()
        .find(|a| a.kind == "os_reboot_required")
        .expect("reboot alert");
    assert!(
        reboot.message.contains("(a, b, c, …)"),
        "{}",
        reboot.message
    );
    let stale = alerts
        .iter()
        .find(|a| a.kind == "os_index_stale")
        .expect("stale alert");
    assert!(stale.message.contains("4 days"), "{}", stale.message);
    assert!(stale.message.contains("exit 100"), "{}", stale.message);
    // An index that has never refreshed has no age to report.
    let fresh_install = hyperion_types::OsUpdateStatus {
        checked_at: now - 60,
        ..Default::default()
    };
    assert!(os_update_alerts(&fresh_install, now, None).is_empty());
}
