//! Tests for `service::kv_expiry`.

use super::*;

/// A value that was never measured prints a dash, never a zero. The whole
/// letter is built on refusing to state a figure it cannot evidence, and
/// "0 attacks blocked" on a site nobody watched is exactly that lie.
#[test]
fn an_unmeasured_value_is_a_dash_not_a_zero() {
    let from = 1_780_272_000;
    let report = CareReport {
        hosting_id: hyperion_types::HostingId("h".into()),
        domain: "example.cz".into(),
        period_start: from,
        period_end: from + 30 * 86_400,
        attacks_blocked: None,
        attacks_covered_since: None,
        updates_applied: None,
        usage: None,
        uptime: None,
        backups: None,
        integrity: None,
        service_work: None,
        performance: None,
    };
    let (_, _, fields) = care_report_parts(&en(), &report, "example.cz");
    let map: std::collections::BTreeMap<&str, String> = fields.into_iter().collect();
    for key in [
        "attacks_count",
        "updates_count",
        "traffic_requests",
        "uptime_pct",
        "backups_count",
    ] {
        assert_eq!(
            map.get(key).map(String::as_str),
            Some("—"),
            "{key} must not invent a figure"
        );
    }
}

#[tokio::test]
async fn set_expiry_schedules_actions_and_clear_cancels() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    let exp = now_secs() + 2 * 86_400;
    let mut e = hyperion_types::HostingExpiry::defaults();
    e.expires_at = Some(exp);
    e.grace_days = 7;
    e.owner_email = Some("k@x.cz".into());
    let stored = s.set_expiry(sel.clone(), e).await.expect("set");
    assert_eq!(stored.expires_at, Some(exp));
    assert_eq!(stored.grace_days, 7);

    let due_far_future = hyperion_state::scheduler::pending_due(&pool, exp + 100 * 86_400, 100)
        .await
        .expect("pending");
    let actions: Vec<&str> = due_far_future.iter().map(|a| a.action.as_str()).collect();
    assert!(actions.contains(&"suspend_expired"));
    assert!(actions.contains(&"delete_expired"));
    assert!(actions.contains(&"notify_1d"));

    s.clear_expiry(sel).await.expect("clear");
    let after = hyperion_state::scheduler::pending_due(&pool, exp + 100 * 86_400, 100)
        .await
        .expect("pending");
    assert!(after.is_empty(), "actions canceled");
}

#[tokio::test]
async fn scheduler_tick_runs_suspend_for_expired_hosting() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), suspend_mocks());
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());

    // Written straight to the row, NOT through set_expiry.
    //
    // set_expiry now reads a past date as "renews on this day and month,
    // with us since this year" and rolls it forward, so it can no longer
    // produce an already-expired hosting — that is the whole point of the
    // change. The state under test is still perfectly real: it is what
    // every hosting looks like the day after its expiry passes. So the
    // row is put into that state directly, the way time does it.
    let past = now_secs() - 86_400;
    hyperion_state::scheduler::set_expiry(
        &pool,
        &s.get(sel.clone()).await.expect("get").id,
        Some(past),
        None,
        30,
        "30,7,1",
        None,
        now_secs(),
    )
    .await
    .expect("set expiry row");
    let processed = s.scheduler_tick().await.expect("tick");
    assert!(processed >= 1, "processed: {processed}");

    let detail = s.get(sel).await.expect("get");
    assert_eq!(detail.state, HostingState::Suspended);
}
