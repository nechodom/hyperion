//! Tests for `service::url_monitor`: the master's URL checks.

use super::*;
use crate::service::url_monitor::{
    cert_alert_due, cert_check_due, parse_cert_expiry, url_check_outcome,
};
use hyperion_state::web_users::WebRole;
use hyperion_types::url_monitor::{UrlAlertContext, UrlMonitorInput};

/// Real output of `curl -w '%{certs}'` against a Let's Encrypt site (curl
/// 8.14.1, OpenSSL), taken on a node. The leaf comes first.
const CURL_CERTS: &str = include_str!("fixtures/curl_certs_chain.txt");

fn result(ok: bool, status: Option<i64>, error: Option<&str>, hard: bool) -> HttpProbeResult {
    HttpProbeResult {
        success: ok,
        http_status: status,
        response_ms: 12,
        error_message: error.map(str::to_string),
        hard_failure: hard,
    }
}

fn input(url: &str) -> UrlMonitorInput {
    UrlMonitorInput {
        url: url.into(),
        interval_secs: 30,
        alert_after_fails: 3,
        ..Default::default()
    }
}

/// A master with the module on for the cluster and one administrator.
async fn url_master() -> (HostingService<MockAdapterPort>, SqlitePool) {
    let pool = open_memory().await.expect("open");
    hyperion_state::docker::set_cluster_installed(&pool)
        .await
        .expect("cluster on");
    let s = svc(pool.clone(), happy_mocks());
    seed_web_user(&s, "boss", WebRole::Admin).await;
    (s, pool)
}

/// [`url_master`] that can attempt to send: the relay refuses every message
/// and loopback is refused as a webhook, so what a test counts is what was
/// ATTEMPTED.
async fn url_master_sending() -> (HostingService<MockAdapterPort>, SqlitePool) {
    let pool = open_memory().await.expect("open");
    hyperion_state::docker::set_cluster_installed(&pool)
        .await
        .expect("cluster on");
    let s = svc(pool.clone(), happy_mocks())
        .with_email(Some(refusing_relay()), Some("ops@example.cz".into()))
        .with_slack_webhook(Some("https://127.0.0.1/hook".into()));
    seed_web_user(&s, "boss", WebRole::Admin).await;
    (s, pool)
}

fn site_url(site: &TestSite) -> String {
    format!("https://{}/", site.host())
}

/// Move every timestamp ten minutes back so the 30 s interval has elapsed.
async fn url_age(pool: &SqlitePool) {
    for sql in [
        "UPDATE url_monitor_samples SET sampled_at = sampled_at - 600",
        "UPDATE url_monitors SET last_sampled_at = last_sampled_at - 600 \
             WHERE last_sampled_at > 0",
        "UPDATE url_monitors SET last_alert_at = last_alert_at - 600 \
             WHERE last_alert_at IS NOT NULL",
    ] {
        sqlx::query(sql).execute(pool).await.expect("age");
    }
}

async fn url_tick_as(
    s: &HostingService<MockAdapterPort>,
    pool: &SqlitePool,
    site: &TestSite,
    mode: SiteMode,
) -> Vec<hyperion_types::url_monitor::UrlMonitorEvent> {
    url_age(pool).await;
    site.set(mode);
    s.url_monitor_tick().await.expect("tick")
}

/// (kind, severity, title, body) of every bell row, oldest first.
async fn url_bells(pool: &SqlitePool) -> Vec<(String, String, String, String)> {
    sqlx::query_as("SELECT kind, severity, title, body FROM notifications ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("notifications")
}

/// (subject, body) of every URL check mail attempted, oldest first.
async fn url_mails(s: &HostingService<MockAdapterPort>) -> Vec<(String, String)> {
    mails_of(s, "url_monitor").await
}

async fn mails_of(s: &HostingService<MockAdapterPort>, kind: &str) -> Vec<(String, String)> {
    let mut rows = hyperion_state::email_log::list(&s.pool, None, 100)
        .await
        .expect("email log");
    rows.reverse();
    rows.into_iter()
        .filter(|r| r.kind == kind)
        .map(|r| (r.subject, r.body_preview))
        .collect()
}

async fn audits(s: &HostingService<MockAdapterPort>, action: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = ?")
        .bind(action)
        .fetch_one(&s.pool)
        .await
        .expect("count");
    n
}

/// Park a decided alert the way a tick would.
async fn park(pool: &SqlitePool, id: i64, down: bool, error: Option<&str>) {
    hyperion_state::url_monitors::record_transition(pool, id, down, error, now_secs())
        .await
        .expect("transition");
}

// ---------------------------------------------------------------------------
// Deciding
// ---------------------------------------------------------------------------

/// The decision is `monitor_transition` over the same window as the
/// per-hosting monitor, so a flapping sequence announces exactly what
/// `replay_probes` says the per-hosting monitor would.
#[tokio::test]
async fn reuses_anti_flapping() {
    use Probe::{Hard, Ok as Up, Soft};
    let sequences: Vec<Vec<Probe>> = vec![
        vec![
            Up, Soft, Up, Soft, Up, Soft, Up, Soft, Soft, Up, Up, Up, Up, Soft, Up,
        ],
        vec![
            Up, Hard, Hard, Up, Up, Up, Soft, Soft, Soft, Soft, Up, Up, Up, Soft, Up,
        ],
        vec![Soft, Soft, Soft, Soft, Soft, Up, Up, Up, Up, Up],
        vec![Up, Up, Up, Up, Up, Up],
    ];
    for probes in sequences {
        let (s, pool) = url_master().await;
        let id = s
            .url_monitor_set(input("https://example.test/"))
            .await
            .expect("set");
        let mut got = Vec::new();
        for (i, p) in probes.iter().enumerate() {
            let at = 1_000 + 60 * i as i64;
            let r = match p {
                Probe::Ok => result(true, Some(200), None, false),
                Probe::Soft => result(false, None, Some("curl: (28)"), false),
                Probe::Hard => result(false, Some(500), Some("HTTP 500"), true),
            };
            if let Some(t) = s
                .url_apply_sample(id, "https://example.test/", &r, at)
                .await
                .expect("apply")
            {
                got.push((i, t));
            }
        }
        assert_eq!(got, replay_probes(&probes, 3), "{probes:?}");
        let row = hyperion_state::url_monitors::get(&pool, id)
            .await
            .expect("get")
            .expect("row");
        let alerting = got
            .last()
            .is_some_and(|(_, t)| *t == MonitorTransition::Down);
        assert_eq!(row.alert_state == "alerting", alerting, "{probes:?}");
    }
}

/// Down and back up before anyone was told: nobody needs telling.
#[tokio::test]
async fn a_recovery_before_the_alert_went_out_cancels_it() {
    let (s, pool) = url_master().await;
    let id = s
        .url_monitor_set(input("https://example.test/"))
        .await
        .expect("set");
    for (i, ok) in [false, false, false, true, true].into_iter().enumerate() {
        let r = if ok {
            result(true, Some(200), None, false)
        } else {
            result(false, None, Some("curl: (28)"), false)
        };
        s.url_apply_sample(id, "https://example.test/", &r, 1_000 + 60 * i as i64)
            .await
            .expect("apply");
    }
    let row = hyperion_state::url_monitors::get(&pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.alert_state, "ok");
    assert_eq!(row.pending_alert, None, "the down was never announced");
}

#[test]
fn expected_status_is_honoured() {
    // A page that answers 401 on purpose passes when 401 is what is wanted.
    let r = url_check_outcome(result(false, Some(401), Some("HTTP 401"), false), Some(401));
    assert!(
        r.success && r.error_message.is_none() && !r.hard_failure,
        "{r:?}"
    );
    // ...and a 200 fails when it is not.
    let r = url_check_outcome(result(true, Some(200), None, false), Some(401));
    assert!(!r.success, "{r:?}");
    let msg = r.error_message.clone().unwrap_or_default();
    assert!(msg.contains("200") && msg.contains("401"), "{r:?}");
    assert!(
        !r.hard_failure,
        "a wrong but healthy answer is not a broken page"
    );
    // A 5xx that is not the wanted status stays a hard failure.
    let r = url_check_outcome(result(false, Some(502), Some("HTTP 502"), true), Some(200));
    assert!(!r.success && r.hard_failure, "{r:?}");
    // No expectation: the probe's own verdict stands.
    let r = url_check_outcome(result(false, Some(401), Some("HTTP 401"), false), None);
    assert!(!r.success, "{r:?}");
    // No status at all is no match, whatever was wanted.
    let r = url_check_outcome(result(false, None, Some("curl: (7)"), false), Some(200));
    assert!(!r.success && r.http_status.is_none(), "{r:?}");
    // The status matches but the page is a WordPress fatal: still down.
    let r = url_check_outcome(
        result(
            false,
            Some(200),
            Some("HTTP 200 but WordPress critical error page"),
            true,
        ),
        Some(200),
    );
    assert!(!r.success && r.hard_failure, "{r:?}");
    // A connection that dropped after the headers is not a pass either.
    let r = url_check_outcome(
        result(false, Some(200), Some("curl: (18)"), false),
        Some(200),
    );
    assert!(!r.success, "{r:?}");
}

#[tokio::test]
async fn expected_status_reaches_the_tick() {
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    site.set(SiteMode::ServerError);
    let (s, pool) = url_master().await;
    let mut wants_500 = input(&site_url(&site));
    wants_500.expected_status = Some(500);
    let a = s.url_monitor_set(wants_500).await.expect("a");
    let b = s.url_monitor_set(input(&site_url(&site))).await.expect("b");
    s.url_monitor_tick().await.expect("tick");
    let ok = |id| {
        let pool = pool.clone();
        async move {
            let (ok,): (bool,) =
                sqlx::query_as("SELECT success FROM url_monitor_samples WHERE monitor_id = ?")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .expect("sample");
            ok
        }
    };
    assert!(ok(a).await, "500 was what it wanted");
    assert!(
        !ok(b).await,
        "500 is down for a check that wants no particular status"
    );
}

// ---------------------------------------------------------------------------
// Ticking
// ---------------------------------------------------------------------------

/// A hanging site holds up its own sample only: one tick, hung sites and a
/// healthy one, takes about one probe timeout, not one per site.
#[tokio::test]
async fn one_slow_site_does_not_delay_others() {
    if curl_missing() {
        return;
    }
    let up = spawn_test_site().await;
    let hung_a = spawn_test_site().await;
    let hung_b = spawn_test_site().await;
    hung_a.set(SiteMode::Slow(120));
    hung_b.set(SiteMode::Slow(120));
    let (s, pool) = url_master().await;
    let up_id = s.url_monitor_set(input(&site_url(&up))).await.expect("up");
    let a = s
        .url_monitor_set(input(&site_url(&hung_a)))
        .await
        .expect("a");
    let b = s
        .url_monitor_set(input(&site_url(&hung_b)))
        .await
        .expect("b");

    let started = std::time::Instant::now();
    s.url_monitor_tick().await.expect("tick");
    let took = started.elapsed().as_secs();
    let max_time: u64 = PROBE_MAX_TIME_SECS.parse().expect("number");
    assert!(
        took < max_time + 8,
        "two hung sites sampled one after the other would take {} s; this took {took} s",
        2 * max_time
    );

    for (id, want) in [(up_id, true), (a, false), (b, false)] {
        let rows: Vec<(bool,)> =
            sqlx::query_as("SELECT success FROM url_monitor_samples WHERE monitor_id = ?")
                .bind(id)
                .fetch_all(&pool)
                .await
                .expect("samples");
        assert_eq!(rows, vec![(want,)], "monitor {id}");
    }
}

#[tokio::test]
async fn only_due_checks_are_sampled() {
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let (s, pool) = url_master().await;
    let id = s
        .url_monitor_set(input(&site_url(&site)))
        .await
        .expect("set");
    s.url_monitor_tick().await.expect("first");
    s.url_monitor_tick()
        .await
        .expect("second, 30 s have not passed");
    assert_eq!(
        hyperion_state::url_monitors::sample_count(&pool, id)
            .await
            .expect("count"),
        1
    );
    url_age(&pool).await;
    s.url_monitor_tick().await.expect("third");
    assert_eq!(
        hyperion_state::url_monitors::sample_count(&pool, id)
            .await
            .expect("count"),
        2
    );
}

/// The decision stays parked until the web layer says it was handled.
#[tokio::test]
async fn pending_alert_survives_until_acknowledged() {
    use SiteMode::{ServerError, Up};
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let (s, pool) = url_master().await;
    let id = s
        .url_monitor_set(input(&site_url(&site)))
        .await
        .expect("set");
    assert!(url_tick_as(&s, &pool, &site, Up).await.is_empty());
    // A real 500 is a hard failure: down after two.
    assert!(url_tick_as(&s, &pool, &site, ServerError).await.is_empty());
    let events = url_tick_as(&s, &pool, &site, ServerError).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].id, id);
    assert!(events[0].down);
    assert_eq!(events[0].error.as_deref(), Some("HTTP 500"));
    assert_eq!(events[0].url, site_url(&site));

    // Nothing was acknowledged, so it is still there, tick after tick.
    let again = s.url_monitor_tick().await.expect("tick");
    assert_eq!(again, events);
    let again = url_tick_as(&s, &pool, &site, ServerError).await;
    assert_eq!(again, events);

    s.url_monitor_alert(id, UrlAlertContext::default())
        .await
        .expect("alert");
    assert!(s.url_monitor_tick().await.expect("tick").is_empty());

    // The way back is a second event, down = false.
    assert!(url_tick_as(&s, &pool, &site, Up).await.is_empty());
    let back = url_tick_as(&s, &pool, &site, Up).await;
    assert_eq!(back.len(), 1, "{back:?}");
    assert!(!back[0].down);
}

#[tokio::test]
async fn no_check_runs_when_module_off() {
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let err = s
        .url_monitor_set(input(&site_url(&site)))
        .await
        .expect_err("the module is off");
    assert!(err.to_string().contains("Docker module"), "{err}");

    // A row left over from before is neither listed nor sampled.
    let fields = hyperion_state::url_monitors::Fields {
        url: &site_url(&site),
        interval_secs: 30,
        expected_status: None,
        alert_after_fails: 3,
        alert_email: None,
        slack: hyperion_state::url_monitors::SecretField::Keep,
        webhook: hyperion_state::url_monitors::SecretField::Keep,
        node_id: None,
        node_manual: false,
    };
    let id = hyperion_state::url_monitors::insert(&pool, &fields, 1)
        .await
        .expect("insert");
    let list = s.url_monitor_list().await.expect("list");
    assert!(!list.enabled && list.monitors.is_empty(), "{list:?}");
    assert!(s.url_monitor_tick().await.expect("tick").is_empty());
    assert_eq!(
        hyperion_state::url_monitors::sample_count(&pool, id)
            .await
            .expect("count"),
        0,
        "nothing was probed"
    );
    // No alert is sent for it either.
    park(&pool, id, true, Some("x")).await;
    s.url_monitor_alert(id, UrlAlertContext::default())
        .await
        .expect("alert is a no-op");
    assert!(url_bells(&pool).await.is_empty());

    hyperion_state::docker::set_cluster_installed(&pool)
        .await
        .expect("on");
    let list = s.url_monitor_list().await.expect("list");
    assert!(list.enabled);
    assert_eq!(list.monitors.len(), 1);
}

#[tokio::test]
async fn removing_the_module_deletes_the_checks_and_their_history() {
    let (s, pool) = url_master().await;
    let id = s
        .url_monitor_set(input("https://example.test/"))
        .await
        .expect("set");
    s.url_apply_sample(
        id,
        "https://example.test/",
        &result(true, Some(200), None, false),
        1_000,
    )
    .await
    .expect("sample");
    s.docker_cluster_remove().await.expect("remove");
    assert_eq!(
        hyperion_state::url_monitors::count(&pool)
            .await
            .expect("count"),
        0
    );
    assert_eq!(
        hyperion_state::url_monitors::sample_count(&pool, id)
            .await
            .expect("count"),
        0
    );
}

#[tokio::test]
async fn samples_pruned_after_7_days() {
    let (s, pool) = url_master().await;
    let id = s
        .url_monitor_set(input("https://example.test/"))
        .await
        .expect("set");
    let now = now_secs();
    // Not due, so the tick has nothing to probe but still tidies up.
    hyperion_state::url_monitors::set_sampled(&pool, id, now)
        .await
        .expect("stamp");
    for age_days in [10, 8, 6, 1] {
        hyperion_state::url_monitors::insert_sample(
            &pool,
            id,
            &hyperion_state::url_monitors::Sample {
                sampled_at: now - age_days * 86_400,
                success: true,
                http_status: Some(200),
                response_ms: 5,
                error_message: None,
            },
        )
        .await
        .expect("sample");
    }
    s.url_tick_at(now).await.expect("tick");
    let ages: Vec<(i64,)> = sqlx::query_as(
        "SELECT (? - sampled_at) / 86400 FROM url_monitor_samples ORDER BY sampled_at",
    )
    .bind(now)
    .fetch_all(&pool)
    .await
    .expect("left");
    assert_eq!(ages, vec![(6,), (1,)]);
}

#[tokio::test]
async fn a_worker_runs_no_url_checks() {
    let dir = tempfile::tempdir().expect("dir");
    let state = dir.path().join("node-id.json");
    std::fs::write(&state, b"{}").expect("state file");
    let pool = open_memory().await.expect("open");
    hyperion_state::docker::set_cluster_installed(&pool)
        .await
        .expect("on");
    let s = svc(pool, happy_mocks()).with_node_state_file(state);
    assert!(s.url_monitor_list().await.is_err());
    assert!(s
        .url_monitor_set(input("https://example.test/"))
        .await
        .is_err());
    assert!(s.url_monitor_delete(1, "x").await.is_err());
    assert!(s.url_monitor_tick().await.is_err());
    assert!(s
        .url_monitor_alert(1, UrlAlertContext::default())
        .await
        .is_err());
}

/// A box with no workers records `[cluster] mode = "standalone"`; it is not
/// a worker, so its URL checks work like a master's.
#[tokio::test]
async fn a_standalone_box_runs_url_checks() {
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(&cfg, b"[cluster]\nmode = \"standalone\"\n").expect("write");
    let (s, _pool) = url_master().await;
    let s = s.with_agent_config_path(cfg);
    assert!(s.is_standalone());
    s.url_monitor_set(input("https://example.test/"))
        .await
        .expect("saved");
    assert_eq!(s.url_monitor_list().await.expect("list").monitors.len(), 1);
    s.url_monitor_tick().await.expect("tick");
}

// ---------------------------------------------------------------------------
// Saving
// ---------------------------------------------------------------------------

#[tokio::test]
async fn set_validates_url() {
    let (s, pool) = url_master().await;
    let refuse = |what: &'static str, i: UrlMonitorInput| {
        let s = &s;
        async move {
            let err = s
                .url_monitor_set(i)
                .await
                .expect_err(&format!("{what} must be refused"));
            assert!(
                matches!(err, RpcError::Validation { .. }),
                "{what}: {err:?}"
            );
            err.to_string()
        }
    };
    for (what, url) in [
        ("empty", ""),
        ("no scheme", "example.test"),
        ("ftp", "ftp://example.test/"),
        ("file", "file:///etc/passwd"),
        ("script", "javascript:alert(1)"),
        ("no host", "https:///x"),
        ("password", "http://user:pw@example.test/"),
        ("user only", "https://user@example.test/"),
        ("space", "https://example.test/a b"),
        ("newline", "https://example.test/\nHost: x"),
    ] {
        refuse(what, input(url)).await;
    }
    let long = format!("https://example.test/{}", "a".repeat(3000));
    refuse("too long", input(&long)).await;

    let mut i = input("https://example.test/");
    i.interval_secs = 29;
    let msg = refuse("interval under 30", i).await;
    assert!(msg.contains("30"), "{msg}");
    let mut i = input("https://example.test/");
    i.alert_after_fails = 0;
    refuse("alert after 0", i).await;
    for status in [99, 600, -1] {
        let mut i = input("https://example.test/");
        i.expected_status = Some(status);
        refuse("status out of range", i).await;
    }
    let mut i = input("https://example.test/");
    i.alert_slack_webhook = Some("ftp://hooks.example/x".into());
    refuse("slack ftp", i).await;
    let mut i = input("https://example.test/");
    i.alert_webhook_url = Some("javascript:x".into());
    refuse("webhook script", i).await;
    let mut i = input("https://example.test/");
    i.alert_email = Some("not-an-address".into());
    refuse("email", i).await;
    assert_eq!(
        hyperion_state::url_monitors::count(&pool)
            .await
            .expect("count"),
        0,
        "nothing refused was stored"
    );

    // What is fine is stored as written.
    let mut ok = input("https://example.test:8443/health?token=abc");
    ok.expected_status = Some(204);
    ok.alert_email = Some("a@example.cz, b@example.cz".into());
    ok.alert_slack_webhook = Some("https://hooks.example/abc".into());
    ok.alert_webhook_url = Some("http://hooks.example/def".into());
    let id = s.url_monitor_set(ok).await.expect("valid");
    s.url_monitor_set(input("http://example.test/"))
        .await
        .expect("http");
    let row = hyperion_state::url_monitors::get(&pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.url, "https://example.test:8443/health?token=abc");
    assert_eq!(row.expected_status, Some(204));
    assert_eq!(row.alert_after_fails, 3);
}

#[tokio::test]
async fn saved_webhooks_are_never_given_back() {
    let (s, pool) = url_master().await;
    let mut i = input("https://example.test/");
    i.alert_slack_webhook = Some("https://hooks.example/slack-secret".into());
    i.alert_webhook_url = Some("https://hooks.example/generic-secret".into());
    let id = s.url_monitor_set(i).await.expect("set");

    let list = s.url_monitor_list().await.expect("list");
    let v = &list.monitors[0];
    assert!(v.alert_slack_set && v.alert_webhook_set);
    let wire = serde_json::to_string(&list).expect("json");
    assert!(
        !wire.contains("secret") && !wire.contains("hooks.example"),
        "{wire}"
    );

    // Saving again with blank fields keeps both.
    let mut again = input("https://example.test/changed");
    again.id = Some(id);
    s.url_monitor_set(again).await.expect("resave");
    let row = hyperion_state::url_monitors::get(&pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.url, "https://example.test/changed");
    assert_eq!(
        row.alert_slack_webhook.as_deref(),
        Some("https://hooks.example/slack-secret")
    );
    assert_eq!(
        row.alert_webhook_url.as_deref(),
        Some("https://hooks.example/generic-secret")
    );

    // Clearing is explicit.
    let mut clear = input("https://example.test/changed");
    clear.id = Some(id);
    clear.clear_slack_webhook = true;
    s.url_monitor_set(clear).await.expect("clear");
    let row = hyperion_state::url_monitors::get(&pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.alert_slack_webhook, None);
    assert!(row.alert_webhook_url.is_some());

    // The audit trail says a check changed, not where its webhooks go or
    // what token its address carries.
    let details: Vec<(String,)> =
        sqlx::query_as("SELECT payload_json FROM audit_log WHERE action LIKE 'url_monitor.%'")
            .fetch_all(&pool)
            .await
            .expect("audit");
    assert_eq!(details.len(), 3, "{details:?}");
    let all = format!("{details:?}");
    assert!(
        !all.contains("secret") && !all.contains("hooks.example"),
        "{all}"
    );
}

#[tokio::test]
async fn changing_an_unknown_check_is_not_found() {
    let (s, _pool) = url_master().await;
    let mut i = input("https://example.test/");
    i.id = Some(404);
    let err = s.url_monitor_set(i).await.expect_err("no such check");
    assert!(matches!(err, RpcError::NotFound { .. }), "{err:?}");
    s.url_monitor_delete(404, "x")
        .await
        .expect("deleting nothing is fine");
}

#[tokio::test]
async fn list_shows_figures_and_state() {
    let (s, _pool) = url_master().await;
    let id = s
        .url_monitor_set(input("https://example.test/"))
        .await
        .expect("set");
    let v = &s.url_monitor_list().await.expect("list").monitors[0];
    assert_eq!(v.alert_state, "unknown", "no sample yet");
    assert_eq!(v.samples_24h, 0);

    let now = now_secs();
    for (i, (ok, ms)) in [(true, 100), (true, 300), (false, 0), (true, 200)]
        .into_iter()
        .enumerate()
    {
        let r = if ok {
            HttpProbeResult {
                response_ms: ms,
                ..result(true, Some(200), None, false)
            }
        } else {
            result(false, Some(503), Some("HTTP 503"), true)
        };
        s.url_apply_sample(id, "https://example.test/", &r, now - 1_000 + 10 * i as i64)
            .await
            .expect("apply");
    }
    let v = &s.url_monitor_list().await.expect("list").monitors[0];
    assert_eq!(v.samples_24h, 4);
    assert_eq!(v.success_pct_24h, 75);
    assert_eq!(v.avg_ms_24h, 200);
    assert_eq!(v.last_error.as_deref(), Some("HTTP 503"));
    assert_eq!(v.alert_state, "ok");
    assert_eq!(v.last_sampled_at, now - 1_000 + 30);
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alert_includes_context() {
    let (s, pool) = url_master_sending().await;
    let mut i = input("https://shop.example.test/");
    i.alert_email = Some("team@example.cz".into());
    let id = s.url_monitor_set(i).await.expect("set");

    park(&pool, id, true, Some("HTTP 502")).await;
    s.url_monitor_alert(
        id,
        UrlAlertContext {
            stack_summary: Some("shop: web exited 137, OOM-killed".into()),
            ..Default::default()
        },
    )
    .await
    .expect("alert");
    let mails = url_mails(&s).await;
    assert_eq!(mails.len(), 1, "{mails:?}");
    let body = &mails[0].1;
    assert!(body.contains("https://shop.example.test/"), "{body}");
    assert!(body.contains("HTTP 502"), "{body}");
    assert!(body.contains("shop: web exited 137, OOM-killed"), "{body}");
    assert!(
        !body.contains("does not answer either"),
        "the node answered, so it is not accused: {body}"
    );
    let bells = url_bells(&pool).await;
    assert_eq!(bells.len(), 1, "{bells:?}");
    assert_eq!(bells[0].0, format!("url.monitor:{id}"));
    assert_eq!(bells[0].1, "error");
    assert!(bells[0].3.contains("shop: web exited 137"), "{bells:?}");

    // The node behind it does not answer either: the wording says so.
    park(&pool, id, false, None).await;
    s.url_monitor_alert(id, UrlAlertContext::default())
        .await
        .expect("recovery");
    park(&pool, id, true, Some("curl: (7) Failed to connect")).await;
    s.url_monitor_alert(
        id,
        UrlAlertContext {
            node_unreachable: true,
            ..Default::default()
        },
    )
    .await
    .expect("alert");
    let mails = url_mails(&s).await;
    assert_eq!(mails.len(), 3, "{mails:?}");
    assert!(mails[2].1.contains("does not answer either"), "{mails:?}");
    assert!(mails[2].1.contains("curl: (7)"), "{mails:?}");
    assert!(!mails[0].1.contains("does not answer either"));

    // The recovery is its own kind of message, on the same bell card.
    assert!(mails[1].1.contains("answers again"), "{mails:?}");
    let kinds: Vec<String> = url_bells(&pool).await.into_iter().map(|b| b.0).collect();
    assert!(
        kinds.iter().all(|k| *k == format!("url.monitor:{id}")),
        "{kinds:?}"
    );
}

/// Log lines are not part of any outbound alert, and neither is anything a
/// stack summary cannot be trusted to be.
#[tokio::test]
async fn the_stack_line_is_one_short_clean_line() {
    let (s, pool) = url_master_sending().await;
    let mut i = input("https://shop.example.test/");
    i.alert_email = Some("team@example.cz".into());
    let id = s.url_monitor_set(i).await.expect("set");
    park(&pool, id, true, Some("HTTP 502")).await;
    let hostile = format!(
        "shop: web\x1b[31m exited\r\nINJECTED: yes {}",
        "x".repeat(2_000)
    );
    s.url_monitor_alert(
        id,
        UrlAlertContext {
            stack_summary: Some(hostile),
            ..Default::default()
        },
    )
    .await
    .expect("alert");
    let body = &url_mails(&s).await[0].1;
    assert!(!body.contains('\x1b'), "{body:?}");
    assert!(body.len() < 1_000, "{} bytes", body.len());
}

#[tokio::test]
async fn own_channels_come_first_and_the_global_ones_fill_the_gaps() {
    let (s, pool) = url_master_sending().await;
    // Own address only: the mail is its own, Slack falls back to the global.
    let mut a = input("https://a.example.test/");
    a.alert_email = Some("a@example.cz".into());
    let a = s.url_monitor_set(a).await.expect("a");
    park(&pool, a, true, Some("HTTP 500")).await;
    s.url_monitor_alert(a, UrlAlertContext::default())
        .await
        .expect("alert");
    assert_eq!(url_mails(&s).await.len(), 1);
    assert!(mails_of(&s, "docker").await.is_empty(), "no double mail");
    assert_eq!(audits(&s, "notify.docker.slack").await, 1, "global Slack");
    assert_eq!(audits(&s, "notify.url.slack").await, 0);

    // Nothing of its own: both channels are the global ones.
    let b = s
        .url_monitor_set(input("https://b.example.test/"))
        .await
        .expect("b");
    park(&pool, b, true, Some("HTTP 500")).await;
    s.url_monitor_alert(b, UrlAlertContext::default())
        .await
        .expect("alert");
    assert_eq!(url_mails(&s).await.len(), 1, "unchanged");
    assert_eq!(mails_of(&s, "docker").await.len(), 1);
    assert_eq!(audits(&s, "notify.docker.slack").await, 2);

    // Own Slack: the global webhook is not used, the global mail still is.
    let mut c = input("https://c.example.test/");
    c.alert_slack_webhook = Some("https://127.0.0.1/own-hook".into());
    let c = s.url_monitor_set(c).await.expect("c");
    park(&pool, c, true, Some("HTTP 500")).await;
    s.url_monitor_alert(c, UrlAlertContext::default())
        .await
        .expect("alert");
    assert_eq!(audits(&s, "notify.url.slack").await, 1);
    assert_eq!(audits(&s, "notify.docker.slack").await, 2, "unchanged");
    assert_eq!(mails_of(&s, "docker").await.len(), 2);

    // And a `url.` bell never also leaves as a Docker alert.
    assert!(!is_outbound_docker_kind("url.monitor:1"));
    assert!(!is_outbound_docker_kind("url.cert:1"));
}

#[tokio::test]
async fn an_alert_is_sent_once_however_often_it_is_asked_for() {
    let (s, pool) = url_master_sending().await;
    let mut i = input("https://a.example.test/");
    i.alert_email = Some("a@example.cz".into());
    let id = s.url_monitor_set(i).await.expect("set");
    park(&pool, id, true, Some("HTTP 500")).await;
    for _ in 0..3 {
        s.url_monitor_alert(id, UrlAlertContext::default())
            .await
            .expect("alert");
    }
    assert_eq!(url_mails(&s).await.len(), 1);
    assert_eq!(url_bells(&pool).await.len(), 1);
    assert_eq!(audits(&s, "url_monitor.alert").await, 1);
}

#[tokio::test]
async fn the_owning_node_is_worked_out_again_on_recovery_unless_chosen() {
    let (s, pool) = url_master().await;
    let node_of = |id| {
        let pool = pool.clone();
        async move {
            hyperion_state::url_monitors::get(&pool, id)
                .await
                .expect("get")
                .expect("row")
                .node_id
        }
    };
    let mut derived = input("https://a.example.test/");
    derived.node_id = Some("node_a".into());
    let derived = s.url_monitor_set(derived).await.expect("derived");
    let mut chosen = input("https://b.example.test/");
    chosen.node_id = Some("node_a".into());
    chosen.node_manual = true;
    let chosen = s.url_monitor_set(chosen).await.expect("chosen");

    let moved = UrlAlertContext {
        node_rederived: true,
        node_id: Some("node_b".into()),
        ..Default::default()
    };
    for id in [derived, chosen] {
        park(&pool, id, false, None).await;
        // A "down" that was pending first, so there is an "up" to announce.
        hyperion_state::url_monitors::record_transition(&pool, id, true, Some("x"), 1)
            .await
            .expect("down");
        hyperion_state::url_monitors::ack_pending(&pool, id, "down")
            .await
            .expect("ack");
        park(&pool, id, false, None).await;
        s.url_monitor_alert(id, moved.clone()).await.expect("alert");
    }
    assert_eq!(node_of(derived).await.as_deref(), Some("node_b"));
    assert_eq!(
        node_of(chosen).await.as_deref(),
        Some("node_a"),
        "the operator's choice"
    );

    // "No hosting matches any more" is a result too.
    hyperion_state::url_monitors::record_transition(&pool, derived, true, Some("x"), 2)
        .await
        .expect("down");
    hyperion_state::url_monitors::ack_pending(&pool, derived, "down")
        .await
        .expect("ack");
    park(&pool, derived, false, None).await;
    s.url_monitor_alert(
        derived,
        UrlAlertContext {
            node_rederived: true,
            node_id: None,
            ..Default::default()
        },
    )
    .await
    .expect("alert");
    assert_eq!(node_of(derived).await, None);
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

#[test]
fn cert_alerts_at_14_and_3_days_once_each_over_time() {
    let day = 86_400;
    let base = 1_800_000_000;
    let expires = base + 20 * day;
    let mut last = None;
    let mut fired = Vec::new();
    // Every six hours until a day after expiry.
    for step in 0..(21 * 4 + 4) {
        let now = base + step * 6 * 3_600;
        if let Some(d) = cert_alert_due(expires, now, last) {
            fired.push((step / 4, d));
            last = Some(d);
        }
    }
    assert_eq!(fired, vec![(6, 14), (17, 3)], "{fired:?}");

    // Already inside the last window when first seen: the 3 only.
    assert_eq!(cert_alert_due(base + 2 * day, base, None), Some(3));
    // Far away: nothing.
    assert_eq!(cert_alert_due(base + 40 * day, base, None), None);
    // Already warned at 3, never again for the same certificate.
    assert_eq!(cert_alert_due(base + day, base, Some(3)), None);
    // Warned at 14 and now at 10 days: still nothing new.
    assert_eq!(cert_alert_due(base + 10 * day, base, Some(14)), None);
}

#[tokio::test]
async fn cert_alerts_at_14_and_3_days_once_each() {
    let (s, pool) = url_master().await;
    let id = s
        .url_monitor_set(input("https://example.test/"))
        .await
        .expect("set");
    let day = 86_400;
    let now = now_secs();
    let expire = |days: i64| {
        let pool = pool.clone();
        async move {
            sqlx::query("UPDATE url_monitors SET cert_expires_at = ? WHERE id = ?")
                .bind(now + days * day)
                .bind(id)
                .execute(&pool)
                .await
                .expect("expire");
        }
    };
    let certs = || {
        let pool = pool.clone();
        async move {
            url_bells(&pool)
                .await
                .into_iter()
                .filter(|b| b.0 == format!("url.cert:{id}"))
                .collect::<Vec<_>>()
        }
    };

    expire(30).await;
    s.url_cert_alerts(now).await.expect("pass");
    assert!(certs().await.is_empty(), "a month out says nothing");

    expire(13).await;
    s.url_cert_alerts(now).await.expect("pass");
    s.url_cert_alerts(now).await.expect("again");
    let bells = certs().await;
    assert_eq!(bells.len(), 1, "{bells:?}");
    assert_eq!(bells[0].1, "warn");
    assert!(bells[0].3.contains("https://example.test/"), "{bells:?}");
    assert!(bells[0].3.contains("13 days"), "{bells:?}");

    expire(10).await;
    s.url_cert_alerts(now).await.expect("pass");
    assert_eq!(certs().await.len(), 1, "between the two: nothing new");

    expire(2).await;
    s.url_cert_alerts(now).await.expect("pass");
    s.url_cert_alerts(now).await.expect("again");
    assert_eq!(certs().await.len(), 2);

    expire(-1).await;
    s.url_cert_alerts(now).await.expect("pass");
    assert_eq!(certs().await.len(), 2, "the two thresholds, once each");

    // A renewed certificate starts over.
    expire(80).await;
    s.url_cert_alerts(now).await.expect("pass");
    expire(12).await;
    s.url_cert_alerts(now).await.expect("pass");
    assert_eq!(certs().await.len(), 3);
}

#[test]
fn the_certificate_is_read_at_most_once_an_hour() {
    let now = 1_800_000_000;
    assert!(cert_check_due(0, now), "never read");
    assert!(!cert_check_due(now - 59 * 60, now));
    assert!(cert_check_due(now - 60 * 60, now));
    assert!(!cert_check_due(now, now));
}

#[test]
fn parse_cert_expiry_reads_what_curl_prints() {
    use chrono::{TimeZone, Utc};
    let at = |y, mo, d, h, mi, s| {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s)
            .single()
            .expect("date")
            .timestamp()
    };
    // The real thing: four certificates, the site's own first.
    assert_eq!(
        parse_cert_expiry(CURL_CERTS),
        Some(at(2027, 1, 11, 14, 17, 51))
    );
    // A day below ten is space-padded.
    assert_eq!(
        parse_cert_expiry("Subject:CN = a\nExpire date:Sep  2 23:59:59 2028 GMT\n"),
        Some(at(2028, 9, 2, 23, 59, 59))
    );
    // The other shape curl builds print.
    assert_eq!(
        parse_cert_expiry("Expire date:2027-01-11 14:17:51 GMT\n"),
        Some(at(2027, 1, 11, 14, 17, 51))
    );
    assert_eq!(
        parse_cert_expiry("Expire date: 2027-01-11 14:17:51 UTC\r\n"),
        Some(at(2027, 1, 11, 14, 17, 51))
    );
    // The first certificate is the site's, whatever the others say.
    assert_eq!(
        parse_cert_expiry(
            "Expire date:Jan  1 00:00:00 2030 GMT\nExpire date:Jan  1 00:00:00 2026 GMT\n"
        ),
        Some(at(2030, 1, 1, 0, 0, 0))
    );
    for junk in [
        "",
        "Cert:-----BEGIN CERTIFICATE-----",
        "Expire date:",
        "Expire date:next Tuesday",
        "Start date:Oct 13 14:17:52 2026 GMT",
    ] {
        assert_eq!(parse_cert_expiry(junk), None, "{junk:?}");
    }
}

#[tokio::test]
async fn changes_are_audited_by_name() {
    let (s, pool) = url_master().await;
    let mut i = input("https://example.test/health?token=abc");
    i.actor = "kevin".into();
    let id = s.url_monitor_set(i).await.expect("set");
    s.url_monitor_delete(id, "kevin").await.expect("delete");
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT actor_label, action, payload_json FROM audit_log \
         WHERE action LIKE 'url_monitor.%' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    let who: Vec<(&str, &str)> = rows.iter().map(|r| (r.0.as_str(), r.1.as_str())).collect();
    assert_eq!(
        who,
        [
            ("kevin", "url_monitor.set"),
            ("kevin", "url_monitor.delete")
        ]
    );
    assert!(rows[0].2.contains("https://example.test"), "{rows:?}");
    assert!(
        !rows[0].2.contains("abc"),
        "no token in the trail: {rows:?}"
    );
    assert!(!rows[0].2.contains("health"), "no path either: {rows:?}");

    // A name that is not a name falls back to the agent.
    let mut i = input("https://example.test/");
    i.actor = "ke\nvin".into();
    s.url_monitor_set(i).await.expect("set");
    let (who,): (String,) = sqlx::query_as(
        "SELECT actor_label FROM audit_log WHERE action = 'url_monitor.set' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(who, "agent");
}

/// Make `id` fail until the alert is announced, the way a real outage goes:
/// three hard failures, then the web layer's `UrlMonitorAlert`.
async fn open_alert(s: &HostingService<MockAdapterPort>, pool: &SqlitePool, id: i64, url: &str) {
    let now = now_secs();
    for i in 0..3 {
        s.url_apply_sample(
            id,
            url,
            &result(false, Some(500), Some("HTTP 500"), true),
            now - 300 + i * 60,
        )
        .await
        .expect("sample");
    }
    s.url_monitor_alert(id, UrlAlertContext::default())
        .await
        .expect("announce");
    let row = hyperion_state::url_monitors::get(pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(row.alert_state, "alerting");
    assert_eq!(row.pending_alert, None, "announced and acknowledged");
}

/// Everything that went out beyond the bell, in one number.
async fn sent_out(s: &HostingService<MockAdapterPort>) -> i64 {
    audits(s, "notify.docker.slack").await
        + audits(s, "notify.url.slack").await
        + mails_of(s, "docker").await.len() as i64
        + url_mails(s).await.len() as i64
}

/// What was learnt about an address is not true of another one.
#[tokio::test]
async fn changing_the_address_drops_what_was_learnt_about_the_old_one() {
    let (s, pool) = url_master_sending().await;
    let id = s
        .url_monitor_set(input("https://old.example.test/"))
        .await
        .expect("set");
    let day = 86_400;
    let now = now_secs();
    // The old address has a certificate 2 days out that was warned about at
    // 3, and an outage that was announced.
    sqlx::query(
        "UPDATE url_monitors SET cert_expires_at = ?, cert_alert_day = 3, cert_checked_at = ? \
         WHERE id = ?",
    )
    .bind(now + 2 * day)
    .bind(now)
    .bind(id)
    .execute(&pool)
    .await
    .expect("seed cert");
    open_alert(&s, &pool, id, "https://old.example.test/").await;
    let bells_before = url_bells(&pool).await;
    assert_eq!(bells_before.len(), 1, "the open alert: {bells_before:?}");
    assert_eq!(bells_before[0].1, "error");
    let out_before = sent_out(&s).await;
    assert!(out_before > 0, "the announcement went out");

    // Editing other fields keeps all of it, and says nothing.
    let mut same = input("https://old.example.test/");
    same.id = Some(id);
    same.interval_secs = 120;
    s.url_monitor_set(same).await.expect("same address");
    let kept = hyperion_state::url_monitors::get(&pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(kept.interval_secs, 120);
    assert_eq!(kept.cert_expires_at, Some(now + 2 * day));
    assert_eq!(kept.cert_alert_day, Some(3));
    assert_eq!(kept.alert_state, "alerting");
    assert_eq!(
        hyperion_state::url_monitors::sample_count(&pool, id)
            .await
            .expect("count"),
        3
    );
    assert_eq!(
        url_bells(&pool).await,
        bells_before,
        "the card is untouched"
    );

    // A new address starts clean.
    let mut moved = input("https://new.example.test/");
    moved.id = Some(id);
    s.url_monitor_set(moved).await.expect("new address");
    let fresh = hyperion_state::url_monitors::get(&pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(fresh.cert_expires_at, None);
    assert_eq!(fresh.cert_alert_day, None);
    assert_eq!(fresh.cert_checked_at, 0, "its certificate is read at once");
    assert_eq!(fresh.alert_state, "ok");
    assert_eq!(fresh.pending_alert, None);
    assert_eq!(fresh.pending_error, None);
    assert_eq!(fresh.last_sampled_at, 0, "due on the next tick");
    assert_eq!(
        hyperion_state::url_monitors::sample_count(&pool, id)
            .await
            .expect("count"),
        0
    );
    let v = &s.url_monitor_list().await.expect("list").monitors[0];
    assert_eq!((v.samples_24h, v.success_pct_24h), (0, 0));
    assert_eq!(v.alert_state, "unknown");
    assert_eq!(v.last_error, None);

    // No false certificate warning for the new address...
    s.url_cert_alerts(now).await.expect("pass");
    // ...and the card of the old outage is REPLACED, not left saying down.
    let bells = url_bells(&pool).await;
    assert_eq!(bells.len(), 1, "one card, replaced: {bells:?}");
    assert_eq!(bells[0].0, format!("url.monitor:{id}"));
    assert_eq!(bells[0].1, "info");
    assert_eq!(bells[0].2, "URL check changed");
    assert!(
        bells[0].3.contains("https://old.example.test/"),
        "{bells:?}"
    );
    assert!(bells[0].3.contains("no longer applies"), "{bells:?}");
    assert_eq!(
        sent_out(&s).await,
        out_before,
        "bell only: nothing went out"
    );
}

#[tokio::test]
async fn deleting_a_check_with_an_open_alert_replaces_its_card() {
    let (s, pool) = url_master_sending().await;
    let id = s
        .url_monitor_set(input("https://gone.example.test/"))
        .await
        .expect("set");
    open_alert(&s, &pool, id, "https://gone.example.test/").await;
    let out_before = sent_out(&s).await;
    s.url_monitor_delete(id, "kevin").await.expect("delete");
    let bells = url_bells(&pool).await;
    assert_eq!(bells.len(), 1, "one card, replaced: {bells:?}");
    assert_eq!(bells[0].0, format!("url.monitor:{id}"));
    assert_eq!(bells[0].1, "info");
    assert_eq!(bells[0].2, "URL check removed");
    assert!(
        bells[0].3.contains("https://gone.example.test/"),
        "{bells:?}"
    );
    assert_eq!(
        sent_out(&s).await,
        out_before,
        "bell only: nothing went out"
    );
}

/// A healthy check has no open card, so there is nothing to replace.
#[tokio::test]
async fn changing_or_deleting_a_healthy_check_says_nothing() {
    let (s, pool) = url_master_sending().await;
    let id = s
        .url_monitor_set(input("https://fine.example.test/"))
        .await
        .expect("set");
    s.url_apply_sample(
        id,
        "https://fine.example.test/",
        &result(true, Some(200), None, false),
        now_secs(),
    )
    .await
    .expect("sample");
    let mut moved = input("https://elsewhere.example.test/");
    moved.id = Some(id);
    s.url_monitor_set(moved).await.expect("moved");
    s.url_monitor_delete(id, "kevin").await.expect("delete");
    assert!(url_bells(&pool).await.is_empty());
    assert_eq!(sent_out(&s).await, 0);
}

/// A probe that began before the address was changed finishes after it. Its
/// answer is about the old address: no sample, no decision, no certificate.
#[tokio::test]
async fn a_probe_of_the_old_address_does_not_land_on_the_new_one() {
    let (s, pool) = url_master().await;
    let id = s
        .url_monitor_set(input("https://old.example.test/"))
        .await
        .expect("set");
    let mut moved = input("https://new.example.test/");
    moved.id = Some(id);
    s.url_monitor_set(moved).await.expect("moved");

    // Three failures and a certificate read, all of the OLD address.
    let now = now_secs();
    for i in 0..3 {
        s.url_apply_probe(
            id,
            "https://old.example.test/",
            &result(false, Some(500), Some("HTTP 500"), true),
            Some(Some(now + 86_400)),
            now - 300 + i * 60,
        )
        .await
        .expect("late probe");
    }
    let row = hyperion_state::url_monitors::get(&pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(
        hyperion_state::url_monitors::sample_count(&pool, id)
            .await
            .expect("count"),
        0,
        "no sample"
    );
    assert_eq!(row.alert_state, "ok", "no transition");
    assert_eq!(row.pending_alert, None);
    assert_eq!(row.last_alert_at, None);
    assert_eq!(row.last_sampled_at, 0, "still due");
    assert_eq!(row.cert_expires_at, None, "no certificate");
    assert_eq!(row.cert_checked_at, 0);
    assert!(url_bells(&pool).await.is_empty());

    // The same answers about the address it has NOW count.
    s.url_apply_probe(
        id,
        "https://new.example.test/",
        &result(true, Some(200), None, false),
        Some(Some(now + 86_400 * 40)),
        now,
    )
    .await
    .expect("current probe");
    let row = hyperion_state::url_monitors::get(&pool, id)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(
        hyperion_state::url_monitors::sample_count(&pool, id)
            .await
            .expect("count"),
        1
    );
    assert_eq!(row.cert_expires_at, Some(now + 86_400 * 40));

    // A check deleted mid-probe is no error either.
    s.url_monitor_delete(id, "kevin").await.expect("delete");
    s.url_apply_probe(
        id,
        "https://new.example.test/",
        &result(true, Some(200), None, false),
        Some(Some(now)),
        now,
    )
    .await
    .expect("probe of a deleted check");
}

/// An expiry left on a check that is not https is not a fact about it.
#[tokio::test]
async fn a_certificate_on_a_plain_http_check_never_warns() {
    let (s, pool) = url_master().await;
    let id = s
        .url_monitor_set(input("http://plain.example.test/"))
        .await
        .expect("set");
    let now = now_secs();
    sqlx::query("UPDATE url_monitors SET cert_expires_at = ? WHERE id = ?")
        .bind(now + 86_400)
        .bind(id)
        .execute(&pool)
        .await
        .expect("stale expiry");
    s.url_cert_alerts(now).await.expect("pass");
    assert!(url_bells(&pool).await.is_empty());
}
