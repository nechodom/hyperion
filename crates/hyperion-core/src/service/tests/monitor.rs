//! Tests for `service::monitor`.

use super::*;

#[test]
fn monitor_alert_window() {
    use super::{monitor_recovered, monitor_should_alert};
    // Plain streak of 3 at threshold 3.
    assert!(monitor_should_alert(&[true, false, false, false], 3, false));
    assert!(!monitor_should_alert(&[true, true, false, false], 3, false));
    // Hard failure alerts after 2.
    assert!(monitor_should_alert(&[true, true, false, false], 3, true));
    // Flapping: 3 fails in the last 6, never 2 in a row.
    let flap = [false, true, false, true, false, true];
    assert!(monitor_should_alert(&flap, 3, false));
    // Mostly healthy stays quiet.
    assert!(!monitor_should_alert(
        &[false, true, true, true, false, true],
        3,
        false
    ));
    // Recovery needs two clean samples in a row.
    assert!(!monitor_recovered(&[false, false, true], 3));
    assert!(monitor_recovered(&[false, true, true], 3));
    assert!(monitor_recovered(&[false, true], 1));
}

/// Every sequence of 10 probes (ok / soft fail / hard fail, 3^10 of them)
/// at every threshold an operator can realistically pick, checked against
/// what an operator must be able to rely on — not against the algorithm.
#[test]
fn monitor_alerts_keep_their_promises_for_every_probe_sequence() {
    use super::MonitorTransition::{Down, Up};
    const LEN: u32 = 10;
    for threshold in 1..=5i64 {
        let th = threshold as usize;
        for n in 0..3usize.pow(LEN) {
            let probes: Vec<Probe> = (0..LEN)
                .map(|k| match (n / 3usize.pow(k)) % 3 {
                    0 => Probe::Ok,
                    1 => Probe::Soft,
                    _ => Probe::Hard,
                })
                .collect();
            let sent = replay_probes(&probes, threshold);
            let ctx = || format!("threshold {threshold}, {probes:?} → {sent:?}");
            let mut alerting = false;
            let mut last_up: Option<usize> = None;
            let mut next = sent.iter().peekable();
            for (i, p) in probes.iter().enumerate() {
                let fired = next.next_if(|(at, _)| *at == i).map(|(_, t)| *t);
                match fired {
                    Some(Down) => {
                        assert!(!alerting, "down while already down: {}", ctx());
                        assert_ne!(*p, Probe::Ok, "down on a passing probe: {}", ctx());
                        // Enough failures of THIS incident — never ones an
                        // earlier "up" already closed.
                        let since = last_up.map_or(0, |u| u + 1);
                        let fails = probes[since..=i].iter().filter(|q| **q != Probe::Ok);
                        let need = if *p == Probe::Hard { th.min(2) } else { th };
                        assert!(fails.count() >= need, "down too early: {}", ctx());
                        alerting = true;
                    }
                    Some(Up) => {
                        assert!(alerting, "up while not down: {}", ctx());
                        let need = th.min(2);
                        assert!(
                            i + 1 >= need
                                && probes[i + 1 - need..=i].iter().all(|q| *q == Probe::Ok),
                            "up without {need} clean probes in a row: {}",
                            ctx()
                        );
                        alerting = false;
                        last_up = Some(i);
                    }
                    None => {}
                }
                // Never miss an outage: `threshold` failures in a row (two
                // error pages in a row) leave the monitor alerting.
                let streak = probes[..=i].iter().rev().take_while(|q| **q != Probe::Ok);
                let streak: Vec<_> = streak.collect();
                let hard_pair = streak.len() >= 2 && streak[..2].iter().all(|q| **q == Probe::Hard);
                if streak.len() >= th || hard_pair && th >= 2 {
                    assert!(alerting, "outage at {i} not reported: {}", ctx());
                }
            }
            assert!(next.next().is_none(), "unconsumed transitions: {}", ctx());
        }
    }
}

/// A site that fails every other probe forever is broken even though no
/// streak ever builds — the reason the window exists. It must alert, and
/// stay alerting rather than resolve on each lucky request.
#[test]
fn monitor_still_catches_a_flapping_site() {
    use super::MonitorTransition::Down;
    for threshold in 1..=5i64 {
        let probes: Vec<Probe> = (0..40)
            .map(|i| if i % 2 == 0 { Probe::Soft } else { Probe::Ok })
            .collect();
        let sent = replay_probes(&probes, threshold);
        assert_eq!(
            sent.first().map(|s| s.1),
            Some(Down),
            "threshold {threshold}"
        );
        assert!(
            sent[0].0 < 2 * threshold as usize,
            "threshold {threshold}: {sent:?}"
        );
        if threshold >= 2 {
            assert_eq!(sent.len(), 1, "threshold {threshold} re-fired: {sent:?}");
        }
    }
}

/// One outage, then a site that is fine again, must produce exactly one
/// "down" and one "up". The failures from before the recovery stayed in
/// the 2×threshold window, so the very next clean probe re-fired "down"
/// (with "HTTP 200" as its error), the one after that "up" again — every
/// short blip on every site turned into a down/up/down/up storm.
#[test]
fn monitor_does_not_realert_on_failures_it_already_resolved() {
    use super::MonitorTransition::{Down, Up};
    let (f, t) = (false, true);
    let sent = replay_monitor(&[t, t, f, f, f, t, t, t, t, t, t, t], 3, false);
    assert_eq!(sent, vec![(4, Down), (6, Up)]);
    // Same with an error page (hard failure: alert after 2).
    let sent = replay_monitor(&[t, f, f, t, t, t, t, t, t], 3, true);
    assert_eq!(sent, vec![(2, Down), (4, Up)]);
}

/// After a recovery, a single fresh failure is a single failure: the ones
/// the resolved incident was made of must not be counted again.
#[test]
fn monitor_counts_only_failures_since_the_last_recovery() {
    use super::MonitorTransition::{Down, Up};
    let (f, t) = (false, true);
    let sent = replay_monitor(&[f, f, f, t, t, t, f, t, t, t], 3, false);
    assert_eq!(sent, vec![(2, Down), (4, Up)]);
}

/// A probe that succeeded is never the moment to announce "site is down".
#[test]
fn monitor_never_reports_down_on_a_passing_probe() {
    let (f, t) = (false, true);
    // Flapping still alerts — on the failure that makes it 3 of 6.
    let sent = replay_monitor(&[f, t, f, t, f, t, t, t], 3, false);
    assert_eq!(sent.first(), Some(&(4, super::MonitorTransition::Down)));
    // 3 failures in the window, but the newest probe passed: not now.
    let window = [(1, f), (2, t), (3, f), (4, t), (5, f), (6, t)];
    assert_eq!(
        super::monitor_transition(false, None, &window, 3, false),
        None
    );
}

#[test]
fn probe_classifies_wordpress_failures() {
    use super::classify_probe;
    assert!(classify_probe(200, "<html>ok</html>").is_none());
    assert!(classify_probe(301, "").is_none());
    assert_eq!(classify_probe(503, "x").map(|v| v.1), Some(true));
    assert_eq!(classify_probe(404, "x").map(|v| v.1), Some(false));
    assert_eq!(classify_probe(200, "  \n").map(|v| v.1), Some(true));
    let wp = "<p>There has been a critical error on this website.</p>";
    assert_eq!(classify_probe(200, wp).map(|v| v.1), Some(true));
    let db = "<h1>Error establishing a database connection</h1>";
    assert!(classify_probe(200, db).is_some());
    assert!(classify_probe(200, "<b>Fatal error</b>: Uncaught Error").is_some());
    // A post that merely mentions the phrase is not a failure.
    assert!(classify_probe(200, "<p>how to debug a fatal error</p>").is_none());
}

/// curl timing out after the status line but before any body is a slow
/// site, not a white screen: it must not reach `classify_probe` as an
/// empty 200, which is a HARD failure (alerts after two samples).
#[test]
fn probe_timeout_after_headers_is_not_a_white_screen() {
    use super::probe_gave_up;
    // No answer at all.
    assert!(probe_gave_up(0, false, ""));
    // 200 arrived, curl exited 28 before the body: gave up, soft.
    assert!(probe_gave_up(200, false, ""));
    // A real empty 200 (curl finished cleanly) is still judged.
    assert!(!probe_gave_up(200, true, ""));
    // Part of the page arrived before the timeout: judge what came.
    assert!(!probe_gave_up(200, false, "<html><head>"));
    // A clean 500 is a verdict, not a give-up.
    assert!(!probe_gave_up(500, true, "x"));
}

/// The real probe — curl and all — against each way a site answers.
#[tokio::test]
async fn probe_http_reads_a_real_site_right() {
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let url = format!("https://{}/", site.host());

    site.set(SiteMode::Up);
    let r = super::probe_http(&url).await;
    assert!(r.success, "{r:?}");
    assert_eq!(r.http_status, Some(200));
    assert_eq!(r.error_message, None);

    // No answer at all — what production recorded 142× with an EMPTY
    // error: `-s` without `-S` threw curl's reason away.
    site.set(SiteMode::Silent);
    let r = super::probe_http(&url).await;
    assert!(!r.success && !r.hard_failure, "{r:?}");
    assert_eq!(r.http_status, None);
    let err = r.error_message.clone().unwrap_or_default();
    assert!(
        err.starts_with("curl: ("),
        "curl's reason must reach the alert: {r:?}"
    );

    // Dropped after the headers: a soft failure with curl's reason, NOT a
    // white screen (hard, alerts after two).
    site.set(SiteMode::HeadersThenDrop);
    let r = super::probe_http(&url).await;
    assert!(!r.success && !r.hard_failure, "{r:?}");
    assert_eq!(r.http_status, Some(200));
    let err = r.error_message.clone().unwrap_or_default();
    assert!(err.starts_with("curl: ("), "{r:?}");

    // The genuinely broken answers stay hard failures.
    for (mode, what) in [
        (SiteMode::ServerError, "HTTP 500"),
        (SiteMode::Empty, "white screen"),
        (SiteMode::WpCritical, "critical error"),
    ] {
        site.set(mode);
        let r = super::probe_http(&url).await;
        assert!(!r.success && r.hard_failure, "{mode:?}: {r:?}");
        let err = r.error_message.clone().unwrap_or_default();
        assert!(err.contains(what), "{mode:?}: {r:?}");
    }
}

/// An uncached WordPress render on a busy box takes seconds. The 5 s the
/// probe allowed called such a site down; it is slow, and it is up.
#[tokio::test]
async fn probe_http_waits_for_a_slow_page() {
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    site.set(SiteMode::Slow(7));
    let r = super::probe_http(&format!("https://{}/", site.host())).await;
    assert!(r.success, "{r:?}");
    assert!(r.response_ms >= 7_000, "{r:?}");
}

/// A page of several megabytes is read, judged on its head as ever, and
/// never held: the probe keeps the head and the end of the output.
#[tokio::test]
async fn probe_http_judges_a_large_page_on_its_head() {
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let url = format!("https://{}/", site.host());

    site.set(SiteMode::Big(8 * 1024 * 1024));
    let r = super::probe_http(&url).await;
    assert!(r.success, "{r:?}");
    assert_eq!(r.http_status, Some(200));

    site.set(SiteMode::BigCriticalFirst(8 * 1024 * 1024));
    let r = super::probe_http(&url).await;
    assert!(!r.success && r.hard_failure, "{r:?}");
    let err = r.error_message.clone().unwrap_or_default();
    assert!(err.contains("critical error"), "{r:?}");

    // Past the cap nothing is looked at: the same answer as before the
    // output was capped.
    site.set(SiteMode::BigCriticalLate(8 * 1024 * 1024));
    let r = super::probe_http(&url).await;
    assert!(r.success, "{r:?}");
}

/// What is kept of an answer is bounded whatever its size: the head holds
/// the characters judged and the code comes from the end.
#[test]
fn the_probe_output_is_split_into_a_bounded_head_and_a_code() {
    use super::{split_probe_output, PROBE_BODY_CAP, PROBE_STATUS_MARK};
    // Whole output: read as it always was.
    let whole = format!("<html>hi</html>{PROBE_STATUS_MARK}200");
    assert_eq!(
        split_probe_output(whole.as_bytes(), b"", 0),
        ("<html>hi</html>".to_string(), 200)
    );
    // The same output cut into a head and a tail that touch.
    let (h, t) = whole.as_bytes().split_at(10);
    assert_eq!(
        split_probe_output(h, t, 0),
        ("<html>hi</html>".to_string(), 200)
    );
    // No mark: curl never printed it.
    assert_eq!(
        split_probe_output(b"partial", b"", 0),
        ("partial".into(), 0)
    );
    // A body longer than the head kept: the head is cut to the characters
    // judged and the code comes from the tail.
    let head = "é".repeat(PROBE_BODY_CAP * 2);
    let tail = format!("end{PROBE_STATUS_MARK}503");
    let (body, code) = split_probe_output(head.as_bytes(), tail.as_bytes(), 9_999_999);
    assert_eq!(body.chars().count(), PROBE_BODY_CAP);
    assert!(body.chars().all(|c| c == 'é'));
    assert_eq!(code, 503);
    // Dropped bytes and no mark in the tail: no code.
    assert_eq!(split_probe_output(b"abc", b"xyz", 5).1, 0);
    // A mark inside the body does not count: the last one does.
    let tricky = format!("a{PROBE_STATUS_MARK}999 b{PROBE_STATUS_MARK}404");
    assert_eq!(split_probe_output(tricky.as_bytes(), b"", 0).1, 404);
}

/// Every process's command line on this machine, the way any local user
/// reads it.
fn all_command_lines() -> String {
    let out = std::process::Command::new("ps")
        .args(["-axo", "args="])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The address of a probe may carry a token. It must reach curl on stdin,
/// never on the command line, for the whole life of the request.
#[tokio::test]
async fn probe_http_keeps_the_address_off_the_command_line() {
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    site.set(SiteMode::Slow(4));
    // Unique to this run, so a curl left over from an earlier run cannot
    // be mistaken for this one.
    let token = format!(
        "PROBE-TOKEN-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let url = format!("https://{}/page?key={token}", site.host());
    let probe = tokio::spawn(async move { super::probe_http(&url).await });
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let seen = all_command_lines();
    assert!(!seen.contains(&token), "the token is on a command line");
    assert!(
        seen.contains("curl --config -"),
        "the probe was not running when the command lines were read"
    );
    let r = probe.await.expect("probe");
    assert!(r.success, "{r:?}");
}

/// Sporadic blips (one probe in five gets no answer) are not an outage:
/// no bell at all.
#[tokio::test]
async fn monitor_tick_ignores_sporadic_blips() {
    use SiteMode::{Silent, Up};
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let (s, pool, _) = monitored_site(&site).await;
    for i in 0..15 {
        tick_as(&s, &pool, &site, if i % 5 == 1 { Silent } else { Up }).await;
    }
    assert_eq!(bells(&pool).await, Vec::<(String, String)>::new());
}

/// A connection dropped twice after the headers is two soft failures —
/// under the threshold of three — not two "white screens", which alerted.
#[tokio::test]
async fn monitor_tick_dropped_connections_are_not_a_white_screen() {
    use SiteMode::{HeadersThenDrop, Up};
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let (s, pool, _) = monitored_site(&site).await;
    for mode in [Up, HeadersThenDrop, HeadersThenDrop, Up, Up, Up] {
        tick_as(&s, &pool, &site, mode).await;
    }
    assert_eq!(bells(&pool).await, Vec::<(String, String)>::new());
    // ...and each is on record with its status and curl's reason.
    let rows: Vec<(i64, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT success, http_status, error_message FROM monitor_samples \
             WHERE success = 0",
    )
    .fetch_all(&pool)
    .await
    .expect("samples");
    assert_eq!(rows.len(), 2, "{rows:?}");
    for (_, status, err) in rows {
        assert_eq!(status, Some(200));
        assert!(err.unwrap_or_default().starts_with("curl: ("));
    }
}

/// A real outage that answers with an error page still alerts after two.
#[tokio::test]
async fn monitor_tick_still_alerts_fast_on_a_server_error() {
    use SiteMode::{ServerError, Up};
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let (s, pool, host) = monitored_site(&site).await;
    for mode in [Up, ServerError, ServerError] {
        tick_as(&s, &pool, &site, mode).await;
    }
    let kinds: Vec<String> = bells(&pool).await.into_iter().map(|b| b.0).collect();
    assert_eq!(kinds, [format!("monitor.down:{host}")]);
}
