//! Tests for `service::protection`.

use super::*;

/// The empty target list is the whole question, and only the caller can
/// answer it: the panel resolves the master's table and sends it, so
/// empty means the operator configured none; a scheduled run reads THIS
/// Each request must land in exactly ONE hourly bucket, because the
/// care report, /stats and the hosting detail all SUM buckets.
///
/// The regression this pins: the sampler used to parse a 24 h window
/// and store it under an hourly key, so summing a month multiplied the
/// customer's traffic by roughly 24. Summing the per-hour windows here
/// must reproduce the total exactly — no request counted twice, none
/// dropped on a boundary.
#[tokio::test]
async fn hourly_windows_partition_the_access_log_exactly_once() {
    use super::parse_access_log_window;
    use chrono::{TimeZone, Utc};

    let tmp = tempfile::tempdir().expect("tmp");
    let log = tmp.path().join("access.log");
    let base = Utc
        .with_ymd_and_hms(2026, 6, 1, 0, 0, 0)
        .single()
        .expect("base ts")
        .timestamp();

    // Three hours of traffic, including two requests exactly ON hour
    // boundaries — the case a closed range would double-count.
    let offsets = [0i64, 59 * 60, 3600, 3600 + 30 * 60, 7200, 7200 + 59 * 60];
    let mut body = String::new();
    for off in offsets {
        let stamp = Utc
            .timestamp_opt(base + off, 0)
            .single()
            .expect("stamp")
            .format("%d/%b/%Y:%H:%M:%S +0000");
        // Combined format; body_bytes_sent is field 10 (index 9).
        body.push_str(&format!(
            "1.2.3.4 - - [{stamp}] \"GET / HTTP/1.1\" 200 100 \"-\" \"ua\"\n"
        ));
    }
    std::fs::write(&log, &body).expect("write log");

    // Whole span, as one window: the ground truth.
    let (_, all_out, all_reqs, _) = parse_access_log_window(&log, base, None).await;
    assert_eq!(all_reqs, 6, "fixture should parse as six requests");
    assert_eq!(all_out, 600);

    // The same span cut into the hour buckets the sampler writes.
    let mut sum_reqs = 0;
    let mut sum_out = 0;
    for h in 0..3 {
        let start = base + h * 3600;
        let (_, out, reqs, _) = parse_access_log_window(&log, start, Some(start + 3600)).await;
        assert_eq!(reqs, 2, "hour {h} holds its own two requests");
        sum_reqs += reqs;
        sum_out += out;
    }
    assert_eq!(sum_reqs, all_reqs, "summing buckets must not inflate");
    assert_eq!(sum_out, all_out);

    // An open-ended window still starts where it is told: the old
    // behaviour (ignoring the upper bound) would return all six here.
    let (_, _, tail_reqs, _) = parse_access_log_window(&log, base + 7200, None).await;
    assert_eq!(tail_reqs, 2);

    // logrotate can fire in the MIDDLE of an hour. The part written
    // before the rotation is then only in access.log.1, and re-reading
    // the hour from an almost-empty access.log would lose it. Both
    // files are read, and the time window keeps the older file's
    // out-of-range entries out.
    std::fs::rename(&log, tmp.path().join("access.log.1")).expect("rotate");
    let post = Utc
        .timestamp_opt(base + 3600 + 45 * 60, 0)
        .single()
        .expect("stamp")
        .format("%d/%b/%Y:%H:%M:%S +0000");
    std::fs::write(
        &log,
        format!("9.9.9.9 - - [{post}] \"GET / HTTP/1.1\" 200 100 \"-\" \"ua\"\n"),
    )
    .expect("write fresh log");
    let (_, _, hour1, _) = parse_access_log_window(&log, base + 3600, Some(base + 7200)).await;
    assert_eq!(
        hour1, 3,
        "the rotated-away part of the hour must still be counted"
    );
    // And the rotated file does not leak traffic into other hours.
    let (_, _, hour0, _) = parse_access_log_window(&log, base, Some(base + 3600)).await;
    assert_eq!(hour0, 2);
}

/// Purging a site removes its WAF log and the rotated copies logrotate
/// left behind — and nothing that belongs to another site.
#[tokio::test]
async fn remove_waf_logs_takes_rotated_copies_but_nothing_else() {
    let dir = tempfile::tempdir().expect("dir");
    let id = "01a110d5-1ee1-71c2-b98b-0e31aa826f3b";
    for name in [
        format!("{id}.log"),
        format!("{id}.log.1"),
        format!("{id}.log.2.gz"),
        format!("{id}.logbook"),
        "01a110d5-0000-0000-0000-000000000000.log".to_string(),
    ] {
        std::fs::write(dir.path().join(name), "x").expect("write");
    }
    remove_waf_logs(dir.path(), id).await;
    let mut left: Vec<String> = std::fs::read_dir(dir.path())
        .expect("ls")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec![
            "01a110d5-0000-0000-0000-000000000000.log".to_string(),
            format!("{id}.logbook"),
        ]
    );
}

/// The switch may only silence the source that belongs to the site.
/// Opting EVERY site out empties the HTTP half and leaves the node-wide
/// half (ssh / ftp / mail) identical.
///
/// There is no journald here, so both node-wide halves are empty: what
/// this pins is the attribution rule — a `site: None` intent is never
/// gated — not that a real ssh flood is caught, which needs a journal.
#[tokio::test]
async fn opting_every_site_out_leaves_the_node_wide_sources_alone() {
    let pool = open_memory().await.expect("open");
    let home = tempfile::tempdir().expect("dir");
    let s = svc(pool.clone(), happy_mocks_many()).with_paths(HostingPaths {
        home_root: home.path().display().to_string(),
        ..HostingPaths::default()
    });
    s.create(req("example.cz")).await.expect("create");
    let a = s
        .get(HostingSelector::Domain(
            Domain::parse("example.cz").expect("parse"),
        ))
        .await
        .expect("get");
    write_wp_login_flood(home.path(), &a.system_user, &a.domain, "203.0.113.7");
    let since = now_secs() - s.fail2ban.window_secs;

    let before = s.fail2ban_scan(since).await.expect("scan");
    assert!(
        !http_hits(&before).is_empty(),
        "the flood must be seen first"
    );

    s.hosting_kv_set(
        a.id.as_str().to_string(),
        FAIL2BAN_HTTP_KV_KEY.into(),
        "off".into(),
    )
    .await
    .expect("opt out");
    let after = s.fail2ban_scan(since).await.expect("scan");
    assert!(http_hits(&after).is_empty(), "the site is opted out");
    assert_eq!(
        node_hits(&before),
        node_hits(&after),
        "sshd / ftp / mail journals are node-wide — no site may switch them off"
    );
}

/// Absent key ⇒ on; only a literal "off" opts out. And once a site is
/// out, its care report stops reporting an attacks-blocked count it
/// cannot stand behind — nobody was watching that login page.
#[tokio::test]
async fn http_switch_defaults_on_and_an_opted_out_site_reports_no_count() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let detail = s
        .get(HostingSelector::Domain(
            Domain::parse("example.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let hid = detail.id.as_str().to_string();

    assert!(
        s.http_bruteforce_scan_enabled(&hid).await,
        "absent key ⇒ scanning, so an upgrade changes nothing"
    );
    for (stored, want) in [("off", false), ("on", true), ("", true), (" off ", false)] {
        s.hosting_kv_set(hid.clone(), FAIL2BAN_HTTP_KV_KEY.into(), stored.into())
            .await
            .expect("kv set");
        assert_eq!(
            s.http_bruteforce_scan_enabled(&hid).await,
            want,
            "stored {stored:?}"
        );
    }

    s.hosting_kv_set(hid.clone(), FAIL2BAN_HTTP_KV_KEY.into(), "on".into())
        .await
        .expect("kv set");
    let now = now_secs();

    // The TOGGLE alone is not evidence. With no record of the scanner
    // ever having run on this site, the switch says "watch it" and
    // nothing says it was watched — so the section is unmeasured, not
    // a reassuring zero.
    let never_scanned = s
        .care_report_build(HostingSelector::Id(detail.id.clone()), now - 86_400, now)
        .await
        .expect("report");
    assert_eq!(never_scanned.attacks_blocked, None);

    // Once the scanner has actually run across the period, the count
    // is a real measurement — even at zero.
    s.hosting_kv_set(
        hid.clone(),
        FAIL2BAN_HTTP_SINCE_KV_KEY.into(),
        format!("{},{}", now - 90_000, now),
    )
    .await
    .expect("kv set");
    let on = s
        .care_report_build(HostingSelector::Id(detail.id.clone()), now - 86_400, now)
        .await
        .expect("report");
    assert_eq!(on.attacks_blocked, Some(0));
    assert_eq!(
        on.attacks_covered_since, None,
        "coverage predates the period ⇒ no qualifier"
    );

    // Opted out: "we did not measure this", not a reassuring zero.
    s.hosting_kv_set(hid.clone(), FAIL2BAN_HTTP_KV_KEY.into(), "off".into())
        .await
        .expect("kv set");
    let off = s
        .care_report_build(HostingSelector::Id(detail.id.clone()), now - 86_400, now)
        .await
        .expect("report");
    assert_eq!(off.attacks_blocked, None);
}

#[test]
fn a_coverage_stamp_restarts_after_a_gap() {
    use super::{parse_coverage_stamp, FAIL2BAN_COVERAGE_GAP_SECS as GAP};
    assert_eq!(parse_coverage_stamp("100,200"), Some((100, 200)));
    assert_eq!(parse_coverage_stamp("  100 , 200 "), Some((100, 200)));
    // The first version of this key stored a bare start. Reading it as
    // its own last scan makes an upgrade see one stale stretch and
    // restart coverage, instead of parsing to nothing and silently
    // claiming "watching since now" on every tick.
    assert_eq!(parse_coverage_stamp("100"), Some((100, 100)));
    assert_eq!(parse_coverage_stamp("nonsense"), None);
    assert_eq!(parse_coverage_stamp("100,"), None);

    // Continuous scanning keeps the original start...
    let (since, last) = parse_coverage_stamp("1000,2000").expect("parse");
    let next = 2000 + GAP - 1;
    assert!(next - last <= GAP, "still one unbroken stretch");
    assert_eq!(since, 1000);
    // ...but a silence longer than the threshold does not.
    let after_gap = 2000 + GAP + 1;
    assert!(
        after_gap - last > GAP,
        "an hour of silence means nothing was watching"
    );
}

/// The count and the sentence describing it must come from ONE window.
#[test]
fn the_attacks_count_is_narrowed_to_the_window_the_letter_claims() {
    use super::attacks_window;

    // Protection predates the period ⇒ count the whole period, and the
    // letter's unqualified wording is earned.
    assert_eq!(
        attacks_window(CARE_FROM - 86_400, CARE_FROM, CARE_TO),
        Some(CARE_FROM)
    );

    // Protection starts on the 25th ⇒ the count starts there too. This
    // is the regression: it used to count from CARE_FROM while the
    // sentence said "since 25 Jun … covers only that part of it".
    let since = CARE_FROM + 24 * 86_400;
    assert_eq!(attacks_window(since, CARE_FROM, CARE_TO), Some(since));

    // Protection begins only after the period ended ⇒ unmeasured, not
    // a zero beside a start date in the future. The shape of the first
    // report after an upgrade, when no site has a stamp yet.
    assert_eq!(attacks_window(CARE_TO, CARE_FROM, CARE_TO), None);
    assert_eq!(attacks_window(CARE_TO + 86_400, CARE_FROM, CARE_TO), None);
}

/// Empty-DB sanity check: the renewal tick on a fresh agent
/// returns an empty result vec, doesn't panic, doesn't audit.
/// A real nginx combined line, and the shapes that break naive parsers:
/// a quoted request containing spaces, a "-" byte count, and junk.
#[test]
fn access_line_parses_the_combined_format() {
    let line = r#"203.0.113.7 - - [10/Oct/2026:13:55:36 +0200] "GET /a b?c=1 HTTP/1.1" 200 4521 "-" "Mozilla/5.0""#;
    let (ip, ts, bytes) = super::parse_access_line(line).expect("parses");
    assert_eq!(ip, "203.0.113.7");
    assert_eq!(bytes, 4521);
    // 13:55:36 +0200 is 11:55:36 UTC — the OFFSET must be applied, or
    // every visitor lands in the wrong hour of the window.
    assert_eq!(ts, 1791633336);

    // nginx writes "-" for a response with no body; that is 0 bytes,
    // not a reason to drop the request from the count.
    let dash = r#"203.0.113.7 - - [10/Oct/2026:13:55:36 +0200] "GET / HTTP/1.1" 304 - "-" "curl""#;
    let (_, _, b) = super::parse_access_line(dash).expect("parses");
    assert_eq!(b, 0);

    assert!(super::parse_access_line("").is_none());
    assert!(super::parse_access_line("garbage without brackets").is_none());
}

#[test]
fn bruteforce_evidence_needs_a_recent_scan_after_the_grace() {
    let now = 1_000_000;
    let grace = 2 * FAIL2BAN_COVERAGE_GAP_SECS;
    // A plan that just started: never missing yet.
    assert!(!bruteforce_evidence_missing(None, now - 60, now));
    // Started long ago, never scanned / scanned long ago: missing.
    assert!(bruteforce_evidence_missing(None, now - 10 * grace, now));
    assert!(bruteforce_evidence_missing(Some(now - grace - 1), 0, now));
    // A recent scan is evidence.
    assert!(!bruteforce_evidence_missing(Some(now - 300), 0, now));
}
