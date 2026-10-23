//! Tests for `service::quota`.

use super::*;

/// The reported incident, end to end — real curl, real HTTPS, real
/// SQLite, the real `monitor_tick`: a site that does not answer three
/// probes and then is fine sends ONE "down" and ONE "up". Before, the
/// same run sent down/up/down/up, the second "down" on a probe that
/// passed, and a later single blip re-fired it all again.
#[tokio::test]
async fn monitor_tick_one_outage_one_down_one_up() {
    use SiteMode::{Silent, Up};
    if curl_missing() {
        return;
    }
    let site = spawn_test_site().await;
    let (s, pool, host) = monitored_site(&site).await;
    for mode in [
        Up, Up, Silent, Silent, Silent, Up, Up, Up, Up, Silent, Up, Up, Up, Up,
    ] {
        tick_as(&s, &pool, &site, mode).await;
    }
    let sent = bells(&pool).await;
    let kinds: Vec<&str> = sent.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        kinds,
        [format!("monitor.down:{host}"), format!("monitor.up:{host}")],
        "{sent:?}"
    );
    // The "down" says why: curl's reason, not an empty "last error:".
    assert!(sent[0].1.contains("curl: ("), "{sent:?}");
    let cfg = hyperion_state::monitors::list_enabled(&pool)
        .await
        .expect("list")
        .pop()
        .expect("monitor");
    assert_eq!(cfg.alert_state, "ok");
}

// ============================================================
//  Kernel-quota enablement: pure fstab-splice + quotaon parse.
//  These guard the highest-risk code in the feature (editing
//  /etc/fstab on production + deciding "did quotas come up?").
// ============================================================

#[test]
fn fstab_field_ranges_basic_and_inline_comment() {
    let line = "UUID=abc /home ext4 defaults 0 2 # bind to /home";
    let r = fstab_field_ranges(line);
    // 6 real fields + 4 comment tokens (#, bind, to, /home).
    assert_eq!(&line[r[1].0..r[1].1], "/home");
    assert_eq!(&line[r[3].0..r[3].1], "defaults");
}

#[test]
fn fstab_splice_appends_options_and_preserves_comment_byte_for_byte() {
    let content = "UUID=abc /home ext4 defaults 0 2 # keep this comment\n";
    let out = fstab_with_quota_options(content, "/home", &["usrquota", "grpquota"])
        .expect("match")
        .expect("changed");
    assert_eq!(
        out,
        "UUID=abc /home ext4 defaults,usrquota,grpquota 0 2 # keep this comment\n"
    );
}

#[test]
fn fstab_splice_idempotent_when_already_present() {
    let content = "UUID=abc /home ext4 defaults,usrquota,grpquota 0 2\n";
    let out = fstab_with_quota_options(content, "/home", &["usrquota", "grpquota"]).expect("match");
    assert!(out.is_none(), "no change needed → Ok(None)");
}

#[test]
fn fstab_splice_adds_only_missing_option() {
    let content = "UUID=abc /home ext4 defaults,usrquota 0 2\n";
    let out = fstab_with_quota_options(content, "/home", &["usrquota", "grpquota"])
        .expect("match")
        .expect("changed");
    assert_eq!(out, "UUID=abc /home ext4 defaults,usrquota,grpquota 0 2\n");
}

#[test]
fn fstab_splice_errors_when_mount_absent() {
    let content = "UUID=abc / ext4 defaults 0 1\n";
    let err = fstab_with_quota_options(content, "/home", &["usrquota"]).unwrap_err();
    assert!(
        err.contains("/home"),
        "error names the missing mount: {err}"
    );
}

#[test]
fn fstab_splice_matches_mountpoint_with_escaped_space() {
    // fstab stores spaces octal-escaped; our mount_point is unescaped.
    let content = "UUID=abc /mnt/my\\040disk ext4 defaults 0 2\n";
    let out = fstab_with_quota_options(content, "/mnt/my disk", &["usrquota"])
        .expect("should match via unescape")
        .expect("changed");
    // The escaped mountpoint token is preserved verbatim; only opts change.
    assert_eq!(
        out,
        "UUID=abc /mnt/my\\040disk ext4 defaults,usrquota 0 2\n"
    );
}

#[test]
fn fstab_splice_leaves_other_lines_and_no_trailing_newline_untouched() {
    // No trailing newline, a comment line, and a non-matching line all survive.
    let content = "# header\nUUID=root / ext4 defaults 0 1\nUUID=h /home ext4 defaults 0 2";
    let out = fstab_with_quota_options(content, "/home", &["usrquota", "grpquota"])
        .expect("match")
        .expect("changed");
    assert_eq!(
        out,
        "# header\nUUID=root / ext4 defaults 0 1\nUUID=h /home ext4 defaults,usrquota,grpquota 0 2"
    );
    assert!(!out.ends_with('\n'), "trailing-newline style preserved");
}

#[test]
fn fstab_splice_xfs_uquota() {
    // XFS uses its native user+group quota spelling spliced into the
    // options column. This MUST be uquota/gquota (user accounting), not
    // prjquota (project) — the enforce path is `setquota -u`, which can
    // only target user accounting.
    let content = "UUID=x /srv xfs defaults 0 2\n";
    let out = fstab_with_quota_options(content, "/srv", &["uquota", "gquota"])
        .expect("match")
        .expect("changed");
    assert_eq!(out, "UUID=x /srv xfs defaults,uquota,gquota 0 2\n");
}

/// The WAF ingest reads the root-owned hit log, records every refusal,
/// and offers a ban only for ban-counted rules over the threshold —
/// never for xmlrpc / geo / bot refusals, however many there are.
#[tokio::test]
async fn waf_ingest_records_hits_and_bans_only_ban_counted_rules() {
    let pool = open_memory().await.expect("open");
    let logs = tempfile::tempdir().expect("dir");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let a = s
        .get(HostingSelector::Domain(
            Domain::parse("example.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let now = now_secs();
    let threshold = s.fail2ban.waf_threshold as usize;
    let mut body = String::new();
    for i in 0..threshold {
        body.push_str(&format!(
            "{now}.{i:03}\t8.8.8.8\tprobe_args\tGET\t/?x=../etc\tcurl\n"
        ));
    }
    for i in 0..(threshold * 2) {
        body.push_str(&format!(
            "{now}.{i:03}\t9.9.9.9\txmlrpc\tPOST\t/xmlrpc.php\tbot\n"
        ));
        body.push_str(&format!("{now}.{i:03}\t1.0.0.1\tgeo\tGET\t/\tua\n"));
        // A crawler working through a downloads page: refused, never banned.
        body.push_str(&format!(
            "{now}.{i:03}\t66.249.66.1\tdump_files\tGET\t/files/{i}.zip\tGooglebot/2.1\n"
        ));
    }
    let path = logs.path().join(format!("{}.log", a.id.as_str()));
    std::fs::write(&path, &body).expect("write log");
    let since = now - s.fail2ban.window_secs;

    let intents = s.waf_ingest(logs.path(), since, now).await;
    let ips: Vec<&str> = intents.iter().map(|i| i.ip.as_str()).collect();
    assert_eq!(ips, vec!["8.8.8.8"]);
    assert_eq!(intents[0].site.as_ref().expect("site").id, a.id.as_str());

    let act = s.waf_activity(a.id.as_str()).await.expect("activity");
    let count = |r: &str| act.totals_24h.iter().find(|c| c.rule == r).map(|c| c.hits);
    assert_eq!(count("probe_args"), Some(threshold as i64));
    assert_eq!(count("xmlrpc"), Some(threshold as i64 * 2));
    assert_eq!(count("geo"), Some(threshold as i64 * 2));
    assert!(act.autoban_enabled);

    // A second pass over an unchanged log records nothing twice.
    let _ = s.waf_ingest(logs.path(), since, now).await;
    let again = s.waf_activity(a.id.as_str()).await.expect("activity");
    assert_eq!(again.totals_24h, act.totals_24h, "position must advance");

    // Opted out: hits still recorded, no ban offered.
    s.hosting_kv_set(
        a.id.as_str().to_string(),
        WAF_AUTOBAN_KV_KEY.into(),
        "off".into(),
    )
    .await
    .expect("opt out");
    assert!(s.waf_ingest(logs.path(), since, now).await.is_empty());
}

/// The node-wide audit log is attributed by transaction id: entries for
/// this node's site are recorded under CRS tags, entries for an id it
/// does not host are dropped, and nothing is offered for a ban.
#[tokio::test]
async fn crs_ingest_attributes_audit_entries_to_local_sites_only() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let a = s
        .get(HostingSelector::Domain(
            Domain::parse("example.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let fixture = include_str!("../../../../hyperion-adapters/testdata/modsec_audit.jsonl")
        .replace("01a110d5-1ee1-71c2-b98b-0e31aa826f3b", a.id.as_str());
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("audit.log");
    std::fs::write(&log, &fixture).expect("write");
    let now = now_secs();
    s.crs_ingest(&log, now).await;

    let act = s.waf_activity(a.id.as_str()).await.expect("activity");
    let tags: Vec<&str> = act.recent.iter().map(|h| h.rule.as_str()).collect();
    assert_eq!(
        tags,
        vec!["crs_body", "crs_xss", "crs_sqli"],
        "newest first, this site only"
    );
    assert_eq!(act.recent[2].detail, "942100 · score 5");
    assert!(
        hyperion_state::waf::ip_offenders(&pool, a.id.as_str(), 0, 1)
            .await
            .expect("offenders")
            .is_empty()
    );

    // Read once: a second pass over the same log records nothing new.
    s.crs_ingest(&log, now).await;
    assert_eq!(
        s.waf_activity(a.id.as_str())
            .await
            .expect("activity")
            .recent
            .len(),
        3
    );
}

/// Two sites, both under attack. Opting one out stops its access log
/// being read; the other keeps being scanned exactly as before.
#[tokio::test]
async fn opted_out_site_is_skipped_while_the_others_still_scan() {
    let pool = open_memory().await.expect("open");
    let home = tempfile::tempdir().expect("dir");
    let s = svc(pool.clone(), happy_mocks_many()).with_paths(HostingPaths {
        home_root: home.path().display().to_string(),
        ..HostingPaths::default()
    });
    s.create(req("example.cz"))
        .await
        .expect("create example.cz");
    s.create(req("druhy.cz")).await.expect("create druhy.cz");
    let a = s
        .get(HostingSelector::Domain(
            Domain::parse("example.cz").expect("parse"),
        ))
        .await
        .expect("get example.cz");
    let b = s
        .get(HostingSelector::Domain(
            Domain::parse("druhy.cz").expect("parse"),
        ))
        .await
        .expect("get druhy.cz");
    write_wp_login_flood(home.path(), &a.system_user, &a.domain, "203.0.113.7");
    write_wp_login_flood(home.path(), &b.system_user, &b.domain, "198.51.100.9");
    let since = now_secs() - s.fail2ban.window_secs;

    // No key on either site: both are scanned, which is what every
    // install that predates this switch keeps doing.
    assert_eq!(
        http_hits(&s.fail2ban_scan(since).await.expect("scan")),
        {
            let mut want = vec![
                (a.id.as_str().to_string(), "203.0.113.7".to_string()),
                (b.id.as_str().to_string(), "198.51.100.9".to_string()),
            ];
            want.sort();
            want
        },
        "absent key must mean ON for both sites"
    );

    // Opt example.cz out — the panel writes the same key the getter reads.
    s.hosting_kv_set(
        a.id.as_str().to_string(),
        FAIL2BAN_HTTP_KV_KEY.into(),
        "off".into(),
    )
    .await
    .expect("opt out");
    assert_eq!(
        http_hits(&s.fail2ban_scan(since).await.expect("scan")),
        vec![(b.id.as_str().to_string(), "198.51.100.9".to_string())],
        "one site's switch must not silence its neighbour"
    );
}

/// A one-off send never moves the schedule: not when it fails, and the
/// success path has no marker write at all (see `care_report_send_range`).
#[tokio::test]
async fn care_report_range_send_leaves_the_schedule_marker_alone() {
    let pool = open_memory().await.expect("open");
    let (s, detail) = site_owing_a_care_report(&pool).await;
    let marker = (now_secs() - 10 * 86_400).to_string();
    hyperion_state::hosting_kv::set(
        &pool,
        detail.id.as_str(),
        CARE_REPORT_KV_PERIOD_END,
        &marker,
        now_secs(),
    )
    .await
    .expect("kv");
    let now = now_secs();
    let err = s
        .care_report_send_range(
            HostingSelector::Id(detail.id.clone()),
            now - 90 * 86_400,
            now,
        )
        .await
        .expect_err("the relay refuses");
    assert!(err.to_string().contains("Emails tab"), "got: {err}");
    assert_eq!(
        hyperion_state::hosting_kv::get(&pool, detail.id.as_str(), CARE_REPORT_KV_PERIOD_END)
            .await
            .expect("kv")
            .as_deref(),
        Some(marker.as_str())
    );
}

/// `[email]` is written by two Settings forms: the relay (Mail) and the
/// administrator addresses (Alerts → Recipients). Each posts only its own
/// keys, so a save must leave every key it did not post exactly as it was —
/// otherwise saving the relay wipes the alert recipients, or saving the
/// recipients wipes the stored SMTP password.
#[tokio::test]
async fn email_save_leaves_keys_it_did_not_post_alone() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("agent.toml");
    std::fs::write(
        &path,
        "[email]\nenabled = true\nsmtp_host = \"smtp.example.cz\"\nsmtp_port = 587\n\
             smtp_password = \"s3cret\"\ndefault_to = \"ops@example.cz, cto@example.cz\"\n",
    )
    .expect("seed");
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks()).with_agent_config_path(path.clone());
    let save = |pairs: Vec<(&'static str, &'static str)>| {
        let fields: std::collections::BTreeMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        s.agent_config_update("email".to_string(), fields)
    };
    let read = || -> toml_edit::DocumentMut {
        std::fs::read_to_string(&path)
            .expect("read back")
            .parse()
            .expect("parse")
    };

    // The relay form: no default_to, password left blank (post_config
    // drops an empty password before it gets here).
    save(vec![
        ("enabled", "false"),
        ("smtp_host", "relay.example.cz"),
        ("from_address", "noreply@example.cz"),
    ])
    .await
    .expect("relay save");
    let doc = read();
    assert_eq!(doc["email"]["smtp_host"].as_str(), Some("relay.example.cz"));
    assert_eq!(doc["email"]["enabled"].as_bool(), Some(false));
    assert_eq!(
        doc["email"]["default_to"].as_str(),
        Some("ops@example.cz, cto@example.cz")
    );
    assert_eq!(doc["email"]["smtp_password"].as_str(), Some("s3cret"));
    assert_eq!(doc["email"]["smtp_port"].as_integer(), Some(587));

    // The recipients form: default_to only.
    save(vec![("default_to", "ops@example.cz")])
        .await
        .expect("recipients save");
    let doc = read();
    assert_eq!(doc["email"]["default_to"].as_str(), Some("ops@example.cz"));
    assert_eq!(doc["email"]["smtp_password"].as_str(), Some("s3cret"));
    assert_eq!(doc["email"]["smtp_host"].as_str(), Some("relay.example.cz"));
    assert_eq!(
        doc["email"]["from_address"].as_str(),
        Some("noreply@example.cz")
    );
}

#[test]
fn quota_enforce_decide_transitions() {
    use super::{
        quota_enforce_decide as d, QuotaExceedAction::Notify, QuotaExceedAction::Suspend,
        QuotaState::Ok, QuotaState::Over, QuotaState::Released, QuotaState::Suspended, QuotaStep,
    };
    let cap = 1000;
    // No cap → never acts.
    assert_eq!(d(5000, 0, Suspend, Ok), (QuotaStep::Nothing, Ok));
    // Under cap → nothing.
    assert_eq!(d(500, cap, Notify, Ok), (QuotaStep::Nothing, Ok));
    // Cross the cap, notify-mode → notify once, then stay quiet.
    assert_eq!(d(1000, cap, Notify, Ok), (QuotaStep::NotifyOver, Over));
    assert_eq!(d(1200, cap, Notify, Over), (QuotaStep::Nothing, Over));
    // Cross the cap, suspend-mode → suspend.
    assert_eq!(d(1000, cap, Suspend, Ok), (QuotaStep::Suspend, Suspended));
    // Operator flips notify→suspend while already over → suspends now.
    assert_eq!(d(1200, cap, Suspend, Over), (QuotaStep::Suspend, Suspended));
    // Suspended + still over (or within hysteresis band) → hold.
    assert_eq!(
        d(1200, cap, Suspend, Suspended),
        (QuotaStep::Nothing, Suspended)
    );
    assert_eq!(
        d(950, cap, Suspend, Suspended),
        (QuotaStep::Nothing, Suspended)
    ); // 95% > 90% floor
       // Suspended + drops below 90% → auto-resume.
    assert_eq!(d(899, cap, Suspend, Suspended), (QuotaStep::AutoResume, Ok));
    // Over (notify) + drops into hysteresis band → hold "over".
    assert_eq!(d(950, cap, Notify, Over), (QuotaStep::Nothing, Over));
    // Over (notify) + drops well under → reset so a future crossing re-notifies.
    assert_eq!(d(400, cap, Notify, Over), (QuotaStep::Nothing, Ok));
    assert_eq!(d(1000, cap, Notify, Ok), (QuotaStep::NotifyOver, Over)); // re-crosses → re-notifies

    // Released = WE suspended it, operator manually resumed. MUST never
    // re-suspend even while still over (the core safety guarantee), only
    // re-arm once usage drops well under the cap.
    assert_eq!(
        d(1200, cap, Suspend, Released),
        (QuotaStep::Nothing, Released)
    );
    assert_eq!(
        d(1000, cap, Suspend, Released),
        (QuotaStep::Nothing, Released)
    );
    assert_eq!(
        d(950, cap, Suspend, Released),
        (QuotaStep::Nothing, Released)
    ); // hysteresis band
    assert_eq!(d(899, cap, Suspend, Released), (QuotaStep::Nothing, Ok)); // re-armed, no suspend

    // Hysteresis floor never rounds below 1 KiB: a 1-KiB cap still resumes
    // at 0 usage instead of being stuck suspended forever.
    assert_eq!(d(0, 1, Suspend, Suspended), (QuotaStep::AutoResume, Ok));
}

#[test]
fn quotaon_report_parsing() {
    // Modern quota-tools, user on / group off.
    assert!(quota_report_shows_on(
        "user quota on /home (/dev/sda3) is on\ngroup quota on /home (/dev/sda3) is off"
    ));
    // Older format.
    assert!(quota_report_shows_on(
        "/dev/sda1 [/home]: user quotas turned on"
    ));
    // Everything off must read inactive (no `is on` substring in `is off`).
    assert!(!quota_report_shows_on(
        "user quota on /home (/dev/sda3) is off\ngroup quota on /home (/dev/sda3) is off"
    ));
    assert!(!quota_report_shows_on(""));

    // Regression: the exact line `quotaon -p` prints on Debian 12 for an
    // ACTIVE root filesystem. `apply_disk_quota` used to scan this for the
    // literal "user quotas on" (plural), which never appears here — so it
    // false-negatived and refused setquota on a correctly-enabled host.
    // The canonical parser matches it; the dropped substring must not.
    let modern_active = "user quota on / (/dev/vda1) is on\ngroup quota on / (/dev/vda1) is on";
    assert!(quota_report_shows_on(modern_active));
    assert!(
        !modern_active.contains("user quotas on"),
        "the old apply_disk_quota substring never occurs in modern output"
    );
}

// ───────────── Move / Copy: what travels with the site ─────────────

/// `my-shop.cz` and `my.shop.cz` derive the same account; the import
/// must get a name of its own, and every candidate must be a valid
/// system user even when the base already fills 32 characters.
#[test]
fn import_user_candidates_are_unique_and_valid() {
    let a = import_user_candidates("my-shop.cz").expect("derive");
    let b = import_user_candidates("my.shop.cz").expect("derive");
    assert_eq!(a[0], b[0], "the collision this guards against");
    assert_eq!(a[0].as_str(), "my_shop_cz");
    assert_eq!(a[1].as_str(), "my_shop_cz_2");
    let long =
        import_user_candidates("a-very-extremely-long-subdomain-name-here.cz").expect("derive");
    assert_eq!(long.len(), 99);
    let mut seen = std::collections::HashSet::new();
    for n in &long {
        assert!(n.as_str().len() <= 32, "{n}");
        assert!(SystemUserName::parse(n.as_str()).is_ok(), "{n}");
        assert!(seen.insert(n.clone()), "duplicate candidate {n}");
    }
    assert!(long[1].as_str().ends_with("_2"));
}

/// Export → JSON → import, as a Move: every setting arrives on the new
/// hosting id, secrets and run state do not, and the report says so.
#[tokio::test]
async fn move_carries_settings_to_the_new_site() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), carry_mocks());
    let src = carry_source(&s, &pool).await;
    let settings = s.collect_carried_settings(&src).await;
    // Through the wire format, as the bundle does.
    let settings: hyperion_types::migration::HostingCarriedSettings =
        serde_json::from_str(&serde_json::to_string(&settings).expect("ser")).expect("de");
    assert!(
        settings
            .not_carried
            .iter()
            .any(|n| n.starts_with("Git deploy")),
        "{:?}",
        settings.not_carried
    );

    s.create(HostingCreateReq {
        aliases: vec![Domain::parse("www.moved.cz").expect("alias")],
        ..req("moved.cz")
    })
    .await
    .expect("create target");
    let tsel = HostingSelector::Domain(Domain::parse("moved.cz").expect("parse"));
    let target = s.get(tsel.clone()).await.expect("get");
    let report = s
        .apply_carried_settings(&target, Some(&settings), false)
        .await;
    assert!(
        report.iter().all(|l| !l.contains("NOT carried (")),
        "{report:#?}"
    );
    let tid = target.id.as_str();

    let l = s.get_limits(tsel.clone()).await.expect("limits");
    assert_eq!((l.php_memory_mb, l.php_max_children), (768, 14));

    let kv = |k: &'static str| {
        let pool = pool.clone();
        async move {
            hyperion_state::hosting_kv::get(&pool, tid, k)
                .await
                .expect("kv")
        }
    };
    assert_eq!(kv("backup_at").await.as_deref(), Some("03:30"));
    assert_eq!(kv("backup_cadence").await.as_deref(), Some("daily"));
    assert_eq!(kv("php.mem_auto_max_mb").await.as_deref(), Some("1024"));
    assert!(
        kv("care_service_checks").await.is_some(),
        "move carries care state"
    );
    assert_eq!(kv("dkim").await, None);
    assert_eq!(kv("gitsync_webhook_secret").await, None);
    assert_eq!(kv("gitsync_webhook").await, None);
    assert_eq!(kv("backup_last_run_at").await, None);

    assert_eq!(s.hosting_quota_action(tid).await.as_str(), "suspend");

    let t = s.get(tsel.clone()).await.expect("get");
    assert!(t.vhost_options.noindex);
    assert!(t.vhost_options.force_https);
    assert_eq!(
        t.vhost_options.canonical_host, "www",
        "the target has the www alias"
    );
    assert_eq!(
        t.vhost_options.effective_waf_level(),
        hyperion_types::waf::WafLevel::Strict
    );
    assert!(t.vhost_options.basic_auth_enabled && t.vhost_options.basic_auth_set);
    assert_eq!(
        hyperion_state::hostings::get_basic_auth_hash(&pool, &t.id)
            .await
            .expect("hash"),
        "$2b$10$hash"
    );

    let e = s.get_expiry(tsel.clone()).await.expect("expiry");
    assert_eq!(e.owner_email.as_deref(), Some("owner@shop.cz"));
    assert!(e.expires_at.is_some());
    let m = hyperion_state::monitors::get(&pool, &t.id)
        .await
        .expect("monitor")
        .expect("row");
    assert!(m.enabled);
    assert_eq!((m.url_path.as_str(), m.interval_secs), ("/health", 120));

    let b = profiles::get_apply(&pool, &t.id)
        .await
        .expect("apply")
        .expect("row");
    assert!(b.profile_id.is_some(), "the profile exists on this node");
    assert_eq!(b.price_minor, Some(39_900));
    assert!(b.price_pinned);
    assert_eq!(
        b.next_billing_at,
        Some(1_900_000_000),
        "billing clock unchanged"
    );

    let plans = hyperion_state::packages::list_for_hosting(&pool, &t.id)
        .await
        .expect("plans");
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].package_name, "Care Plus");
    assert_eq!(plans[0].prior_state_json.as_deref(), Some("{}"));
    assert_eq!(plans[0].activated_at, 1_700_000_100);
}
