use super::*;

/// "Check DNS" and the banner at the top of the page answer the same
/// question, so a check has to carry the banner with it — one saying
/// "matches" under the other saying "DNS mismatch" is the bug this pins.
#[test]
fn dns_check_answer_refreshes_the_page_banner() {
    let check = |matches: bool| DnsCheckResult {
        domain: "example.cz".into(),
        resolved_a: vec!["192.0.2.1".into()],
        resolved_aaaa: vec![],
        our_public_ipv4: Some("192.0.2.1".into()),
        our_public_ipv6: None,
        matches,
        note: "note".into(),
        proxied: false,
        origin_cert_self_signed: false,
    };
    let oob = r#"<div id="dns-banner" hx-swap-oob="innerHTML">"#;

    let html = render_dns_check_with_banner(check(true)).unwrap();
    assert!(html.contains("matches ✓"), "{html}");
    assert!(html.contains(oob), "{html}");
    assert!(html.contains("DNS OK"), "{html}");
    assert!(!html.contains("DNS mismatch"), "{html}");

    let html = render_dns_check_with_banner(check(false)).unwrap();
    assert!(html.contains("no match ✗"), "{html}");
    assert!(html.contains(oob), "{html}");
    assert!(html.contains("DNS mismatch"), "{html}");
    assert!(!html.contains("DNS OK"), "{html}");

    // The swap only lands if the page has a target that survives the lazy load.
    let page = include_str!("../../../templates/hostings_detail.html");
    assert!(page.contains(r#"<div id="dns-banner" hx-get="#));
}

/// Notes, tags and the panel's `.user.ini` copy follow the site to its
/// new id; the PHP-memory automation and worker state (same `php.`
/// prefix, node state) do not — the bundle carries those.
#[test]
fn master_site_kv_is_notes_tags_and_php_ini_only() {
    for k in [
        "notes",
        "tags",
        "php.memory_limit",
        "php.upload_max_filesize",
    ] {
        assert!(is_master_site_kv(k), "{k}");
    }
    for k in [
        "php.mem_auto",
        "php.mem_auto_max_mb",
        "php.mem_auto_state",
        "php.workers_full",
        "php.workers_auto",
        "php.workers_auto_max",
        "php.workers_auto_state",
        "backup_at",
        "dkim",
        "staging_domain",
    ] {
        assert!(!is_master_site_kv(k), "{k}");
    }
}

#[test]
fn backup_schedule_reads_custom_period_and_time() {
    let kv = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let s = BackupSchedule::from_kv(&kv(&[
        ("backup_cadence", "custom"),
        ("backup_interval_days", "3"),
        ("backup_at", "3:05"),
    ]));
    assert_eq!(s.period_secs(), Some(3 * 86_400));
    assert_eq!(s.at, "03:05");
    assert_eq!(s.label(), "Every 3 days at 03:05");
    // Custom with no valid period schedules nothing — same as the tick.
    let s = BackupSchedule::from_kv(&kv(&[
        ("backup_cadence", "custom"),
        ("backup_interval_days", "400"),
    ]));
    assert_eq!(s.period_secs(), None);
    // Unknown cadence and junk time fall back to off / any time.
    let s = BackupSchedule::from_kv(&kv(&[("backup_cadence", "hourly"), ("backup_at", "25:00")]));
    assert_eq!(s.cadence, "off");
    assert_eq!(s.at, "");
    assert_eq!(
        BackupSchedule::from_kv(&kv(&[("backup_cadence", "daily")])).label(),
        "Daily"
    );
}

#[test]
fn bare_name_drops_one_www_and_keeps_two_labels() {
    assert_eq!(
        bare_name_of("www.example.cz").as_deref(),
        Some("example.cz")
    );
    assert_eq!(bare_name_of("example.cz"), None);
    assert_eq!(bare_name_of("www.cz"), None);
}

fn bulk(ids: &str) -> Vec<i64> {
    BackupDeleteBulkForm {
        selector: "s".into(),
        backup_ids: ids.into(),
        offsite: String::new(),
    }
    .ids()
}

#[test]
fn bulk_backup_ids_parses_dedupes_and_rejects_garbage() {
    // Ordinary case: three ids, order preserved.
    assert_eq!(bulk("3,1,2"), vec![3, 1, 2]);
    // Whitespace tolerated (the field is joined client-side but be lenient).
    assert_eq!(bulk(" 5 , 6 "), vec![5, 6]);
    // Duplicates collapse — a doubled id must not delete-twice / miscount.
    assert_eq!(bulk("4,4,4"), vec![4]);
    // Non-numeric / non-positive fragments are dropped, not errors.
    assert_eq!(bulk("7,abc,,-1,0,8"), vec![7, 8]);
    // Empty field (nothing ticked) yields nothing — the handler no-ops.
    assert!(bulk("").is_empty());
}

#[test]
fn bulk_backup_ids_are_capped() {
    // A tampered POST can't fan out unbounded RPCs.
    let many: String = (1..=500)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(bulk(&many).len(), 100);
}

fn bulk_selected(s: &str) -> Vec<String> {
    BulkForm {
        action: "suspend".into(),
        selected: s.into(),
        asset_id: String::new(),
        activate: None,
    }
    .selected_ids()
}

#[test]
fn bulk_selected_ids_split_dedupe_drop_blanks_no_truncation() {
    // Ordinary case: three ids, order preserved.
    assert_eq!(bulk_selected("h-a,h-b,h-c"), vec!["h-a", "h-b", "h-c"]);
    // Whitespace tolerated; blank fragments (trailing/doubled commas) dropped.
    assert_eq!(bulk_selected(" h-a , , h-b ,"), vec!["h-a", "h-b"]);
    // Duplicates collapse — a doubled id must not act-twice / miscount.
    assert_eq!(bulk_selected("h-a,h-a,h-b"), vec!["h-a", "h-b"]);
    // Empty field (nothing ticked) yields nothing — the handler no-ops.
    assert!(bulk_selected("").is_empty());
    // The parser must NOT cap: a big "select all" has to come back whole so
    // post_bulk can REJECT it (and say so) rather than the parser silently
    // truncating it to a prefix that then finishes as a green "ok" job.
    let many: String = (0..2000)
        .map(|n| format!("h-{n}"))
        .collect::<Vec<_>>()
        .join(",");
    // 2000 exceeds MAX_BULK_SELECTION, so post_bulk will REJECT this batch
    // with a flash rather than the parser quietly returning a 1000-prefix.
    assert_eq!(bulk_selected(&many).len(), 2000);
}

/// The cluster lookup takes the FIRST node that answers, and the same
/// answer picks the node every later RPC is dispatched to. A node that
/// replies to every HostingGet would become the resolver for every
/// hosting in the cluster, so an answer that is not the hosting asked for
/// must be refused.
#[test]
fn a_node_cannot_answer_for_a_hosting_that_was_not_asked_for() {
    let asked_id = HostingSelector::Id(hyperion_types::HostingId("h-victim".into()));
    assert!(detail_matches(&asked_id, "h-victim", "victim.cz"));
    assert!(!detail_matches(&asked_id, "h-attacker", "attacker.cz"));
    // The domain matching is irrelevant when the id was asked for.
    assert!(!detail_matches(&asked_id, "h-attacker", "victim.cz"));

    let asked_domain =
        HostingSelector::Domain(hyperion_validate::Domain::parse("victim.cz").expect("parse"));
    assert!(detail_matches(&asked_domain, "h-victim", "victim.cz"));
    assert!(!detail_matches(&asked_domain, "h-victim", "attacker.cz"));
}

/// A domain is a hostname, and the selector often comes from something
/// the operator typed — so case must not decide whether a legitimate
/// node's answer is accepted.
#[test]
fn the_domain_comparison_ignores_case_but_not_the_domain() {
    let asked =
        HostingSelector::Domain(hyperion_validate::Domain::parse("victim.cz").expect("parse"));
    assert!(detail_matches(&asked, "h1", "VICTIM.cz"));
    assert!(detail_matches(&asked, "h1", "Victim.CZ"));
    // A prefix or a suffix is a different domain, not a near miss.
    assert!(!detail_matches(&asked, "h1", "victim.cz.evil"));
    assert!(!detail_matches(&asked, "h1", "notvictim.cz"));
    assert!(!detail_matches(&asked, "h1", ""));
}

/// After a Move the original stays behind SUSPENDED on the source node
/// under the same domain. A domain lookup that took the master's answer
/// first resolved every domain-addressed action to that parked copy.
#[test]
fn a_domain_lookup_prefers_the_live_copy_over_a_parked_one() {
    use hyperion_types::HostingState;
    let asked =
        HostingSelector::Domain(hyperion_validate::Domain::parse("moved.cz").expect("parse"));
    let mut pick = LookupPick::new(&asked);
    // Master answers first with the suspended original: keep asking.
    assert_eq!(pick.offer(HostingState::Suspended, "master"), None);
    // The worker that received the Move has the live one: take it.
    assert_eq!(pick.offer(HostingState::Active, "worker"), Some("worker"));
}

#[test]
fn a_parked_copy_is_still_found_when_it_is_the_only_one() {
    use hyperion_types::HostingState;
    let asked =
        HostingSelector::Domain(hyperion_validate::Domain::parse("parked.cz").expect("parse"));
    let mut pick = LookupPick::new(&asked);
    assert_eq!(pick.offer(HostingState::Trashed, "master"), None);
    assert_eq!(pick.offer(HostingState::Suspended, "worker"), None);
    // The FIRST parked answer wins — the master's, as before.
    assert_eq!(pick.into_fallback(), Some("master"));
}

/// An id names exactly one row, suspended or not — nothing to prefer.
#[test]
fn an_id_lookup_takes_the_first_match_whatever_its_state() {
    use hyperion_types::{HostingId, HostingState};
    let asked = HostingSelector::Id(HostingId::from("h1".to_string()));
    let mut pick = LookupPick::new(&asked);
    assert_eq!(
        pick.offer(HostingState::Suspended, "master"),
        Some("master")
    );
}

#[test]
fn a_failed_or_provisioning_site_is_live_for_lookup() {
    use hyperion_types::HostingState;
    let asked = HostingSelector::Domain(hyperion_validate::Domain::parse("x.cz").expect("parse"));
    for st in [
        HostingState::Active,
        HostingState::Failed,
        HostingState::Provisioning,
    ] {
        let mut pick = LookupPick::new(&asked);
        assert_eq!(pick.offer(st, 1), Some(1), "{st:?}");
    }
}

/// Render the site-health row for a given probe result.
fn render_health(report: hyperion_types::WpFatalReport) -> String {
    FatalCardTpl {
        report,
        selector: "example.com".into(),
        csrf_token: "t".into(),
        csrf_wp_debug: "t".into(),
        csrf_dropin: "t".into(),
        target_node: String::new(),
        wp_debug_enabled: false,
        error: None,
    }
    .render()
    .expect("health row renders")
}

/// A probe that got nothing back (curl's `000`) used to fall through to
/// "answers HTTP 0, no fatal error" with a green dot — over a site no
/// visitor could reach. It must say so, and why.
#[test]
fn no_answer_is_not_healthy() {
    let html = render_health(hyperion_types::WpFatalReport {
        http_status: 0,
        probe_error: "Couldn't connect to server".into(),
        ..Default::default()
    });
    assert!(html.contains("No answer from the front page"));
    // HTML-escaped on render, so match past the apostrophe.
    assert!(html.contains("t connect to server"));
    assert!(!html.contains("HTTP 0"));
    assert!(!html.contains("no fatal error"));
    assert!(!html.contains("chk-dot ok"));
}

/// A 4xx front page is not a WordPress fatal, but it is not healthy
/// either.
#[test]
fn error_page_is_not_healthy() {
    let html = render_health(hyperion_types::WpFatalReport {
        http_status: 404,
        ..Default::default()
    });
    assert!(html.contains("HTTP 404"));
    assert!(html.contains("document root"));
    assert!(!html.contains("chk-dot ok"));
}

#[test]
fn a_200_is_healthy() {
    let html = render_health(hyperion_types::WpFatalReport {
        http_status: 200,
        ..Default::default()
    });
    assert!(html.contains("answers HTTP 200, no fatal error"));
    assert!(html.contains("chk-dot ok"));
}

/// Render the integrity card for a given scan result.
fn render_integrity(scan: hyperion_types::WpIntegrityScanResult) -> String {
    IntegrityCardTpl {
        scan,
        selector: "example.com".into(),
        csrf_token: "t".into(),
        notice: None,
        queued_since: 0,
    }
    .render()
    .expect("integrity card renders")
}

/// The failure mode this whole card exists to prevent: a scan that
/// could not run must not produce a word an operator could forward to
/// a paying customer as "your site is fine".
#[test]
fn unchecked_never_renders_as_clean() {
    let html = render_integrity(integrity_not_checked("wp-cli exited 1".into()));
    assert!(html.contains(r#"data-verdict="never""#));
    assert!(html.contains("Couldn't check"));
    assert!(html.contains("not a clean result"));
    assert!(!html.contains("Clean —"));
    assert!(html.contains("wp-cli exited 1"));
}

/// Verified files with no malware scanner is its own verdict. ClamAV
/// being absent is normal, but it is not a clean bill of health —
/// checksum verification never looks inside `wp-content/uploads`.
#[test]
fn verified_without_clamav_is_not_clean() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        core_ok: true,
        wp_cli_ok: true,
        clamav_available: false,
        plugins_checked: 3,
        plugins_total: 3,
        scanned_at: 1_700_000_000,
        ..Default::default()
    });
    assert!(html.contains(r#"data-verdict="partial""#));
    assert!(html.contains("malware not scanned"));
    assert!(html.contains("ClamAV isn't installed"));
    assert!(!html.contains("Clean —"));
}

/// ClamAV IS installed but this site has no pass yet — the node's one
/// scanner slot was busy, or clamscan could not finish. That must not be
/// rendered as "isn't installed": the operator who just added ClamAV
/// would go looking for a problem on the Services page that isn't there.
#[test]
fn installed_clamav_without_a_pass_is_not_called_missing() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        core_ok: true,
        wp_cli_ok: true,
        clamav_available: false,
        clamav_installed: true,
        plugins_checked: 3,
        plugins_total: 3,
        error: Some("malware scan skipped: another scan is already running on this node".into()),
        scanned_at: 1_700_000_000,
        ..Default::default()
    });
    assert!(html.contains(r#"data-verdict="partial""#));
    assert!(html.contains("malware not scanned"));
    assert!(!html.contains("ClamAV isn't installed"));
    assert!(html.contains("ClamAV is installed"));
    assert!(html.contains("another scan is already running"));
    assert!(!html.contains("Clean —"));
}

/// Both signals ran and both came back empty — the only state allowed
/// to say so.
#[test]
fn both_signals_clean_says_clean() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        core_ok: true,
        wp_cli_ok: true,
        clamav_available: true,
        plugins_checked: 3,
        plugins_total: 3,
        scanned_at: 1_700_000_000,
        ..Default::default()
    });
    assert!(html.contains(r#"data-verdict="clean""#));
    assert!(html.contains("Clean —"));
    assert!(html.contains("ClamAV scanned the site"));
}

/// Premium plugins have no published checksums. They must never be
/// counted or styled as findings — a card that flags Elementor Pro
/// every night is a card nobody reads.
#[test]
fn unknown_plugins_are_coverage_not_findings() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        core_ok: true,
        wp_cli_ok: true,
        clamav_available: true,
        plugins_unknown: vec!["elementor-pro".into(), "wp-rocket".into()],
        plugins_checked: 1,
        plugins_total: 3,
        scanned_at: 1_700_000_000,
        ..Default::default()
    });
    assert!(html.contains("this is normal"));
    assert!(html.contains("elementor-pro"));
    // Still clean: unknown coverage is not a finding.
    assert!(html.contains(r#"data-verdict="clean""#));
    assert!(!html.contains("need attention"));
}

/// Findings outrank a half-failed probe: something we DID see is more
/// actionable than something we couldn't, and the paths have to be on
/// screen either way.
#[test]
fn findings_are_listed_with_their_paths() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        wp_cli_ok: true,
        clamav_available: true,
        core_modified: vec!["wp-includes/load.php".into()],
        core_unexpected: vec!["wp-admin/x.php".into()],
        plugins_failed: vec![hyperion_types::WpIntegrityPluginResult {
            slug: "akismet".into(),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: "akismet.php".into(),
                message: "Checksum does not match".into(),
            }],
        }],
        malware: vec![hyperion_types::WpMalwareHit {
            path: "/var/www/uploads/s.php".into(),
            signature: "Php.Trojan.Webshell-1".into(),
        }],
        scanned_at: 1_700_000_000,
        ..Default::default()
    });
    assert!(html.contains(r#"data-verdict="findings""#));
    assert!(html.contains("4 file(s) need attention"));
    assert!(html.contains("wp-includes/load.php"));
    assert!(html.contains("wp-admin/x.php"));
    assert!(html.contains("akismet.php"));
    assert!(html.contains("Php.Trojan.Webshell-1"));
    assert!(!html.contains("Clean —"));
}

/// A core finding the repair can actually fix gets the button; a plugin
/// that failed verification gets its own reinstall, carrying its slug.
#[test]
fn fixable_findings_offer_a_fix() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        wp_cli_ok: true,
        core_missing: vec!["license.txt".into(), "readme.html".into()],
        plugins_failed: vec![hyperion_types::WpIntegrityPluginResult {
            slug: "akismet".into(),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: "akismet.php".into(),
                message: "Checksum does not match".into(),
            }],
        }],
        scanned_at: 1_700_000_000,
        ..Default::default()
    });
    assert!(html.contains(r#"hx-post="/hostings/integrity/repair-core""#));
    assert!(html.contains(r#"hx-post="/hostings/integrity/reinstall-plugin""#));
    assert!(html.contains(r#"name="slug" value="akismet""#));
    // Confirm attributes ride on the form, where the driver reads them.
    assert!(html.contains(r#"data-confirm-title="Repair WordPress core files""#));
}

/// The core repair puts official files back; it does not delete anything.
/// A card offering "Repair" for a file that SHOULDN'T exist would promise a
/// fix that leaves the dropper exactly where it was.
#[test]
fn unexpected_core_files_get_no_repair_button() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        wp_cli_ok: true,
        core_unexpected: vec!["wp-includes/x.php".into()],
        scanned_at: 1_700_000_000,
        ..Default::default()
    });
    assert!(!html.contains("/hostings/integrity/repair-core"));
    assert!(html.contains("aren't removed by any fix here"));
}

/// Opening the WordPress tab reads the stored result. `WpIntegrityScan`
/// runs wp-cli and maybe clamscan on the node, so the page-load request must
/// be the read-only one.
#[test]
fn integrity_panel_get_dispatches_stored_not_scan() {
    let sel = parse_selector("example.com").expect("selector");
    assert!(matches!(
        integrity_panel_request(sel),
        Request::WpIntegrityStored { .. }
    ));
    // …and the GET handler builds its request through that function only.
    let src = include_str!("integrity.rs");
    let get = src
        .split("pub async fn get_integrity_panel")
        .nth(1)
        .and_then(|rest| rest.split("/// Queue a scan").next())
        .expect("get_integrity_panel source");
    assert!(get.contains("integrity_stored_on_node"));
    assert!(!get.contains("WpIntegrityScan"));
}

/// A node from before `WpIntegrityStored` rejects the request by name; the
/// card says the node needs updating rather than echoing the parser error.
#[test]
fn an_old_node_renders_as_needs_updating() {
    let why = integrity_error_text("invalid request: unknown variant `wp_integrity_stored`");
    let html = render_integrity(integrity_not_checked(why));
    assert!(html.contains("this node needs updating to show scan results"));
    assert!(!html.contains("unknown variant"));
    assert!(html.contains(r#"data-verdict="never""#));
    assert!(!html.contains("Clean —"));
    assert_eq!(integrity_error_text("boom"), "boom");
}

/// A site nobody has scanned says so, and polls only while a scan is queued.
#[test]
fn never_scanned_says_not_scanned_and_only_a_queued_card_polls() {
    let html = render_integrity(Default::default());
    assert!(html.contains("Not scanned yet"));
    assert!(!html.contains("Clean —"));
    assert!(html.contains(r#"data-verdict="never""#));
    assert!(
        !html.contains("hx-trigger=\"every 10s\""),
        "idle card must not poll"
    );
    assert!(!html.contains(" disabled"));

    let queued = IntegrityCardTpl {
        scan: hyperion_types::WpIntegrityScanResult {
            scan_queued: true,
            ..Default::default()
        },
        selector: "example.com".into(),
        csrf_token: "t".into(),
        notice: None,
        queued_since: 1_700_000_000,
    }
    .render()
    .expect("renders");
    assert!(queued.contains(
        r#"hx-get="/hostings/example.com/integrity-panel?queued_at=1700000000" hx-trigger="every 10s""#
    ));
    assert!(queued.contains(r#"data-verdict="running""#));
    assert!(queued.contains("scan queued"));
    assert!(queued.contains(" disabled"));
    assert!(!queued.contains("Clean —"));
}

/// "Scan now" and the re-scan after a fix only ask the node, which answers at
/// once. A scan can wait an hour behind another site's: nothing here holds a
/// request or a job open for it.
#[test]
fn scan_now_only_asks_the_node() {
    let sel = HostingSelector::Domain(Domain::parse("example.com").expect("domain"));
    assert!(matches!(
        integrity_scan_request(sel),
        Request::WpIntegrityScanRequest { .. }
    ));
    let src = include_str!("integrity.rs");
    assert!(!src.contains("spawn_job"));
    assert!(!src.contains(&format!("Request::WpIntegrityScan{}", " {")));
    assert_eq!(src.matches("request_integrity_scan(&state").count(), 2);
}

/// The node's flag decides, for as long as the page has been waiting up to two
/// hours. A reload starts its own wait rather than never ending.
#[test]
fn a_card_polls_while_the_node_says_queued() {
    let now = 1_700_000_000;
    assert_eq!(poll_state(false, now - 60, now), (false, now - 60));
    assert_eq!(poll_state(false, 0, now), (false, now));
    assert_eq!(poll_state(true, now - 16 * 60, now), (true, now - 16 * 60));
    assert_eq!(poll_state(true, 0, now), (true, now), "after a reload");
    assert!(poll_state(true, now - 2 * 3600 + 1, now).0);
    assert!(!poll_state(true, now - 2 * 3600, now).0);
}

fn rule_hit(rel: &str) -> hyperion_types::SiteFileFinding {
    hyperion_types::SiteFileFinding {
        rel: rel.into(),
        kind: hyperion_types::FindingKind::RuleHit,
        severity: "high".into(),
        rule_id: Some("php.eval-base64".into()),
        line: 3,
        snippet: "eval(base64_decode($x))".into(),
        ..Default::default()
    }
}

/// A finished native scan of a WordPress site that found nothing.
fn native_scan() -> hyperion_types::WpIntegrityScanResult {
    hyperion_types::WpIntegrityScanResult {
        core_ok: true,
        wp_cli_ok: true,
        native_scan_ran: true,
        scanned_at: 1_794_055_205,
        plugins_checked: 3,
        plugins_total: 4,
        coverage: hyperion_types::ScanCoverage {
            plugins_verified: 3,
            plugins_total: 4,
            themes_verified: 1,
            themes_total: 2,
            files_watched: 1200,
            watching_since: 1_794_055_205,
            upstream_ran: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn verdict_findings_lists_the_rule_hit_and_says_attention() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        findings: vec![rule_hit("wp-content/uploads/x.php")],
        ..native_scan()
    });
    assert!(html.contains(r#"data-verdict="findings""#));
    assert!(html.contains("1 file(s) need attention"));
    assert!(html.contains("wp-content/uploads/x.php"));
    assert!(html.contains("php.eval-base64"));
    assert!(html.contains("line 3"));
    assert!(html.contains("chk-dot err"));
    assert!(!html.contains("Clean —"));
}

#[test]
fn verdict_review_counts_changes_and_is_not_clean() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        review: vec![hyperion_types::SiteFileFinding {
            rel: "wp-content/themes/t/new.js".into(),
            ..Default::default()
        }],
        ..native_scan()
    });
    assert!(html.contains(r#"data-verdict="review""#));
    assert!(html.contains("1 change(s) to review"));
    assert!(html.contains("wp-content/themes/t/new.js"));
    assert!(html.contains("chk-dot warn"));
    assert!(!html.contains("Clean —"));
}

/// ClamAV isn't needed for a clean native scan, and the coverage line says what
/// it did and didn't cover.
#[test]
fn verdict_clean_without_clamav() {
    let html = render_integrity(native_scan());
    assert!(html.contains(r#"data-verdict="clean""#));
    assert!(html.contains("Clean —"));
    assert!(html.contains("chk-dot ok"));
}

#[test]
fn verdict_partial_when_the_scan_did_not_cover_the_site() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        coverage: hyperion_types::ScanCoverage {
            partial_reasons: vec!["stopped after 500000 files".into()],
            ..native_scan().coverage
        },
        ..native_scan()
    });
    assert!(html.contains(r#"data-verdict="partial""#));
    assert!(html.contains("Partly checked"));
    assert!(!html.contains("Clean —"));
}

/// A scan in flight shows its spinner next to a standing finding instead of
/// hiding it, and stands in for the verdict when there is nothing else to say.
#[test]
fn verdict_running_keeps_standing_findings_visible() {
    let idle = render_integrity(hyperion_types::WpIntegrityScanResult {
        scan_queued: true,
        ..native_scan()
    });
    assert!(idle.contains(r#"data-verdict="running""#));
    assert!(idle.contains("No verdict until the scan finishes"));
    assert!(idle.contains("scanning in the background"));
    assert!(!idle.contains("Clean —"));

    let busy = render_integrity(hyperion_types::WpIntegrityScanResult {
        scan_queued: true,
        findings: vec![rule_hit("a/shell.php")],
        ..native_scan()
    });
    assert!(busy.contains(r#"data-verdict="findings""#));
    assert!(busy.contains("a/shell.php"));
    assert!(busy.contains("scanning in the background"));
}

#[test]
fn verdict_never_says_nothing_was_verified() {
    let html = render_integrity(Default::default());
    assert!(html.contains(r#"data-verdict="never""#));
    assert!(html.contains("Not scanned yet"));
    assert!(html.contains("nothing was verified"));
}

#[test]
fn coverage_line_names_database_not_scanned() {
    let html = render_integrity(native_scan());
    assert!(html.contains("The database is not scanned"));
    // …on a state with no scan too.
    assert!(render_integrity(Default::default()).contains("The database is not scanned"));
}

#[test]
fn coverage_line_counts_themes() {
    let html = render_integrity(native_scan());
    assert!(html.contains("3 of 4 plugin(s)"));
    assert!(html.contains("1 of 2 theme(s)"));
    assert!(html.contains("against wordpress.org"));
    assert!(html.contains("1200 files watched"));
}

#[test]
fn watching_since_shown_after_first_scan() {
    let html = render_integrity(native_scan());
    assert!(html.contains("since 2026-11-07"), "{html}");
    // Earlier changes can't be proven, and the card says why that date is there.
    let fresh = render_integrity(hyperion_types::WpIntegrityScanResult {
        coverage: hyperion_types::ScanCoverage {
            watching_since: 0,
            ..native_scan().coverage
        },
        ..native_scan()
    });
    assert!(!fresh.contains("watched since"));
}

#[test]
fn pilot_label_shown_while_report_only() {
    let pilot = render_integrity(hyperion_types::WpIntegrityScanResult {
        report_only: true,
        ..native_scan()
    });
    assert!(pilot.contains("running in test mode"));
    assert!(pilot.contains("don't send alerts yet"));
    let live = render_integrity(native_scan());
    assert!(!live.contains("test mode"));
    // The pilot changes no verdict: the panel shows what the scan found.
    let hit = render_integrity(hyperion_types::WpIntegrityScanResult {
        report_only: true,
        findings: vec![rule_hit("x.php")],
        ..native_scan()
    });
    assert!(hit.contains(r#"data-verdict="findings""#));
}

#[test]
fn partial_names_what_did_not_run() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        coverage: hyperion_types::ScanCoverage {
            partial_reasons: vec![
                "symlinked directories not looked at: <evil>".into(),
                "stopped after 500000 files".into(),
            ],
            ..native_scan().coverage
        },
        ..native_scan()
    });
    assert!(html.contains("didn't finish"));
    assert!(html.contains("stopped after 500000 files"));
    assert!(html.contains("symlinked directories not looked at: &lt;evil&gt;"));
    assert!(!html.contains("<evil>"));
    assert!(!html.contains("malware not scanned"));

    // WordPress, and the comparison could not run: no wp-cli, no blame on the site.
    let offline = render_integrity(hyperion_types::WpIntegrityScanResult {
        wp_cli_ok: false,
        coverage: hyperion_types::ScanCoverage {
            upstream_ran: false,
            ..native_scan().coverage
        },
        ..native_scan()
    });
    assert!(offline.contains(r#"data-verdict="partial""#));
    assert!(offline
        .contains("wordpress.org could not be reached or the WordPress version could not be read"));
    assert!(!offline.contains("wp-cli"));
    assert!(!offline.contains("Clean —"));
}

/// Everything a tenant controls reaches the page through askama's escaping, with
/// control characters made visible.
#[test]
fn snippet_is_escaped() {
    let nasty = hyperion_types::SiteFileFinding {
        rel: "up/<script>alert(1)</script>\u{1b}[31m\nx\u{202e}.php".into(),
        snippet: "<script>alert('s')</script>\u{7}".into(),
        rule_id: Some("<b>rule</b>".into()),
        domains: vec!["<i>evil.example</i>".into()],
        ..rule_hit("x")
    };
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        findings: vec![nasty.clone()],
        review: vec![nasty],
        coverage: hyperion_types::ScanCoverage {
            partial_reasons: vec!["<script>reason</script>".into()],
            ..native_scan().coverage
        },
        malware: vec![hyperion_types::WpMalwareHit {
            path: "/h/<script>m</script>".into(),
            signature: "<script>sig</script>".into(),
        }],
        ..native_scan()
    });
    assert!(!html.contains("<script"), "{html}");
    assert!(!html.contains("<b>rule"));
    assert!(!html.contains("<i>evil"));
    assert!(html.contains("&lt;script&gt;alert(1)"));
    for bad in ['\u{1b}', '\u{7}', '\u{202e}'] {
        assert!(!html.contains(bad), "{bad:?} leaked");
    }
    // A newline in a path doesn't break the line it sits on.
    assert!(!html.contains("\nx"));
}

#[test]
fn lists_are_capped_at_fifty_with_a_count() {
    let many: Vec<_> = (0..60).map(|i| rule_hit(&format!("f/{i}.php"))).collect();
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        findings: many.clone(),
        review: many,
        ..native_scan()
    });
    assert!(html.contains("f/49.php"));
    assert!(!html.contains("f/50.php"));
    assert!(html.contains("Showing 50 of 60"));
}

/// A whole plugin differing is one fact, worded as such.
#[test]
fn component_level_finding_says_the_plugin_no_longer_matches() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        plugins_failed: vec![hyperion_types::WpIntegrityPluginResult {
            slug: "akismet".into(),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: ".".into(),
                message: "9 of 10 files differ from wordpress.org, 0 added".into(),
            }],
        }],
        findings: vec![hyperion_types::SiteFileFinding {
            rel: "wp-content/plugins/akismet".into(),
            kind: hyperion_types::FindingKind::UpstreamModified,
            severity: "high".into(),
            component: Some("akismet".into()),
            source_label: Some("wordpress.org".into()),
            snippet: "9 of 10 files differ from wordpress.org, 0 added".into(),
            ..Default::default()
        }],
        core_modified: vec![".".into()],
        ..native_scan()
    });
    assert!(html.contains("this plugin no longer matches wordpress.org"));
    assert!(html.contains("most of WordPress core no longer matches"));
    // The same fact isn't listed a second time under the findings.
    assert!(!html.contains("<code>wp-content/plugins/akismet</code>"));
    // Core's "." and the plugin's "." are one fact each.
    assert!(html.contains("2 file(s) need attention"));
}

/// A vendor package is not wordpress.org, and the card doesn't claim it is.
#[test]
fn component_finding_names_its_own_reference() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        plugins_failed: vec![hyperion_types::WpIntegrityPluginResult {
            slug: "elementor-pro".into(),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: ".".into(),
                message: "x".into(),
            }],
        }],
        findings: vec![hyperion_types::SiteFileFinding {
            rel: "wp-content/plugins/elementor-pro".into(),
            kind: hyperion_types::FindingKind::UpstreamModified,
            component: Some("elementor-pro".into()),
            source_label: Some("vendor package".into()),
            ..Default::default()
        }],
        ..native_scan()
    });
    assert!(html.contains("this plugin no longer matches the vendor&#x27;s package"));
    // A private plugin sharing a slug with a wordpress.org one must not be offered
    // a replacement from wordpress.org.
    assert!(!html.contains("/hostings/integrity/reinstall-plugin"));
    assert!(!html.contains("Reinstall elementor-pro"));
    assert!(!html.contains("from wordpress.org and replaces"));
}

/// The reinstall button needs a positive "wordpress.org" label on a native
/// record: a missing one (findings cut by the cap) is not read as wordpress.org.
/// Slug text shown in the dialog is made printable.
#[test]
fn reinstall_needs_wordpress_org_as_the_reference() {
    let failed = |slug: &str| hyperion_types::WpIntegrityPluginResult {
        slug: slug.into(),
        issues: vec![hyperion_types::WpIntegrityFileIssue {
            path: "a.php".into(),
            message: "Checksum does not match".into(),
        }],
    };
    let labelled = |slug: &str, label: &str| hyperion_types::SiteFileFinding {
        component: Some(slug.into()),
        source_label: Some(label.into()),
        kind: hyperion_types::FindingKind::UpstreamModified,
        ..Default::default()
    };
    let org = render_integrity(hyperion_types::WpIntegrityScanResult {
        plugins_failed: vec![failed("akismet\u{1b}")],
        findings: vec![labelled("akismet\u{1b}", "wordpress.org")],
        ..native_scan()
    });
    assert!(org.contains("/hostings/integrity/reinstall-plugin"));
    assert!(org.contains("Reinstall akismet\u{fffd}"));

    let unlabelled = render_integrity(hyperion_types::WpIntegrityScanResult {
        plugins_failed: vec![failed("akismet")],
        ..native_scan()
    });
    assert!(!unlabelled.contains("/hostings/integrity/reinstall-plugin"));

    let vendor = render_integrity(hyperion_types::WpIntegrityScanResult {
        plugins_failed: vec![failed("acf-pro")],
        findings: vec![labelled("acf-pro", "vendor package")],
        ..native_scan()
    });
    assert!(!vendor.contains("/hostings/integrity/reinstall-plugin"));
    assert!(vendor.contains("don't match the vendor&#x27;s package"));
    assert!(vendor.contains("would install a different plugin"));

    // A record from before the label could only have meant wordpress.org.
    let old = render_integrity(hyperion_types::WpIntegrityScanResult {
        wp_cli_ok: true,
        scanned_at: 1,
        plugins_failed: vec![failed("akismet")],
        ..Default::default()
    });
    assert!(old.contains("/hostings/integrity/reinstall-plugin"));
}

/// The scan's error text reaches the page printable and escaped.
#[test]
fn scan_error_is_escaped_and_printable() {
    let html = render_integrity(integrity_not_checked(
        "<script>x</script>\u{1b}\nboom".into(),
    ));
    assert!(!html.contains("<script>"));
    assert!(!html.contains('\u{1b}'));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn theme_failures_are_listed() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        themes_failed: vec![hyperion_types::WpIntegrityPluginResult {
            slug: "twentytwentyfour".into(),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: "functions.php".into(),
                message: "Checksum does not match".into(),
            }],
        }],
        ..native_scan()
    });
    assert!(html.contains(r#"data-verdict="findings""#));
    assert!(html.contains("Theme <code>twentytwentyfour</code>"));
    assert!(html.contains("functions.php"));
    assert!(html.contains("1 file(s) need attention"));
    // File actions come later: no button on a theme yet.
    assert!(!html.contains("reinstall-theme"));
}

/// A site with no WordPress has no release to compare with, which is not a
/// failure, and its card never talks about wordpress.org.
fn non_wordpress_scan() -> hyperion_types::WpIntegrityScanResult {
    hyperion_types::WpIntegrityScanResult {
        native_scan_ran: true,
        scanned_at: 1_794_055_205,
        coverage: hyperion_types::ScanCoverage {
            no_upstream: true,
            files_watched: 80,
            watching_since: 1_794_055_205,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn non_wordpress_card_never_mentions_wordpress() {
    for scan in [
        non_wordpress_scan(),
        hyperion_types::WpIntegrityScanResult {
            findings: vec![rule_hit("index.php")],
            ..non_wordpress_scan()
        },
        hyperion_types::WpIntegrityScanResult {
            review: vec![hyperion_types::SiteFileFinding {
                rel: "a.js".into(),
                ..Default::default()
            }],
            ..non_wordpress_scan()
        },
        hyperion_types::WpIntegrityScanResult {
            coverage: hyperion_types::ScanCoverage {
                partial_reasons: vec!["stopped early".into()],
                ..non_wordpress_scan().coverage
            },
            ..non_wordpress_scan()
        },
    ] {
        let html = render_integrity(scan);
        assert!(!html.to_lowercase().contains("wordpress"), "{html}");
        assert!(!html.contains("plugin(s)"));
        assert!(!html.contains("theme(s)"));
    }
    let clean = render_integrity(non_wordpress_scan());
    assert!(clean.contains(r#"data-verdict="clean""#));
    assert!(clean.contains("80 files watched"));
    // ClamAV doesn't run on such a site; the card doesn't call it missing.
    assert!(clean.contains("ClamAV doesn't run on this kind of site"));
    assert!(!clean.contains("isn't installed"));
}

/// Hostings other than WordPress ones get the card on the overview tab: PHP and
/// static sites that have no WordPress, never a reverse proxy.
#[test]
fn card_on_overview_tab_for_php_kind_without_wordpress() {
    assert!(integrity_on_overview("php", false));
    assert!(integrity_on_overview("static", false));
    // WordPress keeps its row on the WordPress tab, and one card per site.
    assert!(!integrity_on_overview("php", true));
    let page = include_str!("../../../templates/hostings_detail.html");
    let overview = page
        .split(r#"id="tab-overview""#)
        .nth(1)
        .and_then(|r| r.split(r#"id="tab-ssl""#).next())
        .expect("overview tab");
    assert!(overview.contains("self.integrity_on_overview()"));
    assert!(overview.contains(r#"hx-get="/hostings/{{ detail.id.as_str() }}/integrity-panel""#));
    assert_eq!(overview.matches("integrity-panel").count(), 1);
    // The WordPress tab still has its own row, under a WordPress site only.
    let wp = page
        .split(r#"id="tab-wordpress""#)
        .nth(1)
        .and_then(|r| r.split(r#"id="tab-settings""#).next())
        .expect("wordpress tab");
    assert!(wp.contains("integrity-panel"));
}

#[test]
fn no_card_for_reverse_proxy() {
    assert!(!integrity_on_overview("reverse_proxy", false));
    assert!(!integrity_on_overview("reverse_proxy", true));
    assert!(!integrity_on_overview("redirect", false));
}

/// Hits from an earlier pass still show when the latest pass couldn't run.
#[test]
fn clamav_hits_show_when_the_last_pass_did_not_run() {
    let html = render_integrity(hyperion_types::WpIntegrityScanResult {
        clamav_available: false,
        scanned_at: 1,
        malware: vec![hyperion_types::WpMalwareHit {
            path: "/home/x/a.php".into(),
            signature: "Php.Trojan.Webshell-1".into(),
        }],
        ..Default::default()
    });
    assert!(html.contains("Php.Trojan.Webshell-1"));
}

/// The outcome of a fix renders inside the row (HTMX won't swap an error
/// status), worded so a failure can't be read as success.
#[test]
fn fix_outcome_renders_in_the_card() {
    let ok = IntegrityCardTpl {
        scan: hyperion_types::WpIntegrityScanResult {
            wp_cli_ok: true,
            core_ok: true,
            ..Default::default()
        },
        selector: "example.com".into(),
        csrf_token: "t".into(),
        notice: Some((true, "WordPress 6.4.2 core files replaced.".into())),
        queued_since: 0,
    }
    .render()
    .expect("renders");
    assert!(ok.contains("Fixed: WordPress 6.4.2 core files replaced."));
    let failed = IntegrityCardTpl {
        scan: integrity_not_checked("x".into()),
        selector: "example.com".into(),
        csrf_token: "t".into(),
        notice: Some((false, "download failed".into())),
        queued_since: 0,
    }
    .render()
    .expect("renders");
    assert!(failed.contains("Fix failed: download failed"));
    assert!(failed.contains("tone-err"));
}

/// Every outdated row on the Updates row gets its own update button: each
/// core release (a major says what can break before anything runs), and each
/// plugin and theme by slug. A viewer without WpManage sees the rows but no
/// button the POST would refuse, and an up-to-date site names its release.
#[test]
fn the_updates_row_offers_every_update_by_hand() {
    let scan = |core_updates, findings| hyperion_types::WpVulnScanResult {
        checked: 4,
        core_version: "6.5.3".into(),
        core_checked: true,
        core_updates,
        findings,
        ..Default::default()
    };
    let finding =
        |slug: &str, kind: &str, from: &str, to: &str, major: bool| hyperion_types::WpVulnFinding {
            slug: slug.into(),
            name: slug.into(),
            kind: kind.into(),
            installed_version: from.into(),
            patched_version: to.into(),
            update_type: if major { "major" } else { "minor" }.into(),
            auto_updatable: !major,
            ..Default::default()
        };
    let full = || {
        scan(
            vec![
                hyperion_types::WpCoreUpdate {
                    version: "6.7.1".into(),
                    update_type: "major".into(),
                },
                hyperion_types::WpCoreUpdate {
                    version: "6.5.5".into(),
                    update_type: "minor".into(),
                },
            ],
            vec![
                finding("woocommerce", "plugin", "8.9.1", "9.4.0", true),
                finding("astra", "theme", "4.6.1", "4.6.9", false),
            ],
        )
    };
    let html = wp_updates::VulnPanelTpl::new(full(), "kos.cz".into(), true, "tok".into(), true)
        .render()
        .expect("render");
    assert_eq!(
        html.matches(r#"action="/hostings/wp/core-update""#).count(),
        2
    );
    assert!(html.contains(r#"name="version" value="6.7.1""#), "{html}");
    assert!(html.contains(r#"name="version" value="6.5.5""#), "{html}");
    assert!(html.contains("is a major release"), "{html}");
    assert!(html.contains("Update to 6.7.1"), "{html}");
    // Plugin and theme by slug, through the existing action endpoints.
    assert!(
        html.contains(r#"action="/hostings/wp/plugin-action""#),
        "{html}"
    );
    assert!(
        html.contains(r#"name="slug" value="woocommerce""#),
        "{html}"
    );
    assert!(
        html.contains(r#"action="/hostings/wp/theme-action""#),
        "{html}"
    );
    assert!(html.contains(r#"name="slug" value="astra""#), "{html}");
    assert_eq!(html.matches(r#"name="action" value="update""#).count(), 2);
    // The site's own row returns to the site, never to /vulns.
    assert!(!html.contains(r#"name="back""#), "{html}");
    // A major plugin release confirms first; a minor one does not.
    assert!(
        html.contains(r#"data-confirm-title="Update woocommerce to 9.4.0""#),
        "{html}"
    );
    assert!(
        !html.contains(r#"data-confirm-title="Update astra"#),
        "{html}"
    );

    let viewer = wp_updates::VulnPanelTpl::new(full(), "kos.cz".into(), true, "tok".into(), false)
        .render()
        .expect("render");
    assert!(viewer.contains("woocommerce"), "{viewer}");
    assert!(!viewer.contains("upd-act"), "{viewer}");
    assert!(!viewer.contains("core-update"), "{viewer}");

    let none = wp_updates::VulnPanelTpl::new(
        scan(vec![], vec![]),
        "kos.cz".into(),
        true,
        "tok".into(),
        true,
    )
    .render()
    .expect("render");
    assert!(!none.contains("core-update"), "{none}");
    assert!(!none.contains("upd-act"), "{none}");
    assert!(
        none.contains("WordPress 6.5.3 is the latest release"),
        "{none}"
    );
}
