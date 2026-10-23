use super::*;
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
    assert!(html.contains(r#"data-verdict="unchecked""#));
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
    assert!(!html.contains("don't match what should be on disk"));
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
    assert!(html.contains("4 file(s) don't match"));
    assert!(html.contains("wp-includes/load.php"));
    assert!(html.contains("wp-admin/x.php"));
    assert!(html.contains("akismet.php"));
    assert!(html.contains("Php.Trojan.Webshell-1"));
    assert!(!html.contains("Clean —"));
}
