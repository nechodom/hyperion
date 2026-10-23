//! Tests for `service::care_report`.

use super::*;

/// A Czech report must contain no English at all.
///
/// This is the test the whole catalogue exists for. Before it, six
/// placeholders expanded to English sections, the "not measured"
/// disclosure was appended in English no matter what, and the month
/// names came out of a Rust array — so a letter an operator had
/// carefully translated still reached their customer with English in
/// it. The check is deliberately crude (look for words that could only
/// come from the English pack) because a subtle check would not have
/// caught the bug it is here to prevent.
#[test]
fn a_czech_letter_carries_no_english() {
    let cs = LetterCatalog::new(LetterLang::Cs);
    let from = 1_780_272_000;
    let to = from + 30 * 86_400;
    // Every section MEASURED, so every "some" branch renders...
    let measured = CareReport {
        attacks_blocked: Some(12),
        updates_applied: Some(3),
        usage: Some(CareUsage {
            bw_in_bytes: Some(2_000_000),
            bw_out_bytes: 34_500_000,
            requests: 12_345,
            disk_peak_bytes: 1_200_000_000,
            days_counted: 20,
            days_in_period: 30,
        }),
        uptime: Some(CareUptime {
            samples: 100,
            successes: 97,
            days_counted: 20,
            days_in_period: 30,
        }),
        backups: Some(CareBackups {
            taken: 30,
            failed: 1,
            last_success_at: Some(to - 3600),
        }),
        integrity: Some(CareIntegrity {
            scanned_at: to - 3600,
            checksums_ran: true,
            malware_scan_ran: false,
            core_issues: 2,
            plugin_issues: 1,
            malware_hits: 1,
        }),
        ..CareReport::empty(HostingId("t".into()), "example.cz".into(), from, to)
    };
    // ...and once more with everything UNMEASURED, so does every
    // "not monitored" branch plus the appended disclosure.
    let unmeasured = CareReport::empty(HostingId("t".into()), "example.cz".into(), from, to);
    for r in [&measured, &unmeasured] {
        let (subject, body) = care_report_render_with(&cs, r, "example.cz", "");
        let whole = format!("{subject}\n{body}");
        for english in [
            "CARE REPORT",
            "Site:",
            "Period:",
            "ATTACKS",
            "UPDATES",
            "TRAFFIC",
            "AVAILABILITY",
            "BACKUPS",
            "FILE INTEGRITY",
            "not monitored",
            "not measured",
            "NOT MEASURED",
            "days",
            "checks",
            "requests",
            "copies",
            "findings",
            "Jun",
            "care plan",
        ] {
            assert!(
                !whole.contains(english),
                "Czech letter still contains {english:?}:\n{whole}"
            );
        }
    }
}

/// The disclosure that gets bolted onto a custom letter follows the
/// language too — it used to arrive in English on top of Czech prose.
#[test]
fn the_unmeasured_disclosure_is_translated() {
    let cs = LetterCatalog::new(LetterLang::Cs);
    let from = 1_780_272_000;
    let r = CareReport::empty(
        HostingId("t".into()),
        "example.cz".into(),
        from,
        from + 86_400,
    );
    // A letter that mentions no section at all, so all six are omitted.
    let (_, body) = care_report_render_with(&cs, &r, "example.cz", "Dobrý den. {domain}");
    assert!(body.starts_with("Dobrý den. example.cz"), "{body}");
    assert!(body.contains("V TOMTO OBDOBÍ NEMĚŘENO"), "{body}");
    assert!(body.contains("dostupnost"), "{body}");
    assert!(!body.contains("NOT MEASURED"), "{body}");
}

/// Czech numbers and dates, which are as much a translation as the
/// words: "34,500" reads as thirty-four and a half to a Czech customer.
#[test]
fn czech_numbers_and_dates() {
    let cs = LetterCatalog::new(LetterLang::Cs);
    let from = 1_780_272_000; // 2026-06-01
    let r = CareReport {
        attacks_blocked: Some(12_345),
        ..CareReport::empty(
            HostingId("t".into()),
            "example.cz".into(),
            from,
            from + 86_400,
        )
    };
    let (_, body) =
        care_report_render_with(&cs, &r, "example.cz", "{attacks_count} {period_start}");
    assert!(body.starts_with("12 345 1. čvn 2026"), "{body}");
}

#[tokio::test]
async fn a_care_report_records_which_letter_it_was_rendered_from() {
    let tmp = tempfile::tempdir().expect("tmp");
    let toml = tmp.path().join("agent.toml");
    std::fs::write(
        &toml,
        b"[notifications]\ncare_report_body_template = \"Dobry den, {domain}. {uptime}\"\n",
    )
    .expect("write agent.toml");

    // The node that has the operator's letter (today: the master).
    let pool = open_memory().await.expect("open");
    let edited = svc(pool.clone(), happy_mocks()).with_agent_config_path(toml);
    edited.create(req("pece.cz")).await.expect("create");
    let detail = edited
        .get(HostingSelector::Domain(
            Domain::parse("pece.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let mail = edited
        .care_report_preview(HostingSelector::Id(detail.id.clone()))
        .await
        .expect("preview");
    assert!(
        mail.body.starts_with("Dobry den, pece.cz."),
        "the operator's letter is what this node renders: {:?}",
        mail.body
    );
    let audit = edited.audit_list(200).await.expect("audit");
    let row = audit
        .iter()
        .find(|a| a.action == "package.report.preview")
        .expect("preview is audited");
    assert!(
        row.payload_json.contains("\"letter\":\"operator"),
        "the trail must name the letter that was rendered: {}",
        row.payload_json
    );

    // A node that never received it — no agent.toml wired at all, the
    // same state as a worker the save could not reach. Same site, same
    // code, different letter, and the trail says so instead of leaving
    // "which one did the customer get" to guesswork.
    let pool2 = open_memory().await.expect("open");
    let untouched = svc(pool2, happy_mocks());
    untouched.create(req("pece.cz")).await.expect("create");
    let d2 = untouched
        .get(HostingSelector::Domain(
            Domain::parse("pece.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let plain = untouched
        .care_report_preview(HostingSelector::Id(d2.id.clone()))
        .await
        .expect("preview");
    assert_ne!(
        plain.body, mail.body,
        "this is the divergence the trail has to explain"
    );
    let audit2 = untouched.audit_list(200).await.expect("audit");
    let row2 = audit2
        .iter()
        .find(|a| a.action == "package.report.preview")
        .expect("preview is audited");
    assert!(
        row2.payload_json.contains("\"letter\":\"built-in\""),
        "a node without the operator's letter must say so: {}",
        row2.payload_json
    );
}

/// The scheduled report: a refused send must leave the period OPEN.
///
/// The marker is both "already reported" and the START of the next
/// period, so advancing it on a failure does not merely skip one letter —
/// it deletes those days: the customer never hears about that month and
/// the next report begins after it.
#[tokio::test]
async fn care_report_tick_leaves_the_period_open_when_the_relay_refuses() {
    let pool = open_memory().await.expect("open");
    let (s, detail) = site_owing_a_care_report(&pool).await;

    let sent = s.care_report_tick().await.expect("tick");
    assert_eq!(sent, 0, "the relay refused it — nothing went out");
    assert_eq!(
        hyperion_state::hosting_kv::get(&pool, detail.id.as_str(), CARE_REPORT_KV_PERIOD_END)
            .await
            .expect("kv"),
        None,
        "the period must stay open — those 40 days are otherwise lost"
    );
    // And the attempt is where the operator looks for it: the site's
    // Emails tab, reading 'failed'. This also proves the tick got as far
    // as trying, rather than skipping on one of the earlier guards.
    let log = s
        .email_log_list(Some(detail.id.as_str().to_string()), 10)
        .await
        .expect("email log");
    assert!(
        log.iter()
            .any(|e| e.kind == CARE_REPORT_EMAIL_KIND && e.state == "failed"),
        "{log:?}"
    );
}

/// The operator's "Send now": a refused send is an error naming where the
/// relay's own message is, never a marked period.
#[tokio::test]
async fn care_report_send_errors_on_a_refused_relay_and_marks_nothing() {
    let pool = open_memory().await.expect("open");
    let (s, detail) = site_owing_a_care_report(&pool).await;

    let err = s
        .care_report_send(HostingSelector::Id(detail.id.clone()))
        .await
        .expect_err("a refused send must not read as success");
    // The wording will change; that it points at the Emails tab, where
    // `notify_email` put the relay's own words, must not.
    assert!(err.to_string().contains("Emails tab"), "got: {err}");
    assert_eq!(
        hyperion_state::hosting_kv::get(&pool, detail.id.as_str(), CARE_REPORT_KV_PERIOD_END)
            .await
            .expect("kv"),
        None,
        "the period stays open until a report actually goes out"
    );
    let audit = s.audit_list(200).await.expect("audit");
    assert!(
        !audit.iter().any(|a| a.action == "package.report.send"),
        "nothing was sent, so nothing may be audited as sent: {audit:?}"
    );
}

/// A custom-range preview covers exactly the operator's range, clamped
/// to now, and leaves the schedule's marker where it was.
#[tokio::test]
async fn care_report_range_preview_uses_the_given_range_and_marks_nothing() {
    let pool = open_memory().await.expect("open");
    let (s, detail) = site_owing_a_care_report(&pool).await;
    let now = now_secs();
    let from = now - 365 * 86_400;
    // An end in the future: "to: today" posts tomorrow's midnight.
    let mail = s
        .care_report_preview_range(HostingSelector::Id(detail.id.clone()), from, now + 86_400)
        .await
        .expect("preview");
    assert_eq!(mail.period_start, from);
    assert!(
        mail.period_end <= now_secs() && mail.period_end >= now,
        "the end is clamped to now: {}",
        mail.period_end
    );
    assert_eq!(mail.to, "zakaznik@pece.cz");
    assert_eq!(
        hyperion_state::hosting_kv::get(&pool, detail.id.as_str(), CARE_REPORT_KV_PERIOD_END)
            .await
            .expect("kv"),
        None
    );
}

#[tokio::test]
async fn care_report_range_refuses_an_empty_or_reversed_range() {
    let pool = open_memory().await.expect("open");
    let (s, detail) = site_owing_a_care_report(&pool).await;
    let now = now_secs();
    for (from, to) in [
        (now - 86_400, now - 2 * 86_400), // reversed
        (now - 86_400, now - 86_400),     // empty
        (now + 86_400, now + 2 * 86_400), // wholly in the future
    ] {
        let err = s
            .care_report_preview_range(HostingSelector::Id(detail.id.clone()), from, to)
            .await
            .expect_err("not a real window");
        assert!(
            matches!(err, RpcError::Validation { .. }),
            "{from}..{to}: {err}"
        );
    }
}

/// A subject written into the catalogue renders exactly as the same text
/// did as an old `[notifications]` subject template.
///
/// Settings moves those templates into `care.subject` /
/// `expiry.subject.days`. The catalogue subjects used to get only a few
/// tokens ({domain}, the period / {days} {unit}), so a moved subject
/// naming `{expires_at}` or `{when}` — both documented for the old
/// template — would have reached the customer as literal braces.
#[test]
fn a_catalogue_subject_takes_every_placeholder_the_old_template_did() {
    let mut cat = en();
    let exp = "{domain} | {expires_at} | {when} | {days_left} | {delete_at_iso} | {days} {unit}";
    cat.overrides
        .insert("expiry.subject.days".into(), exp.into());
    let now = EXP_TS - 7 * 86_400;
    let (from_catalogue, _) = expiry_warning_mail_with(&cat, "example.cz", EXP_TS, 14, now, "", "");
    let (from_template, _) =
        expiry_warning_mail_with(&en(), "example.cz", EXP_TS, 14, now, "", exp);
    assert_eq!(from_catalogue, from_template);
    assert!(!from_catalogue.contains('{'), "{from_catalogue}");

    let from = 1_780_272_000;
    let r = CareReport::empty(
        HostingId("t".into()),
        "example.cz".into(),
        from,
        from + 30 * 86_400,
    );
    let care = "{domain} {period_end_iso} {attacks_count} {days}";
    let mut cat = en();
    cat.overrides.insert("care.subject".into(), care.into());
    let (from_catalogue, _) = care_report_render_full(&cat, &r, "example.cz", "", "");
    let (from_template, _) = care_report_render_full(&en(), &r, "example.cz", "", care);
    assert_eq!(from_catalogue, from_template);
    assert!(!from_catalogue.contains('{'), "{from_catalogue}");
    // The built-in subjects are unchanged by the wider set.
    let (s, _) = care_report_render_full(&en(), &r, "example.cz", "", "");
    assert_eq!(s, "Care report for example.cz (1 Jun 2026 – 30 Jun 2026)");
}

#[test]
fn care_letter_empty_template_is_todays_letter() {
    let r = mk_care_report();
    let (subject, body) = care_report_render(&en(), &r, "example.cz");
    // Explicit "" and whitespace-only both mean "built-in letter".
    assert_eq!(
        care_report_render_with(&en(), &r, "example.cz", ""),
        (subject.clone(), body.clone())
    );
    assert_eq!(
        care_report_render_with(&en(), &r, "example.cz", "  \n\t ").1,
        body
    );
    // …and today's letter is still exactly this.
    assert_eq!(
        subject,
        "Care report for example.cz (1 Jun 2026 – 30 Jun 2026)"
    );
    assert!(body.starts_with(
        "CARE REPORT\nSite:    example.cz\nPeriod:  1 Jun 2026 – 30 Jun 2026 (30 days)\n\n"
    ));
    assert!(body.ends_with(
        "--\nYou receive this report because example.cz is on a care plan.\n\
             The figures come straight from the server the site runs on; times are UTC.\n\
             If anything here needs explaining, just reply to this e-mail.\n"
    ));
    assert!(body.contains("ATTACKS BLOCKED: 12"));
    assert!(body.contains("AVAILABILITY: not monitored"));
}

#[test]
fn care_letter_default_template_reproduces_the_builtin_letter() {
    // The constant the Settings editor offers as a starting point is
    // written by hand in hyperion-types; if either it or the built-in
    // format! drifts, the operator's "default" would silently differ
    // from what their customers have been receiving.
    for r in [mk_care_report(), {
        // Every section unmeasured — the other branch of all six.
        CareReport::empty(
            HostingId("h2".into()),
            "quiet.cz".into(),
            CARE_FROM,
            CARE_TO,
        )
    }] {
        let (_, builtin) = care_report_render(&en(), &r, &r.domain);
        let (_, templated) = care_report_render_with(
            &en(),
            &r,
            &r.domain,
            hyperion_types::CARE_REPORT_DEFAULT_BODY_TEMPLATE,
        );
        assert_eq!(builtin, templated);
    }
}

/// Protection switched on partway through bounds the claim. Without
/// this the letter said "0 — protection ran for the whole period"
/// about days nobody was watching.
#[test]
fn attacks_started_mid_period_says_so_instead_of_claiming_the_period() {
    // 15 Jun, inside the 1–30 Jun fixture period.
    let since = CARE_FROM + 14 * 86_400;

    let quiet = care_section_attacks(&en(), Some(0), Some(since));
    assert!(quiet.contains("since 15 Jun 2026"), "{quiet}");
    assert!(
        !quiet.contains("Protection ran for the whole period"),
        "a zero from half a period must not claim the period: {quiet}"
    );

    let busy = care_section_attacks(&en(), Some(4), Some(since));
    assert!(
        busy.contains("ATTACKS BLOCKED: 4 (since 15 Jun 2026)"),
        "{busy}"
    );

    // Full coverage keeps the original, unqualified wording.
    let full = care_section_attacks(&en(), Some(0), None);
    assert!(
        full.contains("Protection ran for the whole period"),
        "{full}"
    );
}

/// The Settings preview is built from the same section renderers as a
/// real letter, so an operator tunes wording against text customers
/// actually receive. This pins that it is wired up — the previous
/// version was hand-copied prose in the page's JavaScript, and it had
/// already drifted.
#[test]
fn the_settings_preview_sample_comes_from_the_real_renderer() {
    let fields = care_report_preview_fields(&en());
    let get = |k: &str| {
        fields
            .iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    // Availability is deliberately the unmeasured one.
    assert_eq!(get("uptime"), care_section_uptime(&en(), None));
    assert!(get("uptime").contains("AVAILABILITY: not monitored"));
    // And the measured sections are byte-identical to the letter's.
    assert_eq!(get("attacks"), care_section_attacks(&en(), Some(12), None));
    assert_eq!(get("updates"), care_section_updates(&en(), Some(3)));
    // Every placeholder the docs promise has a sample.
    for k in [
        "domain",
        "period_start",
        "period_end",
        "days",
        "attacks",
        "updates",
        "traffic",
        "uptime",
        "backups",
        "integrity",
    ] {
        assert!(!get(k).is_empty(), "missing preview sample for {{{k}}}");
    }
}

#[test]
fn care_letter_custom_template_keeps_an_unmeasured_section_honest() {
    let r = mk_care_report(); // uptime is None
    let (subject, body) = care_report_render_with(
        &en(),
        &r,
        "example.cz",
        "{domain} {period_start}–{period_end} ({days})\n{uptime}\n{attacks}",
    );
    // The subject is ours; only the body is operator-editable.
    assert_eq!(
        subject,
        "Care report for example.cz (1 Jun 2026 – 30 Jun 2026)"
    );
    assert!(body.starts_with("example.cz 1 Jun 2026–30 Jun 2026 (30 days)\n"));
    assert!(body.contains("ATTACKS BLOCKED: 12"));
    // The rearranged letter still says nobody was watching, in full.
    assert!(body.contains(
        "AVAILABILITY: not monitored (uptime checks were not active)\n  \
             We were not checking this site regularly during the period, so we\n  \
             cannot say whether it stayed reachable. A figure of 100 % would be\n  \
             invented."
    ));
}

#[test]
fn care_letter_unknown_placeholder_is_left_literal() {
    let r = mk_care_report();
    let (_, body) = care_report_render_with(&en(), &r, "example.cz", "{domain} {nope} {unclosed");
    // `starts_with`, not `==`: this letter names no section at all, so
    // the unmeasured-section disclosure is appended after it. That is
    // `a_custom_letter_cannot_drop_an_unmeasured_section`'s business;
    // what matters here is that the bad tokens survive verbatim.
    assert!(body.starts_with("example.cz {nope} {unclosed"), "{body}");
}

/// `{uptime_pct}` now exists — a translated letter needs the bare number,
/// because the section placeholder that used to be the only option
/// carries an English paragraph with it.
///
/// What it must NOT do is what this design originally withheld it to
/// prevent: let a template print a confident "100 %" for a site nobody
/// was checking. Zero samples yields a dash, so the number can only ever
/// appear when it was really measured.
#[test]
fn uptime_pct_cannot_invent_a_figure_for_an_unmonitored_site() {
    let r = mk_care_report();
    assert!(
        r.uptime.as_ref().map(|u| u.samples).unwrap_or(0) == 0,
        "this fixture is the unmonitored one"
    );
    let (_, body) = care_report_render_with(&en(), &r, "example.cz", "{uptime_pct}");
    assert!(
        body.starts_with('—'),
        "an unmonitored site must not yield a percentage: {body}"
    );
    assert!(!body.contains("100"), "{body}");
}

/// The bug this whole split exists for: a translated letter must not have
/// English put back into it. `{attacks}` and friends expand to a whole
/// SECTION — heading, figure, and an English paragraph — so a Czech
/// template using them came out as an English block followed by the Czech
/// sentence meant to replace it. The `_count` forms carry the measurement
/// and nothing else.
#[test]
fn value_placeholders_carry_no_english() {
    let fields: std::collections::BTreeMap<&str, String> =
        care_report_preview_fields(&en()).into_iter().collect();
    // Digits only. A word here is English leaking into somebody's letter.
    for key in [
        "attacks_count",
        "updates_count",
        "traffic_requests",
        "uptime_pct",
        "backups_count",
        "backups_failed",
        "days_count",
        "period_start_iso",
        "period_end_iso",
    ] {
        let v = fields.get(key).unwrap_or_else(|| panic!("missing {key}"));
        assert!(
            !v.chars().any(|c| c.is_ascii_alphabetic()),
            "{key} = {v:?} contains a word — a value placeholder must be a \
                 measurement, so a template in any language can put its own \
                 wording around it"
        );
    }
    // Byte sizes carry a UNIT, and a unit is not a language: "34.5 MB"
    // reads the same in Czech. What they must not carry is prose, so the
    // rule is "a number and a unit symbol", not "no letters at all".
    //
    // SI steps, not binary ones: these are the same figures the
    // `{traffic}` section quotes, and one measurement printed in MiB in
    // one placeholder and MB in the paragraph beside it is two different
    // numbers for one fact in one letter.
    for key in ["traffic_sent", "traffic_received", "disk_peak"] {
        let v = fields.get(key).unwrap_or_else(|| panic!("missing {key}"));
        let words: Vec<&str> = v.split_whitespace().collect();
        assert!(
            words.len() <= 2,
            "{key} = {v:?} is prose, not a measurement"
        );
        if let Some(unit) = words.get(1) {
            assert!(
                matches!(*unit, "B" | "kB" | "MB" | "GB"),
                "{key} = {v:?} — {unit:?} is not a byte unit"
            );
        }
    }
}

#[test]
fn a_warn_only_page_check_is_not_reported_as_everything_rendered() {
    let cat = en();
    // Every page answered, but a link 404s (a warn). Must NOT claim
    // "every one loaded, with its links and images resolving".
    let mut perf = hyperion_types::CarePerformance {
        checked_at: 1,
        pages_checked: 8,
        pages_ok: 8,
        findings_error: 0,
        findings_warn: 1,
        median_ttfb_ms: 200,
        slowest_ttfb_ms: 400,
        html_bytes: 1000,
        cwv: None,
    };
    let out = care_section_performance(&cat, Some(&perf));
    assert!(!out.contains("every one loaded"), "{out}");
    assert!(out.contains("problem"), "{out}");
    assert!(
        out.contains("Server response"),
        "a page answered, so speed is quoted: {out}"
    );

    // Nothing answered: no "0 ms typical" fabricated speed line.
    perf.pages_ok = 0;
    perf.findings_error = 8;
    let out = care_section_performance(&cat, Some(&perf));
    assert!(
        !out.contains("Server response"),
        "no page answered, no speed line: {out}"
    );

    // Genuinely clean: the OK line.
    let clean = hyperion_types::CarePerformance {
        findings_warn: 0,
        findings_error: 0,
        pages_ok: 8,
        pages_checked: 8,
        ..perf.clone()
    };
    assert!(care_section_performance(&cat, Some(&clean)).contains("every one loaded"));
}

/// A broken page is counted ONCE. site_check pushes exactly one finding per
/// non-OK page, so a broken page is already in findings_error/findings_warn;
/// adding `(pages_checked - pages_ok)` on top counted it twice and could
/// print more "problems" than pages fetched.
#[test]
fn a_broken_page_is_counted_once_not_twice() {
    let cat = en();
    // One page, and it errors: one finding, one problem — not two.
    let one = hyperion_types::CarePerformance {
        checked_at: 1,
        pages_checked: 1,
        pages_ok: 0,
        findings_error: 1,
        findings_warn: 0,
        median_ttfb_ms: 0,
        slowest_ttfb_ms: 0,
        html_bytes: 0,
        cwv: None,
    };
    let out = care_section_performance(&cat, Some(&one));
    assert!(
        out.contains("1 problem"),
        "one dead page is one problem: {out}"
    );
    assert!(
        !out.contains("2 problem"),
        "the page must not be counted twice: {out}"
    );

    // 8 fetched, 2 pages broken (2 page findings) plus 3 broken links
    // (3 findings): five distinct problems, not seven.
    let mixed = hyperion_types::CarePerformance {
        pages_checked: 8,
        pages_ok: 6,
        findings_error: 2,
        findings_warn: 3,
        ..one.clone()
    };
    let out = care_section_performance(&cat, Some(&mixed));
    assert!(
        out.contains("5 problem"),
        "2 broken pages + 3 broken links = 5 problems: {out}"
    );
    assert!(
        !out.contains("7 problem"),
        "the 2 broken pages must not be added a second time: {out}"
    );
}

/// An operator's own item has no translation anywhere, so the letter has
/// to carry the label. Printing the lookup key at a paying customer is
/// the failure this guards.
#[test]
fn a_custom_check_is_named_in_the_letter_not_keyed() {
    use std::collections::BTreeMap;
    let cat = crate::letters::LetterCatalog::new(crate::letters::LetterLang::Cs);
    let mut labels = BTreeMap::new();
    labels.insert("gdpr-review".to_string(), "GDPR revize".to_string());
    let work = hyperion_types::package::CareServiceWork {
        done: vec!["render".into(), "gdpr-review".into()],
        missing: vec!["forms".into()],
        labels,
    };
    let out = care_section_service(&cat, Some(&work));
    assert!(out.contains("GDPR revize"), "{out}");
    assert!(
        !out.contains("care.service.item"),
        "a catalogue key reached a customer letter: {out}"
    );
    // The built-ins still come from the pack, so a Czech letter names them
    // in Czech — an operator's edit of a plan must not override that.
    assert!(!out.contains("Pages and navigation"), "{out}");

    // An id with no label at all falls back to the id, never to the key.
    let bare = hyperion_types::package::CareServiceWork {
        done: vec!["stock-feed".into()],
        missing: Vec::new(),
        labels: BTreeMap::new(),
    };
    let out = care_section_service(&cat, Some(&bare));
    assert!(out.contains("stock-feed"), "{out}");
    assert!(!out.contains("care.service.item"), "{out}");
}

/// A plan that leaves sections out of the letter: they are gone — as
/// sections, as bare values, and from the "we could not measure" note —
/// and the blank lines they leave behind are tidied. Everything else is
/// byte-for-byte what the full letter says.
#[test]
fn a_plan_that_leaves_sections_out_sends_a_shorter_honest_letter() {
    let r = mk_care_report(); // uptime is UNMEASURED here, on purpose
    let (_, full) = care_report_render_with_omitting(&en(), &r, "example.cz", "", ReportOmit::NONE);
    let (_, short) = care_report_render_with_omitting(
        &en(),
        &r,
        "example.cz",
        "",
        omit_of("attacks,uptime,traffic"),
    );

    // Unchanged when nothing is left out — the default path is untouched.
    assert_eq!(
        full,
        care_report_render_with(&en(), &r, "example.cz", "").1,
        "no omit = today's letter, byte for byte"
    );
    // The three sections are not mentioned at all…
    let attacks = care_section_attacks(&en(), r.attacks_blocked, r.attacks_covered_since);
    let traffic = care_section_usage(&en(), r.usage.as_ref());
    assert!(full.contains(&attacks) && full.contains(&traffic));
    assert!(!short.contains(&attacks), "{short}");
    assert!(!short.contains(&traffic), "{short}");
    // …the sections it does send are exactly as before…
    for kept in [
        care_section_updates(&en(), r.updates_applied),
        care_section_backups(&en(), r.backups.as_ref()),
        care_section_integrity(&en(), r.integrity.as_ref()),
    ] {
        assert!(short.contains(&kept), "{kept}\n---\n{short}");
    }
    // …and the unmeasured UPTIME section the plan does not sell is not
    // disclosed as "not measured": the customer never bought it.
    let uptime_unmeasured = care_section_uptime(&en(), None);
    assert!(full.contains(&uptime_unmeasured));
    assert!(!short.contains(&uptime_unmeasured), "{short}");
    assert!(
        !short.to_uppercase().contains("AVAILABILITY"),
        "an omitted section must never be reported as unmeasured: {short}"
    );
    // (PERFORMANCE is sent by this plan and unmeasured in the fixture, so
    // the letter rightly still says "not measured" for THAT section.)
    // No run of blank lines where a section used to be.
    assert!(!short.contains("\n\n\n"), "{short:?}");
}

/// The disclosure rule is untouched for sections the plan DOES send: an
/// operator who deletes `{uptime}` from a custom letter still gets the
/// "not measured" note appended — unless the plan itself leaves uptime out.
#[test]
fn the_unmeasured_note_still_covers_what_the_plan_sends() {
    let r = mk_care_report();
    let tpl = "{domain}\n{attacks}";
    let (_, sent) =
        care_report_render_with_omitting(&en(), &r, "example.cz", tpl, ReportOmit::NONE);
    assert!(
            sent.contains("uptime") || sent.to_lowercase().contains("availability"),
            "uptime is sent by the plan but absent from the letter and unmeasured, so it is disclosed: {sent}"
        );
    let (_, left_out) =
        care_report_render_with_omitting(&en(), &r, "example.cz", tpl, omit_of("uptime"));
    assert!(
        !left_out.to_lowercase().contains("availability"),
        "uptime is left out by the plan, so there is nothing to disclose: {left_out}"
    );
}

/// A custom sentence around a bare value must not reintroduce a figure the
/// plan left out.
#[test]
fn bare_values_of_a_left_out_section_become_a_dash() {
    let r = mk_care_report();
    let tpl = "{attacks_count}|{updates_count}|{traffic_sent}|{backups_count}|{attacks}";
    let (_, body) =
        care_report_render_with_omitting(&en(), &r, "example.cz", tpl, omit_of("attacks,traffic"));
    let first_line = body.lines().next().expect("line");
    assert!(first_line.starts_with("—|3|—|30|"), "{first_line}");
}

/// CRLF templates keep their line endings when sections are left out.
#[test]
fn collapsing_blank_lines_keeps_crlf() {
    assert_eq!(
        collapse_blank_runs("a\r\n\r\n\r\n\r\nb\r\n"),
        "a\r\n\r\nb\r\n"
    );
    assert_eq!(collapse_blank_runs("a\n\nb\n"), "a\n\nb\n");
    assert_eq!(collapse_blank_runs("a\n \n\t\nb"), "a\n \nb");
}
