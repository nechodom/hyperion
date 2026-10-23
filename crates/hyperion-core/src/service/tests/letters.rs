//! Tests for `service::letters`.

use super::*;

/// The customer letters are read from the agent.toml of the node that
/// OWNS the hosting, so the same panel legitimately sends two different
/// letters — the operator's on the master, the built-in one on a worker
/// that has not received it yet. That is the divergence; what must never
/// happen is it being untraceable. Every render records which body it
/// used, and this pins both halves of that.
/// THE ACTUAL REPRODUCTION of the operator's report.
///
/// They edited "the whole report template with placeholders" — which is
/// `care.body`, a sentence in the Customer-letters editor, not the
/// `[notifications]` body template the test below covers. The cluster
/// letter language was left at its default (English); the site follows its
/// care package, which is set to Czech. The preview never changed.
#[tokio::test]
async fn an_edited_letter_reaches_a_site_whose_package_is_in_another_language() {
    let tmp = tempfile::tempdir().expect("tmp");
    let toml = tmp.path().join("agent.toml");
    // Default cluster language (no `lang` key = English), one override:
    // the whole letter, rewritten by the operator.
    std::fs::write(
        &toml,
        "[letters]\n\"care.body\" = \"VLASTNI DOPIS pro {domain}\"\n".as_bytes(),
    )
    .expect("write agent.toml");
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks()).with_agent_config_path(toml);
    let detail = hosting_for_packages(&s, "cesky.cz").await;
    // The site follows its care package, which writes in Czech.
    hyperion_state::packages::activate(
        &pool,
        &hyperion_state::packages::NewActivation {
            report_omit: String::new(),
            valid_from: None,
            enforcement_started: true,
            hosting_id: detail.id.clone(),
            package_id: 1,
            package_name: "Péče".into(),
            letters_lang: "cs".into(),
            check_items: String::new(),
            price_minor: None,
            price_currency: None,
            price_interval: None,
            features: PackageFeatures::default(),
            next_billing_at: None,
            prior_state_json: None,
        },
        0,
    )
    .await
    .expect("activate");

    let cat = s.letter_catalog_for(&detail.id).await;
    assert_eq!(cat.lang, LetterLang::Cs, "the site writes in Czech");
    assert!(
        cat.get("care.body").contains("VLASTNI DOPIS"),
        "the operator's rewritten letter must reach this site, got: {:?}",
        cat.get("care.body")
    );
}

/// The protection still holds where it rests on a FACT: an operator who
/// has declared their wording is English must not see it appear in a
/// Czech letter. Undeclared applies; declared-and-different withholds.
#[test]
fn declared_foreign_wording_is_withheld_but_undeclared_wording_is_not() {
    let parse = |toml: &str| letter_catalog_from_toml(toml);

    // Undeclared: nothing is thrown away, whatever the letter's language.
    let mut undeclared = parse("[letters]\n\"care.body\" = \"X\"\n");
    undeclared.lang = LetterLang::Cs;
    drop_foreign_overrides(&mut undeclared, LetterLang::En);
    assert_eq!(undeclared.get("care.body"), "X", "undeclared must apply");

    // Declared English, rendered in Czech: withheld.
    let mut foreign = parse("[letters]\noverrides_lang = \"en\"\n\"care.body\" = \"X\"\n");
    foreign.lang = LetterLang::Cs;
    drop_foreign_overrides(&mut foreign, LetterLang::En);
    assert_ne!(
        foreign.get("care.body"),
        "X",
        "declared-and-different withholds"
    );

    // Declared Czech, rendered in Czech: applied.
    let mut same = parse("[letters]\noverrides_lang = \"cs\"\n\"care.body\" = \"X\"\n");
    same.lang = LetterLang::Cs;
    drop_foreign_overrides(&mut same, LetterLang::En);
    assert_eq!(same.get("care.body"), "X");

    // The declaration is not itself mistaken for a sentence override.
    assert!(!parse("[letters]\noverrides_lang = \"cs\"\n")
        .overrides
        .contains_key("overrides_lang"));
}

/// operator_lang / billing_lang parse independently of the customer lang,
/// carry the right defaults, and don't leak into the sentence overrides.
#[test]
fn operator_and_billing_language_parse_and_default() {
    let parse = |toml: &str| letter_catalog_from_toml(toml);

    // Defaults: customer Czech, operator English, billing follows customer.
    let d = parse("[letters]\nlang = \"cs\"\n");
    assert_eq!(d.lang, LetterLang::Cs);
    assert_eq!(
        d.operator_lang,
        LetterLang::En,
        "operator defaults to English"
    );
    assert_eq!(d.billing_lang, None, "billing follows the customer lang");

    // in_language gives the operator view: English, customer overrides gone.
    let op = d.in_language(d.operator_lang);
    assert_eq!(op.lang, LetterLang::En);

    // Explicit values are honoured and kept out of the overrides map.
    let e = parse("[letters]\nlang = \"cs\"\noperator_lang = \"en\"\nbilling_lang = \"cs\"\n");
    assert_eq!(e.operator_lang, LetterLang::En);
    assert_eq!(e.billing_lang, Some(LetterLang::Cs));
    assert!(!e.overrides.contains_key("operator_lang"));
    assert!(!e.overrides.contains_key("billing_lang"));
}

/// `letter_origin` has to agree with the renderers about what counts as
/// "no template", or the trail names a letter that was not sent.
#[test]
fn a_blank_template_is_reported_as_the_built_in_letter() {
    use super::{care_report_render_with, letter_origin};
    let r = mk_care_report();
    for blank in ["", "   ", "\n\t "] {
        assert_eq!(letter_origin(blank), "built-in", "{blank:?}");
        // Same input, same verdict from the renderer: blank ⇒ built-in.
        assert_eq!(
            care_report_render_with(&en(), &r, &r.domain, blank).1,
            care_report_render_with(&en(), &r, &r.domain, "").1,
            "{blank:?}"
        );
    }
    assert!(letter_origin("Dobry den, {domain}").starts_with("operator"));
    // Wording rewritten in the catalogue — the way Settings edits the
    // letters now — is the operator's too, with an empty template.
    let mut cat = crate::letters::LetterCatalog::default();
    assert_eq!(
        super::letter_origin_with("", &cat, super::CARE_FRAME_IDS),
        "built-in"
    );
    cat.overrides
        .insert("care.body".into(), "Dobry den, {domain}".into());
    assert!(super::letter_origin_with("", &cat, super::CARE_FRAME_IDS).starts_with("operator"));
    assert_eq!(
        super::letter_origin_with("", &cat, super::EXPIRY_FRAME_IDS),
        "built-in",
        "a care-report sentence says nothing about the expiry warning"
    );
    assert!(super::is_single_plain_address("ops@example.cz"));
    for bad in [
        "ops@example.cz\r\nBcc: x@evil.test",
        "a@b.cz, c@d.cz",
        "a@b.cz;c@d.cz",
        "Ops <ops@example.cz>",
        "no-at-sign",
        "@example.cz",
        "a@localhost",
    ] {
        assert!(!super::is_single_plain_address(bad), "{bad:?}");
    }
    cat.overrides.insert("care.body".into(), "   ".into());
    assert_eq!(
        super::letter_origin_with("", &cat, super::CARE_FRAME_IDS),
        "built-in"
    );
}

#[test]
fn expiry_warning_30d_states_domain_date_days_and_consequences() {
    let (subject, body) = expiry_warning_mail_with(
        &en(),
        "example.cz",
        EXP_TS,
        14,
        EXP_TS - 30 * 86_400,
        "",
        "",
    );
    assert_eq!(
        subject,
        "[Hyperion] Hosting for example.cz expires in 30 days"
    );
    assert!(body.contains("hosting for example.cz expires on 1 Sep 2026 — 30 days left."));
    assert!(body.contains("on 1 Sep 2026 the hosting will be suspended"));
    // Delete date = expiry + grace, the date DeleteExpired is queued for.
    assert!(body.contains("after a grace period of 14 days, on 15 Sep 2026"));
}

#[test]
fn expiry_warning_7d_variant() {
    let (subject, body) =
        expiry_warning_mail_with(&en(), "example.cz", EXP_TS, 14, EXP_TS - 7 * 86_400, "", "");
    assert_eq!(
        subject,
        "[Hyperion] Hosting for example.cz expires in 7 days"
    );
    assert!(body.contains("7 days left."));
}

#[test]
fn expiry_warning_1d_variant_is_singular() {
    let (subject, body) =
        expiry_warning_mail_with(&en(), "example.cz", EXP_TS, 14, EXP_TS - 86_400, "", "");
    assert_eq!(
        subject,
        "[Hyperion] Hosting for example.cz expires in 1 day"
    );
    assert!(body.contains("1 day left."));
}

#[test]
fn expiry_warning_on_the_day_says_today() {
    let (subject, body) = expiry_warning_mail_with(&en(), "example.cz", EXP_TS, 14, EXP_TS, "", "");
    assert_eq!(subject, "[Hyperion] Hosting for example.cz expires today");
    assert!(body.contains("hosting for example.cz expires today."));
    // A late tick can't produce a negative countdown.
    let (late, _) =
        expiry_warning_mail_with(&en(), "example.cz", EXP_TS, 14, EXP_TS + 3 * 86_400, "", "");
    assert_eq!(late, "[Hyperion] Hosting for example.cz expires today");
}

#[test]
fn expiry_warning_grace_matches_the_scheduled_delete() {
    // grace_days = 0 is stored, but reconcile_scheduled_rows queues the
    // delete at grace.max(1) — the letter must name that same date, and
    // say "1 day" rather than "1 days".
    let (_, body) =
        expiry_warning_mail_with(&en(), "example.cz", EXP_TS, 0, EXP_TS - 86_400, "", "");
    assert!(body.contains("after a grace period of 1 day, on 2 Sep 2026"));
    let (_, body) =
        expiry_warning_mail_with(&en(), "example.cz", EXP_TS, 3, EXP_TS - 2 * 86_400, "", "");
    assert!(body.contains("2 days left."));
    assert!(body.contains("after a grace period of 3 days, on 4 Sep 2026"));
}

/// The expiry preview sample is the letter's own wording, in the letter's
/// language — a Czech letter previewed with "7 days" in it reads as broken.
#[test]
fn the_expiry_preview_sample_comes_from_the_real_renderer() {
    let get = |cat: &LetterCatalog, left: i64, k: &str| {
        expiry_warning_preview_fields(cat, left)
            .into_iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v)
            .unwrap_or_default()
    };
    assert_eq!(get(&en(), 7, "days_left"), "7 days");
    assert_eq!(get(&en(), 7, "expires_at"), "1 Sep 2026");
    assert_eq!(get(&en(), 7, "delete_at_iso"), "2026-09-15");
    assert_eq!(get(&en(), 0, "when"), "expires today");
    assert_eq!(get(&en(), 7, "unit"), "days");
    let cs = LetterCatalog::new(LetterLang::Cs);
    assert_eq!(get(&cs, 7, "days_left"), "7 dní");
    // The sample and the letter agree, token for token.
    let fields = expiry_warning_preview_fields(&en(), 7);
    let tmpl: String = fields.iter().map(|(k, _)| format!("{{{k}}}\n")).collect();
    let (_, body) = expiry_warning_mail_with(
        &en(),
        "example.com",
        EXP_TS,
        14,
        EXP_TS - 7 * 86_400,
        &tmpl,
        "",
    );
    let expected: String = fields
        .iter()
        .map(|(k, v)| {
            // {days} and {unit} are subject-only placeholders.
            if matches!(*k, "days" | "unit") {
                format!("{{{k}}}\n")
            } else {
                format!("{v}\n")
            }
        })
        .collect();
    assert_eq!(body, expected);
}

#[test]
fn expiry_letter_default_template_reproduces_the_builtin_letter() {
    for (grace, now) in [
        (14, EXP_TS - 30 * 86_400),
        (14, EXP_TS - 86_400),
        (0, EXP_TS - 86_400),
        (14, EXP_TS), // "expires today"
    ] {
        let (_, builtin) =
            expiry_warning_mail_with(&en(), "example.cz", EXP_TS, grace, now, "", "");
        let (_, templated) = expiry_warning_mail_with(
            &en(),
            "example.cz",
            EXP_TS,
            grace,
            now,
            hyperion_types::EXPIRY_WARNING_DEFAULT_BODY_TEMPLATE,
            "",
        );
        assert_eq!(builtin, templated, "grace={grace} now={now}");
    }
}

#[test]
fn expiry_letter_custom_template_substitutes_and_preserves_unknowns() {
    let (subject, body) = expiry_warning_mail_with(
        &en(),
        "example.cz",
        EXP_TS,
        14,
        EXP_TS - 7 * 86_400,
        "Renew {domain} before {expires_at} ({days_left} left).\n\
             Deleted on {delete_at}, after {grace_days}.\n{when}\n{mystery}",
        "",
    );
    assert_eq!(
        subject,
        "[Hyperion] Hosting for example.cz expires in 7 days"
    );
    assert_eq!(
        body,
        "Renew example.cz before 1 Sep 2026 (7 days left).\n\
             Deleted on 15 Sep 2026, after 14 days.\n\
             expires on 1 Sep 2026 — 7 days left\n{mystery}"
    );
}

/// A site reading a different language than the cluster gets the PACK,
/// whole — not the operator's Czech sentences dropped into an English
/// letter.
///
/// The overrides are one flat list with no language on them. Applying them
/// across a language boundary produces a letter that is Czech where the
/// operator touched it and English everywhere else, and the customer cannot
/// tell that is a bug — only that their hosting company writes badly.
#[tokio::test]
async fn overrides_do_not_cross_a_language_boundary() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "mixed.cz").await;

    // The operator has rewritten a sentence. Their cluster is English here,
    // so that wording is English wording.
    // Same language as the cluster: the override applies.
    let same = s.letter_catalog_for(&detail.id).await;
    assert_eq!(same.lang, LetterLang::En);

    // Now the site is set to Czech. The operator's English sentence must
    // NOT be spliced into the Czech letter.
    s.hosting_kv_set(
        detail.id.as_str().to_string(),
        HostingService::<MockAdapterPort>::LETTER_LANG_KV_KEY.to_string(),
        "cs".into(),
    )
    .await
    .expect("kv");
    let other = s.letter_catalog_for(&detail.id).await;
    assert_eq!(other.lang, LetterLang::Cs, "the site reads Czech");
    assert!(
        other.overrides.is_empty(),
        "an override authored under the English pack must not reach a Czech letter"
    );
}

/// The language resolves site → package → cluster, and each step is only
/// consulted when the one above it says nothing.
///
/// The order IS the feature: an operator who sets one site to Czech must not
/// have that undone by the package default, and a package default must not
/// be undone by the cluster setting.
#[tokio::test]
async fn the_site_language_beats_the_package_which_beats_the_cluster() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "lang-order.cz").await;

    // Nothing set anywhere: the cluster pack, which is English with no
    // agent.toml behind this service.
    assert_eq!(
        s.letter_catalog_for(&detail.id).await.lang,
        LetterLang::En,
        "with no opinion anywhere the cluster setting decides"
    );

    // A package default alone.
    hyperion_state::packages::activate(
        &pool,
        &hyperion_state::packages::NewActivation {
            report_omit: String::new(),
            valid_from: None,
            enforcement_started: true,
            hosting_id: detail.id.clone(),
            package_id: 1,
            package_name: "Péče".into(),
            check_items: String::new(),
            price_minor: None,
            price_currency: None,
            price_interval: None,
            features: PackageFeatures::default(),
            next_billing_at: None,
            prior_state_json: None,
            letters_lang: "cs".into(),
        },
        0,
    )
    .await
    .expect("activate");
    assert_eq!(
        s.letter_catalog_for(&detail.id).await.lang,
        LetterLang::Cs,
        "the package default must apply when the site says nothing"
    );

    // The site's own setting overrides the package.
    s.hosting_kv_set(
        detail.id.as_str().to_string(),
        HostingService::<MockAdapterPort>::LETTER_LANG_KV_KEY.to_string(),
        "en".into(),
    )
    .await
    .expect("kv set");
    assert_eq!(
        s.letter_catalog_for(&detail.id).await.lang,
        LetterLang::En,
        "the site's own setting must beat its package"
    );

    // An empty site setting is NOT an opinion — it falls through again.
    // Anything else would make "clear this" mean "force the cluster
    // default", which is a different act with no way to ask for it.
    s.hosting_kv_set(
        detail.id.as_str().to_string(),
        HostingService::<MockAdapterPort>::LETTER_LANG_KV_KEY.to_string(),
        String::new(),
    )
    .await
    .expect("kv clear");
    assert_eq!(
        s.letter_catalog_for(&detail.id).await.lang,
        LetterLang::Cs,
        "clearing the site setting falls back to the package, not the cluster"
    );
}
