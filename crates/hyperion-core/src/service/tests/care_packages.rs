//! Tests for `service::care_packages`.

use super::*;

#[test]
fn slugify_folds_czech_and_refuses_to_invent_a_handle() {
    assert_eq!(slugify("Péče Plus"), "pece-plus");
    assert_eq!(slugify("  Zálohy  &  Monitoring "), "zalohy-monitoring");
    assert_eq!(slugify("Údržba 2.0"), "udrzba-2-0");
    // Nothing foldable left ⇒ empty, which validate_package turns into
    // "set a slug yourself" rather than a UNIQUE-index collision.
    assert_eq!(slugify("日本語"), "");
}

#[test]
fn a_plans_checklist_is_normalised_and_bounded() {
    use hyperion_types::care_check::{
        builtin_check_items, check_items_to_json, parse_check_items, CheckItemDef,
    };
    let def = |id: &str, label: &str| CheckItemDef {
        id: id.into(),
        label: label.into(),
        detail: String::new(),
    };

    // Absent, unreadable and "exactly the built-ins" all collapse to "",
    // which is the one value the resolver reads as the built-in four.
    // Two spellings of the same promise is how a plan starts saying
    // different things on different pages.
    for raw in ["", "  ", "{oops", "null", "[]"] {
        assert_eq!(validate_check_items(raw).unwrap(), "", "{raw:?}");
    }
    assert_eq!(
        validate_check_items(&check_items_to_json(&builtin_check_items())).unwrap(),
        ""
    );

    // `post_update` must survive verbatim: `slugify` would rewrite it to
    // `post-update` and orphan every mark ever filed under it.
    let kept = validate_check_items(&check_items_to_json(&[
        def("post_update", "Still working after updates"),
        def("GDPR Review", "GDPR revize"),
    ]))
    .unwrap();
    let ids: Vec<String> = parse_check_items(&kept).into_iter().map(|i| i.id).collect();
    assert_eq!(ids, vec!["post_update", "gdpr-review"]);

    // Two items sharing an id would let one tick satisfy both.
    assert!(validate_check_items(&check_items_to_json(&[
        def("gdpr", "GDPR review"),
        def("GDPR", "GDPR audit"),
    ]))
    .is_err());

    // Bounds: this string is snapshotted onto every activation and frozen
    // into 24 months of every site's record.
    let many: Vec<CheckItemDef> = (0..MAX_CHECK_ITEMS + 1)
        .map(|n| def(&format!("i{n}"), &format!("Check {n}")))
        .collect();
    assert!(validate_check_items(&check_items_to_json(&many)).is_err());
    let long = "x".repeat(MAX_CHECK_LABEL + 1);
    assert!(validate_check_items(&check_items_to_json(&[def("x", &long)])).is_err());
}

#[test]
fn validate_package_derives_slug_and_bounds_pricing() {
    let p = validate_package(care_input("Péče Plus", PackageFeatures::default())).expect("valid");
    assert_eq!(p.slug, "pece-plus", "derived when the caller left it empty");
    assert!(p.enabled, "a new package is offerable");

    // An interval the billing sweep can't step would mean a package
    // that silently never reminds anyone.
    let bad = PackageInput {
        price_interval: Some("weekly".into()),
        ..care_input("X", PackageFeatures::default())
    };
    assert!(validate_package(bad).is_err());
    let negative = PackageInput {
        price_minor: Some(-1),
        ..care_input("X", PackageFeatures::default())
    };
    assert!(validate_package(negative).is_err());
    let nameless = PackageInput {
        name: "   ".into(),
        ..care_input("X", PackageFeatures::default())
    };
    assert!(validate_package(nameless).is_err());
}

/// The seam this feature lives or dies on: a plan's checklist has to
/// reach the SITE — through the activation snapshot, on the node that
/// owns it — and an edit has to reach the sites already sold.
#[tokio::test]
async fn a_plans_checklist_reaches_its_sites_and_survives_an_edit() {
    use hyperion_types::care_check::{check_items_to_json, CheckItemDef};
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "checklist.cz").await;
    let def = |id: &str, label: &str| CheckItemDef {
        id: id.into(),
        label: label.into(),
        detail: String::new(),
    };

    // A plan promising three checks, one of them the operator's own.
    let mut input = care_input("Péče Plus", PackageFeatures::default());
    input.check_items =
        check_items_to_json(&[def("render", "Vzhled"), def("gdpr-review", "GDPR revize")]);
    let pkg = s.package_create(input.clone()).await.expect("create");
    assert_eq!(
        hyperion_types::care_check::parse_check_items(&pkg.check_items).len(),
        2
    );

    // Nothing held yet, so the site is asked the built-in four rather
    // than nothing — "0 of 0" would render as a finished month.
    assert_eq!(s.care_check_items(&detail.id).await.len(), 4);

    s.package_activate(HostingSelector::Id(detail.id.clone()), pkg.id, None, None)
        .await
        .expect("activate");
    let ids: Vec<String> = s
        .care_check_items(&detail.id)
        .await
        .into_iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(
        ids,
        vec!["render", "gdpr-review"],
        "the site must be asked what its plan promises, off the snapshot"
    );

    // The operator edits the plan. Sites already on it have to follow —
    // otherwise the plan page and the site page say different things,
    // for ever, and only one of them is what gets ticked.
    input.check_items = check_items_to_json(&[
        def("render", "Vzhled"),
        def("gdpr-review", "GDPR revize"),
        def("stock-feed", "Kontrola importu"),
    ]);
    s.package_update(pkg.id, input.clone())
        .await
        .expect("update");
    assert_eq!(
        s.care_check_items(&detail.id).await.len(),
        3,
        "an edit must reach the sites already sold"
    );

    // The dashboard counts against that list, not against four.
    let period = hyperion_types::care_check::period_key(now_secs());
    let rows = s.care_overview(period.clone()).await.expect("overview");
    let row = rows
        .iter()
        .find(|r| r.hosting_id == detail.id.as_str())
        .expect("row");
    assert_eq!((row.checks_done, row.checks_total), (0, 3));
    assert!(
        row.outstanding.contains(&"Kontrola importu".to_string()),
        "the operator's own wording, not an id: {:?}",
        row.outstanding
    );

    // And clearing the plan's list falls back to the built-ins rather
    // than promising nothing.
    input.check_items = String::new();
    s.package_update(pkg.id, input).await.expect("clear");
    assert_eq!(s.care_check_items(&detail.id).await.len(), 4);
}

/// The care packages page reads a site's billing from the overview: the
/// earliest start, the soonest reminder, and EVERY priced plan at the
/// price the site agreed to — a later re-price of the definition must not
/// move what the roster says the customer owes.
#[tokio::test]
async fn care_overview_carries_each_sites_agreed_price_and_dates() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "billing.cz").await;
    let now = now_secs();

    let care = s
        .package_create(care_input("Care", PackageFeatures::default()))
        .await
        .expect("care");
    let mut yearly = care_input("Backups", PackageFeatures::default());
    yearly.price_minor = Some(120_000);
    yearly.price_interval = Some("yearly".into());
    let yearly = s.package_create(yearly).await.expect("yearly");

    let sel = HostingSelector::Id(detail.id.clone());
    s.package_activate(sel.clone(), care.id, None, Some(now - 90 * 86_400))
        .await
        .expect("care on");
    s.package_activate(sel, yearly.id, None, None)
        .await
        .expect("yearly on");

    // Re-pricing the definition afterwards changes nothing already sold.
    let mut repriced = care_input("Care", PackageFeatures::default());
    repriced.price_minor = Some(99_900);
    s.package_update(care.id, repriced).await.expect("reprice");

    let period = hyperion_types::care_check::period_key(now);
    let rows = s.care_overview(period).await.expect("overview");
    let row = rows
        .iter()
        .find(|r| r.hosting_id == detail.id.as_str())
        .expect("row");
    let since = row.since.expect("since");
    assert!(
        (since - (now - 90 * 86_400)).abs() < 86_400,
        "the backdated plan is the earliest start"
    );
    assert!(
        row.next_billing_at.is_some(),
        "both plans carry an interval"
    );
    let mut prices: Vec<(i64, &str)> = row
        .charges
        .iter()
        .map(|c| (c.price_minor, c.interval.as_str()))
        .collect();
    prices.sort();
    assert_eq!(prices, vec![(49_000, "monthly"), (120_000, "yearly")]);
    let monthly: i64 = row.charges.iter().filter_map(|c| c.monthly_minor()).sum();
    assert_eq!(monthly, 49_000 + 10_000);
}

/// The half of a package edit that does not happen on the master.
///
/// `hosting_packages` is co-located with its hosting, so the UPDATE inside
/// `package_update` reaches the master's own sites and nothing else. A
/// worker's copy is moved by this call and by nothing else — no tick
/// re-derives it, because the enforcement pass reads the SNAPSHOT.
#[tokio::test]
async fn package_relist_moves_the_activations_this_node_owns() {
    use hyperion_types::care_check::{check_items_to_json, CheckItemDef};
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "worker-owned.cz").await;

    // Stand in for what a worker's database looks like: an activation
    // written when the site was sold, with NO definition behind it —
    // `service_packages` is empty on a worker, which is the whole reason
    // the values have to travel with the request.
    hyperion_state::packages::activate(
        &pool,
        &hyperion_state::packages::NewActivation {
            report_omit: String::new(),
            valid_from: None,
            enforcement_started: true,
            hosting_id: detail.id.clone(),
            package_id: 42,
            package_name: "Péče Plus".into(),
            letters_lang: "en".into(),
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

    // Before: the site is on the built-in four and English.
    assert_eq!(s.care_check_items(&detail.id).await.len(), 4);
    assert_eq!(s.letter_catalog_for(&detail.id).await.lang, LetterLang::En);

    let items = check_items_to_json(&[
        CheckItemDef {
            id: "gdpr-review".into(),
            label: "GDPR revize".into(),
            detail: String::new(),
        },
        CheckItemDef {
            id: "stock-feed".into(),
            label: "Import skladu".into(),
            detail: String::new(),
        },
    ]);
    let (relanguaged, relisted) = s
        .package_relist(42, "cs", &items, "")
        .await
        .expect("relist");
    assert_eq!((relanguaged, relisted), (1, 1));

    let ids: Vec<String> = s
        .care_check_items(&detail.id)
        .await
        .into_iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(
        ids,
        vec!["gdpr-review", "stock-feed"],
        "the edit has to reach a site whose definition lives on another box"
    );
    assert_eq!(
        s.letter_catalog_for(&detail.id).await.lang,
        LetterLang::Cs,
        "and so does the letter language, broken the same way since v0.61.0"
    );

    // A package this node holds nothing for is a no-op, not an error: the
    // master fans this out to every node, most of which own no site on it.
    assert_eq!(
        s.package_relist(999, "cs", &items, "").await.expect("noop"),
        (0, 0)
    );
}

/// The opt-in re-price reaches a site whose definition lives on another
/// box, and refuses an interval the billing sweep could not step.
#[tokio::test]
async fn package_reprice_moves_the_activations_this_node_owns() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "repriced.cz").await;
    let id = hyperion_state::packages::activate(
        &pool,
        &hyperion_state::packages::NewActivation {
            report_omit: String::new(),
            valid_from: None,
            enforcement_started: true,
            hosting_id: detail.id.clone(),
            package_id: 42,
            package_name: "Péče Plus".into(),
            letters_lang: "cs".into(),
            check_items: String::new(),
            price_minor: Some(49_000),
            price_currency: Some("Kč".into()),
            price_interval: Some("monthly".into()),
            features: PackageFeatures::default(),
            next_billing_at: Some(9_999_999_999),
            prior_state_json: None,
        },
        0,
    )
    .await
    .expect("activate");

    assert!(s
        .package_reprice(42, Some(1), None, Some("weekly".into()))
        .await
        .is_err());
    let n = s
        .package_reprice(42, Some(59_000), Some(" Kč ".into()), Some("Yearly".into()))
        .await
        .expect("reprice");
    assert_eq!(n, 1);
    let row = hyperion_state::packages::get_activation(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.price_minor, Some(59_000));
    assert_eq!(row.price_currency.as_deref(), Some("Kč"));
    assert_eq!(row.price_interval.as_deref(), Some("yearly"));
    assert_eq!(row.next_billing_at, Some(9_999_999_999));
    // Nothing held here: a no-op, not an error.
    assert_eq!(
        s.package_reprice(999, Some(1), None, None)
            .await
            .expect("noop"),
        0
    );
}

#[tokio::test]
async fn activation_captures_prior_state_and_applies_the_bundle() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "example.cz").await;
    let hid = detail.id.as_str().to_string();
    // What the customer had before they bought anything: auto-updates
    // switched off by hand, weekly backups, monitoring switched off.
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("seed");
    s.hosting_kv_set(hid.clone(), BACKUP_KV_CADENCE.into(), "weekly".into())
        .await
        .expect("seed");
    s.package_set_monitoring(&detail, false)
        .await
        .expect("seed");

    let def = s
        .package_create(care_input(
            "Péče Plus",
            PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                monitoring: FeatureToggle::On,
                backup_cadence: BackupCadence::Daily,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    assert_eq!(def.slug, "pece-plus");
    assert_eq!(def.active_count, 0);

    let act = s
        .package_activate(HostingSelector::Id(detail.id.clone()), def.id, None, None)
        .await
        .expect("activate");

    // Applied — through the setters the panel and the ticks read.
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("on")
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_CADENCE).await.as_deref(),
        Some("daily")
    );
    assert!(monitoring_on(&pool, &detail.id).await);

    // Snapshotted price + an armed reminder clock. Neither charges
    // anyone; the sweep just has something to fire on.
    assert_eq!(act.price_minor, Some(49_000));
    assert_eq!(act.price_interval.as_deref(), Some("monthly"));
    assert!(act.next_billing_at.is_some_and(|t| t > now_secs()));

    // Prior state holds the SITE's values, only for forced features.
    let prior: PackagePriorState =
        serde_json::from_str(&act.prior_state_json.expect("captured")).expect("de");
    assert_eq!(prior.wp_auto_update, Some(false));
    assert_eq!(prior.monitoring, Some(false));
    assert_eq!(prior.backup_cadence, Some(BackupCadence::Weekly));
    assert_eq!(
        prior.hardening, None,
        "a feature the package leaves alone has nothing to restore"
    );
    assert_eq!(s.package_get(def.id).await.expect("get").active_count, 1);
}

#[tokio::test]
async fn re_activating_a_held_package_reasserts_without_a_second_row() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "example.cz").await;
    let hid = detail.id.as_str().to_string();
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("seed");
    let def = s
        .package_create(care_input(
            "Péče",
            PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let first = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");

    // Someone switches the paid feature off, then the admin re-runs
    // "activate" on a package the site already holds.
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("drift");
    let again = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("re-activate");

    assert_eq!(again.id, first.id, "the same activation row, re-asserted");
    assert_eq!(
        s.package_activations(sel, true)
            .await
            .expect("history")
            .len(),
        1,
        "no duplicate row, not even a cancelled one"
    );
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("on"),
        "re-activation re-asserts the bundle"
    );
    // The ORIGINAL snapshot survives. Re-capturing it here would record
    // the state the first activation forced, and the eventual cancel
    // would then "restore" the package's own values.
    let prior: PackagePriorState =
        serde_json::from_str(&again.prior_state_json.expect("kept")).expect("de");
    assert_eq!(prior.wp_auto_update, Some(false));
}

#[tokio::test]
async fn cancel_restores_exactly_what_the_package_changed() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "example.cz").await;
    let hid = detail.id.as_str().to_string();
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("seed");
    s.hosting_kv_set(hid.clone(), BACKUP_KV_CADENCE.into(), "weekly".into())
        .await
        .expect("seed");
    // Monitoring is on and stays on for the customer's own reasons —
    // the load-bearing case for `leave`, since no package here sells it.
    assert!(monitoring_on(&pool, &detail.id).await);

    let def = s
        .package_create(care_input(
            "Zálohy",
            PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                backup_cadence: BackupCadence::Daily,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let act = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");

    let cancelled = s.package_cancel(sel.clone(), act.id).await.expect("cancel");
    assert!(!cancelled.state.is_active());
    assert_eq!(cancelled.next_billing_at, None, "reminders stop");

    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("off"),
        "restored to what the customer had"
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_CADENCE).await.as_deref(),
        Some("weekly")
    );
    assert!(
        monitoring_on(&pool, &detail.id).await,
        "the package never forced monitoring, so cancelling must not touch it"
    );
    // Kept as history, and a second cancel is a no-op rather than a
    // second restore on top of whatever changed since.
    let history = s
        .package_activations(sel.clone(), true)
        .await
        .expect("hist");
    assert_eq!(history.len(), 1);
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "on".into())
        .await
        .expect("later change");
    s.package_cancel(sel, act.id).await.expect("re-cancel");
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("on"),
        "a double cancel must not replay the restore"
    );
}

#[tokio::test]
async fn cancel_leaves_a_feature_another_package_still_pays_for() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "example.cz").await;
    let hid = detail.id.as_str().to_string();
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("seed");
    s.package_set_monitoring(&detail, false)
        .await
        .expect("seed");

    // Two packages that overlap on monitoring; only the first also
    // sells auto-updates.
    let plus = s
        .package_create(care_input(
            "Péče Plus",
            PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                monitoring: FeatureToggle::On,
                ..Default::default()
            },
        ))
        .await
        .expect("define plus");
    let watch = s
        .package_create(care_input(
            "Monitoring",
            PackageFeatures {
                monitoring: FeatureToggle::On,
                ..Default::default()
            },
        ))
        .await
        .expect("define watch");
    let sel = HostingSelector::Id(detail.id.clone());
    let act_plus = s
        .package_activate(sel.clone(), plus.id, None, None)
        .await
        .expect("activate plus");
    s.package_activate(sel.clone(), watch.id, None, None)
        .await
        .expect("activate watch");
    assert!(monitoring_on(&pool, &detail.id).await);

    s.package_cancel(sel.clone(), act_plus.id)
        .await
        .expect("cancel plus");

    assert!(
        monitoring_on(&pool, &detail.id).await,
        "cancelling the cheaper package must not switch off what the \
             customer still pays for through the other one"
    );
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("off"),
        "the feature only the cancelled package forced does go back"
    );
    assert_eq!(
        s.package_activations(sel, false).await.expect("held").len(),
        1,
        "the other package is still held"
    );
}

#[tokio::test]
async fn enforce_tick_puts_back_features_that_were_switched_off() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "example.cz").await;
    let hid = detail.id.as_str().to_string();
    let def = s
        .package_create(care_input(
            "Péče Plus",
            PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                monitoring: FeatureToggle::On,
                hardening: FeatureToggle::On,
                backup_cadence: BackupCadence::Daily,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    s.package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");

    // Nothing has moved yet, so the tick must not write a thing.
    assert_eq!(
        s.package_enforce_tick().await.expect("tick"),
        0,
        "a healthy site costs the tick nothing"
    );

    // Now someone undoes all four by hand.
    let live = s.get(sel.clone()).await.expect("re-read");
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("drift");
    s.hosting_kv_set(hid.clone(), BACKUP_KV_CADENCE.into(), "off".into())
        .await
        .expect("drift");
    s.package_set_monitoring(&live, false).await.expect("drift");
    s.package_set_waf_level(&live, hyperion_types::waf::WafLevel::Off)
        .await
        .expect("drift");

    assert_eq!(
        s.package_enforce_tick().await.expect("tick"),
        4,
        "every paid feature comes back"
    );
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("on")
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_CADENCE).await.as_deref(),
        Some("daily")
    );
    assert!(monitoring_on(&pool, &detail.id).await);
    assert!(
        s.get(sel.clone())
            .await
            .expect("get")
            .vhost_options
            .waf_enabled,
        "hardening goes back through the vhost path, not a raw column write"
    );
    // …and the pass right after a correction is quiet again.
    assert_eq!(s.package_enforce_tick().await.expect("tick"), 0);
}

/// The firewall a plan sells: held at Strict, the Core Rule Set and the
/// brute-force scan forced, the operator told when the node lacks what
/// the plan needs (once, not every tick), and a cancel putting back the
/// EXACT prior level — Standard, not merely "still on".
#[tokio::test]
async fn firewall_package_enforces_warns_once_and_restores_exactly() {
    use hyperion_types::crs::CrsMode;
    use hyperion_types::waf::WafLevel;
    use std::sync::atomic::{AtomicBool, Ordering};
    let pool = open_memory().await.expect("open");
    let mut mocks = package_mocks();
    // No ModSecurity engine on this node — until the test installs one.
    let engine = std::sync::Arc::new(AtomicBool::new(false));
    let e = engine.clone();
    mocks.expect_modsec_status().returning(move || {
        let on = e.load(Ordering::SeqCst);
        hyperion_types::crs::ModsecStatus {
            module: on,
            crs: on,
            ..Default::default()
        }
    });
    mocks.expect_modsec_sync_http().returning(|_| Ok(true));
    let s = svc(pool.clone(), mocks);
    let detail = hosting_for_packages(&s, "fw.cz").await;
    let hid = detail.id.as_str().to_string();
    let sel = HostingSelector::Id(detail.id.clone());
    // The customer's own setup: WAF on Standard, scan opted out.
    s.package_set_waf_level(&detail, WafLevel::Standard)
        .await
        .expect("seed waf");
    s.hosting_kv_set(hid.clone(), FAIL2BAN_HTTP_KV_KEY.into(), "off".into())
        .await
        .expect("seed scan");

    let mut f = PackageFeatures {
        crs: CrsPin::Detect,
        bruteforce: FeatureToggle::On,
        ..Default::default()
    };
    f.set_firewall_choice("strict");
    let def = s
        .package_create(care_input("Bezpečnost", f))
        .await
        .expect("define");
    let act = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");
    let opts = s.get(sel.clone()).await.expect("get").vhost_options;
    assert_eq!(opts.effective_waf_level(), WafLevel::Strict);
    assert_eq!(
        opts.crs_settings().mode,
        CrsMode::Off,
        "no engine: the Core Rule Set waits instead of failing the activation"
    );
    assert_eq!(
        kv_of(&pool, &hid, FAIL2BAN_HTTP_KV_KEY).await.as_deref(),
        Some("on")
    );
    let prior: PackagePriorState =
        serde_json::from_str(&act.prior_state_json.expect("captured")).expect("de");
    assert_eq!(prior.waf_level.as_deref(), Some("standard"));
    assert_eq!(prior.crs.as_deref(), Some("off"));
    assert_eq!(prior.bruteforce, Some(false));

    // Read back what the definition and the activation stored (mig 084).
    let back = s.package_get(def.id).await.expect("get def");
    assert_eq!(back.features.firewall_choice(), "strict");
    assert_eq!(back.features.crs, CrsPin::Detect);
    assert_eq!(back.features.bruteforce, FeatureToggle::On);
    let row = hyperion_state::packages::get_activation(&pool, act.id)
        .await
        .expect("read")
        .expect("row");
    assert!(row.features.firewall_strict);
    assert_eq!(row.features.crs, CrsPin::Detect);

    // The node has no ModSecurity: the operator is told, and told once.
    assert_eq!(s.package_enforce_tick().await.expect("tick"), 0);
    let warned = kv_of(&pool, &hid, PACKAGE_PROTECTION_WARNED_KV)
        .await
        .unwrap_or_default();
    assert!(warned.contains("ModSecurity"), "{warned}");
    assert!(
        !warned.contains("brute-force"),
        "a plan that only just started gets the scanner's first pass: {warned}"
    );
    s.package_enforce_tick().await.expect("tick 2");
    assert_eq!(
        kv_of(&pool, &hid, PACKAGE_PROTECTION_WARNED_KV)
            .await
            .unwrap_or_default(),
        warned,
        "same reason, no new alert"
    );

    // Engine installed: the next tick switches the rule set on and the
    // outstanding alert clears.
    engine.store(true, Ordering::SeqCst);
    assert_eq!(s.package_enforce_tick().await.expect("tick 3"), 1);
    assert_eq!(
        s.get(sel.clone())
            .await
            .expect("get")
            .vhost_options
            .crs_settings()
            .mode,
        CrsMode::Detect
    );
    assert_eq!(
        kv_of(&pool, &hid, PACKAGE_PROTECTION_WARNED_KV)
            .await
            .unwrap_or_default(),
        ""
    );

    // A hand-lowered level comes back to Strict.
    let live = s.get(sel.clone()).await.expect("re-read");
    s.package_set_waf_level(&live, WafLevel::Standard)
        .await
        .expect("drift");
    assert_eq!(s.package_enforce_tick().await.expect("tick 4"), 1);

    // Cancel: exactly what the site had before.
    s.package_cancel(sel.clone(), act.id).await.expect("cancel");
    let opts = s.get(sel.clone()).await.expect("get").vhost_options;
    assert_eq!(opts.effective_waf_level(), WafLevel::Standard);
    assert_eq!(opts.crs_settings().mode, CrsMode::Off);
    assert_eq!(
        kv_of(&pool, &hid, FAIL2BAN_HTTP_KV_KEY).await.as_deref(),
        Some("off")
    );
}

#[test]
fn package_waf_target_keeps_a_stricter_hand_set_level() {
    use hyperion_types::waf::WafLevel::*;
    assert_eq!(package_waf_target(None, Strict), None);
    assert_eq!(package_waf_target(Some(Standard), Strict), Some(Strict));
    assert_eq!(package_waf_target(Some(Standard), Off), Some(Standard));
    assert_eq!(package_waf_target(Some(Strict), Standard), Some(Strict));
    assert_eq!(package_waf_target(Some(Off), Strict), Some(Off));
}

#[tokio::test]
async fn enforce_tick_is_inert_without_packages_and_after_a_cancel() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    // No definitions at all: the whole feature is ignorable.
    assert_eq!(s.package_enforce_tick().await.expect("tick"), 0);

    let detail = hosting_for_packages(&s, "example.cz").await;
    let hid = detail.id.as_str().to_string();
    let def = s
        .package_create(care_input(
            "Zálohy",
            PackageFeatures {
                backup_cadence: BackupCadence::Daily,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let act = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");
    s.package_cancel(sel, act.id).await.expect("cancel");

    // A cancelled activation is history — the tick must not re-assert it.
    s.hosting_kv_set(hid.clone(), BACKUP_KV_CADENCE.into(), "off".into())
        .await
        .expect("operator switches backups off");
    assert_eq!(s.package_enforce_tick().await.expect("tick"), 0);
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_CADENCE).await.as_deref(),
        Some("off"),
        "nobody is paying for backups any more"
    );
}

#[tokio::test]
async fn deleting_a_definition_keeps_the_activation_enforceable() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "example.cz").await;
    let hid = detail.id.as_str().to_string();
    let def = s
        .package_create(care_input(
            "Zálohy",
            PackageFeatures {
                backup_cadence: BackupCadence::Daily,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let act = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");

    s.package_delete(def.id).await.expect("delete");

    let held = s.package_activations(sel, false).await.expect("held");
    assert_eq!(held.len(), 1, "the customer's record survives the delete");
    assert_eq!(held[0].id, act.id);
    assert_eq!(
        held[0].price_minor,
        Some(49_000),
        "the price they agreed to is not ours to erase"
    );
    assert_eq!(
        held[0].package_name, "Zálohy",
        "the name snapshot still says what was bought"
    );

    // …and neither is the SERVICE. The activation carries its own bundle
    // snapshot, so retiring a definition must not quietly stop delivering
    // what someone is still paying for: drift is still corrected.
    s.hosting_kv_set(hid.clone(), BACKUP_KV_CADENCE.into(), "off".into())
        .await
        .expect("drift");
    assert_eq!(
        s.package_enforce_tick().await.expect("tick"),
        1,
        "a deleted definition must not silently disable enforcement"
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_CADENCE).await.as_deref(),
        Some("daily")
    );
}

#[tokio::test]
async fn packages_on_one_hosting_do_not_reach_another() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks_two_sites());
    s.create(req_no_db("a-site.cz")).await.expect("create a");
    s.create(req_no_db("b-site.cz")).await.expect("create b");
    let a = s
        .get(HostingSelector::Domain(
            Domain::parse("a-site.cz").expect("parse"),
        ))
        .await
        .expect("get a");
    let b = s
        .get(HostingSelector::Domain(
            Domain::parse("b-site.cz").expect("parse"),
        ))
        .await
        .expect("get b");
    let def = s
        .package_create(care_input(
            "Zálohy",
            PackageFeatures {
                backup_cadence: BackupCadence::Daily,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let act = s
        .package_activate(HostingSelector::Id(a.id.clone()), def.id, None, None)
        .await
        .expect("activate on a");

    assert_eq!(
        kv_of(&pool, b.id.as_str(), BACKUP_KV_CADENCE).await,
        None,
        "the other site is untouched"
    );
    // An activation id from another hosting is a 404, never a
    // cancellation of someone else's package.
    assert!(s
        .package_cancel(HostingSelector::Id(b.id.clone()), act.id)
        .await
        .is_err());
}

#[test]
fn a_plan_may_not_leave_out_every_section() {
    assert!(validate_report_omit("").is_ok());
    assert_eq!(
        validate_report_omit(" uptime,attacks,bogus ").unwrap(),
        "attacks,uptime"
    );
    let all = ReportSection::ALL
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(",");
    assert!(validate_report_omit(&all).is_err());
}

#[test]
fn a_start_date_must_be_plausible() {
    let now = 1_800_000_000;
    assert_eq!(validate_valid_from(None, now).unwrap(), None);
    assert_eq!(
        validate_valid_from(Some(now - 40 * 86_400), now).unwrap(),
        Some(now - 40 * 86_400)
    );
    assert_eq!(
        validate_valid_from(Some(now + 300 * 86_400), now).unwrap(),
        Some(now + 300 * 86_400)
    );
    assert!(
        validate_valid_from(Some(now + 400 * 86_400), now).is_err(),
        "over a year ahead"
    );
    assert!(validate_valid_from(Some(0), now).is_err(), "before 2015");
    assert!(
        validate_valid_from(Some(1_700_000_000_000), now).is_err(),
        "epoch milliseconds"
    );
}

/// Backdated: the plan is in force at once, but the first report and the
/// billing clock count from the operator's date, not from the click.
#[tokio::test]
async fn a_backdated_plan_counts_reports_and_billing_from_its_date() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "zpetne.cz").await;
    let hid = detail.id.as_str().to_string();
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("seed");
    let mut input = care_input(
        "Péče Plus",
        PackageFeatures {
            wp_auto_update: FeatureToggle::On,
            report_cadence: ReportCadence::Monthly,
            ..Default::default()
        },
    );
    input.report_omit = "attacks".into();
    let def = s.package_create(input).await.expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let now = now_secs();
    let started = now - 100 * 86_400;

    let act = s
        .package_activate(sel.clone(), def.id, None, Some(started))
        .await
        .expect("activate backdated");
    assert_eq!(act.valid_from, Some(started));
    assert!(
        act.enforcement_started,
        "a date in the past starts the plan now"
    );
    assert_eq!(
        act.report_omit, "attacks",
        "the plan's section choice is snapshotted"
    );
    // Enforced immediately.
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("on")
    );
    // The reminder clock is the next whole interval AFTER today, counted
    // from the start date — not "30 days from the click".
    let next = act.next_billing_at.expect("clock armed");
    assert!(next > now);
    assert_eq!((next - started) % (30 * 86_400), 0, "aligned to the term");
    assert!(next - now <= 30 * 86_400);

    // The first report runs from the operator's date, and carries the
    // plan's sections.
    let (cadence, from, omit) = s.care_report_entitlement(&detail.id).await;
    assert_eq!(cadence, ReportCadence::Monthly);
    assert_eq!(from, Some(started));
    assert_eq!(omit.to_stored(), "attacks");
}

/// A plan dated for the future is recorded and shown, and does NOTHING:
/// no features forced, no prior state captured, no report entitlement, no
/// monthly checks. When its date arrives the next pass starts it, capturing
/// the site as it is THEN.
#[tokio::test]
async fn a_future_plan_does_nothing_until_it_starts() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "budouci.cz").await;
    let hid = detail.id.as_str().to_string();
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("seed");
    let def = s
        .package_create(care_input(
            "Péče Plus",
            PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                report_cadence: ReportCadence::Monthly,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let now = now_secs();
    let start = now + 20 * 86_400;

    let act = s
        .package_activate(sel.clone(), def.id, None, Some(start))
        .await
        .expect("activate for the future");
    assert!(act.is_pending());
    assert_eq!(act.valid_from, Some(start));
    assert_eq!(act.prior_state_json, None, "nothing captured yet");
    // Billing starts with the term: a first renewal a whole interval after it.
    assert_eq!(act.next_billing_at, Some(start + 30 * 86_400));
    // Not forced…
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("off")
    );
    // …not re-asserted by the drift tick…
    assert_eq!(s.package_enforce_tick().await.expect("tick"), 0);
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("off")
    );
    // …not entitled to a report…
    let (cadence, from, _) = s.care_report_entitlement(&detail.id).await;
    assert_eq!((cadence, from), (ReportCadence::Leave, None));
    // …not asked for monthly checks beyond the built-in fallback, and not
    // counted on the care dashboard.
    assert!(s
        .care_overview("2026-10".into())
        .await
        .expect("overview")
        .is_empty());
    // …and re-activating it must not start it early.
    let again = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("re-activate");
    assert_eq!(again.id, act.id);
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("off")
    );
    // The card still lists it (it is held).
    assert_eq!(
        s.package_activations(sel.clone(), false)
            .await
            .expect("held")
            .len(),
        1
    );

    // The site changes in the meantime…
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "on".into())
        .await
        .expect("changed by hand");
    // …and the date arrives (moved into the past directly, as time passing would).
    packages::set_valid_from(&pool, act.id, now - 60, act.next_billing_at)
        .await
        .expect("time passes");
    assert_eq!(s.package_enforce_tick().await.expect("tick"), 0);
    let started = packages::get_activation(&pool, act.id)
        .await
        .expect("read")
        .expect("row");
    assert!(started.enforcement_started, "the pass started it");
    // The prior state is the site as it was AT THE START (on), not as it was
    // when the form was submitted (off): cancelling must not switch off a
    // setting the customer turned on themselves in the weeks between.
    let prior: PackagePriorState =
        serde_json::from_str(&started.prior_state_json.expect("captured")).expect("de");
    assert_eq!(prior.wp_auto_update, Some(true));
    let (cadence, from, _) = s.care_report_entitlement(&detail.id).await;
    assert_eq!(cadence, ReportCadence::Monthly);
    assert_eq!(from, Some(now - 60), "reports count from the start date");
}

/// Cancelling a plan that never started touches nothing.
#[tokio::test]
async fn cancelling_a_waiting_plan_restores_nothing() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "zrusit.cz").await;
    let hid = detail.id.as_str().to_string();
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "on".into())
        .await
        .expect("seed");
    let def = s
        .package_create(care_input(
            "Péče",
            PackageFeatures {
                wp_auto_update: FeatureToggle::Off,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let act = s
        .package_activate(sel.clone(), def.id, None, Some(now_secs() + 5 * 86_400))
        .await
        .expect("activate");
    s.package_cancel(sel, act.id).await.expect("cancel");
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("on"),
        "nothing was forced, so nothing is put back"
    );
}

/// The date can be corrected; a plan already in force cannot be pushed into
/// the future (that would mean un-forcing features).
#[tokio::test]
async fn changing_a_start_date_follows_the_rules() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks_two_sites());
    s.create(req_no_db("datum.cz")).await.expect("create");
    let detail = s
        .get(HostingSelector::Domain(
            Domain::parse("datum.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let hid = detail.id.as_str().to_string();
    s.hosting_kv_set(hid.clone(), "wp_auto_update".into(), "off".into())
        .await
        .expect("seed");
    let def = s
        .package_create(care_input(
            "Péče",
            PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let now = now_secs();

    // In force → backdate: fine, and it re-aims the billing clock.
    let act = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");
    assert_eq!(act.valid_from, None);
    let earlier = now - 70 * 86_400;
    let moved = s
        .package_set_valid_from(sel.clone(), act.id, earlier)
        .await
        .expect("backdate");
    assert_eq!(moved.valid_from, Some(earlier));
    assert!(moved
        .next_billing_at
        .is_some_and(|t| t > now && (t - earlier) % (30 * 86_400) == 0));

    // In force → future: refused, nothing changes.
    let err = s
        .package_set_valid_from(sel.clone(), act.id, now + 10 * 86_400)
        .await
        .expect_err("cannot postpone a plan in force");
    assert!(err.to_string().contains("already in force"), "{err}");
    let unchanged = packages::get_activation(&pool, act.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.valid_from, Some(earlier));

    // Out of range: refused.
    assert!(s
        .package_set_valid_from(sel.clone(), act.id, 5)
        .await
        .is_err());

    // An activation id from another site is a 404.
    s.create(req_no_db("jiny.cz")).await.expect("create other");
    let other = s
        .get(HostingSelector::Domain(
            Domain::parse("jiny.cz").expect("parse"),
        ))
        .await
        .expect("get other");
    assert!(s
        .package_set_valid_from(HostingSelector::Id(other.id.clone()), act.id, earlier)
        .await
        .is_err());

    // Waiting → later: fine. Waiting → today: starts at once.
    s.package_cancel(sel.clone(), act.id).await.expect("cancel");
    let waiting = s
        .package_activate(sel.clone(), def.id, None, Some(now + 30 * 86_400))
        .await
        .expect("activate for later");
    assert!(waiting.is_pending());
    let later = s
        .package_set_valid_from(sel.clone(), waiting.id, now + 45 * 86_400)
        .await
        .expect("postpone a waiting plan");
    assert!(later.is_pending());
    assert_eq!(later.valid_from, Some(now + 45 * 86_400));
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("off"),
        "a waiting plan forces nothing, even after being moved"
    );

    let started = s
        .package_set_valid_from(sel.clone(), waiting.id, now - 3_600)
        .await
        .expect("bring it forward");
    assert!(
        !started.is_pending(),
        "a date that has passed starts the plan now"
    );
    assert_eq!(
        kv_of(&pool, &hid, "wp_auto_update").await.as_deref(),
        Some("on")
    );

    // A cancelled activation's dates are history.
    s.package_cancel(sel.clone(), waiting.id)
        .await
        .expect("cancel");
    assert!(s
        .package_set_valid_from(sel, waiting.id, earlier)
        .await
        .is_err());
}

/// Editing a plan's section choice reaches the sites already on it, and the
/// relist refuses a value that would send an empty letter.
#[tokio::test]
async fn a_plans_report_sections_follow_an_edit() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "sekce.cz").await;
    let def = s
        .package_create(care_input(
            "Péče",
            PackageFeatures {
                report_cadence: ReportCadence::Monthly,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    s.package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");
    let omit_now = || async {
        let (_, _, o) = s.care_report_entitlement(&detail.id).await;
        o.to_stored()
    };
    assert_eq!(omit_now().await, "");

    let mut edit = care_input(
        "Péče",
        PackageFeatures {
            report_cadence: ReportCadence::Monthly,
            ..Default::default()
        },
    );
    edit.report_omit = " uptime , attacks ".into();
    let updated = s
        .package_update(def.id, edit.clone())
        .await
        .expect("update");
    assert_eq!(updated.report_omit, "attacks,uptime", "stored canonically");
    assert_eq!(
        omit_now().await,
        "attacks,uptime",
        "the sold site follows the edit"
    );

    // The worker-node path: the relist takes values, not an id lookup.
    let (_, _) = s
        .package_relist(def.id, "", "", "traffic")
        .await
        .expect("relist");
    assert_eq!(omit_now().await, "traffic");
    let all = ReportSection::ALL
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<_>>()
        .join(",");
    assert!(s.package_relist(def.id, "", "", &all).await.is_err());
    assert_eq!(
        omit_now().await,
        "traffic",
        "a refused relist changes nothing"
    );

    // And the definition itself refuses to be saved empty.
    edit.report_omit = all;
    assert!(s.package_update(def.id, edit).await.is_err());
}

/// Two plans on one site send the union of their sections.
#[tokio::test]
async fn two_plans_send_every_section_either_includes() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "dva.cz").await;
    let sel = HostingSelector::Id(detail.id.clone());
    let mk = |name: &str, omit: &str, cadence: ReportCadence| {
        let mut i = care_input(
            name,
            PackageFeatures {
                report_cadence: cadence,
                ..Default::default()
            },
        );
        i.report_omit = omit.into();
        i
    };
    let a = s
        .package_create(mk("A", "attacks,uptime,traffic", ReportCadence::Monthly))
        .await
        .unwrap();
    let b = s
        .package_create(mk("B", "uptime,integrity", ReportCadence::Weekly))
        .await
        .unwrap();
    // A plan that sells NO report has no say in what the report holds.
    let c = s
        .package_create(mk("C", "", ReportCadence::Leave))
        .await
        .unwrap();
    for id in [a.id, b.id, c.id] {
        s.package_activate(sel.clone(), id, None, None)
            .await
            .expect("activate");
    }
    let (_, _, omit) = s.care_report_entitlement(&detail.id).await;
    assert_eq!(
        omit.to_stored(),
        "uptime",
        "left out only where every report-selling plan leaves it out"
    );
}
