//! Tests for `service::wp_mail`.

use super::*;

/// The mail-rewrite switch, end to end on a real WordPress-shaped tree:
/// `off` writes a module that changes nothing and hands sending back,
/// `on` pins the sender again, `hand_back` keeps the pin but stops the
/// takeover — and a takeover stamp never survives `off`.
#[tokio::test]
async fn wp_mail_override_switch_rewrites_the_module() {
    use hyperion_adapters::wpmail;
    let pool = open_memory().await.expect("memory db");
    let s = svc(pool.clone(), MockAdapterPort::new());
    let site = tempfile::tempdir().expect("tmp");
    let root = site.path().join("htdocs");
    std::fs::create_dir_all(root.join("wp-content")).expect("wp-content");
    let suid = system_users::insert(
        &pool,
        "web_mail_cz",
        5001,
        "/home/web_mail_cz",
        "/bin/bash",
        now_secs(),
    )
    .await
    .expect("user");
    let id = HostingId::new_v7();
    hostings::insert(
        &pool,
        &id,
        "mail.cz",
        suid,
        None,
        &root.to_string_lossy(),
        now_secs(),
        None,
    )
    .await
    .expect("hosting");
    let sel = HostingSelector::Id(id.clone());
    let module = || {
        std::fs::read_to_string(wpmail::mu_plugin_path(&root.to_string_lossy()))
            .expect("module written")
    };

    // Hyperion had taken sending over; the operator says "own SMTP".
    hyperion_state::hosting_kv::set(&pool, id.as_str(), WP_MAIL_FORCE_LOCAL_KV_KEY, "1", 1)
        .await
        .expect("kv");
    let report = s
        .wp_mail_override_set(sel.clone(), "off".into())
        .await
        .expect("off");
    assert!(module().contains("define('HYPERION_MAIL_PIN_FROM', false);"));
    assert!(module().contains("define('HYPERION_MAIL_FORCE_LOCAL', false);"));
    assert_eq!(
        hyperion_state::hosting_kv::get(&pool, id.as_str(), WP_MAIL_FORCE_LOCAL_KV_KEY)
            .await
            .expect("kv"),
        None,
        "turning rewriting off must hand sending back"
    );
    let item = report
        .items
        .iter()
        .find(|i| i.id == "wp_mail_plugin")
        .expect("plugin item");
    assert_eq!(item.severity, "info", "{item:?}");
    assert!(item.label.contains("does not rewrite"), "{item:?}");

    // Back on: the sender is pinned again, and the card says so.
    let report = s
        .wp_mail_override_set(sel.clone(), "on".into())
        .await
        .expect("on");
    assert!(module().contains("define('HYPERION_MAIL_PIN_FROM', true);"));
    let item = report
        .items
        .iter()
        .find(|i| i.id == "wp_mail_plugin")
        .expect("plugin item");
    assert!(
        item.detail
            .contains("rewrites any From address outside mail.cz"),
        "{item:?}"
    );

    // Taken over again, then handed back: pin stays, takeover goes.
    hyperion_state::hosting_kv::set(&pool, id.as_str(), WP_MAIL_FORCE_LOCAL_KV_KEY, "1", 1)
        .await
        .expect("kv");
    s.wp_mail_override_set(sel.clone(), "hand_back".into())
        .await
        .expect("hand back");
    assert!(module().contains("define('HYPERION_MAIL_PIN_FROM', true);"));
    assert!(module().contains("define('HYPERION_MAIL_FORCE_LOCAL', false);"));

    assert!(s
        .wp_mail_override_set(sel, "sideways".into())
        .await
        .is_err());
}

/// A site whose PHP `mail()` itself fails ("Could not instantiate mail
/// function") while Hyperion already sends in the SMTP plugin's place: the
/// plugin is current and the takeover is done, so "Configure" has nothing
/// left to do about those failures. The card must say where the failure is
/// — the server's mail path — and not offer a button that re-renders the
/// same card.
#[tokio::test]
async fn php_mail_failing_is_reported_as_the_servers_path_not_a_repair() {
    use hyperion_adapters::wpmail;
    let pool = open_memory().await.expect("memory db");
    let s = svc(pool.clone(), MockAdapterPort::new());
    let site = tempfile::tempdir().expect("tmp");
    let root = site.path().join("htdocs");
    std::fs::create_dir_all(root.join("wp-content")).expect("wp-content");
    std::fs::create_dir_all(site.path().join("logs")).expect("logs");
    let suid = system_users::insert(
        &pool,
        "web_spol_cz",
        5002,
        "/home/web_spol_cz",
        "/bin/bash",
        now_secs(),
    )
    .await
    .expect("user");
    let id = HostingId::new_v7();
    hostings::insert(
        &pool,
        &id,
        "spol.cz",
        suid,
        None,
        &root.to_string_lossy(),
        now_secs(),
        None,
    )
    .await
    .expect("hosting");
    let sel = HostingSelector::Id(id.clone());
    let taken_over = now_secs() - 3_600;
    hyperion_state::hosting_kv::set(
        &pool,
        id.as_str(),
        WP_MAIL_FORCE_LOCAL_KV_KEY,
        &taken_over.to_string(),
        taken_over,
    )
    .await
    .expect("kv");
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00");
    std::fs::write(
        wpmail::failure_log_path(&root.to_string_lossy()).expect("log path"),
        format!("{ts}\tsponzoring@spol.cz\tCould not instantiate mail function.\n"),
    )
    .expect("log");

    let report = s.wp_mail_repair(sel).await.expect("repair");
    let failures = report
        .items
        .iter()
        .find(|i| i.id == "wp_mail_failures")
        .expect("failures item");
    assert_eq!(failures.severity, "error", "{failures:?}");
    assert!(failures.label.contains("PHP mail()"), "{failures:?}");
    assert!(
        failures.detail.contains("same path"),
        "the takeover is named as no help: {failures:?}"
    );
    assert_eq!(
        failures.fix, "",
        "the repair cannot change PHP's mail(), so it must not be offered for it"
    );
    let transport = report
        .items
        .iter()
        .find(|i| i.id == "wp_mail_transport")
        .expect("the server's mail path is probed");
    // The button shows only when the probe found something the repair can
    // put back (postfix stopped, postdrop permissions) — never for nothing.
    assert_eq!(report.has_site_repair(), transport.fix == "site_repair");
}

/// The size card names the limit the way the Settings field sets it (MB =
/// MiB), and never passes an unreadable limit off as the default.
#[test]
fn size_limit_is_described_in_settings_units() {
    use super::super::wp_mail::describe_size_limit;
    assert_eq!(
        describe_size_limit(Some(10_240_000)),
        "about 10 MB (postfix's default)"
    );
    assert_eq!(describe_size_limit(Some(25 * 1024 * 1024)), "25 MB");
    assert_eq!(describe_size_limit(Some(15_000_000)), "14.3 MB");
    assert!(describe_size_limit(Some(0)).contains("no limit"));
    assert!(!describe_size_limit(None).contains("default"));
}
