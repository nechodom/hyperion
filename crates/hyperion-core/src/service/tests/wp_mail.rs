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
