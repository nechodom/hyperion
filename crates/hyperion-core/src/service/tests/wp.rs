//! Tests for `service::wp`.

use super::*;

/// Filesystem WP-detection happy path: both wp-config.php and
/// wp-includes/version.php present with a parseable
/// `$wp_version` line → returns Some(<version>).
#[tokio::test]
async fn detect_wp_install_on_disk_finds_version() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(root.join("wp-config.php"), b"<?php /* fake */ ?>").unwrap();
    std::fs::create_dir_all(root.join("wp-includes")).unwrap();
    std::fs::write(
        root.join("wp-includes/version.php"),
        b"<?php\n\
              // The WordPress version string.\n\
              $wp_version = '6.4.2';\n\
              $wp_db_version = 56657;\n",
    )
    .unwrap();
    let got = super::detect_wp_install_on_disk(root.to_str().unwrap()).await;
    assert_eq!(got, Some("6.4.2".to_string()));
}

/// Missing wp-config.php → no WP, no fake.
#[tokio::test]
async fn detect_wp_install_on_disk_returns_none_when_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let got = super::detect_wp_install_on_disk(tmp.path().to_str().unwrap()).await;
    assert_eq!(got, None);
}

/// wp-config.php present but wp-includes/version.php missing —
/// partial install state. Don't fake a version; let the
/// operator's install button stay available to recover it.
#[tokio::test]
async fn detect_wp_install_on_disk_returns_none_on_partial_install() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("wp-config.php"), b"<?php ?>").unwrap();
    let got = super::detect_wp_install_on_disk(tmp.path().to_str().unwrap()).await;
    assert_eq!(got, None);
}

/// version.php exists but $wp_version line is missing /
/// malformed → return Some("unknown") to honestly reflect
/// "WP is here but we can't tell which version".
#[tokio::test]
async fn detect_wp_install_on_disk_handles_unknown_version() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(root.join("wp-config.php"), b"<?php ?>").unwrap();
    std::fs::create_dir_all(root.join("wp-includes")).unwrap();
    std::fs::write(
        root.join("wp-includes/version.php"),
        b"<?php\n// no $wp_version line here\n",
    )
    .unwrap();
    let got = super::detect_wp_install_on_disk(root.to_str().unwrap()).await;
    assert_eq!(got, Some("unknown".to_string()));
}

/// Comment that mentions `$wp_version` but isn't the actual
/// directive must NOT be parsed as the version.
#[tokio::test]
async fn detect_wp_install_on_disk_skips_commented_version() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(root.join("wp-config.php"), b"<?php ?>").unwrap();
    std::fs::create_dir_all(root.join("wp-includes")).unwrap();
    std::fs::write(
        root.join("wp-includes/version.php"),
        b"<?php\n\
              // $wp_version = '5.0.0'; // old comment\n\
              $wp_version = '6.5';\n",
    )
    .unwrap();
    let got = super::detect_wp_install_on_disk(root.to_str().unwrap()).await;
    assert_eq!(got, Some("6.5".to_string()));
}

/// End-to-end: a hosting WITHOUT a wp_installs row but WITH
/// wp-config + version.php on disk must surface as Some(status)
/// via `wp_status()`, and a second call must hit the DB
/// directly (self-heal upsert succeeded).
#[tokio::test]
async fn wp_status_filesystem_fallback_self_heals() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("wpfs.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("wpfs.cz").unwrap());
    let detail = s.get(sel.clone()).await.expect("get");

    // Materialise WP files in a writable tempdir and re-point
    // the hostings row at it. The mock's default root_dir is
    // `/home/<user>/...` which isn't writable in CI.
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(root.join("wp-config.php"), b"<?php ?>").unwrap();
    std::fs::create_dir_all(root.join("wp-includes")).unwrap();
    std::fs::write(
        root.join("wp-includes/version.php"),
        b"<?php\n$wp_version = '6.4.2';\n",
    )
    .unwrap();
    sqlx::query("UPDATE hostings SET root_dir = ? WHERE id = ?")
        .bind(root.to_str().unwrap())
        .bind(detail.id.as_str())
        .execute(&pool)
        .await
        .expect("repoint root_dir");

    // First call should detect + self-heal.
    let first = s.wp_status(sel.clone()).await.expect("first wp_status");
    let first = first.expect("must detect WP");
    assert_eq!(first.wp_version, "6.4.2");

    // Second call must come from the DB row that was just
    // written. We assert by removing the on-disk files and
    // expecting the status to still come back.
    std::fs::remove_dir_all(root).ok();
    let second = s.wp_status(sel.clone()).await.expect("second wp_status");
    let second = second.expect("DB row must survive disk removal");
    assert_eq!(second.wp_version, "6.4.2");
}

/// The recorded version is the install-time one; core updates after that
/// (WordPress's own updater, wp-admin, the sweep) must reach the row the
/// hostings list reads — the list showed "WordPress 7.1" for sites long on
/// 7.1.4. An unreadable version.php never overwrites a real version.
#[tokio::test]
async fn recorded_wp_version_follows_the_files_on_disk() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("wpver.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("wpver.cz").unwrap());
    let detail = s.get(sel.clone()).await.expect("get");
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(root.join("wp-config.php"), b"<?php ?>").unwrap();
    std::fs::create_dir_all(root.join("wp-includes")).unwrap();
    let write_version = |v: &str| {
        std::fs::write(
            root.join("wp-includes/version.php"),
            format!("<?php\n$wp_version = '{v}';\n"),
        )
        .unwrap()
    };
    write_version("7.1");
    sqlx::query("UPDATE hostings SET root_dir = ? WHERE id = ?")
        .bind(root.to_str().unwrap())
        .bind(detail.id.as_str())
        .execute(&pool)
        .await
        .expect("repoint root_dir");
    wordpress::record_install(&pool, &detail.id, "https://wpver.cz", "7.1", "h", 1)
        .await
        .expect("wp row");
    let recorded = |pool: SqlitePool, id: HostingId| async move {
        wordpress::get_install(&pool, &id)
            .await
            .expect("get")
            .expect("row")
            .wp_version
    };

    // Updated behind the panel's back: the tick picks it up.
    write_version("7.1.4");
    assert_eq!(s.wp_version_refresh_tick().await.expect("tick"), 1);
    assert_eq!(recorded(pool.clone(), detail.id.clone()).await, "7.1.4");
    assert_eq!(s.wp_version_refresh_tick().await.expect("again"), 0);

    // ...and so does a page load of the site.
    write_version("7.2");
    let st = s.wp_status(sel.clone()).await.expect("status").expect("wp");
    assert_eq!(st.wp_version, "7.2");
    assert_eq!(recorded(pool.clone(), detail.id.clone()).await, "7.2");

    // A version.php that is not a plain file is "unknown" — never written.
    std::fs::remove_file(root.join("wp-includes/version.php")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", root.join("wp-includes/version.php")).unwrap();
    assert_eq!(s.wp_version_refresh_tick().await.expect("tick"), 0);
    let st = s.wp_status(sel).await.expect("status").expect("wp");
    assert_eq!(st.wp_version, "7.2");
}

/// Runs the base-theme tick once against a recorded WordPress site whose
/// docroot is a temp dir laid out by `layout`. Any adapter call the test did
/// not expect on `mocks` fails it, which is how "wp-cli never ran" is asserted.
async fn base_theme_tick(
    mocks: MockAdapterPort,
    state: &str,
    layout: impl FnOnce(&std::path::Path),
) -> usize {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), mocks);
    s.create(req("blank.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("blank.cz").unwrap());
    let detail = s.get(sel).await.expect("get");
    let tmp = tempfile::tempdir().expect("tempdir");
    layout(tmp.path());
    sqlx::query("UPDATE hostings SET root_dir = ?, state = ? WHERE id = ?")
        .bind(tmp.path().to_str().unwrap())
        .bind(state)
        .bind(detail.id.as_str())
        .execute(&pool)
        .await
        .expect("repoint root_dir");
    wordpress::record_install(&pool, &detail.id, "https://blank.cz", "6.9", "h", 1)
        .await
        .expect("wp row");
    s.wp_base_theme_tick().await.expect("tick")
}

/// What a `--skip-content` install leaves behind: the directory and its
/// `index.php` placeholder, no theme.
fn no_themes(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("wp-content/themes")).unwrap();
    std::fs::write(root.join("wp-content/themes/index.php"), b"<?php").unwrap();
}

fn listed_theme(slug: &str) -> hyperion_types::WpTheme {
    hyperion_types::WpTheme {
        slug: slug.into(),
        name: slug.into(),
        version: "1.0".into(),
        status: "active".into(),
        update_available: false,
        latest_version: String::new(),
    }
}

#[tokio::test]
async fn base_theme_tick_repairs_a_site_with_no_theme() {
    let mut a = happy_mocks();
    a.expect_wp_theme_list()
        .times(1)
        .returning(|_, _| Ok((vec![], "6.9".into())));
    a.expect_wp_install_base_theme()
        .times(1)
        .returning(|_, _| Ok("twentytwentyfive".into()));
    assert_eq!(base_theme_tick(a, "active", no_themes).await, 1);
}

#[tokio::test]
async fn base_theme_tick_repairs_a_site_with_no_themes_directory() {
    let mut a = happy_mocks();
    a.expect_wp_theme_list()
        .times(1)
        .returning(|_, _| Ok((vec![], "6.9".into())));
    a.expect_wp_install_base_theme()
        .times(1)
        .returning(|_, _| Ok("twentytwentyfive".into()));
    assert_eq!(base_theme_tick(a, "active", |_| {}).await, 1);
}

#[tokio::test]
async fn base_theme_tick_never_runs_wp_cli_when_a_theme_is_on_disk() {
    let layout = |root: &std::path::Path| {
        no_themes(root);
        std::fs::create_dir(root.join("wp-content/themes/astra")).unwrap();
    };
    assert_eq!(base_theme_tick(happy_mocks(), "active", layout).await, 0);
}

/// A symlink is the site user's own arrangement. Root does not follow it.
#[tokio::test]
async fn base_theme_tick_leaves_a_symlinked_themes_directory_alone() {
    let layout = |root: &std::path::Path| {
        std::fs::create_dir(root.join("wp-content")).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("wp-content/themes")).unwrap();
    };
    assert_eq!(base_theme_tick(happy_mocks(), "active", layout).await, 0);
}

/// Bedrock and friends move the themes out of wp-content. The directory looks
/// empty, wp-cli knows better, and its answer decides.
#[tokio::test]
async fn base_theme_tick_trusts_wp_cli_over_an_empty_directory() {
    let mut a = happy_mocks();
    a.expect_wp_theme_list()
        .times(1)
        .returning(|_, _| Ok((vec![listed_theme("sage")], "6.9".into())));
    assert_eq!(base_theme_tick(a, "active", no_themes).await, 0);
}

/// An error says nothing about the themes, so nothing gets installed.
#[tokio::test]
async fn base_theme_tick_installs_nothing_when_wp_cli_cannot_answer() {
    let mut a = happy_mocks();
    a.expect_wp_theme_list()
        .times(1)
        .returning(|_, _| Err(AdapterError::Other("database down".into())));
    assert_eq!(base_theme_tick(a, "active", no_themes).await, 0);
}

#[tokio::test]
async fn base_theme_tick_skips_a_site_that_is_not_active() {
    assert_eq!(
        base_theme_tick(happy_mocks(), "suspended", no_themes).await,
        0
    );
}

#[tokio::test]
async fn base_theme_tick_does_not_count_a_failed_install() {
    let mut a = happy_mocks();
    a.expect_wp_theme_list()
        .times(1)
        .returning(|_, _| Ok((vec![], "6.9".into())));
    a.expect_wp_install_base_theme()
        .times(1)
        .returning(|_, _| Err(AdapterError::Other("wordpress.org unreachable".into())));
    assert_eq!(base_theme_tick(a, "active", no_themes).await, 0);
}

/// One WordPress site on disk, loader in place, recorded as installed.
async fn cron_site(
    a: MockAdapterPort,
) -> (
    SqlitePool,
    HostingService<MockAdapterPort>,
    tempfile::TempDir,
    String,
    std::path::PathBuf,
) {
    let pool = open_memory().await.expect("open");
    let home = tempfile::tempdir().expect("home");
    let s = svc(pool.clone(), a).with_paths(HostingPaths {
        home_root: home.path().display().to_string(),
        ..Default::default()
    });
    s.create(req("ex.cz")).await.expect("create");
    let d = s
        .get(HostingSelector::Domain(Domain::parse("ex.cz").unwrap()))
        .await
        .expect("get");
    let root = std::path::PathBuf::from(&d.root_dir);
    let mu = root.join("wp-content/mu-plugins");
    std::fs::create_dir_all(&mu).expect("mu-plugins");
    std::fs::write(mu.join("hyperion.php"), "<?php\n").expect("loader");
    wordpress::record_install(&pool, &d.id, "https://ex.cz", "6.9", "x", 1)
        .await
        .expect("record");
    (pool, s, home, d.id.as_str().to_string(), mu)
}

/// The module that turns WordPress's own cron off lands only after the
/// command line has worked on that site.
#[tokio::test]
async fn system_cron_disables_wp_cron_only_after_it_has_worked() {
    let mut a = happy_mocks();
    a.expect_wp_cron_run().times(1).returning(|_, _| Ok(()));
    let (pool, s, _home, id, mu) = cron_site(a).await;
    let module = mu.join("hyperion/cron.php");
    assert!(!module.exists());

    let mut last_run = std::collections::HashMap::new();
    assert_eq!(s.wp_system_cron_tick(&mut last_run).await.expect("tick"), 1);
    assert!(module.exists());
    let st = hyperion_types::wpcron::State::parse(
        &hyperion_state::hosting_kv::get(&pool, &id, hyperion_types::wpcron::KV_STATE)
            .await
            .expect("kv")
            .expect("state"),
    )
    .expect("parse");
    assert!(st.last_ok_at > 0);

    // Just ran: `times(1)` above is what proves it is not run again yet.
    assert_eq!(s.wp_system_cron_tick(&mut last_run).await.expect("tick"), 0);
}

/// A site whose cron keeps failing from the command line goes back to how
/// it was, so it does not lose cron altogether.
#[tokio::test]
async fn system_cron_falls_back_after_repeated_failure() {
    use hyperion_types::wpcron;
    let mut a = happy_mocks();
    a.expect_wp_cron_run()
        .times(wpcron::MAX_FAILS as usize)
        .returning(|_, _| Err(AdapterError::Other("fatal".into())));
    let (pool, s, _home, id, mu) = cron_site(a).await;
    let module = mu.join("hyperion/cron.php");
    std::fs::create_dir_all(module.parent().unwrap()).expect("dir");
    std::fs::write(&module, "old").expect("module");

    for _ in 0..wpcron::MAX_FAILS {
        // Fresh map: each loop stands for a run some minutes later.
        let mut last_run = std::collections::HashMap::new();
        assert_eq!(s.wp_system_cron_tick(&mut last_run).await.expect("tick"), 0);
    }
    assert!(!module.exists(), "back to WordPress's own cron");
    let st = wpcron::State::parse(
        &hyperion_state::hosting_kv::get(&pool, &id, wpcron::KV_STATE)
            .await
            .expect("kv")
            .expect("state"),
    )
    .expect("parse");
    assert!(st.retry_after > now_secs());

    // `times` above: waiting out the retry, no further run.
    let mut last_run = std::collections::HashMap::new();
    assert_eq!(s.wp_system_cron_tick(&mut last_run).await.expect("tick"), 0);
}

/// Turned off: nothing runs and the module goes. No loader (a report-only
/// site): Hyperion adds nothing.
#[tokio::test]
async fn system_cron_leaves_alone_a_site_turned_off_or_report_only() {
    let mut a = happy_mocks();
    a.expect_wp_cron_run().times(0);
    let (pool, s, _home, id, mu) = cron_site(a).await;
    let module = mu.join("hyperion/cron.php");
    std::fs::create_dir_all(module.parent().unwrap()).expect("dir");
    std::fs::write(&module, "old").expect("module");
    hyperion_state::hosting_kv::set(&pool, &id, hyperion_types::wpcron::KV_ENABLED, "off", 0)
        .await
        .expect("kv");
    let mut last_run = std::collections::HashMap::new();
    assert_eq!(s.wp_system_cron_tick(&mut last_run).await.expect("tick"), 0);
    assert!(!module.exists());

    hyperion_state::hosting_kv::delete(&pool, &id, hyperion_types::wpcron::KV_ENABLED)
        .await
        .expect("kv");
    std::fs::remove_file(mu.join("hyperion.php")).expect("loader");
    assert_eq!(s.wp_system_cron_tick(&mut last_run).await.expect("tick"), 0);
    assert!(!module.exists());
}

/// A staging copy keeps cron firing only when somebody opens it: on a timer
/// it would repeat the real site's reminders and renewals.
#[tokio::test]
async fn system_cron_leaves_a_site_kept_out_of_search_engines_alone() {
    let mut a = happy_mocks();
    a.expect_wp_cron_run().times(0);
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    let (_pool, s, _home, id, mu) = cron_site(a).await;
    let sel = HostingSelector::Id(HostingId(id));
    let mut o = s.get(sel.clone()).await.expect("get").vhost_options;
    o.noindex = true;
    s.set_vhost_options(sel, o, None).await.expect("options");
    let module = mu.join("hyperion/cron.php");
    std::fs::create_dir_all(module.parent().unwrap()).expect("dir");
    std::fs::write(&module, "old").expect("module");
    let mut last_run = std::collections::HashMap::new();
    assert_eq!(s.wp_system_cron_tick(&mut last_run).await.expect("tick"), 0);
    assert!(!module.exists());
}

/// A new WordPress site starts with the page cache on, briefly.
#[tokio::test]
async fn a_new_wordpress_site_starts_with_the_page_cache_on() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_wp_install_run()
        .returning(|_, _, _, _, _, _, _| Ok("6.9".into()));
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    let s = svc(pool, a);
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    assert!(
        !s.get(sel.clone())
            .await
            .expect("get")
            .vhost_options
            .fastcgi_cache_enabled
    );
    s.install_wordpress(
        sel.clone(),
        hyperion_types::WpInstallRequest {
            site_url: "https://ex.cz".into(),
            title: "Ex".into(),
            admin_user: "admin".into(),
            admin_email: "a@ex.cz".into(),
            admin_password: "correct horse battery".into(),
            locale: "en_US".into(),
            version: "latest".into(),
            no_index: false,
        },
    )
    .await
    .expect("install");
    let o = s.get(sel).await.expect("get").vhost_options;
    assert!(o.fastcgi_cache_enabled);
    assert_eq!(o.fastcgi_cache_ttl, 60);
}
