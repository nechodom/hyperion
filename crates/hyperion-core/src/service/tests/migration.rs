//! Tests for `service::migration`.

use super::*;

/// A bundle id names one directory under the migration dir: a path never
/// gets through, and a missing bundle is NotFound before any staging dir
/// is made.
#[tokio::test]
async fn local_bundle_import_refuses_paths_and_missing_bundles() {
    let pool = open_memory().await.expect("memory db");
    let s = svc(pool, MockAdapterPort::new());
    for bad in ["", "..", "../etc", "mig/../../x", "a.b"] {
        let e = s
            .hosting_import_local_bundle(bad.into(), None, Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(e, RpcError::Validation { .. }), "{bad}: {e:?}");
    }
    let e = s
        .hosting_import_local_bundle("mig_no_such_bundle_zz".into(), None, Vec::new())
        .await
        .unwrap_err();
    assert!(matches!(e, RpcError::NotFound { .. }), "{e:?}");
}

/// The clone override rewrites the STAGED manifest only. The bundle on
/// disk stays as exported, so a retried copy still finds it whole.
#[tokio::test]
async fn local_bundle_import_stages_and_leaves_the_bundle_alone() {
    let pool = open_memory().await.expect("memory db");
    let s = svc(pool, MockAdapterPort::new());
    let source = tempfile::tempdir().expect("tmp");
    let staging = tempfile::tempdir().expect("tmp");
    let manifest = r#"{"domain":"jtmotors.cz"}"#;
    std::fs::write(source.path().join("manifest.json"), manifest).expect("manifest");
    std::fs::write(source.path().join("archive.tar.gz"), b"tar").expect("archive");
    // The manifest is too thin to import, which is fine: the importer
    // refuses it before touching anything, after the staging is done.
    let _ = s
        .import_local_bundle_staged(staging.path(), source.path(), Some("copy.jtmotors.cz"), &[])
        .await;
    let staged: serde_json::Value = serde_json::from_slice(
        &std::fs::read(staging.path().join("manifest.json")).expect("staged manifest"),
    )
    .expect("json");
    assert_eq!(staged["domain"], "copy.jtmotors.cz");
    assert_eq!(staged["renamed_from"], "jtmotors.cz");
    assert_eq!(
        std::fs::read(staging.path().join("archive.tar.gz")).expect("staged archive"),
        b"tar"
    );
    assert!(!staging.path().join("archive.sql").exists());
    assert_eq!(
        std::fs::read_to_string(source.path().join("manifest.json")).expect("source"),
        manifest
    );
}

/// The migration download cap reads `[migration] max_download_gb`, defaults
/// to 64 GB, and clamps a nonsense value back to the default so the
/// disk-fill guard can neither be disabled (0) nor overflowed.
#[test]
fn migration_download_cap_reads_config_and_clamps() {
    use std::io::Write;
    let gb = 1024u64 * 1024 * 1024;
    let write = |body: &str| {
        let mut f = tempfile::NamedTempFile::new().expect("temp");
        f.write_all(body.as_bytes()).expect("write");
        f
    };
    // No path / empty file → the 64 GB default.
    assert_eq!(read_migration_max_download_bytes(None), 64 * gb);
    let empty = write("");
    assert_eq!(
        read_migration_max_download_bytes(Some(empty.path())),
        64 * gb
    );
    // A legitimate override (a 200 GB media site).
    let ok = write("[migration]\nmax_download_gb = 200\n");
    assert_eq!(read_migration_max_download_bytes(Some(ok.path())), 200 * gb);
    // Out of range clamps to the default — 0 must not disable the guard,
    // and a petabyte must not overflow it.
    let zero = write("[migration]\nmax_download_gb = 0\n");
    assert_eq!(
        read_migration_max_download_bytes(Some(zero.path())),
        64 * gb
    );
    let huge = write("[migration]\nmax_download_gb = 5000\n");
    assert_eq!(
        read_migration_max_download_bytes(Some(huge.path())),
        64 * gb
    );
}

/// A clone rewrites the manifest to a new domain; it must REPLACE the
/// source's aliases (with the operator's, or none), never keep them —
/// keeping `www.<source>` collided with the still-present source on
/// `hosting_aliases.alias_domain` and broke every clone whose source had an
/// alias.
#[tokio::test]
async fn clone_manifest_rewrite_replaces_aliases_never_keeps_the_source_ones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mf = dir.path().join("manifest.json");
    tokio::fs::write(
        &mf,
        r#"{"domain":"dluhopisar.cz","aliases":["www.dluhopisar.cz"]}"#,
    )
    .await
    .expect("write");

    // No override aliases → the source alias must be DROPPED, not carried.
    rewrite_manifest_domain(&mf, "dluh.example.cz", &[])
        .await
        .expect("rewrite");
    let v: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&mf).await.unwrap()).unwrap();
    assert_eq!(v["domain"], "dluh.example.cz");
    assert_eq!(
        v["aliases"].as_array().expect("aliases array").len(),
        0,
        "source aliases must be dropped so the clone can't collide"
    );

    // With override aliases → exactly those are used.
    rewrite_manifest_domain(&mf, "dluh2.example.cz", &["www.dluh2.example.cz".into()])
        .await
        .expect("rewrite2");
    let v2: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&mf).await.unwrap()).unwrap();
    assert_eq!(v2["aliases"][0], "www.dluh2.example.cz");
}

#[tokio::test]
async fn prune_migration_bundle_dir_missing_root_is_ok() {
    // Root doesn't exist yet — should return 0, not error.
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist");
    let n = prune_migration_bundle_dir(&missing, std::time::Duration::from_secs(60))
        .await
        .expect("missing root must be Ok");
    assert_eq!(n, 0);
}

#[tokio::test]
async fn prune_migration_bundle_dir_respects_max_age() {
    // With a generous max_age, nothing fresh should be pruned.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let mig_a = root.join("mig_fresh");
    tokio::fs::create_dir_all(&mig_a).await.unwrap();

    let n = prune_migration_bundle_dir(root, std::time::Duration::from_secs(86_400))
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(mig_a.exists());
}

/// The import skips a name a site on this node already has.
#[tokio::test]
async fn free_import_user_skips_a_taken_account() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), MockAdapterPort::new());
    system_users::insert(
        &pool,
        "my_shop_cz",
        5001,
        "/home/my_shop_cz",
        "/bin/bash",
        1,
    )
    .await
    .expect("user");
    let got = s.free_import_user("my.shop.cz").await.expect("free");
    assert_eq!(got.as_str(), "my_shop_cz_2");
    let got = s.free_import_user("other.cz").await.expect("free");
    assert_eq!(got.as_str(), "other_cz");
}

#[test]
fn crontab_paths_follow_the_site_to_its_new_tree() {
    let body = "\
# m h dom mon dow command — /home/shop_cz/shop.cz stays in comments
*/5 * * * * php /home/shop_cz/shop.cz/htdocs/wp-cron.php >/dev/null
0 3 * * * cd /home/shop_cz && ./backup.sh /home/shop_cz/shop.cz
0 4 * * * tar czf /tmp/x.tgz /home/shop_cz/shop.cz.old
0 5 * * * wp --path=/home/shop_cz/blog.cz/htdocs cron event run --due-now
HOME=/home/shop_cz
";
    let (out, notes) = rewrite_crontab_paths(
        body,
        "/home/shop_cz/shop.cz",
        "/home/copy_cz/copy.cz",
        "/home/shop_cz",
        "/home/copy_cz",
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        "# m h dom mon dow command — /home/shop_cz/shop.cz stays in comments"
    );
    assert_eq!(
        lines[1],
        "*/5 * * * * php /home/copy_cz/copy.cz/htdocs/wp-cron.php >/dev/null"
    );
    assert_eq!(
        lines[2],
        "0 3 * * * cd /home/copy_cz && ./backup.sh /home/copy_cz/copy.cz"
    );
    // `shop.cz.old` is another path, not the site's tree — and it is
    // under the source home, so it belongs to the source account.
    assert!(
        lines[3].starts_with("# hyperion: disabled on import"),
        "{}",
        lines[3]
    );
    assert!(lines[3].contains("/home/shop_cz/shop.cz.old"));
    // Another site of the source account: disabled, never repointed.
    assert!(
        lines[4].starts_with("# hyperion: disabled on import"),
        "{}",
        lines[4]
    );
    assert!(lines[4].contains("/home/shop_cz/blog.cz/htdocs"));
    assert_eq!(lines[5], "HOME=/home/copy_cz");
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(out.ends_with('\n'));
    validate_crontab(&out).expect("still a valid crontab");
}

/// A Move whose account keeps its name: the site's own lines stay,
/// lines for sites that stayed behind are still disabled.
#[test]
fn crontab_rewrite_on_a_same_named_account() {
    let body = "* * * * * php /home/a_cz/a.cz/htdocs/x.php\n\
                    * * * * * php /home/a_cz/b.cz/htdocs/x.php\n";
    let (out, notes) = rewrite_crontab_paths(
        body,
        "/home/a_cz/a.cz",
        "/home/a_cz/a.cz",
        "/home/a_cz",
        "/home/a_cz",
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "* * * * * php /home/a_cz/a.cz/htdocs/x.php");
    assert!(lines[1].starts_with("# hyperion: disabled on import"));
    assert_eq!(notes.len(), 1);
}

#[test]
fn replace_bounded_path_matches_whole_paths_only() {
    let f = |l: &str| replace_bounded_path(l, "/home/a/x.cz", "/N", true);
    assert_eq!(f("cd /home/a/x.cz"), "cd /N");
    assert_eq!(f("cd /home/a/x.cz/htdocs;ls"), "cd /N/htdocs;ls");
    assert_eq!(f("--path='/home/a/x.cz'"), "--path='/N'");
    assert_eq!(f("/home/a/x.cz.old"), "/home/a/x.cz.old");
    assert_eq!(f("/srv/home/a/x.cz"), "/srv/home/a/x.cz");
    assert_eq!(f("x/home/a/x.cz"), "x/home/a/x.cz");
    assert_eq!(
        replace_bounded_path("/home/a/b /home/a", "/home/a", "/H", false),
        "/home/a/b /H"
    );
}

/// The allow-list: configuration travels, secrets and run state never.
#[test]
fn carried_kv_allow_list() {
    for k in [
        "backup_at",
        "backup_cadence",
        "backup_target",
        "php.mem_auto",
        "php.mem_auto_max_mb",
        "php.mem_auto_state",
        "wp_auto_update",
        "regguard_enabled",
        "gitsync_repo",
    ] {
        assert_eq!(carried_kv_scope(k), Some(CarryScope::Always), "{k}");
    }
    for k in [
        "care_service_checks",
        "care_report_recipients",
        "care_report_period_end",
    ] {
        assert_eq!(carried_kv_scope(k), Some(CarryScope::MoveOnly), "{k}");
    }
    for k in [
        // secrets
        "dkim",
        "gitsync_pubkey",
        "gitsync_webhook_secret",
        // on without its (uncarried) secret = open deploy trigger
        "gitsync_webhook",
        // run state
        "backup_last_run_at",
        "quota_exceed_state",
        "waf_log_pos",
        "nginx.vhost_gen",
        "logins_locked",
        "integrity_scan",
        "staging_domain",
        "php.workers_full",
    ] {
        assert_eq!(carried_kv_scope(k), None, "{k}");
    }
    assert_eq!(
        carried_kv_scope(HostingService::<MockAdapterPort>::LETTER_LANG_KV_KEY),
        Some(CarryScope::Always)
    );
}

/// A Copy is a new site: technical settings yes; billing, plans, expiry,
/// uptime alerts and care bookkeeping no — and the www redirect is
/// dropped because the copy has no www alias.
#[tokio::test]
async fn copy_leaves_billing_plans_and_alerts_behind() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), carry_mocks());
    let src = carry_source(&s, &pool).await;
    let settings = s.collect_carried_settings(&src).await;

    s.create(req("copy.cz")).await.expect("create target");
    let tsel = HostingSelector::Domain(Domain::parse("copy.cz").expect("parse"));
    let target = s.get(tsel.clone()).await.expect("get");
    let report = s
        .apply_carried_settings(&target, Some(&settings), true)
        .await;
    let tid = target.id.as_str();

    let l = s.get_limits(tsel.clone()).await.expect("limits");
    assert_eq!(l.php_memory_mb, 768);
    assert_eq!(
        hyperion_state::hosting_kv::get(&pool, tid, "backup_at")
            .await
            .expect("kv")
            .as_deref(),
        Some("03:30")
    );
    assert_eq!(
        hyperion_state::hosting_kv::get(&pool, tid, "care_service_checks")
            .await
            .expect("kv"),
        None
    );
    let t = s.get(tsel.clone()).await.expect("get");
    assert!(t.vhost_options.noindex);
    assert_eq!(t.vhost_options.canonical_host, "");
    assert!(
        report.iter().any(|l| l.starts_with("canonical host www")),
        "{report:#?}"
    );
    assert!(
        report
            .iter()
            .any(|l| l.contains("a copy is a new site") && l.contains("care plans (1)")),
        "{report:#?}"
    );
    assert_eq!(
        profiles::get_apply(&pool, &t.id).await.expect("apply"),
        None
    );
    assert!(hyperion_state::packages::list_for_hosting(&pool, &t.id)
        .await
        .expect("plans")
        .is_empty());
    // The copy keeps whatever monitoring a new site gets, not the
    // original's alert settings.
    assert!(!hyperion_state::monitors::get(&pool, &t.id)
        .await
        .expect("monitor")
        .is_some_and(|m| m.url_path == "/health" || m.alert_email.is_some()));
}

/// Extra FTP logins travel as the name the operator chose and the
/// landing directory relative to the document root — the composed login
/// and the absolute path belong to the source.
#[tokio::test]
async fn ftp_logins_are_exported_by_name_and_relative_path() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), carry_mocks());
    s.create(req("ftp.cz")).await.expect("create");
    let d = s
        .get(HostingSelector::Domain(
            Domain::parse("ftp.cz").expect("parse"),
        ))
        .await
        .expect("get");
    hyperion_state::ftp_accounts::insert(
        &pool,
        &d.id,
        "deploy.ftp.cz",
        &format!("{}/wp-content/uploads", d.root_dir),
        "agency",
        "kevin",
        1,
    )
    .await
    .expect("ftp");
    let got = s.collect_carried_settings(&d).await.ftp_logins;
    assert_eq!(
        got,
        vec![hyperion_types::migration::CarriedFtpLogin {
            name: "deploy".into(),
            path: "wp-content/uploads".into(),
            label: "agency".into(),
        }]
    );
}

/// A pasted-URL bundle loses its raw nginx snippet and says so; one
/// without a snippet (or without settings at all) is left untouched.
#[test]
fn raw_nginx_snippet_is_stripped_from_foreign_bundles() {
    let mut v = serde_json::json!({
        "domain": "x.cz",
        "settings": {
            "vhost_options": { "custom_nginx_snippet": "location /x { alias /etc/; }",
                               "noindex": true },
            "not_carried": []
        }
    });
    assert!(strip_raw_nginx_snippet_json(&mut v));
    let st: hyperion_types::migration::HostingCarriedSettings =
        serde_json::from_value(v["settings"].clone()).expect("still parses");
    let o = st.vhost_options.expect("options");
    assert_eq!(o.custom_nginx_snippet, "");
    assert!(o.noindex, "the rest of the options stay");
    assert!(st.not_carried[0].starts_with("Custom nginx snippet: dropped"));

    let mut empty =
        serde_json::json!({"settings": {"vhost_options": {"custom_nginx_snippet": ""}}});
    assert!(!strip_raw_nginx_snippet_json(&mut empty));
    let mut old = serde_json::json!({"domain": "x.cz"});
    assert!(!strip_raw_nginx_snippet_json(&mut old));
}

/// Carried vhost options get the panel's validation: a bundle naming a
/// redirect target nginx would choke on (or worse) is refused, and the
/// site keeps the defaults it was created with.
#[tokio::test]
async fn carried_vhost_options_are_validated() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), carry_mocks());
    s.create(req("val.cz")).await.expect("create");
    let d = s
        .get(HostingSelector::Domain(
            Domain::parse("val.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let mut opts = d.vhost_options.clone();
    opts.redirect_url = "javascript:alert(1)".into();
    opts.noindex = true;
    let settings = hyperion_types::migration::HostingCarriedSettings {
        vhost_options: Some(opts),
        ..Default::default()
    };
    let report = s.apply_carried_settings(&d, Some(&settings), false).await;
    assert!(
        report
            .iter()
            .any(|l| l.starts_with("vhost options: NOT carried — refused")),
        "{report:#?}"
    );
    let t = s.get(HostingSelector::Id(d.id.clone())).await.expect("get");
    assert_eq!(t.vhost_options, d.vhost_options);
}

/// A bundle from before settings travelled is reported as such, never
/// as "nothing to carry".
#[tokio::test]
async fn old_bundle_reports_settings_not_carried() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), carry_mocks());
    s.create(req("old.cz")).await.expect("create");
    let d = s
        .get(HostingSelector::Domain(
            Domain::parse("old.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let report = s.apply_carried_settings(&d, None, false).await;
    assert_eq!(report.len(), 1);
    assert!(report[0].starts_with("settings NOT carried"), "{report:?}");
}

/// A Move reaching a node without ModSecurity says the rule set did not
/// come along instead of rendering a vhost that pretends it did.
#[tokio::test]
async fn crs_without_modsecurity_is_reported() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), carry_mocks());
    s.create(req("crs.cz")).await.expect("create");
    let d = s
        .get(HostingSelector::Domain(
            Domain::parse("crs.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let mut opts = d.vhost_options.clone();
    opts.crs_mode = "block".into();
    let settings = hyperion_types::migration::HostingCarriedSettings {
        vhost_options: Some(opts),
        ..Default::default()
    };
    let report = s.apply_carried_settings(&d, Some(&settings), false).await;
    assert!(
        report
            .iter()
            .any(|l| l.starts_with("OWASP Core Rule Set: NOT carried")),
        "{report:#?}"
    );
    let t = s.get(HostingSelector::Id(d.id.clone())).await.expect("get");
    assert_eq!(
        t.vhost_options.crs_settings().mode,
        hyperion_types::crs::CrsMode::Off
    );
}
