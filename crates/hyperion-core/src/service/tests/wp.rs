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
