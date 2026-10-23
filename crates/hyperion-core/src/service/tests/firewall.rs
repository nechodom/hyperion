//! Tests for `service::firewall`.

use super::*;

#[tokio::test]
async fn prune_migration_bundle_dir_only_touches_mig_prefix() {
    // With max_age=0, "older than now" == every dir → all
    // mig_*-prefixed dirs go, everything else stays. This
    // exercises the prefix filter without needing to forge
    // mtimes (filetime isn't in workspace deps).
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let mig_a = root.join("mig_aaa");
    let mig_b = root.join("mig_bbb");
    let bundle_dir = root.join("bundle-01ABC"); // panel-import staging dir
    let inc_dir = root.join("inc_01ABC"); // import-from-url download staging
    let other = root.join("keepme");
    let plain_file = root.join("README");
    for d in [&mig_a, &mig_b, &bundle_dir, &inc_dir, &other] {
        tokio::fs::create_dir_all(d).await.unwrap();
        tokio::fs::write(d.join("archive.tar.gz"), b"x")
            .await
            .unwrap();
    }
    tokio::fs::write(&plain_file, b"hi").await.unwrap();
    // Self-service ingested bundle (flat file) + a loose .tar that's NOT ours.
    let bundle_tar = root.join("bundle-99.tar");
    let loose_tar = root.join("operator-backup.tar");
    tokio::fs::write(&bundle_tar, b"secret-dump").await.unwrap();
    tokio::fs::write(&loose_tar, b"keep").await.unwrap();

    // Sleep ~10ms so created dirs' mtime < now() at the call
    // site — without this the cutoff check (mtime < cutoff)
    // can race and skip new dirs even with max_age=0.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let n = prune_migration_bundle_dir(root, std::time::Duration::from_millis(0))
        .await
        .unwrap();
    // 2 mig_* dirs + 1 bundle-* dir + 1 inc_* dir + 1 bundle-*.tar file.
    assert_eq!(n, 5, "all mig_*/bundle-*/inc_* artifacts should be removed");
    assert!(!inc_dir.exists(), "abandoned import staging is swept");
    assert!(!mig_a.exists());
    assert!(!mig_b.exists());
    assert!(!bundle_dir.exists(), "bundle-* staging dirs are swept");
    assert!(!bundle_tar.exists(), "bundle-*.tar files are swept");
    assert!(other.exists(), "non-mig_/bundle- dirs are off-limits");
    assert!(plain_file.exists(), "loose files are off-limits");
    assert!(loose_tar.exists(), "non-bundle .tar files are off-limits");
}
