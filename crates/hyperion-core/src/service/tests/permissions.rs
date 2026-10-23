//! Tests for `service::permissions`.

/// The autoheal probe must fire on exactly the tree an imported
/// CloudPanel site arrives with (0770 dirs / 0660 files), and stay
/// quiet on a healthy one — a false positive here would chmod a
/// customer's tree every 5 minutes forever.
#[test]
fn perm_probe_fires_on_archive_modes_and_not_on_healthy_trees() {
    use super::tree_denies_world_read;
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().expect("tmp");
    let root = tmp.path().join("htdocs");
    std::fs::create_dir_all(root.join("wp-includes")).expect("mkdir");
    std::fs::write(root.join("index.php"), b"<?php").expect("write");

    // Healthy: 0755/0644.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    std::fs::set_permissions(
        root.join("wp-includes"),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("chmod");
    std::fs::set_permissions(
        root.join("index.php"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod");
    assert!(!tree_denies_world_read(&root), "healthy tree must not fire");

    // The imported-CloudPanel shape: a first-level dir at 0770.
    std::fs::set_permissions(
        root.join("wp-includes"),
        std::fs::Permissions::from_mode(0o770),
    )
    .expect("chmod");
    assert!(tree_denies_world_read(&root), "0770 subdir must fire");

    // A first-level file at 0660 fires too.
    std::fs::set_permissions(
        root.join("wp-includes"),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("chmod");
    std::fs::set_permissions(
        root.join("index.php"),
        std::fs::Permissions::from_mode(0o660),
    )
    .expect("chmod");
    assert!(tree_denies_world_read(&root), "0660 file must fire");

    // The docroot itself untraversable fires.
    std::fs::set_permissions(
        root.join("index.php"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750)).expect("chmod");
    assert!(tree_denies_world_read(&root), "0750 docroot must fire");

    // Absent path: someone else's problem, never a mode problem.
    assert!(!tree_denies_world_read(std::path::Path::new(
        "/definitely/not/here"
    )));
}
