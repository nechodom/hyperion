//! The file manager's service layer: what it lists, what it agrees to open,
//! and what a save is allowed to overwrite.

use super::*;

async fn site() -> (
    HostingService<MockAdapterPort>,
    HostingSelector,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let pool = open_memory().await.expect("open");
    let home = tempfile::tempdir().expect("home");
    let s = svc(pool, happy_mocks()).with_paths(HostingPaths {
        home_root: home.path().display().to_string(),
        ..Default::default()
    });
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    let d = s.get(sel.clone()).await.expect("get");
    let root = std::path::PathBuf::from(&d.root_dir);
    std::fs::create_dir_all(&root).expect("htdocs");
    (s, sel, root, home)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test]
async fn files_with_no_telling_extension_can_be_opened() {
    let (s, sel, root, _home) = site().await;
    std::fs::write(root.join(".htaccess"), "RewriteEngine On\n").expect("write");
    std::fs::write(root.join(".env"), "KEY=1\n").expect("write");
    std::fs::write(root.join("Makefile"), "all:\n").expect("write");
    std::fs::write(root.join("logo.png"), [0x89, b'P', b'N', b'G', 0, 0]).expect("write");
    // A binary hiding behind a name that says nothing.
    std::fs::write(root.join("blob"), [1u8, 2, 0, 3]).expect("write");

    let (_, entries) = s
        .hosting_file_list(sel.clone(), String::new())
        .await
        .expect("list");
    let viewable = |n: &str| {
        entries
            .iter()
            .find(|e| e.name == n)
            .unwrap_or_else(|| panic!("{n} listed"))
            .inline_viewable
    };
    assert!(viewable(".htaccess"));
    assert!(viewable(".env"));
    assert!(viewable("Makefile"));
    assert!(!viewable("logo.png"));

    let c = s
        .hosting_file_read(sel.clone(), ".htaccess".into())
        .await
        .expect("read");
    assert_eq!(c.content, "RewriteEngine On\n");
    assert!(!c.lossy && !c.crlf && !c.version.is_empty());

    let err = s
        .hosting_file_read(sel.clone(), "blob".into())
        .await
        .expect_err("binary content is refused whatever the name");
    assert!(err.to_string().contains("binary"), "{err}");
    assert!(s.hosting_file_read(sel, "logo.png".into()).await.is_err());
}

#[tokio::test]
async fn listing_reads_like_a_person_sorts_and_reports_modes() {
    use std::os::unix::fs::PermissionsExt;
    let (s, sel, root, _home) = site().await;
    for n in ["index.php", "README", "apple.txt", "Zebra.txt"] {
        std::fs::write(root.join(n), "x").expect("write");
    }
    std::fs::create_dir(root.join("wp-content")).expect("mkdir");
    std::fs::create_dir(root.join("Assets")).expect("mkdir");
    std::fs::set_permissions(
        root.join("index.php"),
        std::fs::Permissions::from_mode(0o640),
    )
    .expect("chmod");
    std::os::unix::fs::symlink(root.join("index.php"), root.join("link")).expect("symlink");

    let (_, entries) = s.hosting_file_list(sel, String::new()).await.expect("list");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Assets",
            "wp-content",
            "apple.txt",
            "index.php",
            "link",
            "README",
            "Zebra.txt"
        ]
    );
    let by = |n: &str| entries.iter().find(|e| e.name == n).expect("entry");
    assert_eq!(by("index.php").mode, 0o640);
    assert_eq!(by("link").kind, "symlink");
    assert!(!by("link").inline_viewable);
}

#[tokio::test]
async fn text_in_a_legacy_encoding_opens_flagged() {
    let (s, sel, root, _home) = site().await;
    // "příloha\r\n" in Windows-1250.
    std::fs::write(
        root.join("old.txt"),
        [0x70, 0xF8, 0xED, 0x6C, 0x6F, 0x68, 0x61, b'\r', b'\n'],
    )
    .expect("write");
    let c = s
        .hosting_file_read(sel, "old.txt".into())
        .await
        .expect("legacy text is still readable");
    assert!(c.lossy, "and says its content is an approximation");
    assert!(c.crlf);
    assert!(c.content.starts_with('p'));
}

#[tokio::test]
async fn a_save_is_refused_when_the_file_changed_underneath() {
    let (s, sel, root, _home) = site().await;
    let f = root.join("a.txt");
    std::fs::write(&f, "one").expect("write");
    let opened = s
        .hosting_file_read(sel.clone(), "a.txt".into())
        .await
        .expect("read");
    std::fs::write(&f, "someone else was here").expect("write");

    let err = s
        .hosting_file_write(
            sel.clone(),
            "a.txt".into(),
            b64(b"mine"),
            Some(opened.version),
            false,
        )
        .await
        .expect_err("stale save");
    assert!(err.to_string().contains("changed on disk"), "{err}");
    assert_eq!(std::fs::read(&f).expect("read"), b"someone else was here");

    // Re-reading gives the version that lets the save through.
    let again = s
        .hosting_file_read(sel.clone(), "a.txt".into())
        .await
        .expect("read");
    s.hosting_file_write(
        sel.clone(),
        "a.txt".into(),
        b64(b"mine"),
        Some(again.version),
        false,
    )
    .await
    .expect("fresh save");
    assert_eq!(std::fs::read(&f).expect("read"), b"mine");

    // An older master sends no version (or an empty one): still a plain write.
    s.hosting_file_write(sel, "a.txt".into(), b64(b"old"), Some(String::new()), false)
        .await
        .expect("no version, no check");
}

#[tokio::test]
async fn a_new_file_never_replaces_one_and_a_folder_goes_only_when_asked() {
    let (s, sel, root, _home) = site().await;
    std::fs::write(root.join("keep.txt"), "keep").expect("write");
    assert!(s
        .hosting_file_write(sel.clone(), "keep.txt".into(), b64(b""), None, true)
        .await
        .is_err());
    assert_eq!(std::fs::read(root.join("keep.txt")).expect("read"), b"keep");

    std::fs::create_dir_all(root.join("cache/deep")).expect("mkdir");
    std::fs::write(root.join("cache/deep/f"), "x").expect("write");
    assert!(s
        .hosting_file_delete(sel.clone(), "cache".into(), false)
        .await
        .is_err());
    assert!(root.join("cache/deep/f").exists());
    s.hosting_file_delete(sel, "cache".into(), true)
        .await
        .expect("recursive");
    assert!(!root.join("cache").exists());
}
