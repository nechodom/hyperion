//! Git deploy against REAL GitHub, as a REAL site user, on a real Debian box.
//!
//! Ignored by default: it needs root, Linux, `git`/`rsync`/`sudo`/`ssh`, a
//! throwaway machine (it creates a unix user) and network access to
//! github.com. Run it in a container:
//!
//! ```text
//! docker run --rm --tmpfs /run:rw,nosuid,nodev,noexec \
//!   -v "$PWD":/src:ro -w /src rust:1-bookworm sh -c '
//!   apt-get update -qq && apt-get install -y -qq git rsync sudo openssh-client >/dev/null &&
//!   mkdir -p /run/hyperion &&
//!   cargo test -p hyperion-adapters --test gitsync_live -- --ignored --test-threads=1'
//! ```
//!
//! Public repositories only — a deploy key that GitHub does not know still
//! proves the ssh path (host-key pinning, the key reaching ssh, the refusal
//! being explained), without any credential in the test.
//!
//! `/run` is a `noexec` tmpfs above because that is how Debian mounts it on a
//! real node — a token deploy that tried to exec a helper from the run
//! directory failed there and nowhere else.

use hyperion_adapters::gitsync::{self, Auth, SyncParams};
use std::path::Path;
use std::process::Command;

const USER: &str = "gslive";
const HOME: &str = "/home/gslive";
const HTDOCS: &str = "/home/gslive/example.test/htdocs";

fn sh(cmd: &str) {
    let ok = Command::new("sh").arg("-c").arg(cmd).status().unwrap();
    assert!(ok.success(), "setup failed: {cmd}");
}

/// A site laid out like Hyperion lays one out: the user's home and the
/// htdocs owned by the site user, the site directory between them ROOT's
/// (`ensure_dirs` creates it as root and chowns only htdocs/logs/tmp). A
/// user-owned site directory here is what hid the first-deploy
/// "mkdir … Permission denied" on every real node.
fn site() {
    sh(&format!(
        "id {USER} >/dev/null 2>&1 || useradd -m -d {HOME} -s /usr/sbin/nologin {USER}; \
         rm -rf {HOME}/example.test {HOME}/.hyperion-gitsync; mkdir -p {HTDOCS}; \
         echo 'placeholder' > {HTDOCS}/index.html; \
         chown -R {USER}:{USER} {HOME}; chown root:root {HOME}/example.test; \
         chmod 0755 {HOME}/example.test; mkdir -p /run/hyperion"
    ));
}

const SITE_KEY: &str = "01a1873b-6223-73e2-a29a-45c86c38b7c0";
const CHECKOUT: &str = "/home/gslive/.hyperion-gitsync/01a1873b-6223-73e2-a29a-45c86c38b7c0";

fn params<'a>(repo: &'a str, branch: &'a str, subdir: &'a str, auth: Auth) -> SyncParams<'a> {
    SyncParams {
        repo,
        branch,
        subdir,
        htdocs: HTDOCS,
        run_as: USER,
        home_dir: HOME,
        site_key: SITE_KEY,
        auth,
    }
}

fn exists(p: &str) -> bool {
    Path::new(&format!("{HTDOCS}/{p}")).exists()
}

fn owner_uid(p: &str) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("{HTDOCS}/{p}")).unwrap().uid()
}

#[tokio::test]
#[ignore]
async fn deploys_switches_repo_and_branch_and_explains_failures() {
    site();

    // 1. A public repository: the webroot becomes the branch, the placeholder
    //    goes, `.git` is never served, files belong to the site user.
    let last = gitsync::sync(params(
        "https://github.com/octocat/Spoon-Knife",
        "main",
        "",
        Auth::Public,
    ))
    .await
    .expect("public deploy");
    assert_eq!(last.status, "ok");
    assert_eq!(last.commit.len(), 7, "{last:?}");
    assert!(exists("index.html") && exists("styles.css"));
    assert!(!std::fs::read_to_string(format!("{HTDOCS}/index.html"))
        .unwrap()
        .contains("placeholder"));
    assert!(!exists(".git"), ".git must never reach the webroot");
    assert!(Path::new(&format!("{CHECKOUT}/repo/.git")).exists());
    // The checkout holds the whole branch: other local users must not read it.
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata("/home/gslive/.hyperion-gitsync")
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
    let uid = Command::new("id").args(["-u", USER]).output().unwrap();
    let uid: u32 = String::from_utf8_lossy(&uid.stdout).trim().parse().unwrap();
    assert_eq!(owner_uid("index.html"), uid);

    // 2. Pasted in a browser form + a CHANGED repository: the existing
    //    checkout must follow the new origin, and the old repo's files go.
    let last = gitsync::sync(params(
        "https://github.com/octocat/Hello-World/tree/master",
        "master",
        "",
        Auth::Public,
    ))
    .await
    .expect("switch repo");
    assert_eq!(last.status, "ok");
    assert!(exists("README"), "Hello-World has a README");
    assert!(
        !exists("styles.css"),
        "the previous repo's files must be gone"
    );

    // 3. A CHANGED branch on the same checkout.
    let last = gitsync::sync(params(
        "https://github.com/octocat/Hello-World",
        "test",
        "",
        Auth::Public,
    ))
    .await
    .expect("switch branch");
    assert_eq!(last.status, "ok");

    // 4. A sub-directory as the webroot.
    let last = gitsync::sync(params(
        "https://github.com/github/gitignore",
        "main",
        "Global",
        Auth::Public,
    ))
    .await
    .expect("subdir deploy");
    assert_eq!(last.status, "ok");
    assert!(exists("macOS.gitignore"), "Global/ contents at the webroot");
    assert!(!exists("Global"));

    // 5. Failures say what to do.
    let (msg, _) = gitsync::sync(params(
        "https://github.com/github/gitignore",
        "main",
        "no-such-dir",
        Auth::Public,
    ))
    .await
    .unwrap_err();
    assert!(msg.contains("no directory"), "{msg}");
    assert!(
        exists("macOS.gitignore"),
        "a refused deploy leaves the site alone"
    );

    let (msg, _) = gitsync::sync(params(
        "https://github.com/octocat/Hello-World",
        "no-such-branch-xyz",
        "",
        Auth::Public,
    ))
    .await
    .unwrap_err();
    assert!(msg.contains("no branch"), "{msg}");

    let (msg, detail) = gitsync::sync(params(
        "https://github.com/hyperion-nonexistent-owner-zz/private-or-missing",
        "main",
        "",
        Auth::Public,
    ))
    .await
    .unwrap_err();
    assert!(msg.contains("private"), "{msg} / {detail}");

    // 6. The ssh path with a key GitHub has never seen: the pinned host key
    //    must be ACCEPTED (no "host key" error) and the key itself refused.
    let (pem, public) = gitsync::generate_deploy_key("example.test")
        .await
        .expect("keygen");
    assert!(public.starts_with("ssh-ed25519 ") && public.ends_with("example.test"));
    let (msg, detail) = gitsync::sync(params(
        "https://github.com/octocat/Hello-World",
        "master",
        "",
        Auth::DeployKey(pem.clone()),
    ))
    .await
    .unwrap_err();
    assert!(
        msg.contains("refused the deploy key") || msg.contains("no repository this deploy key"),
        "{msg} / {detail}"
    );
    assert!(
        !detail.to_ascii_lowercase().contains("host key"),
        "{detail}"
    );

    // 7. A token GitHub does not accept. (On a PUBLIC repository GitHub never
    //    asks for it and the deploy simply works, so this needs one that is
    //    not public: only then does git hand over the token, and get refused.)
    let (msg, detail) = gitsync::sync(params(
        "https://github.com/hyperion-nonexistent-owner-zz/private-or-missing",
        "master",
        "",
        Auth::Pat("github_pat_not_a_real_token_0000".into()),
    ))
    .await
    .unwrap_err();
    assert!(msg.contains("token"), "{msg} / {detail}");
    // …and refused BY GITHUB: the token was handed over. "Could not read
    // Password" (or "cannot exec") is the same sentence above but means git
    // never got the token at all.
    let lc = detail.to_ascii_lowercase();
    assert!(
        !lc.contains("cannot exec") && !lc.contains("could not read password"),
        "{detail}"
    );

    // 8. The access check touches nothing and finds the branch.
    let c = gitsync::check(params(
        "https://github.com/octocat/Hello-World",
        "master",
        "",
        Auth::Public,
    ))
    .await;
    assert!(c.ok, "{c:?}");
    assert_eq!(c.commit.len(), 7);
    let c = gitsync::check(params(
        "https://github.com/octocat/Hello-World",
        "nope-nope",
        "",
        Auth::Public,
    ))
    .await;
    assert!(!c.ok && c.message.contains("no branch"), "{c:?}");

    // 9. No per-run credential directory is left behind.
    let leftovers: Vec<_> = std::fs::read_dir("/run/hyperion")
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("gitsync-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // 10. Disconnect removes the checkout, keeps the site.
    gitsync::remove_checkout(HTDOCS, USER, HOME, SITE_KEY).await;
    assert!(!Path::new(CHECKOUT).exists());
    assert!(exists("macOS.gitignore"));
}
