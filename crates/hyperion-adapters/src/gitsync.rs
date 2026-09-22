//! Git deploy: make a hosting's webroot match a branch of a GitHub repository.
//!
//! SECURITY. The checkout writes into a tenant-owned tree, so every git and
//! rsync command runs as the SITE's own unix user via `sudo -H -u <user>`, the
//! same dropped-privilege sandbox wp-cli and the Lighthouse runner use — a
//! symlink a hostile tenant plants in the webroot then reaches only what that
//! tenant already can. Credentials never touch a command line: a deploy key is
//! handed to `ssh` with `-i <file>`, a token is fed through `GIT_ASKPASS`, and
//! both live in a per-run directory that is removed afterwards. `.git` is never
//! copied into the webroot — the repo is cloned to a sibling directory and the
//! tree (or a sub-directory of it) is rsynced across, so the source history is
//! never web-served.

use crate::cmd;
use crate::AdapterError;
use hyperion_types::gitsync::GitSyncLast;

/// Which credential to authenticate with, carrying the secret material for the
/// duration of one sync only.
pub enum Auth {
    Public,
    /// The PEM of the ed25519 private deploy key.
    DeployKey(String),
    /// A read-only personal access token.
    Pat(String),
}

/// Is `git` installed on this node?
pub async fn git_available() -> bool {
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            cmd::run("/usr/bin/git", &["--version"]),
        )
        .await,
        Ok(Ok(_))
    )
}

/// A GitHub repository URL, https or ssh, nothing else. The value reaches a
/// command line as a git argument (never a shell), so the check is about
/// pointing the deploy somewhere sane, not about escaping.
pub fn valid_repo(url: &str) -> bool {
    let u = url.trim();
    if u.len() > 400 || u.contains(char::is_whitespace) || u.starts_with('-') {
        return false;
    }
    let https = u.strip_prefix("https://github.com/");
    let ssh = u.strip_prefix("git@github.com:");
    let path = match (https, ssh) {
        (Some(p), _) | (_, Some(p)) => p,
        _ => return false,
    };
    let path = path.strip_suffix(".git").unwrap_or(path);
    // owner/repo, each a normal GitHub name segment.
    let mut parts = path.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let seg_ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    seg_ok(owner) && seg_ok(repo)
}

/// A git ref / branch name: safe characters only, and never a leading `-` (which
/// git would read as an option, not a ref).
pub fn valid_branch(b: &str) -> bool {
    let b = b.trim();
    !b.is_empty()
        && b.len() <= 200
        && !b.starts_with('-')
        && !b.contains("..")
        && b.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'/'))
}

/// A webroot sub-directory: relative, no traversal, no leading `-`.
pub fn valid_subdir(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return true;
    }
    !s.starts_with('/')
        && !s.starts_with('-')
        && s.len() <= 300
        && s.split('/').all(|seg| {
            !seg.is_empty()
                && seg != ".."
                && seg != "."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

/// Rewrite an https GitHub URL to its ssh form (deploy keys authenticate over
/// ssh). An already-ssh URL is returned unchanged.
fn to_ssh_url(url: &str) -> String {
    if let Some(path) = url.trim().strip_prefix("https://github.com/") {
        format!("git@github.com:{path}")
    } else {
        url.trim().to_string()
    }
}

/// Rewrite an ssh GitHub URL to https with a token username. The token is NOT
/// here — it rides in `GIT_ASKPASS`; only the constant username goes in the URL.
fn to_https_url(url: &str) -> String {
    let path = if let Some(p) = url.trim().strip_prefix("git@github.com:") {
        p.to_string()
    } else if let Some(p) = url.trim().strip_prefix("https://github.com/") {
        p.to_string()
    } else {
        url.trim().to_string()
    };
    format!("https://x-access-token@github.com/{path}")
}

/// Generate an ed25519 deploy keypair. Runs as ROOT in a root-only temp — key
/// generation never touches the tenant tree, only the checkout does — and
/// returns `(private_pem, public_line)`. The caller stores the private half in
/// the node's secret store and shows the public half to the operator.
pub async fn generate_deploy_key() -> Result<(String, String), AdapterError> {
    let dir = format!("/run/hyperion/gitsync-keygen-{}", std::process::id());
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| AdapterError::Other(format!("keygen dir: {e}")))?;
    set_mode(std::path::Path::new(&dir), 0o700)
        .await
        .map_err(|e| AdapterError::Other(format!("keygen dir mode: {e}")))?;
    let key = format!("{dir}/id");
    let res = cmd::run(
        "/usr/bin/ssh-keygen",
        &[
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "hyperion-gitsync",
            "-f",
            &key,
        ],
    )
    .await;
    let out = async {
        res?;
        let priv_pem = tokio::fs::read_to_string(&key)
            .await
            .map_err(|e| AdapterError::Other(format!("read private key: {e}")))?;
        let pub_line = tokio::fs::read_to_string(format!("{key}.pub"))
            .await
            .map_err(|e| AdapterError::Other(format!("read public key: {e}")))?;
        Ok::<_, AdapterError>((priv_pem, pub_line.trim().to_string()))
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    out
}

/// Inputs for one deploy.
pub struct SyncParams<'a> {
    pub repo: &'a str,
    pub branch: &'a str,
    /// Relative webroot sub-directory, or empty for the repo root.
    pub subdir: &'a str,
    /// The site's document root (its htdocs).
    pub htdocs: &'a str,
    /// The site's unix user; git and rsync run as this user.
    pub run_as: &'a str,
    /// The site user's home, for HOME/known_hosts.
    pub home_dir: &'a str,
    pub auth: Auth,
}

/// Deploy: clone-or-update the repo to a sibling of the webroot, then mirror the
/// tree (or `subdir`) into the webroot. Returns the deployed commit.
pub async fn sync(p: SyncParams<'_>) -> Result<GitSyncLast, AdapterError> {
    if !valid_repo(p.repo) {
        return Err(AdapterError::Other(format!(
            "not a GitHub repo: {:?}",
            p.repo
        )));
    }
    if !valid_branch(p.branch) {
        return Err(AdapterError::Other(format!("not a branch: {:?}", p.branch)));
    }
    if !valid_subdir(p.subdir) {
        return Err(AdapterError::Other(format!(
            "not a webroot sub-directory: {:?}",
            p.subdir
        )));
    }
    if p.run_as.trim().is_empty()
        || !p
            .run_as
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(AdapterError::Other(format!(
            "not a system user: {:?}",
            p.run_as
        )));
    }

    // The repo is cloned to a sibling of htdocs, NOT into it: `.git` must never
    // be web-served, and the webroot is a mirror of a sub-tree, not the checkout.
    let htdocs = p.htdocs.trim_end_matches('/');
    let site_dir = std::path::Path::new(htdocs)
        .parent()
        .ok_or_else(|| AdapterError::Other(format!("webroot has no parent: {htdocs}")))?
        .to_string_lossy()
        .to_string();
    let repo_dir = format!("{site_dir}/.hyperion-gitsync");

    // Per-run credential dir, owned by the site user, removed at the end.
    let run_dir = format!("/run/hyperion/gitsync-run-{}", std::process::id());
    let _ = run_as_root_mkdir(&run_dir, p.run_as).await;

    let result = sync_inner(&p, htdocs, &repo_dir, &run_dir).await;
    let _ = tokio::fs::remove_dir_all(&run_dir).await;
    result
}

/// Create `dir` owned by `user`, 0700. Root does the mkdir (the dir lives under
/// root-owned /run), then hands it to the site user so the credential written
/// inside is readable by the git it runs.
async fn run_as_root_mkdir(dir: &str, user: &str) -> Result<(), AdapterError> {
    let _ = tokio::fs::remove_dir_all(dir).await;
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| AdapterError::Other(format!("run dir: {e}")))?;
    set_mode(std::path::Path::new(dir), 0o700).await.ok();
    cmd::run("/bin/chown", &[user, dir]).await?;
    Ok(())
}

async fn sync_inner(
    p: &SyncParams<'_>,
    htdocs: &str,
    repo_dir: &str,
    run_dir: &str,
) -> Result<GitSyncLast, AdapterError> {
    let cache = format!(
        "{}/.hyperion-gitsync-home",
        p.home_dir.trim_end_matches('/')
    );
    let (clone_url, mut git_env): (String, Vec<(String, String)>) = match &p.auth {
        Auth::Public => (to_https_url(p.repo).replace("x-access-token@", ""), vec![]),
        Auth::DeployKey(pem) => {
            let key = format!("{run_dir}/id");
            write_run_secret(&key, pem.as_bytes(), p.run_as).await?;
            let known = format!("{run_dir}/known_hosts");
            let ssh = format!(
                "/usr/bin/ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
                 -o UserKnownHostsFile={known} -o BatchMode=yes"
            );
            (to_ssh_url(p.repo), vec![("GIT_SSH_COMMAND".into(), ssh)])
        }
        Auth::Pat(token) => {
            // GIT_ASKPASS prints the token as the password; the username is the
            // constant `x-access-token` already in the URL. The token reaches
            // the script through a 0600 file the site user owns, never argv.
            let tok_file = format!("{run_dir}/token");
            write_run_secret(&tok_file, token.as_bytes(), p.run_as).await?;
            let askpass = format!("{run_dir}/askpass");
            let script = format!("#!/bin/sh\ncat {tok_file}\n");
            write_run_secret(&askpass, script.as_bytes(), p.run_as).await?;
            cmd::run("/bin/chmod", &["0700", &askpass]).await?;
            (
                to_https_url(p.repo),
                vec![
                    ("GIT_ASKPASS".into(), askpass),
                    ("GIT_TERMINAL_PROMPT".into(), "0".into()),
                ],
            )
        }
    };
    git_env.push(("HOME".into(), cache.clone()));
    git_env.push(("GIT_CONFIG_NOSYSTEM".into(), "1".into()));

    // Cache/home for git, and the repo dir, owned by the site user.
    site_mkdir(p.run_as, &cache).await?;

    let has_git = tokio::fs::try_exists(format!("{repo_dir}/.git"))
        .await
        .unwrap_or(false);
    if has_git {
        run_git(
            p,
            &git_env,
            &["-C", repo_dir, "fetch", "--depth", "1", "origin", p.branch],
        )
        .await?;
        run_git(
            p,
            &git_env,
            &[
                "-C",
                repo_dir,
                "reset",
                "--hard",
                &format!("origin/{}", p.branch),
            ],
        )
        .await?;
    } else {
        // A fresh, shallow clone of one branch.
        site_mkdir(p.run_as, repo_dir).await?;
        run_git(
            p,
            &git_env,
            &[
                "clone",
                "--depth",
                "1",
                "--branch",
                p.branch,
                "--single-branch",
                &clone_url,
                repo_dir,
            ],
        )
        .await?;
    }

    // Mirror the tree (or a sub-directory of it) into the webroot, dropping
    // `.git` so history is never served. A trailing slash on the source makes
    // rsync copy its CONTENTS.
    let src = if p.subdir.trim().is_empty() {
        format!("{repo_dir}/")
    } else {
        format!("{}/{}/", repo_dir, p.subdir.trim().trim_matches('/'))
    };
    if !tokio::fs::try_exists(src.trim_end_matches('/'))
        .await
        .unwrap_or(false)
    {
        return Err(AdapterError::Other(format!(
            "the branch has no directory {:?} to deploy",
            p.subdir
        )));
    }
    let dst = format!("{htdocs}/");
    run_site(
        p.run_as,
        &cache,
        &[],
        "/usr/bin/rsync",
        &["-a", "--delete", "--exclude", ".git", &src, &dst],
    )
    .await?;

    // Read what we deployed: short sha + subject.
    let sha = run_git(
        p,
        &git_env,
        &["-C", repo_dir, "rev-parse", "--short", "HEAD"],
    )
    .await?
    .trim()
    .to_string();
    let subject = run_git(p, &git_env, &["-C", repo_dir, "log", "-1", "--pretty=%s"])
        .await
        .unwrap_or_default()
        .trim()
        .chars()
        .take(200)
        .collect::<String>();
    Ok(GitSyncLast {
        at: 0, // stamped by the caller
        commit: sha,
        status: "ok".into(),
        message: subject,
        trigger: String::new(),
    })
}

/// Write a per-run secret file 0600 owned by the site user.
async fn write_run_secret(path: &str, content: &[u8], user: &str) -> Result<(), AdapterError> {
    tokio::fs::write(path, content)
        .await
        .map_err(|e| AdapterError::Other(format!("write run secret: {e}")))?;
    set_mode(std::path::Path::new(path), 0o600)
        .await
        .map_err(|e| AdapterError::Other(format!("run secret mode: {e}")))?;
    cmd::run("/bin/chown", &[user, path]).await?;
    Ok(())
}

/// `mkdir -p <dir>` as the site user (so the tree is site-owned from the top).
async fn site_mkdir(user: &str, dir: &str) -> Result<(), AdapterError> {
    run_site(user, dir, &[], "/bin/mkdir", &["-p", dir])
        .await
        .map(|_| ())
}

/// Run `git` as the site user with the deploy environment.
async fn run_git(
    p: &SyncParams<'_>,
    env: &[(String, String)],
    args: &[&str],
) -> Result<String, AdapterError> {
    let cache = format!(
        "{}/.hyperion-gitsync-home",
        p.home_dir.trim_end_matches('/')
    );
    run_site(p.run_as, &cache, env, "/usr/bin/git", args).await
}

/// `sudo -H -u <user> /usr/bin/env HOME=<home> <env…> <program> <args…>` — the
/// wp-cli / Lighthouse shape, so the child has a writable HOME and never any
/// privilege beyond the tenant's own.
async fn run_site(
    user: &str,
    home: &str,
    env: &[(String, String)],
    program: &str,
    args: &[&str],
) -> Result<String, AdapterError> {
    let mut argv: Vec<String> = vec![
        "-H".into(),
        "-u".into(),
        user.into(),
        "/usr/bin/env".into(),
        format!("HOME={}", home.trim_end_matches('/')),
    ];
    for (k, v) in env {
        argv.push(format!("{k}={v}"));
    }
    argv.push(program.into());
    argv.extend(args.iter().map(|s| s.to_string()));
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    // A hung network op must not wedge the job.
    tokio::time::timeout(
        std::time::Duration::from_secs(600),
        cmd::run_capturing_all("/usr/bin/sudo", &borrowed),
    )
    .await
    .map_err(|_| AdapterError::Other(format!("{program} timed out")))?
}

async fn set_mode(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_urls() {
        assert!(valid_repo("https://github.com/owner/repo"));
        assert!(valid_repo("https://github.com/owner/repo.git"));
        assert!(valid_repo("git@github.com:owner/repo.git"));
        assert!(!valid_repo("https://gitlab.com/owner/repo")); // github only
        assert!(!valid_repo("https://github.com/owner")); // no repo
        assert!(!valid_repo("https://github.com/owner/repo/extra"));
        assert!(!valid_repo("-oProxyCommand=evil")); // arg injection
        assert!(!valid_repo("https://github.com/owner/repo world"));
    }

    #[test]
    fn branches_and_subdirs() {
        assert!(valid_branch("main"));
        assert!(valid_branch("release/1.x"));
        assert!(!valid_branch("--upload-pack=evil"));
        assert!(!valid_branch("a b"));
        assert!(!valid_branch("a..b"));
        assert!(valid_subdir(""));
        assert!(valid_subdir("public"));
        assert!(valid_subdir("dist/site"));
        assert!(!valid_subdir("../etc"));
        assert!(!valid_subdir("/abs"));
        assert!(!valid_subdir("a/../b"));
    }

    #[test]
    fn url_rewrites_never_carry_the_token() {
        assert_eq!(
            to_ssh_url("https://github.com/o/r.git"),
            "git@github.com:o/r.git"
        );
        let https = to_https_url("git@github.com:o/r.git");
        assert_eq!(https, "https://x-access-token@github.com/o/r.git");
        assert!(!https.contains("ghp_")); // never the secret
    }
}
