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
//! never web-served. GitHub's ssh host keys are PINNED (see
//! [`GITHUB_KNOWN_HOSTS`]): the per-run `known_hosts` is thrown away after each
//! deploy, so trust-on-first-use there would have meant trusting whoever
//! answered on port 22 every single time.

use crate::cmd;
use crate::AdapterError;
use hyperion_types::gitsync::{parse_repo, GitSyncCheck, GitSyncLast, RepoRef};
use std::time::Duration;

const GIT: &str = "/usr/bin/git";
const RSYNC: &str = "/usr/bin/rsync";
const SSH: &str = "/usr/bin/ssh";
const SUDO: &str = "/usr/bin/sudo";

/// Root-owned runtime directory (systemd `RuntimeDirectory=hyperion`, 0755).
/// Per-run credential directories go under it, never into the tenant tree.
const RUN_BASE: &str = "/run/hyperion";

/// A network step (clone, fetch, ls-remote) may take this long before the
/// whole process group is killed.
const NET_TIMEOUT: Duration = Duration::from_secs(600);
/// A local step (reset, rsync, rev-parse).
const LOCAL_TIMEOUT: Duration = Duration::from_secs(300);

/// GitHub's published ssh host keys (`https://api.github.com/meta` →
/// `ssh_keys`), pinned. If GitHub ever rotates them a deploy fails with a
/// host-key error that says exactly that, rather than silently trusting a
/// stranger.
pub const GITHUB_KNOWN_HOSTS: &str = "\
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
";

/// Which credential to authenticate with, carrying the secret material for the
/// duration of one run only.
pub enum Auth {
    Public,
    /// The PEM of the ed25519 private deploy key.
    DeployKey(String),
    /// A read-only personal access token.
    Pat(String),
}

impl Auth {
    fn kind(&self) -> AuthKind {
        match self {
            Auth::Public => AuthKind::Public,
            Auth::DeployKey(_) => AuthKind::DeployKey,
            Auth::Pat(_) => AuthKind::Pat,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    Public,
    DeployKey,
    Pat,
}

/// Is `git` installed on this node?
pub async fn git_available() -> bool {
    exists(GIT).await
}

/// The programs a deploy needs that this node lacks. `ssh` only matters for a
/// deploy key. Empty = ready.
pub async fn missing_tools(needs_ssh: bool) -> Vec<String> {
    let mut out = Vec::new();
    for (name, path) in [("git", GIT), ("rsync", RSYNC), ("sudo", SUDO)] {
        if !exists(path).await {
            out.push(name.to_string());
        }
    }
    if needs_ssh && !exists(SSH).await {
        out.push("ssh".to_string());
    }
    out
}

async fn exists(path: &str) -> bool {
    tokio::fs::try_exists(path).await.unwrap_or(false)
}

/// A GitHub repository URL, in any form [`parse_repo`] accepts.
pub fn valid_repo(url: &str) -> bool {
    parse_repo(url).is_some()
}

/// A git ref / branch name: safe characters only, and never a leading `-` (which
/// git would read as an option, not a ref).
pub fn valid_branch(b: &str) -> bool {
    let b = b.trim();
    !b.is_empty()
        && b.len() <= 200
        && !b.starts_with('-')
        && !b.starts_with('/')
        && !b.ends_with('/')
        && !b.ends_with(".lock")
        && !b.contains("..")
        && !b.contains("//")
        && b.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'/'))
}

/// A webroot sub-directory: relative, no traversal, no leading `-`.
pub fn valid_subdir(s: &str) -> bool {
    let s = s.trim().trim_end_matches('/');
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
                && seg != ".git"
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

/// Generate an ed25519 deploy keypair. Runs as ROOT in a root-only temp — key
/// generation never touches the tenant tree, only the checkout does — and
/// returns `(private_pem, public_line)`. The caller stores the private half in
/// the node's secret store and shows the public half to the operator.
pub async fn generate_deploy_key(comment: &str) -> Result<(String, String), AdapterError> {
    let dir = format!("{RUN_BASE}/gitsync-keygen-{}", random_tag());
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| AdapterError::Other(format!("keygen dir: {e}")))?;
    set_mode(&dir, 0o700)
        .await
        .map_err(|e| AdapterError::Other(format!("keygen dir mode: {e}")))?;
    let key = format!("{dir}/id");
    // The comment shows in GitHub's deploy-key list, so the operator can tell
    // which site a key belongs to. Plain characters only: it is an argument.
    let comment: String = comment
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
        .take(80)
        .collect();
    let comment = if comment.is_empty() {
        "hyperion-deploy".to_string()
    } else {
        comment
    };
    let res = cmd::run(
        "/usr/bin/ssh-keygen",
        &["-q", "-t", "ed25519", "-N", "", "-C", &comment, "-f", &key],
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

/// Inputs for one deploy or access check.
pub struct SyncParams<'a> {
    pub repo: &'a str,
    pub branch: &'a str,
    /// Relative webroot sub-directory, or empty for the repo root.
    pub subdir: &'a str,
    /// The site's document root (its htdocs).
    pub htdocs: &'a str,
    /// The site's unix user; git and rsync run as this user.
    pub run_as: &'a str,
    /// The site user's home, for git's HOME.
    pub home_dir: &'a str,
    pub auth: Auth,
}

/// Where the checkout lives: a sibling of the webroot, never inside it.
pub fn checkout_dir(htdocs: &str) -> Option<String> {
    let htdocs = htdocs.trim().trim_end_matches('/');
    let parent = std::path::Path::new(htdocs).parent()?;
    if parent.as_os_str().is_empty() || parent == std::path::Path::new("/") {
        return None;
    }
    Some(format!("{}/.hyperion-gitsync", parent.display()))
}

fn git_home(home_dir: &str) -> String {
    format!("{}/.hyperion-gitsync-home", home_dir.trim_end_matches('/'))
}

/// Everything about the inputs that can be refused before running anything.
fn validate(p: &SyncParams<'_>) -> Result<RepoRef, AdapterError> {
    let repo = parse_repo(p.repo)
        .ok_or_else(|| AdapterError::Other(format!("not a GitHub repository: {:?}", p.repo)))?;
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
        || p.run_as == "root"
        || !p
            .run_as
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(AdapterError::Other(format!(
            "not a site user: {:?}",
            p.run_as
        )));
    }
    Ok(repo)
}

/// Can this node read the configured branch with the configured credential?
/// A `git ls-remote` — touches neither the checkout nor the webroot.
pub async fn check(p: SyncParams<'_>) -> GitSyncCheck {
    let kind = p.auth.kind();
    let repo = match validate(&p) {
        Ok(r) => r,
        Err(e) => {
            return GitSyncCheck {
                ok: false,
                message: e.to_string(),
                ..Default::default()
            }
        }
    };
    let res = with_run_dir(p.run_as, |run_dir| {
        let p = &p;
        let repo = &repo;
        async move {
            let (url, env) = prepare_auth(&p.auth, repo, &run_dir, p.run_as).await?;
            let home = git_home(p.home_dir);
            site_mkdir(p.run_as, &home).await?;
            let refname = format!("refs/heads/{}", p.branch.trim());
            run_site(
                p.run_as,
                &home,
                &env,
                GIT,
                // `-C` a directory git owns: ls-remote otherwise inspects
                // whatever repository the agent's working directory is in.
                &["-C", &home, "ls-remote", "--heads", &url, &refname],
                NET_TIMEOUT,
            )
            .await
        }
    })
    .await;
    match res {
        Ok(out) => match out.split_whitespace().next() {
            Some(sha) if sha.len() >= 7 => GitSyncCheck {
                ok: true,
                commit: sha[..7].to_string(),
                message: format!(
                    "This node can read {} and its branch {}.",
                    repo.slug(),
                    p.branch.trim()
                ),
                detail: String::new(),
            },
            _ => GitSyncCheck {
                ok: false,
                commit: String::new(),
                message: format!(
                    "Access works, but {} has no branch named {:?}.",
                    repo.slug(),
                    p.branch.trim()
                ),
                detail: String::new(),
            },
        },
        Err(e) => {
            let (message, detail) = explain(&e, kind, p.branch.trim());
            GitSyncCheck {
                ok: false,
                commit: String::new(),
                message,
                detail,
            }
        }
    }
}

/// Deploy: clone-or-update the repo in a sibling of the webroot, then mirror
/// the tree (or `subdir`) into the webroot. Returns the deployed commit; on
/// failure the error is already explained for the operator (see
/// [`explain`]) and carried as `(message, detail)`.
pub async fn sync(p: SyncParams<'_>) -> Result<GitSyncLast, (String, String)> {
    let kind = p.auth.kind();
    let branch = p.branch.trim().to_string();
    let repo = validate(&p).map_err(|e| (e.to_string(), String::new()))?;
    let res = with_run_dir(p.run_as, |run_dir| {
        let p = &p;
        let repo = &repo;
        async move { sync_inner(p, repo, &run_dir).await }
    })
    .await;
    res.map_err(|e| explain(&e, kind, &branch))
}

/// Make a per-run credential directory under the root-owned runtime dir,
/// hand it to the site user (0700), run `f`, and remove it whatever happened.
/// Unique per call: two deploys of different sites — or a deploy racing an
/// access check — never share or delete each other's credentials.
async fn with_run_dir<F, Fut, T>(user: &str, f: F) -> Result<T, AdapterError>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<T, AdapterError>>,
{
    let dir = format!("{RUN_BASE}/gitsync-run-{}", random_tag());
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| AdapterError::Other(format!("run dir: {e}")))?;
    let prepared = async {
        set_mode(&dir, 0o700)
            .await
            .map_err(|e| AdapterError::Other(format!("run dir mode: {e}")))?;
        cmd::run("/bin/chown", &["--", user, &dir]).await?;
        Ok::<_, AdapterError>(())
    }
    .await;
    let out = match prepared {
        Ok(()) => f(dir.clone()).await,
        Err(e) => Err(e),
    };
    let _ = tokio::fs::remove_dir_all(&dir).await;
    out
}

/// The URL git should use and the environment that authenticates it. Secrets
/// are written into `run_dir` (site-user owned, 0600) and only their PATHS go
/// into the environment.
async fn prepare_auth(
    auth: &Auth,
    repo: &RepoRef,
    run_dir: &str,
    user: &str,
) -> Result<(String, Vec<(String, String)>), AdapterError> {
    // Never let git stop and wait for a password on a terminal it does not
    // have: under a job that is a ten-minute hang, then a timeout.
    let mut env: Vec<(String, String)> = vec![
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
    ];
    let url = match auth {
        Auth::Public => repo.https_url(),
        Auth::DeployKey(pem) => {
            let key = format!("{run_dir}/id");
            // ssh refuses a key without a trailing newline ("invalid format").
            let mut pem = pem.trim_end().to_string();
            pem.push('\n');
            write_run_secret(&key, pem.as_bytes(), user).await?;
            let known = format!("{run_dir}/known_hosts");
            write_run_secret(&known, GITHUB_KNOWN_HOSTS.as_bytes(), user).await?;
            env.push((
                "GIT_SSH_COMMAND".into(),
                format!(
                    "{SSH} -i {key} -o IdentitiesOnly=yes -o IdentityAgent=none \
                     -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known} \
                     -o GlobalKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=20"
                ),
            ));
            repo.ssh_url()
        }
        Auth::Pat(token) => {
            // GIT_ASKPASS prints the token as the password; the username is the
            // constant `x-access-token` in the URL. The token reaches the
            // script through a 0600 file the site user owns, never argv.
            let tok_file = format!("{run_dir}/token");
            write_run_secret(&tok_file, token.trim().as_bytes(), user).await?;
            let askpass = format!("{run_dir}/askpass");
            let script = format!("#!/bin/sh\nexec cat {tok_file}\n");
            write_run_secret(&askpass, script.as_bytes(), user).await?;
            set_mode(&askpass, 0o700)
                .await
                .map_err(|e| AdapterError::Other(format!("askpass mode: {e}")))?;
            env.push(("GIT_ASKPASS".into(), askpass));
            format!("https://x-access-token@github.com/{}.git", repo.slug())
        }
    };
    Ok((url, env))
}

async fn sync_inner(
    p: &SyncParams<'_>,
    repo: &RepoRef,
    run_dir: &str,
) -> Result<GitSyncLast, AdapterError> {
    let htdocs = p.htdocs.trim().trim_end_matches('/');
    let repo_dir = checkout_dir(htdocs)
        .ok_or_else(|| AdapterError::Other(format!("webroot has no parent: {htdocs}")))?;
    let branch = p.branch.trim();
    let home = git_home(p.home_dir);
    let (url, env) = prepare_auth(&p.auth, repo, run_dir, p.run_as).await?;
    site_mkdir(p.run_as, &home).await?;

    let git = |args: Vec<String>, timeout: Duration| {
        let env = env.clone();
        let home = home.clone();
        async move {
            let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
            run_site(p.run_as, &home, &env, GIT, &borrowed, timeout).await
        }
    };
    let rd = repo_dir.clone();
    let in_repo = move |rest: &[&str]| -> Vec<String> {
        let mut v = vec!["-C".to_string(), rd.clone()];
        v.extend(rest.iter().map(|s| s.to_string()));
        v
    };

    // Re-use the checkout when there is one: the remote URL and the branch
    // are re-applied EVERY time, so changing the repository, the branch or the
    // credential in the panel takes effect on the next deploy (a clone keeps
    // its original origin and its single-branch refspec forever otherwise,
    // and the "new" settings would keep deploying the old repository). The
    // URL is rebuilt from the parsed owner/name, so it can never start with
    // `-` and be read as an option.
    let has_git = tokio::fs::try_exists(format!("{repo_dir}/.git"))
        .await
        .unwrap_or(false);
    if !has_git {
        // A half-made checkout (an interrupted first clone) would make every
        // later clone fail with "destination path already exists". Remove it
        // as the site user — it lives in their tree.
        let _ = run_site(
            p.run_as,
            &home,
            &[],
            "/bin/rm",
            &["-rf", "--", &repo_dir],
            LOCAL_TIMEOUT,
        )
        .await;
        git(
            vec!["init".into(), "-q".into(), repo_dir.clone()],
            LOCAL_TIMEOUT,
        )
        .await?;
        git(in_repo(&["remote", "add", "origin", &url]), LOCAL_TIMEOUT).await?;
    } else {
        git(
            in_repo(&["remote", "set-url", "origin", &url]),
            LOCAL_TIMEOUT,
        )
        .await?;
    }
    let refspec = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
    git(
        in_repo(&[
            "fetch",
            "--depth",
            "1",
            "--no-tags",
            "--prune",
            "origin",
            &refspec,
        ]),
        NET_TIMEOUT,
    )
    .await?;
    let target = format!("refs/remotes/origin/{branch}");
    git(
        in_repo(&["checkout", "-q", "--force", "--detach", &target]),
        LOCAL_TIMEOUT,
    )
    .await?;
    // Nothing but the commit's own files may reach the webroot: drop anything
    // untracked or ignored that a previous build or a tenant left behind.
    git(in_repo(&["clean", "-q", "-ffdx"]), LOCAL_TIMEOUT).await?;

    // Mirror the tree (or a sub-directory of it) into the webroot, dropping
    // `.git` so history is never served. A trailing slash on the source makes
    // rsync copy its CONTENTS.
    let sub = p.subdir.trim().trim_matches('/');
    let src = if sub.is_empty() {
        format!("{repo_dir}/")
    } else {
        format!("{repo_dir}/{sub}/")
    };
    if !tokio::fs::try_exists(src.trim_end_matches('/'))
        .await
        .unwrap_or(false)
    {
        return Err(AdapterError::Other(format!(
            "NO_SUBDIR: the branch has no directory {sub:?} to deploy"
        )));
    }
    run_site(
        p.run_as,
        &home,
        &[],
        RSYNC,
        &[
            "-rlpt",
            "--delete",
            "--exclude=.git",
            "--",
            &src,
            &format!("{htdocs}/"),
        ],
        LOCAL_TIMEOUT,
    )
    .await?;

    // Read what we deployed: short sha + subject.
    let sha = git(in_repo(&["rev-parse", "--short=7", "HEAD"]), LOCAL_TIMEOUT)
        .await?
        .trim()
        .to_string();
    let subject = git(in_repo(&["log", "-1", "--pretty=%s"]), LOCAL_TIMEOUT)
        .await
        .unwrap_or_default()
        .trim()
        .chars()
        .take(200)
        .collect::<String>();
    Ok(GitSyncLast {
        commit: sha,
        status: "ok".into(),
        message: subject,
        ..Default::default()
    })
}

/// Remove the checkout and git's private HOME (on disconnect). Runs as the
/// site user — both live in their tree. The webroot is left as deployed.
pub async fn remove_checkout(htdocs: &str, run_as: &str, home_dir: &str) {
    let home = git_home(home_dir);
    let mut targets = vec![home.clone()];
    if let Some(d) = checkout_dir(htdocs) {
        targets.push(d);
    }
    for t in targets {
        let _ = run_site(
            run_as,
            home_dir,
            &[],
            "/bin/rm",
            &["-rf", "--", &t],
            LOCAL_TIMEOUT,
        )
        .await;
    }
}

/// Turn a failed git/rsync step into one plain sentence for the operator, plus
/// the raw last lines git printed. The sentence names the FIX, because the raw
/// git output for "you picked the wrong credential" is the same "Repository
/// not found" GitHub returns for a repository that really does not exist.
pub fn explain(e: &AdapterError, auth: AuthKind, branch: &str) -> (String, String) {
    // Only a command's own output is evidence worth showing beside the
    // sentence; anything else IS the sentence.
    let (raw, detail) = match e {
        AdapterError::Command { stderr_tail, .. } => {
            (stderr_tail.clone(), last_lines(stderr_tail, 4))
        }
        AdapterError::Other(m) => (m.clone(), String::new()),
        other => (other.to_string(), String::new()),
    };
    let lc = raw.to_ascii_lowercase();
    let msg = if lc.contains("timed out") && !lc.contains("connection timed out") {
        "Git took longer than ten minutes and was stopped. A very large repository? \
         Try a sub-directory branch with only the built site."
            .to_string()
    } else if lc.contains("host key verification failed")
        || lc.contains("remote host identification has changed")
    {
        "github.com answered with an ssh host key that is not GitHub's published one, \
         so the deploy refused to connect. If GitHub has rotated its keys, Hyperion \
         needs an update; otherwise something is intercepting this node's traffic."
            .to_string()
    } else if lc.contains("could not resolve host")
        || lc.contains("could not resolve hostname")
        || lc.contains("network is unreachable")
        || lc.contains("connection timed out")
        || lc.contains("failed to connect")
        || lc.contains("connection refused")
    {
        "This node could not reach github.com — check its DNS and outbound firewall.".to_string()
    } else if lc.contains("permission denied (publickey)") {
        "GitHub refused the deploy key. Add the public key shown here to the \
         repository under Settings → Deploy keys (or regenerate it if it was removed)."
            .to_string()
    } else if lc.contains("couldn't find remote ref")
        || lc.contains("remote branch") && lc.contains("not found")
        || lc.contains("invalid refspec")
    {
        format!("The repository has no branch named {branch:?}.")
    } else if lc.contains("no_subdir:") {
        raw.split_once("NO_SUBDIR: ")
            .map(|(_, m)| {
                let mut m = m.trim().to_string();
                if let Some(c) = m.get(0..1) {
                    m.replace_range(0..1, &c.to_uppercase());
                }
                format!("{m}. Check the webroot sub-directory setting.")
            })
            .unwrap_or_else(|| raw.trim().to_string())
    } else if lc.contains("repository not found")
        || lc.contains("could not read username")
        || lc.contains("could not read password")
        || lc.contains("authentication failed")
        || lc.contains("invalid username or password")
        || lc.contains("terminal prompts disabled")
        || lc.contains("access denied")
        || lc.contains("returned error: 403")
    {
        match auth {
            AuthKind::Public => "GitHub refused access: the repository is private, or it \
                does not exist. For a private repository choose Deploy key or Access token."
                .to_string(),
            AuthKind::DeployKey => "GitHub found no repository this deploy key may read. \
                Add the key to THIS repository's Deploy keys (a key added to another \
                repository or to a user account does not count), and check the URL."
                .to_string(),
            AuthKind::Pat => "GitHub refused the access token. Check it has not expired \
                and that it grants Contents: read on this repository."
                .to_string(),
        }
    } else if lc.contains("rsync") {
        "Copying the files into the webroot failed — see the details.".to_string()
    } else {
        let last = last_lines(&raw, 1);
        let last = last
            .trim()
            .trim_start_matches("fatal: ")
            .trim_start_matches("error: ");
        if last.is_empty() {
            "Git failed without saying why.".to_string()
        } else {
            let mut m = last.to_string();
            if let Some(c) = m.get(0..1) {
                m.replace_range(0..1, &c.to_uppercase());
            }
            m
        }
    };
    (msg, detail)
}

/// The last `n` non-empty lines, each trimmed, at most 600 characters total.
fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    let joined = lines[start..].join("\n");
    if joined.chars().count() > 600 {
        joined.chars().take(600).collect()
    } else {
        joined
    }
}

/// Write a per-run secret file 0600 owned by the site user.
async fn write_run_secret(path: &str, content: &[u8], user: &str) -> Result<(), AdapterError> {
    tokio::fs::write(path, content)
        .await
        .map_err(|e| AdapterError::Other(format!("write run secret: {e}")))?;
    set_mode(path, 0o600)
        .await
        .map_err(|e| AdapterError::Other(format!("run secret mode: {e}")))?;
    cmd::run("/bin/chown", &["--", user, path]).await?;
    Ok(())
}

/// `mkdir -p <dir>` as the site user (so the tree is site-owned from the top).
async fn site_mkdir(user: &str, dir: &str) -> Result<(), AdapterError> {
    run_site(
        user,
        "/",
        &[],
        "/bin/mkdir",
        &["-p", "--", dir],
        LOCAL_TIMEOUT,
    )
    .await
    .map(|_| ())
}

/// `sudo -H -u <user> /usr/bin/env HOME=<home> <env…> <program> <args…>` — the
/// wp-cli / Lighthouse shape, so the child has a writable HOME and never any
/// privilege beyond the tenant's own. Its own process group, killed whole on
/// timeout: `sudo → env → git → ssh` would otherwise leave git and ssh
/// running after the job gave up.
async fn run_site(
    user: &str,
    home: &str,
    env: &[(String, String)],
    program: &str,
    args: &[&str],
    timeout: Duration,
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
    let label = std::path::Path::new(program)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    cmd::run_group_timeout(SUDO, &borrowed, timeout, &label).await
}

async fn set_mode(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await
}

fn random_tag() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
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
        assert!(!valid_branch("/main"));
        assert!(!valid_branch("main.lock"));
        assert!(valid_subdir(""));
        assert!(valid_subdir("public"));
        assert!(valid_subdir("public/"));
        assert!(valid_subdir("dist/site"));
        assert!(!valid_subdir("../etc"));
        assert!(!valid_subdir("/abs"));
        assert!(!valid_subdir("a/../b"));
        assert!(!valid_subdir(".git"));
    }

    #[test]
    fn checkout_is_a_sibling_of_the_webroot() {
        assert_eq!(
            checkout_dir("/home/u/example.com/htdocs").as_deref(),
            Some("/home/u/example.com/.hyperion-gitsync")
        );
        assert_eq!(
            checkout_dir("/home/u/example.com/htdocs/").as_deref(),
            Some("/home/u/example.com/.hyperion-gitsync")
        );
        assert_eq!(checkout_dir("/htdocs"), None);
        assert_eq!(checkout_dir("htdocs"), None);
    }

    fn cmd_err(tail: &str) -> AdapterError {
        AdapterError::Command {
            cmd: "sudo …".into(),
            code: 128,
            stderr_tail: tail.into(),
        }
    }

    #[test]
    fn git_failures_are_explained_by_their_fix() {
        let nf = cmd_err(
            "remote: Repository not found.\nfatal: repository 'https://github.com/o/r/' not found",
        );
        assert!(explain(&nf, AuthKind::Public, "main").0.contains("private"));
        assert!(explain(&nf, AuthKind::Pat, "main").0.contains("token"));
        assert!(explain(&nf, AuthKind::DeployKey, "main")
            .0
            .contains("Deploy keys"));
        let pk = cmd_err("git@github.com: Permission denied (publickey).\r\nfatal: Could not read from remote repository.");
        assert!(explain(&pk, AuthKind::DeployKey, "main")
            .0
            .contains("refused the deploy key"));
        let br = cmd_err("fatal: couldn't find remote ref refs/heads/nope");
        assert_eq!(
            explain(&br, AuthKind::Public, "nope").0,
            "The repository has no branch named \"nope\"."
        );
        let hk =
            cmd_err("Host key verification failed.\nfatal: Could not read from remote repository.");
        assert!(explain(&hk, AuthKind::DeployKey, "main")
            .0
            .contains("host key"));
        let dns = cmd_err(
            "fatal: unable to access 'https://github.com/o/r/': Could not resolve host: github.com",
        );
        assert!(explain(&dns, AuthKind::Public, "main")
            .0
            .contains("could not reach"));
        let sub =
            AdapterError::Other("NO_SUBDIR: the branch has no directory \"web\" to deploy".into());
        let (m, _) = explain(&sub, AuthKind::Public, "main");
        assert!(m.starts_with("The branch has no directory \"web\""), "{m}");
        let to = AdapterError::Other("git timed out".into());
        assert!(explain(&to, AuthKind::Public, "main")
            .0
            .contains("ten minutes"));
        // The raw evidence travels along, trimmed to the last lines.
        assert!(explain(&nf, AuthKind::Public, "main")
            .1
            .contains("not found"));
        // A local failure is the sentence itself — no "other:" prefix, and no
        // raw-evidence fold repeating it.
        let local = AdapterError::Other("run dir: Read-only file system (os error 30)".into());
        assert_eq!(
            explain(&local, AuthKind::Public, "main"),
            (
                "Run dir: Read-only file system (os error 30)".to_string(),
                String::new()
            )
        );
    }

    #[test]
    fn the_pinned_known_hosts_are_github_only() {
        for line in GITHUB_KNOWN_HOSTS.lines() {
            assert!(line.starts_with("github.com "), "{line}");
        }
        assert_eq!(GITHUB_KNOWN_HOSTS.lines().count(), 3);
    }
}
