//! Deploy a hosting's webroot from a Git repository (GitHub, public or private).
//!
//! The repository the operator points at IS the site — a sync makes the webroot
//! match a branch exactly (`git reset --hard`), so it is a deploy target, not a
//! working copy. Private repositories authenticate with either an SSH **deploy
//! key** Hyperion generates (the operator adds its public half to the repo) or a
//! read-only **personal access token**. A verified GitHub webhook can auto-deploy
//! on push. Every git command runs as the SITE's own unix user, never as root:
//! the checkout writes into a tenant-owned tree, so dropped privileges are the
//! sandbox, exactly as wp-cli and the Lighthouse runner do it.

use serde::{Deserialize, Serialize};

/// Which credential a private repository uses.
pub const AUTH_PUBLIC: &str = "public";
pub const AUTH_DEPLOY_KEY: &str = "deploykey";
pub const AUTH_PAT: &str = "pat";

/// The per-hosting deploy configuration. Holds no secret — the deploy private
/// key and the token live in the node's root-only secret store, and only
/// whether they are set is ever surfaced (see [`GitSyncView`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSyncConfig {
    /// Empty = not configured. An `https://github.com/owner/repo(.git)` or
    /// `git@github.com:owner/repo.git` URL.
    pub repo: String,
    /// Branch to deploy. Empty is treated as `main`.
    pub branch: String,
    /// A sub-directory of the repo that is the webroot, relative and without
    /// `..`. Empty = the repository root is the webroot.
    pub subdir: String,
    /// One of [`AUTH_PUBLIC`], [`AUTH_DEPLOY_KEY`], [`AUTH_PAT`].
    pub auth: String,
    /// Auto-deploy when a signature-verified GitHub webhook reports a push to
    /// `branch`.
    pub webhook_enabled: bool,
}

impl GitSyncConfig {
    pub fn is_configured(&self) -> bool {
        !self.repo.trim().is_empty()
    }
    /// The branch to act on, defaulting a blank one to `main`.
    pub fn effective_branch(&self) -> &str {
        let b = self.branch.trim();
        if b.is_empty() {
            "main"
        } else {
            b
        }
    }
}

/// The outcome of one deploy, kept so the card can show state without
/// re-running anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSyncLast {
    /// Unix seconds, 0 = never synced.
    pub at: i64,
    /// Short commit the webroot was set to (empty on failure).
    pub commit: String,
    /// "ok" | "error" | "".
    pub status: String,
    /// One line for the operator: the commit subject on success, a plain
    /// explanation of what went wrong on failure. Never carries a credential.
    pub message: String,
    /// How the deploy started: "manual" | "webhook" | "".
    pub trigger: String,
    /// On failure, the last lines git itself printed — the raw evidence
    /// behind `message`. Empty on success. Never carries a credential (git
    /// never echoes one, and the token is never in a URL).
    #[serde(default)]
    pub detail: String,
    /// Who started it: the panel user for "manual", empty for a webhook.
    #[serde(default)]
    pub actor: String,
}

/// How many deploys a site remembers for its history list.
pub const HISTORY_KEEP: usize = 10;

/// Everything the card renders. Secrets are represented only as "is it set".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSyncView {
    pub config: GitSyncConfig,
    /// The deploy key's PUBLIC half, safe to display and to paste into the
    /// repo's Deploy keys. Empty when none has been generated.
    pub deploy_pubkey: String,
    /// A token is stored (never the token itself). Populated by the node.
    pub pat_set: bool,
    /// The webhook HMAC secret to paste into GitHub, or empty when auto-deploy
    /// is off. The panel both shows this and verifies incoming pushes against
    /// it — it lets a caller trigger a redeploy of the CONFIGURED repo, nothing
    /// more, so it is low-sensitivity but still a secret.
    pub webhook_secret: String,
    /// The path GitHub should POST to (`/webhooks/git/<id>`); the operator
    /// prepends the panel's public origin.
    pub webhook_path: String,
    /// `git` is installed on the owning node.
    pub git_available: bool,
    pub last: GitSyncLast,
    /// Recent deploys, newest first (`last` is the first entry). Capped at
    /// [`HISTORY_KEEP`]. Empty from a node that predates the history.
    #[serde(default)]
    pub history: Vec<GitSyncLast>,
    /// A deploy is running on the node right now.
    #[serde(default)]
    pub running: bool,
    /// Programs a deploy needs that the owning node lacks (`git`, `rsync`,
    /// `ssh`, `sudo`). Empty = ready.
    #[serde(default)]
    pub missing_tools: Vec<String>,
}

/// The answer to "can this node read the configured branch?" — a
/// `git ls-remote` with the configured credential, which touches nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSyncCheck {
    pub ok: bool,
    /// The branch's current commit on GitHub (short), when `ok`.
    pub commit: String,
    /// One line for the operator.
    pub message: String,
    /// What git printed, on failure.
    pub detail: String,
}

/// A GitHub repository, parsed out of whatever form the operator pasted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    pub owner: String,
    pub name: String,
}

impl RepoRef {
    /// `owner/name`.
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
    /// The canonical form Hyperion stores: `https://github.com/owner/name`.
    pub fn https_url(&self) -> String {
        format!("https://github.com/{}/{}", self.owner, self.name)
    }
    /// The ssh form a deploy key authenticates over.
    pub fn ssh_url(&self) -> String {
        format!("git@github.com:{}/{}.git", self.owner, self.name)
    }
    pub fn commit_url(&self, sha: &str) -> String {
        format!("{}/commit/{}", self.https_url(), sha)
    }
    pub fn tree_url(&self, branch: &str) -> String {
        format!("{}/tree/{}", self.https_url(), branch)
    }
    /// Where the operator adds a deploy key.
    pub fn deploy_keys_url(&self) -> String {
        format!("{}/settings/keys/new", self.https_url())
    }
    /// Where the operator adds a webhook.
    pub fn webhooks_url(&self) -> String {
        format!("{}/settings/hooks/new", self.https_url())
    }
}

/// Parse a GitHub repository out of what an operator is likely to paste:
/// `https://github.com/o/r`, with or without `.git`, a trailing slash, a
/// `/tree/<branch>…` tail copied from the browser, or no scheme at all;
/// `git@github.com:o/r.git`; `ssh://git@github.com/o/r.git`. Anything that
/// is not github.com, or whose owner/name is not a plain GitHub name, is
/// `None` — the value later reaches git as an argument, so it must never
/// start with `-` or carry anything but a name.
pub fn parse_repo(input: &str) -> Option<RepoRef> {
    let u = input.trim();
    if u.is_empty() || u.len() > 400 || u.contains(char::is_whitespace) || u.starts_with('-') {
        return None;
    }
    let path = [
        "https://github.com/",
        "http://github.com/",
        "https://www.github.com/",
        "github.com/",
        "www.github.com/",
        "git@github.com:",
        "ssh://git@github.com/",
    ]
    .iter()
    .find_map(|p| u.strip_prefix(p))?;
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let mut name = parts.next()?;
    // Whatever follows owner/name must be a browser tail (`/`, `/tree/…`,
    // `/blob/…`) — never a third path segment we would silently drop.
    match parts.next() {
        None | Some("") | Some("tree") | Some("blob") | Some("commits") => {}
        Some(_) => return None,
    }
    name = name.strip_suffix(".git").unwrap_or(name);
    let seg_ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && !s.starts_with('-')
            && !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    if !seg_ok(owner) || !seg_ok(name) {
        return None;
    }
    Some(RepoRef {
        owner: owner.to_string(),
        name: name.to_string(),
    })
}

/// Verify a GitHub webhook signature: `X-Hub-Signature-256: sha256=<hex>` is
/// HMAC-SHA256 of the raw body under the per-hosting secret. Constant-time.
///
/// Lives here (a dependency both the web edge and the node adapter can link),
/// not in the adapter, because the web crate must never depend on
/// `hyperion-adapters`.
pub fn verify_webhook(secret: &str, body: &[u8], header: &str) -> bool {
    use hmac::{Hmac, Mac};
    let Some(hex) = header.trim().strip_prefix("sha256=") else {
        return false;
    };
    let Ok(sig) = decode_hex(hex) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_signature_roundtrips_and_rejects() {
        use hmac::{Hmac, Mac};
        let secret = "s3cr3t";
        let body = b"{\"ref\":\"refs/heads/main\"}";
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let sig = format!(
            "sha256={}",
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>()
        );
        assert!(verify_webhook(secret, body, &sig));
        assert!(!verify_webhook("wrong", body, &sig));
        assert!(!verify_webhook(secret, b"tampered", &sig));
        assert!(!verify_webhook(secret, body, "sha256=00"));
        assert!(!verify_webhook(secret, body, "garbage"));
    }

    #[test]
    fn repo_forms_operators_paste() {
        let want = Some(RepoRef {
            owner: "acme".into(),
            name: "site".into(),
        });
        for ok in [
            "https://github.com/acme/site",
            "https://github.com/acme/site.git",
            "https://github.com/acme/site/",
            "https://github.com/acme/site/tree/main/public",
            "github.com/acme/site",
            "git@github.com:acme/site.git",
            "ssh://git@github.com/acme/site.git",
            "  https://github.com/acme/site  ",
        ] {
            assert_eq!(parse_repo(ok), want, "{ok}");
        }
        for bad in [
            "",
            "https://gitlab.com/acme/site",
            "https://github.com/acme",
            "https://github.com/acme/site/extra",
            "https://github.com.evil.io/acme/site",
            "-oProxyCommand=evil",
            "https://github.com/-acme/site",
            "https://github.com/acme/site world",
            "https://github.com/acme/..",
        ] {
            assert_eq!(parse_repo(bad), None, "{bad}");
        }
        let r = parse_repo("git@github.com:acme/site.git").unwrap();
        assert_eq!(r.https_url(), "https://github.com/acme/site");
        assert_eq!(r.ssh_url(), "git@github.com:acme/site.git");
        assert_eq!(
            r.deploy_keys_url(),
            "https://github.com/acme/site/settings/keys/new"
        );
    }

    #[test]
    fn a_view_from_an_older_node_still_decodes() {
        // A node built before history/running/missing_tools answers without
        // them; the panel must not fail to render its card.
        let old = r#"{"config":{"repo":"","branch":"","subdir":"","auth":"public","webhook_enabled":false},
            "deploy_pubkey":"","pat_set":false,"webhook_secret":"","webhook_path":"/webhooks/git/x",
            "git_available":true,"last":{"at":0,"commit":"","status":"","message":"","trigger":""}}"#;
        let v: GitSyncView = serde_json::from_str(old).unwrap();
        assert!(v.history.is_empty() && !v.running && v.missing_tools.is_empty());
    }
}
