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

/// The outcome of the last sync, kept so the card can show state without
/// re-running anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSyncLast {
    /// Unix seconds, 0 = never synced.
    pub at: i64,
    /// Short commit the webroot was last set to.
    pub commit: String,
    /// "ok" | "error" | "".
    pub status: String,
    /// One line for the operator (the commit subject on success, the error on
    /// failure). Never carries a credential.
    pub message: String,
    /// How the sync started: "manual" | "webhook" | "".
    pub trigger: String,
}

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
}
