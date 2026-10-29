//! Git deploy from GitHub: config, deploy keys, checks and syncs.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Everything the git-deploy card renders. Runs on the OWNING node (the
    /// config, the secrets, `git` and the deploy lock all live where the
    /// site's files do).
    pub async fn git_sync_view(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::gitsync::GitSyncView, RpcError> {
        use hyperion_types::gitsync as t;
        let detail = self.get(sel).await?;
        let id = detail.id.as_str();
        let config = self.git_sync_config(id).await;
        let history = self.git_sync_history(id).await;
        let last = history.first().cloned().unwrap_or_default();
        let missing_tools =
            hyperion_adapters::gitsync::missing_tools(config.auth == t::AUTH_DEPLOY_KEY).await;
        Ok(t::GitSyncView {
            deploy_pubkey: self.kvs(id, "gitsync_pubkey").await,
            pat_set: tokio::fs::try_exists(gitsync_pat_path(id))
                .await
                .unwrap_or(false),
            webhook_secret: self.kvs(id, "gitsync_webhook_secret").await,
            webhook_path: format!("/webhooks/git/{id}"),
            git_available: !missing_tools.iter().any(|m| m == "git"),
            running: gitsync_lock(&detail.id).try_lock().is_err(),
            missing_tools,
            config,
            last,
            history,
        })
    }

    pub(super) async fn git_sync_config(&self, id: &str) -> hyperion_types::gitsync::GitSyncConfig {
        use hyperion_types::gitsync as t;
        let auth = self.kvs(id, "gitsync_auth").await;
        t::GitSyncConfig {
            repo: self.kvs(id, "gitsync_repo").await,
            branch: self.kvs(id, "gitsync_branch").await,
            subdir: self.kvs(id, "gitsync_subdir").await,
            auth: if auth.is_empty() {
                t::AUTH_PUBLIC.to_string()
            } else {
                auth
            },
            webhook_enabled: self.kvs(id, "gitsync_webhook").await == "1",
        }
    }

    /// Recent deploys, newest first. A site deployed before the history
    /// existed has only `gitsync_last`; it becomes the one entry.
    pub(super) async fn git_sync_history(
        &self,
        id: &str,
    ) -> Vec<hyperion_types::gitsync::GitSyncLast> {
        let hist: Vec<hyperion_types::gitsync::GitSyncLast> =
            serde_json::from_str(&self.kvs(id, "gitsync_history").await).unwrap_or_default();
        if !hist.is_empty() {
            return hist;
        }
        match serde_json::from_str::<hyperion_types::gitsync::GitSyncLast>(
            &self.kvs(id, "gitsync_last").await,
        ) {
            Ok(l) if l.at > 0 => vec![l],
            _ => Vec::new(),
        }
    }

    /// Save the deploy configuration, and set/clear the access token when
    /// `pat` is `Some` (`Some("")` clears it, `None` leaves it untouched).
    /// The repository is stored in its canonical `https://github.com/o/r`
    /// form whatever was pasted. Choosing "deploy key" generates one when the
    /// site has none, so the key to add to GitHub is on screen right after
    /// the save — not behind a second button.
    pub async fn git_sync_config_set(
        &self,
        sel: HostingSelector,
        config: hyperion_types::gitsync::GitSyncConfig,
        pat: Option<String>,
    ) -> Result<(), RpcError> {
        use hyperion_adapters::gitsync as g;
        use hyperion_types::gitsync as t;
        let detail = self.get(sel).await?;
        let id = detail.id.as_str();
        let bad = |m: &str| RpcError::Validation { message: m.into() };
        let repo = match t::parse_repo(&config.repo) {
            Some(r) => r.https_url(),
            None if config.repo.trim().is_empty() => {
                return Err(bad("Enter the GitHub repository to deploy from."))
            }
            None => {
                return Err(bad(
                    "That is not a GitHub repository — paste its address, like https://github.com/owner/repo.",
                ))
            }
        };
        if !g::valid_branch(config.effective_branch()) {
            return Err(bad("That is not a valid branch name."));
        }
        let subdir = config.subdir.trim().trim_matches('/').to_string();
        if !g::valid_subdir(&subdir) {
            return Err(bad(
                "The folder must be a path inside the repository, like public or dist/site.",
            ));
        }
        if ![t::AUTH_PUBLIC, t::AUTH_DEPLOY_KEY, t::AUTH_PAT].contains(&config.auth.as_str()) {
            return Err(bad("Unknown access method."));
        }
        if config.auth == t::AUTH_PAT
            && pat.as_deref().map(str::trim).unwrap_or("").is_empty()
            && !tokio::fs::try_exists(gitsync_pat_path(id))
                .await
                .unwrap_or(false)
        {
            return Err(bad("Paste the access token to use."));
        }
        let now = now_secs();
        for (k, v) in [
            ("gitsync_repo", repo.clone()),
            ("gitsync_branch", config.branch.trim().to_string()),
            ("gitsync_subdir", subdir),
            ("gitsync_auth", config.auth.clone()),
            (
                "gitsync_webhook",
                if config.webhook_enabled { "1" } else { "0" }.to_string(),
            ),
        ] {
            hyperion_state::hosting_kv::set(&self.pool, id, k, &v, now)
                .await
                .map_err(|e| RpcError::Internal_with(format!("kv set: {e}")))?;
        }
        // A webhook needs a secret to verify pushes: mint one the first time
        // auto-deploy is enabled and keep it stable afterwards.
        if config.webhook_enabled && self.kvs(id, "gitsync_webhook_secret").await.is_empty() {
            let secret: String = {
                use rand::RngCore;
                let mut b = [0u8; 24];
                rand::thread_rng().fill_bytes(&mut b);
                b.iter().map(|x| format!("{x:02x}")).collect()
            };
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                id,
                "gitsync_webhook_secret",
                &secret,
                now,
            )
            .await;
        }
        if let Some(p) = pat {
            let path = gitsync_pat_path(id);
            if p.trim().is_empty() {
                let _ = tokio::fs::remove_file(&path).await;
            } else {
                write_secret_file(&path, p.trim().as_bytes())
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("store token: {e}")))?;
            }
        }
        if config.auth == t::AUTH_DEPLOY_KEY
            && (self.kvs(id, "gitsync_pubkey").await.is_empty()
                || !tokio::fs::try_exists(gitsync_key_path(id))
                    .await
                    .unwrap_or(false))
        {
            self.git_sync_store_new_key(&detail).await?;
        }
        self.append_audit(
            "hosting.gitsync.config",
            Some(id),
            &serde_json::json!({ "repo": repo, "auth": config.auth }).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Generate a deploy keypair, store the private half in the node secret
    /// store, and return the public half for the operator to add to the repo.
    pub async fn git_sync_generate_key(&self, sel: HostingSelector) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let pubkey = self.git_sync_store_new_key(&detail).await?;
        self.append_audit(
            "hosting.gitsync.genkey",
            Some(detail.id.as_str()),
            "{}",
            "ok",
        )
        .await;
        Ok(pubkey)
    }

    pub(super) async fn git_sync_store_new_key(
        &self,
        detail: &HostingDetail,
    ) -> Result<String, RpcError> {
        let id = detail.id.as_str();
        // The comment names the site in GitHub's deploy-key list.
        let comment = format!("hyperion@{}", detail.domain);
        let (priv_pem, pubkey) = hyperion_adapters::gitsync::generate_deploy_key(&comment)
            .await
            .map_err(|e| RpcError::Internal_with(format!("generate deploy key: {e}")))?;
        write_secret_file(&gitsync_key_path(id), priv_pem.as_bytes())
            .await
            .map_err(|e| RpcError::Internal_with(format!("store deploy key: {e}")))?;
        hyperion_state::hosting_kv::set(&self.pool, id, "gitsync_pubkey", &pubkey, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("kv set: {e}")))?;
        Ok(pubkey)
    }

    /// The deploy inputs for a site, with its credential loaded.
    pub(super) async fn git_sync_auth(
        &self,
        id: &str,
        auth: &str,
    ) -> Result<hyperion_adapters::gitsync::Auth, RpcError> {
        use hyperion_adapters::gitsync as g;
        use hyperion_types::gitsync as t;
        Ok(match auth {
            t::AUTH_DEPLOY_KEY => {
                let pem = tokio::fs::read_to_string(gitsync_key_path(id))
                    .await
                    .map_err(|_| RpcError::Validation {
                        message: "No deploy key has been generated yet.".into(),
                    })?;
                g::Auth::DeployKey(pem)
            }
            t::AUTH_PAT => {
                let tok = tokio::fs::read_to_string(gitsync_pat_path(id))
                    .await
                    .map_err(|_| RpcError::Validation {
                        message: "No access token has been saved yet.".into(),
                    })?;
                g::Auth::Pat(tok.trim().to_string())
            }
            _ => g::Auth::Public,
        })
    }

    /// Can this node read the configured branch? Touches nothing on disk
    /// beyond git's private HOME.
    pub async fn git_sync_check(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::gitsync::GitSyncCheck, RpcError> {
        use hyperion_adapters::gitsync as g;
        let detail = self.get(sel).await?;
        let id = detail.id.as_str();
        let config = self.git_sync_config(id).await;
        if !config.is_configured() {
            return Err(RpcError::Validation {
                message: "No repository is connected to this site.".into(),
            });
        }
        let missing =
            g::missing_tools(config.auth == hyperion_types::gitsync::AUTH_DEPLOY_KEY).await;
        if !missing.is_empty() {
            return Ok(hyperion_types::gitsync::GitSyncCheck {
                ok: false,
                message: format!("This node is missing {}.", missing.join(", ")),
                ..Default::default()
            });
        }
        let auth = self.git_sync_auth(id, &config.auth).await?;
        let home = self.home_dir_for(detail.system_user.as_str());
        Ok(g::check(g::SyncParams {
            repo: &config.repo,
            branch: config.effective_branch(),
            subdir: &config.subdir,
            htdocs: detail.root_dir.trim(),
            run_as: detail.system_user.as_str(),
            home_dir: &home,
            site_key: detail.id.as_str(),
            auth,
        })
        .await)
    }

    /// Deploy now: make the webroot match the configured branch. `trigger` is
    /// "manual" or "webhook", `actor` the panel user (empty for a webhook).
    /// One deploy per site at a time — a push landing while the operator's
    /// own deploy runs is refused, not interleaved into the same checkout.
    /// Stores the outcome either way (so the card can show a failure), and
    /// returns `Err` on failure so a job fails visibly.
    pub async fn git_sync_now(
        &self,
        sel: HostingSelector,
        trigger: String,
        actor: String,
    ) -> Result<hyperion_types::gitsync::GitSyncLast, RpcError> {
        use hyperion_adapters::gitsync as g;
        use hyperion_types::gitsync as t;
        let detail = self.get(sel).await?;
        let id = detail.id.as_str();
        let config = self.git_sync_config(id).await;
        if !config.is_configured() {
            return Err(RpcError::Validation {
                message: "No repository is connected to this site.".into(),
            });
        }
        let lock = gitsync_lock(&detail.id);
        let _one_at_a_time = match lock.try_lock() {
            Ok(g) => g,
            // A push that lands while a deploy runs must still reach the
            // site — the running deploy may have fetched the commit BEFORE
            // it. Queue exactly one follow-up (it fetches whatever is newest
            // when it starts, so further pushes in the meantime are covered
            // by it and need no deploy of their own).
            Err(_) if trigger == "webhook" => {
                if !gitsync_queue(&detail.id, true) {
                    return Err(RpcError::Conflict {
                        message: "A deploy is running and another is already queued.".into(),
                    });
                }
                let g = lock.lock().await;
                gitsync_queue(&detail.id, false);
                g
            }
            Err(_) => {
                return Err(RpcError::Conflict {
                    message: "A deploy of this site is already running.".into(),
                })
            }
        };
        let missing = g::missing_tools(config.auth == t::AUTH_DEPLOY_KEY).await;
        let outcome = if !missing.is_empty() {
            Err((
                format!(
                    "This node is missing {} — run update.sh on it, then deploy again.",
                    missing.join(", ")
                ),
                String::new(),
            ))
        } else {
            match self.git_sync_auth(id, &config.auth).await {
                Err(e) => Err((e.to_string(), String::new())),
                Ok(auth) => {
                    let home = self.home_dir_for(detail.system_user.as_str());
                    g::sync(g::SyncParams {
                        repo: &config.repo,
                        branch: config.effective_branch(),
                        subdir: &config.subdir,
                        htdocs: detail.root_dir.trim(),
                        run_as: detail.system_user.as_str(),
                        home_dir: &home,
                        site_key: detail.id.as_str(),
                        auth,
                    })
                    .await
                }
            }
        };
        let last = match outcome {
            Ok(l) => t::GitSyncLast {
                at: now_secs(),
                status: "ok".into(),
                trigger: trigger.clone(),
                actor: actor.clone(),
                ..l
            },
            Err((message, detail_lines)) => t::GitSyncLast {
                at: now_secs(),
                commit: String::new(),
                status: "error".into(),
                message: message.chars().take(400).collect(),
                trigger: trigger.clone(),
                detail: detail_lines,
                actor: actor.clone(),
            },
        };
        let mut history = self.git_sync_history(id).await;
        history.insert(0, last.clone());
        history.truncate(t::HISTORY_KEEP);
        let now = now_secs();
        for (k, v) in [
            (
                "gitsync_last",
                serde_json::to_string(&last).unwrap_or_default(),
            ),
            (
                "gitsync_history",
                serde_json::to_string(&history).unwrap_or_default(),
            ),
        ] {
            let _ = hyperion_state::hosting_kv::set(&self.pool, id, k, &v, now).await;
        }
        self.append_audit(
            "hosting.gitsync.deploy",
            Some(id),
            &serde_json::json!({
                "domain": detail.domain,
                "commit": last.commit,
                "status": last.status,
                "trigger": trigger,
            })
            .to_string(),
            if last.status == "ok" { "ok" } else { "error" },
        )
        .await;
        if last.status == "error" {
            return Err(RpcError::Validation {
                message: last.message.clone(),
            });
        }
        self.purge_page_cache_after(id, "hosting.gitsync.deploy")
            .await;
        Ok(last)
    }

    /// Stop deploying this site from GitHub: forget the settings, the deploy
    /// key, the token, the webhook secret and the history, and remove the
    /// checkout. The webroot keeps whatever was last deployed.
    pub async fn git_sync_disconnect(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        let lock = gitsync_lock(&detail.id);
        let Ok(_no_deploy_meanwhile) = lock.try_lock() else {
            return Err(RpcError::Conflict {
                message: "A deploy of this site is running — disconnect once it has finished."
                    .into(),
            });
        };
        let repo = self.kvs(detail.id.as_str(), "gitsync_repo").await;
        self.git_sync_forget(&detail).await;
        self.append_audit(
            "hosting.gitsync.disconnect",
            Some(detail.id.as_str()),
            &serde_json::json!({ "repo": repo }).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Drop every git-deploy key and secret of a site, and its checkout.
    /// Shared by disconnect and hosting delete — a deleted site's deploy key
    /// must not outlive it, and the checkout lives in the user's home, which
    /// outlives the site when the user owns other sites too.
    pub(super) async fn git_sync_forget(&self, detail: &HostingDetail) {
        let id = detail.id.as_str();
        for k in GITSYNC_KV_KEYS {
            let _ = hyperion_state::hosting_kv::delete(&self.pool, id, k).await;
        }
        let _ = tokio::fs::remove_file(gitsync_key_path(id)).await;
        let _ = tokio::fs::remove_file(gitsync_pat_path(id)).await;
        hyperion_adapters::gitsync::remove_checkout(
            detail.root_dir.trim(),
            detail.system_user.as_str(),
            &self.home_dir_for(detail.system_user.as_str()),
            id,
        )
        .await;
    }
}

/// Where a hosting's deploy private key and access token live: the node's
/// root-only secret store, one file each, keyed by hosting id.
/// Every `hosting_kv` key the git deploy writes.
pub(super) const GITSYNC_KV_KEYS: [&str; 9] = [
    "gitsync_repo",
    "gitsync_branch",
    "gitsync_subdir",
    "gitsync_auth",
    "gitsync_webhook",
    "gitsync_webhook_secret",
    "gitsync_pubkey",
    "gitsync_last",
    "gitsync_history",
];

/// One git deploy per site at a time (deploy, webhook deploy, disconnect).
pub(super) fn gitsync_lock(id: &HostingId) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    let map = LOCKS.get_or_init(Default::default);
    let mut guard = map.lock().unwrap_or_else(|p| p.into_inner());
    guard.entry(id.as_str().to_string()).or_default().clone()
}

/// Mark (`true`) or clear (`false`) a site's queued webhook deploy. Marking
/// returns false when one is already queued.
pub(super) fn gitsync_queue(id: &HostingId, mark: bool) -> bool {
    static QUEUED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let set = QUEUED.get_or_init(Default::default);
    let mut guard = set.lock().unwrap_or_else(|p| p.into_inner());
    if mark {
        guard.insert(id.as_str().to_string())
    } else {
        guard.remove(id.as_str());
        true
    }
}

pub(super) fn gitsync_key_path(id: &str) -> String {
    format!("/etc/hyperion/secrets/gitsync-{id}.key")
}
pub(super) fn gitsync_pat_path(id: &str) -> String {
    format!("/etc/hyperion/secrets/gitsync-{id}.pat")
}
