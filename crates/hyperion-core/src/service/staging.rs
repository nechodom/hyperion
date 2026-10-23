//! WordPress staging copies: create and push back to production.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Best-effort `wp search-replace //from //to` + cache flush on a
    /// WordPress install. Runs wp-cli directly (same path as
    /// wp_reset_password). A non-WP site or wp-cli hiccup is logged, not
    /// fatal — the caller has already moved the files + DB.
    pub(crate) async fn wp_rewrite_domain(
        &self,
        system_user: &str,
        root_dir: &str,
        from: &str,
        to: &str,
    ) {
        let old_url = format!("//{from}");
        let new_url = format!("//{to}");
        let sr = [
            "search-replace",
            old_url.as_str(),
            new_url.as_str(),
            "--all-tables",
            "--skip-columns=guid",
            "--report-changed-only",
        ];
        let argv = hyperion_adapters::wpcli::build_argv(system_user, root_dir, &sr);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        match hyperion_adapters::cmd::run("/usr/bin/sudo", &refs).await {
            Ok(_) => {
                let flush = hyperion_adapters::wpcli::build_argv(
                    system_user,
                    root_dir,
                    &["cache", "flush"],
                );
                let frefs: Vec<&str> = flush.iter().map(String::as_str).collect();
                let _ = hyperion_adapters::cmd::run("/usr/bin/sudo", &frefs).await;
            }
            Err(e) => {
                tracing::info!(error = %e, "wp_rewrite_domain skipped (non-WP or wp-cli error)")
            }
        }
    }

    /// Recursively chown a hosting's home tree to its system user — needed
    /// after restoring an archive that belonged to a *different* user
    /// (staging ↔ prod), where tar preserves the source uid.
    pub(super) async fn chown_home_tree(
        &self,
        system_user: &str,
        domain: &str,
    ) -> Result<(), RpcError> {
        let host_root = format!("{}/{}/{}", self.paths.home_root, system_user, domain);
        let owner = format!("{system_user}:{system_user}");
        hyperion_adapters::cmd::run("/usr/bin/chown", &["-R", &owner, &host_root])
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "chown".into(),
                reason: e.to_string(),
            })?;
        Ok(())
    }

    /// Effective staging hostname for a hosting: the operator's
    /// per-hosting override (trimmed, lowercased) when supplied +
    /// non-empty, else the default `staging.<domain>`.
    pub(super) fn effective_staging_domain(override_in: Option<&str>, prod_domain: &str) -> String {
        match override_in.map(str::trim).filter(|s| !s.is_empty()) {
            Some(custom) => custom.to_ascii_lowercase(),
            None => format!("staging.{prod_domain}"),
        }
    }

    /// Resolve the staging hostname for create/push: an explicit override
    /// (from the form) wins; else the value THIS node persisted at create
    /// time (so push-back works regardless of the master-side metadata
    /// write); else the default `staging.<domain>`.
    pub(super) async fn resolve_staging_domain(
        &self,
        prod_id: &str,
        prod_domain: &str,
        override_in: Option<&str>,
    ) -> String {
        if let Some(s) = override_in.map(str::trim).filter(|s| !s.is_empty()) {
            return s.to_ascii_lowercase();
        }
        if let Ok(Some(v)) =
            hyperion_state::hosting_kv::get(&self.pool, prod_id, "staging_domain").await
        {
            if !v.trim().is_empty() {
                return v.trim().to_ascii_lowercase();
            }
        }
        Self::effective_staging_domain(None, prod_domain)
    }

    /// Create a `staging.<domain>` copy of a WordPress (or any) hosting:
    /// provision a sibling hosting, copy prod's files + DB into it, fix
    /// ownership, and rewrite the WP URL to the staging domain. The
    /// staging site is flagged no-index. Same-node only. `staging_domain`
    /// overrides the default `staging.<domain>` hostname when supplied.
    pub async fn wp_staging_create(
        &self,
        sel: HostingSelector,
        staging_domain: Option<String>,
    ) -> Result<String, RpcError> {
        let prod = self.get(sel).await?;
        let staging_domain = self
            .resolve_staging_domain(prod.id.as_str(), &prod.domain, staging_domain.as_deref())
            .await;
        let staging_dom = hyperion_validate::Domain::parse(&staging_domain).map_err(|e| {
            RpcError::Validation {
                message: format!("staging domain invalid: {e}"),
            }
        })?;
        // A custom hostname must differ from production, or the push-back
        // would overwrite the site it came from.
        if staging_domain == prod.domain {
            return Err(RpcError::Validation {
                message: "staging hostname must differ from the production domain".into(),
            });
        }
        // Refuse if a staging site already exists — push/refresh is a
        // separate, explicit action.
        if self
            .get(HostingSelector::Domain(staging_dom.clone()))
            .await
            .is_ok()
        {
            return Err(RpcError::Conflict {
                message: format!("{staging_domain} already exists — push or delete it first"),
            });
        }

        // DNS preflight: the staging hostname must already resolve to
        // this server, or the cert issuance inside create() will fail.
        // Block on a definite mismatch with a clear, actionable message;
        // tolerate a probe error (network hiccup) and let create() try.
        if let Ok(dns) = self.dns_check(staging_dom.clone()).await {
            if !dns.matches {
                return Err(RpcError::Conflict {
                    message: format!(
                        "{staging_domain} doesn't resolve to this server yet — point its DNS \
                         (an A/AAAA record, or a *.{} wildcard) here first, then retry. {}",
                        prod.domain, dns.note
                    ),
                });
            }
        }

        // 1. Snapshot prod (also our restore source). Internal and local by
        // construction — see `OffsiteSource::NotWanted`.
        let run = self
            .backup_run(
                HostingSelector::Id(prod.id.clone()),
                Vec::new(),
                OffsiteSource::NotWanted,
                None,
            )
            .await?;
        let archive = run
            .archive_path
            .ok_or_else(|| RpcError::ProvisioningFailed {
                stage: "staging_backup".into(),
                reason: "prod backup produced no archive".into(),
            })?;

        // 2. Provision the staging hosting mirroring prod.
        let create = HostingCreateReq {
            domain: staging_dom.clone(),
            aliases: vec![],
            php_version: prod.php_version,
            database: prod.database.as_ref().map(|d| d.engine),
            system_user: None,
            kind: prod.kind.clone(),
            proxy_upstream_url: prod.proxy_upstream_url.clone(),
        };
        let created = self.create(create).await?;

        // 3. Restore prod's snapshot into staging, fix ownership, rewrite.
        if let Err(e) = self
            .backup_restore(
                HostingSelector::Id(created.id.clone()),
                archive,
                hyperion_types::BackupRestoreMode::FilesAndDb,
            )
            .await
        {
            self.roll_back_created(&created.id).await;
            return Err(e);
        }
        let staging = self.get(HostingSelector::Id(created.id.clone())).await?;
        self.chown_home_tree(&staging.system_user, &staging.domain)
            .await?;
        self.wp_rewrite_domain(
            &staging.system_user,
            &staging.root_dir,
            &prod.domain,
            &staging_domain,
        )
        .await;

        // Record the hostname THIS node actually used so push-back +
        // "Open staging" resolve it even if the master-side metadata write
        // didn't land (shared-nothing: the node owns the source of truth).
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            prod.id.as_str(),
            "staging_domain",
            &staging_domain,
            now_secs(),
        )
        .await;

        self.append_audit(
            "wp.staging.create",
            Some(prod.id.as_str()),
            &serde_json::json!({"prod": prod.domain, "staging": staging_domain}).to_string(),
            "ok",
        )
        .await;
        Ok(staging_domain)
    }

    /// Push a `staging.<domain>` site back over production: take a
    /// pre-push safety backup of prod, copy staging's files + DB onto
    /// prod, fix ownership, and rewrite the WP URL back to the prod
    /// domain. Same-node only.
    pub async fn wp_staging_push(
        &self,
        sel: HostingSelector,
        staging_domain: Option<String>,
    ) -> Result<(), RpcError> {
        let prod = self.get(sel).await?;
        let staging_domain = self
            .resolve_staging_domain(prod.id.as_str(), &prod.domain, staging_domain.as_deref())
            .await;
        let staging_dom = hyperion_validate::Domain::parse(&staging_domain).map_err(|e| {
            RpcError::Validation {
                message: format!("staging domain invalid: {e}"),
            }
        })?;
        let staging = self
            .get(HostingSelector::Domain(staging_dom))
            .await
            .map_err(|_| RpcError::Conflict {
                message: format!("no {staging_domain} to push — create a staging site first"),
            })?;

        // 1. Pre-push safety backup of prod (so a bad push is recoverable).
        // Both snapshots are internal rollback material, never an off-site
        // copy anyone was promised — see `OffsiteSource::NotWanted`.
        let _ = self
            .backup_run(
                HostingSelector::Id(prod.id.clone()),
                Vec::new(),
                OffsiteSource::NotWanted,
                None,
            )
            .await?;
        // 2. Snapshot staging — our push source.
        let run = self
            .backup_run(
                HostingSelector::Id(staging.id.clone()),
                Vec::new(),
                OffsiteSource::NotWanted,
                None,
            )
            .await?;
        let archive = run
            .archive_path
            .ok_or_else(|| RpcError::ProvisioningFailed {
                stage: "staging_backup".into(),
                reason: "staging backup produced no archive".into(),
            })?;
        // 3. Restore staging's snapshot over prod, fix ownership, rewrite.
        self.backup_restore(
            HostingSelector::Id(prod.id.clone()),
            archive,
            hyperion_types::BackupRestoreMode::FilesAndDb,
        )
        .await?;
        self.chown_home_tree(&prod.system_user, &prod.domain)
            .await?;
        self.wp_rewrite_domain(
            &prod.system_user,
            &prod.root_dir,
            &staging_domain,
            &prod.domain,
        )
        .await;

        self.append_audit(
            "wp.staging.push",
            Some(prod.id.as_str()),
            &serde_json::json!({"prod": prod.domain, "staging": staging_domain}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }
}
