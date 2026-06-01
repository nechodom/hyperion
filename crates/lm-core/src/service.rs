//! `HostingService` — the orchestrator. Single-node, no transport.

use async_trait::async_trait;
use lm_adapters::rollback::{Rollback, RollbackStack};
use lm_adapters::AdapterError;
use lm_rpc::wire::{DbCredentials, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector};
use lm_rpc::RpcError;
use lm_state::{certificates, databases, hostings, system_users};
use lm_types::{
    now_secs, CertInfo, DbProvision, DbSummary, HostingDetail, HostingId, HostingState,
    HostingSummary, PhpVersion, SecretId,
};
use lm_validate::SystemUserName;
use sqlx::SqlitePool;
use std::sync::Arc;

/// External-effects boundary for `HostingService`.
///
/// In production this is implemented by a thin wrapper around `lm-adapters`.
/// In tests we use `MockAdapterPort` via `mockall::automock`.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AdapterPort: Send + Sync {
    async fn ensure_user(&self, name: &str, home_dir: &str) -> Result<u32, AdapterError>;
    async fn delete_user(&self, name: &str) -> Result<(), AdapterError>;
    async fn ensure_dirs(
        &self,
        htdocs: &str,
        logs: &str,
        tmp: &str,
        owner_uid: u32,
    ) -> Result<(), AdapterError>;
    async fn remove_hosting_tree(&self, root: &str) -> Result<(), AdapterError>;

    async fn fpm_ensure(
        &self,
        system_user: &str,
        domain: &str,
        version: PhpVersion,
    ) -> Result<(), AdapterError>;
    async fn fpm_delete(&self, system_user: &str, version: PhpVersion) -> Result<(), AdapterError>;

    async fn db_create(
        &self,
        engine: DbProvision,
        hosting_id: &HostingId,
        domain: &str,
    ) -> Result<DbCredentials, AdapterError>;
    async fn db_drop(
        &self,
        engine: DbProvision,
        db_name: &str,
        db_user: &str,
    ) -> Result<(), AdapterError>;

    async fn acme_issue(&self, domain: &str, sans: &[String]) -> Result<CertInfo, AdapterError>;
    async fn acme_delete(&self, domain: &str) -> Result<(), AdapterError>;

    async fn nginx_write_vhost(&self, detail: &HostingDetail) -> Result<(), AdapterError>;
    async fn nginx_delete_vhost(&self, domain: &str) -> Result<(), AdapterError>;
    async fn nginx_apply_suspended(
        &self,
        domain: &str,
        reason_message: Option<String>,
    ) -> Result<(), AdapterError>;

    /// Apply per-pool PHP limits (memory, max_children, …). No-op if hosting
    /// has no PHP-FPM pool (static site).
    async fn apply_php_limits(
        &self,
        system_user: &str,
        domain: &str,
        version: Option<PhpVersion>,
        php_memory_mb: i64,
        php_max_exec_secs: i64,
        php_max_children: i64,
        php_max_requests: i64,
    ) -> Result<(), AdapterError>;

    /// Lock the DB user/role so the hosting cannot reach its database.
    async fn db_lock(
        &self,
        engine: DbProvision,
        db_user: &str,
    ) -> Result<(), AdapterError>;
    async fn db_unlock(
        &self,
        engine: DbProvision,
        db_user: &str,
    ) -> Result<(), AdapterError>;

    /// `usermod -L` / `-U` and shell swap to /usr/sbin/nologin.
    async fn linux_lock_login(&self, name: &str) -> Result<(), AdapterError>;
    async fn linux_unlock_login(&self, name: &str) -> Result<(), AdapterError>;

    /// `pkill -KILL -u <name>` to kill any process owned by the suspended user.
    async fn kill_user_procs(&self, name: &str) -> Result<(), AdapterError>;
}

#[derive(Clone)]
pub struct HostingService<A: AdapterPort + 'static> {
    pub pool: SqlitePool,
    pub adapters: Arc<A>,
    pub secrets: Arc<crate::SecretsStore>,
    pub paths: HostingPaths,
}

#[derive(Debug, Clone)]
pub struct HostingPaths {
    pub home_root: String,           // e.g. "/home"
    pub acme_challenge_root: String, // e.g. "/var/lib/linux-manager/acme-challenges"
}

impl Default for HostingPaths {
    fn default() -> Self {
        Self {
            home_root: "/home".into(),
            acme_challenge_root: "/var/lib/linux-manager/acme-challenges".into(),
        }
    }
}

impl<A: AdapterPort + 'static> HostingService<A> {
    pub fn new(pool: SqlitePool, adapters: Arc<A>, secrets: Arc<crate::SecretsStore>) -> Self {
        Self {
            pool,
            adapters,
            secrets,
            paths: HostingPaths::default(),
        }
    }

    pub fn with_paths(mut self, paths: HostingPaths) -> Self {
        self.paths = paths;
        self
    }

    /// Provision a hosting end-to-end with LIFO rollback on partial failure.
    pub async fn create(&self, req: HostingCreateReq) -> Result<HostingCreated, RpcError> {
        // 1. Validate (parse already did most). Derive system user if absent.
        let system_user = match req.system_user.clone() {
            Some(u) => u,
            None => SystemUserName::derive_from_domain(req.domain.as_str())?,
        };
        let domain = req.domain.as_str();
        let home_dir = format!("{}/{}", self.paths.home_root, system_user);
        let hosting_root = format!("{}/{}", home_dir, domain);
        let htdocs = format!("{}/htdocs", hosting_root);
        let logs = format!("{}/logs", hosting_root);
        let tmp = format!("{}/tmp", hosting_root);

        let mut stack = RollbackStack::new();

        // 2. ensure_user
        let uid = match self
            .adapters
            .ensure_user(system_user.as_str(), &home_dir)
            .await
        {
            Ok(u) => u,
            Err(e) => return Err(e.into()),
        };
        stack.push(Box::new(DeleteUser {
            adapters: self.adapters.clone(),
            name: system_user.as_str().to_string(),
        }));

        // 3. ensure_dirs
        if let Err(e) = self.adapters.ensure_dirs(&htdocs, &logs, &tmp, uid).await {
            let _ = stack.rollback_all().await;
            return Err(e.into());
        }
        stack.push(Box::new(RemoveTree {
            adapters: self.adapters.clone(),
            root: hosting_root.clone(),
        }));

        // 4. INSERT hosting row (now we have system_user_id)
        let suid_row = match system_users::insert(
            &self.pool,
            system_user.as_str(),
            uid as i64,
            &home_dir,
            "/usr/sbin/nologin",
            now_secs(),
        )
        .await
        {
            Ok(id) => id,
            Err(e) => {
                // If the user is already in the DB (re-run after partial create), fetch.
                match system_users::get_by_name(&self.pool, system_user.as_str()).await {
                    Ok(Some(row)) => row.id,
                    _ => {
                        let _ = stack.rollback_all().await;
                        return Err(RpcError::Internal_with(format!("system_users insert: {e}")));
                    }
                }
            }
        };
        let hosting_id = HostingId::new_v7();
        if let Err(e) = hostings::insert(
            &self.pool,
            &hosting_id,
            domain,
            suid_row,
            req.php_version,
            &htdocs,
            now_secs(),
        )
        .await
        {
            let _ = stack.rollback_all().await;
            return Err(RpcError::AlreadyExists {
                kind: "hosting".into(),
                id: format!("{} ({})", domain, e),
            });
        }
        let hosting_id_for_rollback = hosting_id.clone();
        stack.push(Box::new(MarkFailedOrDeleteRow {
            pool: self.pool.clone(),
            id: hosting_id_for_rollback,
        }));

        // 4b. aliases
        for alias in &req.aliases {
            if let Err(e) = hostings::insert_alias(&self.pool, &hosting_id, alias.as_str()).await {
                let _ = stack.rollback_all().await;
                return Err(RpcError::AlreadyExists {
                    kind: "alias".into(),
                    id: format!("{} ({})", alias, e),
                });
            }
        }

        // 5. PHP-FPM pool
        if let Some(ver) = req.php_version {
            if let Err(e) = self
                .adapters
                .fpm_ensure(system_user.as_str(), domain, ver)
                .await
            {
                let _ = stack.rollback_all().await;
                return Err(e.into());
            }
            stack.push(Box::new(FpmDelete {
                adapters: self.adapters.clone(),
                system_user: system_user.as_str().to_string(),
                version: ver,
            }));
        }

        // 6. database
        let mut db_creds: Option<DbCredentials> = None;
        if let Some(engine) = req.database {
            let creds = match self.adapters.db_create(engine, &hosting_id, domain).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = stack.rollback_all().await;
                    return Err(e.into());
                }
            };
            let secret_id = SecretId::new();
            if let Err(e) = self
                .secrets
                .put(
                    &secret_id,
                    &serde_json::json!({
                        "engine": engine.as_str(),
                        "db_name": creds.db_name,
                        "db_user": creds.db_user,
                        "password": creds.password,
                    }),
                )
                .await
            {
                let _ = stack.rollback_all().await;
                return Err(RpcError::Internal_with(format!("secret write: {e}")));
            }
            if let Err(e) = databases::insert(
                &self.pool,
                &hosting_id,
                engine,
                &creds.db_name,
                &creds.db_user,
                &secret_id,
                now_secs(),
            )
            .await
            {
                let _ = stack.rollback_all().await;
                return Err(RpcError::Internal_with(format!("databases row: {e}")));
            }
            let db_name_for_rb = creds.db_name.clone();
            let db_user_for_rb = creds.db_user.clone();
            stack.push(Box::new(DbDrop {
                adapters: self.adapters.clone(),
                engine,
                db_name: db_name_for_rb,
                db_user: db_user_for_rb,
            }));
            db_creds = Some(creds);
        }

        // 7. ACME cert
        let sans: Vec<String> = req.aliases.iter().map(|d| d.to_string()).collect();
        let cert = match self.adapters.acme_issue(domain, &sans).await {
            Ok(c) => c,
            Err(e) => {
                let _ = stack.rollback_all().await;
                return Err(e.into());
            }
        };
        let cert_path = format!("/etc/linux-manager/certs/{}/fullchain.pem", domain);
        let key_path = format!("/etc/linux-manager/certs/{}/privkey.pem", domain);
        let _ = certificates::upsert(
            &self.pool,
            domain,
            now_secs(),
            cert.not_after,
            &cert_path,
            &key_path,
            &cert.issuer,
        )
        .await;
        stack.push(Box::new(AcmeDelete {
            adapters: self.adapters.clone(),
            domain: domain.to_string(),
        }));

        // 8. nginx vhost
        let detail = HostingDetail {
            id: hosting_id.clone(),
            domain: domain.to_string(),
            aliases: sans.clone(),
            state: HostingState::Provisioning,
            system_user: system_user.as_str().to_string(),
            php_version: req.php_version,
            root_dir: htdocs.clone(),
            database: db_creds.as_ref().map(|c| DbSummary {
                engine: c.engine,
                db_name: c.db_name.clone(),
                db_user: c.db_user.clone(),
            }),
            cert: Some(cert.clone()),
            created_at: now_secs(),
            updated_at: now_secs(),
        };
        if let Err(e) = self.adapters.nginx_write_vhost(&detail).await {
            let _ = stack.rollback_all().await;
            return Err(e.into());
        }

        // 9. transition to active
        if let Err(e) =
            hostings::set_state(&self.pool, &hosting_id, HostingState::Active, now_secs()).await
        {
            // We were so close.
            let _ = stack.rollback_all().await;
            return Err(RpcError::Internal_with(format!("set_state: {e}")));
        }

        // success — discard rollback
        stack.forget();

        Ok(HostingCreated {
            id: hosting_id,
            system_user: system_user.as_str().to_string(),
            root_dir: htdocs,
            db: db_creds,
            cert: Some(cert),
        })
    }

    pub async fn list(&self) -> Result<Vec<HostingSummary>, RpcError> {
        hostings::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))
    }

    pub async fn get(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError> {
        let row = match sel {
            HostingSelector::Id(id) => hostings::get_by_id(&self.pool, &id).await,
            HostingSelector::Domain(d) => hostings::get_by_domain(&self.pool, d.as_str()).await,
        }
        .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
        .ok_or_else(|| RpcError::NotFound {
            kind: "hosting".into(),
            id: "selector".into(),
        })?;

        let aliases = hostings::aliases(&self.pool, &row.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("aliases: {e}")))?;
        let db = databases::get_for_hosting(&self.pool, &row.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("databases: {e}")))?
            .map(|d| DbSummary {
                engine: d.engine,
                db_name: d.db_name,
                db_user: d.db_user,
            });
        let cert_row = certificates::get(&self.pool, &row.domain)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cert: {e}")))?;
        let cert = cert_row.map(|c| CertInfo {
            domain: c.domain,
            sans: aliases.clone(),
            issuer: c.issuer,
            not_after: c.not_after,
            fingerprint_sha256: String::new(),
        });
        let suser = system_users::get_by_name(&self.pool, "")
            .await
            .ok()
            .flatten();
        let system_user_name = match suser {
            Some(_) => String::new(),
            None => {
                match sqlx::query_as::<_, (String,)>("SELECT name FROM system_users WHERE id = ?")
                    .bind(row.system_user_id)
                    .fetch_optional(&self.pool)
                    .await
                {
                    Ok(Some((s,))) => s,
                    _ => String::new(),
                }
            }
        };
        Ok(HostingDetail {
            id: row.id,
            domain: row.domain,
            aliases,
            state: row.state,
            system_user: system_user_name,
            php_version: row.php_version,
            root_dir: row.root_dir,
            database: db,
            cert,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    pub async fn delete(&self, sel: HostingSelector, opts: DeleteOpts) -> Result<(), RpcError> {
        let detail = self.get(sel.clone()).await?;
        hostings::set_state(&self.pool, &detail.id, HostingState::Deleting, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set deleting: {e}")))?;

        // best-effort nginx delete
        let _ = self.adapters.nginx_delete_vhost(&detail.domain).await;
        // best-effort cert delete
        let _ = self.adapters.acme_delete(&detail.domain).await;
        let _ = certificates::delete(&self.pool, &detail.domain).await;
        // db drop
        if let Some(db) = detail.database.as_ref() {
            if !opts.keep_database {
                let _ = self
                    .adapters
                    .db_drop(db.engine, &db.db_name, &db.db_user)
                    .await;
            }
        }
        // fpm pool delete
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        // remove tree
        let hosting_root = format!(
            "{}/{}/{}",
            self.paths.home_root, detail.system_user, detail.domain
        );
        let _ = self.adapters.remove_hosting_tree(&hosting_root).await;

        if !opts.keep_user {
            // delete user only if no other hostings reference them
            let (others,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM hostings WHERE system_user_id = (SELECT id FROM system_users WHERE name = ?) AND id != ?")
                    .bind(&detail.system_user)
                    .bind(detail.id.as_str())
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("count: {e}")))?;
            if others == 0 {
                let _ = self.adapters.delete_user(&detail.system_user).await;
            }
        }

        hostings::delete(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete row: {e}")))?;
        Ok(())
    }

    /// Apply / replace the per-hosting limits. Persists the row, then asks the
    /// adapter to apply the PHP-FPM side effects. Returns the canonical row
    /// (so callers see exactly what was stored after defaults / clamping).
    pub async fn set_limits(
        &self,
        sel: HostingSelector,
        limits: lm_types::HostingLimits,
    ) -> Result<lm_types::HostingLimits, RpcError> {
        let detail = self.get(sel).await?;
        let limits = clamp_limits(limits);
        let row = limits_to_row(&detail.id, &limits, now_secs());
        lm_state::limits::upsert(&self.pool, &row)
            .await
            .map_err(|e| RpcError::Internal_with(format!("limits upsert: {e}")))?;
        if let Err(e) = self
            .adapters
            .apply_php_limits(
                &detail.system_user,
                &detail.domain,
                detail.php_version,
                limits.php_memory_mb,
                limits.php_max_exec_secs,
                limits.php_max_children,
                limits.php_max_requests,
            )
            .await
        {
            return Err(e.into());
        }
        Ok(limits)
    }

    pub async fn get_limits(
        &self,
        sel: HostingSelector,
    ) -> Result<lm_types::HostingLimits, RpcError> {
        let detail = self.get(sel).await?;
        let row = lm_state::limits::get(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("limits get: {e}")))?;
        Ok(row.map(row_to_limits).unwrap_or_else(lm_types::HostingLimits::defaults))
    }

    /// Best-effort suspend. State row goes to 'suspended'; cascading effects
    /// (nginx swap, FPM stop, DB lock, login lock, kill procs) run as
    /// best-effort — failures are logged but don't revert state. Suspended is
    /// the safer state; operators retry to converge.
    pub async fn suspend(
        &self,
        sel: HostingSelector,
        reason: lm_types::SuspendReason,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state == HostingState::Suspended {
            return Ok(());
        }
        if detail.state == HostingState::Deleting {
            return Err(RpcError::Conflict {
                message: "hosting is being deleted".into(),
            });
        }
        hostings::set_state(&self.pool, &detail.id, HostingState::Suspended, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set suspended: {e}")))?;
        let susp = lm_state::limits::SuspensionRow {
            hosting_id: detail.id.clone(),
            suspended_at: now_secs(),
            suspended_by: reason.label().to_string(),
            reason_message: reason.message().map(|s| s.to_string()),
            custom_page_html: None,
        };
        lm_state::limits::insert_suspension(&self.pool, &susp)
            .await
            .map_err(|e| RpcError::Internal_with(format!("insert suspension: {e}")))?;

        let _ = self
            .adapters
            .nginx_apply_suspended(&detail.domain, reason.message().map(|s| s.to_string()))
            .await;
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_lock(db.engine, &db.db_user).await;
        }
        let _ = self.adapters.linux_lock_login(&detail.system_user).await;
        let _ = self.adapters.kill_user_procs(&detail.system_user).await;

        self.append_audit(
            "hosting.suspend",
            Some(detail.id.as_str()),
            &serde_json::json!({"reason": reason.label()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Undo a suspend. Brings the hosting back to 'active'.
    pub async fn resume(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Suspended {
            return Ok(());
        }
        // Re-apply effects in resume order.
        let _ = self.adapters.linux_unlock_login(&detail.system_user).await;
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_unlock(db.engine, &db.db_user).await;
        }
        if let Some(ver) = detail.php_version {
            let _ = self
                .adapters
                .fpm_ensure(&detail.system_user, &detail.domain, ver)
                .await;
            // Re-apply persisted limits to FPM pool.
            if let Ok(Some(row)) = lm_state::limits::get(&self.pool, &detail.id).await {
                let _ = self
                    .adapters
                    .apply_php_limits(
                        &detail.system_user,
                        &detail.domain,
                        Some(ver),
                        row.php_memory_mb,
                        row.php_max_exec_secs,
                        row.php_max_children,
                        row.php_max_requests,
                    )
                    .await;
            }
        }
        let _ = self.adapters.nginx_write_vhost(&detail).await;
        hostings::set_state(&self.pool, &detail.id, HostingState::Active, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set active: {e}")))?;
        lm_state::limits::delete_suspension(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete suspension: {e}")))?;
        self.append_audit(
            "hosting.resume",
            Some(detail.id.as_str()),
            "{}",
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn usage(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<lm_types::HostingUsageBucket>, RpcError> {
        let detail = self.get(sel).await?;
        let rows = lm_state::limits::usage_for(&self.pool, &detail.id, limit.max(1).min(744))
            .await
            .map_err(|e| RpcError::Internal_with(format!("usage: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|b| lm_types::HostingUsageBucket {
                period: b.period,
                disk_used_bytes: b.disk_used_bytes,
                inodes_used: b.inodes_used,
                bw_in_bytes: b.bw_in_bytes,
                bw_out_bytes: b.bw_out_bytes,
                php_requests: b.php_requests,
            })
            .collect())
    }

    pub async fn set_expiry(
        &self,
        sel: HostingSelector,
        expiry: lm_types::HostingExpiry,
    ) -> Result<lm_types::HostingExpiry, RpcError> {
        let detail = self.get(sel).await?;
        let grace = expiry.grace_days.clamp(1, 365);
        let offsets = lm_state::scheduler::parse_offsets(&expiry.warning_offsets_days);
        let csv = if offsets.is_empty() {
            "30,7,1".to_string()
        } else {
            offsets
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        lm_state::scheduler::set_expiry(
            &self.pool,
            &detail.id,
            expiry.expires_at,
            expiry.owner_email.as_deref(),
            grace,
            &csv,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set_expiry: {e}")))?;
        // Cancel any previously-queued actions and re-schedule from scratch.
        lm_state::scheduler::cancel_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cancel: {e}")))?;
        if let Some(exp) = expiry.expires_at {
            self.reschedule_actions_for(&detail.id, exp, grace, &offsets).await?;
        }
        self.append_audit(
            "hosting.set_expiry",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "expires_at": expiry.expires_at,
                "grace_days": grace,
            })
            .to_string(),
            "ok",
        )
        .await;
        let updated = lm_state::scheduler::get_expiry(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get_expiry: {e}")))?
            .ok_or(RpcError::Internal)?;
        Ok(expiry_row_to_dto(updated))
    }

    pub async fn get_expiry(
        &self,
        sel: HostingSelector,
    ) -> Result<lm_types::HostingExpiry, RpcError> {
        let detail = self.get(sel).await?;
        let row = lm_state::scheduler::get_expiry(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get_expiry: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.0.clone(),
            })?;
        Ok(expiry_row_to_dto(row))
    }

    pub async fn clear_expiry(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        lm_state::scheduler::set_expiry(
            &self.pool, &detail.id, None, None, 30, "30,7,1", now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("clear: {e}")))?;
        lm_state::scheduler::cancel_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cancel: {e}")))?;
        self.append_audit(
            "hosting.clear_expiry",
            Some(detail.id.as_str()),
            "{}",
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn upcoming_expiries(
        &self,
        within_seconds: i64,
    ) -> Result<Vec<lm_types::ExpiringHosting>, RpcError> {
        let rows = lm_state::scheduler::list_with_expiry(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        let cutoff = now_secs() + within_seconds.max(0);
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let exp = r.expires_at?;
                if exp <= cutoff {
                    Some(lm_types::ExpiringHosting {
                        id: r.id,
                        domain: r.domain,
                        expires_at: exp,
                        owner_email: r.owner_email,
                        grace_days: r.grace_days,
                    })
                } else {
                    None
                }
            })
            .collect())
    }

    /// Drive one tick of the scheduler. Returns the number of actions
    /// processed (success + failed). Designed to be called both manually
    /// and from a tokio interval task in lm-agent.
    pub async fn scheduler_tick(&self) -> Result<i64, RpcError> {
        // 1. Make sure every hosting with an expires_at has its scheduled rows.
        self.reconcile_scheduled_rows()
            .await
            .map_err(|e| RpcError::Internal_with(format!("reconcile: {e}")))?;

        // 2. Take a slice of due, pending actions.
        let now = now_secs();
        let due = lm_state::scheduler::pending_due(&self.pool, now, 100)
            .await
            .map_err(|e| RpcError::Internal_with(format!("pending_due: {e}")))?;
        let mut processed = 0i64;
        for action in due {
            lm_state::scheduler::mark_running(&self.pool, action.id, now)
                .await
                .map_err(|e| RpcError::Internal_with(format!("mark_running: {e}")))?;
            let result = self.run_action(&action).await;
            match result {
                Ok(()) => {
                    lm_state::scheduler::mark_done(&self.pool, action.id)
                        .await
                        .map_err(|e| RpcError::Internal_with(format!("mark_done: {e}")))?;
                }
                Err(e) => {
                    tracing::warn!(action_id=action.id, error=%e, "scheduled action failed");
                    lm_state::scheduler::mark_failed_or_retry(
                        &self.pool,
                        action.id,
                        &e,
                        3,
                    )
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("mark_failed: {e}")))?;
                }
            }
            processed += 1;
        }
        Ok(processed)
    }

    async fn reconcile_scheduled_rows(&self) -> Result<(), lm_state::StateError> {
        let rows = lm_state::scheduler::list_with_expiry(&self.pool).await?;
        let now = now_secs();
        for r in rows {
            let Some(exp) = r.expires_at else { continue };
            let offsets = lm_state::scheduler::parse_offsets(&r.warning_offsets_days);
            // Map each offset to a notification kind. Beyond the spec's
            // 30/7/1-day defaults we still queue extras, but we tag any
            // offset >= 30 as Notify30d, 7..30 as Notify7d, <7 as Notify1d
            // (good-enough bucketing for v1).
            for offset_days in &offsets {
                let kind = if *offset_days >= 30 {
                    lm_state::scheduler::ScheduledKind::Notify30d
                } else if *offset_days >= 7 {
                    lm_state::scheduler::ScheduledKind::Notify7d
                } else {
                    lm_state::scheduler::ScheduledKind::Notify1d
                };
                let due = exp - offset_days * 86_400;
                if due > now - 7 * 86_400 {
                    lm_state::scheduler::upsert(&self.pool, &r.id, kind, due, now).await?;
                }
            }
            lm_state::scheduler::upsert(
                &self.pool,
                &r.id,
                lm_state::scheduler::ScheduledKind::SuspendExpired,
                exp,
                now,
            )
            .await?;
            let delete_at = exp + r.grace_days.max(1) * 86_400;
            lm_state::scheduler::upsert(
                &self.pool,
                &r.id,
                lm_state::scheduler::ScheduledKind::DeleteExpired,
                delete_at,
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn reschedule_actions_for(
        &self,
        id: &HostingId,
        expires_at: i64,
        grace_days: i64,
        offsets: &[i64],
    ) -> Result<(), RpcError> {
        let now = now_secs();
        for offset_days in offsets {
            let kind = if *offset_days >= 30 {
                lm_state::scheduler::ScheduledKind::Notify30d
            } else if *offset_days >= 7 {
                lm_state::scheduler::ScheduledKind::Notify7d
            } else {
                lm_state::scheduler::ScheduledKind::Notify1d
            };
            let due = expires_at - offset_days * 86_400;
            if due > now - 7 * 86_400 {
                lm_state::scheduler::upsert(&self.pool, id, kind, due, now)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
            }
        }
        lm_state::scheduler::upsert(
            &self.pool,
            id,
            lm_state::scheduler::ScheduledKind::SuspendExpired,
            expires_at,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
        let delete_at = expires_at + grace_days.max(1) * 86_400;
        lm_state::scheduler::upsert(
            &self.pool,
            id,
            lm_state::scheduler::ScheduledKind::DeleteExpired,
            delete_at,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
        Ok(())
    }

    async fn run_action(
        &self,
        action: &lm_state::scheduler::ScheduledRow,
    ) -> Result<(), String> {
        use lm_state::scheduler::ScheduledKind;
        match action.action {
            ScheduledKind::Notify30d | ScheduledKind::Notify7d | ScheduledKind::Notify1d => {
                // Foundation: we log the notification. Real SMTP integration
                // is config-gated and ships with the controller (sub-project 4).
                let row = lm_state::scheduler::get_expiry(&self.pool, &action.hosting_id)
                    .await
                    .map_err(|e| e.to_string())?;
                let email = row.as_ref().and_then(|r| r.owner_email.as_deref());
                tracing::info!(
                    hosting=%action.hosting_id, action=action.action.as_str(),
                    owner=email.unwrap_or("<none>"),
                    "expiry notification due",
                );
                self.append_audit(
                    "scheduler.notify",
                    Some(action.hosting_id.as_str()),
                    &serde_json::json!({"kind": action.action.as_str()}).to_string(),
                    "ok",
                )
                .await;
                Ok(())
            }
            ScheduledKind::SuspendExpired => {
                self.suspend(
                    HostingSelector::Id(action.hosting_id.clone()),
                    lm_types::SuspendReason::Expired,
                )
                .await
                .map_err(|e| e.to_string())
            }
            ScheduledKind::DeleteExpired => self
                .delete(
                    HostingSelector::Id(action.hosting_id.clone()),
                    lm_rpc::wire::DeleteOpts::default(),
                )
                .await
                .map_err(|e| e.to_string()),
        }
    }

    pub async fn audit_list(
        &self,
        limit: i64,
    ) -> Result<Vec<lm_rpc::AuditEntryWire>, RpcError> {
        let rows = lm_state::audit::list(&self.pool, limit.max(1).min(1000))
            .await
            .map_err(|e| RpcError::Internal_with(format!("audit list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|e| lm_rpc::AuditEntryWire {
                id: e.id,
                ts: e.ts,
                actor_uid: e.actor_uid,
                actor_label: e.actor_label,
                action: e.action,
                target: e.target,
                payload_json: e.payload_json,
                result: e.result,
            })
            .collect())
    }

    pub(crate) async fn append_audit(
        &self,
        action: &str,
        target: Option<&str>,
        payload_json: &str,
        result: &str,
    ) {
        let r = lm_state::audit::append(
            &self.pool,
            lm_state::audit::AppendReq {
                ts: now_secs(),
                actor_uid: 0,
                actor_label: "agent",
                action,
                target,
                payload_json,
                result,
            },
        )
        .await;
        if let Err(e) = r {
            tracing::warn!(error=%e, "audit append failed");
        }
    }
}

fn expiry_row_to_dto(row: lm_state::scheduler::ExpiryRow) -> lm_types::HostingExpiry {
    lm_types::HostingExpiry {
        expires_at: row.expires_at,
        owner_email: row.owner_email,
        grace_days: row.grace_days,
        warning_offsets_days: row.warning_offsets_days,
    }
}

fn clamp_limits(mut l: lm_types::HostingLimits) -> lm_types::HostingLimits {
    // Hard sanity ranges. Refusing to store nonsense is more useful than
    // silently mis-applying it later.
    l.php_memory_mb = l.php_memory_mb.clamp(16, 8192);
    l.php_max_exec_secs = l.php_max_exec_secs.clamp(1, 3600);
    l.php_max_children = l.php_max_children.clamp(1, 200);
    l.php_max_requests = l.php_max_requests.clamp(0, 1_000_000);
    l.db_max_connections = l.db_max_connections.clamp(1, 1000);
    if let Some(b) = l.disk_soft_bytes {
        l.disk_soft_bytes = Some(b.max(0));
    }
    if let Some(b) = l.disk_hard_bytes {
        l.disk_hard_bytes = Some(b.max(0));
    }
    if let Some(b) = l.bw_monthly_bytes {
        l.bw_monthly_bytes = Some(b.max(0));
    }
    if let Some(k) = l.throttle_kbps {
        l.throttle_kbps = Some(k.clamp(1, 10_000_000));
    }
    l
}

fn limits_to_row(
    id: &HostingId,
    l: &lm_types::HostingLimits,
    now: i64,
) -> lm_state::limits::LimitsRow {
    lm_state::limits::LimitsRow {
        hosting_id: id.clone(),
        disk_soft_bytes: l.disk_soft_bytes,
        disk_hard_bytes: l.disk_hard_bytes,
        inode_soft: l.inode_soft,
        inode_hard: l.inode_hard,
        php_memory_mb: l.php_memory_mb,
        php_max_exec_secs: l.php_max_exec_secs,
        php_max_children: l.php_max_children,
        php_max_requests: l.php_max_requests,
        db_max_connections: l.db_max_connections,
        bw_monthly_bytes: l.bw_monthly_bytes,
        over_bw_policy: l.over_bw_policy.as_str().to_string(),
        throttle_kbps: l.throttle_kbps,
        updated_at: now,
    }
}

fn row_to_limits(row: lm_state::limits::LimitsRow) -> lm_types::HostingLimits {
    let policy = match row.over_bw_policy.as_str() {
        "throttle" => lm_types::OverBwPolicy::Throttle,
        _ => lm_types::OverBwPolicy::Suspend,
    };
    lm_types::HostingLimits {
        disk_soft_bytes: row.disk_soft_bytes,
        disk_hard_bytes: row.disk_hard_bytes,
        inode_soft: row.inode_soft,
        inode_hard: row.inode_hard,
        php_memory_mb: row.php_memory_mb,
        php_max_exec_secs: row.php_max_exec_secs,
        php_max_children: row.php_max_children,
        php_max_requests: row.php_max_requests,
        db_max_connections: row.db_max_connections,
        bw_monthly_bytes: row.bw_monthly_bytes,
        over_bw_policy: policy,
        throttle_kbps: row.throttle_kbps,
    }
}

// ===== Internal-error helper =====
trait InternalWith {
    fn internal_with(msg: String) -> Self;
}
impl InternalWith for RpcError {
    fn internal_with(msg: String) -> Self {
        tracing::error!(error=%msg, "internal error");
        RpcError::Internal
    }
}

// Allow `RpcError::Internal_with(..)` call style.
#[allow(non_snake_case)]
impl RpcErrorExt for RpcError {
    fn Internal_with(msg: String) -> Self {
        <RpcError as InternalWith>::internal_with(msg)
    }
}

trait RpcErrorExt {
    #[allow(non_snake_case)]
    fn Internal_with(msg: String) -> Self;
}

// ===== Rollback impls =====

struct DeleteUser<A: AdapterPort> {
    adapters: Arc<A>,
    name: String,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for DeleteUser<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .delete_user(&self.name)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "delete_user"
    }
}

struct RemoveTree<A: AdapterPort> {
    adapters: Arc<A>,
    root: String,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for RemoveTree<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .remove_hosting_tree(&self.root)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "remove_tree"
    }
}

struct MarkFailedOrDeleteRow {
    pool: SqlitePool,
    id: HostingId,
}
#[async_trait]
impl Rollback for MarkFailedOrDeleteRow {
    async fn run(&self) -> Result<(), String> {
        hostings::set_state(&self.pool, &self.id, HostingState::Failed, now_secs())
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "mark_hosting_failed"
    }
}

struct FpmDelete<A: AdapterPort> {
    adapters: Arc<A>,
    system_user: String,
    version: PhpVersion,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for FpmDelete<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .fpm_delete(&self.system_user, self.version)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "fpm_delete"
    }
}

struct DbDrop<A: AdapterPort> {
    adapters: Arc<A>,
    engine: DbProvision,
    db_name: String,
    db_user: String,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for DbDrop<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .db_drop(self.engine, &self.db_name, &self.db_user)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "db_drop"
    }
}

struct AcmeDelete<A: AdapterPort> {
    adapters: Arc<A>,
    domain: String,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for AcmeDelete<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .acme_delete(&self.domain)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "acme_delete"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretsStore;
    use lm_state::db::open_memory;
    use lm_types::{CertInfo, DbProvision};
    use lm_validate::Domain;
    use mockall::predicate::*;

    fn req(d: &str) -> HostingCreateReq {
        HostingCreateReq {
            domain: Domain::parse(d).expect("parse"),
            aliases: vec![],
            php_version: Some(PhpVersion::V8_3),
            database: Some(DbProvision::MariaDB),
            system_user: None,
        }
    }

    fn cert_for(d: &str) -> CertInfo {
        CertInfo {
            domain: d.into(),
            sans: vec![],
            issuer: "letsencrypt".into(),
            not_after: 1_700_000_000,
            fingerprint_sha256: "deadbeef".into(),
        }
    }

    fn db_creds() -> DbCredentials {
        DbCredentials {
            engine: DbProvision::MariaDB,
            db_name: "lm_a".into(),
            db_user: "lm_u".into(),
            password: "p".into(),
        }
    }

    fn happy_mocks() -> MockAdapterPort {
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost().returning(|_| Ok(()));
        a
    }

    fn svc(pool: SqlitePool, a: MockAdapterPort) -> HostingService<MockAdapterPort> {
        let secrets_dir = tempfile::tempdir().expect("dir");
        let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
        HostingService::new(pool, Arc::new(a), secrets)
    }

    #[tokio::test]
    async fn create_happy_path() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        let r = s.create(req("example.cz")).await.expect("create");
        assert!(r.db.is_some());
        let detail = s
            .get(HostingSelector::Domain(
                Domain::parse("example.cz").expect("parse"),
            ))
            .await
            .expect("get");
        assert_eq!(detail.state, HostingState::Active);
        assert_eq!(detail.system_user, "example_cz");
    }

    #[tokio::test]
    async fn create_rolls_back_on_acme_failure() {
        let pool = open_memory().await.expect("open");
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue()
            .returning(|_, _| Err(AdapterError::Acme("dns".into())));
        // Expect rollbacks for the four prior steps.
        a.expect_db_drop().returning(|_, _, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_remove_hosting_tree().returning(|_| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        let r = s.create(req("example.cz")).await;
        assert!(r.is_err());
        let row = hostings::get_by_domain(&pool, "example.cz")
            .await
            .expect("query");
        match row {
            Some(r) => assert_eq!(r.state, HostingState::Failed),
            None => {}
        }
    }

    #[tokio::test]
    async fn create_rolls_back_on_nginx_failure() {
        let pool = open_memory().await.expect("open");
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost()
            .returning(|_| Err(AdapterError::Other("nginx -t failed".into())));
        a.expect_acme_delete().returning(|_| Ok(()));
        a.expect_db_drop().returning(|_, _, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_remove_hosting_tree().returning(|_| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        let r = s.create(req("example.cz")).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn list_returns_active_after_create() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool, happy_mocks());
        s.create(req("a.cz")).await.expect("a");
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1043));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost().returning(|_| Ok(()));
        // Replace the adapter for the second call using a fresh svc.
        let secrets_dir = tempfile::tempdir().expect("dir");
        let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
        let s2 = HostingService {
            pool: s.pool.clone(),
            adapters: Arc::new(a),
            secrets,
            paths: HostingPaths::default(),
        };
        s2.create(HostingCreateReq {
            domain: Domain::parse("b.cz").expect("parse"),
            aliases: vec![],
            php_version: None,
            database: None,
            system_user: None,
        })
        .await
        .expect("b");
        let rows = s.list().await.expect("list");
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn duplicate_domain_is_already_exists() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("dup.cz")).await.expect("first ok");
        // Second create: fresh mock with the same expectations.
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1043));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        a.expect_remove_hosting_tree().returning(|_| Ok(()));
        let secrets_dir = tempfile::tempdir().expect("dir");
        let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
        let s2 = HostingService {
            pool: s.pool.clone(),
            adapters: Arc::new(a),
            secrets,
            paths: HostingPaths::default(),
        };
        let r = s2.create(req("dup.cz")).await;
        match r {
            Err(RpcError::AlreadyExists { kind, .. }) => assert_eq!(kind, "hosting"),
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    fn suspend_mocks() -> MockAdapterPort {
        let mut a = happy_mocks();
        a.expect_nginx_apply_suspended().returning(|_, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_db_lock().returning(|_, _| Ok(()));
        a.expect_linux_lock_login().returning(|_| Ok(()));
        a.expect_kill_user_procs().returning(|_| Ok(()));
        a
    }

    fn resume_mocks() -> MockAdapterPort {
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost().returning(|_| Ok(()));
        a.expect_nginx_apply_suspended().returning(|_, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_db_lock().returning(|_, _| Ok(()));
        a.expect_linux_lock_login().returning(|_| Ok(()));
        a.expect_kill_user_procs().returning(|_| Ok(()));
        a.expect_linux_unlock_login().returning(|_| Ok(()));
        a.expect_db_unlock().returning(|_, _| Ok(()));
        a.expect_apply_php_limits()
            .returning(|_, _, _, _, _, _, _| Ok(()));
        a
    }

    #[tokio::test]
    async fn suspend_sets_state_and_writes_suspension_row() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), suspend_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        s.suspend(
            sel.clone(),
            lm_types::SuspendReason::Manual {
                message: Some("over quota".into()),
            },
        )
        .await
        .expect("suspend");
        let detail = s.get(sel).await.expect("get");
        assert_eq!(detail.state, HostingState::Suspended);
        let row = lm_state::limits::get_suspension(&pool, &detail.id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(row.suspended_by, "manual");
        assert_eq!(row.reason_message.as_deref(), Some("over quota"));
    }

    #[tokio::test]
    async fn suspend_is_idempotent_for_already_suspended() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), suspend_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        s.suspend(sel.clone(), lm_types::SuspendReason::Expired)
            .await
            .expect("first");
        // Second call is a no-op; no extra adapter calls beyond what
        // suspend_mocks already allows. Should succeed.
        s.suspend(sel, lm_types::SuspendReason::Expired)
            .await
            .expect("idempotent");
    }

    #[tokio::test]
    async fn suspend_refuses_when_already_deleting() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), suspend_mocks());
        let created = s.create(req("ex.cz")).await.expect("create");
        // Force into 'deleting' directly.
        lm_state::hostings::set_state(
            &pool,
            &created.id,
            HostingState::Deleting,
            now_secs(),
        )
        .await
        .expect("set");
        let sel = HostingSelector::Id(created.id.clone());
        let r = s
            .suspend(sel, lm_types::SuspendReason::Manual { message: None })
            .await;
        match r {
            Err(RpcError::Conflict { .. }) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resume_brings_back_to_active() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), resume_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        s.suspend(sel.clone(), lm_types::SuspendReason::Expired)
            .await
            .expect("suspend");
        s.resume(sel.clone()).await.expect("resume");
        let detail = s.get(sel).await.expect("get");
        assert_eq!(detail.state, HostingState::Active);
        let susp = lm_state::limits::get_suspension(&pool, &detail.id)
            .await
            .expect("get");
        assert!(susp.is_none(), "suspension row removed on resume");
    }

    #[tokio::test]
    async fn set_limits_clamps_and_persists() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_apply_php_limits()
            .returning(|_, _, _, _, _, _, _| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        let mut l = lm_types::HostingLimits::defaults();
        l.php_memory_mb = 100_000; // nonsense
        l.php_max_children = 0; // nonsense
        let stored = s.set_limits(sel.clone(), l).await.expect("set");
        assert_eq!(stored.php_memory_mb, 8192, "clamped to upper bound");
        assert_eq!(stored.php_max_children, 1, "clamped to lower bound");
        // Round-trip via get_limits
        let l2 = s.get_limits(sel).await.expect("get");
        assert_eq!(l2, stored);
    }

    #[tokio::test]
    async fn get_limits_defaults_when_no_row() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        let l = s.get_limits(sel).await.expect("get");
        assert_eq!(l, lm_types::HostingLimits::defaults());
    }

    #[tokio::test]
    async fn set_expiry_schedules_actions_and_clear_cancels() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        let exp = now_secs() + 2 * 86_400;
        let mut e = lm_types::HostingExpiry::defaults();
        e.expires_at = Some(exp);
        e.grace_days = 7;
        e.owner_email = Some("k@x.cz".into());
        let stored = s.set_expiry(sel.clone(), e).await.expect("set");
        assert_eq!(stored.expires_at, Some(exp));
        assert_eq!(stored.grace_days, 7);

        let due_far_future = lm_state::scheduler::pending_due(&pool, exp + 100 * 86_400, 100)
            .await
            .expect("pending");
        let actions: Vec<&str> = due_far_future.iter().map(|a| a.action.as_str()).collect();
        assert!(actions.contains(&"suspend_expired"));
        assert!(actions.contains(&"delete_expired"));
        assert!(actions.contains(&"notify_1d"));

        s.clear_expiry(sel).await.expect("clear");
        let after = lm_state::scheduler::pending_due(&pool, exp + 100 * 86_400, 100)
            .await
            .expect("pending");
        assert!(after.is_empty(), "actions canceled");
    }

    #[tokio::test]
    async fn scheduler_tick_runs_suspend_for_expired_hosting() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), suspend_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());

        let past = now_secs() - 86_400;
        let mut e = lm_types::HostingExpiry::defaults();
        e.expires_at = Some(past);
        s.set_expiry(sel.clone(), e).await.expect("set");
        let processed = s.scheduler_tick().await.expect("tick");
        assert!(processed >= 1, "processed: {processed}");

        let detail = s.get(sel).await.expect("get");
        assert_eq!(detail.state, HostingState::Suspended);
    }

    #[tokio::test]
    async fn upcoming_expiries_filters_by_window() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("a.cz")).await.expect("a");
        let sel = HostingSelector::Domain(Domain::parse("a.cz").unwrap());
        let exp = now_secs() + 10 * 86_400;
        let mut e = lm_types::HostingExpiry::defaults();
        e.expires_at = Some(exp);
        s.set_expiry(sel, e).await.expect("set");

        let within_5d = s.upcoming_expiries(5 * 86_400).await.expect("up");
        assert!(within_5d.is_empty(), "10d > 5d window");

        let within_30d = s.upcoming_expiries(30 * 86_400).await.expect("up");
        assert_eq!(within_30d.len(), 1);
        assert_eq!(within_30d[0].domain, "a.cz");
    }
}
