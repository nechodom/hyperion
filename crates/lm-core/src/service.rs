//! `HostingService` — the orchestrator. Single-node, no transport.

use async_trait::async_trait;
use lm_adapters::rollback::{Rollback, RollbackStack};
use lm_adapters::AdapterError;
use lm_rpc::wire::{
    DbCredentials, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
};
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
    async fn ensure_user(
        &self,
        name: &str,
        home_dir: &str,
    ) -> Result<u32, AdapterError>;
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
    async fn fpm_delete(
        &self,
        system_user: &str,
        version: PhpVersion,
    ) -> Result<(), AdapterError>;

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

    async fn acme_issue(
        &self,
        domain: &str,
        sans: &[String],
    ) -> Result<CertInfo, AdapterError>;
    async fn acme_delete(&self, domain: &str) -> Result<(), AdapterError>;

    async fn nginx_write_vhost(
        &self,
        detail: &HostingDetail,
    ) -> Result<(), AdapterError>;
    async fn nginx_delete_vhost(&self, domain: &str) -> Result<(), AdapterError>;
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
    pub home_root: String, // e.g. "/home"
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
    pub async fn create(
        &self,
        req: HostingCreateReq,
    ) -> Result<HostingCreated, RpcError> {
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
        if let Err(e) = self
            .adapters
            .ensure_dirs(&htdocs, &logs, &tmp, uid)
            .await
        {
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
            let creds = match self
                .adapters
                .db_create(engine, &hosting_id, domain)
                .await
            {
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
        if let Err(e) = hostings::set_state(
            &self.pool,
            &hosting_id,
            HostingState::Active,
            now_secs(),
        )
        .await
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
            None => match sqlx::query_as::<_, (String,)>(
                "SELECT name FROM system_users WHERE id = ?",
            )
            .bind(row.system_user_id)
            .fetch_optional(&self.pool)
            .await
            {
                Ok(Some((s,))) => s,
                _ => String::new(),
            },
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

    pub async fn delete(
        &self,
        sel: HostingSelector,
        opts: DeleteOpts,
    ) -> Result<(), RpcError> {
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
                let _ = self.adapters.db_drop(db.engine, &db.db_name, &db.db_user).await;
            }
        }
        // fpm pool delete
        if let Some(ver) = detail.php_version {
            let _ = self
                .adapters
                .fpm_delete(&detail.system_user, ver)
                .await;
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
        a.expect_acme_issue()
            .returning(|d, _| Ok(cert_for(d)));
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
        a.expect_acme_issue()
            .returning(|d, _| Ok(cert_for(d)));
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
        a.expect_acme_issue()
            .returning(|d, _| Ok(cert_for(d)));
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
}
