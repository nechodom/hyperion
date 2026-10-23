//! Rollback steps pushed while provisioning, undone in LIFO order on failure.

use super::*;

// ===== Rollback impls =====

pub(super) struct DeleteUser<A: AdapterPort> {
    pub(super) adapters: Arc<A>,
    pub(super) name: String,
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

/// Drop the `system_users` row by id during create-failure rollback.
///
/// Pushed onto the rollback stack AFTER a successful
/// `system_users::insert`. Without this, a later step's failure
/// (FPM, DB, ACME, nginx, …) rolls back the Linux-side user via
/// `userdel` but leaves the DB row, claiming the UID forever. The
/// next create attempt's `useradd` reuses that UID (Linux freed it
/// at userdel time) and trips `UNIQUE(system_users.uid)`:
///
///   useradd → UID 1000  (Linux says ok)
///   system_users::insert(uid=1000) → UNIQUE constraint failed
///
/// LIFO order in the rollback stack: DeleteSystemUsersRow runs
/// BEFORE DeleteUser, so the DB row goes away first, then the
/// Linux user — matches the order the normal delete() path uses.
pub(super) struct DeleteSystemUsersRow {
    pub(super) pool: SqlitePool,
    pub(super) row_id: i64,
}
#[async_trait]
impl Rollback for DeleteSystemUsersRow {
    async fn run(&self) -> Result<(), String> {
        system_users::delete(&self.pool, self.row_id)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "delete_system_users_row"
    }
}

pub(super) struct RemoveTree<A: AdapterPort> {
    pub(super) adapters: Arc<A>,
    pub(super) root: String,
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

pub(super) struct MarkFailedOrDeleteRow {
    pub(super) pool: SqlitePool,
    pub(super) id: HostingId,
}
#[async_trait]
impl Rollback for MarkFailedOrDeleteRow {
    /// On create-failure rollback we DELETE the half-created
    /// hostings row instead of just marking it `failed`. Previously
    /// the row stayed forever, and the UNIQUE constraint on
    /// `hostings.domain` then blocked every subsequent attempt to
    /// re-create the same domain — even after the operator "deleted"
    /// it via the UI (the UI didn't see the failed row because the
    /// listing is hosting-state-aware on the master side, and
    /// HostingDelete refused to act on a state=failed row through
    /// the normal happy-path delete).
    ///
    /// `hostings::delete_id` cascades into aliases / system_user
    /// references so the row goes away cleanly.
    async fn run(&self) -> Result<(), String> {
        hostings::delete(&self.pool, &self.id)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "delete_hosting_row"
    }
}

pub(super) struct FpmDelete<A: AdapterPort> {
    pub(super) adapters: Arc<A>,
    pub(super) system_user: String,
    pub(super) version: PhpVersion,
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

pub(super) struct DbDrop<A: AdapterPort> {
    pub(super) adapters: Arc<A>,
    pub(super) engine: DbProvision,
    pub(super) db_name: String,
    pub(super) db_user: String,
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

pub(super) struct AcmeDelete<A: AdapterPort> {
    pub(super) adapters: Arc<A>,
    pub(super) domain: String,
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

/// Rollback for a hosting that REFERENCES a shared wildcard cert: drop
/// only its `certificates` row (the cert FILES belong to the wildcard and
/// must be left untouched). Used when create() reuses a node wildcard and
/// a later step fails — without this the reference row would orphan once
/// the half-created hosting row is rolled back.
pub(super) struct CertRowDelete {
    pub(super) pool: SqlitePool,
    pub(super) domain: String,
}
#[async_trait]
impl Rollback for CertRowDelete {
    async fn run(&self) -> Result<(), String> {
        certificates::delete(&self.pool, &self.domain)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "delete_cert_reference_row"
    }
}
