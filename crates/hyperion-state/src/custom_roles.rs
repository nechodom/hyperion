//! Custom roles: persisted granular-RBAC roles (a capability bitmask + a scope).
//!
//! A custom role is referenced by `web_users.custom_role_id`. The effective
//! capabilities of a logged-in user are resolved by
//! [`crate::web_users::effective_role`] (built-in preset or this custom set) and
//! stamped into the session. See `capabilities.rs` for the `Capability`/`CapSet`
//! model and the design spec.

use crate::capabilities::CapSet;
use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CustomRoleRow {
    pub id: i64,
    pub name: String,
    /// Capability bitmask (stored as i64; the bits never exceed 2^30).
    pub capabilities: i64,
    pub scope_all_hostings: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl CustomRoleRow {
    pub fn caps(&self) -> CapSet {
        CapSet::from_bits(self.capabilities as u64)
    }
    pub fn scope_all(&self) -> bool {
        self.scope_all_hostings != 0
    }
}

const COLS: &str = "id, name, capabilities, scope_all_hostings, created_at, updated_at";

/// Create a custom role. The `name` UNIQUE constraint surfaces a duplicate as a
/// `StateError` (the web layer turns it into a flash).
pub async fn create(
    pool: &SqlitePool,
    name: &str,
    capabilities: u64,
    scope_all: bool,
    now: i64,
) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO custom_roles (name, capabilities, scope_all_hostings, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(capabilities as i64)
    .bind(i64::from(scope_all))
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn update(
    pool: &SqlitePool,
    id: i64,
    name: &str,
    capabilities: u64,
    scope_all: bool,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE custom_roles SET name = ?, capabilities = ?, scope_all_hostings = ?, \
         updated_at = ? WHERE id = ?",
    )
    .bind(name)
    .bind(capabilities as i64)
    .bind(i64::from(scope_all))
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<CustomRoleRow>, StateError> {
    let sql = format!("SELECT {COLS} FROM custom_roles ORDER BY name");
    Ok(sqlx::query_as(&sql).fetch_all(pool).await?)
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Option<CustomRoleRow>, StateError> {
    let sql = format!("SELECT {COLS} FROM custom_roles WHERE id = ?");
    Ok(sqlx::query_as(&sql).bind(id).fetch_optional(pool).await?)
}

/// How many web users are assigned this custom role (delete guard).
pub async fn count_in_use(pool: &SqlitePool, id: i64) -> Result<i64, StateError> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM web_users WHERE custom_role_id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// Delete a custom role. Callers MUST check [`count_in_use`] first (the web
/// layer refuses to delete an in-use role).
pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM custom_roles WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capability;

    async fn mem() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn crud_and_in_use_guard() {
        let pool = mem().await;
        let caps = [Capability::HostingView, Capability::BackupRun]
            .into_iter()
            .collect::<CapSet>();
        let id = create(&pool, "Junior op", caps.bits(), false, 100)
            .await
            .unwrap();

        let got = get(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.name, "Junior op");
        assert_eq!(got.caps(), caps);
        assert!(!got.scope_all());
        assert_eq!(count_in_use(&pool, id).await.unwrap(), 0);

        update(&pool, id, "Senior op", CapSet::all().bits(), true, 200)
            .await
            .unwrap();
        let got = get(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.name, "Senior op");
        assert!(got.scope_all());
        assert_eq!(got.caps(), CapSet::all());

        assert_eq!(list(&pool).await.unwrap().len(), 1);
        delete(&pool, id).await.unwrap();
        assert!(get(&pool, id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn duplicate_name_rejected() {
        let pool = mem().await;
        create(&pool, "Dup", 0, false, 1).await.unwrap();
        assert!(create(&pool, "Dup", 0, false, 1).await.is_err());
    }
}
