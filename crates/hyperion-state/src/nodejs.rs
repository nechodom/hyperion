//! `node_apps` + `port_pool` tables.

use crate::db::StateError;
use hyperion_types::{HostingId, SecretId};
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAppRow {
    pub hosting_id: HostingId,
    pub node_version: String,
    pub app_entry: String,
    pub listen_port: i64,
    pub env_vars_secret_id: SecretId,
    pub memory_mb: i64,
    pub cpu_quota_pct: i64,
    pub tasks_max: i64,
    pub install_state: String,
    pub last_deploy_at: Option<i64>,
    pub last_deploy_log: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NodeAppNew<'a> {
    pub hosting_id: &'a HostingId,
    pub node_version: &'a str,
    pub app_entry: &'a str,
    pub listen_port: i64,
    pub env_vars_secret_id: &'a SecretId,
    pub memory_mb: i64,
    pub cpu_quota_pct: i64,
    pub tasks_max: i64,
    pub now: i64,
}

pub async fn insert(pool: &SqlitePool, n: &NodeAppNew<'_>) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO node_apps
           (hosting_id, node_version, app_entry, listen_port, env_vars_secret_id,
            memory_mb, cpu_quota_pct, tasks_max, install_state, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)"#,
    )
    .bind(n.hosting_id.as_str())
    .bind(n.node_version)
    .bind(n.app_entry)
    .bind(n.listen_port)
    .bind(n.env_vars_secret_id.as_str())
    .bind(n.memory_mb)
    .bind(n.cpu_quota_pct)
    .bind(n.tasks_max)
    .bind(n.now)
    .bind(n.now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get(pool: &SqlitePool, id: &HostingId) -> Result<Option<NodeAppRow>, StateError> {
    type Tup = (
        String,
        String,
        String,
        i64,
        String,
        i64,
        i64,
        i64,
        String,
        Option<i64>,
        Option<String>,
        i64,
        i64,
    );
    let row: Option<Tup> = sqlx::query_as(
        "SELECT hosting_id, node_version, app_entry, listen_port, env_vars_secret_id,
                memory_mb, cpu_quota_pct, tasks_max, install_state, last_deploy_at,
                last_deploy_log, created_at, updated_at
         FROM node_apps WHERE hosting_id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            hosting_id,
            node_version,
            app_entry,
            listen_port,
            env_vars_secret_id,
            memory_mb,
            cpu_quota_pct,
            tasks_max,
            install_state,
            last_deploy_at,
            last_deploy_log,
            created_at,
            updated_at,
        )| NodeAppRow {
            hosting_id: HostingId(hosting_id),
            node_version,
            app_entry,
            listen_port,
            env_vars_secret_id: SecretId(env_vars_secret_id),
            memory_mb,
            cpu_quota_pct,
            tasks_max,
            install_state,
            last_deploy_at,
            last_deploy_log,
            created_at,
            updated_at,
        },
    ))
}

pub async fn set_install_state(
    pool: &SqlitePool,
    id: &HostingId,
    state: &str,
    log_tail: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE node_apps SET install_state = ?, last_deploy_log = ?,
            last_deploy_at = ?, updated_at = ?
         WHERE hosting_id = ?",
    )
    .bind(state)
    .bind(log_tail)
    .bind(now)
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

// ---------- Port pool ----------

#[derive(Debug, thiserror::Error)]
pub enum PortPoolError {
    #[error("no free port in pool")]
    Exhausted,
    #[error("state: {0}")]
    State(#[from] StateError),
}

/// Pop the lowest free port and mark it used. Atomic via `UPDATE ... WHERE`.
pub async fn allocate_port(pool: &SqlitePool) -> Result<u16, PortPoolError> {
    let mut tx = pool.begin().await.map_err(StateError::from)?;
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT port FROM port_pool WHERE used = 0 ORDER BY port LIMIT 1")
            .fetch_optional(&mut *tx)
            .await
            .map_err(StateError::from)?;
    let port = match row {
        Some((p,)) => p,
        None => return Err(PortPoolError::Exhausted),
    };
    sqlx::query("UPDATE port_pool SET used = 1 WHERE port = ?")
        .bind(port)
        .execute(&mut *tx)
        .await
        .map_err(StateError::from)?;
    tx.commit().await.map_err(StateError::from)?;
    Ok(port as u16)
}

pub async fn release_port(pool: &SqlitePool, port: u16) -> Result<(), StateError> {
    sqlx::query("UPDATE port_pool SET used = 0 WHERE port = ?")
        .bind(port as i64)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;
    use crate::{hostings, system_users};

    async fn fixture(pool: &SqlitePool) -> HostingId {
        let suid = system_users::insert(pool, "u", 1042, "/home/u", "/x", 1)
            .await
            .expect("user");
        let id = HostingId::new_v7();
        hostings::insert(pool, &id, "example.cz", suid, None, "/r", 1)
            .await
            .expect("hosting");
        id
    }

    #[tokio::test]
    async fn insert_and_get_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let sec = SecretId::new();
        insert(
            &pool,
            &NodeAppNew {
                hosting_id: &id,
                node_version: "20",
                app_entry: "server.js",
                listen_port: 30000,
                env_vars_secret_id: &sec,
                memory_mb: 512,
                cpu_quota_pct: 200,
                tasks_max: 500,
                now: 100,
            },
        )
        .await
        .expect("insert");
        let got = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.node_version, "20");
        assert_eq!(got.listen_port, 30000);
        assert_eq!(got.install_state, "pending");
    }

    #[tokio::test]
    async fn node_version_check_constraint() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let r = sqlx::query(
            "INSERT INTO node_apps
             (hosting_id, node_version, app_entry, listen_port, env_vars_secret_id,
              memory_mb, cpu_quota_pct, tasks_max, install_state, created_at, updated_at)
             VALUES (?, '14', 'a.js', 30001, 'sec', 256, 100, 200, 'pending', 1, 1)",
        )
        .bind(id.as_str())
        .execute(&pool)
        .await;
        assert!(r.is_err(), "node 14 should be rejected by CHECK");
    }

    #[tokio::test]
    async fn allocate_port_returns_distinct_ports() {
        let pool = open_memory().await.expect("open");
        let a = allocate_port(&pool).await.expect("a");
        let b = allocate_port(&pool).await.expect("b");
        let c = allocate_port(&pool).await.expect("c");
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert!(a >= 30000 && a < 40000);
    }

    #[tokio::test]
    async fn release_port_makes_it_available() {
        let pool = open_memory().await.expect("open");
        let a = allocate_port(&pool).await.expect("a");
        release_port(&pool, a).await.expect("release");
        let again = allocate_port(&pool).await.expect("again");
        assert_eq!(again, a, "lowest free port reused");
    }

    #[tokio::test]
    async fn set_install_state_persists() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let sec = SecretId::new();
        insert(
            &pool,
            &NodeAppNew {
                hosting_id: &id,
                node_version: "20",
                app_entry: "server.js",
                listen_port: 30000,
                env_vars_secret_id: &sec,
                memory_mb: 256,
                cpu_quota_pct: 100,
                tasks_max: 200,
                now: 100,
            },
        )
        .await
        .expect("insert");
        set_install_state(&pool, &id, "ready", Some("ok"), 200)
            .await
            .expect("set");
        let got = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.install_state, "ready");
        assert_eq!(got.last_deploy_log.as_deref(), Some("ok"));
    }
}
