//! Docker module install state (`docker_module`, `docker_nodes`) and the
//! per-node tables its ticks keep (`docker_projects`,
//! `docker_container_watch`, `docker_image_checks`).
//!
//! Nothing here runs docker; it only remembers what the module decided.

use crate::db::StateError;
use sqlx::SqlitePool;

/// The single `docker_module` row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleRow {
    pub cluster_installed: bool,
    pub node_installed: bool,
    pub buildx: bool,
    pub installed_at: i64,
    pub disk_json: String,
    pub disk_at: i64,
}

/// A node the master knows runs the module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerNodeRow {
    pub node_id: String,
    pub installed_at: i64,
    pub silent_since: i64,
    pub alert_state: String,
}

type ModuleTuple = (i64, i64, i64, i64, String, i64);

pub async fn get_module(pool: &SqlitePool) -> Result<ModuleRow, StateError> {
    // The migration inserts the row; a missing one reads as "off".
    let row: Option<ModuleTuple> = sqlx::query_as(
        "SELECT cluster_installed, node_installed, buildx, installed_at, disk_json, disk_at \
         FROM docker_module WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map_or_else(ModuleRow::default, |r| ModuleRow {
        cluster_installed: r.0 != 0,
        node_installed: r.1 != 0,
        buildx: r.2 != 0,
        installed_at: r.3,
        disk_json: r.4,
        disk_at: r.5,
    }))
}

/// Is the module on for this node? This is the gate every tick checks.
pub async fn node_installed(pool: &SqlitePool) -> Result<bool, StateError> {
    Ok(get_module(pool).await?.node_installed)
}

/// Turn the module on for this node. `installed_at` keeps its first value
/// when the module was already on.
pub async fn set_node_installed(
    pool: &SqlitePool,
    buildx: bool,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO docker_module (id, node_installed, buildx, installed_at) \
         VALUES (1, 1, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET \
           installed_at = CASE WHEN node_installed = 1 AND installed_at > 0 \
                               THEN installed_at ELSE excluded.installed_at END, \
           node_installed = 1, buildx = excluded.buildx",
    )
    .bind(buildx)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Cache the last `docker system df` result.
pub async fn set_disk(pool: &SqlitePool, json: &str, now: i64) -> Result<(), StateError> {
    sqlx::query("UPDATE docker_module SET disk_json = ?, disk_at = ? WHERE id = 1")
        .bind(json)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

/// Turn the module off for this node and forget everything it kept. One
/// transaction, so a half-removed module cannot be observed.
pub async fn clear_node(pool: &SqlitePool) -> Result<(), StateError> {
    let mut tx = pool.begin().await?;
    for table in [
        "docker_projects",
        "docker_container_watch",
        "docker_image_checks",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "UPDATE docker_module SET node_installed = 0, buildx = 0, installed_at = 0, \
         disk_json = '', disk_at = 0 WHERE id = 1",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Master: the operator turned the module on for the cluster.
pub async fn set_cluster_installed(pool: &SqlitePool) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO docker_module (id, cluster_installed) VALUES (1, 1) \
         ON CONFLICT(id) DO UPDATE SET cluster_installed = 1",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Master: turn the cluster flag off and forget every node.
pub async fn clear_cluster(pool: &SqlitePool) -> Result<(), StateError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM docker_nodes")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE docker_module SET cluster_installed = 0 WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Master: note that `node_id` runs the module. Registering a node again
/// keeps its first `installed_at` and its alert bookkeeping.
pub async fn register_node(pool: &SqlitePool, node_id: &str, now: i64) -> Result<(), StateError> {
    sqlx::query("INSERT INTO docker_nodes (node_id, installed_at) VALUES (?, ?) ON CONFLICT(node_id) DO NOTHING")
        .bind(node_id)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

/// Master: `node_id` no longer runs the module. An unknown node is not an error.
pub async fn unregister_node(pool: &SqlitePool, node_id: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM docker_nodes WHERE node_id = ?")
        .bind(node_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_nodes(pool: &SqlitePool) -> Result<Vec<DockerNodeRow>, StateError> {
    let rows: Vec<(String, i64, i64, String)> = sqlx::query_as(
        "SELECT node_id, installed_at, silent_since, alert_state FROM docker_nodes ORDER BY node_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DockerNodeRow {
            node_id: r.0,
            installed_at: r.1,
            silent_since: r.2,
            alert_state: r.3,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_fresh_database_has_the_module_off() {
        let pool = crate::db::open_memory().await.expect("open");
        assert_eq!(get_module(&pool).await.expect("read"), ModuleRow::default());
        assert!(!node_installed(&pool).await.expect("read"));
    }

    #[tokio::test]
    async fn reinstalling_keeps_the_first_install_time_but_refreshes_buildx() {
        let pool = crate::db::open_memory().await.expect("open");
        set_node_installed(&pool, false, 100).await.expect("on");
        set_node_installed(&pool, true, 900).await.expect("again");
        let m = get_module(&pool).await.expect("read");
        assert!(m.node_installed && m.buildx);
        assert_eq!(m.installed_at, 100);

        clear_node(&pool).await.expect("off");
        set_node_installed(&pool, false, 2000).await.expect("on");
        assert_eq!(get_module(&pool).await.expect("read").installed_at, 2000);
    }

    #[tokio::test]
    async fn registering_a_node_twice_keeps_its_alert_state() {
        let pool = crate::db::open_memory().await.expect("open");
        register_node(&pool, "w1", 10).await.expect("register");
        sqlx::query("UPDATE docker_nodes SET alert_state = 'silent', silent_since = 50")
            .execute(&pool)
            .await
            .expect("alert");
        register_node(&pool, "w1", 99).await.expect("again");
        let nodes = list_nodes(&pool).await.expect("list");
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            (nodes[0].installed_at, nodes[0].alert_state.as_str()),
            (10, "silent")
        );
        unregister_node(&pool, "w1").await.expect("remove");
        unregister_node(&pool, "w1").await.expect("again is fine");
        assert!(list_nodes(&pool).await.expect("list").is_empty());
    }
}
