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

/// Master: turn the cluster flag off and forget every node. The URL checks
/// are part of the module, so they and their history go with it.
pub async fn clear_cluster(pool: &SqlitePool) -> Result<(), StateError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM url_monitor_samples")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM url_monitors")
        .execute(&mut *tx)
        .await?;
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

/// Master: record that `node_id` went silent (or answers again). Returns
/// whether the stored state CHANGED, which is the only moment worth an alert:
/// the update is one statement, so two callers cannot both see a transition.
/// A node that is not registered is not changed.
pub async fn set_node_silent(
    pool: &SqlitePool,
    node_id: &str,
    silent: bool,
    now: i64,
) -> Result<bool, StateError> {
    let (state, since, other) = if silent {
        ("silent", now, "silent")
    } else {
        ("ok", 0, "ok")
    };
    let r = sqlx::query(
        "UPDATE docker_nodes SET alert_state = ?, silent_since = ? \
         WHERE node_id = ? AND alert_state <> ?",
    )
    .bind(state)
    .bind(since)
    .bind(node_id)
    .bind(other)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
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

/// Reserved `docker_projects` row that holds the daemon's own alert state.
/// The parentheses cannot appear in a compose project name, so it never
/// collides with a project, and [`list_projects`] leaves it out.
pub const DAEMON_ROW: &str = "(daemon)";

/// One row of `docker_projects`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectRow {
    pub project: String,
    pub last_seen_at: i64,
    pub gone_since: i64,
    pub problem_since: i64,
    /// `ok`, `problem` or `gone`.
    pub alert_state: String,
    pub last_summary: String,
}

type ProjectTuple = (String, i64, i64, i64, String, String);

fn project_of(r: ProjectTuple) -> ProjectRow {
    ProjectRow {
        project: r.0,
        last_seen_at: r.1,
        gone_since: r.2,
        problem_since: r.3,
        alert_state: r.4,
        last_summary: r.5,
    }
}

const PROJECT_COLS: &str =
    "project, last_seen_at, gone_since, problem_since, alert_state, last_summary";

/// Every project this node has seen, by name. Not the daemon's row.
pub async fn list_projects(pool: &SqlitePool) -> Result<Vec<ProjectRow>, StateError> {
    let rows: Vec<ProjectTuple> = sqlx::query_as(&format!(
        "SELECT {PROJECT_COLS} FROM docker_projects WHERE project != ? ORDER BY project"
    ))
    .bind(DAEMON_ROW)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(project_of).collect())
}

/// One row, including the daemon's.
pub async fn get_project(
    pool: &SqlitePool,
    project: &str,
) -> Result<Option<ProjectRow>, StateError> {
    let row: Option<ProjectTuple> = sqlx::query_as(&format!(
        "SELECT {PROJECT_COLS} FROM docker_projects WHERE project = ?"
    ))
    .bind(project)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(project_of))
}

pub async fn put_project(pool: &SqlitePool, r: &ProjectRow) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO docker_projects \
           (project, last_seen_at, gone_since, problem_since, alert_state, last_summary) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(project) DO UPDATE SET \
           last_seen_at = excluded.last_seen_at, gone_since = excluded.gone_since, \
           problem_since = excluded.problem_since, alert_state = excluded.alert_state, \
           last_summary = excluded.last_summary",
    )
    .bind(&r.project)
    .bind(r.last_seen_at)
    .bind(r.gone_since)
    .bind(r.problem_since)
    .bind(&r.alert_state)
    .bind(&r.last_summary)
    .execute(pool)
    .await?;
    Ok(())
}

/// Forget a project: its row and its restart history, nothing else. Whether
/// anything was there is the return value; the daemon's row is not a project
/// and is never touched.
pub async fn forget_project(pool: &SqlitePool, project: &str) -> Result<bool, StateError> {
    if project == DAEMON_ROW {
        return Ok(false);
    }
    let mut tx = pool.begin().await?;
    let gone = sqlx::query("DELETE FROM docker_projects WHERE project = ?")
        .bind(project)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM docker_container_watch WHERE project = ?")
        .bind(project)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(gone > 0)
}

/// Restart history of one compose service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchRow {
    pub project: String,
    pub service: String,
    /// Sum of the service's containers' restart counts at the last look.
    pub restart_count: i64,
    /// Unix seconds at which that count was seen to rise.
    pub rises: Vec<i64>,
}

pub async fn load_watch(pool: &SqlitePool) -> Result<Vec<WatchRow>, StateError> {
    let rows: Vec<(String, String, i64, String)> = sqlx::query_as(
        "SELECT project, service, restart_count, restart_window_json FROM docker_container_watch",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| WatchRow {
            project: r.0,
            service: r.1,
            restart_count: r.2,
            // A damaged window reads as no history rather than failing the tick.
            rises: serde_json::from_str(&r.3).unwrap_or_default(),
        })
        .collect())
}

pub async fn put_watch(pool: &SqlitePool, r: &WatchRow) -> Result<(), StateError> {
    let json = serde_json::to_string(&r.rises).unwrap_or_else(|_| "[]".into());
    sqlx::query(
        "INSERT INTO docker_container_watch (project, service, restart_count, restart_window_json) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(project, service) DO UPDATE SET \
           restart_count = excluded.restart_count, \
           restart_window_json = excluded.restart_window_json",
    )
    .bind(&r.project)
    .bind(&r.service)
    .bind(r.restart_count)
    .bind(json)
    .execute(pool)
    .await?;
    Ok(())
}

/// One row of `docker_image_checks`: what the daily check last learnt about
/// one image reference (`nginx:alpine`, as a container names it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageCheckRow {
    pub image_ref: String,
    /// The `Id` of the image the tag pointed at on this node when it was read.
    pub local_digest: String,
    /// The digest the registry answered with. Kept across failed checks, so
    /// the last answer can still be told.
    pub remote_digest: String,
    /// `current`, `update`, `cannot:<reason>` or `unknown`.
    pub state: String,
    /// Unix seconds of the last answer, or of the last try when there never
    /// was one.
    pub checked_at: i64,
    /// The remote digest the operator was already told about.
    pub notified_digest: String,
    /// Unix seconds; the registry is not asked again before this.
    pub retry_after: i64,
}

type ImageCheckTuple = (String, String, String, String, i64, String, i64);

fn image_check_of(r: ImageCheckTuple) -> ImageCheckRow {
    ImageCheckRow {
        image_ref: r.0,
        local_digest: r.1,
        remote_digest: r.2,
        state: r.3,
        checked_at: r.4,
        notified_digest: r.5,
        retry_after: r.6,
    }
}

const IMAGE_CHECK_COLS: &str =
    "image_ref, local_digest, remote_digest, state, checked_at, notified_digest, retry_after";

pub async fn get_image_check(
    pool: &SqlitePool,
    image_ref: &str,
) -> Result<Option<ImageCheckRow>, StateError> {
    let row: Option<ImageCheckTuple> = sqlx::query_as(&format!(
        "SELECT {IMAGE_CHECK_COLS} FROM docker_image_checks WHERE image_ref = ?"
    ))
    .bind(image_ref)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(image_check_of))
}

pub async fn list_image_checks(pool: &SqlitePool) -> Result<Vec<ImageCheckRow>, StateError> {
    let rows: Vec<ImageCheckTuple> = sqlx::query_as(&format!(
        "SELECT {IMAGE_CHECK_COLS} FROM docker_image_checks ORDER BY image_ref"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(image_check_of).collect())
}

pub async fn put_image_check(pool: &SqlitePool, r: &ImageCheckRow) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO docker_image_checks \
           (image_ref, local_digest, remote_digest, state, checked_at, notified_digest, retry_after) \
         VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(image_ref) DO UPDATE SET \
           local_digest = excluded.local_digest, remote_digest = excluded.remote_digest, \
           state = excluded.state, checked_at = excluded.checked_at, \
           notified_digest = excluded.notified_digest, retry_after = excluded.retry_after",
    )
    .bind(&r.image_ref)
    .bind(&r.local_digest)
    .bind(&r.remote_digest)
    .bind(&r.state)
    .bind(r.checked_at)
    .bind(&r.notified_digest)
    .bind(r.retry_after)
    .execute(pool)
    .await?;
    Ok(())
}

/// Forget references no container uses any more. A row is kept for as long
/// as `keep` names it, and for a while after, because a stack that is taken
/// down and brought back must not be told about the same digest twice.
/// Returns how many rows went.
pub async fn prune_image_checks(
    pool: &SqlitePool,
    keep: &[String],
    older_than: i64,
) -> Result<u64, StateError> {
    let mut gone = 0;
    for r in list_image_checks(pool).await? {
        if r.checked_at < older_than && !keep.contains(&r.image_ref) {
            gone += sqlx::query("DELETE FROM docker_image_checks WHERE image_ref = ?")
                .bind(&r.image_ref)
                .execute(pool)
                .await?
                .rows_affected();
        }
    }
    Ok(gone)
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

    #[tokio::test]
    async fn forgetting_a_project_clears_its_row_and_history_only() {
        let pool = crate::db::open_memory().await.expect("open");
        for p in ["shop", "blog", DAEMON_ROW] {
            put_project(
                &pool,
                &ProjectRow {
                    project: p.into(),
                    alert_state: "problem".into(),
                    ..Default::default()
                },
            )
            .await
            .expect("put");
        }
        put_watch(
            &pool,
            &WatchRow {
                project: "shop".into(),
                service: "web".into(),
                restart_count: 4,
                rises: vec![10, 20],
            },
        )
        .await
        .expect("watch");

        assert_eq!(
            list_projects(&pool).await.expect("list").len(),
            2,
            "the daemon row is not a project"
        );
        assert!(forget_project(&pool, "shop").await.expect("forget"));
        assert!(!forget_project(&pool, "shop").await.expect("again"));
        assert!(!forget_project(&pool, DAEMON_ROW).await.expect("daemon"));
        assert!(get_project(&pool, DAEMON_ROW).await.expect("get").is_some());
        assert!(load_watch(&pool).await.expect("watch").is_empty());
        let names: Vec<_> = list_projects(&pool)
            .await
            .expect("list")
            .into_iter()
            .map(|r| r.project)
            .collect();
        assert_eq!(names, ["blog"]);
    }

    #[tokio::test]
    async fn watch_rows_round_trip_and_a_damaged_window_reads_empty() {
        let pool = crate::db::open_memory().await.expect("open");
        let w = WatchRow {
            project: "p".into(),
            service: "s".into(),
            restart_count: 7,
            rises: vec![1, 2, 3],
        };
        put_watch(&pool, &w).await.expect("put");
        assert_eq!(
            load_watch(&pool).await.expect("load"),
            std::slice::from_ref(&w)
        );
        sqlx::query("UPDATE docker_container_watch SET restart_window_json = 'nope'")
            .execute(&pool)
            .await
            .expect("damage");
        let got = load_watch(&pool).await.expect("load");
        assert_eq!((got[0].restart_count, got[0].rises.is_empty()), (7, true));
    }

    #[tokio::test]
    async fn image_checks_round_trip_and_old_unused_rows_are_pruned() {
        let pool = crate::db::open_memory().await.expect("open");
        assert!(get_image_check(&pool, "a:1").await.expect("get").is_none());
        for (r, at) in [("a:1", 10), ("b:1", 10), ("c:1", 500)] {
            put_image_check(
                &pool,
                &ImageCheckRow {
                    image_ref: r.into(),
                    state: "current".into(),
                    checked_at: at,
                    remote_digest: "sha256:x".into(),
                    ..Default::default()
                },
            )
            .await
            .expect("put");
        }
        let mut a = get_image_check(&pool, "a:1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!((a.state.as_str(), a.checked_at), ("current", 10));
        a.notified_digest = "sha256:x".into();
        a.retry_after = 99;
        put_image_check(&pool, &a).await.expect("again");
        assert_eq!(list_image_checks(&pool).await.expect("list").len(), 3);

        let gone = prune_image_checks(&pool, &["a:1".to_string()], 100)
            .await
            .expect("prune");
        assert_eq!(gone, 1, "b:1 is old and unused; a:1 is used; c:1 is recent");
        let left: Vec<_> = list_image_checks(&pool)
            .await
            .expect("list")
            .into_iter()
            .map(|r| r.image_ref)
            .collect();
        assert_eq!(left, ["a:1", "c:1"]);
        let a = get_image_check(&pool, "a:1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(
            (a.notified_digest.as_str(), a.retry_after),
            ("sha256:x", 99)
        );
    }
}
