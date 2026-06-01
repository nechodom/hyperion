//! `nodes` table — agent enrollment registry on the master.

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRow {
    pub id: i64,
    pub node_id: String,
    pub label: String,
    pub master_url: Option<String>,
    pub enrolled_at: i64,
    pub last_seen_at: i64,
    pub agent_version: String,
    pub public_ip: Option<String>,
    pub enrolled_via: String,
    pub secret_hash: String,
}

#[derive(Debug, Clone)]
pub struct NewNode {
    pub node_id: String,
    pub label: String,
    pub master_url: Option<String>,
    pub agent_version: String,
    pub public_ip: Option<String>,
    pub enrolled_via_hash: String,
    /// BLAKE3 hex hash of the per-node shared secret. Master stores the
    /// hash; node persists the plaintext for heartbeat auth.
    pub secret_hash: String,
}

/// Look up a node by its public id. Used by the heartbeat verifier.
pub async fn get_by_node_id(
    pool: &SqlitePool,
    node_id: &str,
) -> Result<Option<NodeRow>, StateError> {
    let row: Option<(
        i64,
        String,
        String,
        Option<String>,
        i64,
        i64,
        String,
        Option<String>,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT id, node_id, label, master_url, enrolled_at, last_seen_at,
                agent_version, public_ip, enrolled_via, secret_hash
         FROM nodes WHERE node_id = ?",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            id,
            node_id,
            label,
            master_url,
            enrolled_at,
            last_seen_at,
            agent_version,
            public_ip,
            enrolled_via,
            secret_hash,
        )| NodeRow {
            id,
            node_id,
            label,
            master_url,
            enrolled_at,
            last_seen_at,
            agent_version,
            public_ip,
            enrolled_via,
            secret_hash,
        },
    ))
}

pub async fn insert(pool: &SqlitePool, n: &NewNode, now: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO nodes
           (node_id, label, master_url, enrolled_at, last_seen_at,
            agent_version, public_ip, enrolled_via, secret_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id"#,
    )
    .bind(&n.node_id)
    .bind(&n.label)
    .bind(&n.master_url)
    .bind(now)
    .bind(now)
    .bind(&n.agent_version)
    .bind(&n.public_ip)
    .bind(&n.enrolled_via_hash)
    .bind(&n.secret_hash)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<NodeRow>, StateError> {
    let rows: Vec<(
        i64,
        String,
        String,
        Option<String>,
        i64,
        i64,
        String,
        Option<String>,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT id, node_id, label, master_url, enrolled_at, last_seen_at,
                agent_version, public_ip, enrolled_via, secret_hash
         FROM nodes ORDER BY enrolled_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                node_id,
                label,
                master_url,
                enrolled_at,
                last_seen_at,
                agent_version,
                public_ip,
                enrolled_via,
                secret_hash,
            )| NodeRow {
                id,
                node_id,
                label,
                master_url,
                enrolled_at,
                last_seen_at,
                agent_version,
                public_ip,
                enrolled_via,
                secret_hash,
            },
        )
        .collect())
}

pub async fn touch_last_seen(
    pool: &SqlitePool,
    node_id: &str,
    now: i64,
    version: Option<&str>,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE nodes SET last_seen_at = ?, agent_version = COALESCE(?, agent_version)
         WHERE node_id = ?",
    )
    .bind(now)
    .bind(version)
    .bind(node_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn insert_then_list() {
        let pool = open_memory().await.expect("open");
        let n = NewNode {
            node_id: "node-abc".into(),
            label: "node5.example.com".into(),
            master_url: Some("https://master.example.com:8443".into()),
            agent_version: "0.1.0".into(),
            public_ip: Some("1.2.3.4".into()),
            enrolled_via_hash: "deadbeef".into(),
            secret_hash: "h".into(),
        };
        insert(&pool, &n, 100).await.expect("insert");
        let l = list(&pool).await.expect("list");
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].node_id, "node-abc");
    }

    #[tokio::test]
    async fn duplicate_node_id_is_rejected() {
        let pool = open_memory().await.expect("open");
        let n = NewNode {
            node_id: "n1".into(),
            label: "n".into(),
            master_url: None,
            agent_version: "0.1.0".into(),
            public_ip: None,
            enrolled_via_hash: "x".into(),
            secret_hash: "h".into(),
        };
        insert(&pool, &n, 100).await.expect("first");
        let r = insert(&pool, &n, 200).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn touch_updates_last_seen() {
        let pool = open_memory().await.expect("open");
        let n = NewNode {
            node_id: "n1".into(),
            label: "n".into(),
            master_url: None,
            agent_version: "0.1.0".into(),
            public_ip: None,
            enrolled_via_hash: "x".into(),
            secret_hash: "h".into(),
        };
        insert(&pool, &n, 100).await.expect("insert");
        touch_last_seen(&pool, "n1", 200, Some("0.2.0"))
            .await
            .expect("touch");
        let l = list(&pool).await.expect("list");
        assert_eq!(l[0].last_seen_at, 200);
        assert_eq!(l[0].agent_version, "0.2.0");
    }
}
