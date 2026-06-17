//! WordPress asset library — operator-uploaded plugin / theme ZIPs.
//!
//! Files live under `/var/lib/hyperion/wp-assets/<id>/<stored_filename>`.
//! The DB row holds metadata + a SHA-256 we use to detect on-disk
//! corruption before feeding the zip to wp-cli.

use crate::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WpAssetRow {
    pub id: i64,
    /// "plugin" or "theme".
    pub kind: String,
    pub original_name: String,
    pub stored_filename: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub uploaded_at: i64,
    pub uploaded_by: String,
}

/// Insert a freshly-uploaded asset row and return the auto-generated id.
/// Caller has already written the file to disk and computed the hash.
pub async fn insert(
    pool: &SqlitePool,
    kind: &str,
    original_name: &str,
    stored_filename: &str,
    size_bytes: i64,
    sha256: &str,
    uploaded_at: i64,
    uploaded_by: &str,
) -> Result<i64, StateError> {
    let r = sqlx::query(
        "INSERT INTO wp_assets \
            (kind, original_name, stored_filename, size_bytes, sha256, uploaded_at, uploaded_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(kind)
    .bind(original_name)
    .bind(stored_filename)
    .bind(size_bytes)
    .bind(sha256)
    .bind(uploaded_at)
    .bind(uploaded_by)
    .execute(pool)
    .await?;
    Ok(r.last_insert_rowid())
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<WpAssetRow>, StateError> {
    let rows: Vec<(i64, String, String, String, i64, String, i64, String)> = sqlx::query_as(
        "SELECT id, kind, original_name, stored_filename, size_bytes, sha256, uploaded_at, uploaded_by \
         FROM wp_assets ORDER BY uploaded_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                kind,
                original_name,
                stored_filename,
                size_bytes,
                sha256,
                uploaded_at,
                uploaded_by,
            )| {
                WpAssetRow {
                    id,
                    kind,
                    original_name,
                    stored_filename,
                    size_bytes,
                    sha256,
                    uploaded_at,
                    uploaded_by,
                }
            },
        )
        .collect())
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<Option<WpAssetRow>, StateError> {
    let row: Option<(i64, String, String, String, i64, String, i64, String)> = sqlx::query_as(
        "SELECT id, kind, original_name, stored_filename, size_bytes, sha256, uploaded_at, uploaded_by \
         FROM wp_assets WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            id,
            kind,
            original_name,
            stored_filename,
            size_bytes,
            sha256,
            uploaded_at,
            uploaded_by,
        )| {
            WpAssetRow {
                id,
                kind,
                original_name,
                stored_filename,
                size_bytes,
                sha256,
                uploaded_at,
                uploaded_by,
            }
        },
    ))
}

pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM wp_assets WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Replace an existing asset's on-disk file metadata. Used by
/// `WpAssetReplace` so profiles + audit references that point at
/// `@asset:<id>` survive a version bump.
#[allow(clippy::too_many_arguments)]
pub async fn replace(
    pool: &SqlitePool,
    id: i64,
    original_name: &str,
    stored_filename: &str,
    size_bytes: i64,
    sha256: &str,
    uploaded_at: i64,
    uploaded_by: &str,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE wp_assets SET \
            original_name = ?, stored_filename = ?, size_bytes = ?, \
            sha256 = ?, uploaded_at = ?, uploaded_by = ? \
         WHERE id = ?",
    )
    .bind(original_name)
    .bind(stored_filename)
    .bind(size_bytes)
    .bind(sha256)
    .bind(uploaded_at)
    .bind(uploaded_by)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Record (or update) the fact that `hosting_id` (on `node_id`)
/// got `asset_id` installed. Upsert keyed on (asset_id, hosting_id)
/// so re-install just bumps last_at. Best-effort callers can
/// ignore the error.
pub async fn record_install(
    pool: &SqlitePool,
    asset_id: i64,
    hosting_id: &str,
    node_id: &str,
    activate: bool,
    last_at: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO wp_asset_installs (asset_id, hosting_id, node_id, activate, last_at) \
         VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(asset_id, hosting_id) DO UPDATE SET \
            node_id = excluded.node_id, \
            activate = excluded.activate, \
            last_at = excluded.last_at",
    )
    .bind(asset_id)
    .bind(hosting_id)
    .bind(node_id)
    .bind(if activate { 1 } else { 0 })
    .bind(last_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Count distinct hostings tracked as having `asset_id` installed.
/// Returns 0 for unknown assets (no row constraint here).
pub async fn install_count(pool: &SqlitePool, asset_id: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM wp_asset_installs WHERE asset_id = ?")
        .bind(asset_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallTargetRow {
    pub hosting_id: String,
    pub node_id: String,
    pub activate: bool,
    pub last_at: i64,
}

/// List all (hosting_id, node_id, activate, last_at) tuples where
/// `asset_id` was previously installed. Used by `WpAssetReinstallAll`.
pub async fn list_install_targets(
    pool: &SqlitePool,
    asset_id: i64,
) -> Result<Vec<InstallTargetRow>, StateError> {
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT hosting_id, node_id, activate, last_at \
         FROM wp_asset_installs WHERE asset_id = ?",
    )
    .bind(asset_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(hosting_id, node_id, activate, last_at)| InstallTargetRow {
                hosting_id,
                node_id,
                activate: activate != 0,
                last_at,
            },
        )
        .collect())
}

/// Lookup the unique SHA — used to dedupe an upload (if the same
/// bytes are already in the library, return the existing row instead
/// of inserting a second copy).
pub async fn get_by_sha(pool: &SqlitePool, sha256: &str) -> Result<Option<WpAssetRow>, StateError> {
    let row: Option<(i64, String, String, String, i64, String, i64, String)> = sqlx::query_as(
        "SELECT id, kind, original_name, stored_filename, size_bytes, sha256, uploaded_at, uploaded_by \
         FROM wp_assets WHERE sha256 = ?",
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            id,
            kind,
            original_name,
            stored_filename,
            size_bytes,
            sha256,
            uploaded_at,
            uploaded_by,
        )| {
            WpAssetRow {
                id,
                kind,
                original_name,
                stored_filename,
                size_bytes,
                sha256,
                uploaded_at,
                uploaded_by,
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn insert_and_list() {
        let pool = open_memory().await.expect("open");
        let id = insert(
            &pool,
            "plugin",
            "akismet.zip",
            "akismet-deadbeef.zip",
            12345,
            "deadbeef",
            1_700_000_000,
            "kevin",
        )
        .await
        .expect("insert");
        assert!(id > 0);
        let all = list(&pool).await.expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].kind, "plugin");
        assert_eq!(all[0].original_name, "akismet.zip");
    }

    #[tokio::test]
    async fn get_by_sha_dedupes() {
        let pool = open_memory().await.expect("open");
        let _ = insert(
            &pool, "plugin", "x.zip", "x-1.zip", 1, "shaaaaaa", 1, "kevin",
        )
        .await
        .unwrap();
        let dup = get_by_sha(&pool, "shaaaaaa").await.unwrap();
        assert!(dup.is_some());
        let missing = get_by_sha(&pool, "nothere").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn delete_drops_row() {
        let pool = open_memory().await.expect("open");
        let id = insert(&pool, "theme", "t.zip", "t-1.zip", 1, "s", 1, "k")
            .await
            .unwrap();
        delete(&pool, id).await.unwrap();
        assert!(get_by_id(&pool, id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_bad_kind() {
        let pool = open_memory().await.expect("open");
        let r = insert(&pool, "not-a-real-kind", "x.zip", "x.zip", 1, "s", 1, "k").await;
        assert!(r.is_err(), "CHECK constraint should reject");
    }
}
