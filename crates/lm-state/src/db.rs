//! Pool open + migrations.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("audit chain broken at row {row}: expected {expected}, got {got}")]
    AuditChain {
        row: i64,
        expected: String,
        got: String,
    },
    #[error("invalid state value '{0}'")]
    InvalidState(String),
}

/// Open a SQLite pool at `path`, applying migrations idempotently.
pub async fn open(path: &Path) -> Result<SqlitePool, StateError> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let url = format!("sqlite://{}", path.display());
    let opts = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// In-memory pool. Used heavily in tests.
pub async fn open_memory() -> Result<SqlitePool, StateError> {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_db_applies_migrations() {
        let pool = open_memory().await.expect("open");
        let row: (i64,) = sqlx::query_as("SELECT count(*) FROM hostings")
            .fetch_one(&pool)
            .await
            .expect("query");
        assert_eq!(row.0, 0);
    }

    #[tokio::test]
    async fn migrations_create_all_tables() {
        let pool = open_memory().await.expect("open");
        for table in [
            "system_users",
            "hostings",
            "hosting_aliases",
            "databases",
            "certificates",
            "audit_log",
        ] {
            let sql = format!("SELECT count(*) FROM {table}");
            let row: (i64,) = sqlx::query_as(&sql)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("table {table} missing: {e}"));
            assert_eq!(row.0, 0, "{table}");
        }
    }

    #[tokio::test]
    async fn on_disk_db_creates_parent_dir() {
        let d = tempfile::tempdir().expect("tempdir");
        let path = d.path().join("nested/state.db");
        let _pool = open(&path).await.expect("open");
        assert!(path.exists(), "db file created");
    }
}
