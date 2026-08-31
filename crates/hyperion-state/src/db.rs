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
    if path.to_string_lossy() != ":memory:" {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    // Create the file OURSELVES at 0600 before SQLite gets to it.
    //
    // SQLite creates a missing database with the process umask, which on a
    // Debian service is 0644 — and /var/lib/hyperion is 0711, so any local
    // user can walk in and read it by name. This database holds every
    // operator's argon2 hash and their TOTP secret in cleartext, so a
    // world-readable copy makes the second factor decorative. Every hosting
    // has a real local account, so "any local user" means any customer.
    //
    // Created before connecting rather than chmodded after, because a
    // chmod-after-open leaves a window in which the file is readable — and
    // the attacker choosing when to look is the whole game.
    //
    // Skipped for SQLite's special paths. `:memory:` and a `file:` URI are
    // not filenames, and pre-creating them literally drops a stray `:memory:`
    // file wherever the process happens to be — which is exactly what landed
    // in the repository the first time this shipped.
    let is_real_file = {
        let p = path.to_string_lossy();
        p != ":memory:" && !p.starts_with("file:")
    };
    if is_real_file {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path);
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
    // Heal a database created by an older build, and the WAL sidecars SQLite
    // makes itself — those carry the same rows and were equally readable.
    if is_real_file {
        use std::os::unix::fs::PermissionsExt;
        for p in [
            path.to_path_buf(),
            path.with_extension("db-wal"),
            path.with_extension("db-shm"),
        ] {
            if p.exists() {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
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

#[cfg(test)]
mod permission_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The database holds every operator's argon2 hash and their TOTP secret
    /// in CLEARTEXT, and /var/lib/hyperion is 0711 — so a world-readable file
    /// there is readable by every hosting's system user, which makes the
    /// second factor decorative. SQLite would create it with the process
    /// umask (0644 on a Debian service) if left to itself.
    #[tokio::test]
    async fn the_database_is_never_world_readable() {
        let d = tempfile::tempdir().expect("tmp");
        let p = d.path().join("state.db");
        let pool = open(&p).await.expect("open");
        drop(pool);

        for f in [
            p.clone(),
            p.with_extension("db-wal"),
            p.with_extension("db-shm"),
        ] {
            if !f.exists() {
                continue;
            }
            let mode = std::fs::metadata(&f).expect("stat").permissions().mode() & 0o777;
            assert_eq!(
                mode & 0o077,
                0,
                "{} is {mode:o} — group/other can read the TOTP secrets",
                f.display()
            );
        }
    }

    /// A database left behind by an older build must be tightened on the next
    /// start, not only on a fresh create — otherwise every existing box keeps
    /// the exposure forever.
    #[tokio::test]
    async fn an_existing_loose_database_is_tightened() {
        let d = tempfile::tempdir().expect("tmp");
        let p = d.path().join("state.db");
        // Pre-create it wide open, the way an older build left it.
        std::fs::write(&p, b"").expect("create");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let pool = open(&p).await.expect("open");
        drop(pool);

        let mode = std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "still {mode:o} — the heal did not run");
    }
}

#[cfg(test)]
mod special_path_tests {
    use super::*;

    /// `:memory:` is not a filename. Pre-creating the database file to fix
    /// its permissions must not take that literally — the first version did,
    /// and a stray `:memory:` file was committed to the repository by a test
    /// that opens one.
    #[tokio::test]
    async fn the_memory_path_creates_no_file() {
        let d = tempfile::tempdir().expect("tmp");
        let cwd = std::env::current_dir().expect("cwd");
        // Run from a scratch directory so a stray file is visible and cannot
        // land in the source tree.
        std::env::set_current_dir(d.path()).expect("cd");
        let pool = open(Path::new(":memory:")).await;
        std::env::set_current_dir(cwd).expect("cd back");
        assert!(pool.is_ok(), "an in-memory database must still open");
        assert!(
            !d.path().join(":memory:").exists(),
            "a literal ':memory:' file was created"
        );
    }
}
