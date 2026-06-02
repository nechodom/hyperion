//! `hostings`, `hosting_aliases` tables.

use crate::db::StateError;
use hyperion_types::{HostingId, HostingState, HostingSummary, PhpVersion};
use sqlx::SqlitePool;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingRow {
    pub id: HostingId,
    pub domain: String,
    pub state: HostingState,
    pub system_user_id: i64,
    pub php_version: Option<PhpVersion>,
    pub root_dir: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// Per-hosting ACME contact email. `None` means "fall back to
    /// agent-wide [acme] contact_email from agent.toml" — the same
    /// value that issue_real_cert defaults to when this is missing.
    pub acme_contact_email: Option<String>,
}

pub async fn insert(
    pool: &SqlitePool,
    id: &HostingId,
    domain: &str,
    system_user_id: i64,
    php_version: Option<PhpVersion>,
    root_dir: &str,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hostings
           (id, domain, state, system_user_id, php_version, root_dir, created_at, updated_at)
           VALUES (?, ?, 'provisioning', ?, ?, ?, ?, ?)"#,
    )
    .bind(id.as_str())
    .bind(domain)
    .bind(system_user_id)
    .bind(php_version.map(|v| v.as_str()))
    .bind(root_dir)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_alias(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    alias: &str,
) -> Result<(), StateError> {
    sqlx::query("INSERT INTO hosting_aliases (hosting_id, alias_domain) VALUES (?, ?)")
        .bind(hosting_id.as_str())
        .bind(alias)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn aliases(pool: &SqlitePool, hosting_id: &HostingId) -> Result<Vec<String>, StateError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT alias_domain FROM hosting_aliases WHERE hosting_id = ? ORDER BY alias_domain",
    )
    .bind(hosting_id.as_str())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

pub async fn set_state(
    pool: &SqlitePool,
    id: &HostingId,
    state: HostingState,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query("UPDATE hostings SET state = ?, updated_at = ? WHERE id = ?")
        .bind(state.as_str())
        .bind(now)
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete(pool: &SqlitePool, id: &HostingId) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hostings WHERE id = ?")
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_by_id(
    pool: &SqlitePool,
    id: &HostingId,
) -> Result<Option<HostingRow>, StateError> {
    fetch_one(
        pool,
        "WHERE id = ?",
        sqlx::query_as::<_, RawHostingRow>(QUERY_BASE).bind(id.as_str()),
    )
    .await
}

pub async fn get_by_domain(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Option<HostingRow>, StateError> {
    fetch_one(
        pool,
        "WHERE domain = ?",
        sqlx::query_as::<_, RawHostingRow>(QUERY_DOMAIN).bind(domain),
    )
    .await
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<HostingSummary>, StateError> {
    let rows: Vec<(String, String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, domain, state, php_version, created_at FROM hostings ORDER BY domain",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, domain, state, php_version, created_at) in rows {
        out.push(HostingSummary {
            id: HostingId(id),
            domain,
            state: HostingState::from_str(&state).map_err(StateError::InvalidState)?,
            php_version: match php_version {
                Some(v) => Some(PhpVersion::from_str(&v).map_err(StateError::InvalidState)?),
                None => None,
            },
            created_at,
        });
    }
    Ok(out)
}

// --- internals ---

type RawHostingRow = (
    String,
    String,
    String,
    i64,
    Option<String>,
    String,
    i64,
    i64,
    Option<String>,
);

const QUERY_BASE: &str =
    "SELECT id, domain, state, system_user_id, php_version, root_dir, created_at, updated_at, acme_contact_email FROM hostings WHERE id = ?";
const QUERY_DOMAIN: &str =
    "SELECT id, domain, state, system_user_id, php_version, root_dir, created_at, updated_at, acme_contact_email FROM hostings WHERE domain = ?";

async fn fetch_one<'a>(
    pool: &'a SqlitePool,
    _why: &'static str,
    q: sqlx::query::QueryAs<'a, sqlx::Sqlite, RawHostingRow, sqlx::sqlite::SqliteArguments<'a>>,
) -> Result<Option<HostingRow>, StateError> {
    let row = q.fetch_optional(pool).await?;
    let Some((
        id,
        domain,
        state,
        system_user_id,
        php_version,
        root_dir,
        created_at,
        updated_at,
        acme_contact_email,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(HostingRow {
        id: HostingId(id),
        domain,
        state: HostingState::from_str(&state).map_err(StateError::InvalidState)?,
        system_user_id,
        php_version: match php_version {
            Some(v) => Some(PhpVersion::from_str(&v).map_err(StateError::InvalidState)?),
            None => None,
        },
        root_dir,
        created_at,
        updated_at,
        acme_contact_email,
    }))
}

/// Update (or clear) the per-hosting ACME contact email. `None` means
/// "use agent-wide default". Returns the row count touched (0 if the
/// hosting wasn't found).
pub async fn set_acme_contact_email(
    pool: &SqlitePool,
    id: &HostingId,
    email: Option<&str>,
    now: i64,
) -> Result<u64, StateError> {
    let r = sqlx::query(
        "UPDATE hostings SET acme_contact_email = ?, updated_at = ? WHERE id = ?",
    )
    .bind(email)
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;
    use crate::system_users;

    async fn fresh_user(pool: &SqlitePool, name: &str, uid: i64) -> i64 {
        system_users::insert(pool, name, uid, &format!("/home/{name}"), "/x", 1)
            .await
            .expect("insert user")
    }

    #[tokio::test]
    async fn insert_then_get_by_id() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "ex_cz", 1042).await;
        let id = HostingId::new_v7();
        insert(
            &pool,
            &id,
            "example.cz",
            suid,
            Some(PhpVersion::V8_3),
            "/home/ex_cz/example.cz/htdocs",
            42,
        )
        .await
        .expect("insert");
        let got = get_by_id(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.domain, "example.cz");
        assert_eq!(got.state, HostingState::Provisioning);
        assert_eq!(got.php_version, Some(PhpVersion::V8_3));
    }

    #[tokio::test]
    async fn domain_uniqueness() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "ex_cz", 1042).await;
        let id = HostingId::new_v7();
        insert(&pool, &id, "example.cz", suid, None, "/x", 1)
            .await
            .expect("first ok");
        let id2 = HostingId::new_v7();
        let r = insert(&pool, &id2, "example.cz", suid, None, "/y", 2).await;
        assert!(r.is_err(), "duplicate domain must fail");
    }

    #[tokio::test]
    async fn state_check_rejects_invalid() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "ex_cz", 1042).await;
        // Insert valid, then try to set an invalid state via direct SQL.
        let id = HostingId::new_v7();
        insert(&pool, &id, "example.cz", suid, None, "/x", 1)
            .await
            .expect("ok");
        let bad = sqlx::query("UPDATE hostings SET state='bogus' WHERE id = ?")
            .bind(id.as_str())
            .execute(&pool)
            .await;
        assert!(bad.is_err(), "CHECK should refuse 'bogus'");
    }

    /// Verify the new acme_contact_email column round-trips.
    /// New hostings get NULL (= fall back to agent-wide email);
    /// set_acme_contact_email writes; reading via get_by_id returns it.
    #[tokio::test]
    async fn acme_contact_email_round_trip() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "ex_cz", 1042).await;
        let id = HostingId::new_v7();
        insert(&pool, &id, "example.cz", suid, None, "/x", 1)
            .await
            .expect("insert");

        // Default: NULL — operator hasn't set anything.
        let got = get_by_id(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.acme_contact_email, None,
            "fresh hostings must have NULL acme_contact_email so they fall back to the agent default");

        // Set to a concrete value.
        let n = set_acme_contact_email(&pool, &id, Some("ops@example.cz"), 2)
            .await
            .expect("set");
        assert_eq!(n, 1, "exactly one row updated");
        let got = get_by_id(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.acme_contact_email.as_deref(), Some("ops@example.cz"));
        assert_eq!(got.updated_at, 2, "updated_at bumped on set");

        // Clear (NULL → fall back to default again).
        let n = set_acme_contact_email(&pool, &id, None, 3)
            .await
            .expect("clear");
        assert_eq!(n, 1);
        let got = get_by_id(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.acme_contact_email, None);
    }

    /// Updating a non-existent hosting must return 0 rows touched
    /// rather than raising.
    #[tokio::test]
    async fn acme_contact_email_unknown_hosting_returns_zero() {
        let pool = open_memory().await.expect("open");
        let id = HostingId::new_v7();
        let n = set_acme_contact_email(&pool, &id, Some("x@y.z"), 1)
            .await
            .expect("update");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn set_state_transitions() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "u", 1042).await;
        let id = HostingId::new_v7();
        insert(&pool, &id, "example.cz", suid, None, "/x", 1)
            .await
            .expect("ok");
        set_state(&pool, &id, HostingState::Active, 2)
            .await
            .expect("transition");
        let got = get_by_id(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.state, HostingState::Active);
        assert_eq!(got.updated_at, 2);
    }

    #[tokio::test]
    async fn cascade_deletes_aliases_and_databases() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "u", 1042).await;
        let id = HostingId::new_v7();
        insert(&pool, &id, "example.cz", suid, None, "/x", 1)
            .await
            .expect("ok");
        insert_alias(&pool, &id, "www.example.cz")
            .await
            .expect("alias");
        // Use direct INSERT for databases (cleaner than going through
        // databases::insert which needs a SecretId).
        sqlx::query(
            r#"INSERT INTO databases (hosting_id, engine, db_name, db_user, secret_id, created_at)
               VALUES (?, 'mariadb', 'd', 'u', 'sec1', 1)"#,
        )
        .bind(id.as_str())
        .execute(&pool)
        .await
        .expect("db row");
        delete(&pool, &id).await.expect("delete");
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM hosting_aliases")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(n, 0, "aliases cascade");
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM databases")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(n, 0, "databases cascade");
    }

    #[tokio::test]
    async fn list_returns_summary() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "u", 1042).await;
        let a = HostingId::new_v7();
        let b = HostingId::new_v7();
        insert(&pool, &a, "a.cz", suid, Some(PhpVersion::V8_3), "/x", 1)
            .await
            .expect("ok");
        insert(&pool, &b, "b.cz", suid, None, "/y", 2)
            .await
            .expect("ok");
        let rows = list(&pool).await.expect("list");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].domain, "a.cz");
        assert_eq!(rows[0].php_version, Some(PhpVersion::V8_3));
        assert_eq!(rows[1].domain, "b.cz");
        assert_eq!(rows[1].php_version, None);
    }

    #[tokio::test]
    async fn get_by_domain_works() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "u", 1042).await;
        let id = HostingId::new_v7();
        insert(&pool, &id, "example.cz", suid, None, "/x", 1)
            .await
            .expect("ok");
        let got = get_by_domain(&pool, "example.cz")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.id, id);
        let missing = get_by_domain(&pool, "absent.cz").await.expect("get");
        assert!(missing.is_none());
    }
}
