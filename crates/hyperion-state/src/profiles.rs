//! `hosting_profiles` + `hosting_profile_apply` — templates of
//! limits/expiry/pricing the operator can apply to hostings in bulk.

use crate::db::StateError;
use hyperion_types::HostingId;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq, Default, sqlx::FromRow)]
pub struct ProfileRow {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub disk_hard_mb: Option<i64>,
    pub bw_monthly_mb: Option<i64>,
    pub expiry_grace_days: i64,
    pub expiry_warning_offsets: String,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub slack_webhook: Option<String>,
    /// Newline-separated WordPress plugin list. See profile.rs for
    /// the syntax (slug, @asset:<id>, trailing ! for activate).
    #[sqlx(default)]
    pub wp_plugins: String,
    #[sqlx(default)]
    pub wp_themes: String,
    /// Migration 027 — optional wizard pre-fill for PHP version
    /// ("8.1".."8.4"). `#[sqlx(default)]` so older agents
    /// pre-migration-027 still deserialise the row when read.
    #[sqlx(default)]
    pub default_php_version: Option<String>,
    /// Migration 027 — optional wizard pre-fill for DB engine
    /// ("mariadb" | "postgres" | "none").
    #[sqlx(default)]
    pub default_db_engine: Option<String>,
    /// Migration 045 — default action when a hosting created from this profile
    /// exceeds its disk hard cap: "notify" (default) or "suspend". Copied into
    /// the hosting's `hosting_kv` at create time.
    #[sqlx(default)]
    pub quota_exceed_action: String,
    /// Migration 046 — soft (warning) disk cap + memory cap, seeded into the
    /// enforced `hosting_quotas` row at apply (alongside `disk_hard_mb`).
    #[sqlx(default)]
    pub disk_soft_mb: Option<i64>,
    #[sqlx(default)]
    pub mem_limit_mib: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct NewProfile {
    pub name: String,
    pub description: String,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub disk_hard_mb: Option<i64>,
    pub bw_monthly_mb: Option<i64>,
    pub expiry_grace_days: i64,
    pub expiry_warning_offsets: String,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub slack_webhook: Option<String>,
    /// See ProfileRow::wp_plugins / wp_themes for the syntax.
    pub wp_plugins: String,
    pub wp_themes: String,
    /// See ProfileRow::default_php_version.
    pub default_php_version: Option<String>,
    /// See ProfileRow::default_db_engine.
    pub default_db_engine: Option<String>,
    /// See ProfileRow::quota_exceed_action ("notify" | "suspend").
    pub quota_exceed_action: String,
    /// See ProfileRow::disk_soft_mb / mem_limit_mib.
    pub disk_soft_mb: Option<i64>,
    pub mem_limit_mib: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileApplyRow {
    pub hosting_id: HostingId,
    pub profile_id: Option<i64>,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub next_billing_at: Option<i64>,
    pub applied_at: i64,
}

pub async fn insert(pool: &SqlitePool, p: &NewProfile, now: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO hosting_profiles
           (name, description, php_memory_mb, php_max_exec_secs, php_max_children,
            php_max_requests, db_max_connections, disk_hard_mb, bw_monthly_mb,
            expiry_grace_days, expiry_warning_offsets, price_minor, price_currency,
            price_interval, slack_webhook, wp_plugins, wp_themes,
            default_php_version, default_db_engine, quota_exceed_action,
            disk_soft_mb, mem_limit_mib,
            created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING id"#,
    )
    .bind(&p.name)
    .bind(&p.description)
    .bind(p.php_memory_mb)
    .bind(p.php_max_exec_secs)
    .bind(p.php_max_children)
    .bind(p.php_max_requests)
    .bind(p.db_max_connections)
    .bind(p.disk_hard_mb)
    .bind(p.bw_monthly_mb)
    .bind(p.expiry_grace_days)
    .bind(&p.expiry_warning_offsets)
    .bind(p.price_minor)
    .bind(&p.price_currency)
    .bind(&p.price_interval)
    .bind(&p.slack_webhook)
    .bind(&p.wp_plugins)
    .bind(&p.wp_themes)
    .bind(&p.default_php_version)
    .bind(&p.default_db_engine)
    .bind(&p.quota_exceed_action)
    .bind(p.disk_soft_mb)
    .bind(p.mem_limit_mib)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn update(
    pool: &SqlitePool,
    id: i64,
    p: &NewProfile,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"UPDATE hosting_profiles SET
            name = ?, description = ?, php_memory_mb = ?, php_max_exec_secs = ?,
            php_max_children = ?, php_max_requests = ?, db_max_connections = ?,
            disk_hard_mb = ?, bw_monthly_mb = ?, expiry_grace_days = ?,
            expiry_warning_offsets = ?, price_minor = ?, price_currency = ?,
            price_interval = ?, slack_webhook = ?, wp_plugins = ?, wp_themes = ?,
            default_php_version = ?, default_db_engine = ?, quota_exceed_action = ?,
            disk_soft_mb = ?, mem_limit_mib = ?,
            updated_at = ?
           WHERE id = ?"#,
    )
    .bind(&p.name)
    .bind(&p.description)
    .bind(p.php_memory_mb)
    .bind(p.php_max_exec_secs)
    .bind(p.php_max_children)
    .bind(p.php_max_requests)
    .bind(p.db_max_connections)
    .bind(p.disk_hard_mb)
    .bind(p.bw_monthly_mb)
    .bind(p.expiry_grace_days)
    .bind(&p.expiry_warning_offsets)
    .bind(p.price_minor)
    .bind(&p.price_currency)
    .bind(&p.price_interval)
    .bind(&p.slack_webhook)
    .bind(&p.wp_plugins)
    .bind(&p.wp_themes)
    .bind(&p.default_php_version)
    .bind(&p.default_db_engine)
    .bind(&p.quota_exceed_action)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_profiles WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

const SELECT_ALL: &str =
    "SELECT id, name, description, php_memory_mb, php_max_exec_secs, php_max_children,
            php_max_requests, db_max_connections, disk_hard_mb, bw_monthly_mb,
            expiry_grace_days, expiry_warning_offsets, price_minor, price_currency,
            price_interval, slack_webhook, wp_plugins, wp_themes,
            default_php_version, default_db_engine, quota_exceed_action,
            disk_soft_mb, mem_limit_mib,
            created_at, updated_at
     FROM hosting_profiles";

pub async fn list(pool: &SqlitePool) -> Result<Vec<ProfileRow>, StateError> {
    let q = format!("{} ORDER BY name", SELECT_ALL);
    let rows: Vec<ProfileRow> = sqlx::query_as::<_, ProfileRow>(&q).fetch_all(pool).await?;
    Ok(rows)
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Option<ProfileRow>, StateError> {
    let q = format!("{} WHERE id = ?", SELECT_ALL);
    let row: Option<ProfileRow> = sqlx::query_as::<_, ProfileRow>(&q)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn upsert_apply(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    profile_id: Option<i64>,
    price_minor: Option<i64>,
    price_currency: Option<&str>,
    price_interval: Option<&str>,
    next_billing_at: Option<i64>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_profile_apply
            (hosting_id, profile_id, price_minor, price_currency, price_interval,
             next_billing_at, applied_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(hosting_id) DO UPDATE SET
            profile_id = excluded.profile_id,
            price_minor = excluded.price_minor,
            price_currency = excluded.price_currency,
            price_interval = excluded.price_interval,
            next_billing_at = excluded.next_billing_at,
            applied_at = excluded.applied_at"#,
    )
    .bind(hosting_id.as_str())
    .bind(profile_id)
    .bind(price_minor)
    .bind(price_currency)
    .bind(price_interval)
    .bind(next_billing_at)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// How many hostings were created from / applied this profile (drives the
/// "in use: N" badge + the re-apply / delete-confirm copy).
pub async fn count_in_use(pool: &SqlitePool, profile_id: i64) -> Result<i64, StateError> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM hosting_profile_apply WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_one(pool)
            .await?;
    Ok(n)
}

/// Count of hostings per profile, for the profiles list ({profile_id: count}).
pub async fn counts_by_profile(pool: &SqlitePool) -> Result<Vec<(i64, i64)>, StateError> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT profile_id, COUNT(*) FROM hosting_profile_apply
          WHERE profile_id IS NOT NULL GROUP BY profile_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The hosting ids currently on this profile — drives "re-apply to all".
pub async fn hosting_ids_for_profile(
    pool: &SqlitePool,
    profile_id: i64,
) -> Result<Vec<String>, StateError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT hosting_id FROM hosting_profile_apply WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(h,)| h).collect())
}

pub async fn get_apply(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<Option<ProfileApplyRow>, StateError> {
    let row: Option<(
        String,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<i64>,
        i64,
    )> = sqlx::query_as(
        "SELECT hosting_id, profile_id, price_minor, price_currency, price_interval,
                next_billing_at, applied_at
         FROM hosting_profile_apply WHERE hosting_id = ?",
    )
    .bind(hosting_id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            hosting_id,
            profile_id,
            price_minor,
            price_currency,
            price_interval,
            next_billing_at,
            applied_at,
        )| ProfileApplyRow {
            hosting_id: HostingId(hosting_id),
            profile_id,
            price_minor,
            price_currency,
            price_interval,
            next_billing_at,
            applied_at,
        },
    ))
}

/// All hostings whose next billing is within `within_secs` of `now`.
pub async fn due_billings(
    pool: &SqlitePool,
    now: i64,
    within_secs: i64,
) -> Result<Vec<ProfileApplyRow>, StateError> {
    let rows: Vec<(
        String,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<i64>,
        i64,
    )> = sqlx::query_as(
        "SELECT hosting_id, profile_id, price_minor, price_currency, price_interval,
                next_billing_at, applied_at
         FROM hosting_profile_apply
         WHERE next_billing_at IS NOT NULL AND next_billing_at <= ?
         ORDER BY next_billing_at",
    )
    .bind(now + within_secs)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                hosting_id,
                profile_id,
                price_minor,
                price_currency,
                price_interval,
                next_billing_at,
                applied_at,
            )| ProfileApplyRow {
                hosting_id: HostingId(hosting_id),
                profile_id,
                price_minor,
                price_currency,
                price_interval,
                next_billing_at,
                applied_at,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn insert_then_list() {
        let pool = open_memory().await.expect("open");
        let p = NewProfile {
            name: "Pro".into(),
            description: "Mid-tier plan".into(),
            php_memory_mb: 512,
            php_max_exec_secs: 90,
            php_max_children: 20,
            php_max_requests: 2000,
            db_max_connections: 100,
            disk_hard_mb: Some(2048),
            bw_monthly_mb: Some(10_000),
            expiry_grace_days: 30,
            expiry_warning_offsets: "30,7,1".into(),
            price_minor: Some(19_900),
            price_currency: Some("CZK".into()),
            price_interval: Some("monthly".into()),
            slack_webhook: None,
            wp_plugins: String::new(),
            wp_themes: String::new(),
            default_php_version: None,
            default_db_engine: None,
            quota_exceed_action: "suspend".into(),
            disk_soft_mb: Some(1024),
            mem_limit_mib: Some(256),
        };
        let id = insert(&pool, &p, 100).await.expect("insert");
        assert!(id > 0);
        let all = list(&pool).await.expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Pro");
        assert_eq!(all[0].price_minor, Some(19_900));
        assert_eq!(all[0].quota_exceed_action, "suspend");
        assert_eq!(all[0].disk_soft_mb, Some(1024));
        assert_eq!(all[0].mem_limit_mib, Some(256));
    }

    #[tokio::test]
    async fn duplicate_name_rejected() {
        let pool = open_memory().await.expect("open");
        let p = NewProfile {
            name: "Basic".into(),
            ..Default::default()
        };
        insert(&pool, &p, 1).await.expect("first");
        assert!(insert(&pool, &p, 2).await.is_err());
    }
}
