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
    /// Migration 048 — recurring-backup cadence seeded at apply
    /// ("off"|"daily"|"weekly"|"monthly").
    #[sqlx(default)]
    pub backup_cadence: String,
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
    /// See ProfileRow::backup_cadence.
    pub backup_cadence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileApplyRow {
    pub hosting_id: HostingId,
    pub profile_id: Option<i64>,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub next_billing_at: Option<i64>,
    /// Snapshot of the profile's Slack billing/expiry webhook at apply time
    /// (migration 047). billing_sweep reads this first so the channel survives
    /// a profile delete; `None` falls back to the live profile lookup.
    pub slack_webhook: Option<String>,
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
            disk_soft_mb, mem_limit_mib, backup_cadence,
            created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    .bind(&p.backup_cadence)
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
            disk_soft_mb = ?, mem_limit_mib = ?, backup_cadence = ?,
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
    .bind(p.disk_soft_mb)
    .bind(p.mem_limit_mib)
    .bind(&p.backup_cadence)
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
            disk_soft_mb, mem_limit_mib, backup_cadence,
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

#[allow(clippy::too_many_arguments)]
pub async fn upsert_apply(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    profile_id: Option<i64>,
    price_minor: Option<i64>,
    price_currency: Option<&str>,
    price_interval: Option<&str>,
    next_billing_at: Option<i64>,
    slack_webhook: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_profile_apply
            (hosting_id, profile_id, price_minor, price_currency, price_interval,
             next_billing_at, slack_webhook, applied_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(hosting_id) DO UPDATE SET
            profile_id = excluded.profile_id,
            price_minor = excluded.price_minor,
            price_currency = excluded.price_currency,
            price_interval = excluded.price_interval,
            next_billing_at = excluded.next_billing_at,
            slack_webhook = excluded.slack_webhook,
            applied_at = excluded.applied_at"#,
    )
    .bind(hosting_id.as_str())
    .bind(profile_id)
    .bind(price_minor)
    .bind(price_currency)
    .bind(price_interval)
    .bind(next_billing_at)
    .bind(slack_webhook)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// How many LIVE hostings are on this profile (drives the "in use: N" badge +
/// the re-apply / delete-confirm copy). Trashed sites are excluded — they're on
/// their way out and shouldn't inflate the count or the re-apply scope.
pub async fn count_in_use(pool: &SqlitePool, profile_id: i64) -> Result<i64, StateError> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM hosting_profile_apply a
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.profile_id = ? AND h.state != 'trashed'",
    )
    .bind(profile_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Count of LIVE hostings per profile, for the profiles list ({profile_id: count}).
pub async fn counts_by_profile(pool: &SqlitePool) -> Result<Vec<(i64, i64)>, StateError> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT a.profile_id, COUNT(*) FROM hosting_profile_apply a
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.profile_id IS NOT NULL AND h.state != 'trashed'
          GROUP BY a.profile_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The LIVE hosting ids currently on this profile — drives "re-apply to all".
/// Trashed sites are skipped so a bulk re-apply doesn't churn dead sites.
pub async fn hosting_ids_for_profile(
    pool: &SqlitePool,
    profile_id: i64,
) -> Result<Vec<String>, StateError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT a.hosting_id FROM hosting_profile_apply a
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.profile_id = ? AND h.state != 'trashed'",
    )
    .bind(profile_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(h,)| h).collect())
}

/// Move a hosting's billing clock (used by billing_sweep to advance the date
/// after a reminder fires, so the reminder doesn't re-fire every tick forever).
/// `None` clears it (a row with no interval should stop being due).
pub async fn set_next_billing(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    next_billing_at: Option<i64>,
) -> Result<(), StateError> {
    sqlx::query("UPDATE hosting_profile_apply SET next_billing_at = ? WHERE hosting_id = ?")
        .bind(next_billing_at)
        .bind(hosting_id.as_str())
        .execute(pool)
        .await?;
    Ok(())
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
        Option<String>,
        i64,
    )> = sqlx::query_as(
        "SELECT hosting_id, profile_id, price_minor, price_currency, price_interval,
                next_billing_at, slack_webhook, applied_at
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
            slack_webhook,
            applied_at,
        )| ProfileApplyRow {
            hosting_id: HostingId(hosting_id),
            profile_id,
            price_minor,
            price_currency,
            price_interval,
            next_billing_at,
            slack_webhook,
            applied_at,
        },
    ))
}

/// All LIVE hostings whose next billing is within `within_secs` of `now`.
/// Trashed sites are excluded — a site in the bin must stop generating billing
/// reminders.
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
        Option<String>,
        i64,
    )> = sqlx::query_as(
        "SELECT a.hosting_id, a.profile_id, a.price_minor, a.price_currency, a.price_interval,
                a.next_billing_at, a.slack_webhook, a.applied_at
         FROM hosting_profile_apply a
           JOIN hostings h ON h.id = a.hosting_id
         WHERE a.next_billing_at IS NOT NULL AND a.next_billing_at <= ? AND h.state != 'trashed'
         ORDER BY a.next_billing_at",
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
                slack_webhook,
                applied_at,
            )| ProfileApplyRow {
                hosting_id: HostingId(hosting_id),
                profile_id,
                price_minor,
                price_currency,
                price_interval,
                next_billing_at,
                slack_webhook,
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
            backup_cadence: "daily".into(),
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
        assert_eq!(all[0].backup_cadence, "daily");
    }

    #[tokio::test]
    async fn update_persists_changes() {
        // Regression guard: update()'s bind chain must stay aligned with its SQL
        // placeholders. A missing bind makes the trailing params NULL, so the
        // statement becomes `WHERE id = NULL` and silently updates zero rows
        // while the caller still sees Ok — every profile edit a no-op.
        let pool = open_memory().await.expect("open");
        let id = insert(
            &pool,
            &NewProfile {
                name: "Pro".into(),
                php_memory_mb: 256,
                disk_hard_mb: Some(1024),
                disk_soft_mb: Some(512),
                mem_limit_mib: Some(128),
                quota_exceed_action: "notify".into(),
                ..Default::default()
            },
            100,
        )
        .await
        .expect("insert");

        update(
            &pool,
            id,
            &NewProfile {
                name: "Pro+".into(),
                php_memory_mb: 999,
                disk_hard_mb: Some(4096),
                disk_soft_mb: Some(3072),
                mem_limit_mib: Some(777),
                quota_exceed_action: "suspend".into(),
                ..Default::default()
            },
            200,
        )
        .await
        .expect("update");

        let row = get(&pool, id).await.expect("get").expect("row exists");
        assert_eq!(row.name, "Pro+");
        assert_eq!(row.php_memory_mb, 999);
        assert_eq!(row.disk_hard_mb, Some(4096));
        assert_eq!(row.disk_soft_mb, Some(3072));
        assert_eq!(row.mem_limit_mib, Some(777));
        assert_eq!(row.quota_exceed_action, "suspend");
        assert_eq!(row.updated_at, 200, "updated_at must advance, not go NULL");
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
