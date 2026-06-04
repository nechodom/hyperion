//! Multi-user web admin: users, roles, per-web access, 2FA, invites,
//! password resets. Persisted in agent state.db so the agent is the
//! sole authority on who can log in to the panel; web is a thin UI
//! that calls RPC for every credential check.

use crate::db::StateError;
use hyperion_types::HostingId;
use sqlx::SqlitePool;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebRole {
    SuperAdmin,
    Admin,
    Operator,
    Viewer,
}

impl WebRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuperAdmin => "super_admin",
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }
    /// Convenience: does this role see ALL hostings without consulting
    /// `web_user_hosting_access`?
    pub fn sees_all_hostings(self) -> bool {
        matches!(self, Self::SuperAdmin | Self::Admin)
    }
    /// Convenience: can this role manage other users / invites?
    pub fn can_manage_users(self) -> bool {
        matches!(self, Self::SuperAdmin)
    }
    /// Convenience: read-only role?
    pub fn is_read_only(self) -> bool {
        matches!(self, Self::Viewer)
    }
}

impl FromStr for WebRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "super_admin" => Ok(Self::SuperAdmin),
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "viewer" => Ok(Self::Viewer),
            other => Err(format!("unknown web role: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUserRow {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: WebRole,
    pub totp_secret_base32: Option<String>,
    pub totp_enrolled_at: Option<i64>,
    pub totp_required: bool,
    pub locked: bool,
    pub locked_reason: Option<String>,
    pub last_login_at: Option<i64>,
    pub last_login_ip: Option<String>,
    pub failed_logins: i64,
    pub failed_locked_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl WebUserRow {
    pub fn is_2fa_enrolled(&self) -> bool {
        self.totp_secret_base32.is_some() && self.totp_enrolled_at.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct NewWebUser<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub password_hash: &'a str,
    pub role: WebRole,
}

pub async fn insert(pool: &SqlitePool, n: &NewWebUser<'_>, now: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO web_users
           (username, email, password_hash, role, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?) RETURNING id"#,
    )
    .bind(n.username)
    .bind(n.email)
    .bind(n.password_hash)
    .bind(n.role.as_str())
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<Option<WebUserRow>, StateError> {
    fetch_one(pool, "WHERE id = ?", id).await
}

pub async fn get_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<WebUserRow>, StateError> {
    fetch_one_str(pool, "WHERE username = ?", username).await
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<WebUserRow>, StateError> {
    let rows = raw_select(pool, "ORDER BY username", None::<&str>).await?;
    Ok(rows)
}

pub async fn count(pool: &SqlitePool) -> Result<i64, StateError> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM web_users")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn set_password_hash(
    pool: &SqlitePool,
    user_id: i64,
    phc: &str,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE web_users SET password_hash = ?, updated_at = ?, failed_logins = 0 WHERE id = ?",
    )
    .bind(phc)
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_role(
    pool: &SqlitePool,
    user_id: i64,
    role: WebRole,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query("UPDATE web_users SET role = ?, updated_at = ? WHERE id = ?")
        .bind(role.as_str())
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_email(
    pool: &SqlitePool,
    user_id: i64,
    email: &str,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query("UPDATE web_users SET email = ?, updated_at = ? WHERE id = ?")
        .bind(email)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_locked(
    pool: &SqlitePool,
    user_id: i64,
    locked: bool,
    reason: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE web_users SET locked = ?, locked_reason = ?, updated_at = ? WHERE id = ?",
    )
    .bind(if locked { 1 } else { 0 })
    .bind(reason)
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_totp(
    pool: &SqlitePool,
    user_id: i64,
    secret_base32: Option<&str>,
    enrolled_at: Option<i64>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE web_users SET totp_secret_base32 = ?, totp_enrolled_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(secret_base32)
    .bind(enrolled_at)
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_totp_required(
    pool: &SqlitePool,
    user_id: i64,
    required: bool,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query("UPDATE web_users SET totp_required = ?, updated_at = ? WHERE id = ?")
        .bind(if required { 1 } else { 0 })
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn record_login(
    pool: &SqlitePool,
    user_id: i64,
    ip: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE web_users SET last_login_at = ?, last_login_ip = ?, failed_logins = 0, \
         failed_locked_at = NULL, updated_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(ip)
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Bump failed-login counter. Caller decides whether to lock based on
/// the returned count.
pub async fn record_failed_login(
    pool: &SqlitePool,
    user_id: i64,
    now: i64,
) -> Result<i64, StateError> {
    sqlx::query("UPDATE web_users SET failed_logins = failed_logins + 1, updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    let (n,): (i64,) = sqlx::query_as("SELECT failed_logins FROM web_users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn delete(pool: &SqlitePool, user_id: i64) -> Result<u64, StateError> {
    let r = sqlx::query("DELETE FROM web_users WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

// --- backup codes ---

pub async fn insert_backup_codes(
    pool: &SqlitePool,
    user_id: i64,
    hashed: &[String],
    now: i64,
) -> Result<(), StateError> {
    let mut tx = pool.begin().await?;
    // Wipe any previous (one set per user).
    sqlx::query("DELETE FROM web_user_backup_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for h in hashed {
        sqlx::query(
            "INSERT INTO web_user_backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
        )
        .bind(user_id)
        .bind(h)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Try to consume a backup code by its blake3 hex hash. Returns Ok(true)
/// if a fresh (unused) code matched and was marked used. Atomic.
pub async fn consume_backup_code(
    pool: &SqlitePool,
    user_id: i64,
    code_hash: &str,
    now: i64,
) -> Result<bool, StateError> {
    let r = sqlx::query(
        "UPDATE web_user_backup_codes SET used_at = ? \
         WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
    )
    .bind(now)
    .bind(user_id)
    .bind(code_hash)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn count_unused_backup_codes(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<i64, StateError> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM web_user_backup_codes WHERE user_id = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

// --- per-web access ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
    Read,
    Manage,
}
impl AccessLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Manage => "manage",
        }
    }
}
impl FromStr for AccessLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "manage" => Ok(Self::Manage),
            other => Err(format!("unknown access level: {other}")),
        }
    }
}

pub async fn grant_hosting_access(
    pool: &SqlitePool,
    user_id: i64,
    hosting_id: &HostingId,
    level: AccessLevel,
    granted_by: Option<i64>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO web_user_hosting_access
           (user_id, hosting_id, level, granted_by, granted_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(user_id, hosting_id) DO UPDATE SET level = excluded.level"#,
    )
    .bind(user_id)
    .bind(hosting_id.as_str())
    .bind(level.as_str())
    .bind(granted_by)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn revoke_hosting_access(
    pool: &SqlitePool,
    user_id: i64,
    hosting_id: &HostingId,
) -> Result<u64, StateError> {
    let r = sqlx::query(
        "DELETE FROM web_user_hosting_access WHERE user_id = ? AND hosting_id = ?",
    )
    .bind(user_id)
    .bind(hosting_id.as_str())
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

pub async fn list_hosting_ids_for_user(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<(HostingId, AccessLevel)>, StateError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT hosting_id, level FROM web_user_hosting_access WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (hid, lvl) in rows {
        out.push((
            HostingId(hid),
            AccessLevel::from_str(&lvl).map_err(StateError::InvalidState)?,
        ));
    }
    Ok(out)
}

/// All access grants for a given hosting — used by the per-hosting
/// "Access" tab on the detail page. Joins to web_users so each row
/// carries the username + email without an extra round-trip.
pub async fn list_access_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<Vec<(i64, String, String, AccessLevel, Option<i64>, i64)>, StateError> {
    let rows: Vec<(i64, String, String, String, Option<i64>, i64)> = sqlx::query_as(
        "SELECT a.user_id, u.username, u.email, a.level, a.granted_by, a.granted_at
         FROM web_user_hosting_access a
         JOIN web_users u ON u.id = a.user_id
         WHERE a.hosting_id = ?
         ORDER BY u.username",
    )
    .bind(hosting_id.as_str())
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (uid, username, email, lvl, by, at) in rows {
        out.push((
            uid,
            username,
            email,
            AccessLevel::from_str(&lvl).map_err(StateError::InvalidState)?,
            by,
            at,
        ));
    }
    Ok(out)
}

pub async fn user_hosting_access(
    pool: &SqlitePool,
    user_id: i64,
    hosting_id: &HostingId,
) -> Result<Option<AccessLevel>, StateError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT level FROM web_user_hosting_access WHERE user_id = ? AND hosting_id = ?",
    )
    .bind(user_id)
    .bind(hosting_id.as_str())
    .fetch_optional(pool)
    .await?;
    match row {
        None => Ok(None),
        Some((s,)) => Ok(Some(AccessLevel::from_str(&s).map_err(StateError::InvalidState)?)),
    }
}

// --- invites ---

#[derive(Debug, Clone)]
pub struct InviteRow {
    pub id: i64,
    pub token_hash: String,
    pub email: String,
    pub role: WebRole,
    pub created_by: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
    pub accepted_at: Option<i64>,
    pub accepted_user_id: Option<i64>,
}

pub async fn create_invite(
    pool: &SqlitePool,
    token_hash: &str,
    email: &str,
    role: WebRole,
    created_by: Option<i64>,
    now: i64,
    expires_at: i64,
) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO web_invites
           (token_hash, email, role, created_by, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?) RETURNING id"#,
    )
    .bind(token_hash)
    .bind(email)
    .bind(role.as_str())
    .bind(created_by)
    .bind(now)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn find_invite_by_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<InviteRow>, StateError> {
    let row: Option<(
        i64, String, String, String, Option<i64>, i64, i64, Option<i64>, Option<i64>,
    )> = sqlx::query_as(
        "SELECT id, token_hash, email, role, created_by, created_at, expires_at,
                accepted_at, accepted_user_id
         FROM web_invites WHERE token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, h, e, r, by, ca, ex, aa, au)| InviteRow {
        id,
        token_hash: h,
        email: e,
        role: WebRole::from_str(&r).unwrap_or(WebRole::Viewer),
        created_by: by,
        created_at: ca,
        expires_at: ex,
        accepted_at: aa,
        accepted_user_id: au,
    }))
}

pub async fn mark_invite_accepted(
    pool: &SqlitePool,
    invite_id: i64,
    user_id: i64,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE web_invites SET accepted_at = ?, accepted_user_id = ? WHERE id = ?",
    )
    .bind(now)
    .bind(user_id)
    .bind(invite_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_pending_invites(pool: &SqlitePool) -> Result<Vec<InviteRow>, StateError> {
    let rows: Vec<(
        i64, String, String, String, Option<i64>, i64, i64, Option<i64>, Option<i64>,
    )> = sqlx::query_as(
        "SELECT id, token_hash, email, role, created_by, created_at, expires_at,
                accepted_at, accepted_user_id
         FROM web_invites
         WHERE accepted_at IS NULL
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, h, e, r, by, ca, ex, aa, au)| InviteRow {
            id,
            token_hash: h,
            email: e,
            role: WebRole::from_str(&r).unwrap_or(WebRole::Viewer),
            created_by: by,
            created_at: ca,
            expires_at: ex,
            accepted_at: aa,
            accepted_user_id: au,
        })
        .collect())
}

pub async fn revoke_invite(pool: &SqlitePool, invite_id: i64) -> Result<u64, StateError> {
    let r = sqlx::query("DELETE FROM web_invites WHERE id = ?")
        .bind(invite_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

// --- internals ---

async fn fetch_one(
    pool: &SqlitePool,
    suffix: &'static str,
    bind: i64,
) -> Result<Option<WebUserRow>, StateError> {
    let sql = format!("SELECT {COLS} FROM web_users {suffix}", COLS = COLS);
    let row: Option<RawUser> = sqlx::query_as(&sql).bind(bind).fetch_optional(pool).await?;
    Ok(row.map(raw_to_row))
}
async fn fetch_one_str(
    pool: &SqlitePool,
    suffix: &'static str,
    bind: &str,
) -> Result<Option<WebUserRow>, StateError> {
    let sql = format!("SELECT {COLS} FROM web_users {suffix}", COLS = COLS);
    let row: Option<RawUser> = sqlx::query_as(&sql).bind(bind).fetch_optional(pool).await?;
    Ok(row.map(raw_to_row))
}
async fn raw_select(
    pool: &SqlitePool,
    suffix: &'static str,
    _bind: Option<&str>,
) -> Result<Vec<WebUserRow>, StateError> {
    let sql = format!("SELECT {COLS} FROM web_users {suffix}", COLS = COLS);
    let rows: Vec<RawUser> = sqlx::query_as(&sql).fetch_all(pool).await?;
    Ok(rows.into_iter().map(raw_to_row).collect())
}

const COLS: &str = "id, username, email, password_hash, role, totp_secret_base32, \
                    totp_enrolled_at, totp_required, locked, locked_reason, \
                    last_login_at, last_login_ip, failed_logins, failed_locked_at, \
                    created_at, updated_at";

type RawUser = (
    i64,            // id
    String,         // username
    String,         // email
    String,         // password_hash
    String,         // role
    Option<String>, // totp_secret_base32
    Option<i64>,    // totp_enrolled_at
    i64,            // totp_required
    i64,            // locked
    Option<String>, // locked_reason
    Option<i64>,    // last_login_at
    Option<String>, // last_login_ip
    i64,            // failed_logins
    Option<i64>,    // failed_locked_at
    i64,            // created_at
    i64,            // updated_at
);

fn raw_to_row(r: RawUser) -> WebUserRow {
    WebUserRow {
        id: r.0,
        username: r.1,
        email: r.2,
        password_hash: r.3,
        role: WebRole::from_str(&r.4).unwrap_or(WebRole::Viewer),
        totp_secret_base32: r.5,
        totp_enrolled_at: r.6,
        totp_required: r.7 != 0,
        locked: r.8 != 0,
        locked_reason: r.9,
        last_login_at: r.10,
        last_login_ip: r.11,
        failed_logins: r.12,
        failed_locked_at: r.13,
        created_at: r.14,
        updated_at: r.15,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    async fn fresh_user(pool: &SqlitePool, name: &str) -> i64 {
        insert(
            pool,
            &NewWebUser {
                username: name,
                email: &format!("{name}@example.cz"),
                password_hash: "$argon2id$dummy",
                role: WebRole::Admin,
            },
            10,
        )
        .await
        .expect("insert")
    }

    #[tokio::test]
    async fn insert_then_get_by_id_and_username() {
        let pool = open_memory().await.expect("open");
        let id = fresh_user(&pool, "alice").await;
        let by_id = get_by_id(&pool, id).await.expect("get").expect("present");
        assert_eq!(by_id.username, "alice");
        assert_eq!(by_id.role, WebRole::Admin);
        assert!(!by_id.is_2fa_enrolled());
        let by_name = get_by_username(&pool, "alice")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(by_name.id, id);
    }

    #[tokio::test]
    async fn username_uniqueness() {
        let pool = open_memory().await.expect("open");
        let _ = fresh_user(&pool, "alice").await;
        let r = insert(
            &pool,
            &NewWebUser {
                username: "alice",
                email: "other@x.cz",
                password_hash: "x",
                role: WebRole::Viewer,
            },
            20,
        )
        .await;
        assert!(r.is_err(), "duplicate username must fail");
    }

    #[tokio::test]
    async fn role_check_rejects_invalid() {
        let pool = open_memory().await.expect("open");
        let id = fresh_user(&pool, "alice").await;
        let r = sqlx::query("UPDATE web_users SET role = 'wizard' WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await;
        assert!(r.is_err(), "CHECK should refuse 'wizard'");
    }

    #[tokio::test]
    async fn totp_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fresh_user(&pool, "alice").await;
        set_totp(&pool, id, Some("JBSWY3DPEHPK3PXP"), Some(42), 100)
            .await
            .expect("set totp");
        let u = get_by_id(&pool, id).await.expect("get").expect("present");
        assert_eq!(u.totp_secret_base32.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(u.totp_enrolled_at, Some(42));
        assert!(u.is_2fa_enrolled());

        set_totp(&pool, id, None, None, 101).await.expect("clear");
        let u = get_by_id(&pool, id).await.expect("get").expect("present");
        assert!(!u.is_2fa_enrolled());
    }

    #[tokio::test]
    async fn backup_codes_one_time_use() {
        let pool = open_memory().await.expect("open");
        let id = fresh_user(&pool, "alice").await;
        let hashes = vec!["hash1".to_string(), "hash2".to_string()];
        insert_backup_codes(&pool, id, &hashes, 1)
            .await
            .expect("insert codes");
        assert_eq!(count_unused_backup_codes(&pool, id).await.expect("count"), 2);
        // First consume succeeds.
        assert!(consume_backup_code(&pool, id, "hash1", 2)
            .await
            .expect("consume"));
        // Second consume of same hash fails (used_at set).
        assert!(!consume_backup_code(&pool, id, "hash1", 3)
            .await
            .expect("re-consume"));
        // Wrong hash fails.
        assert!(!consume_backup_code(&pool, id, "nope", 4)
            .await
            .expect("wrong"));
        assert_eq!(count_unused_backup_codes(&pool, id).await.expect("count"), 1);
    }

    #[tokio::test]
    async fn role_helpers_match_expectations() {
        assert!(WebRole::SuperAdmin.sees_all_hostings());
        assert!(WebRole::Admin.sees_all_hostings());
        assert!(!WebRole::Operator.sees_all_hostings());
        assert!(!WebRole::Viewer.sees_all_hostings());
        assert!(WebRole::SuperAdmin.can_manage_users());
        assert!(!WebRole::Admin.can_manage_users());
        assert!(!WebRole::Operator.can_manage_users());
        assert!(!WebRole::Viewer.can_manage_users());
        assert!(WebRole::Viewer.is_read_only());
        assert!(!WebRole::Operator.is_read_only());
    }

    #[tokio::test]
    async fn hosting_access_grant_revoke_round_trip() {
        let pool = open_memory().await.expect("open");
        // Need a hosting to point at — create a stub via the hostings table.
        let suid = crate::system_users::insert(&pool, "u", 1001, "/home/u", "/x", 1)
            .await
            .expect("user");
        let hid = HostingId::new_v7();
        crate::hostings::insert(&pool, &hid, "x.cz", suid, None, "/x", 1, None)
            .await
            .expect("hosting");
        let uid = fresh_user(&pool, "alice").await;

        grant_hosting_access(&pool, uid, &hid, AccessLevel::Manage, None, 5)
            .await
            .expect("grant");
        let lvl = user_hosting_access(&pool, uid, &hid)
            .await
            .expect("get level")
            .expect("present");
        assert_eq!(lvl, AccessLevel::Manage);

        // Upsert downgrades.
        grant_hosting_access(&pool, uid, &hid, AccessLevel::Read, None, 6)
            .await
            .expect("regrant");
        let lvl = user_hosting_access(&pool, uid, &hid)
            .await
            .expect("get level")
            .expect("present");
        assert_eq!(lvl, AccessLevel::Read);

        let removed = revoke_hosting_access(&pool, uid, &hid)
            .await
            .expect("revoke");
        assert_eq!(removed, 1);
        let lvl = user_hosting_access(&pool, uid, &hid)
            .await
            .expect("get level");
        assert!(lvl.is_none());
    }

    #[tokio::test]
    async fn invite_create_find_accept() {
        let pool = open_memory().await.expect("open");
        let inviter = fresh_user(&pool, "admin").await;
        let id = create_invite(
            &pool,
            "tokenhash",
            "newbie@example.cz",
            WebRole::Viewer,
            Some(inviter),
            10,
            10 + 86400,
        )
        .await
        .expect("create");
        let row = find_invite_by_hash(&pool, "tokenhash")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(row.id, id);
        assert_eq!(row.role, WebRole::Viewer);
        assert!(row.accepted_at.is_none());
        // Pretend the recipient created a user record then we mark.
        let newbie = fresh_user(&pool, "newbie").await;
        mark_invite_accepted(&pool, id, newbie, 20)
            .await
            .expect("accept");
        let row = find_invite_by_hash(&pool, "tokenhash")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(row.accepted_at, Some(20));
        assert_eq!(row.accepted_user_id, Some(newbie));
    }

    #[tokio::test]
    async fn count_and_list_match_insertions() {
        let pool = open_memory().await.expect("open");
        assert_eq!(count(&pool).await.expect("count empty"), 0);
        for n in ["alice", "bob", "carol"] {
            let _ = fresh_user(&pool, n).await;
        }
        assert_eq!(count(&pool).await.expect("count 3"), 3);
        let users = list(&pool).await.expect("list");
        let names: Vec<&str> = users.iter().map(|u| u.username.as_str()).collect();
        assert_eq!(names, vec!["alice", "bob", "carol"]);
    }
}
