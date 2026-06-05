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
    /// "php" | "static" | "reverse_proxy" | "redirect". Defaults to
    /// "php" for pre-migration-014 rows.
    pub kind: String,
    /// Upstream URL for kind=reverse_proxy. None for other kinds.
    pub proxy_upstream_url: Option<String>,
    /// Stable identifier of the node this hosting was provisioned on.
    /// Read from `HYPERION_NODE_ID` env or `/etc/hostname` at create
    /// time (see `HostingService::current_node_id`). `None` for rows
    /// that pre-date migration 016 and haven't been backfilled yet.
    pub node_id: Option<String>,
    /// Migration 020 — operator-controlled vhost knobs. Default
    /// values match the pre-020 vhost rendering exactly.
    pub vhost_options: hyperion_types::VhostOptions,
    /// Migration 021 — WordPress + Redis app-layer toggles. Default
    /// values match a fresh non-WP hosting.
    pub wp_extras: hyperion_types::WpExtras,
    /// Migration 026 — when the row is `state = 'trashed'`, the
    /// unix-epoch second when delete was issued. `None` for any
    /// non-trashed row.
    pub trashed_at: Option<i64>,
}

pub async fn insert(
    pool: &SqlitePool,
    id: &HostingId,
    domain: &str,
    system_user_id: i64,
    php_version: Option<PhpVersion>,
    root_dir: &str,
    now: i64,
    node_id: Option<&str>,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hostings
           (id, domain, state, system_user_id, php_version, root_dir, created_at, updated_at, node_id)
           VALUES (?, ?, 'provisioning', ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(id.as_str())
    .bind(domain)
    .bind(system_user_id)
    .bind(php_version.map(|v| v.as_str()))
    .bind(root_dir)
    .bind(now)
    .bind(now)
    .bind(node_id)
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

/// Set state = Trashed + stamp trashed_at = now. The scheduler
/// reads `trashed_at` to decide when to GC; the UI uses it for
/// the "X days remaining" badge on /trash.
pub async fn mark_trashed(
    pool: &SqlitePool,
    id: &HostingId,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE hostings SET state = 'trashed', trashed_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Restore a trashed hosting back to Active (clears trashed_at).
pub async fn unmark_trashed(
    pool: &SqlitePool,
    id: &HostingId,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE hostings SET state = 'active', trashed_at = NULL, updated_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Trashed rows whose retention window has expired (now -
/// trashed_at >= retention_secs). Caller passes the resolved
/// retention seconds — the state crate doesn't know about
/// the cluster config.
pub async fn list_trashed_expired(
    pool: &SqlitePool,
    now: i64,
    retention_secs: i64,
) -> Result<Vec<HostingRow>, StateError> {
    let cutoff = now - retention_secs;
    let ids: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM hostings WHERE state = 'trashed' AND trashed_at <= ? \
         ORDER BY trashed_at",
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(ids.len());
    for (id,) in ids {
        if let Some(row) = get_by_id(pool, &HostingId(id)).await? {
            out.push(row);
        }
    }
    Ok(out)
}

/// All currently-trashed hostings (any age). Used by the
/// /trash page UI.
pub async fn list_trashed(pool: &SqlitePool) -> Result<Vec<HostingRow>, StateError> {
    let ids: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM hostings WHERE state = 'trashed' ORDER BY trashed_at DESC",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(ids.len());
    for (id,) in ids {
        if let Some(row) = get_by_id(pool, &HostingId(id)).await? {
            out.push(row);
        }
    }
    Ok(out)
}

/// Read just the trashed_at timestamp (NULL for not-trashed).
/// Used by the service layer to compute "days remaining".
pub async fn get_trashed_at(
    pool: &SqlitePool,
    id: &HostingId,
) -> Result<Option<i64>, StateError> {
    let row: Option<(Option<i64>,)> = sqlx::query_as(
        "SELECT trashed_at FROM hostings WHERE id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(t,)| t))
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
        sqlx::query_as::<_, RawHostingHead>(QUERY_BASE).bind(id.as_str()),
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
        sqlx::query_as::<_, RawHostingHead>(QUERY_DOMAIN).bind(domain),
    )
    .await
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<HostingSummary>, StateError> {
    let rows: Vec<(String, String, String, Option<String>, i64, Option<String>)> = sqlx::query_as(
        "SELECT id, domain, state, php_version, created_at, node_id FROM hostings \
         WHERE state != 'trashed' \
         ORDER BY domain",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, domain, state, php_version, created_at, node_id) in rows {
        out.push(HostingSummary {
            id: HostingId(id),
            domain,
            state: HostingState::from_str(&state).map_err(StateError::InvalidState)?,
            php_version: match php_version {
                Some(v) => Some(PhpVersion::from_str(&v).map_err(StateError::InvalidState)?),
                None => None,
            },
            created_at,
            node_id,
        });
    }
    Ok(out)
}

// --- internals ---

// Split the SELECT into two halves to stay under sqlx's
// 16-column FromRow tuple limit. Halve 1 = the "classic"
// hosting columns. Halve 2 = the vhost knobs from migration 020.
//
// We do TWO sequential queries keyed by the same id/domain — the
// second is a cheap UNIQUE-keyed lookup, so the latency hit is
// marginal vs. one big JOIN-shaped query.
type RawHostingHead = (
    String,           // id
    String,           // domain
    String,           // state
    i64,              // system_user_id
    Option<String>,   // php_version
    String,           // root_dir
    i64,              // created_at
    i64,              // updated_at
    Option<String>,   // acme_contact_email
    String,           // kind
    Option<String>,   // proxy_upstream_url
    Option<String>,   // node_id
    Option<i64>,      // trashed_at (NULL when not trashed)
);
type RawHostingVhost = (
    i64,    // basic_auth_enabled
    String, // basic_auth_user
    String, // basic_auth_hash
    i64,    // force_https
    i64,    // hsts_max_age
    String, // custom_nginx_snippet
    i64,    // maintenance_mode
    i64,    // fastcgi_cache_enabled
    i64,    // fastcgi_cache_ttl
    String, // redirect_url
    i64,    // redirect_code
    i64,    // redirect_preserve_path
);

const QUERY_BASE: &str =
    "SELECT id, domain, state, system_user_id, php_version, root_dir, created_at, updated_at, \
            acme_contact_email, kind, proxy_upstream_url, node_id, trashed_at \
     FROM hostings WHERE id = ?";
const QUERY_DOMAIN: &str =
    "SELECT id, domain, state, system_user_id, php_version, root_dir, created_at, updated_at, \
            acme_contact_email, kind, proxy_upstream_url, node_id, trashed_at \
     FROM hostings WHERE domain = ?";
const QUERY_VHOST_BY_ID: &str =
    "SELECT basic_auth_enabled, basic_auth_user, basic_auth_hash, force_https, hsts_max_age, \
            custom_nginx_snippet, maintenance_mode, fastcgi_cache_enabled, fastcgi_cache_ttl, \
            redirect_url, redirect_code, redirect_preserve_path \
     FROM hostings WHERE id = ?";

// Third row tuple for the WP/Redis extras (migration 021). Same PK
// lookup as the vhost half — single index hit per detail load.
type RawHostingWp = (
    i64, // wp_debug_enabled
    i64, // wp_debug_log
    i64, // wp_debug_display
    i64, // wp_debug_log_size_bytes
    i64, // redis_enabled
    Option<i64>, // redis_db_number
    i64, // redis_password_set
);

const QUERY_WP_BY_ID: &str =
    "SELECT wp_debug_enabled, wp_debug_log, wp_debug_display, wp_debug_log_size_bytes, \
            redis_enabled, redis_db_number, redis_password_set \
     FROM hostings WHERE id = ?";

async fn fetch_one<'a>(
    pool: &'a SqlitePool,
    _why: &'static str,
    q: sqlx::query::QueryAs<'a, sqlx::Sqlite, RawHostingHead, sqlx::sqlite::SqliteArguments<'a>>,
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
        kind,
        proxy_upstream_url,
        node_id,
        trashed_at,
    )) = row
    else {
        return Ok(None);
    };
    // Second query for the vhost knob columns. We key on the same
    // id we just read so the lookup is a single PK hit.
    let vhost_row: Option<RawHostingVhost> = sqlx::query_as(QUERY_VHOST_BY_ID)
        .bind(&id)
        .fetch_optional(pool)
        .await?;
    let vhost_options = match vhost_row {
        Some((
            basic_auth_enabled,
            basic_auth_user,
            basic_auth_hash,
            force_https,
            hsts_max_age,
            custom_nginx_snippet,
            maintenance_mode,
            fastcgi_cache_enabled,
            fastcgi_cache_ttl,
            redirect_url,
            redirect_code,
            redirect_preserve_path,
        )) => hyperion_types::VhostOptions {
            basic_auth_enabled: basic_auth_enabled != 0,
            basic_auth_user,
            basic_auth_set: !basic_auth_hash.is_empty(),
            force_https: force_https != 0,
            hsts_max_age,
            custom_nginx_snippet,
            maintenance_mode: maintenance_mode != 0,
            fastcgi_cache_enabled: fastcgi_cache_enabled != 0,
            fastcgi_cache_ttl,
            redirect_url,
            redirect_code,
            redirect_preserve_path: redirect_preserve_path != 0,
        },
        None => hyperion_types::VhostOptions::default(),
    };
    // Third lookup: WP/Redis extras (migration 021). Same PK hit.
    let wp_row: Option<RawHostingWp> = sqlx::query_as(QUERY_WP_BY_ID)
        .bind(&id)
        .fetch_optional(pool)
        .await?;
    let wp_extras = match wp_row {
        Some((
            wp_debug_enabled,
            wp_debug_log,
            wp_debug_display,
            wp_debug_log_size_bytes,
            redis_enabled,
            redis_db_number,
            redis_password_set,
        )) => hyperion_types::WpExtras {
            wp_debug_enabled: wp_debug_enabled != 0,
            wp_debug_log: wp_debug_log != 0,
            wp_debug_display: wp_debug_display != 0,
            wp_debug_log_size_bytes,
            redis_enabled: redis_enabled != 0,
            redis_db_number,
            redis_password_set: redis_password_set != 0,
        },
        None => hyperion_types::WpExtras::default(),
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
        kind,
        proxy_upstream_url,
        node_id,
        vhost_options,
        wp_extras,
        trashed_at,
    }))
}

/// Read the per-hosting basic-auth password hash (NOT exposed in
/// HostingRow.vhost_options — only the "is_set" bool is). Used by
/// the vhost render to write the .htpasswd file. Empty string when
/// basic auth isn't configured.
pub async fn get_basic_auth_hash(
    pool: &SqlitePool,
    id: &HostingId,
) -> Result<String, StateError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT basic_auth_hash FROM hostings WHERE id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(s,)| s).unwrap_or_default())
}

/// Update the operator-controlled vhost knobs in one statement.
/// `basic_auth_hash` should be `None` when the operator left the
/// password field empty (preserves the existing stored hash) and
/// `Some(new_hash)` when a new value was provided. Empty new_hash
/// clears the credential.
#[allow(clippy::too_many_arguments)]
pub async fn set_vhost_options(
    pool: &SqlitePool,
    id: &HostingId,
    opts: &hyperion_types::VhostOptions,
    basic_auth_hash: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    // If hash is None, don't touch the column.
    if let Some(h) = basic_auth_hash {
        sqlx::query(
            "UPDATE hostings SET basic_auth_enabled=?, basic_auth_user=?, basic_auth_hash=?, \
                force_https=?, hsts_max_age=?, custom_nginx_snippet=?, \
                maintenance_mode=?, fastcgi_cache_enabled=?, fastcgi_cache_ttl=?, \
                redirect_url=?, redirect_code=?, redirect_preserve_path=?, updated_at=? \
             WHERE id = ?",
        )
        .bind(opts.basic_auth_enabled as i64)
        .bind(&opts.basic_auth_user)
        .bind(h)
        .bind(opts.force_https as i64)
        .bind(opts.hsts_max_age)
        .bind(&opts.custom_nginx_snippet)
        .bind(opts.maintenance_mode as i64)
        .bind(opts.fastcgi_cache_enabled as i64)
        .bind(opts.fastcgi_cache_ttl)
        .bind(&opts.redirect_url)
        .bind(opts.redirect_code)
        .bind(opts.redirect_preserve_path as i64)
        .bind(now)
        .bind(id.as_str())
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE hostings SET basic_auth_enabled=?, basic_auth_user=?, \
                force_https=?, hsts_max_age=?, custom_nginx_snippet=?, \
                maintenance_mode=?, fastcgi_cache_enabled=?, fastcgi_cache_ttl=?, \
                redirect_url=?, redirect_code=?, redirect_preserve_path=?, updated_at=? \
             WHERE id = ?",
        )
        .bind(opts.basic_auth_enabled as i64)
        .bind(&opts.basic_auth_user)
        .bind(opts.force_https as i64)
        .bind(opts.hsts_max_age)
        .bind(&opts.custom_nginx_snippet)
        .bind(opts.maintenance_mode as i64)
        .bind(opts.fastcgi_cache_enabled as i64)
        .bind(opts.fastcgi_cache_ttl)
        .bind(&opts.redirect_url)
        .bind(opts.redirect_code)
        .bind(opts.redirect_preserve_path as i64)
        .bind(now)
        .bind(id.as_str())
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Update the WP/Redis extras for one hosting.
///
/// Three split setters because callers want different update shapes:
/// - the WP debug toggle (operator action) writes debug + ttl + redis
///   flags but NOT the log-size sample
/// - the agent's hourly tick writes ONLY the log-size sample (we don't
///   want it to clobber the operator's other settings)
/// - the Redis enable flow writes ONLY the redis_* columns
///
/// All three accept an `i64` instead of `bool` at the SQL boundary —
/// SQLite has no native bool, and casting on the bind side keeps the
/// migration sane.
pub async fn set_wp_debug(
    pool: &SqlitePool,
    id: &HostingId,
    enabled: bool,
    log: bool,
    display: bool,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE hostings SET wp_debug_enabled=?, wp_debug_log=?, wp_debug_display=?, \
                             updated_at=? WHERE id = ?",
    )
    .bind(enabled as i64)
    .bind(log as i64)
    .bind(display as i64)
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_wp_debug_log_size(
    pool: &SqlitePool,
    id: &HostingId,
    size_bytes: i64,
) -> Result<(), StateError> {
    sqlx::query("UPDATE hostings SET wp_debug_log_size_bytes=? WHERE id = ?")
        .bind(size_bytes)
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_redis(
    pool: &SqlitePool,
    id: &HostingId,
    enabled: bool,
    db_number: Option<i64>,
    password_set: bool,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE hostings SET redis_enabled=?, redis_db_number=?, redis_password_set=?, \
                             updated_at=? WHERE id = ?",
    )
    .bind(enabled as i64)
    .bind(db_number)
    .bind(password_set as i64)
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Find the lowest unused Redis DB number across all hostings on this
/// agent. Used at provisioning time so two hostings on the same node
/// don't share a DB and clobber each other's cache.
///
/// Returns `Some(n)` for the smallest free slot in [0, max), or
/// `None` if every slot is taken (operator needs to bump
/// `databases` in /etc/redis/redis.conf and reload first).
pub async fn next_free_redis_db(
    pool: &SqlitePool,
    max: i64,
) -> Result<Option<i64>, StateError> {
    let taken: Vec<(i64,)> = sqlx::query_as(
        "SELECT redis_db_number FROM hostings \
         WHERE redis_enabled = 1 AND redis_db_number IS NOT NULL \
         ORDER BY redis_db_number",
    )
    .fetch_all(pool)
    .await?;
    let taken: std::collections::BTreeSet<i64> = taken.into_iter().map(|(n,)| n).collect();
    for n in 0..max {
        if !taken.contains(&n) {
            return Ok(Some(n));
        }
    }
    Ok(None)
}

/// Set the hosting kind + upstream URL on an existing row.
/// `proxy_url` must be Some when `kind == "reverse_proxy"`, None otherwise.
pub async fn set_kind(
    pool: &SqlitePool,
    id: &HostingId,
    kind: &str,
    proxy_upstream_url: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE hostings SET kind = ?, proxy_upstream_url = ?, updated_at = ? WHERE id = ?",
    )
    .bind(kind)
    .bind(proxy_upstream_url)
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert with explicit kind + optional proxy URL — used by the
/// reverse-proxy create flow. Falls back to the simpler `insert`
/// when kind=php.
pub async fn insert_with_kind(
    pool: &SqlitePool,
    id: &HostingId,
    domain: &str,
    system_user_id: i64,
    php_version: Option<PhpVersion>,
    root_dir: &str,
    kind: &str,
    proxy_upstream_url: Option<&str>,
    now: i64,
    node_id: Option<&str>,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hostings
           (id, domain, state, system_user_id, php_version, root_dir,
            created_at, updated_at, kind, proxy_upstream_url, node_id)
           VALUES (?, ?, 'provisioning', ?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(id.as_str())
    .bind(domain)
    .bind(system_user_id)
    .bind(php_version.map(|v| v.as_str()))
    .bind(root_dir)
    .bind(now)
    .bind(now)
    .bind(kind)
    .bind(proxy_upstream_url)
    .bind(node_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// One-shot backfill: every hostings row with NULL node_id gets the
/// caller's node id. Called by the agent at startup so the list +
/// detail UIs show a node chip even for pre-migration rows.
pub async fn backfill_node_id(
    pool: &SqlitePool,
    node_id: &str,
) -> Result<u64, StateError> {
    let r = sqlx::query("UPDATE hostings SET node_id = ? WHERE node_id IS NULL")
        .bind(node_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
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

/// Update the hosting's `php_version` column. `None` means "drop
/// PHP, become a static site" — we accept it but the service layer
/// rejects it (static-vs-PHP is a kind change handled elsewhere) so
/// the DB level stays permissive.
pub async fn set_php_version(
    pool: &SqlitePool,
    id: &HostingId,
    php_version: Option<PhpVersion>,
    now: i64,
) -> Result<u64, StateError> {
    let r = sqlx::query(
        "UPDATE hostings SET php_version = ?, updated_at = ? WHERE id = ?",
    )
    .bind(php_version.map(|v| v.as_str()))
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
            None,
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
        insert(&pool, &id, "example.cz", suid, None, "/x", 1, None)
            .await
            .expect("first ok");
        let id2 = HostingId::new_v7();
        let r = insert(&pool, &id2, "example.cz", suid, None, "/y", 2, None).await;
        assert!(r.is_err(), "duplicate domain must fail");
    }

    #[tokio::test]
    async fn set_php_version_round_trip() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "ex_cz", 1042).await;
        let id = HostingId::new_v7();
        insert(
            &pool,
            &id,
            "example.cz",
            suid,
            Some(PhpVersion::V8_3),
            "/x",
            1,
            None,
        )
        .await
        .expect("insert");

        // Switch to 8.4.
        let n = set_php_version(&pool, &id, Some(PhpVersion::V8_4), 100)
            .await
            .expect("update");
        assert_eq!(n, 1, "should update exactly one row");
        let got = get_by_id(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.php_version, Some(PhpVersion::V8_4));
        assert_eq!(got.updated_at, 100, "updated_at should be refreshed");

        // Setting to None is accepted at the DB level (service layer
        // is what blocks it).
        let n = set_php_version(&pool, &id, None, 200).await.expect("clear");
        assert_eq!(n, 1);
        let got = get_by_id(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.php_version, None);
    }

    #[tokio::test]
    async fn state_check_rejects_invalid() {
        let pool = open_memory().await.expect("open");
        let suid = fresh_user(&pool, "ex_cz", 1042).await;
        // Insert valid, then try to set an invalid state via direct SQL.
        let id = HostingId::new_v7();
        insert(&pool, &id, "example.cz", suid, None, "/x", 1, None)
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
        insert(&pool, &id, "example.cz", suid, None, "/x", 1, None)
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
        insert(&pool, &id, "example.cz", suid, None, "/x", 1, None)
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
        insert(&pool, &id, "example.cz", suid, None, "/x", 1, None)
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
        insert(&pool, &a, "a.cz", suid, Some(PhpVersion::V8_3), "/x", 1, None)
            .await
            .expect("ok");
        insert(&pool, &b, "b.cz", suid, None, "/y", 2, None)
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
        insert(&pool, &id, "example.cz", suid, None, "/x", 1, None)
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
