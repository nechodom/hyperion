//! `api_keys` — bearer credentials for the remote management API
//! (`/api/v1`). Mirrors [`crate::web_sessions`]: a master-only ledger
//! that the agent owns and the web tier reaches over RPC.
//!
//! An API key IS a scoped capability bundle. It carries a [`CapSet`]
//! bitmask + a tenant `scope_all` flag, both **clamped at creation to
//! ≤ the owning web user's effective caps**, so the same RBAC gates the
//! browser UI uses (`ctx.can(cap)`, `require_hosting_access`) apply
//! unchanged. Revoking/down-scoping the owner can never be *exceeded*
//! by a key it minted.
//!
//! Only the SHA-256 of the raw key is stored. The plaintext
//! (`hyp_<32 bytes base62>`, CSPRNG) is returned **once** from
//! [`create`] and is otherwise unrecoverable.
//!
//! See `docs/superpowers/specs/2026-06-30-remote-management-api-design.md`.

use crate::capabilities::CapSet;
use crate::db::StateError;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

/// Human-facing prefix on every raw key (`hyp_…`). Used to recognise a
/// Bearer token as an API key + as the stored display prefix.
pub const KEY_PREFIX: &str = "hyp_";

/// Number of CSPRNG bytes packed into the base62 body of a raw key.
const KEY_BODY_BYTES: usize = 32;

/// How many leading characters of the raw key to keep for display
/// (e.g. `hyp_a1b2c3d4`). Display-only — never enough entropy to be a
/// credential on its own.
const DISPLAY_PREFIX_LEN: usize = 12;

/// Base62 alphabet for the random key body (URL- and shell-safe, no
/// ambiguous separators).
const BASE62: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// A row from `api_keys` projected for display. **Never** carries the
/// raw key or its hash — only the safe-to-show prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRow {
    pub id: i64,
    pub key_prefix: String,
    pub label: String,
    pub owner_user_id: i64,
    pub caps: u64,
    pub scope_all: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<i64>,
}

/// The resolved identity behind a presented key: who owns it + what it
/// can do. Returned by [`resolve_active`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKey {
    pub id: i64,
    pub label: String,
    pub owner_user_id: i64,
    pub caps: u64,
    pub scope_all: bool,
}

/// Outcome of [`create`]: the row id + the **raw** key, shown to the
/// operator exactly once.
#[derive(Debug, Clone)]
pub struct CreatedKey {
    pub id: i64,
    pub raw_key: String,
    pub key_prefix: String,
}

/// SHA-256 (hex) of a raw key. The same function hashes a key for
/// storage (here) and for lookup (the Bearer extractor), so they must
/// stay byte-identical.
pub fn hash_key(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    hex::encode(digest)
}

/// Generate a fresh `hyp_<32 bytes base62>` key from the OS CSPRNG.
fn generate_raw_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; KEY_BODY_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut body = String::with_capacity(KEY_BODY_BYTES);
    for b in bytes {
        // Map each random byte into the base62 alphabet. The modulo bias
        // is negligible for a credential of this length (the entropy
        // floor is 32 bytes = 256 bits; even with bias the body keeps
        // well over 180 bits).
        body.push(BASE62[(b as usize) % 62] as char);
    }
    format!("{KEY_PREFIX}{body}")
}

/// Mint a new API key owned by `owner_user_id`.
///
/// `requested_caps` / `requested_scope_all` are what the operator asked
/// for; they are **clamped to the owner's effective caps**
/// (`owner_caps` / `owner_scope_all`) before storage so a key can never
/// out-grant its owner. The raw key is generated here, hashed with
/// SHA-256, and only the hash + display prefix are persisted. The
/// plaintext is returned in [`CreatedKey::raw_key`] and is otherwise
/// unrecoverable.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &SqlitePool,
    label: &str,
    owner_user_id: i64,
    requested_caps: CapSet,
    requested_scope_all: bool,
    owner_caps: CapSet,
    owner_scope_all: bool,
    created_at: i64,
    expires_at: Option<i64>,
) -> Result<CreatedKey, StateError> {
    // Clamp: caps &= owner_caps, scope_all &= owner_scope_all.
    let clamped_caps = CapSet::from_bits(requested_caps.bits() & owner_caps.bits());
    let clamped_scope_all = requested_scope_all && owner_scope_all;

    let raw_key = generate_raw_key();
    let key_hash = hash_key(&raw_key);
    let key_prefix: String = raw_key.chars().take(DISPLAY_PREFIX_LEN).collect();

    let id = sqlx::query(
        r#"INSERT INTO api_keys
            (key_hash, key_prefix, label, owner_user_id, caps, scope_all,
             created_at, last_used_at, expires_at, revoked_at, revoked_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL)"#,
    )
    .bind(&key_hash)
    .bind(&key_prefix)
    .bind(label)
    .bind(owner_user_id)
    .bind(clamped_caps.bits() as i64)
    .bind(clamped_scope_all as i64)
    .bind(created_at)
    .bind(expires_at)
    .execute(pool)
    .await?
    .last_insert_rowid();

    Ok(CreatedKey {
        id,
        raw_key,
        key_prefix,
    })
}

/// Resolve a presented key by its SHA-256 hash, returning its identity
/// only if the key is **active**: present, not revoked, not expired.
///
/// `now` is the current unix time; a key with `expires_at <= now` is
/// rejected. Caller is expected to hash the raw bearer token with
/// [`hash_key`] first.
pub async fn resolve_active(
    pool: &SqlitePool,
    key_hash: &str,
    now: i64,
) -> Result<Option<ResolvedKey>, StateError> {
    let row: Option<(i64, String, i64, i64, i64, Option<i64>)> = sqlx::query_as(
        r#"SELECT id, label, owner_user_id, caps, scope_all, expires_at
             FROM api_keys
            WHERE key_hash = ?
              AND revoked_at IS NULL"#,
    )
    .bind(key_hash)
    .fetch_optional(pool)
    .await?;
    Ok(
        row.and_then(|(id, label, owner_user_id, caps, scope_all, expires_at)| {
            // Expired keys are inert even though the row is still present.
            if let Some(exp) = expires_at {
                if exp <= now {
                    return None;
                }
            }
            Some(ResolvedKey {
                id,
                label,
                owner_user_id,
                caps: caps as u64,
                scope_all: scope_all != 0,
            })
        }),
    )
}

/// Newest-first list of every key (revoked + expired included), for the
/// admin Settings card. Never returns the hash or the raw key.
pub async fn list(pool: &SqlitePool, limit: i64) -> Result<Vec<ApiKeyRow>, StateError> {
    let limit = limit.clamp(1, 500);
    let rows: Vec<(
        i64,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    )> = sqlx::query_as(
        r#"SELECT id, key_prefix, label, owner_user_id, caps, scope_all,
                  created_at, last_used_at, expires_at, revoked_at, revoked_by
             FROM api_keys
            ORDER BY created_at DESC
            LIMIT ?"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                key_prefix,
                label,
                owner_user_id,
                caps,
                scope_all,
                created_at,
                last_used_at,
                expires_at,
                revoked_at,
                revoked_by,
            )| ApiKeyRow {
                id,
                key_prefix,
                label,
                owner_user_id,
                caps: caps as u64,
                scope_all: scope_all != 0,
                created_at,
                last_used_at,
                expires_at,
                revoked_at,
                revoked_by,
            },
        )
        .collect())
}

/// Stamp `last_used_at` for the key with this hash. Best-effort: the
/// caller fires it on a successful request and ignores the result
/// (a failed touch must never fail the request).
pub async fn touch(pool: &SqlitePool, key_hash: &str, now: i64) -> Result<(), StateError> {
    sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?")
        .bind(now)
        .bind(key_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Flip `revoked_at` for one key by id. No-op (returns false) if already
/// revoked or unknown. After this, [`resolve_active`] rejects the key.
pub async fn revoke(
    pool: &SqlitePool,
    id: i64,
    revoked_by: i64,
    now: i64,
) -> Result<bool, StateError> {
    let n = sqlx::query(
        "UPDATE api_keys SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(revoked_by)
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capability;
    use crate::db::open_memory;

    async fn fresh() -> SqlitePool {
        let p = open_memory().await.expect("open mem");
        // api_keys.owner_user_id references web_users(id); seed one.
        sqlx::query(
            r#"INSERT INTO web_users
                (id, username, email, password_hash, role, totp_required,
                 locked, failed_logins, created_at, updated_at)
               VALUES (1, 'kevin', 'k@example.com', 'x', 'admin', 0,
                       0, 0, 0, 0)"#,
        )
        .execute(&p)
        .await
        .expect("seed user");
        p
    }

    /// Raw key has the `hyp_` prefix and stable SHA-256 hashing.
    #[test]
    fn key_format_and_hash_are_stable() {
        let raw = generate_raw_key();
        assert!(
            raw.starts_with(KEY_PREFIX),
            "raw key must carry hyp_ prefix"
        );
        // hyp_ (4) + 32 base62 chars.
        assert_eq!(raw.len(), KEY_PREFIX.len() + KEY_BODY_BYTES);
        // Hash is deterministic + 64 hex chars (SHA-256).
        let h1 = hash_key(&raw);
        let h2 = hash_key(&raw);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        // A different key hashes differently.
        assert_ne!(hash_key("hyp_other"), h1);
        // Known-answer: SHA-256 of the literal "hyp_" empty body sanity.
        assert_eq!(
            hash_key("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// create stores only the hash; the row never exposes raw/hash, and
    /// resolve_active accepts a live key.
    #[tokio::test]
    async fn create_then_resolve_active() {
        let p = fresh().await;
        let owner = CapSet::all();
        let want = [Capability::HostingView, Capability::NodesView]
            .into_iter()
            .collect::<CapSet>();
        let created = create(&p, "ci", 1, want, false, owner, true, 1000, None)
            .await
            .expect("create");
        assert!(created.raw_key.starts_with(KEY_PREFIX));

        let resolved = resolve_active(&p, &hash_key(&created.raw_key), 1500)
            .await
            .expect("resolve")
            .expect("active");
        assert_eq!(resolved.owner_user_id, 1);
        assert_eq!(resolved.caps, want.bits());
        assert!(!resolved.scope_all);

        // The list view never leaks the hash/raw — only the prefix.
        let rows = list(&p, 10).await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key_prefix, created.key_prefix);
        assert!(created.raw_key.starts_with(&rows[0].key_prefix));
    }

    /// resolve_active rejects a revoked key.
    #[tokio::test]
    async fn resolve_active_rejects_revoked() {
        let p = fresh().await;
        let created = create(
            &p,
            "k",
            1,
            CapSet::all(),
            true,
            CapSet::all(),
            true,
            100,
            None,
        )
        .await
        .expect("create");
        let hash = hash_key(&created.raw_key);
        assert!(resolve_active(&p, &hash, 200).await.expect("r1").is_some());
        assert!(revoke(&p, created.id, 1, 300).await.expect("revoke"));
        assert!(resolve_active(&p, &hash, 400).await.expect("r2").is_none());
        // Second revoke is a no-op (idempotent).
        assert!(!revoke(&p, created.id, 1, 500).await.expect("revoke-2"));
    }

    /// resolve_active rejects an expired key (and accepts it before expiry).
    #[tokio::test]
    async fn resolve_active_rejects_expired() {
        let p = fresh().await;
        let created = create(
            &p,
            "k",
            1,
            CapSet::all(),
            true,
            CapSet::all(),
            true,
            100,
            Some(1000),
        )
        .await
        .expect("create");
        let hash = hash_key(&created.raw_key);
        // Before expiry → live.
        assert!(resolve_active(&p, &hash, 999)
            .await
            .expect("live")
            .is_some());
        // At/after expiry → inert.
        assert!(resolve_active(&p, &hash, 1000)
            .await
            .expect("exp")
            .is_none());
        assert!(resolve_active(&p, &hash, 2000)
            .await
            .expect("exp")
            .is_none());
    }

    /// caps + scope_all are clamped to the owner at creation — a key can
    /// never out-grant its owner.
    #[tokio::test]
    async fn caps_are_clamped_to_owner() {
        let p = fresh().await;
        // Owner only holds HostingView (no NodesView, no scope_all).
        let owner = [Capability::HostingView].into_iter().collect::<CapSet>();
        // But the operator asks for HostingView + NodesView + scope_all.
        let want = [Capability::HostingView, Capability::NodesView]
            .into_iter()
            .collect::<CapSet>();
        let created = create(&p, "k", 1, want, true, owner, false, 100, None)
            .await
            .expect("create");
        let resolved = resolve_active(&p, &hash_key(&created.raw_key), 200)
            .await
            .expect("resolve")
            .expect("active");
        let got = CapSet::from_bits(resolved.caps);
        assert!(got.contains(Capability::HostingView), "kept owner's cap");
        assert!(
            !got.contains(Capability::NodesView),
            "must NOT grant a cap the owner lacks"
        );
        assert!(
            !resolved.scope_all,
            "scope_all clamped off (owner lacked it)"
        );
    }

    /// touch updates last_used_at; missing hash is a no-op.
    #[tokio::test]
    async fn touch_updates_last_used() {
        let p = fresh().await;
        let created = create(
            &p,
            "k",
            1,
            CapSet::all(),
            true,
            CapSet::all(),
            true,
            100,
            None,
        )
        .await
        .expect("create");
        let hash = hash_key(&created.raw_key);
        assert!(list(&p, 10).await.expect("l")[0].last_used_at.is_none());
        touch(&p, &hash, 555).await.expect("touch");
        assert_eq!(
            list(&p, 10).await.expect("l2")[0].last_used_at,
            Some(555),
            "last_used_at stamped"
        );
        // A touch on an unknown hash must not error.
        touch(&p, "deadbeef", 999).await.expect("touch-unknown");
    }
}
