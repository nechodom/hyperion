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
    /// Worker's inbound-listener TLS SPKI pin (curl --pinnedpubkey form),
    /// reported on each heartbeat. `None` until the first heartbeat that
    /// carries it (or for nodes whose agent predates Block C). Warn-only
    /// today; the basis for `--pinnedpubkey` enforcement later — which is
    /// exactly why it is pinned trust-on-first-use and cleared only by
    /// re-enrollment / `node_reset_crypto`, like `resp_pubkey` below. A
    /// pin a heartbeat could overwrite would be no pin at all.
    pub tls_spki_pin: Option<String>,
    /// Base64 (no-pad) Ed25519 public key the node signs its RPC
    /// RESPONSES with (its own /etc/hyperion/node-rpc.key). `None` means
    /// this node's responses can't be verified — an agent predating
    /// response signing, or one that hasn't reported since being
    /// upgraded. PRESENCE is the capability gate; never `agent_version`,
    /// which is an unorderable git-describe string that lags a restart by
    /// a full heartbeat. Pinned trust-on-first-use and cleared only by
    /// re-enrollment (see `touch_last_seen` / `upsert_enrollment`).
    pub resp_pubkey: Option<String>,
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

/// Single source of truth for the SELECT list + its tuple shape: every
/// reader below goes through `COLS` and `to_row`, so adding a column can
/// only ever be a one-line-per-place change instead of two hand-kept
/// column lists that silently shift the destructuring when they drift.
const COLS: &str = "id, node_id, label, master_url, enrolled_at, last_seen_at, \
                    agent_version, public_ip, enrolled_via, secret_hash, tls_spki_pin, \
                    resp_pubkey";

type RawNode = (
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
    Option<String>,
    Option<String>,
);

fn to_row(r: RawNode) -> NodeRow {
    NodeRow {
        id: r.0,
        node_id: r.1,
        label: r.2,
        master_url: r.3,
        enrolled_at: r.4,
        last_seen_at: r.5,
        agent_version: r.6,
        public_ip: r.7,
        enrolled_via: r.8,
        secret_hash: r.9,
        tls_spki_pin: r.10,
        resp_pubkey: r.11,
    }
}

/// Look up a node by its public id. Used by the heartbeat verifier.
pub async fn get_by_node_id(
    pool: &SqlitePool,
    node_id: &str,
) -> Result<Option<NodeRow>, StateError> {
    let row: Option<RawNode> =
        sqlx::query_as(&format!("SELECT {COLS} FROM nodes WHERE node_id = ?"))
            .bind(node_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(to_row))
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

/// Insert a freshly-enrolled node, OR — when `node_id` already exists —
/// update it in place: re-mint its secret hash and refresh
/// label/master_url/agent_version/public_ip/last_seen. `enrolled_at` is
/// deliberately NOT touched on the update path so the original
/// enrollment time survives a re-enroll.
///
/// This backs idempotent (re-)enrollment (Block B): a box that proves
/// continuity (matching prior secret) or adopts a currently-free id
/// keeps its `node_id` instead of orphaning into a brand-new row. The
/// reuse-vs-fresh decision lives in the service layer; by the time we
/// get here `node_id` is already the EFFECTIVE id to write.
///
/// Both pinned crypto columns (`tls_spki_pin`, `resp_pubkey`) are
/// CLEARED on the update path. Enrollment is precisely the moment a
/// node's keys may legitimately change — reinstalled box, regenerated
/// TLS cert, fresh node-rpc.key — and the pins are trust-on-first-use
/// with refuse-on-change, so carrying stale ones across a re-enroll
/// would lock the node out permanently with no recovery short of
/// hand-editing the database. The caller re-pins straight after, from
/// the values in the enroll request (or on the next heartbeat).
pub async fn upsert_enrollment(
    pool: &SqlitePool,
    n: &NewNode,
    now: i64,
) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO nodes
           (node_id, label, master_url, enrolled_at, last_seen_at,
            agent_version, public_ip, enrolled_via, secret_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(node_id) DO UPDATE SET
              label         = excluded.label,
              master_url    = COALESCE(excluded.master_url, nodes.master_url),
              last_seen_at  = excluded.last_seen_at,
              agent_version = excluded.agent_version,
              public_ip     = excluded.public_ip,
              enrolled_via  = excluded.enrolled_via,
              secret_hash   = excluded.secret_hash,
              tls_spki_pin  = NULL,
              resp_pubkey   = NULL
           RETURNING id"#,
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
    let rows: Vec<RawNode> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM nodes ORDER BY enrolled_at DESC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(to_row).collect())
}

pub async fn touch_last_seen(
    pool: &SqlitePool,
    node_id: &str,
    now: i64,
    version: Option<&str>,
    tls_spki_pin: Option<&str>,
    resp_pubkey: Option<&str>,
) -> Result<(), StateError> {
    // BOTH pinned crypto columns are WRITE-ONCE, by the same rule:
    // `COALESCE(<column>, ?)` puts the STORED value first, so a
    // heartbeat can only ever FILL an empty column (trust-on-first-use)
    // and can never replace a value already on file. A heartbeat is
    // authenticated by the shared node secret alone, over a `curl -k`
    // channel, so a silent re-pin would mean that leaking that secret
    // (or landing a single forged heartbeat on-path) is enough to swap
    // in an attacker's response-signing key and forge every RPC response
    // afterwards — or to re-point tls_spki_pin at the attacker's own
    // cert, which would quietly defeat `--pinnedpubkey` enforcement the
    // moment an operator switches it on, and keep defeating it forever.
    // Re-pinning is therefore an explicit operator act: (re-)enrollment
    // and `node_reset_crypto` clear the columns, and the next report
    // re-pins whatever the box now presents.
    //
    // agent_version keeps the opposite COALESCE order on purpose — it is
    // a display string, not a trust anchor, so newest-wins is right and
    // omitting it just keeps the last known value.
    //
    // Detecting "the node reported a value that differs from the pinned
    // one" — the interesting security event — is the service layer's
    // job; it already holds the row from the secret check and can warn
    // or refuse. This statement just guarantees storage never quietly
    // rotates a trust anchor underneath it.
    sqlx::query(
        "UPDATE nodes SET last_seen_at = ?,
                          agent_version = COALESCE(?, agent_version),
                          tls_spki_pin  = COALESCE(tls_spki_pin, ?),
                          resp_pubkey   = COALESCE(resp_pubkey, ?)
         WHERE node_id = ?",
    )
    .bind(now)
    .bind(version)
    .bind(tls_spki_pin)
    .bind(resp_pubkey)
    .bind(node_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Pin a node's Ed25519 response-signing pubkey, but only while the
/// column is still empty. Returns `true` when THIS call adopted the key
/// — the trust-on-first-use moment worth audit-logging — and `false`
/// when a key was already on file (including when it's the identical
/// key, or when `node_id` doesn't exist).
///
/// The check and the write are one statement, so the TOFU decision is a
/// real compare-and-set: two heartbeats arriving together from a node
/// that just got upgraded cannot both read "empty" and pin different
/// keys. Callers that care about a MISMATCH compare the reported key
/// against what `get_by_node_id` handed them and apply policy there;
/// this fn keeps the pinned key rather than erroring, because "the node
/// reported a different key" is a trust decision, not a storage fault.
pub async fn set_resp_pubkey_if_absent(
    pool: &SqlitePool,
    node_id: &str,
    resp_pubkey: &str,
) -> Result<bool, StateError> {
    let n =
        sqlx::query("UPDATE nodes SET resp_pubkey = ? WHERE node_id = ? AND resp_pubkey IS NULL")
            .bind(resp_pubkey)
            .bind(node_id)
            .execute(pool)
            .await?
            .rows_affected();
    Ok(n > 0)
}

/// Mark a node as drained — auto-placer + create wizard will skip
/// it on the next dispatch. Idempotent: re-draining updates the
/// timestamp + reason but doesn't error.
pub async fn drain(
    pool: &SqlitePool,
    node_id: &str,
    reason: &str,
    drained_by: i64,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO node_drain (node_id, drained_at, reason, drained_by)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(node_id) DO UPDATE SET
              drained_at = excluded.drained_at,
              reason     = excluded.reason,
              drained_by = excluded.drained_by"#,
    )
    .bind(node_id)
    .bind(now)
    .bind(reason)
    .bind(drained_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// Lift the drain flag. No-op when the node wasn't drained.
pub async fn undrain(pool: &SqlitePool, node_id: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM node_drain WHERE node_id = ?")
        .bind(node_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Set of currently-drained node ids. Cheap lookup the auto-
/// placer + create wizard call before placing new hostings.
pub async fn drained_set(
    pool: &SqlitePool,
) -> Result<std::collections::HashSet<String>, StateError> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT node_id FROM node_drain")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(n,)| n).collect())
}

/// Delete a node row + cascade its drain marker. Caller is
/// responsible for the policy decision ("there are still hostings
/// here, refuse" vs "force-detach") — this fn just runs the SQL.
/// Returns `true` when the row existed and was removed.
///
/// Hostings whose `node_id` referenced this row are NOT cascaded;
/// they get orphaned (node_id stays set, but find_hosting_anywhere
/// will no longer route to a node that doesn't exist). The Service
/// layer optionally NULLs them when force-removing.
pub async fn delete(pool: &SqlitePool, node_id: &str) -> Result<bool, StateError> {
    let mut tx = pool.begin().await?;
    // Drop the drain marker first to keep the schema consistent.
    sqlx::query("DELETE FROM node_drain WHERE node_id = ?")
        .bind(node_id)
        .execute(&mut *tx)
        .await?;
    let n = sqlx::query("DELETE FROM nodes WHERE node_id = ?")
        .bind(node_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(n > 0)
}

/// Count hostings currently routed to this node — used by the
/// node-removal flow's "are you sure?" gate. Excludes trashed
/// rows since those are headed for hard-delete anyway.
pub async fn count_hostings_on_node(pool: &SqlitePool, node_id: &str) -> Result<i64, StateError> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM hostings WHERE node_id = ? AND state != 'trashed'")
            .bind(node_id)
            .fetch_one(pool)
            .await?;
    Ok(n)
}

/// Re-point every (non-trashed) hosting routed to `from_node_id` over to
/// `to_node_id`. Block B orphan adoption: when a box re-enrolled under a
/// new id (so its hostings still carry the dead old id), the operator
/// re-points them to the live id of the SAME physical box so the master
/// routes management RPCs there again. Returns the number of rows moved.
///
/// Trashed rows are left alone (headed for purge). The caller is
/// responsible for the policy check that `to_node_id` is a live node and
/// genuinely hosts these sites' files.
pub async fn reassign_hostings(
    pool: &SqlitePool,
    from_node_id: &str,
    to_node_id: &str,
) -> Result<u64, StateError> {
    let n = sqlx::query("UPDATE hostings SET node_id = ? WHERE node_id = ? AND state != 'trashed'")
        .bind(to_node_id)
        .bind(from_node_id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n)
}

/// Rename a node's display label without touching its `node_id`
/// (the immutable enrollment identifier). The label is what shows
/// up in dashboard dropdowns, the test-domain template token, the
/// /install page, and so on — operators want to rename a freshly
/// enrolled `host123.local` to "Frankfurt prod" without re-doing
/// the enrollment dance.
///
/// Returns `true` when the row existed and was updated.
pub async fn set_label(pool: &SqlitePool, node_id: &str, label: &str) -> Result<bool, StateError> {
    let n = sqlx::query("UPDATE nodes SET label = ? WHERE node_id = ?")
        .bind(label)
        .bind(node_id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n > 0)
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
        touch_last_seen(
            &pool,
            "n1",
            200,
            Some("0.2.0"),
            Some("sha256//abc="),
            Some("pub-a"),
        )
        .await
        .expect("touch");
        let l = list(&pool).await.expect("list");
        assert_eq!(l[0].last_seen_at, 200);
        assert_eq!(l[0].agent_version, "0.2.0");
        assert_eq!(l[0].tls_spki_pin.as_deref(), Some("sha256//abc="));
        assert_eq!(l[0].resp_pubkey.as_deref(), Some("pub-a"));
        // Omitting either on a later heartbeat must NOT null it (COALESCE).
        touch_last_seen(&pool, "n1", 300, Some("0.2.0"), None, None)
            .await
            .expect("touch2");
        let l2 = list(&pool).await.expect("list2");
        assert_eq!(l2[0].tls_spki_pin.as_deref(), Some("sha256//abc="));
        assert_eq!(l2[0].resp_pubkey.as_deref(), Some("pub-a"));
        // A heartbeat reporting DIFFERENT pinned crypto must not re-key
        // or re-pin the node — the shared node secret alone cannot
        // rotate either trust anchor. Both columns are write-once.
        touch_last_seen(
            &pool,
            "n1",
            400,
            Some("0.2.0"),
            Some("sha256//EVIL="),
            Some("pub-EVIL"),
        )
        .await
        .expect("touch3");
        let l3 = list(&pool).await.expect("list3");
        assert_eq!(
            l3[0].tls_spki_pin.as_deref(),
            Some("sha256//abc="),
            "heartbeat must never overwrite a pinned TLS SPKI pin — one \
             forged heartbeat would otherwise re-point cert pinning at \
             the attacker's cert, permanently"
        );
        assert_eq!(
            l3[0].resp_pubkey.as_deref(),
            Some("pub-a"),
            "heartbeat must never overwrite a pinned response key"
        );
        // ...and last_seen/agent_version still update on that same
        // heartbeat: refusing the re-pin must not make a healthy node
        // look offline.
        assert_eq!(l3[0].last_seen_at, 400);
    }

    /// A node whose TLS pin column is still empty must be able to pin on
    /// its FIRST report — write-once is trust-on-first-use, not
    /// write-never. Separate from the test above so a regression that
    /// makes the column permanently unwritable can't hide behind it.
    #[tokio::test]
    async fn first_heartbeat_pins_tls_pin() {
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
        // Pre-pin heartbeat from an agent that reports no cert yet.
        touch_last_seen(&pool, "n1", 200, None, None, None)
            .await
            .expect("touch1");
        let row = get_by_node_id(&pool, "n1").await.expect("get").unwrap();
        assert_eq!(row.tls_spki_pin, None);
        // First report carrying a pin adopts it.
        touch_last_seen(&pool, "n1", 300, None, Some("sha256//first="), None)
            .await
            .expect("touch2");
        let row = get_by_node_id(&pool, "n1").await.expect("get").unwrap();
        assert_eq!(row.tls_spki_pin.as_deref(), Some("sha256//first="));
    }

    #[tokio::test]
    async fn set_resp_pubkey_if_absent_is_write_once() {
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
        let first = set_resp_pubkey_if_absent(&pool, "n1", "pub-a")
            .await
            .expect("set");
        assert!(first, "empty column → this call adopted the key");
        let again = set_resp_pubkey_if_absent(&pool, "n1", "pub-b")
            .await
            .expect("set2");
        assert!(!again, "a key is already on file → refused");
        let row = get_by_node_id(&pool, "n1").await.expect("get").unwrap();
        assert_eq!(row.resp_pubkey.as_deref(), Some("pub-a"));
        // Unknown node is a no-op, not an error.
        let missing = set_resp_pubkey_if_absent(&pool, "nope", "pub-c")
            .await
            .expect("set3");
        assert!(!missing);
    }

    #[tokio::test]
    async fn upsert_reuses_id_and_preserves_enrolled_at() {
        let pool = open_memory().await.expect("open");
        let mut n = NewNode {
            node_id: "n-reuse".into(),
            label: "first".into(),
            master_url: Some("https://m1".into()),
            agent_version: "0.1.0".into(),
            public_ip: Some("1.1.1.1".into()),
            enrolled_via_hash: "tok1".into(),
            secret_hash: "hash-a".into(),
        };
        let id1 = upsert_enrollment(&pool, &n, 100).await.expect("insert");
        // Pin both crypto columns as a live node would, so the re-enroll
        // below can prove they get cleared.
        touch_last_seen(
            &pool,
            "n-reuse",
            200,
            None,
            Some("sha256//old="),
            Some("pub-old"),
        )
        .await
        .expect("pin");
        // Re-enroll the SAME node_id with a new secret + fields at a later time.
        n.label = "renamed".into();
        n.secret_hash = "hash-b".into();
        n.public_ip = Some("2.2.2.2".into());
        let id2 = upsert_enrollment(&pool, &n, 500).await.expect("upsert");
        assert_eq!(id1, id2, "same row id — reused, not a new row");
        let l = list(&pool).await.expect("list");
        assert_eq!(l.len(), 1, "no duplicate row");
        let row = get_by_node_id(&pool, "n-reuse")
            .await
            .expect("get")
            .unwrap();
        assert_eq!(
            row.enrolled_at, 100,
            "enrolled_at preserved across re-enroll"
        );
        assert_eq!(row.last_seen_at, 500, "last_seen bumped");
        assert_eq!(row.secret_hash, "hash-b", "secret re-minted");
        assert_eq!(row.label, "renamed");
        assert_eq!(row.public_ip.as_deref(), Some("2.2.2.2"));
        // Re-enrollment is the ONLY thing that clears the pinned crypto:
        // a reinstalled box legitimately brings a new cert + new
        // node-rpc.key, and keeping the old pins would lock it out for
        // good under refuse-on-change.
        assert_eq!(row.tls_spki_pin, None, "stale TLS pin cleared");
        assert_eq!(row.resp_pubkey, None, "stale response pubkey cleared");
        // ...and the column is free for the fresh key to be pinned again.
        assert!(set_resp_pubkey_if_absent(&pool, "n-reuse", "pub-new")
            .await
            .expect("re-pin"));
    }

    #[tokio::test]
    async fn reassign_moves_matching_hostings() {
        let pool = open_memory().await.expect("open");
        // FK target for hostings.system_user_id.
        sqlx::query(
            "INSERT INTO system_users (id, name, uid, home_dir, created_at) \
             VALUES (1, 'u', 1001, '/home/u', 0)",
        )
        .execute(&pool)
        .await
        .expect("user");
        for (id, domain, node) in [
            ("h1", "a.test", "old"),
            ("h2", "b.test", "old"),
            ("h3", "c.test", "keep"),
        ] {
            sqlx::query(
                "INSERT INTO hostings \
                 (id, domain, state, system_user_id, root_dir, created_at, updated_at, node_id) \
                 VALUES (?, ?, 'active', 1, ?, 0, 0, ?)",
            )
            .bind(id)
            .bind(domain)
            .bind(format!("/srv/{id}"))
            .bind(node)
            .execute(&pool)
            .await
            .expect("insert hosting");
        }
        let moved = reassign_hostings(&pool, "old", "new")
            .await
            .expect("reassign");
        assert_eq!(moved, 2, "only the two 'old' rows move");
        assert_eq!(count_hostings_on_node(&pool, "old").await.expect("c"), 0);
        assert_eq!(count_hostings_on_node(&pool, "new").await.expect("c"), 2);
        assert_eq!(
            count_hostings_on_node(&pool, "keep").await.expect("c"),
            1,
            "unrelated node untouched"
        );
    }

    #[tokio::test]
    async fn upsert_adopts_free_id() {
        // Adopting a node_id that doesn't exist yet == a plain insert.
        let pool = open_memory().await.expect("open");
        let n = NewNode {
            node_id: "adopt-me".into(),
            label: "l".into(),
            master_url: None,
            agent_version: "0.1.0".into(),
            public_ip: None,
            enrolled_via_hash: "t".into(),
            secret_hash: "h".into(),
        };
        upsert_enrollment(&pool, &n, 100).await.expect("adopt");
        let row = get_by_node_id(&pool, "adopt-me").await.expect("get");
        assert!(row.is_some());
    }
}
