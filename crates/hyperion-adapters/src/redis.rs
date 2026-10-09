//! Node-wide memory policy for the local `redis-server`.
//!
//! Redis on a Hyperion node is the WordPress object cache and nothing else
//! (one ACL user + DB slot per site, see `redis_ensure_acl`). Debian ships it
//! with no `maxmemory` and the `noeviction` policy — right for a database,
//! wrong for a cache: it grows with every site until the box swaps, and once
//! something caps it, `noeviction` turns "cache full" into write errors that
//! the Redis Object Cache plugin surfaces as a broken site.
//!
//! So: a cap sized to the box, and least-recently-used eviction across all
//! keys. Applied only where the operator left the defaults — an explicit
//! `maxmemory` or policy in redis.conf is theirs and is never touched.

use crate::{cmd, AdapterError};

const MIB: u64 = 1024 * 1024;

/// One sixteenth of RAM, at least 64 MiB, at most 512 MiB. Object caches
/// are small (a busy WooCommerce site rarely passes 100 MiB), and the
/// memory is better spent on PHP workers and the database.
pub fn cache_maxmemory_bytes(mem_total_kib: u64) -> u64 {
    let ram = mem_total_kib.saturating_mul(1024);
    (ram / 16).clamp(64 * MIB, 512 * MIB)
}

/// The `CONFIG SET`s to issue, given what the server reports now.
pub fn plan(
    current_maxmemory: u64,
    current_policy: &str,
    mem_total_kib: u64,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if current_maxmemory == 0 {
        out.push((
            "maxmemory",
            cache_maxmemory_bytes(mem_total_kib).to_string(),
        ));
    }
    if current_policy.trim() == "noeviction" {
        out.push(("maxmemory-policy", "allkeys-lru".to_string()));
    }
    out
}

/// `redis-cli CONFIG GET <param>` prints the name, then the value.
fn parse_config_get(out: &str) -> Option<String> {
    out.lines().nth(1).map(|v| v.trim().to_string())
}

async fn config_get(param: &str) -> Result<String, AdapterError> {
    let out = cmd::run("/usr/bin/redis-cli", &["CONFIG", "GET", param]).await?;
    parse_config_get(&out)
        .ok_or_else(|| AdapterError::Other(format!("redis CONFIG GET {param}: {out:?}")))
}

/// Apply [`plan`] to the running server and persist it to redis.conf.
/// Returns whether anything changed. Live first (`CONFIG SET`), so the cap
/// holds even if the rewrite fails — that only costs persistence across a
/// Redis restart, and is logged.
pub async fn ensure_cache_memory_policy(mem_total_kib: u64) -> Result<bool, AdapterError> {
    // An unparsable answer counts as "set": never overwrite what we cannot read.
    let maxmemory: u64 = config_get("maxmemory").await?.parse().unwrap_or(1);
    let policy = config_get("maxmemory-policy").await?;
    let steps = plan(maxmemory, &policy, mem_total_kib);
    if steps.is_empty() {
        return Ok(false);
    }
    for (param, value) in &steps {
        let out = cmd::run("/usr/bin/redis-cli", &["CONFIG", "SET", param, value]).await?;
        if out.trim() != "OK" {
            return Err(AdapterError::Other(format!(
                "redis CONFIG SET {param} refused: {}",
                out.trim()
            )));
        }
    }
    match cmd::run("/usr/bin/redis-cli", &["CONFIG", "REWRITE"]).await {
        Ok(out) if out.trim() == "OK" => {}
        Ok(out) => tracing::warn!(
            reply = %out.trim(),
            "redis CONFIG REWRITE refused; memory policy is live but not persisted"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "redis CONFIG REWRITE failed; memory policy is live but not persisted"
        ),
    }
    Ok(true)
}

/// `MemTotal` from /proc/meminfo, in KiB (0 when unreadable).
pub async fn mem_total_kib() -> u64 {
    tokio::fs::read_to_string("/proc/meminfo")
        .await
        .ok()
        .and_then(|m| {
            m.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_scales_with_ram_within_bounds() {
        assert_eq!(cache_maxmemory_bytes(512 * 1024), 64 * MIB); // 512 MiB box
        assert_eq!(cache_maxmemory_bytes(4 * 1024 * 1024), 256 * MIB); // 4 GiB
        assert_eq!(cache_maxmemory_bytes(64 * 1024 * 1024), 512 * MIB); // 64 GiB
        assert_eq!(cache_maxmemory_bytes(0), 64 * MIB);
    }

    #[test]
    fn only_the_defaults_are_replaced() {
        let ram = 4 * 1024 * 1024;
        assert_eq!(
            plan(0, "noeviction", ram),
            vec![
                ("maxmemory", (256 * MIB).to_string()),
                ("maxmemory-policy", "allkeys-lru".to_string())
            ]
        );
        // The operator's own cap and policy are left alone.
        assert!(plan(100 * MIB, "volatile-lru", ram).is_empty());
        assert_eq!(plan(100 * MIB, "noeviction", ram).len(), 1);
    }

    #[test]
    fn config_get_reply_is_parsed() {
        assert_eq!(parse_config_get("maxmemory\n0\n").as_deref(), Some("0"));
        assert_eq!(
            parse_config_get("maxmemory-policy\nnoeviction\n").as_deref(),
            Some("noeviction")
        );
        assert_eq!(parse_config_get(""), None);
    }
}
