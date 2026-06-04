//! Tiny in-process per-IP token-bucket rate limiter.
//!
//! Why not `tower-governor` or another crate? The traffic envelope on
//! the endpoints we want to protect is *tiny*:
//!
//!   - `/api/enroll`   — one POST per node per lifetime.
//!   - `/api/heartbeat` — one POST per node per minute.
//!   - `/settings/email-test` — one POST per operator click.
//!
//! For that volume a 50-line in-memory map is fine, has zero new deps,
//! and avoids the tower-layer composition headaches when these
//! handlers also need to read state. The threat model is:
//!
//!   - keep an attacker from filling the audit log with 50k bad
//!     enrollment attempts per second,
//!   - prevent /api/heartbeat from being a probe vector for
//!     node-id enumeration (combined with the timing-leak fix on
//!     the service side),
//!   - block /settings/email-test from being abused as an open
//!     relay or address enumerator.
//!
//! This is NOT a substitute for a real WAF / nginx-level limit —
//! operators with hostile internet exposure should ALSO front the
//! master with cloudflare / nginx rate-limit. This is the second
//! layer of defence inside the app.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Token bucket: refill `capacity` tokens over `refill_period`. Cost
/// of each request is 1 token. When tokens hit 0 the request is
/// rejected with HTTP 429.
#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    pub capacity: u32,
    pub refill_period: Duration,
}

impl Bucket {
    /// "N requests per minute". Common shape for our endpoints.
    pub const fn per_minute(capacity: u32) -> Self {
        Bucket {
            capacity,
            refill_period: Duration::from_secs(60),
        }
    }
}

struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

/// Per-(endpoint, ip) bucket state.
///
/// `endpoint` is a static string ("enroll", "heartbeat", "email-test")
/// so we can reason about the keyspace; `IpAddr` so we group v4 and
/// v6 callers consistently.
pub struct RateLimiter {
    inner: Mutex<HashMap<(&'static str, IpAddr), BucketState>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether the next request from `ip` to `endpoint` is
    /// allowed under `bucket`. Returns true if the request consumes a
    /// token (allowed); false otherwise (limit exceeded).
    pub fn check(&self, endpoint: &'static str, ip: IpAddr, bucket: Bucket) -> bool {
        // A poisoned lock is recoverable — recover with the inner
        // map. Better to keep limiting (possibly stale) than to
        // panic and take down the whole web process.
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        // Lazy cleanup: when the map grows beyond 4096 entries, drop
        // any state whose tokens are already full + last_refill is
        // older than 10 min. Bounds memory on adversarial unique-IP
        // flood without a background task.
        if guard.len() > 4096 {
            let stale_cutoff = now - Duration::from_secs(600);
            guard.retain(|_, s| s.last_refill > stale_cutoff);
        }
        let state = guard
            .entry((endpoint, ip))
            .or_insert(BucketState {
                tokens: bucket.capacity as f64,
                last_refill: now,
            });
        // Refill: capacity tokens over refill_period seconds → rate
        // = capacity / refill_period.
        let elapsed = now.saturating_duration_since(state.last_refill).as_secs_f64();
        let rate = bucket.capacity as f64 / bucket.refill_period.as_secs_f64();
        state.tokens = (state.tokens + elapsed * rate).min(bucket.capacity as f64);
        state.last_refill = now;
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn first_burst_within_capacity_passes() {
        let rl = RateLimiter::new();
        let b = Bucket::per_minute(5);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..5 {
            assert!(rl.check("test", ip, b));
        }
    }

    #[test]
    fn over_capacity_is_refused() {
        let rl = RateLimiter::new();
        let b = Bucket::per_minute(3);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.check("e", ip, b));
        assert!(rl.check("e", ip, b));
        assert!(rl.check("e", ip, b));
        assert!(!rl.check("e", ip, b), "4th must be refused");
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let rl = RateLimiter::new();
        let b = Bucket::per_minute(1);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let b_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        assert!(rl.check("e", a, b));
        assert!(!rl.check("e", a, b)); // a exhausted
        assert!(rl.check("e", b_ip, b)); // b still has its own bucket
    }

    #[test]
    fn separate_endpoints_have_separate_buckets() {
        let rl = RateLimiter::new();
        let b = Bucket::per_minute(1);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert!(rl.check("enroll", ip, b));
        assert!(!rl.check("enroll", ip, b));
        // Different endpoint, same IP — separate bucket.
        assert!(rl.check("heartbeat", ip, b));
    }

    #[test]
    fn refill_grants_more_tokens_over_time() {
        let rl = RateLimiter::new();
        // 6 tokens per minute → 1 token per 10s.
        let b = Bucket {
            capacity: 6,
            refill_period: Duration::from_secs(60),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        for _ in 0..6 {
            assert!(rl.check("e", ip, b));
        }
        assert!(!rl.check("e", ip, b));
        // Manually backdate last_refill 11s into the past (just
        // enough for 1 token to have refilled).
        {
            let mut g = rl.inner.lock().unwrap();
            let s = g.get_mut(&("e", ip)).unwrap();
            s.last_refill -= Duration::from_secs(11);
        }
        assert!(rl.check("e", ip, b), "should have refilled at least 1 token");
    }
}
