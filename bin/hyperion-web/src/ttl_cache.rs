//! One cached value with a time-to-live, loaded single-flight.
//!
//! The panel has a handful of answers that are expensive to compute (a
//! cluster fan-out, a local RPC on every remote dispatch, a curl to an
//! outside service), are the same for every caller, and are asked for far
//! more often than they change. Before this, each such spot hand-rolled a
//! `Mutex<Option<(Instant, T)>>`, and every one of them shared the same
//! flaw: when the entry expired, EVERY concurrent caller saw the miss and
//! ran the expensive load itself — a page fanning out to N nodes did N
//! identical lookups, ten open tabs did ten cluster fan-outs.
//!
//! [`TtlCell::get_or_load`] holds an async lock across the load, so the
//! first caller after expiry loads and everyone queued behind it gets that
//! answer. Only `Ok` answers are kept: a failure is retried by the next
//! caller rather than pinned for a whole TTL.
//!
//! [`TtlCell::invalidate`] never waits for the lock — it bumps a generation,
//! and a value (including one being loaded right now) from an older
//! generation is treated as missing. That keeps invalidation cheap enough
//! to run on every write request.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub struct TtlCell<T> {
    ttl: Duration,
    slot: tokio::sync::Mutex<Option<Slot<T>>>,
    generation: AtomicU64,
}

struct Slot<T> {
    value: T,
    at: Instant,
    generation: u64,
}

impl<T: Clone> TtlCell<T> {
    pub const fn new(ttl: Duration) -> Self {
        TtlCell {
            ttl,
            slot: tokio::sync::Mutex::const_new(None),
            generation: AtomicU64::new(0),
        }
    }

    /// The cached value if it is still valid, else `load()`'s — stored when
    /// it is `Ok`. Concurrent callers on a miss wait for one load.
    pub async fn get_or_load<E, F, Fut>(&self, load: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let mut slot = self.slot.lock().await;
        let generation = self.generation.load(Ordering::SeqCst);
        if let Some(s) = slot.as_ref() {
            if s.generation == generation && s.at.elapsed() < self.ttl {
                return Ok(s.value.clone());
            }
        }
        let value = load().await?;
        *slot = Some(Slot {
            value: value.clone(),
            at: Instant::now(),
            generation,
        });
        Ok(value)
    }

    /// Overwrite with an answer computed elsewhere (a page that just did
    /// the same expensive work). Skipped if a load holds the lock — that
    /// load is about to store an equally fresh answer.
    pub fn put(&self, value: T) {
        if let Ok(mut slot) = self.slot.try_lock() {
            *slot = Some(Slot {
                value,
                at: Instant::now(),
                generation: self.generation.load(Ordering::SeqCst),
            });
        }
    }

    /// Forget the value, and any load in flight, without waiting.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[tokio::test]
    async fn concurrent_misses_load_once() {
        let cell = Arc::new(TtlCell::<usize>::new(Duration::from_secs(60)));
        let loads = Arc::new(AtomicUsize::new(0));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let (cell, loads) = (cell.clone(), loads.clone());
            set.spawn(async move {
                cell.get_or_load(|| async {
                    loads.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok::<_, ()>(7)
                })
                .await
            });
        }
        while let Some(r) = set.join_next().await {
            assert_eq!(r.unwrap(), Ok(7));
        }
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn errors_are_not_cached() {
        let cell = TtlCell::<usize>::new(Duration::from_secs(60));
        assert_eq!(
            cell.get_or_load(|| async { Err::<usize, _>("down") }).await,
            Err("down")
        );
        assert_eq!(cell.get_or_load(|| async { Ok::<_, &str>(1) }).await, Ok(1));
        assert_eq!(cell.get_or_load(|| async { Ok::<_, &str>(2) }).await, Ok(1));
    }

    #[tokio::test]
    async fn expiry_and_invalidation() {
        let cell = TtlCell::<usize>::new(Duration::from_millis(30));
        let ok = |n| move || async move { Ok::<_, ()>(n) };
        assert_eq!(cell.get_or_load(ok(1)).await, Ok(1));
        assert_eq!(cell.get_or_load(ok(2)).await, Ok(1));
        cell.invalidate();
        assert_eq!(cell.get_or_load(ok(3)).await, Ok(3));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(cell.get_or_load(ok(4)).await, Ok(4));
        cell.put(5);
        assert_eq!(cell.get_or_load(ok(6)).await, Ok(5));
    }

    #[tokio::test]
    async fn invalidation_during_load_drops_its_answer() {
        let cell = Arc::new(TtlCell::<usize>::new(Duration::from_secs(60)));
        let c2 = cell.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let loader = tokio::spawn(async move {
            c2.get_or_load(|| async {
                rx.await.ok();
                Ok::<_, ()>(1)
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        cell.invalidate();
        tx.send(()).ok();
        assert_eq!(loader.await.unwrap(), Ok(1));
        assert_eq!(cell.get_or_load(|| async { Ok::<_, ()>(2) }).await, Ok(2));
    }
}
