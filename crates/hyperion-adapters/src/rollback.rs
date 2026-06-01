//! LIFO rollback stack for multi-step provisioning.

use std::fmt;

/// One reversible action.
#[async_trait::async_trait]
pub trait Rollback: Send + Sync {
    async fn run(&self) -> Result<(), String>;
    fn label(&self) -> &str;
}

pub struct RollbackStack {
    actions: Vec<Box<dyn Rollback>>,
}

impl RollbackStack {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
        }
    }

    pub fn push(&mut self, a: Box<dyn Rollback>) {
        self.actions.push(a);
    }

    /// Pop and run every action in LIFO order. Failures are accumulated and
    /// returned; they do not abort the cleanup of later actions.
    pub async fn rollback_all(&mut self) -> Vec<String> {
        let mut errs = Vec::new();
        while let Some(a) = self.actions.pop() {
            let label = a.label().to_string();
            if let Err(e) = a.run().await {
                errs.push(format!("{label}: {e}"));
                tracing::warn!(action=%label, error=%e, "rollback step failed");
            } else {
                tracing::info!(action=%label, "rollback step ok");
            }
        }
        errs
    }

    pub fn forget(self) {
        drop(self.actions);
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

impl Default for RollbackStack {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RollbackStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RollbackStack {{ depth: {} }}", self.actions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    struct Counting {
        name: String,
        seq: Arc<AtomicI32>,
        expected: i32,
    }

    #[async_trait::async_trait]
    impl Rollback for Counting {
        async fn run(&self) -> Result<(), String> {
            let cur = self.seq.fetch_sub(1, Ordering::SeqCst);
            if cur != self.expected {
                return Err(format!("expected {} got {}", self.expected, cur));
            }
            Ok(())
        }
        fn label(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn lifo_order() {
        let c = Arc::new(AtomicI32::new(3));
        let mut s = RollbackStack::new();
        s.push(Box::new(Counting {
            name: "a".into(),
            seq: c.clone(),
            expected: 1,
        }));
        s.push(Box::new(Counting {
            name: "b".into(),
            seq: c.clone(),
            expected: 2,
        }));
        s.push(Box::new(Counting {
            name: "c".into(),
            seq: c.clone(),
            expected: 3,
        }));
        assert_eq!(s.len(), 3);
        let errs = s.rollback_all().await;
        assert!(errs.is_empty(), "errors: {errs:?}");
        assert_eq!(c.load(Ordering::SeqCst), 0);
    }

    struct Failing(String);
    #[async_trait::async_trait]
    impl Rollback for Failing {
        async fn run(&self) -> Result<(), String> {
            Err(self.0.clone())
        }
        fn label(&self) -> &str {
            "failing"
        }
    }

    #[tokio::test]
    async fn failure_doesnt_stop_subsequent_rollbacks() {
        let c = Arc::new(AtomicI32::new(1));
        let mut s = RollbackStack::new();
        s.push(Box::new(Counting {
            name: "ok-1".into(),
            seq: c.clone(),
            expected: 1,
        }));
        s.push(Box::new(Failing("fail-2".into())));
        let errs = s.rollback_all().await;
        // Both popped; one failed.
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("failing: fail-2"));
        assert_eq!(c.load(Ordering::SeqCst), 0, "ok-1 still ran");
    }

    #[tokio::test]
    async fn forget_drops_without_running() {
        let c = Arc::new(AtomicI32::new(1));
        let mut s = RollbackStack::new();
        s.push(Box::new(Counting {
            name: "a".into(),
            seq: c.clone(),
            expected: 1,
        }));
        s.forget();
        assert_eq!(c.load(Ordering::SeqCst), 1, "not decremented");
    }
}
