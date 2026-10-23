//! Runtime status of the acme-dns responder. The socket loop lives in the
//! agent binary; `AcmeDnsConfigGet` runs in the service. Both sit in the
//! same process, so a process-wide cell is the whole bridge.

use std::sync::RwLock;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// `addr:53` the responder is bound to (UDP and TCP).
    pub listening: Vec<String>,
    pub last_error: Option<String>,
}

static STATUS: RwLock<Status> = RwLock::new(Status {
    listening: Vec::new(),
    last_error: None,
});

pub fn get() -> Status {
    STATUS.read().map(|s| s.clone()).unwrap_or_default()
}

pub fn set(status: Status) {
    if let Ok(mut s) = STATUS.write() {
        *s = status;
    }
}
