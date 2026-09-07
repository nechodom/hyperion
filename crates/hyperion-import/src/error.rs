use thiserror::Error;

/// Errors raised while detecting or extracting a source panel.
#[derive(Debug, Error)]
pub enum ImportError {
    #[error("source panel not detected at the given location")]
    NotDetected,
    #[error("unsupported source-location mode for this adapter: {0}")]
    UnsupportedMode(String),
    #[error("command `{cmd}` failed: {msg}")]
    Command { cmd: String, msg: String },
    /// A spawned command outlived its wall-clock budget and was killed.
    ///
    /// Separate from [`ImportError::Command`] because it says something
    /// different: not "this failed" but "we stopped waiting". Nothing was
    /// diagnosed, and whatever the command had already written is a partial
    /// artefact the caller must throw away rather than pack.
    #[error("{what} exceeded its {budget} budget and was killed (`{cmd}`)")]
    Timeout {
        what: String,
        budget: String,
        cmd: String,
    },
    #[error("parse error in {what}: {msg}")]
    Parse { what: String, msg: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
