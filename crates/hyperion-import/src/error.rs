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
    #[error("parse error in {what}: {msg}")]
    Parse { what: String, msg: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
