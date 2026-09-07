//! The `SourceAdapter` trait + the source-location modes every adapter accepts.

use crate::error::ImportError;
use crate::ir::ImportIR;
use std::path::PathBuf;

/// Where an adapter reads the source panel from.
#[derive(Debug, Clone)]
pub enum Location {
    /// The source panel is installed on *this* node — read local files / CLIs.
    /// This is the P0 / headline case (Hyperion agent on the old panel box).
    InPlace,
    /// Pull from a remote source box over SSH (P1).
    Remote(SshTarget),
    /// An uploaded export archive already staged on this node (P1).
    Archive(PathBuf),
}

impl Location {
    /// Short label for error messages / logs (never includes the ssh key).
    pub fn mode(&self) -> &'static str {
        match self {
            Location::InPlace => "in-place",
            Location::Remote(_) => "remote",
            Location::Archive(_) => "archive",
        }
    }
}

/// SSH target for `Location::Remote`. The key is an ephemeral 0600 file written
/// for the job and deleted on completion — never persisted to the DB.
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub user: String,
    pub key_path: PathBuf,
    pub port: u16,
}

/// Result of a cheap [`SourceAdapter::detect`] probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePanelInfo {
    pub kind: SourceKind,
    pub version: String,
    /// Whether the source has these subsystems enabled, so `extract` can skip
    /// the ones that are off (and the report can be honest about what's absent).
    pub has_mail: bool,
    pub has_dns: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    HestiaCp,
    CloudPanel,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::HestiaCp => "hestiacp",
            SourceKind::CloudPanel => "cloudpanel",
        }
    }
}

/// A source control panel Hyperion can import from.
#[async_trait::async_trait]
pub trait SourceAdapter: Send + Sync {
    fn kind(&self) -> SourceKind;

    /// Cheap probe: is this panel present at `location`? `None` = not found.
    async fn detect(&self, location: &Location) -> Option<SourcePanelInfo>;

    /// Walk the source and produce the panel-neutral IR. Performs **no writes**
    /// to the target — DB dumps and file copies happen later, during apply.
    async fn extract(&self, location: &Location) -> Result<ImportIR, ImportError>;
}

/// Runs the adapter's read commands either locally (in-place) or over SSH
/// (remote), so a single adapter body serves both modes.
pub enum Runner {
    Local,
    Ssh(SshTarget),
}

/// Wall-clock budget for one adapter read ([`Runner::sh`] and everything built
/// on it: `cat`, `ls -1`, `test -e`, `sqlite3 -readonly`, `clpctl --version`).
///
/// Policy, not a measurement — set far above what any of these needs, because
/// the cost of being wrong is not symmetric: too generous only delays a run
/// that was already stuck, too tight fails a detection that would have worked.
pub const READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

impl Runner {
    pub fn for_location(loc: &Location) -> Self {
        match loc {
            Location::Remote(t) => Runner::Ssh(t.clone()),
            _ => Runner::Local,
        }
    }

    /// Run a `/bin/sh -c` command (locally or on the remote box) and return its
    /// stdout. Non-zero exit → `Err`.
    ///
    /// Budgeted like everything else this crate spawns. These are all small
    /// reads of panel configuration — no payload ever moves through here — so a
    /// command still running after [`READ_BUDGET`] is stuck, not slow. It
    /// matters most over SSH: `ConnectTimeout` only covers reaching the box, and
    /// a session that dies afterwards leaves `ssh` waiting on a socket nobody
    /// will ever close.
    pub async fn sh(&self, command: &str) -> Result<String, ImportError> {
        let cmd = match self {
            Runner::Local => {
                let mut c = tokio::process::Command::new("sh");
                c.arg("-c").arg(command);
                c
            }
            Runner::Ssh(t) => {
                let mut c = tokio::process::Command::new("ssh");
                c.args(t.ssh_opts())
                    .arg(format!("{}@{}", t.user, t.host))
                    .arg(command);
                c
            }
        };
        let what = format!(
            "reading `{}` from the source panel",
            command.chars().take(60).collect::<String>()
        );
        let out = crate::proc::capture(cmd, READ_BUDGET, &what).await?;
        if !out.status.success() {
            return Err(ImportError::Command {
                cmd: command.to_string(),
                msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// Read a file's contents (local fs or `cat` over ssh). `None` if absent.
    pub async fn read(&self, path: &str) -> Option<String> {
        match self {
            Runner::Local => tokio::fs::read_to_string(path).await.ok(),
            Runner::Ssh(_) => self.sh(&format!("cat -- {}", shell_quote(path))).await.ok(),
        }
    }

    /// List the entry names directly under `path` (local readdir or `ls -1`).
    pub async fn list_dir(&self, path: &str) -> Vec<String> {
        match self {
            Runner::Local => {
                let mut v = Vec::new();
                if let Ok(mut rd) = tokio::fs::read_dir(path).await {
                    while let Ok(Some(e)) = rd.next_entry().await {
                        v.push(e.file_name().to_string_lossy().to_string());
                    }
                }
                v
            }
            Runner::Ssh(_) => self
                .sh(&format!("ls -1 {}", shell_quote(path)))
                .await
                .map(|s| {
                    s.lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// Does a path exist (local stat or `test -e` over ssh)?
    pub async fn exists(&self, path: &str) -> bool {
        match self {
            Runner::Local => std::path::Path::new(path).exists(),
            Runner::Ssh(_) => self
                .sh(&format!("test -e {} && echo y", shell_quote(path)))
                .await
                .map(|s| s.trim() == "y")
                .unwrap_or(false),
        }
    }
}

impl SshTarget {
    /// Common ssh CLI options: key, port, batch (key-only), accept new host key,
    /// short connect timeout. Shared by `Runner` and the engine's rsync/dump.
    pub fn ssh_opts(&self) -> Vec<String> {
        vec![
            "-i".into(),
            self.key_path.display().to_string(),
            "-p".into(),
            self.port.to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
        ]
    }
}

/// Single-quote a string for safe embedding in a `/bin/sh` command.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
