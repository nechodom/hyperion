//! Wire types for the Docker monitoring module. Read-only facts about
//! containers; nothing here can carry `Config.Env` or foreign labels.

use serde::{Deserialize, Serialize};

/// One published port of a container.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerPort {
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
    pub proto: String,
}

/// What the adapter knows about one container. Stats fields stay `None`
/// until a stats read is merged in; `log_size_bytes` is filled by whoever
/// can stat the log file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub project: String,
    pub service: String,
    pub oneoff: bool,
    pub working_dir: String,
    pub image: String,
    pub image_id: String,
    pub state: String,
    pub health: Option<String>,
    pub exit_code: i64,
    pub oom_killed: bool,
    pub restart_count: i64,
    pub restart_policy: String,
    /// Unix seconds; 0 when the container never started.
    pub started_at: i64,
    /// Unix seconds; 0 while it is still running or never ran.
    pub finished_at: i64,
    pub ports: Vec<DockerPort>,
    /// CPU percent times 100.
    pub cpu_pct_x100: Option<i64>,
    pub mem_bytes: Option<u64>,
    pub log_path: String,
    pub log_size_bytes: u64,
    /// The json-file `max-size` option, when set.
    pub log_max_size: Option<String>,
}

/// Disk use as `docker system df` reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerDisk {
    pub images_bytes: u64,
    pub volumes_bytes: u64,
    pub build_cache_bytes: u64,
    pub containers_bytes: u64,
    pub read_at: i64,
}

/// Whether the Docker module is on, as one node (or the master) reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerModuleState {
    /// The operator turned the module on for the cluster (master only).
    pub cluster_installed: bool,
    /// This node runs the module.
    pub node_installed: bool,
    /// `docker buildx` is available on this node.
    pub buildx: bool,
    /// The daemon's version; `None` while the module is off or the daemon
    /// did not answer.
    pub docker_version: Option<String>,
}

/// One node the master has recorded as running the module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerNodeEntry {
    /// `local` for the master itself, else the enrolled node id.
    pub node_id: String,
    pub installed_at: i64,
    /// The master has alerted that this node stopped answering and has not
    /// yet announced that it is back.
    pub silent: bool,
}

/// Master: whether the module is on for the cluster and which nodes the
/// master fans out to. The web layer reads this instead of a database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerNodeList {
    pub cluster_installed: bool,
    pub nodes: Vec<DockerNodeEntry>,
}

/// One compose project on a node, with the verdict the module reached. A
/// project that is gone has no containers and a `gone_since`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerProject {
    /// The compose project name; empty for containers that belong to none
    /// (shown as "other containers").
    pub name: String,
    pub containers: Vec<DockerContainer>,
    /// `ok`, `problem` or `gone`.
    pub verdict: String,
    /// What is wrong, as service, exit code and cause. Never log text.
    pub summary: String,
    /// Domains of the hostings this project belongs to.
    pub hostings: Vec<String>,
    /// Unix seconds since the project's containers all disappeared.
    pub gone_since: Option<i64>,
}

/// What a node's Docker looked like at the last read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerNodeStatus {
    /// Unix seconds of the last successful read of the container list.
    pub read_at: i64,
    /// Unix seconds of the last `docker stats` read; the CPU and memory
    /// figures are that old.
    pub stats_at: i64,
    /// The daemon answered on the latest attempt. When it did not,
    /// `projects` is the last thing it said.
    pub daemon_ok: bool,
    pub daemon_error: Option<String>,
    pub projects: Vec<DockerProject>,
    pub disk: Option<DockerDisk>,
}

/// Lines returned when the request does not say.
pub const DEFAULT_LOG_LINES: u32 = 200;
/// The most lines one request may ask for.
pub const MAX_LOG_LINES: u32 = 2000;
/// The most log text one response carries, whatever the line count.
pub const MAX_LOG_BYTES: usize = 1024 * 1024;

/// Ask for the log of one container, or of every container of a stack.
///
/// `container` is a name the node looks up in its own inspect result; it is
/// never handed to `docker`. `since_cursor` is the opaque `cursor` of an
/// earlier answer and asks only for what came after it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerLogRequest {
    /// The compose project; empty for the group of containers without one.
    pub project: String,
    /// One container of that project; `None` reads all of them.
    pub container: Option<String>,
    /// 0 means the default.
    pub lines: u32,
    pub since_cursor: Option<String>,
    /// Plain text, matched without regard to case. Not a pattern.
    pub filter: Option<String>,
    /// Who opened the log, for the audit entry. `None` writes none, which is
    /// what a follow poll sends.
    pub audit_actor: Option<String>,
}

// The filter is what someone searched for in a log; keep it out of any
// `{:?}` that ends up in a log file.
impl std::fmt::Debug for DockerLogRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerLogRequest")
            .field("project", &self.project)
            .field("container", &self.container)
            .field("lines", &self.lines)
            .field("filter", &self.filter.as_ref().map(|_| "(set)"))
            .finish_non_exhaustive()
    }
}

/// One line of a container's log.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerLogLine {
    /// Docker's RFC 3339 timestamp, as printed.
    pub ts: String,
    /// The service the line came from (the container name when it has none).
    pub service: String,
    /// The text, without escape sequences or control characters.
    pub text: String,
}

// Log text must not reach a tracing line by accident.
impl std::fmt::Debug for DockerLogLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerLogLine")
            .field("ts", &self.ts)
            .field("service", &self.service)
            .field("text_len", &self.text.len())
            .finish()
    }
}

/// The answer to a [`DockerLogRequest`]: oldest line first.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerLogChunk {
    pub lines: Vec<DockerLogLine>,
    /// Hand this back as `since_cursor` to get what is new. Opaque. `None`
    /// when nothing was read.
    pub cursor: Option<String>,
    /// Some of the log was left out: the byte cap was reached, or the read
    /// was cut short.
    pub truncated: bool,
    /// Containers of the stack whose log could not be read.
    pub unreadable: u32,
}

impl std::fmt::Debug for DockerLogChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerLogChunk")
            .field("lines", &self.lines.len())
            .field("cursor", &self.cursor)
            .field("truncated", &self.truncated)
            .field("unreadable", &self.unreadable)
            .finish()
    }
}
