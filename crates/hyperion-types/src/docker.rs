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
