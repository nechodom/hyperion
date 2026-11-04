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
