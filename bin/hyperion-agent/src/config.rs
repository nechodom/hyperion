use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub agent: AgentSection,
    pub acme: AcmeSection,
    pub backup_remote: BackupRemoteSection,
    pub enrollment: EnrollmentSection,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct EnrollmentSection {
    /// URL of the master to enroll against (https://master.example.com).
    pub master_url: String,
    /// One-time invite token minted by the master. Consumed on first boot.
    pub invite_token: String,
    /// Label this node wants to be known as in the cluster.
    pub node_label: String,
    /// Path where the assigned node_id is persisted after first enrollment.
    /// Defaults to /etc/hyperion/node-id.json.
    pub state_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AgentSection {
    pub socket_path: PathBuf,
    pub socket_group: String,
    pub state_db: PathBuf,
    pub secrets_dir: PathBuf,
    pub log_path: PathBuf,
    pub home_root: PathBuf,
    pub backup_root: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AcmeSection {
    pub directory_url: String,
    pub contact_email: String,
    pub challenge_dir: PathBuf,
}

/// Optional remote-backup destination. When enabled (`enabled=true`)
/// every successful `backup_now` pushes the archive (+ optional SQL
/// dump) to the configured FTP/FTPS/SFTP server after the local
/// archive is written. Empty by default — operator opts in.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BackupRemoteSection {
    pub enabled: bool,
    /// "ftp" | "ftps" | "sftp"
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Plaintext for now; will move into secrets store in a later pass.
    pub password: String,
    /// Per-hosting directory is appended automatically.
    pub base_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentSection::default(),
            acme: AcmeSection::default(),
            backup_remote: BackupRemoteSection::default(),
            enrollment: EnrollmentSection::default(),
        }
    }
}

impl Default for BackupRemoteSection {
    fn default() -> Self {
        Self {
            enabled: false,
            scheme: "ftp".into(),
            host: String::new(),
            port: 21,
            user: String::new(),
            password: String::new(),
            base_path: "/hyperion-backups".into(),
        }
    }
}

impl Default for AgentSection {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/hyperion.sock"),
            socket_group: "hyperion-admin".into(),
            state_db: PathBuf::from("/var/lib/hyperion/state.db"),
            secrets_dir: PathBuf::from("/etc/hyperion/secrets"),
            log_path: PathBuf::from("/var/log/hyperion/agent.log"),
            home_root: PathBuf::from("/home"),
            backup_root: PathBuf::from("/var/lib/hyperion/backups/local"),
        }
    }
}

impl Default for AcmeSection {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contact_email: "admin@example.com".into(),
            challenge_dir: PathBuf::from("/var/lib/hyperion/acme-challenges"),
        }
    }
}

impl Config {
    pub fn load_from_path(path: &std::path::Path) -> anyhow::Result<Self> {
        if !path.exists() {
            tracing::info!(path=%path.display(), "no config file, using defaults");
            return Ok(Self::default());
        }
        let s = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&s)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_load() {
        let cfg = Config::default();
        assert_eq!(cfg.agent.socket_group, "hyperion-admin");
        assert_eq!(cfg.acme.contact_email, "admin@example.com");
    }

    #[test]
    fn partial_toml_overrides_default() {
        let toml = r#"
            [agent]
            socket_group = "ops"
            [acme]
            contact_email = "k@x.cz"
        "#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.agent.socket_group, "ops");
        assert_eq!(cfg.acme.contact_email, "k@x.cz");
        // Defaults preserved for unspecified
        assert_eq!(
            cfg.agent.socket_path.to_string_lossy(),
            "/run/hyperion.sock"
        );
    }
}
