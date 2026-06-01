use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub agent: AgentSection,
    pub acme: AcmeSection,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentSection::default(),
            acme: AcmeSection::default(),
        }
    }
}

impl Default for AgentSection {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/linux-manager.sock"),
            socket_group: "lm-admin".into(),
            state_db: PathBuf::from("/var/lib/linux-manager/state.db"),
            secrets_dir: PathBuf::from("/etc/linux-manager/secrets"),
            log_path: PathBuf::from("/var/log/linux-manager/agent.log"),
            home_root: PathBuf::from("/home"),
            backup_root: PathBuf::from("/var/lib/linux-manager/backups/local"),
        }
    }
}

impl Default for AcmeSection {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contact_email: "admin@example.com".into(),
            challenge_dir: PathBuf::from("/var/lib/linux-manager/acme-challenges"),
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
        assert_eq!(cfg.agent.socket_group, "lm-admin");
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
            "/run/linux-manager.sock"
        );
    }
}
