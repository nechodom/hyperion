use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub agent: AgentSection,
    pub acme: AcmeSection,
    pub backup_remote: BackupRemoteSection,
    pub backup_retention: BackupRetentionSection,
    pub enrollment: EnrollmentSection,
    pub slack: SlackSection,
    pub email: EmailSection,
    pub remote_rpc: RemoteRpcSection,
}

/// Inbound master→node RPC listener. The master's hyperion-web
/// POSTs signed RPC requests to `https://<this-node>:port/agent-rpc`
/// and this section configures the listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RemoteRpcSection {
    /// When `true`, hyperion-agent binds `bind` and accepts signed
    /// RPC requests. `false` is safe — the local Unix socket
    /// always works, the operator just can't drive this node from
    /// the master UI.
    pub enabled: bool,
    /// IP+port to bind to. Default `0.0.0.0:9443` exposes the
    /// listener on every interface; operators on multi-homed
    /// hosts can pin it (e.g. `10.0.0.5:9443`) to a single
    /// private interface. The port also has to be opened in
    /// whatever firewall is in front (ufw / iptables / cloud SG).
    pub bind: String,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
}

impl Default for RemoteRpcSection {
    fn default() -> Self {
        Self {
            // Default OFF on workers so an old agent.toml that
            // doesn't even mention [remote_rpc] gets the safe
            // behavior. install-node.sh sets this to true.
            enabled: false,
            bind: "0.0.0.0:9443".into(),
            tls_cert_file: PathBuf::from("/etc/hyperion/agent-rpc.crt"),
            tls_key_file: PathBuf::from("/etc/hyperion/agent-rpc.key"),
        }
    }
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
    /// When `true`, the node verifies the master's TLS cert against
    /// the system CA bundle. Defaults to `false` because install-
    /// master.sh ships a self-signed cert (no DNS at install time
    /// → no LE) and the node has no trust anchor to bootstrap.
    /// The bearer token + per-node secret are the auth; TLS here
    /// is encryption-in-transit. Set `true` once the master serves
    /// a real LE cert.
    #[serde(default)]
    pub verify_tls: bool,
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
    /// Days before `not_after` at which the background renewal tick
    /// re-issues an LE cert. 30 is the Let's Encrypt-recommended
    /// buffer (gives a 60-day window of retries before expiry).
    pub renewal_window_days: i64,
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

/// Backup retention policy. After every successful local backup,
/// archives older than `max_age_days` are deleted, but at least
/// `keep_latest_n` newest per hosting are always retained.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BackupRetentionSection {
    pub max_age_days: i64,
    pub keep_latest_n: i64,
}

/// Default Slack incoming webhook for cluster-wide notifications
/// (backup failures, billing reminders, cert renewals). Profiles can
/// override per-profile.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SlackSection {
    pub default_webhook: String,
}

/// SMTP relay credentials for transactional email (billing reminders,
/// cert expiry, backup failures). Operator should use any
/// production-grade relay — Postmark, SendGrid, Mailgun, Brevo, AWS
/// SES, or a self-hosted postfix-with-auth. Direct-from-VPS sends to
/// public mailboxes are NOT recommended (will land in spam).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EmailSection {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub from_address: String,
    pub from_name: String,
    /// "starttls" (587) | "tls" (465) | "plain" (dev only)
    pub security: String,
    /// Default operator address that gets cluster-wide notifications
    /// (billing reminders for hostings with no owner_email set).
    pub default_to: String,
}

impl Default for EmailSection {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_host: "smtp.example.com".into(),
            smtp_port: 587,
            smtp_user: String::new(),
            smtp_password: String::new(),
            from_address: "hyperion@example.com".into(),
            from_name: "Hyperion".into(),
            security: "starttls".into(),
            default_to: String::new(),
        }
    }
}

impl Default for BackupRetentionSection {
    fn default() -> Self {
        Self {
            max_age_days: 30,
            keep_latest_n: 5,
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
            renewal_window_days: 30,
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
