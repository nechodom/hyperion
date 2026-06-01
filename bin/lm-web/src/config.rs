use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub web: WebSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebSection {
    /// `host:port` to listen on.
    pub listen: String,
    /// Path to the lm-agent Unix socket.
    pub agent_socket: PathBuf,
    /// JSON file with the (single) admin user record.
    pub admin_user_file: PathBuf,
    /// Ed25519 secret for session cookie signing. Generated on first start.
    pub session_key_file: PathBuf,
    /// Optional 32-byte CSRF key file. Generated on first start.
    pub csrf_key_file: PathBuf,
    /// Session TTL (idle) in seconds.
    pub session_ttl_secs: i64,
    /// Bind cookies as Secure (set false in dev when running over plain HTTP).
    pub secure_cookies: bool,
    /// Cookie name for the session.
    pub session_cookie_name: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            web: WebSection::default(),
        }
    }
}

impl Default for WebSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8443".into(),
            agent_socket: PathBuf::from("/run/linux-manager.sock"),
            admin_user_file: PathBuf::from("/etc/linux-manager/web-admin.json"),
            session_key_file: PathBuf::from("/etc/linux-manager/web-session.key"),
            csrf_key_file: PathBuf::from("/etc/linux-manager/web-csrf.key"),
            session_ttl_secs: 8 * 3600,
            secure_cookies: true,
            session_cookie_name: "lm_session".into(),
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
        Ok(toml::from_str(&s)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.web.session_ttl_secs, 8 * 3600);
        assert!(c.web.secure_cookies);
        assert_eq!(c.web.session_cookie_name, "lm_session");
    }

    #[test]
    fn partial_toml_overrides() {
        let toml = r#"
            [web]
            listen = "0.0.0.0:9000"
            secure_cookies = false
        "#;
        let c: Config = toml::from_str(toml).expect("parse");
        assert_eq!(c.web.listen, "0.0.0.0:9000");
        assert!(!c.web.secure_cookies);
        // Defaults preserved:
        assert_eq!(c.web.session_cookie_name, "lm_session");
    }
}
