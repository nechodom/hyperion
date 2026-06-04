//! Public wire types exchanged in RPC bodies.

use hyperion_types::{CertInfo, DbProvision, HostingId, PhpVersion};
use hyperion_validate::{Domain, SystemUserName};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentInfo {
    pub hostname: String,
    pub version: String,
    pub schema_version: i64,
    pub hostings_count: i64,
    /// Master-assigned node id from /etc/hyperion/node-id.json.
    /// `None` when the agent isn't enrolled (single-node setup OR
    /// enrollment failed). Surfaced on `hctl info` so the operator
    /// can confirm enrollment without SSHing into the file.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Master URL the node phones home to. Same source as node_id.
    #[serde(default)]
    pub master_url: Option<String>,
    /// Unix-seconds timestamp when enrollment completed.
    #[serde(default)]
    pub enrolled_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingCreateReq {
    pub domain: Domain,
    #[serde(default)]
    pub aliases: Vec<Domain>,
    #[serde(default)]
    pub php_version: Option<PhpVersion>,
    #[serde(default)]
    pub database: Option<DbProvision>,
    #[serde(default)]
    pub system_user: Option<SystemUserName>,
    /// Hosting kind. Default "php" for back-compat with older clients.
    /// "reverse_proxy" requires `proxy_upstream_url` to be Some.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Upstream URL for kind=reverse_proxy. Ignored for other kinds.
    #[serde(default)]
    pub proxy_upstream_url: Option<String>,
}

fn default_kind() -> String {
    "php".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingCreated {
    pub id: HostingId,
    pub system_user: String,
    pub root_dir: String,
    pub db: Option<DbCredentials>,
    pub cert: Option<CertInfo>,
    /// Populated when WordPress was installed inline at create time.
    /// Returned ONCE — same security model as the DB password.
    #[serde(default)]
    pub wp: Option<WpCreatedInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpCreatedInfo {
    pub admin_user: String,
    pub admin_email: String,
    pub admin_password: String,
    pub admin_login_url: String,
}

/// Returned ONCE at creation time; never reread from the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbCredentials {
    pub engine: DbProvision,
    pub db_name: String,
    pub db_user: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum HostingSelector {
    Id(HostingId),
    Domain(Domain),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DeleteOpts {
    #[serde(default)]
    pub keep_user: bool,
    #[serde(default)]
    pub keep_database: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_req_minimal_round_trip() {
        let r = HostingCreateReq {
            domain: Domain::parse("example.cz").expect("parse"),
            aliases: vec![],
            php_version: None,
            database: None,
            system_user: None,
            kind: "php".into(),
            proxy_upstream_url: None,
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: HostingCreateReq = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(r, back);
    }

    #[test]
    fn create_req_full_round_trip() {
        let r = HostingCreateReq {
            domain: Domain::parse("example.cz").expect("parse"),
            aliases: vec![Domain::parse("www.example.cz").expect("parse")],
            php_version: Some(PhpVersion::V8_3),
            database: Some(DbProvision::MariaDB),
            system_user: Some(SystemUserName::parse("example_cz").expect("parse")),
            kind: "php".into(),
            proxy_upstream_url: None,
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: HostingCreateReq = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(r, back);
    }

    #[test]
    fn selector_variants_round_trip() {
        let id_sel = HostingSelector::Id(HostingId::new_v7());
        let j = serde_json::to_string(&id_sel).expect("serialize");
        let back: HostingSelector = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(id_sel, back);

        let dom_sel = HostingSelector::Domain(Domain::parse("ex.cz").expect("parse"));
        let j = serde_json::to_string(&dom_sel).expect("serialize");
        let back: HostingSelector = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(dom_sel, back);
    }

    #[test]
    fn delete_opts_defaults() {
        let parsed: DeleteOpts = serde_json::from_str("{}").expect("deserialize");
        assert_eq!(parsed, DeleteOpts::default());
        assert!(!parsed.keep_user);
        assert!(!parsed.keep_database);
    }
}
