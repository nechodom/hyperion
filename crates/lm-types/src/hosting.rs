//! Hosting DTOs.

use crate::{cert::CertInfo, db::DbSummary, ids::HostingId, php::PhpVersion};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HostingState {
    Provisioning,
    Active,
    Suspended,
    Failed,
    Deleting,
}

impl HostingState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Failed => "failed",
            Self::Deleting => "deleting",
        }
    }
}

impl fmt::Display for HostingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HostingState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "failed" => Ok(Self::Failed),
            "deleting" => Ok(Self::Deleting),
            other => Err(format!("unknown state: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingSummary {
    pub id: HostingId,
    pub domain: String,
    pub state: HostingState,
    pub php_version: Option<PhpVersion>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingDetail {
    pub id: HostingId,
    pub domain: String,
    pub aliases: Vec<String>,
    pub state: HostingState,
    pub system_user: String,
    pub php_version: Option<PhpVersion>,
    pub root_dir: String,
    pub database: Option<DbSummary>,
    pub cert: Option<CertInfo>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbProvision;

    #[test]
    fn state_round_trip() {
        for s in [
            HostingState::Provisioning,
            HostingState::Active,
            HostingState::Suspended,
            HostingState::Failed,
            HostingState::Deleting,
        ] {
            let j = serde_json::to_string(&s).expect("serialize");
            let back: HostingState = serde_json::from_str(&j).expect("deserialize");
            assert_eq!(s, back);
            assert_eq!(HostingState::from_str(s.as_str()).expect("parse"), s);
        }
    }

    #[test]
    fn detail_round_trip() {
        let d = HostingDetail {
            id: HostingId::new_v7(),
            domain: "example.cz".into(),
            aliases: vec!["www.example.cz".into()],
            state: HostingState::Active,
            system_user: "example_cz".into(),
            php_version: Some(PhpVersion::V8_3),
            root_dir: "/home/example_cz/example.cz/htdocs".into(),
            database: Some(DbSummary {
                engine: DbProvision::MariaDB,
                db_name: "lm_a_db".into(),
                db_user: "lm_a_u".into(),
            }),
            cert: None,
            created_at: 1,
            updated_at: 2,
        };
        let j = serde_json::to_string(&d).expect("serialize");
        let back: HostingDetail = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(d, back);
    }

    #[test]
    fn summary_round_trip() {
        let s = HostingSummary {
            id: HostingId::new_v7(),
            domain: "ex.cz".into(),
            state: HostingState::Provisioning,
            php_version: None,
            created_at: 0,
        };
        let j = serde_json::to_string(&s).expect("serialize");
        let back: HostingSummary = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(s, back);
    }
}
