//! Database engine enum + summary DTO.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbProvision {
    MariaDB,
    Postgres,
}

impl DbProvision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MariaDB => "mariadb",
            Self::Postgres => "postgres",
        }
    }
}

impl fmt::Display for DbProvision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DbProvision {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "mariadb" | "mysql" | "maria" => Ok(Self::MariaDB),
            "postgres" | "postgresql" | "pg" => Ok(Self::Postgres),
            other => Err(format!("unknown db engine: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbSummary {
    pub engine: DbProvision,
    pub db_name: String,
    pub db_user: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_lowercase() {
        let s = serde_json::to_string(&DbProvision::MariaDB).expect("serialize");
        assert_eq!(s, "\"mariadb\"");
        let s = serde_json::to_string(&DbProvision::Postgres).expect("serialize");
        assert_eq!(s, "\"postgres\"");
    }

    #[test]
    fn deserializes_lowercase() {
        let v: DbProvision = serde_json::from_str("\"mariadb\"").expect("deserialize");
        assert_eq!(v, DbProvision::MariaDB);
    }

    #[test]
    fn fromstr_accepts_aliases() {
        assert_eq!(
            "mysql".parse::<DbProvision>().expect("parse"),
            DbProvision::MariaDB
        );
        assert_eq!(
            "PG".parse::<DbProvision>().expect("parse"),
            DbProvision::Postgres
        );
        assert_eq!(
            "PostgreSQL".parse::<DbProvision>().expect("parse"),
            DbProvision::Postgres
        );
    }

    #[test]
    fn fromstr_rejects_garbage() {
        assert!("sqlite".parse::<DbProvision>().is_err());
        assert!("".parse::<DbProvision>().is_err());
    }

    #[test]
    fn summary_round_trip() {
        let v = DbSummary {
            engine: DbProvision::MariaDB,
            db_name: "x".into(),
            db_user: "y".into(),
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: DbSummary = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }
}
