//! Hosting profile DTOs — operator-defined templates.

use serde::{Deserialize, Serialize};

use crate::HostingId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingProfile {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub disk_hard_mb: Option<i64>,
    pub bw_monthly_mb: Option<i64>,
    pub expiry_grace_days: i64,
    pub expiry_warning_offsets: String,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub slack_webhook: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl HostingProfile {
    /// Pretty price like "199.00 Kč/měsíc" or "—" when no price.
    pub fn pretty_price(&self) -> String {
        match (&self.price_minor, &self.price_currency, &self.price_interval) {
            (Some(m), Some(c), Some(iv)) => {
                let major = *m as f64 / 100.0;
                let iv_word = match iv.as_str() {
                    "monthly" => "/měsíc",
                    "quarterly" => "/kvartál",
                    "yearly" => "/rok",
                    other => other,
                };
                format!("{major:.2} {c}{iv_word}")
            }
            _ => "—".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProfileInput {
    pub name: String,
    pub description: String,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub disk_hard_mb: Option<i64>,
    pub bw_monthly_mb: Option<i64>,
    pub expiry_grace_days: i64,
    pub expiry_warning_offsets: String,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub slack_webhook: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileApply {
    pub hosting_id: HostingId,
    pub profile_id: Option<i64>,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub next_billing_at: Option<i64>,
    pub applied_at: i64,
}

impl ProfileApply {
    pub fn pretty_price(&self) -> String {
        match (
            &self.price_minor,
            &self.price_currency,
            &self.price_interval,
        ) {
            (Some(m), Some(c), Some(iv)) => {
                let major = *m as f64 / 100.0;
                let iv_word = match iv.as_str() {
                    "monthly" => "/měsíc",
                    "quarterly" => "/kvartál",
                    "yearly" => "/rok",
                    other => other,
                };
                format!("{major:.2} {c}{iv_word}")
            }
            _ => "—".into(),
        }
    }
}
