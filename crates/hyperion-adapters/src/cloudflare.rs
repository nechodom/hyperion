//! Cloudflare DNS provider for automated DNS-01 wildcard issuance.
//!
//! Scaffold: the manual DNS-01 flow works without this. When a
//! Cloudflare API token is present (in `/etc/hyperion/cloudflare.token`
//! or `$HYPERION_CLOUDFLARE_TOKEN`), the service can publish the
//! `_acme-challenge` TXT records itself and finish issuance without the
//! operator touching DNS.
//!
//! Calls go through `curl` (every node already has it; pulling in a HTTP
//! client just for this would double-link a TLS stack) against the
//! Cloudflare v4 API. The token needs `Zone:Read` + `DNS:Edit`.

use crate::AdapterError;

const TOKEN_FILE: &str = "/etc/hyperion/cloudflare.token";
const API: &str = "https://api.cloudflare.com/client/v4";

/// The configured token, if any. File takes precedence over env.
pub fn token() -> Option<String> {
    if let Ok(s) = std::fs::read_to_string(TOKEN_FILE) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    std::env::var("HYPERION_CLOUDFLARE_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// True when a token is configured (drives the UI's "Cloudflare
/// (automatic)" option being offered vs. disabled).
pub fn is_configured() -> bool {
    token().is_some()
}

async fn curl_json(token: &str, args: &[&str]) -> Result<serde_json::Value, AdapterError> {
    let auth = format!("Authorization: Bearer {token}");
    let mut full: Vec<&str> = vec![
        "-fsS",
        "--max-time",
        "30",
        "-H",
        &auth,
        "-H",
        "Content-Type: application/json",
    ];
    full.extend_from_slice(args);
    let out = crate::cmd::run("/usr/bin/curl", &full).await?;
    serde_json::from_str(&out).map_err(|e| AdapterError::Other(format!("cloudflare json: {e}")))
}

/// Find the zone id whose name is the longest DNS suffix of `record_name`.
async fn zone_id_for(token: &str, record_name: &str) -> Result<(String, String), AdapterError> {
    let url = format!("{API}/zones?per_page=50");
    let v = curl_json(token, &[&url]).await?;
    let zones = v["result"]
        .as_array()
        .ok_or_else(|| AdapterError::Other("cloudflare: no zones in response".into()))?;
    let mut best: Option<(String, String)> = None;
    for z in zones {
        let (Some(id), Some(name)) = (z["id"].as_str(), z["name"].as_str()) else {
            continue;
        };
        if (record_name == name || record_name.ends_with(&format!(".{name}")))
            && best
                .as_ref()
                .map(|(_, n)| name.len() > n.len())
                .unwrap_or(true)
        {
            best = Some((id.to_string(), name.to_string()));
        }
    }
    best.ok_or_else(|| {
        AdapterError::Other(format!(
            "cloudflare: no zone covers {record_name} (is the domain on this account?)"
        ))
    })
}

/// Publish one TXT record per value at `record_name`. Returns the created
/// record ids so the caller can clean them up after issuance.
pub async fn publish_txt(
    token: &str,
    record_name: &str,
    values: &[String],
) -> Result<Vec<String>, AdapterError> {
    let (zone_id, _zone_name) = zone_id_for(token, record_name).await?;
    let url = format!("{API}/zones/{zone_id}/dns_records");
    let mut ids = Vec::new();
    for value in values {
        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120,
        })
        .to_string();
        let v = curl_json(token, &["-X", "POST", &url, "--data", &body]).await?;
        if v["success"].as_bool() != Some(true) {
            return Err(AdapterError::Other(format!(
                "cloudflare: TXT create failed: {}",
                v["errors"]
            )));
        }
        if let Some(id) = v["result"]["id"].as_str() {
            ids.push((zone_id.clone(), id.to_string()));
        }
    }
    // Encode as "zone:id" so cleanup doesn't need to re-resolve the zone.
    Ok(ids.into_iter().map(|(z, i)| format!("{z}:{i}")).collect())
}

/// Delete the TXT records created by `publish_txt`. Best-effort.
pub async fn cleanup_txt(token: &str, record_ids: &[String]) {
    for entry in record_ids {
        let Some((zone, id)) = entry.split_once(':') else {
            continue;
        };
        let url = format!("{API}/zones/{zone}/dns_records/{id}");
        let _ = curl_json(token, &["-X", "DELETE", &url]).await;
    }
}
