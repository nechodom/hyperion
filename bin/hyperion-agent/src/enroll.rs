//! Node-side enrollment with the master.
//!
//! On first boot of an enrollment-configured agent we POST
//! `master_url/api/enroll` with `{token, label, agent_version, public_ip}`,
//! receive back `{node_id, master_url}`, persist it, and stop.
//! Subsequent boots see the state file and skip enrollment.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct EnrollmentConfig {
    pub master_url: String,
    pub token: String,
    pub label: String,
    pub state_file: PathBuf,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    token: &'a str,
    label: &'a str,
    agent_version: &'a str,
    public_ip: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct EnrollResponse {
    node_id: String,
    master_url: String,
}

#[derive(Deserialize, Serialize)]
struct PersistedNodeId {
    node_id: String,
    master_url: String,
    enrolled_at: i64,
}

pub async fn ensure_enrolled(cfg: EnrollmentConfig) -> Result<(), String> {
    if cfg.state_file.exists() {
        tracing::debug!(path=%cfg.state_file.display(), "node already enrolled, skipping");
        return Ok(());
    }
    // Don't hammer the master if it's unreachable on first boot — give it
    // 10s to settle (relevant when both come up in parallel).
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    let agent_version = env!("CARGO_PKG_VERSION");
    let public_ip = fetch_public_ip().await;
    let url = format!("{}/api/enroll", cfg.master_url.trim_end_matches('/'));
    let body = serde_json::to_string(&EnrollRequest {
        token: &cfg.token,
        label: &cfg.label,
        agent_version,
        public_ip,
    })
    .map_err(|e| format!("serialize: {e}"))?;

    tracing::info!(master=%cfg.master_url, "attempting node enrollment");
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args([
            "-fsS",
            "--max-time",
            "15",
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "--data",
            &body,
            &url,
        ])
        .output()
        .await
        .map_err(|e| format!("curl spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "enrollment POST exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let resp: EnrollResponse = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("parse response: {e} (raw: {})", String::from_utf8_lossy(&out.stdout)))?;

    // Persist node_id so future boots skip enrollment.
    if let Some(parent) = cfg.state_file.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let persisted = PersistedNodeId {
        node_id: resp.node_id.clone(),
        master_url: resp.master_url.clone(),
        enrolled_at: chrono::Utc::now().timestamp(),
    };
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|e| format!("serialize persisted: {e}"))?;
    tokio::fs::write(&cfg.state_file, &bytes)
        .await
        .map_err(|e| format!("write {}: {e}", cfg.state_file.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = tokio::fs::set_permissions(
        &cfg.state_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .await;
    tracing::info!(node_id=%resp.node_id, master=%resp.master_url, "node enrolled");
    Ok(())
}

async fn fetch_public_ip() -> Option<String> {
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args(["-fsS", "--max-time", "4", "https://api.ipify.org"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
