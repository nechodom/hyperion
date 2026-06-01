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
    secret: String,
}

#[derive(Deserialize, Serialize)]
pub struct PersistedNodeId {
    pub node_id: String,
    pub master_url: String,
    #[serde(default)]
    pub secret: String,
    pub enrolled_at: i64,
}

/// Load the persisted node identity if present.
pub async fn load_persisted(path: &std::path::Path) -> Option<PersistedNodeId> {
    let bytes = tokio::fs::read(path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
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
        secret: resp.secret.clone(),
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

/// Background heartbeat loop. Reads the persisted node-id file every
/// `period_secs` and POSTs {node_id, secret, agent_version} to
/// `<master>/api/heartbeat`. Single error → log + retry next tick.
pub async fn heartbeat_loop(state_file: std::path::PathBuf, period_secs: u64) {
    let agent_version = env!("CARGO_PKG_VERSION");
    let period = std::time::Duration::from_secs(period_secs);
    let mut interval = tokio::time::interval(period);
    // First tick fires immediately — skip it so we wait one period after
    // enrollment before phoning home.
    interval.tick().await;
    loop {
        interval.tick().await;
        let p = match load_persisted(&state_file).await {
            Some(p) if !p.secret.is_empty() => p,
            _ => continue, // not enrolled yet, or pre-secret deploy
        };
        let url = format!("{}/api/heartbeat", p.master_url.trim_end_matches('/'));
        let body = match serde_json::to_string(&serde_json::json!({
            "node_id": p.node_id,
            "secret": p.secret,
            "agent_version": agent_version,
        })) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error=%e, "heartbeat serialize");
                continue;
            }
        };
        let result = tokio::process::Command::new("/usr/bin/curl")
            .args([
                "-fsS",
                "--max-time",
                "8",
                "-X",
                "POST",
                "-H",
                "content-type: application/json",
                "--data",
                &body,
                &url,
            ])
            .output()
            .await;
        match result {
            Ok(out) if out.status.success() => {
                tracing::debug!(node = %p.node_id, master = %p.master_url, "heartbeat ok");
            }
            Ok(out) => {
                tracing::warn!(
                    code = ?out.status.code(),
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "heartbeat returned non-zero — will retry"
                );
            }
            Err(e) => tracing::warn!(error=%e, "heartbeat curl failed"),
        }
    }
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
