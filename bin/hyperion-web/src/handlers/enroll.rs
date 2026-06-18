//! `/api/enroll` — node enrollment endpoint.
//!
//! No session auth: the invite token IS the bearer credential. Calling
//! agents POST this once on first boot, then persist the returned
//! `node_id` to disk. Subsequent boots skip enrollment (until the
//! operator deletes the local marker).

use crate::error::AppError;
use crate::ratelimit::Bucket;
use crate::state::SharedState;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Effective IP for rate-limit bucketing. Prefers `X-Forwarded-For`
/// (when hyperion-web sits behind nginx / cloudflare), falls back to
/// `X-Real-IP`, then to the connection peer.
///
/// Bucketing per-source-IP only matters when the deployment topology
/// actually exposes a per-client IP. In a deployment where every
/// request lands at hyperion-web from the same upstream proxy WITHOUT
/// X-Forwarded-For propagation, all requests will share a bucket —
/// which is the safer-default failure mode (over-limit) than the
/// alternative of no limit at all.
fn effective_ip(headers: &HeaderMap, peer: SocketAddr) -> std::net::IpAddr {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            if let Ok(ip) = first.trim().parse() {
                return ip;
            }
        }
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = v.trim().parse() {
            return ip;
        }
    }
    peer.ip()
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    /// Human-friendly label the node wants to be known as.
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub agent_version: String,
    #[serde(default)]
    pub public_ip: Option<String>,
    /// Block B idempotent re-enrollment: the node_id + per-node secret the
    /// re-enrolling box already had on disk. The master reuses the id on a
    /// matching secret, adopts a free id, else mints fresh. `serde(default)`
    /// keeps first-time enrollers (no prior identity) working.
    #[serde(default)]
    pub prior_node_id: Option<String>,
    #[serde(default)]
    pub prior_secret: Option<String>,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub node_id: String,
    pub master_url: String,
    /// Per-node shared secret for ongoing heartbeats. Returned once.
    pub secret: String,
    /// Base64 of the master's Ed25519 public key for the master→
    /// node remote-RPC channel. `None` when the master hasn't been
    /// upgraded to support remote RPC; nodes ignore in that case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_rpc_pubkey: Option<String>,
}

pub async fn post_enroll(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Result<Response, AppError> {
    // Rate-limit per source IP: enroll is a one-time event per node
    // lifetime, so 5/min is extremely generous and still pinches off
    // any kind of token-fuzzing flood.
    let ip = effective_ip(&headers, peer);
    if !state.ratelimit.check("enroll", ip, Bucket::per_minute(5)) {
        return Err(AppError::TooManyRequests(
            "enrollment rate limit exceeded — try again shortly".into(),
        ));
    }
    if req.token.trim().is_empty() {
        return Err(AppError::BadRequest("missing token".into()));
    }
    let label = if req.label.trim().is_empty() {
        "node".to_string()
    } else {
        req.label.trim().to_string()
    };
    // Caller IP (best-effort) for the consumed-by-ip field.
    let caller_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Candidate id for a fresh enrollment; the master may instead reuse the
    // box's prior id (idempotent re-enroll) and echo that back.
    let candidate_node_id = format!("node_{}", ulid::Ulid::new());
    let outcome = consume_and_register(
        &state,
        &req.token,
        &caller_ip,
        &candidate_node_id,
        &label,
        &req.agent_version,
        req.public_ip.as_deref(),
        req.prior_node_id.as_deref(),
        req.prior_secret.as_deref(),
    )
    .await;
    match outcome {
        Ok((node_id, secret, master_rpc_pubkey)) => {
            let master_url = derive_master_from_headers(&headers, &state);
            Ok(Json(EnrollResponse {
                node_id,
                master_url,
                secret,
                master_rpc_pubkey,
            })
            .into_response())
        }
        Err(e) => Err(AppError::BadRequest(format!("enrollment refused: {e}"))),
    }
}

async fn consume_and_register(
    state: &SharedState,
    token: &str,
    caller_ip: &str,
    node_id: &str,
    label: &str,
    agent_version: &str,
    public_ip: Option<&str>,
    prior_node_id: Option<&str>,
    prior_secret: Option<&str>,
) -> Result<(String, String, Option<String>), String> {
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EnrollConsume {
            token: token.to_string(),
            caller_ip: caller_ip.to_string(),
            node_id: node_id.to_string(),
            label: label.to_string(),
            agent_version: agent_version.to_string(),
            public_ip: public_ip.map(String::from),
            prior_node_id: prior_node_id.map(String::from),
            prior_secret: prior_secret.map(String::from),
        },
    )
    .await
    .map_err(|e| format!("rpc: {e}"))?;
    match resp {
        RpcResponse::EnrollConsume {
            node_id,
            secret,
            master_rpc_pubkey,
        } => Ok((node_id, secret, master_rpc_pubkey)),
        RpcResponse::Error(e) => Err(e.to_string()),
        _ => Err("unexpected response".into()),
    }
}

/// Periodic heartbeat — node POSTs {node_id, secret, agent_version}.
#[derive(serde::Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub secret: String,
    #[serde(default)]
    pub agent_version: String,
    /// Worker's inbound TLS SPKI pin (Block C, warn-only). `#[serde(default)]`
    /// so older agents that don't send it still post valid heartbeats.
    #[serde(default)]
    pub tls_spki_pin: Option<String>,
}

pub async fn post_heartbeat(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Response, AppError> {
    // 60/min per IP: nodes heartbeat every 60s so a generous cap
    // tolerates up to ~60 distinct nodes behind a single NAT before
    // we'd start dropping. Realistic deployments have at most a
    // handful — anything well above that is fuzzing / enumeration.
    let ip = effective_ip(&headers, peer);
    if !state
        .ratelimit
        .check("heartbeat", ip, Bucket::per_minute(60))
    {
        return Err(AppError::TooManyRequests(
            "heartbeat rate limit exceeded".into(),
        ));
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NodeHeartbeat {
            node_id: req.node_id,
            secret: req.secret,
            agent_version: req.agent_version,
            tls_spki_pin: req.tls_spki_pin,
        },
    )
    .await?;
    match resp {
        RpcResponse::NodeHeartbeat { master_rpc_pubkey } => {
            // Echo the master's remote-RPC pubkey back to the node
            // on every heartbeat ack. Nodes that were enrolled
            // before remote-RPC existed will pick it up here and
            // persist it without needing to re-enroll.
            let mut body = serde_json::json!({"status":"ok"});
            if let Some(pk) = master_rpc_pubkey {
                body["master_rpc_pubkey"] = serde_json::Value::String(pk);
            }
            Ok(Json(body).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::BadRequest(format!("heartbeat refused: {e}"))),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

fn derive_master_from_headers(headers: &HeaderMap, state: &SharedState) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| {
            if state.cfg.web.secure_cookies {
                "https".into()
            } else {
                "http".into()
            }
        });
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| state.cfg.web.listen.clone());
    format!("{scheme}://{host}")
}
