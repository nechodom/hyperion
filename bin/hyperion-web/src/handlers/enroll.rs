//! `/api/enroll` — node enrollment endpoint.
//!
//! No session auth: the invite token IS the bearer credential. Calling
//! agents POST this once on first boot, then persist the returned
//! `node_id` to disk. Subsequent boots skip enrollment (until the
//! operator deletes the local marker).

use crate::error::AppError;
use crate::state::SharedState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use serde::{Deserialize, Serialize};

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
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub node_id: String,
    pub master_url: String,
}

pub async fn post_enroll(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Result<Response, AppError> {
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

    let node_id = format!("node_{}", ulid::Ulid::new());
    let outcome = consume_and_register(
        &state,
        &req.token,
        &caller_ip,
        &node_id,
        &label,
        &req.agent_version,
        req.public_ip.as_deref(),
    )
    .await;
    match outcome {
        Ok(()) => {
            let master_url = derive_master_from_headers(&headers, &state);
            Ok(Json(EnrollResponse {
                node_id,
                master_url,
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
) -> Result<(), String> {
    // The web binary doesn't hold the agent's SqlitePool directly. We use
    // two new RPC methods: InviteConsume + NodeInsert. For Foundation
    // simplicity these are wired through the existing socket. If we wanted
    // to skip the round-trip we'd hand the SharedState a pool ref.
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EnrollConsume {
            token: token.to_string(),
            caller_ip: caller_ip.to_string(),
            node_id: node_id.to_string(),
            label: label.to_string(),
            agent_version: agent_version.to_string(),
            public_ip: public_ip.map(String::from),
        },
    )
    .await
    .map_err(|e| format!("rpc: {e}"))?;
    match resp {
        RpcResponse::EnrollConsume => Ok(()),
        RpcResponse::Error(e) => Err(e.to_string()),
        _ => Err("unexpected response".into()),
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
