//! `/healthz` + `/readyz` — operational probes for load balancers,
//! monitoring, and orchestration.
//!
//! `/healthz` is liveness — does the web binary respond at all? Always
//! returns 200 if the process is up enough to handle the request.
//!
//! `/readyz` is readiness — can we reach the agent socket? Returns 503
//! if the agent is unreachable so an LB can pull this replica out of
//! rotation.

use crate::state::SharedState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use serde_json::json;

pub async fn get_healthz() -> Response {
    let body = json!({
        "status": "ok",
        "service": "hyperion-web",
        "version": env!("CARGO_PKG_VERSION"),
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

pub async fn get_readyz(State(state): State<SharedState>) -> Response {
    let started = std::time::Instant::now();
    let probe =
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            hyperion_rpc_client::call(&state.agent_socket, Request::AgentInfo).await
        })
        .await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let (status, body) = match probe {
        Ok(Ok(RpcResponse::AgentInfo(i))) => (
            StatusCode::OK,
            json!({
                "status": "ready",
                "agent": {
                    "hostname": i.hostname,
                    "version": i.version,
                    "hostings_count": i.hostings_count,
                },
                "probe_ms": elapsed_ms,
            }),
        ),
        Ok(Ok(RpcResponse::Error(e))) => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "degraded", "reason": e.to_string(), "probe_ms": elapsed_ms}),
        ),
        Ok(Ok(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "degraded", "reason": "unexpected agent response", "probe_ms": elapsed_ms}),
        ),
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "down", "reason": format!("rpc: {e}"), "probe_ms": elapsed_ms}),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "down", "reason": "agent probe timed out (>3s)", "probe_ms": elapsed_ms}),
        ),
    };
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}
