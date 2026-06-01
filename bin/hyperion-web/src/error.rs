//! Unified error type for handlers.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not authenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("agent rpc: {0}")]
    Rpc(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AppError::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "<h1>401 Unauthorized</h1>".to_string(),
            ),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "<h1>403 Forbidden</h1>".to_string()),
            AppError::BadRequest(m) => (
                StatusCode::BAD_REQUEST,
                format!("<h1>400 Bad Request</h1><p>{m}</p>"),
            ),
            AppError::NotFound => (StatusCode::NOT_FOUND, "<h1>404 Not Found</h1>".to_string()),
            AppError::Rpc(m) => (
                StatusCode::BAD_GATEWAY,
                format!("<h1>502 Bad Gateway</h1><p>agent rpc: {m}</p>"),
            ),
            AppError::Internal(m) => {
                tracing::error!(error=%m, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "<h1>500 Internal Server Error</h1>".to_string(),
                )
            }
        };
        (status, [("content-type", "text/html; charset=utf-8")], body).into_response()
    }
}

impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        AppError::Internal(format!("template: {e}"))
    }
}

impl From<hyperion_rpc_client::ClientError> for AppError {
    fn from(e: hyperion_rpc_client::ClientError) -> Self {
        AppError::Rpc(e.to_string())
    }
}

impl From<hyperion_validate::ValidationError> for AppError {
    fn from(e: hyperion_validate::ValidationError) -> Self {
        AppError::BadRequest(e.to_string())
    }
}
