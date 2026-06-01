//! Static assets embedded into the binary so deployment is single-file.

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;

const APP_CSS: &str = include_str!("../../static/app.css");
const HTMX_JS: &str = include_str!("../../static/htmx.min.js");

pub async fn app_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        APP_CSS,
    )
}

pub async fn htmx_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        HTMX_JS,
    )
}
