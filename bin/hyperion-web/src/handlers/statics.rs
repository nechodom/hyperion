//! Static assets embedded into the binary so deployment is single-file.

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;

const APP_CSS: &str = include_str!("../../static/app.css");
const HTMX_JS: &str = include_str!("../../static/htmx.min.js");

/// BLAKE3-prefix hash of the embedded CSS. Used as a `?v=…` query string
/// on every `<link>` so a redeploy busts the browser cache automatically.
/// Computed once on first access.
pub fn css_version() -> &'static str {
    static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    V.get_or_init(|| hex::encode(&blake3::hash(APP_CSS.as_bytes()).as_bytes()[..6]))
}

/// Same idea for the HTMX bundle so swapping its version invalidates cleanly.
pub fn htmx_version() -> &'static str {
    static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    V.get_or_init(|| hex::encode(&blake3::hash(HTMX_JS.as_bytes()).as_bytes()[..6]))
}

pub async fn app_css() -> impl IntoResponse {
    // immutable + 1 year — the `?v=<hash>` query forces a new URL whenever
    // the file content changes, so the cache CAN safely be forever.
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
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
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        HTMX_JS,
    )
}
