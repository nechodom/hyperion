//! Static assets embedded into the binary so deployment is single-file.
//!
//! Every asset is linked as `/static/<name>?v=<hash>`, so its URL changes
//! whenever its content does and the response can be cached forever
//! (`immutable`, one year). On top of that:
//!
//! * a gzip copy is built ONCE per process (the content never changes while
//!   it runs) and served to every browser that accepts it — the stylesheet
//!   is ~200 KB raw, a fraction of that compressed;
//! * the hash doubles as a strong `ETag`, so a revalidation (a hard reload,
//!   a proxy that ignores `immutable`) is answered `304` with no body.
//!
//! HTML pages are deliberately NOT compressed: they carry CSRF tokens next
//! to text an attacker can influence (search boxes, domains), which is the
//! BREACH setup. These files are identical for everyone and hold no secret.

use std::io::Write;
use std::sync::OnceLock;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const APP_CSS: &str = include_str!("../../static/app.css");
const APP_JS: &str = include_str!("../../static/app.js");
const HTMX_JS: &str = include_str!("../../static/htmx.min.js");

const CSS_TYPE: &str = "text/css; charset=utf-8";
const JS_TYPE: &str = "application/javascript; charset=utf-8";

struct Asset {
    raw: &'static str,
    /// 12 hex chars of BLAKE3 — the `?v=` value and (quoted) the ETag.
    version: String,
    etag: HeaderValue,
    /// `None` when compressing did not make it smaller (never, for text
    /// this size, but a failed encoder must not take the asset down).
    gzip: Option<Vec<u8>>,
}

impl Asset {
    fn build(raw: &'static str) -> Self {
        let version = hex::encode(&blake3::hash(raw.as_bytes()).as_bytes()[..6]);
        // Quoted hex is always a valid header value; the fallback is only
        // there so this can never panic.
        let etag = HeaderValue::from_str(&format!("\"{version}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("\"0\""));
        Asset {
            raw,
            version,
            etag,
            gzip: gzip(raw.as_bytes()).filter(|z| z.len() < raw.len()),
        }
    }
}

fn gzip(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(bytes).ok()?;
    enc.finish().ok()
}

fn css() -> &'static Asset {
    static A: OnceLock<Asset> = OnceLock::new();
    A.get_or_init(|| Asset::build(APP_CSS))
}

fn app_js() -> &'static Asset {
    static A: OnceLock<Asset> = OnceLock::new();
    A.get_or_init(|| Asset::build(APP_JS))
}

fn htmx() -> &'static Asset {
    static A: OnceLock<Asset> = OnceLock::new();
    A.get_or_init(|| Asset::build(HTMX_JS))
}

/// `?v=` for `/static/app.css` — a redeploy with a changed stylesheet busts
/// the browser cache automatically.
pub fn css_version() -> &'static str {
    &css().version
}

/// `?v=` for `/static/htmx.min.js`.
pub fn htmx_version() -> &'static str {
    &htmx().version
}

/// `?v=` for `/static/app.js`. Called straight from base.html, so pages
/// need no extra template field for it.
pub fn app_js_version() -> &'static str {
    &app_js().version
}

/// Does `Accept-Encoding` allow gzip? `gzip;q=0` is an explicit refusal.
fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|item| {
            let mut parts = item.split(';').map(str::trim);
            let coding = parts.next().unwrap_or_default();
            let refused = parts.any(|p| {
                p.strip_prefix("q=")
                    .and_then(|q| q.parse::<f32>().ok())
                    .is_some_and(|q| q == 0.0)
            });
            (coding.eq_ignore_ascii_case("gzip") || coding == "*") && !refused
        })
}

/// Does `If-None-Match` already name this version?
fn not_modified(headers: &HeaderMap, etag: &HeaderValue) -> bool {
    let Some(want) = etag.to_str().ok() else {
        return false;
    };
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().trim_start_matches("W/"))
        .any(|t| t == want || t == "*")
}

fn serve(asset: &'static Asset, content_type: &'static str, headers: &HeaderMap) -> Response {
    let common = [
        (
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        ),
        (header::ETAG, asset.etag.clone()),
        // A cache in between must key on the encoding, or a gzip body
        // could be handed to a client that never asked for one.
        (header::VARY, HeaderValue::from_static("Accept-Encoding")),
    ];
    if not_modified(headers, &asset.etag) {
        return (StatusCode::NOT_MODIFIED, common).into_response();
    }
    let ct = (header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    match &asset.gzip {
        Some(z) if accepts_gzip(headers) => (
            StatusCode::OK,
            common,
            [
                ct,
                (header::CONTENT_ENCODING, HeaderValue::from_static("gzip")),
            ],
            z.as_slice(),
        )
            .into_response(),
        _ => (StatusCode::OK, common, [ct], asset.raw).into_response(),
    }
}

pub async fn app_css(headers: HeaderMap) -> Response {
    serve(css(), CSS_TYPE, &headers)
}

pub async fn app_js_handler(headers: HeaderMap) -> Response {
    serve(app_js(), JS_TYPE, &headers)
}

pub async fn htmx_js(headers: HeaderMap) -> Response {
    serve(htmx(), JS_TYPE, &headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: header::HeaderName, v: &'static str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(name, HeaderValue::from_static(v));
        m
    }

    #[test]
    fn gzip_negotiation() {
        assert!(accepts_gzip(&h(
            header::ACCEPT_ENCODING,
            "gzip, deflate, br"
        )));
        assert!(accepts_gzip(&h(
            header::ACCEPT_ENCODING,
            "br;q=1.0, GZIP;q=0.5"
        )));
        assert!(accepts_gzip(&h(header::ACCEPT_ENCODING, "*")));
        assert!(!accepts_gzip(&h(header::ACCEPT_ENCODING, "gzip;q=0")));
        assert!(!accepts_gzip(&h(header::ACCEPT_ENCODING, "br, deflate")));
        assert!(!accepts_gzip(&HeaderMap::new()));
    }

    #[test]
    fn assets_compress_and_round_trip() {
        for a in [css(), app_js(), htmx()] {
            let z = a.gzip.as_ref().expect("text this size compresses");
            assert!(z.len() < a.raw.len() / 2, "gzip should at least halve it");
            let mut out = String::new();
            std::io::Read::read_to_string(
                &mut flate2::read::GzDecoder::new(z.as_slice()),
                &mut out,
            )
            .expect("valid gzip");
            assert_eq!(out, a.raw);
        }
    }

    #[test]
    fn etag_revalidation() {
        let a = css();
        let tag: &'static str = Box::leak(format!("\"{}\"", a.version).into_boxed_str());
        assert!(not_modified(&h(header::IF_NONE_MATCH, tag), &a.etag));
        assert!(not_modified(
            &h(header::IF_NONE_MATCH, "\"zzz\", *"),
            &a.etag
        ));
        assert!(!not_modified(&h(header::IF_NONE_MATCH, "\"zzz\""), &a.etag));
        assert!(!not_modified(&HeaderMap::new(), &a.etag));
        let resp = serve(a, CSS_TYPE, &h(header::IF_NONE_MATCH, tag));
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        let resp = serve(a, CSS_TYPE, &h(header::ACCEPT_ENCODING, "gzip"));
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "gzip");
        let resp = serve(a, CSS_TYPE, &HeaderMap::new());
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
    }
}
