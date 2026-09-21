//! Core Web Vitals: measured either by Google's PageSpeed Insights API or by
//! a Lighthouse installed on the node.
//!
//! Both back ends hand back the same `lighthouseResult` shape (PSI wraps it in
//! an envelope with an extra `loadingExperience` block of real-visitor field
//! data; a local Lighthouse returns the bare result and no field data), so one
//! parser reads both. The node holds no browser of its own — Lighthouse is
//! opt-in and, like restic for snapshots, its absence is reported, not
//! installed behind the operator's back.

use crate::cmd;
use crate::AdapterError;
use hyperion_types::perf::{CwvMetrics, CwvResult};
use serde_json::Value;

/// A lab run should never hang the tick. Lighthouse and PSI both usually
/// answer within 30 s; this is the ceiling before we give up.
const MEASURE_TIMEOUT_SECS: u64 = 120;

/// Is a local Lighthouse usable on this node?
///
/// `false` is not an error — it is "this node cannot measure Core Web Vitals
/// locally", and the panel says exactly that with the install hint.
pub async fn lighthouse_available() -> bool {
    // `lighthouse --version` prints the version and exits 0 when the CLI and
    // its Node runtime are both present. It does not launch Chrome, so it is
    // cheap and does not need --no-sandbox.
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            cmd::run("/usr/bin/env", &["lighthouse", "--version"]),
        )
        .await,
        Ok(Ok(_))
    )
}

/// Which profile a lab run emulates.
#[derive(Debug, Clone, Copy)]
pub enum Strategy {
    Mobile,
    Desktop,
}

impl Strategy {
    fn as_str(self) -> &'static str {
        match self {
            Strategy::Mobile => "mobile",
            Strategy::Desktop => "desktop",
        }
    }
    /// Lighthouse spells the mobile profile differently from PSI.
    fn lighthouse_form_factor(self) -> &'static str {
        match self {
            Strategy::Mobile => "mobile",
            Strategy::Desktop => "desktop",
        }
    }
}

/// Only a syntactically valid `https://…` public URL is ever measured. The
/// domain reaches a command line (Lighthouse) and a query string (PSI); a
/// stray space or a `file://`/`http://localhost` would either fail or point
/// the measurement somewhere it should not go.
fn valid_target(url: &str) -> bool {
    url.starts_with("https://")
        && url.len() < 2000
        && !url.contains(char::is_whitespace)
        && !url.contains(['"', '\'', '\\', '<', '>', '`'])
}

/// Measure via Google PageSpeed Insights.
///
/// The API key rides in the request on curl's stdin config, never on argv or
/// in a log — the same discipline every other credential on the node follows.
/// An empty key is allowed: PSI answers keyless at a low rate limit, which is
/// enough for a once-a-week-per-site cadence.
pub async fn measure_psi(
    url: &str,
    api_key: &str,
    strategy: Strategy,
) -> Result<CwvResult, AdapterError> {
    if !valid_target(url) {
        return Err(AdapterError::Other(format!("not a measurable URL: {url:?}")));
    }
    let mut endpoint = format!(
        "https://www.googleapis.com/pagespeedonline/v5/runPagespeed\
         ?url={}&strategy={}&category=performance",
        urlencode(url),
        strategy.as_str()
    );
    if !api_key.trim().is_empty() {
        endpoint.push_str(&format!("&key={}", urlencode(api_key.trim())));
    }
    // curl config on stdin: the key never reaches argv or the error string.
    let config = format!(
        "url = \"{}\"\n\
         max-time = 60\n\
         compressed\n\
         user-agent = \"Hyperion-Performance/1\"\n",
        cmd::curl_config_quote(&endpoint)
    );
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(MEASURE_TIMEOUT_SECS),
        cmd::curl_with_config(&config),
    )
    .await
    .map_err(|_| AdapterError::Other("PageSpeed Insights timed out".into()))??;

    let json: Value = serde_json::from_str(&body)
        .map_err(|e| AdapterError::Other(format!("PageSpeed Insights returned non-JSON ({e})")))?;
    // The API reports its own errors in a JSON envelope rather than an HTTP
    // status curl would flag — surface that message, not a parse failure.
    if let Some(msg) = json
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
    {
        return Err(AdapterError::Other(format!(
            "PageSpeed Insights refused the request: {msg}"
        )));
    }
    let mut result = parse_lighthouse_result(json.get("lighthouseResult").unwrap_or(&Value::Null));
    result.source = "psi".into();
    result.strategy = strategy.as_str().into();
    result.field = parse_field(json.get("loadingExperience"));
    if !result.has_data() {
        return Err(AdapterError::Other(
            "PageSpeed Insights returned no usable metrics".into(),
        ));
    }
    Ok(result)
}

/// Measure via a local Lighthouse.
pub async fn measure_lighthouse(url: &str, strategy: Strategy) -> Result<CwvResult, AdapterError> {
    if !valid_target(url) {
        return Err(AdapterError::Other(format!("not a measurable URL: {url:?}")));
    }
    // Chrome as root refuses to sandbox itself, and the hyperion agent is
    // root; --no-sandbox is required and safe here because the page fetched
    // is the operator's own site, not attacker input.
    let args = [
        "lighthouse",
        url,
        "--quiet",
        "--output=json",
        "--only-categories=performance",
        "--form-factor",
        strategy.lighthouse_form_factor(),
        "--chrome-flags=--headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage",
        "--max-wait-for-load=45000",
    ];
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(MEASURE_TIMEOUT_SECS),
        cmd::run("/usr/bin/env", &args),
    )
    .await
    .map_err(|_| AdapterError::Other("Lighthouse timed out".into()))??;

    // Lighthouse prints only the JSON on stdout with `--output=json --quiet`,
    // but a stray warning line has been seen; take from the first `{`.
    let start = out
        .find('{')
        .ok_or_else(|| AdapterError::Other("Lighthouse produced no JSON".into()))?;
    let json: Value = serde_json::from_str(&out[start..])
        .map_err(|e| AdapterError::Other(format!("Lighthouse returned non-JSON ({e})")))?;
    if let Some(msg) = json
        .get("runtimeError")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
    {
        return Err(AdapterError::Other(format!("Lighthouse could not load the page: {msg}")));
    }
    let mut result = parse_lighthouse_result(&json);
    result.source = "lighthouse".into();
    result.strategy = strategy.as_str().into();
    if !result.has_data() {
        return Err(AdapterError::Other("Lighthouse returned no usable metrics".into()));
    }
    Ok(result)
}

/// Read the LAB half out of a `lighthouseResult` object (PSI's inner object,
/// or a local Lighthouse's whole output). Fills only `lab` and `perf_score`.
fn parse_lighthouse_result(lr: &Value) -> CwvResult {
    let audit_ms = |id: &str| {
        lr.get("audits")
            .and_then(|a| a.get(id))
            .and_then(|a| a.get("numericValue"))
            .and_then(Value::as_f64)
            .map(|v| v.round() as i64)
    };
    let lab = CwvMetrics {
        lcp_ms: audit_ms("largest-contentful-paint"),
        // CLS's numericValue is the unitless score (e.g. 0.05); store ×1000.
        cls_x1000: lr
            .get("audits")
            .and_then(|a| a.get("cumulative-layout-shift"))
            .and_then(|a| a.get("numericValue"))
            .and_then(Value::as_f64)
            .map(|v| (v * 1000.0).round() as i64),
        inp_ms: None,
        tbt_ms: audit_ms("total-blocking-time"),
        fcp_ms: audit_ms("first-contentful-paint"),
    };
    let perf_score = lr
        .get("categories")
        .and_then(|c| c.get("performance"))
        .and_then(|p| p.get("score"))
        .and_then(Value::as_f64)
        .map(|v| (v * 100.0).round() as i64);
    CwvResult {
        lab: (!lab.is_empty()).then_some(lab),
        perf_score,
        ..Default::default()
    }
}

/// Read the FIELD half (real-visitor CrUX data) out of PSI's
/// `loadingExperience`. `None` when the site has too little traffic for it.
fn parse_field(le: Option<&Value>) -> Option<CwvMetrics> {
    let metrics = le?.get("metrics")?;
    let percentile = |id: &str| {
        metrics
            .get(id)
            .and_then(|m| m.get("percentile"))
            .and_then(Value::as_i64)
    };
    let field = CwvMetrics {
        lcp_ms: percentile("LARGEST_CONTENTFUL_PAINT_MS"),
        // The CrUX CLS percentile is the score ×100 (a "10" means 0.10); ×10
        // lands it in our ×1000 units.
        cls_x1000: percentile("CUMULATIVE_LAYOUT_SHIFT_SCORE").map(|v| v * 10),
        inp_ms: percentile("INTERACTION_TO_NEXT_PAINT"),
        tbt_ms: None,
        fcp_ms: percentile("FIRST_CONTENTFUL_PAINT_MS"),
    };
    (!field.is_empty()).then_some(field)
}

/// Percent-encode for a query-string value. Small and dependency-free: the
/// inputs are a URL and an API key, both already narrow.
fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_target_rejects_anything_that_is_not_a_plain_https_url() {
        assert!(valid_target("https://example.cz/"));
        assert!(!valid_target("http://example.cz/"));
        assert!(!valid_target("https://example.cz/ a"));
        assert!(!valid_target("https://example.cz/\"; rm -rf"));
        assert!(!valid_target("file:///etc/passwd"));
    }

    #[test]
    fn a_psi_envelope_parses_into_lab_and_field() {
        let body = r#"{
          "lighthouseResult": {
            "categories": { "performance": { "score": 0.86 } },
            "audits": {
              "largest-contentful-paint": { "numericValue": 2450.4 },
              "cumulative-layout-shift": { "numericValue": 0.052 },
              "total-blocking-time": { "numericValue": 180 },
              "first-contentful-paint": { "numericValue": 1200 }
            }
          },
          "loadingExperience": {
            "metrics": {
              "LARGEST_CONTENTFUL_PAINT_MS": { "percentile": 2600 },
              "CUMULATIVE_LAYOUT_SHIFT_SCORE": { "percentile": 8 },
              "INTERACTION_TO_NEXT_PAINT": { "percentile": 190 }
            }
          }
        }"#;
        let json: Value = serde_json::from_str(body).unwrap();
        let mut r = parse_lighthouse_result(json.get("lighthouseResult").unwrap());
        r.field = parse_field(json.get("loadingExperience"));
        let lab = r.lab.as_ref().unwrap();
        assert_eq!(lab.lcp_ms, Some(2450));
        assert_eq!(lab.cls_x1000, Some(52));
        assert_eq!(lab.tbt_ms, Some(180));
        assert_eq!(lab.fcp_ms, Some(1200));
        assert_eq!(r.perf_score, Some(86));
        let field = r.field.as_ref().unwrap();
        assert_eq!(field.lcp_ms, Some(2600));
        assert_eq!(field.cls_x1000, Some(80)); // 8 → 0.08 → 80/1000
        assert_eq!(field.inp_ms, Some(190));
        assert!(r.best_is_field());
    }

    #[test]
    fn a_bare_lighthouse_output_has_no_field_data() {
        let body = r#"{
          "categories": { "performance": { "score": 0.5 } },
          "audits": { "largest-contentful-paint": { "numericValue": 4100 } }
        }"#;
        let json: Value = serde_json::from_str(body).unwrap();
        let r = parse_lighthouse_result(&json);
        assert_eq!(r.lab.as_ref().unwrap().lcp_ms, Some(4100));
        assert_eq!(r.perf_score, Some(50));
        assert!(parse_field(None).is_none());
    }

    #[test]
    fn missing_metrics_stay_none_rather_than_zero() {
        let json: Value = serde_json::from_str(r#"{"audits":{}}"#).unwrap();
        let r = parse_lighthouse_result(&json);
        assert!(r.lab.is_none(), "no audits means no lab block, not a zeroed one");
    }
}
