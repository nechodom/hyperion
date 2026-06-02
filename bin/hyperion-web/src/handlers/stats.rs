//! `/stats` — cluster, per-node, and overall stats page.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{ClusterStats, NodeMetricsHistory, NodeStats};
use serde::Deserialize;

/// Inline-SVG sparkline derived from a metric series. The template
/// pastes `path_d` directly into an SVG `<path d="...">` element.
#[derive(Debug, Clone)]
pub struct Sparkline {
    /// SVG path data — single polyline from (0,h) → (w,h) baseline.
    pub path_d: String,
    /// Path for the area fill below the line (closed polygon).
    pub area_d: String,
    /// Latest sample value, formatted for display ("1.42", "73%", etc.)
    pub latest_label: String,
    /// Peak value seen in the window ("1.8 max").
    pub peak_label: String,
    /// Average value across the window.
    pub avg_label: String,
    /// "load" | "mem" | "bw" | "reqs" — drives the colour class in CSS.
    pub kind: &'static str,
    /// Whether we had enough data for a meaningful chart (≥2 samples).
    pub has_data: bool,
}

#[derive(Template)]
#[template(path = "stats.html")]
struct StatsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    cluster: Option<ClusterStats>,
    /// The node selected via `?node=<id>`; defaults to the first node
    /// when the cluster has any. None means "no nodes yet".
    selected_node: Option<NodeStats>,
    /// Inline sparkline data for the selected node.
    spark_load: Sparkline,
    spark_mem: Sparkline,
    spark_bw: Sparkline,
    spark_reqs: Sparkline,
    /// Sample window size used for sparklines (oldest..=newest).
    samples_in_window: usize,
    /// How many minutes the sparkline window covers, for the legend.
    window_minutes: i64,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct StatsQuery {
    #[serde(default)]
    node: String,
}

pub async fn get_stats(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(query): Query<StatsQuery>,
) -> Result<Response, AppError> {
    // We need both: latest snapshot (ClusterStats) + history (sparklines).
    // Fetch in parallel since they're independent.
    let cluster_fut =
        hyperion_rpc_client::call(&state.agent_socket, Request::ClusterStats);
    // ~4 hours of 5-minute samples (48 points) is a comfortable
    // sparkline width without being so dense the dots blur into noise.
    let history_fut = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NodeMetricsHistory { limit: 48 },
    );
    let (cluster_res, history_res) = tokio::join!(cluster_fut, history_fut);

    let (cluster, mut error) = match cluster_res {
        Ok(RpcResponse::ClusterStats(c)) => (Some(c), None),
        Ok(RpcResponse::Error(e)) => (None, Some(e.to_string())),
        Ok(_) => (None, Some("unexpected agent response".into())),
        Err(e) => (None, Some(format!("rpc: {e}"))),
    };

    let history: NodeMetricsHistory = match history_res {
        Ok(RpcResponse::NodeMetricsHistory(h)) => h,
        Ok(RpcResponse::Error(e)) => {
            if error.is_none() {
                error = Some(format!("history: {e}"));
            }
            NodeMetricsHistory::default()
        }
        _ => NodeMetricsHistory::default(),
    };

    let selected_node = cluster.as_ref().and_then(|c| {
        if !query.node.is_empty() {
            c.nodes.iter().find(|n| n.node_id == query.node).cloned()
        } else {
            c.nodes.first().cloned()
        }
    });

    let samples_in_window = history.samples.len();
    let window_minutes = if samples_in_window >= 2 {
        let first = history.samples.first().map(|s| s.at).unwrap_or(0);
        let last = history.samples.last().map(|s| s.at).unwrap_or(0);
        ((last - first) / 60).max(0)
    } else {
        0
    };

    let spark_load = build_sparkline(
        history.samples.iter().map(|s| s.loadavg_1m_x100 as f64 / 100.0),
        "load",
        |v| format!("{v:.2}"),
    );
    let spark_mem = build_sparkline(
        history.samples.iter().map(|s| {
            if s.mem_total_kib > 0 {
                (s.mem_used_kib as f64 / s.mem_total_kib as f64) * 100.0
            } else {
                0.0
            }
        }),
        "mem",
        |v| format!("{:.0}%", v),
    );
    let spark_bw = build_sparkline(
        history.samples.iter().map(|s| s.total_bw_out_24h as f64),
        "bw",
        |v| fmt_bytes(&(v as i64)),
    );
    let spark_reqs = build_sparkline(
        history.samples.iter().map(|s| s.total_requests_24h as f64),
        "reqs",
        |v| format!("{}", v as i64),
    );

    let tpl = StatsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "stats",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        cluster,
        selected_node,
        spark_load,
        spark_mem,
        spark_bw,
        spark_reqs,
        samples_in_window,
        window_minutes,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Generate an SVG path data string + summary stats for a series of
/// numeric samples. Auto-scales the Y axis to fit within `H`.
pub fn build_sparkline<I, F>(values: I, kind: &'static str, fmt: F) -> Sparkline
where
    I: IntoIterator<Item = f64>,
    F: Fn(f64) -> String,
{
    const W: f64 = 600.0; // viewBox width
    const H: f64 = 60.0; // viewBox height
    const PAD: f64 = 4.0; // top/bottom inset so peaks don't clip

    let vs: Vec<f64> = values.into_iter().collect();
    if vs.len() < 2 {
        return Sparkline {
            path_d: String::new(),
            area_d: String::new(),
            latest_label: "—".into(),
            peak_label: "—".into(),
            avg_label: "—".into(),
            kind,
            has_data: false,
        };
    }
    let max = vs.iter().copied().fold(f64::NEG_INFINITY, f64::max).max(0.0);
    let min = vs.iter().copied().fold(f64::INFINITY, f64::min).min(max);
    let range = (max - min).max(1e-9);
    let n = vs.len() as f64;
    let dx = W / (n - 1.0);

    let mut path = String::with_capacity(vs.len() * 16);
    for (i, &v) in vs.iter().enumerate() {
        let x = i as f64 * dx;
        let norm = (v - min) / range;
        let y = PAD + (1.0 - norm) * (H - 2.0 * PAD);
        if i == 0 {
            path.push_str(&format!("M{x:.1},{y:.1}"));
        } else {
            path.push_str(&format!(" L{x:.1},{y:.1}"));
        }
    }
    let area = format!("{path} L{:.1},{H} L0,{H} Z", W);

    let latest = *vs.last().unwrap();
    let sum: f64 = vs.iter().sum();
    let avg = sum / n;
    Sparkline {
        path_d: path,
        area_d: area,
        latest_label: fmt(latest),
        peak_label: fmt(max),
        avg_label: fmt(avg),
        kind,
        has_data: true,
    }
}

/// Format a byte count as a short string (e.g. "1.4 GiB"). Public for use
/// from other handlers + templates.
pub fn fmt_bytes(n: &i64) -> String {
    let n = *n as f64;
    let units = ["B", "kiB", "MiB", "GiB", "TiB"];
    let mut i = 0;
    let mut v = n;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", n as i64, units[i])
    } else {
        format!("{:.1} {}", v, units[i])
    }
}

/// 0-decimal percent display. Returns "?" if total == 0.
pub fn fmt_percent(num: &i64, total: &i64) -> String {
    if *total <= 0 {
        return "?".into();
    }
    let p = (*num as f64 / *total as f64 * 100.0).round() as i64;
    format!("{p}%")
}

/// Load average from the stored ×100 integer.
pub fn fmt_load(la_x100: &i64) -> String {
    format!("{:.2}", *la_x100 as f64 / 100.0)
}

/// Format a duration as "Xd Yh Zm".
pub fn fmt_uptime(secs: &i64) -> String {
    if *secs <= 0 {
        return "—".into();
    }
    let secs = *secs;
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

/// Relative timestamp display — "2m ago", "1h 30m ago", "3d ago", "12 Apr".
pub fn fmt_ago(ts: &i64) -> String {
    if *ts <= 0 {
        return "—".into();
    }
    let now = hyperion_types::now_secs();
    let delta = (now - *ts).max(0);
    if delta < 60 {
        return "just now".into();
    }
    if delta < 3600 {
        return format!("{}m ago", delta / 60);
    }
    if delta < 86400 {
        let h = delta / 3600;
        let m = (delta % 3600) / 60;
        if m > 0 && h < 6 {
            return format!("{h}h {m}m ago");
        }
        return format!("{h}h ago");
    }
    if delta < 7 * 86400 {
        let d = delta / 86400;
        return format!("{d}d ago");
    }
    // Older than a week — render a calendar date in UTC.
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(*ts, 0)
        .single()
        .map(|dt| dt.format("%d %b %Y").to_string())
        .unwrap_or_else(|| format!("{ts}"))
}

/// Truncate a long opaque ID to the first 10 chars + ellipsis. Used for
/// hosting IDs in the activity feed where a full ULID/UUIDv7 line-wraps
/// ugly. Caller is expected to put the full ID in a `title="…"`.
pub fn fmt_short_id(s: &str) -> String {
    if s.chars().count() <= 12 {
        return s.to_string();
    }
    let head: String = s.chars().take(10).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sparkline_empty_returns_placeholder() {
        let s = build_sparkline(std::iter::empty(), "load", |v| format!("{v}"));
        assert!(!s.has_data, "empty input must mark sparkline as no-data");
        assert_eq!(s.latest_label, "—");
        assert_eq!(s.peak_label, "—");
        assert_eq!(s.path_d, "");
    }

    #[test]
    fn build_sparkline_single_sample_returns_placeholder() {
        // 1 sample = no line to draw (need at least 2 endpoints).
        let s = build_sparkline(std::iter::once(1.0), "mem", |v| format!("{v}"));
        assert!(!s.has_data);
    }

    #[test]
    fn build_sparkline_two_samples_renders_line() {
        let s = build_sparkline([1.0, 3.0].into_iter(), "load", |v| format!("{v:.1}"));
        assert!(s.has_data);
        // Two points → one M + one L.
        assert!(s.path_d.starts_with('M'), "path must start with Move");
        assert!(s.path_d.contains('L'), "path must contain a Line segment");
        // Y is flipped: smaller value is lower on screen (closer to H=60).
        // First sample (1.0) is the min → y near baseline (large y).
        // Last sample (3.0) is the max → y near top (small y).
        // path_d format: "M0.0,YY.Y L600.0,YY.Y"
        assert!(s.latest_label == "3.0");
        assert!(s.peak_label == "3.0", "peak is the max");
        assert!(s.avg_label == "2.0", "avg of [1,3] is 2");
        // Area path closes back to baseline.
        assert!(s.area_d.contains("L0,60"));
        assert!(s.area_d.ends_with('Z'));
    }

    #[test]
    fn build_sparkline_flat_series_does_not_divide_by_zero() {
        // All samples equal → range collapses to 0; must not produce
        // NaN/Inf in path data.
        let s = build_sparkline([5.0, 5.0, 5.0].into_iter(), "load", |v| format!("{v}"));
        assert!(s.has_data);
        assert!(!s.path_d.contains("NaN"));
        assert!(!s.path_d.contains("inf"));
        assert_eq!(s.peak_label, "5");
        assert_eq!(s.latest_label, "5");
    }

    #[test]
    fn build_sparkline_negative_values_handled() {
        // Load avg shouldn't go negative in practice, but mem % could
        // when total=0 (we coerce to 0.0). Make sure negatives
        // don't break the path.
        let s = build_sparkline([-1.0, 0.0, 1.0].into_iter(), "load", |v| format!("{v:.1}"));
        assert!(s.has_data);
        assert_eq!(s.latest_label, "1.0");
        assert_eq!(s.peak_label, "1.0");
        // Avg = (-1 + 0 + 1)/3 = 0
        assert_eq!(s.avg_label, "0.0");
    }
}
