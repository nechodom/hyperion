//! `/stats` — cluster, per-node, and overall stats page.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::ClusterStats;

#[derive(Template)]
#[template(path = "stats.html")]
struct StatsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    cluster: Option<ClusterStats>,
    error: Option<String>,
}

pub async fn get_stats(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let (cluster, error) = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ClusterStats,
    )
    .await
    {
        Ok(RpcResponse::ClusterStats(c)) => (Some(c), None),
        Ok(RpcResponse::Error(e)) => (None, Some(e.to_string())),
        Ok(_) => (None, Some("unexpected agent response".into())),
        Err(e) => (None, Some(format!("rpc: {e}"))),
    };
    let tpl = StatsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "stats",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        cluster,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
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
