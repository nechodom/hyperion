//! Notification centre: the bell dropdown in base.html and the
//! `/notifications` archive.
//!
//! Three JSON endpoints back the dropdown:
//!   - GET  /api/notifications/feed?limit=10
//!   - POST /api/notifications/mark-read   { id }
//!   - POST /api/notifications/mark-all-read
//!
//! All three require an authenticated session (any role) and scope
//! every query to the session's user_id. RPC layer enforces the
//! same scoping at the DB level — so a malicious user can't mark
//! someone else's notification read even if they craft the body.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use axum::Json;
use hyperion_rpc::{Request, Response as RpcResponse};
use serde::Deserialize;
use std::collections::HashMap;

/// Rows per archive page; "Older" pages on with a keyset cursor.
const PAGE: i64 = 100;

#[derive(Template)]
#[template(path = "notifications.html")]
struct NotificationsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    /// "Does anything need me?" — over the whole archive, never the filter,
    /// so narrowing the list cannot hide an unread error.
    verdict: String,
    verdict_tone: &'static str,
    /// Where the verdict's "latest" points, when it names one.
    verdict_href: Option<String>,
    days: Vec<DayGroup>,
    counts: hyperion_types::NotificationCounts,
    /// `(key, label with count, selected)`.
    topics: Vec<(String, String, bool)>,
    q: String,
    topic: String,
    show: String,
    seg_hrefs: SegHrefs,
    /// Next page, when more rows match.
    older_href: Option<String>,
    /// Paged past the first page.
    paged: bool,
    first_href: String,
    /// Nothing in the archive at all (as opposed to nothing matching).
    archive_empty: bool,
    /// Any filter beyond the defaults — the mark button then says "these".
    filtered: bool,
    /// This page's URL, for the per-row "mark read" to come back to.
    here: String,
}

pub struct Row {
    pub id: i64,
    /// `err` | `warn` | `info` — CSS tone.
    pub tone: &'static str,
    pub severity_label: &'static str,
    pub title: String,
    pub body: String,
    pub topic_label: &'static str,
    pub node: Option<String>,
    pub unread: bool,
    pub ago: String,
    pub abs: String,
    /// Through `/notifications/<id>/open`, which marks it read first. None
    /// when the row links nowhere useful (the dashboard root).
    pub open_href: Option<String>,
}

pub struct DayGroup {
    pub label: String,
    pub rows: Vec<Row>,
}

pub struct SegHrefs {
    pub all: String,
    pub unread: String,
    pub error: String,
    pub warn: String,
    pub info: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct ArchiveQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub topic: String,
    /// `unread` | `error` | `warn` | `info`; anything else = all.
    #[serde(default)]
    pub show: String,
    /// `<created_at>.<id>` of the last row on the previous page.
    #[serde(default)]
    pub before: String,
}

impl ArchiveQuery {
    fn show(&self) -> &'static str {
        match self.show.trim() {
            "unread" => "unread",
            "error" => "error",
            "warn" => "warn",
            "info" => "info",
            _ => "",
        }
    }

    fn before(&self) -> Option<(i64, i64)> {
        let (ts, id) = self.before.trim().split_once('.')?;
        Some((ts.parse().ok()?, id.parse().ok()?))
    }

    fn filter(&self, limit: i64) -> hyperion_types::NotificationSearchFilter {
        let show = self.show();
        hyperion_types::NotificationSearchFilter {
            q: self.q.trim().to_string(),
            severity: if show == "unread" { "" } else { show }.to_string(),
            unread_only: show == "unread",
            topic: self.topic.trim().to_string(),
            before: self.before(),
            limit,
        }
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// `/notifications` with the given filters; empty ones are left out.
fn archive_href(show: &str, topic: &str, q: &str, before: &str) -> String {
    let parts: Vec<String> = [
        ("show", show),
        ("topic", topic),
        ("q", q),
        ("before", before),
    ]
    .into_iter()
    .filter(|(_, v)| !v.is_empty())
    .map(|(k, v)| format!("{k}={}", urlencode(v)))
    .collect();
    if parts.is_empty() {
        "/notifications".into()
    } else {
        format!("/notifications?{}", parts.join("&"))
    }
}

async fn search(
    state: &SharedState,
    user_id: i64,
    filter: hyperion_types::NotificationSearchFilter,
) -> Result<hyperion_types::NotificationSearchResult, AppError> {
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsSearch { user_id, filter },
    )
    .await
    .map_err(AppError::from)?
    {
        RpcResponse::NotificationsSearch(r) => Ok(r),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

fn plural(n: i64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// Headline from the whole archive's counts plus the newest unread error.
fn verdict(
    c: &hyperion_types::NotificationCounts,
    latest_error: Option<&hyperion_types::NotificationView>,
    newest: Option<i64>,
) -> (String, &'static str) {
    if c.unread_error > 0 {
        let mut s = plural(c.unread_error, "unread error", "unread errors");
        let rest = c.unread - c.unread_error;
        if rest > 0 {
            s.push_str(&format!(" · {} more unread", rest));
        }
        if let Some(n) = latest_error {
            s.push_str(&format!(
                " — latest: {} ({})",
                n.title,
                crate::handlers::stats::fmt_ago(&n.created_at)
            ));
        }
        (s, "err")
    } else if c.unread > 0 {
        (
            format!(
                "{} — none of them an error",
                plural(c.unread, "unread notification", "unread notifications")
            ),
            "warn",
        )
    } else if let Some(ts) = newest {
        (
            format!(
                "All read · last notification {}",
                crate::handlers::stats::fmt_ago(&ts)
            ),
            "ok",
        )
    } else {
        ("No notifications yet".into(), "muted")
    }
}

fn open_href(n: &hyperion_types::NotificationView) -> Option<String> {
    (is_internal_href(&n.href) && n.href != "/").then(|| format!("/notifications/{}/open", n.id))
}

fn row(n: hyperion_types::NotificationView, nodes: &HashMap<String, String>) -> Row {
    let (tone, severity_label) = match n.severity.as_str() {
        "error" => ("err", "Error"),
        "warn" => ("warn", "Warning"),
        _ => ("info", "Info"),
    };
    Row {
        open_href: open_href(&n),
        id: n.id,
        tone,
        severity_label,
        topic_label: hyperion_types::notification_topic(&n.kind).1,
        node: (!n.node_id.is_empty())
            .then(|| nodes.get(&n.node_id).cloned().unwrap_or(n.node_id.clone())),
        unread: n.read_at.is_none(),
        ago: crate::handlers::stats::fmt_ago(&n.created_at),
        abs: crate::handlers::emails::fmt_local(n.created_at, "%Y-%m-%d %H:%M:%S"),
        title: n.title,
        body: n.body,
    }
}

/// A link that stays on this panel — never a scheme or `//other-host`.
fn is_internal_href(href: &str) -> bool {
    href.starts_with('/') && !href.starts_with("//") && !href.contains('\\')
}

/// GET /notifications — the archive. The bell shows the newest ten; this is
/// everything kept (90 days), filtered and paged by the agent.
pub async fn get_archive(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<ArchiveQuery>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(Redirect::to("/login").into_response());
    };
    // The page, and the whole archive's headline: unread errors anywhere,
    // and the newest of them, whatever the list below is narrowed to.
    let headline_filter = hyperion_types::NotificationSearchFilter {
        severity: "error".into(),
        unread_only: true,
        limit: 1,
        ..Default::default()
    };
    let (page, headline) = tokio::join!(
        search(&state, sess.user_id, q.filter(PAGE)),
        search(&state, sess.user_id, headline_filter),
    );
    let page = page?;
    let headline = headline?;
    // The newest row of all, for "last notification 3h ago" — the page's own
    // first row when it is unfiltered, else one more look.
    let unfiltered = q.q.trim().is_empty() && q.topic.trim().is_empty() && q.show().is_empty();
    let newest = if unfiltered && q.before().is_none() {
        page.items.first().map(|n| n.created_at)
    } else if headline.counts.all > 0 {
        search(
            &state,
            sess.user_id,
            hyperion_types::NotificationSearchFilter {
                limit: 1,
                ..Default::default()
            },
        )
        .await?
        .items
        .first()
        .map(|n| n.created_at)
    } else {
        None
    };
    let (verdict, verdict_tone) = verdict(&headline.counts, headline.items.first(), newest);
    let verdict_href = headline.items.first().and_then(open_href);

    let nodes: HashMap<String, String> = if page.items.iter().any(|n| !n.node_id.is_empty()) {
        crate::handlers::hostings::fetch_remote_nodes(&state)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|n| {
                let label = if n.label.is_empty() {
                    n.node_id.clone()
                } else {
                    n.label
                };
                (n.node_id, label)
            })
            .collect()
    } else {
        HashMap::new()
    };

    let show = q.show();
    let topic = q.topic.trim().to_string();
    let search_q = q.q.trim().to_string();
    let older_href = page.more.then(|| page.items.last()).flatten().map(|n| {
        archive_href(
            show,
            &topic,
            &search_q,
            &format!("{}.{}", n.created_at, n.id),
        )
    });
    let now = hyperion_types::now_secs();
    let mut days: Vec<DayGroup> = Vec::new();
    for n in page.items {
        let label = crate::handlers::emails::day_label(n.created_at, now);
        let r = row(n, &nodes);
        match days.last_mut() {
            Some(d) if d.label == label => d.rows.push(r),
            _ => days.push(DayGroup {
                label,
                rows: vec![r],
            }),
        }
    }
    let topics = page
        .topics
        .iter()
        .map(|t| {
            let label = if t.unread > 0 {
                format!("{} · {}, {} unread", t.label, t.total, t.unread)
            } else {
                format!("{} · {}", t.label, t.total)
            };
            (t.topic.clone(), label, t.topic == topic)
        })
        .collect();
    let seg_hrefs = SegHrefs {
        all: archive_href("", &topic, &search_q, ""),
        unread: archive_href("unread", &topic, &search_q, ""),
        error: archive_href("error", &topic, &search_q, ""),
        warn: archive_href("warn", &topic, &search_q, ""),
        info: archive_href("info", &topic, &search_q, ""),
    };
    let here = archive_href(show, &topic, &search_q, q.before.trim());
    let tpl = NotificationsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "notifications",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(&state, &ctx),
        verdict,
        verdict_tone,
        verdict_href,
        archive_empty: headline.counts.all == 0,
        days,
        counts: page.counts,
        topics,
        first_href: archive_href(show, &topic, &search_q, ""),
        paged: q.before().is_some(),
        filtered: !unfiltered,
        q: search_q,
        topic,
        show: show.to_string(),
        seg_hrefs,
        older_href,
        here,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// GET /notifications/:id/open — mark it read, then go where it points.
/// The bell and the archive both link here, so following an alert is what
/// reads it (the bell's old click-then-fetch raced the navigation).
pub async fn get_open(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let n = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsGet {
            user_id: sess.user_id,
            id,
        },
    )
    .await
    .map_err(AppError::from)?
    {
        RpcResponse::NotificationsGet(n) => n,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let Some(n) = n else {
        // Someone else's, or pruned: nothing to open.
        return Ok(Redirect::to("/notifications").into_response());
    };
    mark_one(&state, sess.user_id, id).await?;
    let to = if is_internal_href(&n.href) {
        n.href
    } else {
        "/notifications".to_string()
    };
    Ok(Redirect::to(&to).into_response())
}

async fn mark_one(state: &SharedState, user_id: i64, id: i64) -> Result<(), AppError> {
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsMarkRead {
            user_id,
            notification_id: id,
        },
    )
    .await
    .map_err(AppError::from)?
    {
        RpcResponse::NotificationsMarkRead => Ok(()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Where a mark-read form returns to: the archive page it was posted from.
fn back_to(back: &str) -> String {
    let b = back.trim();
    if b == "/notifications" || b.starts_with("/notifications?") {
        b.to_string()
    } else {
        "/notifications".into()
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct MarkOneForm {
    #[serde(default)]
    pub back: String,
}

/// POST /notifications/:id/read — the archive's per-row "Mark read".
pub async fn post_read_one(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(id): Path<i64>,
    Form(f): Form<MarkOneForm>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(Redirect::to("/login").into_response());
    };
    mark_one(&state, sess.user_id, id).await?;
    Ok(Redirect::to(&back_to(&f.back)).into_response())
}

/// POST /notifications/read — "Mark all read", or "Mark these read" with the
/// page's filters: every unread row they match, not only the page on screen.
pub async fn post_read_matching(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(f): Form<ArchiveQuery>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(Redirect::to("/login").into_response());
    };
    let filter = hyperion_types::NotificationSearchFilter {
        before: None,
        ..f.filter(0)
    };
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsMarkMatching {
            user_id: sess.user_id,
            filter,
        },
    )
    .await
    .map_err(AppError::from)?
    {
        RpcResponse::NotificationsMarkAllRead { .. } => {}
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    }
    // Back to the same view, first page: "unread" will now be empty, which
    // is the point.
    Ok(Redirect::to(&archive_href(f.show(), f.topic.trim(), f.q.trim(), "")).into_response())
}

#[derive(Debug, Deserialize)]
pub struct FeedQuery {
    /// Cap: rpc layer clamps to [1, 100]. Default 10 = dropdown size.
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 {
    10
}

pub async fn get_feed(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<FeedQuery>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsFeed {
            user_id: sess.user_id,
            limit: q.limit,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::NotificationsFeed(feed) => Ok((
            [(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")],
            Json(feed),
        )
            .into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Debug, Deserialize)]
pub struct MarkReadBody {
    pub id: i64,
}

pub async fn post_mark_read(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Json(body): Json<MarkReadBody>,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsMarkRead {
            user_id: sess.user_id,
            notification_id: body.id,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::NotificationsMarkRead => Ok(StatusCode::NO_CONTENT.into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_mark_all_read(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NotificationsMarkAllRead {
            user_id: sess.user_id,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::NotificationsMarkAllRead { marked } => Ok((
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"marked\":{}}}", marked),
        )
            .into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(show: &str, topic: &str, query: &str, before: &str) -> ArchiveQuery {
        ArchiveQuery {
            q: query.into(),
            topic: topic.into(),
            show: show.into(),
            before: before.into(),
        }
    }

    #[test]
    fn unread_segment_is_a_flag_not_a_severity() {
        let f = q("unread", "certs", " a.cz ", "").filter(10);
        assert!(f.unread_only);
        assert_eq!(f.severity, "");
        assert_eq!(f.topic, "certs");
        assert_eq!(f.q, "a.cz");
        let f = q("error", "", "", "").filter(10);
        assert!(!f.unread_only);
        assert_eq!(f.severity, "error");
        // Unknown values fall back to "all", never to a raw SQL value.
        assert_eq!(q("bogus", "", "", "").filter(10).severity, "");
    }

    #[test]
    fn cursor_parses_or_is_ignored() {
        assert_eq!(
            q("", "", "", "1700000000.42").before(),
            Some((1_700_000_000, 42))
        );
        for bad in ["", "1700000000", "x.1", "1.y", "1.2.3"] {
            assert_eq!(q("", "", "", bad).before(), None, "{bad}");
        }
    }

    #[test]
    fn hrefs_keep_filters_and_encode_them() {
        assert_eq!(archive_href("", "", "", ""), "/notifications");
        assert_eq!(
            archive_href("unread", "certs", "a b&c", ""),
            "/notifications?show=unread&topic=certs&q=a+b%26c"
        );
    }

    #[test]
    fn mark_read_only_returns_to_the_archive() {
        assert_eq!(
            back_to("/notifications?show=unread"),
            "/notifications?show=unread"
        );
        for bad in [
            "https://evil.cz",
            "//evil.cz",
            "/settings",
            "",
            "/notificationsX",
        ] {
            assert_eq!(back_to(bad), "/notifications", "{bad}");
        }
    }

    #[test]
    fn verdict_leads_with_unread_errors() {
        let c = |unread, unread_error, all| hyperion_types::NotificationCounts {
            all,
            unread,
            unread_error,
            ..Default::default()
        };
        assert_eq!(verdict(&c(3, 1, 9), None, Some(1)).1, "err");
        assert!(verdict(&c(3, 1, 9), None, Some(1))
            .0
            .starts_with("1 unread error · 2 more"));
        assert_eq!(verdict(&c(2, 0, 9), None, Some(1)).1, "warn");
        assert_eq!(verdict(&c(0, 0, 9), None, Some(1)).1, "ok");
        assert_eq!(verdict(&c(0, 0, 0), None, None).1, "muted");
    }

    #[test]
    fn only_internal_links_get_an_open_link() {
        let n = |href: &str| hyperion_types::NotificationView {
            id: 7,
            severity: "error".into(),
            title: String::new(),
            body: String::new(),
            href: href.into(),
            kind: String::new(),
            created_at: 0,
            read_at: None,
            node_id: String::new(),
        };
        assert_eq!(
            open_href(&n("/hostings/a.cz")).as_deref(),
            Some("/notifications/7/open")
        );
        assert_eq!(open_href(&n("/")), None);
        assert_eq!(open_href(&n("//evil.cz")), None);
        assert_eq!(open_href(&n("https://evil.cz")), None);
    }
}
