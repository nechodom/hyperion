//! `GET /api/whatsnew` — the feed behind the "What's new" icon.
//!
//! The entries are compiled in ([`crate::whatsnew`]); this only decides
//! which of them the session gets. Read state lives in the browser.

use crate::auth::AuthCtx;
use crate::whatsnew::{visible, ENTRIES};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

/// The list is for the people who run the panel. A customer or a viewer
/// has nothing to switch on, so they get neither the icon nor the data.
fn may_read(is_customer: bool, read_only: bool) -> bool {
    !is_customer && !read_only
}

pub async fn feed(ctx: AuthCtx) -> Response {
    if !may_read(ctx.is_customer(), ctx.is_read_only()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let entries: Vec<serde_json::Value> = visible(ENTRIES, ctx.scope_all(), |c| ctx.can(c))
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "date": e.date,
                "title": e.title,
                "body": e.body,
                "link": e.link,
                "link_label": e.link_label,
            })
        })
        .collect();
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::json!({ "entries": entries }).to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::may_read;

    #[test]
    fn only_staff_who_can_change_things_read_the_feed() {
        assert!(may_read(false, false));
        assert!(!may_read(true, false));
        assert!(!may_read(false, true));
        assert!(!may_read(true, true));
    }
}
