//! Global search endpoint backing the ⌘K command palette.
//!
//! Returns a small JSON envelope with up to 8 hostings + 8 users
//! matching the query. The palette already has the static page list
//! baked in client-side; this endpoint only hits hot data.
//!
//! Auth: behind the same `require_auth` layer as every other admin
//! handler — no public exposure. Search is case-insensitive substring
//! over `domain` (hostings) and `username` (users).

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Json, Response};
use hyperion_rpc::codec::{Request as RpcRequest, Response as RpcResponse};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
}

#[derive(Serialize)]
struct HostingHit {
    domain: String,
    state: String,
}

#[derive(Serialize)]
struct UserHit {
    username: String,
    role: String,
}

#[derive(Serialize, Default)]
struct SearchResp {
    hostings: Vec<HostingHit>,
    users: Vec<UserHit>,
}

const MAX_HITS_PER_KIND: usize = 8;

/// Score a haystack against the query for cmdk ranking. Higher = better.
///
/// The previous implementation returned the first 8 substring matches in
/// list iteration order — so typing "blog" might surface
/// `something-else-with-blog-in-the-middle.com` before
/// `blog.kevin.cz` purely because the former came first in the DB.
///
/// New ranking, in descending priority:
///   +1000  exact match (full needle == haystack)
///   +500   prefix match (haystack starts with needle)
///   +300   word-boundary hit (needle starts right after `.` / `-` / `_` / ` ` / `/`)
///   +100   substring match
///   +10    multi-token AND — every space-separated word in the needle
///          must appear; +10 per matched extra token (boosts narrowing
///          queries like "blog stav" over "blog")
///   -1*len shorter haystack wins ties (less noise on `example.com` vs
///          `super-long-multi-tenant-staging.example.com.test.foo`)
///
/// Returns 0 if no token from the needle was found anywhere — caller
/// filters those out.
fn score(haystack: &str, needle_lc: &str) -> i64 {
    if haystack.is_empty() || needle_lc.is_empty() {
        return 0;
    }
    let h = haystack.to_ascii_lowercase();
    let tokens: Vec<&str> = needle_lc.split_whitespace().collect();
    if tokens.is_empty() {
        return 0;
    }
    // Every token must appear (AND). Bail early on the first miss.
    if !tokens.iter().all(|t| h.contains(t)) {
        return 0;
    }
    let primary = tokens[0];
    let mut s: i64 = 0;
    if h == primary {
        s += 1000;
    } else if h.starts_with(primary) {
        s += 500;
    } else if let Some(idx) = h.find(primary) {
        // Word-boundary if the char just before the match is a
        // separator we care about. Bytes-safe because we only look
        // at the byte immediately before; ASCII separators always
        // are single-byte and the haystack is lowercased.
        let prev_is_boundary = idx == 0
            || matches!(
                h.as_bytes()[idx - 1],
                b'.' | b'-' | b'_' | b' ' | b'/' | b'@'
            );
        s += if prev_is_boundary { 300 } else { 100 };
    }
    // Bonus for every extra token matched — narrowing query wins.
    s += 10 * (tokens.len() as i64 - 1);
    // Tie-break: shorter haystack wins (cleaner match). Subtract
    // length but bounded so it never overwhelms the category bonuses.
    s -= (h.len() as i64).min(200);
    s
}

pub async fn get_search(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let needle = q.q.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return Ok(Json(SearchResp::default()).into_response());
    }

    // Hostings come from the CLUSTER-WIDE aggregator (master + every enrolled
    // worker), not the master-local socket — otherwise ⌘K can't find any site
    // provisioned on a worker, even though /hostings lists it. Users are
    // master-only (auth lives on the master), so that stays a local call.
    // Run both in parallel; whichever fails contributes an empty list.
    let (hostings_res, users_res) = tokio::join!(
        crate::handlers::hostings::list_hostings(&state),
        hyperion_rpc_client::call(&state.agent_socket, RpcRequest::WebUserList),
    );

    let mut out = SearchResp::default();

    // Hostings: rank by domain. Active hostings get a small bonus so
    // suspended / failed sites of the same name don't outrank the
    // live one the operator is most likely after.
    if let Ok(rows) = hostings_res {
        // Tenant-scoped roles (operator/viewer/customer) must only see
        // domains they hold an access grant for — otherwise the command
        // palette enumerates every domain in the cluster, bypassing the
        // per-user filtering the /hostings list applies. Admin+ pass
        // through.
        let rows = crate::handlers::hostings::filter_by_access(&state, &ctx, rows).await;
        let mut scored: Vec<(i64, HostingHit)> = rows
            .into_iter()
            .filter_map(|r| {
                let mut s = score(&r.domain, &needle);
                if s == 0 {
                    return None;
                }
                let state_str = format!("{:?}", r.state).to_ascii_lowercase();
                if state_str == "active" {
                    s += 5;
                }
                Some((
                    s,
                    HostingHit {
                        domain: r.domain,
                        state: state_str,
                    },
                ))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        out.hostings = scored
            .into_iter()
            .take(MAX_HITS_PER_KIND)
            .map(|(_, h)| h)
            .collect();
    }

    // The user roster (username + role) is super_admin-only — the same
    // gate as /admin/users. Without this, any authenticated viewer/
    // customer/operator could enumerate every account + role via the
    // command palette.
    if ctx.is_super_admin() {
        if let Ok(RpcResponse::WebUserList(rows)) = users_res {
            let mut scored: Vec<(i64, UserHit)> = rows
                .into_iter()
                .filter_map(|u| {
                    let s = score(&u.username, &needle);
                    if s == 0 {
                        return None;
                    }
                    Some((
                        s,
                        UserHit {
                            username: u.username,
                            role: u.role,
                        },
                    ))
                })
                .collect();
            scored.sort_by(|a, b| b.0.cmp(&a.0));
            out.users = scored
                .into_iter()
                .take(MAX_HITS_PER_KIND)
                .map(|(_, h)| h)
                .collect();
        }
    }

    Ok(Json(out).into_response())
}

#[cfg(test)]
mod tests {
    use super::score;

    #[test]
    fn prefix_beats_substring() {
        // "blog.example.com" should outrank "really-cool-blog-thing.test"
        // when the operator types "blog".
        let a = score("blog.example.com", "blog");
        let b = score("really-cool-blog-thing.test", "blog");
        assert!(a > b, "prefix {a} should beat substring {b}");
    }

    #[test]
    fn word_boundary_beats_mid_word() {
        // "kevin.blog.cz" (after the dot) should beat "myblogstuff.com"
        // (mid-word) when typing "blog".
        let a = score("kevin.blog.cz", "blog");
        let b = score("myblogstuff.com", "blog");
        assert!(a > b, "boundary {a} should beat midword {b}");
    }

    #[test]
    fn no_token_match_returns_zero() {
        assert_eq!(score("hello.com", "world"), 0);
        // Multi-token AND: both must match.
        assert_eq!(score("blog.com", "blog kevin"), 0);
        assert!(score("blog.kevin.com", "blog kevin") > 0);
    }

    #[test]
    fn shorter_wins_ties() {
        // Same category (both prefix) → shorter wins.
        let a = score("a.cz", "a");
        let b = score("a-very-long-domain-name.cz", "a");
        assert!(a > b);
    }
}
