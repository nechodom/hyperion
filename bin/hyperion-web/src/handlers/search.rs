//! Global search endpoint backing the ⌘K command palette.
//!
//! Returns a small JSON envelope with up to 8 hits per kind: hostings,
//! users, nodes, profiles and care packages. The palette already has the
//! static page list baked in client-side; this endpoint only hits hot data.
//!
//! A hosting is found by its domain OR by any secondary name a node keeps
//! for it — an alias, the Linux user, a database name or user, an FTP login
//! (the `HostingSearchIndex` RPC). A hit through a secondary name carries
//! `matched` so the palette can say why the site came up. A node whose agent
//! predates that RPC answers with an error and is searched by domain only.
//!
//! Auth: behind the same `require_auth` layer as every other admin
//! handler — no public exposure. Each kind is gated like the page it
//! links to: hostings by per-user access grants, users and nodes
//! super_admin-only, profiles and packages behind `ProfilesManage`.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Json, Response};
use hyperion_rpc::codec::{Request as RpcRequest, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{HostingSearchTerm, HostingSummary};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct HostingHit {
    domain: String,
    state: String,
    /// Set when the hosting matched through a secondary name rather than
    /// its domain, e.g. "alias: shop.example.cz" or "FTP login: anna".
    #[serde(skip_serializing_if = "Option::is_none")]
    matched: Option<String>,
}

#[derive(Serialize)]
struct UserHit {
    username: String,
    role: String,
}

/// A hit that is just a name and a page to open: node, profile, package.
#[derive(Serialize, Debug, PartialEq)]
struct NamedHit {
    label: String,
    href: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    meta: String,
}

#[derive(Serialize, Default)]
struct SearchResp {
    hostings: Vec<HostingHit>,
    users: Vec<UserHit>,
    nodes: Vec<NamedHit>,
    profiles: Vec<NamedHit>,
    packages: Vec<NamedHit>,
}

/// Secondary names keyed by `(node_id, hosting_id)` — the same node tag
/// `list_hostings` puts on its rows, so the two line up.
type SearchIndex = HashMap<(String, String), Vec<HostingSearchTerm>>;

/// A hit through a secondary name ranks a little below the same quality of
/// hit on a domain: typing "shop" should list `shop.cz` before the site
/// that merely has `shop.cz` as an alias.
const SECONDARY_PENALTY: i64 = 50;

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

/// Human label for a `HostingSearchTerm::kind`.
fn term_label(kind: &str) -> &str {
    match kind {
        "alias" => "alias",
        "system_user" => "Linux user",
        "database" => "database",
        "db_user" => "DB user",
        "ftp" => "FTP login",
        other => other,
    }
}

/// Rank the hostings the caller may see against the needle. A domain hit
/// wins over a secondary-name hit; among secondary names the best one is
/// the one reported in `matched`.
fn rank_hostings(rows: Vec<HostingSummary>, index: &SearchIndex, needle: &str) -> Vec<HostingHit> {
    let mut scored: Vec<(i64, HostingHit)> = rows
        .into_iter()
        .filter_map(|r| {
            let mut matched = None;
            let mut s = score(&r.domain, needle);
            if s == 0 {
                let key = (r.node_id.clone().unwrap_or_default(), r.id.0.clone());
                let best = index
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .map(|t| (score(&t.value, needle), t))
                    .filter(|(ts, _)| *ts > 0)
                    .max_by_key(|(ts, _)| *ts)?;
                s = best.0 - SECONDARY_PENALTY;
                matched = Some(format!("{}: {}", term_label(&best.1.kind), best.1.value));
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
                    matched,
                },
            ))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    scored
        .into_iter()
        .take(MAX_HITS_PER_KIND)
        .map(|(_, h)| h)
        .collect()
}

/// Rank name-and-link hits. Each candidate carries every string it may be
/// found by (label, id, address); the best of them counts.
fn rank_named(candidates: Vec<(Vec<String>, NamedHit)>, needle: &str) -> Vec<NamedHit> {
    let mut scored: Vec<(i64, NamedHit)> = candidates
        .into_iter()
        .filter_map(|(keys, hit)| {
            let s = keys.iter().map(|k| score(k, needle)).max().unwrap_or(0);
            (s > 0).then_some((s, hit))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    scored
        .into_iter()
        .take(MAX_HITS_PER_KIND)
        .map(|(_, h)| h)
        .collect()
}

/// Ask the master and every enrolled node for their secondary names, in
/// parallel. Best-effort: a node that fails or predates the RPC simply
/// contributes nothing, and its sites stay findable by domain.
async fn fetch_search_index(state: &SharedState) -> SearchIndex {
    let nodes = crate::dispatcher::cached_nodes(state)
        .await
        .unwrap_or_default();
    let (local, remote) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, RpcRequest::HostingSearchIndex),
        crate::dispatcher::fan_out(state, nodes, RpcRequest::HostingSearchIndex),
    );
    let mut index = SearchIndex::new();
    let mut add = |node: &str, terms: Vec<HostingSearchTerm>| {
        for t in terms {
            index
                .entry((node.to_string(), t.hosting_id.clone()))
                .or_default()
                .push(t);
        }
    };
    if let Ok(RpcResponse::HostingSearchIndex(terms)) = local {
        add(crate::dispatcher::LOCAL_NODE_SENTINEL, terms);
    }
    for (n, resp) in remote {
        if let RpcResponse::HostingSearchIndex(terms) = resp {
            add(&n.node_id, terms);
        }
    }
    index
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

    let super_admin = ctx.is_super_admin();
    let can_profiles = ctx.can(Capability::ProfilesManage);

    // Hostings come from the CLUSTER-WIDE aggregator (master + every enrolled
    // worker), not the master-local socket — otherwise ⌘K can't find any site
    // provisioned on a worker, even though /hostings lists it. Users,
    // profiles and packages are master-only, so those stay local calls.
    // Everything runs in parallel; whichever fails contributes an empty
    // list, and a kind the caller may not see is never even asked for.
    let (hostings_res, index, users_res, nodes_res, profiles_res, packages_res) = tokio::join!(
        crate::handlers::hostings::list_hostings(&state),
        fetch_search_index(&state),
        async {
            if super_admin {
                hyperion_rpc_client::call(&state.agent_socket, RpcRequest::WebUserList)
                    .await
                    .ok()
            } else {
                None
            }
        },
        async {
            if super_admin {
                crate::dispatcher::cached_nodes(&state).await.ok()
            } else {
                None
            }
        },
        async {
            if can_profiles {
                hyperion_rpc_client::call(&state.agent_socket, RpcRequest::ProfileList)
                    .await
                    .ok()
            } else {
                None
            }
        },
        async {
            if can_profiles {
                hyperion_rpc_client::call(&state.agent_socket, RpcRequest::PackageList)
                    .await
                    .ok()
            } else {
                None
            }
        },
    );

    let mut out = SearchResp::default();

    // Hostings: tenant-scoped roles (operator/viewer/customer) must only see
    // domains they hold an access grant for — otherwise the command palette
    // enumerates every domain in the cluster, bypassing the per-user
    // filtering the /hostings list applies. The secondary-name index is
    // joined onto the FILTERED rows only, so it can never surface a site
    // (or a site's DB / FTP names) the caller has no grant for.
    if let Ok(rows) = hostings_res {
        let rows = crate::handlers::hostings::filter_by_access(&state, &ctx, rows).await;
        out.hostings = rank_hostings(rows, &index, &needle);
    }

    // The user roster (username + role) is super_admin-only — the same
    // gate as /admin/users. Without this, any authenticated viewer/
    // customer/operator could enumerate every account + role via the
    // command palette.
    if let Some(RpcResponse::WebUserList(rows)) = users_res {
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

    // Nodes: super_admin-only, like /install itself (the page carries
    // enrolment tokens). Found by label, node id or public IP.
    if let Some(nodes) = nodes_res {
        out.nodes = rank_named(
            nodes
                .into_iter()
                .map(|n| {
                    let mut keys = vec![n.label.clone(), n.node_id.clone()];
                    keys.extend(n.public_ip.clone());
                    let hit = NamedHit {
                        label: if n.label.is_empty() {
                            n.node_id.clone()
                        } else {
                            n.label.clone()
                        },
                        href: format!("/install#node-{}", n.node_id),
                        meta: n.public_ip.unwrap_or(n.node_id),
                    };
                    (keys, hit)
                })
                .collect(),
            &needle,
        );
    }

    if let Some(RpcResponse::ProfileList(rows)) = profiles_res {
        out.profiles = rank_named(
            rows.into_iter()
                .map(|p| {
                    let hit = NamedHit {
                        label: p.name.clone(),
                        href: format!("/profiles/{}/edit", p.id),
                        meta: String::new(),
                    };
                    (vec![p.name], hit)
                })
                .collect(),
            &needle,
        );
    }

    if let Some(RpcResponse::PackageList(rows)) = packages_res {
        out.packages = rank_named(
            rows.into_iter()
                .map(|p| {
                    let hit = NamedHit {
                        label: p.name.clone(),
                        href: format!("/packages#package-{}", p.id),
                        meta: if p.enabled {
                            String::new()
                        } else {
                            "disabled".into()
                        },
                    };
                    (vec![p.name, p.slug], hit)
                })
                .collect(),
            &needle,
        );
    }

    Ok(Json(out).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(node: &str, id: &str, domain: &str) -> HostingSummary {
        serde_json::from_value(serde_json::json!({
            "id": id, "domain": domain, "state": "active", "php_version": null,
            "created_at": 0, "node_id": node,
        }))
        .expect("summary")
    }

    fn term(id: &str, kind: &str, value: &str) -> HostingSearchTerm {
        HostingSearchTerm {
            hosting_id: id.into(),
            kind: kind.into(),
            value: value.into(),
        }
    }

    #[test]
    fn hosting_found_by_secondary_name_says_why() {
        let mut index = SearchIndex::new();
        index.insert(
            ("w1".into(), "h1".into()),
            vec![
                term("h1", "alias", "eshop.example.cz"),
                term("h1", "ftp", "anna"),
            ],
        );
        let hits = rank_hostings(vec![row("w1", "h1", "example.cz")], &index, "anna");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].domain, "example.cz");
        assert_eq!(hits[0].matched.as_deref(), Some("FTP login: anna"));
    }

    #[test]
    fn domain_hit_outranks_secondary_hit() {
        let mut index = SearchIndex::new();
        index.insert(
            ("local".into(), "h2".into()),
            vec![term("h2", "alias", "shop.cz")],
        );
        let hits = rank_hostings(
            vec![
                row("local", "h2", "other.cz"),
                row("local", "h1", "shop.cz"),
            ],
            &index,
            "shop",
        );
        assert_eq!(hits[0].domain, "shop.cz");
        assert_eq!(hits[0].matched, None);
        assert_eq!(hits[1].domain, "other.cz");
        assert_eq!(hits[1].matched.as_deref(), Some("alias: shop.cz"));
    }

    #[test]
    fn index_of_another_node_never_leaks() {
        // Same hosting id on two nodes: the term belongs to w2's site, so
        // w1's site must not match through it.
        let mut index = SearchIndex::new();
        index.insert(
            ("w2".into(), "h1".into()),
            vec![term("h1", "database", "secretdb")],
        );
        let hits = rank_hostings(vec![row("w1", "h1", "a.cz")], &index, "secretdb");
        assert!(hits.is_empty());
    }

    #[test]
    fn only_rows_passed_in_can_match() {
        // The index may hold names of sites the caller has no grant for;
        // with the row filtered out they never surface.
        let mut index = SearchIndex::new();
        index.insert(
            ("w1".into(), "hidden".into()),
            vec![term("hidden", "db_user", "wp_hidden")],
        );
        let hits = rank_hostings(vec![row("w1", "h1", "a.cz")], &index, "wp_hidden");
        assert!(hits.is_empty());
    }

    #[test]
    fn named_hits_match_any_key() {
        let hits = rank_named(
            vec![(
                vec!["Praha 1".into(), "node-abc".into(), "203.0.113.7".into()],
                NamedHit {
                    label: "Praha 1".into(),
                    href: "/install#node-node-abc".into(),
                    meta: String::new(),
                },
            )],
            "203.0",
        );
        assert_eq!(hits.len(), 1);
        assert!(rank_named(vec![], "x").is_empty());
    }

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
