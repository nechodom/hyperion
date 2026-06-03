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

pub async fn get_search(
    State(state): State<SharedState>,
    _ctx: AuthCtx,
    Query(q): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let needle = q.q.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return Ok(Json(SearchResp::default()).into_response());
    }

    // Fan out — both calls are cheap (read-only RPC against the local
    // agent socket) and independent. Run them in parallel; whichever
    // fails just contributes an empty list.
    let (hostings_res, users_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, RpcRequest::HostingList),
        hyperion_rpc_client::call(&state.agent_socket, RpcRequest::WebUserList),
    );

    let mut out = SearchResp::default();

    if let Ok(RpcResponse::HostingList(rows)) = hostings_res {
        for r in rows.into_iter() {
            if r.domain.to_ascii_lowercase().contains(&needle) {
                out.hostings.push(HostingHit {
                    domain: r.domain,
                    state: format!("{:?}", r.state).to_ascii_lowercase(),
                });
                if out.hostings.len() >= MAX_HITS_PER_KIND {
                    break;
                }
            }
        }
    }

    if let Ok(RpcResponse::WebUserList(rows)) = users_res {
        for u in rows.into_iter() {
            if u.username.to_ascii_lowercase().contains(&needle) {
                out.users.push(UserHit {
                    username: u.username,
                    role: u.role,
                });
                if out.users.len() >= MAX_HITS_PER_KIND {
                    break;
                }
            }
        }
    }

    Ok(Json(out).into_response())
}
