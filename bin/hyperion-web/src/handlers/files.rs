//! `/hostings/<sel>/files` — read-only file browser scoped to the
//! hosting's htdocs root. Path traversal + symlinks already refused
//! at the adapter layer; this handler just plumbs URL → RPC →
//! template.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::handlers::hostings::{parse_selector_public, require_hosting_access};
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{HostingFileContent, HostingFileEntry};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "hosting_files.html")]
struct FilesTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    selector: String,
    domain: String,
    rel_path: String,
    breadcrumbs: Vec<(String, String)>,
    entries: Vec<HostingFileEntry>,
    /// Set when ?file=<rel_path> — renders inline viewer.
    viewer: Option<HostingFileContent>,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct FilesQuery {
    #[serde(default)]
    pub path: String,
    /// When set, renders the file viewer instead of the listing.
    /// `file` is a full rel_path (e.g. "wp-content/themes/style.css").
    #[serde(default)]
    pub file: Option<String>,
}

pub async fn get_files(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<FilesQuery>,
) -> Result<Response, AppError> {
    let sel = parse_selector_public(&selector)?;
    let detail_resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingGet(sel.clone())).await?;
    let detail = match detail_resp {
        RpcResponse::HostingGet(d) => d,
        RpcResponse::Error(hyperion_rpc::RpcError::NotFound { .. }) => {
            return Err(AppError::NotFound);
        }
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    // RBAC: same guard as detail page — read level is fine.
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }

    // Decide whether we're browsing a directory or viewing a file.
    let (viewer, rel_path, entries, error) = if let Some(file_path) = q.file.clone() {
        let resp = hyperion_rpc_client::call(
            &state.agent_socket,
            Request::HostingFileRead {
                sel: sel.clone(),
                rel_path: file_path.clone(),
            },
        )
        .await?;
        match resp {
            RpcResponse::HostingFileRead(c) => {
                // Re-list the parent dir so the listing still shows.
                let parent = parent_dir(&file_path);
                let list = list_dir(&state, sel.clone(), parent.clone()).await;
                (Some(c), parent, list.entries, list.error)
            }
            RpcResponse::Error(e) => {
                let list = list_dir(&state, sel.clone(), q.path.clone()).await;
                (None, q.path.clone(), list.entries, Some(e.to_string()))
            }
            _ => return Err(AppError::Internal("unexpected response".into())),
        }
    } else {
        let list = list_dir(&state, sel.clone(), q.path.clone()).await;
        (None, q.path.clone(), list.entries, list.error)
    };

    let breadcrumbs = build_breadcrumbs(&rel_path);

    let tpl = FilesTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        selector,
        domain: detail.domain,
        rel_path,
        breadcrumbs,
        entries,
        viewer,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
}

struct DirListing {
    entries: Vec<HostingFileEntry>,
    error: Option<String>,
}

async fn list_dir(
    state: &SharedState,
    sel: hyperion_rpc::wire::HostingSelector,
    rel_path: String,
) -> DirListing {
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingFileList { sel, rel_path },
    )
    .await
    {
        Ok(RpcResponse::HostingFileList { entries, .. }) => DirListing {
            entries,
            error: None,
        },
        Ok(RpcResponse::Error(e)) => DirListing {
            entries: vec![],
            error: Some(e.to_string()),
        },
        Ok(_) => DirListing {
            entries: vec![],
            error: Some("unexpected response".into()),
        },
        Err(e) => DirListing {
            entries: vec![],
            error: Some(format!("rpc: {e}")),
        },
    }
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

/// Public helper used by the template to render "Up one level" link.
/// Askama can't call private functions, so this is the export.
pub fn parent_path_for_template(path: &str) -> String {
    parent_dir(path)
}

/// `fmt_bytes` from the stats handler is `&i64 -> String`, but file
/// sizes are `u64`. Convert here so the template doesn't need a cast
/// (askama can't parse `as i64`).
pub fn fmt_size_u64(n: &u64) -> String {
    crate::handlers::stats::fmt_bytes(&(*n as i64))
}

/// Build clickable breadcrumb segments. Each tuple is (display, link path).
fn build_breadcrumbs(rel_path: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    out.push(("htdocs".to_string(), String::new()));
    if rel_path.is_empty() {
        return out;
    }
    let mut accum = String::new();
    for seg in rel_path.split('/').filter(|s| !s.is_empty()) {
        if !accum.is_empty() {
            accum.push('/');
        }
        accum.push_str(seg);
        out.push((seg.to_string(), accum.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_dir_handles_typical_cases() {
        assert_eq!(parent_dir(""), "");
        assert_eq!(parent_dir("file.txt"), "");
        assert_eq!(parent_dir("dir/file.txt"), "dir");
        assert_eq!(parent_dir("a/b/c.txt"), "a/b");
    }

    #[test]
    fn breadcrumbs_split_correctly() {
        assert_eq!(
            build_breadcrumbs(""),
            vec![("htdocs".to_string(), "".to_string())]
        );
        assert_eq!(
            build_breadcrumbs("wp-content/themes"),
            vec![
                ("htdocs".to_string(), "".to_string()),
                ("wp-content".to_string(), "wp-content".to_string()),
                ("themes".to_string(), "wp-content/themes".to_string()),
            ]
        );
    }
}
