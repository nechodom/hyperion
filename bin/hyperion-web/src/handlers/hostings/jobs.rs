//! The per-hosting jobs panel.

use super::*;

#[derive(Template)]
#[template(path = "_hosting_jobs_panel.html")]
pub(super) struct HostingJobsPanelTpl {
    pub(super) jobs: Vec<hyperion_types::JobView>,
    pub(super) selector: String,
}

/// GET /hostings/:selector/jobs-panel — running jobs for this hosting.
///
/// Polled, not reloaded: a backup or a restore is a background job precisely
/// so it survives the operator navigating away, but that also meant the page
/// they started it from went silent. This puts the same progress back where
/// the button was.
///
/// Renders an (empty) polling div rather than erroring, for the same reason
/// the SPF/DKIM panels do: HTMX discards a non-2xx, and a panel that stops
/// polling on the first hiccup silently stops being live.
pub async fn get_hosting_jobs_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let empty = |sel: &str| {
        Html(
            HostingJobsPanelTpl {
                jobs: vec![],
                selector: sel.to_string(),
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(_) => return Ok(empty(&selector)),
    };
    let detail = match find_hosting_anywhere(&state, sel).await {
        Ok((d, _)) => d,
        Err(_) => return Ok(empty(&selector)),
    };
    if require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    .is_err()
    {
        return Ok(empty(&selector));
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::JobList {
            kind: None,
            state: Some("running".to_string()),
            limit: 50,
        },
    )
    .await;
    let jobs = match resp {
        Ok(RpcResponse::JobList(v)) => v
            .into_iter()
            // `target` is whatever selector the action was started with, so
            // match BOTH spellings — the id and the domain — or a backup
            // started from the domain URL would not show on the id URL.
            .filter(|j| {
                j.target
                    .as_deref()
                    .is_some_and(|t| t == detail.id.as_str() || t == detail.domain || t == selector)
            })
            .collect(),
        _ => vec![],
    };
    Ok(Html(
        HostingJobsPanelTpl {
            jobs,
            selector: selector.clone(),
        }
        .render()?,
    )
    .into_response())
}
