//! Log viewer.

use super::*;

#[derive(Deserialize)]
pub struct LogsForm {
    pub selector: String,
    pub kind: String,
    #[serde(default = "default_log_lines")]
    pub lines: i64,
}
pub(super) fn default_log_lines() -> i64 {
    200
}

pub async fn post_logs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<LogsForm>,
) -> Result<Response, AppError> {
    // Logs can carry sensitive request data and stack traces — gate
    // them at manage level just like the other per-hosting writes.
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingView)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    // Per-site nginx/php logs live on the OWNING node's disk — dispatch
    // there, not the master local socket (which NotFounds for a
    // worker-hosted site). This is an HTMX target (#logs-output), so on
    // error render an inline fragment, NOT AppError::Rpc — a 5xx makes
    // htmx drop the swap and the button look dead.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::HostingLogs {
            sel,
            log_kind: form.kind.clone(),
            lines: form.lines,
        },
    )
    .await?;
    let body = match resp {
        RpcResponse::HostingLogs(s) => s,
        RpcResponse::Error(e) => {
            let msg = e.to_string();
            let esc = askama_escape::escape(&msg, askama_escape::Html);
            return Ok(Html(format!(
                r#"<div class="flash error" style="margin:0"><div class="flash-body">Could not read logs: {esc}</div></div>"#
            ))
            .into_response());
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let kind = askama_escape::escape(&form.kind, askama_escape::Html).to_string();
    let lines_label = form.lines;
    let pre = if body.trim().is_empty() {
        format!(
            r#"<div class="muted" style="padding:0.5rem 0">No {kind} log entries.</div>"#,
            kind = kind
        )
    } else {
        let esc = askama_escape::escape(&body, askama_escape::Html).to_string();
        format!(
            r#"<div class="muted" style="font-size:0.8rem;margin-bottom:0.4rem">Last {lines} lines · {kind}.log</div>
<pre style="max-height:36rem;overflow:auto;font-size:11.5px;line-height:1.5">{esc}</pre>"#,
            lines = lines_label,
            kind = kind,
            esc = esc
        )
    };
    Ok(Html(pre).into_response())
}
