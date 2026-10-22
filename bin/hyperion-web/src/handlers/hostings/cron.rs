//! Crontab editor.

use super::*;

#[derive(Deserialize)]
pub struct CronForm {
    pub selector: String,
    pub body: String,
}

pub async fn post_cron_save(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CronForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingCron)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    // The crontab lives on the owning node (the editor reads it from
    // there) — write to the same node, not the master local socket.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::CronReplace {
            sel,
            body: form.body,
        },
    )
    .await?;
    match resp {
        RpcResponse::CronReplace => {
            Ok(Redirect::to(&format!("/hostings/{}?cron=saved", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cron_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
