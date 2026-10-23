//! Database password reset.

use super::*;

#[derive(Deserialize)]
pub struct DbResetForm {
    pub selector: String,
    pub new_password: String,
}

pub async fn post_db_reset(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DbResetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingDatabases,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // The database lives on the owning node — dispatch there.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::DbResetPassword {
            sel,
            new_password: form.new_password,
        },
    )
    .await?;
    match resp {
        RpcResponse::DbResetPassword => {
            Ok(Redirect::to(&format!("/hostings/{}?db=reset", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?db_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
