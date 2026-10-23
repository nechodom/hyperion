//! Disk quota settings.

use super::*;

#[derive(serde::Deserialize)]
pub struct QuotaSetForm {
    pub selector: String,
    #[serde(default)]
    pub disk_soft_mib: i64,
    #[serde(default)]
    pub disk_hard_mib: i64,
    /// "notify" (default) or "suspend" — what to do when usage crosses the
    /// disk hard cap.
    #[serde(default)]
    pub exceed_action: String,
}

pub async fn post_quota_set(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<QuotaSetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // UI accepts MiB for both disk fields (cleaner than asking
    // operators to type kibibytes). Convert to KiB at the boundary
    // — setquota wants 1024-byte blocks.
    let disk_soft_kib = form.disk_soft_mib.saturating_mul(1024);
    let disk_hard_kib = form.disk_hard_mib.saturating_mul(1024);
    // setquota runs against the filesystem on the node that holds
    // /home/<user> — dispatch to the owner, not the master local socket
    // (the Quota tab already READS from the owner).
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::QuotaSet {
            hosting: sel,
            disk_soft_kib,
            disk_hard_kib,
            // Always zero: the form fields that fed these were placebo —
            // no reader existed for either (pools build from
            // hosting_limits; nothing enforced or alerted on bandwidth).
            // Writing zeros clears any stale ghost value, so a site's
            // stored policy converges on what is actually true.
            mem_limit_mib: 0,
            bw_soft_mib: 0,
            bw_hard_mib: 0,
            exceed_action: form.exceed_action.clone(),
        },
    )
    .await?;
    // `flash` = green success toast, `flash_error` = red. A kernel rejection
    // is NOT a success: the policy row was saved but the cap isn't enforced, so
    // it must read as an error, not "Quota saved" in green.
    let (param, msg) = match resp {
        RpcResponse::QuotaApplied(v) => match v.last_error.as_deref() {
            // A "pending reboot" deferral is NOT a rejection — the cap is saved
            // and the boot reconciler pushes it once the node reboots. Say so
            // honestly instead of "the kernel rejected it".
            Some(err) if err.starts_with("kernel quotas need a reboot") => {
                ("flash_error", format!("Quota saved — {err}"))
            }
            Some(err) => (
                "flash_error",
                format!("Quota saved, but NOT enforced — the kernel rejected it: {err}"),
            ),
            None => ("flash", "Quota saved + applied to the kernel.".to_string()),
        },
        RpcResponse::Error(e) => ("flash_error", format!("Quota set failed: {e}")),
        _ => ("flash_error", "Quota set: unexpected response".to_string()),
    };
    Ok(Redirect::to(&format!(
        "/hostings/{}?{}={}#quota",
        sel_url,
        param,
        urlencoding(&msg)
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct QuotaEnableForm {
    pub selector: String,
}

/// POST /hostings/quota/enable-kernel — turn on Linux kernel disk quotas on
/// the OWNING node's filesystem (edits /etc/fstab + remount + quotacheck +
/// quotaon). Admin-only: this is a node-wide filesystem change, not a
/// per-hosting tweak, so per-hosting "manage" isn't enough.
pub async fn post_quota_enable_kernel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<QuotaEnableForm>,
) -> Result<Response, AppError> {
    let sel_url = urlencoding(&form.selector);
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error=admin+role+required+to+enable+kernel+quotas#quota",
            sel_url
        ))
        .into_response());
    }
    let sel = parse_selector(&form.selector)?;
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::QuotaEnableKernel { hosting: sel },
    )
    .await?;
    // Only a genuinely-active result is a green toast. A hard failure OR a
    // "reboot required" outcome routes through flash_error so the operator
    // isn't told "done" in green when there's still a manual step left.
    let (param, msg) = match resp {
        RpcResponse::QuotaEnableKernel(s) => {
            if s.ok {
                ("flash", s.message)
            } else {
                ("flash_error", s.message)
            }
        }
        RpcResponse::Error(e) => ("flash_error", format!("Couldn't enable kernel quotas: {e}")),
        _ => (
            "flash_error",
            "Enable kernel quotas: unexpected response".to_string(),
        ),
    };
    Ok(Redirect::to(&format!(
        "/hostings/{}?{}={}#quota",
        sel_url,
        param,
        urlencoding(&msg)
    ))
    .into_response())
}
