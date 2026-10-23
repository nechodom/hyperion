//! Expiry date and price of a hosting.

use super::*;

#[derive(Deserialize)]
pub struct SetExpiryForm {
    pub selector: String,
    /// `YYYY-MM-DD` from <input type="date">, or empty to clear.
    pub expires_on: String,
    #[serde(default)]
    pub owner_email: String,
    #[serde(default)]
    pub grace_days: Option<i64>,
    #[serde(default)]
    pub warning_offsets: Option<String>,
}

pub async fn post_set_expiry(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetExpiryForm>,
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
    let expires_at = match parse_yyyymmdd_to_epoch(form.expires_on.trim()) {
        Ok(t) => t,
        Err(msg) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?expiry_error={}",
                sel_url,
                urlencoding(&msg)
            ))
            .into_response());
        }
    };
    let expiry = hyperion_types::HostingExpiry {
        expires_at,
        owner_email: if form.owner_email.trim().is_empty() {
            None
        } else {
            Some(form.owner_email.trim().to_string())
        },
        // The service works this out from the date typed above: a past date
        // is a renewal day plus the year the customer joined. Sending None
        // does not erase a start date already on record — set_expiry keeps
        // the stored one.
        customer_since: None,
        grace_days: form.grace_days.unwrap_or(30).max(0),
        warning_offsets_days: form
            .warning_offsets
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("30,7,1")
            .to_string(),
    };
    // Expiry lives on the owner node (the detail page reads it from
    // there); dispatch the write to the same node, mirroring
    // post_clear_expiry. Master-local-only made Set fail on every
    // worker-hosted site while Clear worked.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::HostingSetExpiry { sel, expiry },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetExpiry(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?expiry=set", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?expiry_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SetPriceForm {
    pub selector: String,
    /// "2400" / "2400.00" / "2400,00"; empty = no price on this hosting.
    #[serde(default)]
    pub price_major: String,
    #[serde(default)]
    pub price_currency: String,
    #[serde(default)]
    pub price_interval: String,
    /// Checkbox: present ⇒ keep this price when a profile is re-applied.
    #[serde(default)]
    pub pinned: Option<String>,
}

/// Lifecycle & billing → Price. Billing is a platform matter, so this takes
/// the same capability as applying a profile (which also sets the price),
/// not the per-site edit one a customer holds for their own site.
pub async fn post_set_price(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetPriceForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::ProfilesManage)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let refused = |msg: &str| {
        Redirect::to(&format!(
            "/hostings/{}?price_error={}#hosting-price",
            sel_url,
            urlencoding(msg)
        ))
        .into_response()
    };
    let price_minor = match crate::handlers::profiles::parse_price_major(&form.price_major) {
        Ok(v) => v,
        Err(AppError::BadRequest(m)) => return Ok(refused(&m)),
        Err(e) => return Err(e),
    };
    let opt = |s: &str| {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };
    // The price row lives on the node that owns the site, next to the
    // profile snapshot the detail page reads.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::HostingPriceSet {
            sel,
            price_minor,
            price_currency: opt(&form.price_currency),
            price_interval: opt(&form.price_interval),
            pinned: form.pinned.is_some(),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingPriceSet(_) => Ok(Redirect::to(&format!(
            "/hostings/{}?price=set#hosting-price",
            sel_url
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(refused(&e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ClearExpiryForm {
    pub selector: String,
}

pub async fn post_clear_expiry(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ClearExpiryForm>,
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
    // Find owner node first — when the operator clicks Clear Expiry
    // on a worker-hosted row, dispatch to the worker, not the
    // master that doesn't know about that hosting.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::HostingClearExpiry(sel),
    )
    .await?;
    match resp {
        RpcResponse::HostingClearExpiry => {
            Ok(Redirect::to(&format!("/hostings/{}?expiry=cleared", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?expiry_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Parse YYYY-MM-DD into a Unix epoch (UTC midnight). Empty input → None.
pub(super) fn parse_yyyymmdd_to_epoch(s: &str) -> Result<Option<i64>, String> {
    if s.is_empty() {
        return Ok(None);
    }
    let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| format!("Date must be YYYY-MM-DD, got: {s}"))?;
    let dt = d
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| "Invalid date".to_string())?
        .and_utc();
    Ok(Some(dt.timestamp()))
}
