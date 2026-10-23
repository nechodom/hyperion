//! SSL tab: issue, upload, DNS-01 and delete certificates.

use super::*;

#[derive(Deserialize)]
pub struct SetAcmeEmailForm {
    pub(super) selector: String,
    #[serde(default)]
    pub(super) acme_email: String,
}

/// POST /hostings/acme-email — set or clear the per-hosting ACME
/// contact email override. An empty `acme_email` field clears the
/// override, falling back to `[acme] contact_email` from agent.toml.
pub async fn post_set_acme_email(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetAcmeEmailForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::CertManage)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let trimmed = form.acme_email.trim();
    let email = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    };
    let sel_url = urlencoding(&form.selector);
    // The acme_contact_email override lives on the hosting's row on its
    // owning node — dispatch there, not the master local socket (which
    // would NotFound for a worker-hosted site). Agent errors (e.g.
    // malformed email) become a flash, not a 502 page.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::SetHostingAcmeEmail { sel, email },
    )
    .await?;
    match resp {
        RpcResponse::SetHostingAcmeEmail => {
            Ok(Redirect::to(&format!("/hostings/{sel_url}")).into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/{}?cert_error={}#ssl",
            sel_url,
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct CertIssueForm {
    pub selector: String,
    #[serde(default)]
    pub staging: Option<String>,
    #[serde(default)]
    pub require_dns_match: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct CertDeleteForm {
    pub selector: String,
}

/// POST /hostings/cert/delete — drop the certificate so a new one can be
/// issued.
///
/// Synchronous, unlike issuance: this is a file removal plus a vhost
/// re-render, with no third party to wait on. Runs on the OWNING node —
/// the certificate and the vhost both live there.
pub async fn post_cert_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CertDeleteForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::CertManage)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp =
        crate::dispatcher::dispatch_to_node(&state, node.as_deref(), Request::CertDelete { sel })
            .await?;
    match resp {
        RpcResponse::CertDelete => {
            Ok(Redirect::to(&format!("/hostings/{sel_url}?cert=deleted")).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{sel_url}?cert_error={msg}")).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_cert_issue(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CertIssueForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::CertManage)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let req = CertIssueRequest {
        staging: form.staging.as_deref() == Some("on"),
        require_dns_match: form.require_dns_match.as_deref() != Some("off"),
        extra_sans: vec![],
    };
    let staging = req.staging;
    // ── Synchronous pre-flight (authz + form parse above). The
    // owner-node lookup also stays synchronous; only the ACME issuance
    // dispatch — HTTP-01 challenge round-trips with Let's Encrypt plus an
    // nginx reload, which can stall on slow DNS/ACME — moves into the
    // worker so the operator isn't tied to a hung request.
    //
    // Cert lives on the node that owns the hosting (nginx vhost +
    // /etc/letsencrypt/live both go there). Find the right node
    // before dispatching ACME.
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);

    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "acme_issue",
        Some(&form.selector),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_cert_issue_job(reporter, job_state, node, sel, req, staging).await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker: run the ACME issuance on the owning node and fold
/// the issued cert's issuer + expiry into the job log.
pub(crate) async fn run_cert_issue_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    sel: HostingSelector,
    req: CertIssueRequest,
    staging: bool,
) {
    let kind = if staging { "staging" } else { "prod" };
    reporter
        .step(&format!("Issuing {kind} certificate via ACME…"), 10, "")
        .await;
    match crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::CertIssueAcme { sel, req },
    )
    .await
    {
        Ok(RpcResponse::CertIssueAcme(info)) => {
            let log = format!(
                "issued for {} (issuer={}, not_after={})\n",
                info.domain, info.issuer, info.not_after
            );
            reporter
                .step(&format!("{kind} certificate issued."), 100, &log)
                .await;
            reporter.finish(true, None).await;
        }
        Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
        Ok(_) => {
            reporter
                .finish(false, Some("unexpected agent response".into()))
                .await
        }
        Err(e) => reporter.finish(false, Some(e.to_string())).await,
    }
}

/// Upload a custom PEM certificate for a hosting (non-ACME). multipart so
/// operators can paste large PEM blobs without urlencoded-form size limits;
/// mirrors `post_restore_upload`'s field-by-field parsing. The cert + key
/// travel inside the RPC to the owning node — nothing is written locally.
pub async fn post_cert_upload(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    mut multipart: axum::extract::Multipart,
) -> Result<Response, AppError> {
    let mut selector: Option<String> = None;
    let mut cert_pem: Option<String> = None;
    let mut key_pem: Option<String> = None;
    let mut ca_bundle_pem: Option<String> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        match field.name() {
            Some("selector") => {
                selector = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("selector: {e}")))?,
                );
            }
            Some("cert_pem") => {
                cert_pem = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("cert_pem: {e}")))?,
                );
            }
            Some("key_pem") => {
                key_pem = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("key_pem: {e}")))?,
                );
            }
            Some("ca_bundle_pem") => {
                ca_bundle_pem = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("ca_bundle_pem: {e}")))?,
                );
            }
            _ => {}
        }
    }
    let selector = selector.ok_or_else(|| AppError::BadRequest("missing selector".into()))?;
    // Authorize before doing anything with the (sensitive) key material.
    let sel =
        match require_manage_for_selector(&state, &ctx, &selector, Capability::CertManage).await {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let cert_pem = cert_pem
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("missing certificate PEM".into()))?;
    let key_pem = key_pem
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("missing private key PEM".into()))?;
    let ca_bundle_pem = ca_bundle_pem.filter(|s| !s.trim().is_empty());

    let sel_url = urlencoding(&selector);
    // The cert + nginx vhost live on the node that owns the hosting.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::CertUpload {
            sel,
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
            ca_bundle_pem: ca_bundle_pem.map(Into::into),
        },
    )
    .await?;
    match resp {
        RpcResponse::CertUpload(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?cert=custom#ssl", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?cert_error={}#ssl", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct Dns01BeginForm {
    pub selector: String,
    #[serde(default)]
    pub staging: Option<String>,
}

/// Interstitial page that shows the TXT records to publish for a manual
/// DNS-01 wildcard issuance, with a "I've published them, continue" form.
#[derive(Template)]
#[template(path = "cert_dns01.html")]
pub(super) struct Dns01Tpl {
    pub(super) username: String,
    pub(super) user_initial: char,
    pub(super) active: &'static str,
    pub(super) css_version: &'static str,
    pub(super) htmx_version: &'static str,
    pub(super) domain: String,
    pub(super) selector: String,
    pub(super) records: Vec<(String, String)>,
    pub(super) records_field: String,
    pub(super) csrf_finish: String,
    /// Set when a validation was refused because the records aren't on the
    /// authoritative nameservers yet.
    pub(super) error: Option<String>,
}

pub async fn post_cert_dns01_begin(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<Dns01BeginForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::CertManage)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    let staging = form.staging.as_deref() == Some("on");
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::CertDns01Begin { sel, staging },
    )
    .await?;
    match resp {
        RpcResponse::CertDns01Begin {
            completed: true, ..
        } => Ok(Redirect::to(&format!("/hostings/{}?cert=wildcard", sel_url)).into_response()),
        RpcResponse::CertDns01Begin {
            completed: false,
            records,
        } => {
            let tpl = Dns01Tpl {
                username: ctx.username.clone(),
                user_initial: crate::handlers::user_initial(&ctx.username),
                active: "hostings",
                css_version: crate::handlers::css_version(),
                htmx_version: crate::handlers::htmx_version(),
                domain: detail.domain.clone(),
                selector: detail.id.as_str().to_string(),
                records_field: crate::handlers::dns01_records_field(&records),
                records,
                csrf_finish: csrf_token_for(&state, &ctx, "/hostings/cert/dns01/finish"),
                error: None,
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cert_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct Dns01FinishForm {
    pub selector: String,
    /// The records the page showed (see `dns01_records_field`).
    #[serde(default)]
    pub records: String,
}

pub async fn post_cert_dns01_finish(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<Dns01FinishForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::CertManage)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let found = find_hosting_anywhere(&state, sel.clone()).await.ok();
    let target_owned: Option<String> = found.as_ref().and_then(|(_d, n)| n.clone());
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::CertDns01Finish { sel },
    )
    .await?;
    let records = crate::handlers::parse_dns01_records_field(&form.records);
    match resp {
        RpcResponse::CertDns01Finish(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?cert=wildcard", sel_url)).into_response())
        }
        // Nothing was sent to Let's Encrypt: same order, same values. Keep
        // the operator on the records page instead of making them start a
        // new order (= new values) from the hosting page.
        RpcResponse::Error(e)
            if crate::handlers::is_dns01_not_ready(&e.to_string()) && !records.is_empty() =>
        {
            let (domain, selector) = match &found {
                Some((d, _)) => (d.domain.clone(), d.id.as_str().to_string()),
                None => (form.selector.clone(), form.selector.clone()),
            };
            let tpl = Dns01Tpl {
                username: ctx.username.clone(),
                user_initial: crate::handlers::user_initial(&ctx.username),
                active: "hostings",
                css_version: crate::handlers::css_version(),
                htmx_version: crate::handlers::htmx_version(),
                domain,
                selector,
                records_field: crate::handlers::dns01_records_field(&records),
                records,
                csrf_finish: csrf_token_for(&state, &ctx, "/hostings/cert/dns01/finish"),
                error: Some(e.to_string()),
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cert_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
