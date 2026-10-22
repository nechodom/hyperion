//! PHP version, limits and php.ini overrides.

use super::*;

#[derive(Deserialize)]
pub struct PhpIniForm {
    pub selector: String,
    #[serde(default)]
    pub memory_limit: String,
    #[serde(default)]
    pub upload_max_filesize: String,
    #[serde(default)]
    pub post_max_size: String,
    #[serde(default)]
    pub max_execution_time: String,
    #[serde(default)]
    pub max_input_vars: String,
    #[serde(default)]
    pub display_errors: String,
}

/// `256M`, `1G`, `512` or empty. Bounded so a pasted novel can't get in.
pub(super) fn valid_php_size(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let (digits, suffix) = if s
        .as_bytes()
        .last()
        .map(u8::is_ascii_alphabetic)
        .unwrap_or(false)
    {
        (&s[..s.len() - 1], &s[s.len() - 1..])
    } else {
        (s, "")
    };
    !digits.is_empty()
        && digits.len() <= 6
        && digits.bytes().all(|b| b.is_ascii_digit())
        && matches!(suffix, "" | "K" | "M" | "G" | "k" | "m" | "g")
}

pub(super) fn valid_php_int(s: &str, lo: i64, hi: i64) -> bool {
    s.is_empty()
        || s.parse::<i64>()
            .map(|n| (lo..=hi).contains(&n))
            .unwrap_or(false)
}

/// POST /hostings/php-ini — write operator php.ini overrides as a
/// per-hosting `.user.ini` in htdocs (PHP_INI_PERDIR; FPM re-reads it
/// within user_ini.cache_ttl, default 5 min — no restart, and a bad
/// value can never stop the pool starting). Values are validated and
/// also kept in the master KV for re-display.
pub async fn post_set_php_ini(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<PhpIniForm>,
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
    let dr = |k: &str| -> String {
        match k {
            "On" | "Off" | "" => k.to_string(),
            _ => String::new(),
        }
    };
    let display = dr(form.display_errors.trim());
    // Validate; on any bad value bounce back with a flash.
    if !valid_php_size(form.memory_limit.trim())
        || !valid_php_size(form.upload_max_filesize.trim())
        || !valid_php_size(form.post_max_size.trim())
        || !valid_php_int(form.max_execution_time.trim(), 0, 3600)
        || !valid_php_int(form.max_input_vars.trim(), 100, 200_000)
        || (!form.display_errors.trim().is_empty() && display.is_empty())
    {
        return Ok(save_result(
            &headers,
            false,
            "Invalid PHP value — sizes like 256M/1G, numbers in range, display_errors On/Off.",
            format!("/hostings/{sel_url}?flash_error=Invalid+PHP+value#settings"),
        ));
    }
    // Resolve owner — the .user.ini lives on the node hosting the site.
    let (detail, owner_node) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let hosting_id = detail.id.as_str().to_string();

    // Build the .user.ini (only set lines).
    let mut body = String::from("; Managed by Hyperion — edit via the panel (Settings → PHP).\n");
    let mut line = |k: &str, v: &str| {
        let v = v.trim();
        if !v.is_empty() {
            body.push_str(&format!("{k} = {v}\n"));
        }
    };
    // memory_limit and max_execution_time are DELIBERATELY not written.
    //
    // The FPM pool sets both as `php_admin_value`, which by definition
    // `.user.ini` may not override — so a value here was saved, reported
    // as applied, and then ignored by PHP. Two cards claimed to own the
    // same two settings and only one of them worked. They now live solely
    // in "PHP-FPM & DB limits", which rewrites the pool. Not writing them
    // also cleans a stale line out of a `.user.ini` from before this
    // change, the next time the card is saved.
    line("upload_max_filesize", &form.upload_max_filesize);
    line("post_max_size", &form.post_max_size);
    line("max_input_vars", &form.max_input_vars);
    if !display.is_empty() {
        body.push_str(&format!("display_errors = {display}\n"));
    }
    let bytes_b64 = base64_encode(body.as_bytes());
    // Write the file on the owning node (jailed write chowns to the
    // hosting user, so PHP can read it).
    let written = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileWrite {
            sel: HostingSelector::Id(detail.id.clone()),
            rel_path: ".user.ini".into(),
            bytes_b64,
        },
    )
    .await;
    // A write that did not land must not be reported — or stored for
    // re-display — as saved: with the owning node down, the form used to
    // say "PHP settings saved" and show the new values while PHP kept the
    // old ones.
    let write_error = match written {
        Ok(RpcResponse::Error(e)) => Some(e.to_string()),
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    };
    if let Some(e) = write_error {
        tracing::warn!(hosting = %hosting_id, error = %e, "PHP settings: .user.ini write failed");
        return Ok(save_result(
            &headers,
            false,
            "PHP settings were NOT saved — the server hosting this site could not write them. \
             Try again in a moment.",
            format!("/hostings/{sel_url}?flash_error=PHP+settings+not+saved#settings"),
        ));
    }
    // Persist values for re-display (master KV, keyed by ULID).
    for (k, v) in [
        ("php.memory_limit", form.memory_limit.trim()),
        ("php.upload_max_filesize", form.upload_max_filesize.trim()),
        ("php.post_max_size", form.post_max_size.trim()),
        ("php.max_execution_time", form.max_execution_time.trim()),
        ("php.max_input_vars", form.max_input_vars.trim()),
        ("php.display_errors", display.as_str()),
    ] {
        let _ = hyperion_rpc_client::call(
            &state.agent_socket,
            Request::HostingKvSet {
                hosting_id: hosting_id.clone(),
                key: k.to_string(),
                value: v.to_string(),
            },
        )
        .await;
    }
    Ok(save_result(
        &headers,
        true,
        "PHP settings saved (.user.ini; applies within ~5 min).",
        format!(
            "/hostings/{sel_url}?flash={}#settings",
            urlencoding("PHP settings saved (.user.ini; applies within ~5 min).")
        ),
    ))
}

#[derive(Deserialize)]
pub struct SetLimitsForm {
    pub(super) selector: String,
    pub(super) php_memory_mb: i64,
    pub(super) php_max_exec_secs: i64,
    pub(super) php_max_children: i64,
    pub(super) php_max_requests: i64,
    pub(super) db_max_connections: i64,
    /// Checkbox: absent when unticked.
    #[serde(default)]
    pub(super) mem_auto: String,
    #[serde(default)]
    pub(super) mem_auto_max_mb: String,
    #[serde(default)]
    pub(super) target_node: String,
}

#[derive(Deserialize)]
pub struct SetPhpVersionForm {
    pub selector: String,
    /// One of "8.1", "8.2", "8.3", "8.4". Anything else returns 400.
    pub php_version: String,
    /// Optional target-node hint; honours the dispatcher's
    /// local/remote routing the same way every other POST does.
    #[serde(default)]
    pub target_node: String,
}

/// POST /hostings/set-php-version — flip an existing hosting's PHP
/// runtime version. The agent does the FPM teardown + bring-up +
/// vhost rewrite atomically; on success we redirect back to the
/// hosting detail with a success flash on the PHP card.
pub async fn post_set_php_version(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetPhpVersionForm>,
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
    let version: hyperion_types::PhpVersion = form
        .php_version
        .trim()
        .parse()
        .map_err(|e: String| AppError::BadRequest(format!("php_version: {e}")))?;
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetPhpVersion { sel, version },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetPhpVersion(v) => Ok(Redirect::to(&format!(
            "/hostings/{}?flash=PHP+version+switched+to+{}",
            urlencoding(&form.selector),
            v
        ))
        .into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_set_limits(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<SetLimitsForm>,
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
    let mut l = hyperion_types::HostingLimits::defaults();
    l.php_memory_mb = form.php_memory_mb;
    l.php_max_exec_secs = form.php_max_exec_secs;
    l.php_max_children = form.php_max_children;
    l.php_max_requests = form.php_max_requests;
    l.db_max_connections = form.db_max_connections;
    // disk_hard_bytes / bw_monthly_bytes are left at None on purpose.
    // The columns still exist but NOTHING reads them — no enforcement, no
    // alert — so the form fields that fed them were placebo and are gone.
    // The enforced caps are the hosting_quotas row (the quota card), which
    // profiles also write through quota_set. Saving this card now clears
    // any stale ghost value, so old rows converge on the truth.
    let mem_auto_max: i64 = match form.mem_auto_max_mb.trim() {
        "" => hyperion_types::phpmem::DEFAULT_MAX_MB,
        v => match v.parse::<i64>() {
            Ok(n) if (16..=8192).contains(&n) => n,
            _ => {
                return Ok(save_result(
                    &headers,
                    false,
                    "Automatic memory ceiling must be 16–8192 MB.",
                    format!(
                        "/hostings/{}?flash_error={}#limits",
                        urlencoding(&form.selector),
                        urlencoding("Automatic memory ceiling must be 16–8192 MB.")
                    ),
                ))
            }
        },
    };
    let mem_auto_on = form.mem_auto.trim() == "on";
    let target = node_target(&form.target_node);
    let hosting_id = find_hosting_anywhere(&state, sel.clone())
        .await?
        .0
        .id
        .as_str()
        .to_string();
    if mem_auto_on {
        // A ceiling at or under the operator's own value gives the
        // automation nothing to raise to — every out-of-memory would end as
        // a daily "stuck at the ceiling" alert. Refuse it before anything is
        // written. The floor is decided the way set_limits will decide it,
        // from what the OWNING node has stored.
        use hyperion_types::phpmem;
        let stored = fetch_limits(&state, target, sel.clone())
            .await
            .ok()
            .map(|l| l.php_memory_mb);
        let st = match crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::HostingKvList {
                hosting_id: hosting_id.clone(),
            },
        )
        .await
        {
            Ok(RpcResponse::HostingKvList(v)) => v
                .into_iter()
                .find(|(k, _)| k == phpmem::KV_STATE)
                .and_then(|(_, v)| phpmem::State::parse(&v)),
            _ => None,
        };
        let floor = phpmem::floor_after_save(form.php_memory_mb, stored, st.as_ref());
        if phpmem::ceiling_leaves_no_room(mem_auto_max, floor) {
            let msg = format!(
                "Automatic ceiling ({mem_auto_max} MB) must be above the site's own PHP memory \
                 ({floor} MB), or there is nothing to raise to."
            );
            return Ok(save_result(
                &headers,
                false,
                &msg,
                format!(
                    "/hostings/{}?flash_error={}#limits",
                    urlencoding(&form.selector),
                    urlencoding(&msg)
                ),
            ));
        }
    }
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetLimits {
            sel: sel.clone(),
            limits: l,
        },
    )
    .await?;
    if let RpcResponse::HostingSetLimits(_) = resp {
        // The automation's switch and ceiling live in the OWNING node's
        // hosting_kv, beside the state its tick keeps — the pool it rewrites
        // is there. Written after the limits, so a refused save above leaves
        // them as they were.
        for (key, value) in [
            (
                hyperion_types::phpmem::KV_ENABLED,
                if mem_auto_on { "on" } else { "off" }.to_string(),
            ),
            (hyperion_types::phpmem::KV_MAX_MB, mem_auto_max.to_string()),
        ] {
            match crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::HostingKvSet {
                    hosting_id: hosting_id.clone(),
                    key: key.into(),
                    value,
                },
            )
            .await?
            {
                RpcResponse::HostingKvSet => {}
                RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
                _ => return Err(AppError::Internal("unexpected response".into())),
            }
        }
    }
    match resp {
        RpcResponse::HostingSetLimits(_) => Ok(save_result(
            &headers,
            true,
            "PHP-FPM & DB limits saved.",
            format!(
                "/hostings/{}?flash={}#limits",
                urlencoding(&form.selector),
                urlencoding("PHP-FPM & DB limits saved.")
            ),
        )),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
