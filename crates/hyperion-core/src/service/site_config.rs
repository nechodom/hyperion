//! Per-hosting site settings: suspend/resume, vhost options, aliases, Redis, WP
//! debug.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Write the vhost that matches the hosting's STATE.
    ///
    /// `nginx_write_vhost` renders the serving vhost unconditionally — it is
    /// a dumb renderer and has no database to ask. Calling it directly on a
    /// suspended site therefore brings that site back online as a side effect
    /// of an unrelated edit: changing a PHP version or an alias silently
    /// un-suspends a customer who has not paid. Route those through here.
    ///
    /// Only the reason TEXT comes from the database; everything else is the
    /// detail the caller already has. The operator's existing suspension
    /// notice is preserved rather than reworded by an unrelated action.
    /// The text a suspended or trashed site's vhost shows visitors.
    ///
    /// Trash writes no suspension row, so reading one for a trashed site found
    /// nothing — the generic "temporarily unavailable" page — or, for a site
    /// suspended before it was trashed, that old reason (an unpaid invoice, say).
    pub(super) async fn suspended_notice(
        &self,
        id: &HostingId,
        state: HostingState,
    ) -> Option<String> {
        if state == HostingState::Trashed {
            return Some(TRASH_NOTICE.to_string());
        }
        hyperion_state::limits::get_suspension(&self.pool, id)
            .await
            .ok()
            .flatten()
            .and_then(|s| s.reason_message)
    }

    pub(crate) async fn write_vhost_for_state(
        &self,
        detail: &HostingDetail,
    ) -> Result<(), RpcError> {
        if matches!(
            detail.state,
            HostingState::Suspended | HostingState::Trashed
        ) {
            let reason = self.suspended_notice(&detail.id, detail.state).await;
            return self
                .adapters
                .nginx_apply_suspended(&detail.domain, detail.aliases.clone(), reason)
                .await
                .map_err(|e| RpcError::Internal_with(format!("suspended vhost: {e}")));
        }
        if detail.vhost_options.crs_settings().mode != hyperion_types::crs::CrsMode::Off {
            // A CRS site coming back (resumed, restored from the trash) after
            // the rule set was unloaded while it was away: load it first, or
            // the site would run the engine with no rules in it.
            let st = self.adapters.modsec_status().await;
            if st.available() && !st.loaded {
                if let Err(e) = self.adapters.modsec_sync_http(true).await {
                    tracing::warn!(domain = %detail.domain, error = %e, "crs: could not load the rule set");
                }
            }
        }
        self.adapters
            .nginx_write_vhost(detail)
            .await
            .map_err(|e| RpcError::Internal_with(format!("vhost: {e}")))
    }

    /// Best-effort suspend. State row goes to 'suspended'; cascading effects
    /// (nginx swap, FPM stop, DB lock, login lock, kill procs) run as
    /// best-effort — failures are logged but don't revert state. Suspended is
    /// the safer state; operators retry to converge.
    pub async fn suspend(
        &self,
        sel: HostingSelector,
        reason: hyperion_types::SuspendReason,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state == HostingState::Suspended {
            // Already suspended. Normally idempotent — but UPGRADE the recorded
            // reason when the incoming one outranks it (operator/lifecycle hold
            // > automated usage hold). Otherwise e.g. a Manual/Expired suspend
            // stacked on an auto OverDisk suspend would leave suspended_by
            // ="over-disk", and the quota enforce loop would then treat the
            // site as its own and auto-resume it — undoing the operator's hold.
            let current = hyperion_state::limits::get_suspension(&self.pool, &detail.id)
                .await
                .ok()
                .flatten();
            let current_label = current
                .as_ref()
                .map(|s| s.suspended_by.as_str())
                .unwrap_or("");
            if suspend_reason_rank(reason.label()) > suspend_reason_rank(current_label) {
                let susp = hyperion_state::limits::SuspensionRow {
                    hosting_id: detail.id.clone(),
                    suspended_at: now_secs(),
                    suspended_by: reason.label().to_string(),
                    reason_message: reason.message().map(|s| s.to_string()),
                    // Preserve any operator-set custom suspended page (the upsert
                    // overwrites every column).
                    custom_page_html: current.as_ref().and_then(|s| s.custom_page_html.clone()),
                };
                hyperion_state::limits::insert_suspension(&self.pool, &susp)
                    .await
                    .map_err(|e| {
                        RpcError::Internal_with(format!("upgrade suspension reason: {e}"))
                    })?;
                // NOT `let _`. Suspension has already stopped the FPM pool by
                // this point, so if the suspended vhost does not go live the
                // ACTIVE one is still serving — and it proxies to a pool that
                // is gone. The visitor gets 502 Bad Gateway instead of the
                // suspension notice, and the panel says "suspended" because
                // the failure was discarded here. Report it.
                if let Err(e) = self
                    .adapters
                    .nginx_apply_suspended(
                        &detail.domain,
                        detail.aliases.clone(),
                        reason.message().map(|s| s.to_string()),
                    )
                    .await
                {
                    tracing::error!(
                        error = %e, domain = %detail.domain,
                        "suspend: could not apply the suspended vhost — the site will \
                         answer 502 until nginx accepts a config"
                    );
                    return Err(RpcError::ProvisioningFailed {
                        stage: "nginx_suspended_vhost".into(),
                        reason: format!(
                            "{e}. The site is suspended but still serving its old vhost, \
                             which now points at a stopped PHP pool — visitors get 502. \
                             Fix the nginx error and suspend again."
                        ),
                    });
                }
                self.append_audit(
                    "hosting.suspend",
                    Some(detail.id.as_str()),
                    &serde_json::json!({
                        "reason": reason.label(),
                        "upgraded_from": current_label,
                    })
                    .to_string(),
                    "ok",
                )
                .await;
            }
            // Idempotent, and it lets a suspend retried after a part-way
            // failure finish disabling the logins. A site suspended by an
            // older version has no record, and is recorded as such.
            self.apply_login_policy(&detail.id, None).await;
            return Ok(());
        }
        if detail.state == HostingState::Deleting {
            return Err(RpcError::Conflict {
                message: "hosting is being deleted".into(),
            });
        }
        // A trashed row is still loadable via get() (no state filter),
        // so suspend on its detail page / `hctl suspend <domain>` would
        // flip it to Suspended WITHOUT clearing trashed_at — yanking it
        // out of the trash list and the GC (both filter state='trashed')
        // and resurrecting it into the main hostings list. Refuse.
        if detail.state == HostingState::Trashed {
            return Err(RpcError::Conflict {
                message: "hosting is in trash — restore it first".into(),
            });
        }
        {
            // The state and the record that says this code manages the site's
            // logins go down together: a resume racing the slower effects
            // below must not take the site for one an older version locked.
            let _serial = LOGIN_LOCKS.lock().await;
            hostings::set_state(&self.pool, &detail.id, HostingState::Suspended, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("set suspended: {e}")))?;
            self.mark_login_policy_managed_held(&detail.id).await;
        }
        let susp = hyperion_state::limits::SuspensionRow {
            hosting_id: detail.id.clone(),
            suspended_at: now_secs(),
            suspended_by: reason.label().to_string(),
            reason_message: reason.message().map(|s| s.to_string()),
            custom_page_html: None,
        };
        hyperion_state::limits::insert_suspension(&self.pool, &susp)
            .await
            .map_err(|e| RpcError::Internal_with(format!("insert suspension: {e}")))?;

        // Logged, not discarded. The FPM pool is stopped a few lines below,
        // so a vhost that never went live means the site answers 502 rather
        // than the notice — and silence here is why that looked like a
        // mystery rather than a failed step.
        if let Err(e) = self
            .adapters
            .nginx_apply_suspended(
                &detail.domain,
                detail.aliases.clone(),
                reason.message().map(|s| s.to_string()),
            )
            .await
        {
            tracing::error!(
                error = %e, domain = %detail.domain,
                "suspend: could not apply the suspended vhost — the site will answer 502"
            );
        }
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_lock(db.engine, &db.db_user).await;
        }
        // The state and its record were written at the top.
        self.apply_login_policy(&detail.id, Some(false)).await;
        let _ = self.adapters.kill_user_procs(&detail.system_user).await;

        self.append_audit(
            "hosting.suspend",
            Some(detail.id.as_str()),
            &serde_json::json!({"reason": reason.label()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Undo a suspend. Brings the hosting back to 'active'.
    pub async fn resume(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Suspended {
            return Ok(());
        }
        // Re-apply effects in resume order.
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_unlock(db.engine, &db.db_user).await;
        }
        if let Some(ver) = detail.php_version {
            let _ = self.fpm_ensure_with_limits(&detail, ver).await;
        }
        let _ = self.adapters.nginx_write_vhost(&detail).await;
        {
            let _serial = LOGIN_LOCKS.lock().await;
            // Legacy only if it is STILL suspended with no record: a second,
            // concurrent resume finds the site already active.
            let still_suspended = self
                .get(HostingSelector::Id(detail.id.clone()))
                .await
                .is_ok_and(|d| d.state == HostingState::Suspended);
            let legacy =
                still_suspended && matches!(self.login_lock_record(&detail.id).await, Ok(None));
            hostings::set_state(&self.pool, &detail.id, HostingState::Active, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("set active: {e}")))?;
            self.apply_login_policy_held(&detail.id, Some(legacy)).await;
        }
        hyperion_state::limits::delete_suspension(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete suspension: {e}")))?;
        self.append_audit("hosting.resume", Some(detail.id.as_str()), "{}", "ok")
            .await;
        Ok(())
    }

    /// Apply per-hosting vhost options. Validates fields, writes the
    /// htpasswd file (if basic auth password supplied), persists the
    /// new options row, re-renders the vhost with `nginx -t` running
    /// inside `nginx_write_vhost` — rollback on any failure.
    ///
    /// Returns the persisted options (with `basic_auth_set = true`
    /// when a password was supplied, regardless of whether it was
    /// just set or already on file).
    /// Change a reverse-proxy hosting's upstream URL: validate it, update the
    /// row, and re-render the vhost (which `nginx -t`s and rolls back). Returns
    /// the updated detail so the caller can re-render its card.
    pub async fn set_proxy_upstream(
        &self,
        sel: HostingSelector,
        upstream_url: String,
    ) -> Result<hyperion_types::HostingDetail, RpcError> {
        let detail = self.get(sel).await?;
        if detail.kind != "reverse_proxy" {
            return Err(RpcError::Validation {
                message: "this hosting is not a reverse proxy".into(),
            });
        }
        // The renderer is the real chokepoint (it re-validates on every write),
        // but reject here too so the operator gets a clean message, not a vhost
        // error, and the row never stores a value the renderer would refuse.
        let clean =
            hyperion_adapters::nginx::validate_upstream_url(&upstream_url).map_err(|e| {
                RpcError::Validation {
                    message: e.to_string(),
                }
            })?;
        hyperion_state::hostings::set_kind(
            &self.pool,
            &detail.id,
            "reverse_proxy",
            Some(&clean),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("save upstream: {e}")))?;

        let mut updated = detail.clone();
        updated.proxy_upstream_url = Some(clean.clone());
        self.write_vhost_for_state(&updated).await?;

        self.append_audit(
            "hosting.set_proxy_upstream",
            Some(detail.id.as_str()),
            &serde_json::json!({ "domain": detail.domain, "upstream": clean }).to_string(),
            "ok",
        )
        .await;
        Ok(updated)
    }

    /// Validate and normalise vhost options before they are stored and
    /// rendered: every value here ends up in nginx config, so anything
    /// outside its closed set or bounds is refused by name. Shared by the
    /// panel save and the migration importer — a bundle is input too.
    pub(super) async fn normalize_vhost_options(
        &self,
        detail: &HostingDetail,
        mut options: hyperion_types::VhostOptions,
    ) -> Result<hyperion_types::VhostOptions, RpcError> {
        // ─── Validation ─────────────────────────────────────────────
        // HSTS bounds. 0 = disabled; anything above ~2y is silly.
        if options.hsts_max_age < 0 || options.hsts_max_age > 63_072_000 {
            return Err(RpcError::Validation {
                message: "hsts_max_age must be 0..=63072000 (2 years)".into(),
            });
        }
        // FastCGI cache TTL. 0 = use a sane default; cap at 1 day
        // (caching dynamic PHP for longer is almost never right).
        if options.fastcgi_cache_ttl < 0 || options.fastcgi_cache_ttl > 86_400 {
            return Err(RpcError::Validation {
                message: "fastcgi_cache_ttl must be 0..=86400 (24h)".into(),
            });
        }
        // Canonical host: a closed set — this string reaches an nginx
        // `return 301 https://<value>` and a `$host !=` comparison, so a
        // free-form value would be config injection with extra steps.
        if !matches!(options.canonical_host.as_str(), "" | "www" | "non-www") {
            return Err(RpcError::Validation {
                message: "canonical_host must be empty, \"www\" or \"non-www\"".into(),
            });
        }
        // "www" needs www.<domain> inside the cert, or every redirect is
        // served over a TLS error. The create/alias flow adds the www
        // alias to the SANs; a hosting without it must add the alias
        // first, and refusing here with the reason beats a browser
        // certificate warning the operator has to reverse-engineer.
        if options.canonical_host == "www" {
            let www = format!("www.{}", detail.domain.trim_start_matches("www."));
            if !detail.aliases.iter().any(|a| a == &www) {
                return Err(RpcError::Validation {
                    message: format!(
                        "canonical host www requires the alias {www} on this hosting \
                         (it is what puts the name into the certificate). Add the \
                         alias, reissue the certificate, then enable the redirect."
                    ),
                });
            }
        }
        if options.fastcgi_cache_enabled && options.fastcgi_cache_ttl == 0 {
            options.fastcgi_cache_ttl = 300; // 5 min default.
        }
        // Redirect: validated by the adapter at render time too, but
        // catch obvious mistakes early so the operator gets a clean
        // error in the UI rather than an nginx -t failure.
        if !options.redirect_url.is_empty()
            && !(options.redirect_url.starts_with("http://")
                || options.redirect_url.starts_with("https://"))
        {
            return Err(RpcError::Validation {
                message: "redirect_url must start with http:// or https://".into(),
            });
        }
        if options.redirect_code != 0
            && options.redirect_code != 301
            && options.redirect_code != 302
            && options.redirect_code != 307
            && options.redirect_code != 308
        {
            return Err(RpcError::Validation {
                message: "redirect_code must be 301, 302, 307, or 308".into(),
            });
        }
        // Basic auth: empty username with the toggle on is nonsense.
        if options.basic_auth_enabled && options.basic_auth_user.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "basic_auth_user is required when basic auth is enabled".into(),
            });
        }
        // Custom snippet length bound: prevents an operator pasting
        // a 10MB nginx config blob.
        if options.custom_nginx_snippet.len() > 32 * 1024 {
            return Err(RpcError::Validation {
                message: "custom_nginx_snippet must be ≤ 32 KiB".into(),
            });
        }
        // WAF level. A non-empty value must be one we know — it picks which
        // rules nginx renders. An EMPTY one comes from a caller that predates
        // the rework (an older master, a package flipping only the bool):
        // keep the stored level and pins when the bool still agrees with
        // them, so a save from an old panel does not wipe a site's rule
        // overrides; otherwise the bool decides, as it always did.
        if options.waf_level.trim().is_empty() {
            let stored = detail.vhost_options.effective_waf_level();
            let level = if options.waf_enabled == (stored != hyperion_types::waf::WafLevel::Off) {
                stored
            } else if options.waf_enabled {
                hyperion_types::waf::WafLevel::Standard
            } else {
                hyperion_types::waf::WafLevel::Off
            };
            if options.waf_overrides.trim().is_empty() {
                options.waf_overrides = detail.vhost_options.waf_overrides.clone();
            }
            if level == hyperion_types::waf::WafLevel::Off
                && stored != hyperion_types::waf::WafLevel::Off
            {
                // The old switch turned off: that is "no WAF", pins included.
                options.waf_turn_off();
            } else {
                options.set_waf_level(level);
            }
        } else {
            let Some(level) = hyperion_types::waf::WafLevel::parse(&options.waf_level) else {
                return Err(RpcError::Validation {
                    message: "waf_level must be off, standard or strict".into(),
                });
            };
            options.set_waf_level(level);
        }
        options.waf_overrides = hyperion_types::waf::overrides_to_string(
            &hyperion_types::waf::parse_overrides(&options.waf_overrides),
        );

        // ─── OWASP Core Rule Set ───────────────────────────────────
        let stored_crs = detail.vhost_options.crs_settings();
        if options.crs_mode.trim().is_empty() {
            // A caller that predates the CRS tier (an older master, an API
            // client sending only the fields it knows): keep every stored
            // CRS setting rather than reading the empty mode as "off".
            options.crs_mode = detail.vhost_options.crs_mode.clone();
            options.crs_paranoia = detail.vhost_options.crs_paranoia;
            options.crs_threshold = detail.vhost_options.crs_threshold;
            options.crs_wordpress = detail.vhost_options.crs_wordpress;
            options.crs_exclusions = detail.vhost_options.crs_exclusions.clone();
        } else {
            use hyperion_types::crs;
            let Some(mode) = crs::CrsMode::parse(&options.crs_mode) else {
                return Err(RpcError::Validation {
                    message: "crs_mode must be off, detect or block".into(),
                });
            };
            options.crs_mode = mode.as_str().to_string();
            if options.crs_paranoia == 0 {
                options.crs_paranoia = crs::DEFAULT_PARANOIA;
            }
            if !crs::PARANOIA_CHOICES.contains(&options.crs_paranoia) {
                return Err(RpcError::Validation {
                    message: "crs_paranoia must be 1 or 2".into(),
                });
            }
            if options.crs_threshold == 0 {
                options.crs_threshold = crs::DEFAULT_THRESHOLD;
            }
            if !(2..=100).contains(&options.crs_threshold) {
                return Err(RpcError::Validation {
                    message: "crs_threshold must be 2..=100".into(),
                });
            }
            // Strict here, lenient on read: what is STORED must be exactly
            // what the vhost renders, so a bad entry is refused by name.
            let list: Vec<crs::CrsExclusion> = if options.crs_exclusions.trim().is_empty() {
                Vec::new()
            } else {
                serde_json::from_str(&options.crs_exclusions).map_err(|e| RpcError::Validation {
                    message: format!("crs_exclusions is not a valid list: {e}"),
                })?
            };
            crs::validate_exclusions(&list).map_err(|message| RpcError::Validation { message })?;
            options.crs_exclusions = crs::exclusions_to_string(&list);
            // Turning it ON needs the engine on THIS node. A site that already
            // had it on keeps saving even if the engine has gone since — the
            // vhost then renders without it rather than refusing every save.
            if mode != crs::CrsMode::Off && stored_crs.mode == crs::CrsMode::Off {
                let st = self.adapters.modsec_status().await;
                if !st.available() {
                    return Err(RpcError::Validation {
                        message:
                            "The OWASP Core Rule Set needs ModSecurity on this node — install \
                                  it from the Protection card first."
                                .into(),
                    });
                }
            }
        }
        Ok(options)
    }

    pub async fn set_vhost_options(
        &self,
        sel: HostingSelector,
        options: hyperion_types::VhostOptions,
        basic_auth_password: Option<String>,
    ) -> Result<hyperion_types::VhostOptions, RpcError> {
        let detail = self.get(sel).await?;

        let mut options = self.normalize_vhost_options(&detail, options).await?;
        let stored_crs = detail.vhost_options.crs_settings();
        // Whether the node's need for the http-level rule set may change.
        let crs_toggled = (options.crs_settings().mode == hyperion_types::crs::CrsMode::Off)
            != (stored_crs.mode == hyperion_types::crs::CrsMode::Off);

        // ─── htpasswd write (before persist, so a failed bcrypt is
        //     surfaced before we change DB state) ─────────────────────
        let pw_nonempty = basic_auth_password.as_deref().filter(|s| !s.is_empty());
        let pw_provided = pw_nonempty.is_some();
        let mut new_hash_for_db: Option<String> = None;
        if let Some(pw) = pw_nonempty {
            // Cost 10 — same as nginx auth_basic_user_file examples;
            // bcrypt-12 starts noticeably hurting RPS on the first
            // request after a worker boot.
            let hash = bcrypt::hash(pw, 10).map_err(|e| {
                RpcError::Internal_with(format!("bcrypt hash basic-auth password: {e}"))
            })?;
            self.adapters
                .nginx_write_htpasswd(detail.id.as_str(), &options.basic_auth_user, &hash)
                .await
                .map_err(|e| RpcError::Internal_with(format!("write htpasswd: {e}")))?;
            new_hash_for_db = Some(hash);
            options.basic_auth_set = true;
        } else if !options.basic_auth_enabled {
            // Operator turned basic auth off — drop the htpasswd
            // file so it can't be re-used if they turn it back on
            // without setting a new password.
            let _ = self
                .adapters
                .nginx_delete_htpasswd(detail.id.as_str())
                .await;
            options.basic_auth_set = false;
            new_hash_for_db = Some(String::new()); // sentinel: clear
        } else {
            // basic_auth_enabled && no new password → keep existing
            // hash (set by a previous call). basic_auth_set carries
            // the truth from DB into the form.
            options.basic_auth_set = detail.vhost_options.basic_auth_set;
        }

        // ─── Persist ───────────────────────────────────────────────
        hyperion_state::hostings::set_vhost_options(
            &self.pool,
            &detail.id,
            &options,
            new_hash_for_db.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("persist vhost options: {e}")))?;

        // ─── Rule set in or out at http level ──────────────────────
        // Before the vhost: a site switching CRS on needs the rule set loaded
        // first; one switching off may unload it now — its old vhost names
        // only per-site rules, which load without the rule set.
        if crs_toggled {
            if let Err(e) = self.crs_sync().await {
                let _ = hyperion_state::hostings::set_vhost_options(
                    &self.pool,
                    &detail.id,
                    &detail.vhost_options,
                    None,
                    now_secs(),
                )
                .await;
                return Err(RpcError::Validation {
                    message: format!(
                        "ModSecurity rule set could not be loaded: {e}. No changes applied."
                    ),
                });
            }
        }

        // ─── Re-render vhost (nginx -t inside write_vhost) ─────────
        let mut new_detail = detail.clone();
        new_detail.vhost_options = options.clone();
        if let Err(e) = self.write_vhost_for_state(&new_detail).await {
            // nginx -t rejected the new vhost. Roll the DB back to
            // the old options so the persisted state matches what
            // nginx is actually serving.
            let _ = hyperion_state::hostings::set_vhost_options(
                &self.pool,
                &detail.id,
                &detail.vhost_options,
                None, // don't touch hash on rollback
                now_secs(),
            )
            .await;
            if crs_toggled {
                let _ = self.crs_sync().await;
            }
            // Roll back htpasswd too if we just wrote it.
            if pw_provided {
                if detail.vhost_options.basic_auth_set {
                    // we don't have the previous hash here; the safest
                    // move is to leave the now-overwritten file in
                    // place — operator just gets to keep the new pw
                    // they typed, which they can type again. They
                    // wanted to change it anyway.
                } else {
                    let _ = self
                        .adapters
                        .nginx_delete_htpasswd(detail.id.as_str())
                        .await;
                }
            }
            return Err(RpcError::Validation {
                message: format!("nginx config rejected: {e}. No changes applied."),
            });
        }

        // ─── Redirect-loop check ───────────────────────────────────
        // `nginx -t` proves the config PARSES, not that it makes sense. A
        // canonical-host redirect is one half of a conversation: the
        // application has an opinion about its own address too, and when the
        // two disagree each one bounces the visitor at the other and the site
        // dies with ERR_TOO_MANY_REDIRECTS. That is not hypothetical — it is
        // how ingratia.cz went down: nginx said www, WordPress's siteurl said
        // apex.
        //
        // Nothing can predict this from config alone, because the other half
        // lives in the site's own database. So test the real thing: apply,
        // follow the chain, and roll back if it cycles. The operator gets the
        // old behaviour back and a message naming what disagreed, rather than
        // a working panel and a dead site.
        if options.canonical_host != detail.vhost_options.canonical_host
            && !options.canonical_host.is_empty()
        {
            // Bring WordPress along BEFORE probing. The loop is not bad luck,
            // it is the two halves disagreeing: nginx sends visitors to one
            // spelling and WordPress's own Site Address sends them back to
            // the other. Telling the operator to go and fix it by hand makes
            // this setting a trap; the panel knows both halves, so it sets
            // both. The probe below stays as the safety net for the cases
            // this cannot reach — a redirect plugin, a hard-coded constant in
            // wp-config.php, an application that is not WordPress at all.
            let canonical = match options.canonical_host.as_str() {
                "www" => format!("www.{}", detail.domain.trim_start_matches("www.")),
                _ => detail.domain.trim_start_matches("www.").to_string(),
            };
            self.wp_align_site_url(&detail, &canonical).await;
            if let Some(loop_hint) = self.redirect_loop_probe(&detail.domain).await {
                let _ = hyperion_state::hostings::set_vhost_options(
                    &self.pool,
                    &detail.id,
                    &detail.vhost_options,
                    None,
                    now_secs(),
                )
                .await;
                let _ = self.adapters.nginx_write_vhost(&detail).await;
                self.append_audit(
                    "hosting.set_vhost_options",
                    Some(detail.id.as_str()),
                    &serde_json::json!({
                        "domain": detail.domain,
                        "canonical_host": options.canonical_host,
                        "reverted": "redirect loop",
                    })
                    .to_string(),
                    "failed",
                )
                .await;
                return Err(RpcError::Validation { message: loop_hint });
            }
        }

        let audit_payload = serde_json::json!({
            "domain": detail.domain,
            "basic_auth_enabled": options.basic_auth_enabled,
            "basic_auth_user": options.basic_auth_user,
            "basic_auth_password_changed": pw_provided,
            "hsts_max_age": options.hsts_max_age,
            "maintenance_mode": options.maintenance_mode,
            "fastcgi_cache_enabled": options.fastcgi_cache_enabled,
            "fastcgi_cache_ttl": options.fastcgi_cache_ttl,
            "custom_nginx_snippet_len": options.custom_nginx_snippet.len(),
            "redirect_url_set": !options.redirect_url.is_empty(),
            "redirect_code": options.redirect_code,
        });
        self.append_audit(
            "hosting.set_vhost_options",
            Some(detail.id.as_str()),
            &audit_payload.to_string(),
            "ok",
        )
        .await;

        Ok(options)
    }

    /// Replace a hosting's alias domains (SANs) after creation. Rewrites the
    /// nginx `server_name` and reloads. Newly-added aliases are NOT yet covered
    /// by the existing certificate — the operator re-issues from the SSL tab to
    /// extend coverage. nginx -t runs inside `nginx_write_vhost`; on rejection
    /// the DB alias set is rolled back so persisted state matches what nginx
    /// actually serves.
    pub async fn hosting_set_aliases(
        &self,
        sel: HostingSelector,
        aliases: Vec<hyperion_validate::Domain>,
    ) -> Result<HostingDetail, RpcError> {
        let detail = self.get(sel).await?;
        // Normalize: drop any alias equal to the primary domain (redundant),
        // dedupe, and sort for a stable server_name ordering.
        let mut seen = std::collections::BTreeSet::new();
        let mut norm: Vec<String> = Vec::new();
        for a in &aliases {
            let s = a.as_str().to_string();
            if s == detail.domain {
                continue;
            }
            if seen.insert(s.clone()) {
                norm.push(s);
            }
        }
        norm.sort();

        let old_aliases = detail.aliases.clone();
        hyperion_state::hostings::replace_aliases(&self.pool, &detail.id, &norm)
            .await
            .map_err(|e| RpcError::Internal_with(format!("replace aliases: {e}")))?;

        // Re-render the vhost with the new server_name. On nginx -t failure,
        // roll the alias set back to what nginx is still serving.
        let new_detail = self.get(HostingSelector::Id(detail.id.clone())).await?;
        if let Err(e) = self.write_vhost_for_state(&new_detail).await {
            let _ = hyperion_state::hostings::replace_aliases(&self.pool, &detail.id, &old_aliases)
                .await;
            return Err(RpcError::Validation {
                message: format!("nginx config rejected: {e}. Aliases reverted."),
            });
        }

        self.append_audit(
            "hosting.set_aliases",
            Some(detail.id.as_str()),
            &serde_json::json!({ "aliases": norm }).to_string(),
            "ok",
        )
        .await;
        Ok(new_detail)
    }

    // ───────────── WP debug + Redis ─────────────

    pub async fn set_wp_debug(
        &self,
        sel: HostingSelector,
        enabled: bool,
        log: bool,
        display: bool,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        let detail = self.get(sel).await?;
        // WP install required.
        if detail.php_version.is_none() {
            return Err(RpcError::Validation {
                message: "WP_DEBUG toggle requires a PHP hosting".into(),
            });
        }
        self.adapters
            .wp_set_debug(&detail.system_user, &detail.root_dir, enabled, log, display)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp set debug: {e}")))?;
        hyperion_state::hostings::set_wp_debug(
            &self.pool,
            &detail.id,
            enabled,
            log,
            display,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("persist wp debug: {e}")))?;
        let mut wp_extras = detail.wp_extras.clone();
        wp_extras.wp_debug_enabled = enabled;
        wp_extras.wp_debug_log = log;
        wp_extras.wp_debug_display = display;
        self.append_audit(
            "hosting.set_wp_debug",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "enabled": enabled,
                "log": log,
                "display": display,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(wp_extras)
    }

    pub async fn set_redis(
        &self,
        sel: HostingSelector,
        enabled: bool,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        let detail = self.get(sel).await?;
        if detail.php_version.is_none() {
            return Err(RpcError::Validation {
                message: "Redis cache requires a PHP hosting".into(),
            });
        }

        if !enabled {
            // Park the DROP-IN first, before anything else is taken away.
            //
            // `wp-content/object-cache.php` is installed by the Redis Object
            // Cache plugin and is loaded by WordPress before plugins,
            // regardless of whether that plugin is active or even still on
            // disk. Removing the credentials while it is still there leaves a
            // drop-in that cannot connect — so every request fatals,
            // INCLUDING wp-cli's own bootstrap. That is the deadlock: the
            // plugin cannot be deactivated or deleted, because doing either
            // needs a WordPress that boots.
            //
            // First, and best-effort: if this fails the site keeps working,
            // whereas doing it last would mean an error here leaves the site
            // down.
            match hyperion_adapters::wpcli::set_object_cache_dropin(
                &detail.system_user,
                &detail.root_dir,
                false,
            )
            .await
            {
                Ok(true) => tracing::info!(
                    domain = %detail.domain,
                    "parked wp-content/object-cache.php before disabling Redis"
                ),
                Ok(false) => {}
                Err(e) => tracing::warn!(
                    error = %e, domain = %detail.domain,
                    "could not park the object-cache drop-in — the site may fatal until it is removed"
                ),
            }
            // Turn off: drop WP constants, delete ACL, clear DB row.
            self.adapters
                .wp_set_redis(&detail.system_user, &detail.root_dir, None)
                .await
                .map_err(|e| RpcError::Internal_with(format!("wp unset redis: {e}")))?;
            let username = redis_username_for(detail.id.as_str());
            let _ = self.adapters.redis_delete_acl(&username).await;
            hyperion_state::hostings::set_redis(
                &self.pool,
                &detail.id,
                false,
                None,
                false,
                now_secs(),
            )
            .await
            .map_err(|e| RpcError::Internal_with(format!("persist redis off: {e}")))?;
            // Clear stored password secret.
            let _ = self
                .secrets
                .delete(&hyperion_types::SecretId(format!(
                    "redis-{}",
                    detail.id.as_str()
                )))
                .await;
            self.append_audit(
                "hosting.set_redis",
                Some(detail.id.as_str()),
                &serde_json::json!({"domain": detail.domain, "enabled": false}).to_string(),
                "ok",
            )
            .await;
            let mut wpe = detail.wp_extras.clone();
            wpe.redis_enabled = false;
            wpe.redis_db_number = None;
            wpe.redis_password_set = false;
            return Ok(wpe);
        }

        // Preflight: redis-server must be installed + running, else
        // the ACL write would fail with a cryptic redis-cli error
        // and wp-config would still point at a host that refuses
        // connections. Detect early + surface a clear actionable
        // message pointing the operator at /services.
        if !self.adapters.redis_is_available().await {
            return Err(RpcError::Conflict {
                message: "redis-server is not installed or not active on this node. \
                          Install + start it from /services first."
                    .into(),
            });
        }

        // Turn on. Allocate a DB slot (idempotent — reuse existing on re-enable).
        let db_number = match detail.wp_extras.redis_db_number {
            Some(n) => n,
            None => {
                let n = hyperion_state::hostings::next_free_redis_db(&self.pool, 16)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("alloc redis db: {e}")))?
                    .ok_or_else(|| RpcError::Conflict {
                        message: "no free Redis DB slot (all 16 in use). Bump `databases` in \
                                  /etc/redis/redis.conf and reload."
                            .into(),
                    })?;
                n
            }
        };
        let password = generate_redis_password();
        let username = redis_username_for(detail.id.as_str());

        // Provision ACL on the local redis-server.
        self.adapters
            .redis_ensure_acl(&username, &password, db_number)
            .await
            .map_err(|e| RpcError::Internal_with(format!("redis ACL: {e}")))?;
        self.ensure_redis_memory_policy().await;

        // Persist secret BEFORE writing wp-config — so a partial
        // failure doesn't leave wp-config pointing at a password we
        // can't recover. (Re-enabling later regenerates anyway, but
        // the operator might want to grep the secret out for an
        // external tool meanwhile.)
        let secret_id = hyperion_types::SecretId(format!("redis-{}", detail.id.as_str()));
        self.secrets
            .put(&secret_id, &password)
            .await
            .map_err(|e| RpcError::Internal_with(format!("store redis secret: {e}")))?;

        // Write WP_REDIS_* into wp-config.
        let cfg = hyperion_types::WpRedisConfig {
            host: "127.0.0.1".into(),
            port: 6379,
            database: db_number,
            username: username.clone(),
            password,
            key_prefix: format!("h{}_", db_number),
        };
        self.adapters
            .wp_set_redis(&detail.system_user, &detail.root_dir, Some(cfg))
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp set redis: {e}")))?;

        hyperion_state::hostings::set_redis(
            &self.pool,
            &detail.id,
            true,
            Some(db_number),
            true,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("persist redis: {e}")))?;
        self.append_audit(
            "hosting.set_redis",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "enabled": true,
                "db_number": db_number,
            })
            .to_string(),
            "ok",
        )
        .await;
        let mut wpe = detail.wp_extras.clone();
        wpe.redis_enabled = true;
        wpe.redis_db_number = Some(db_number);
        wpe.redis_password_set = true;
        Ok(wpe)
    }

    /// Registration spam guard state for one hosting: the operator's intent
    /// (from `hosting_kv`) plus what is actually on disk.
    pub async fn regguard_view(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::regguard::RegGuardView, RpcError> {
        let detail = self.get(sel).await?;
        self.regguard_view_for(&detail).await
    }

    pub(super) async fn regguard_view_for(
        &self,
        detail: &hyperion_types::HostingDetail,
    ) -> Result<hyperion_types::regguard::RegGuardView, RpcError> {
        let enabled =
            hyperion_state::hosting_kv::get(&self.pool, detail.id.as_str(), "regguard_enabled")
                .await
                .ok()
                .flatten()
                .map(|v| v == "1")
                .unwrap_or(false);
        let is_wordpress =
            tokio::fs::try_exists(std::path::Path::new(&detail.root_dir).join("wp-content"))
                .await
                .unwrap_or(false);
        let installed = if is_wordpress {
            hyperion_adapters::regguard::is_installed(&detail.root_dir).await
        } else {
            false
        };
        Ok(hyperion_types::regguard::RegGuardView {
            enabled,
            installed,
            is_wordpress,
        })
    }

    /// Turn the guard on or off: install/remove the must-use plugin on the
    /// owning node and record the operator's intent in `hosting_kv`.
    pub async fn regguard_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
    ) -> Result<hyperion_types::regguard::RegGuardView, RpcError> {
        let detail = self.get(sel).await?;
        if enabled {
            hyperion_adapters::regguard::install(&detail.root_dir, &detail.system_user)
                .await
                .map_err(|e| RpcError::Internal_with(format!("install spam guard: {e}")))?;
        } else {
            hyperion_adapters::regguard::remove(&detail.root_dir).await;
        }
        hyperion_state::hosting_kv::set(
            &self.pool,
            detail.id.as_str(),
            "regguard_enabled",
            if enabled { "1" } else { "0" },
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("save spam guard state: {e}")))?;
        self.append_audit(
            "hosting.regguard_set",
            Some(detail.id.as_str()),
            &serde_json::json!({ "domain": detail.domain, "enabled": enabled }).to_string(),
            "ok",
        )
        .await;
        self.regguard_view_for(&detail).await
    }

    pub async fn rotate_redis_password(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        let detail = self.get(sel).await?;
        if !detail.wp_extras.redis_enabled {
            return Err(RpcError::Validation {
                message: "Redis not enabled for this hosting".into(),
            });
        }
        let Some(db_number) = detail.wp_extras.redis_db_number else {
            return Err(RpcError::Validation {
                message: "Redis enabled but no DB number — re-enable Redis first".into(),
            });
        };
        let password = generate_redis_password();
        let username = redis_username_for(detail.id.as_str());
        self.adapters
            .redis_ensure_acl(&username, &password, db_number)
            .await
            .map_err(|e| RpcError::Internal_with(format!("redis ACL rotate: {e}")))?;
        let secret_id = hyperion_types::SecretId(format!("redis-{}", detail.id.as_str()));
        self.secrets
            .put(&secret_id, &password)
            .await
            .map_err(|e| RpcError::Internal_with(format!("store redis secret: {e}")))?;
        let cfg = hyperion_types::WpRedisConfig {
            host: "127.0.0.1".into(),
            port: 6379,
            database: db_number,
            username,
            password,
            key_prefix: format!("h{}_", db_number),
        };
        self.adapters
            .wp_set_redis(&detail.system_user, &detail.root_dir, Some(cfg))
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp re-set redis: {e}")))?;
        self.append_audit(
            "hosting.rotate_redis_password",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        Ok(detail.wp_extras)
    }

    pub async fn rotate_wp_debug_log(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // truncate via Linux only. Caller's responsibility to verify
        // hosting exists (.get already does).
        let p = std::path::Path::new(&detail.root_dir).join("wp-content/debug.log");
        // best-effort — if file is missing, we Ok anyway.
        // O_NOFOLLOW, not File::create: that opens O_CREAT|O_TRUNC and
        // follows links, so a tenant who points wp-content/debug.log at a
        // root-owned file and clicks "Clear debug log" on their own site
        // truncates that file instead. They own wp-content, so they can
        // place the link.
        if let Err(e) = hyperion_adapters::fs::truncate_no_follow(&p) {
            return Err(RpcError::Validation {
                message: format!("truncate debug.log: {e}"),
            });
        }
        // Update sampled size in DB so the UI reflects the new state.
        let _ = hyperion_state::hostings::set_wp_debug_log_size(&self.pool, &detail.id, 0).await;
        self.append_audit(
            "hosting.rotate_wp_debug_log",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Re-assert the Redis ACL for every hosting that has Redis on, using the
    /// password already in the secret store.
    ///
    /// The ACL is written once at enable and once at rotate, so a site keeps
    /// whatever rule set was current the day it was switched on. When the
    /// rules have to change — `+info` was missing, and the Redis Object Cache
    /// plugin calls INFO on every page load, so the site broke with
    /// "NOPERM … has no permissions to run the 'info' command" and the plugin
    /// could not even be deactivated through wp-cli, because its drop-in runs
    /// first and fails there too — every existing site stays broken until
    /// someone thinks to rotate the password.
    ///
    /// Idempotent, and deliberately reuses the STORED password rather than
    /// generating one: a new password would have to be written into
    /// wp-config.php too, and a boot-time task must not be able to break a
    /// working site.
    pub async fn redis_acl_reassert_on_boot(&self) -> Result<i64, RpcError> {
        if !self.adapters.redis_is_available().await {
            return Ok(0);
        }
        let mut fixed = 0i64;
        for s in self.list().await? {
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            if !detail.wp_extras.redis_enabled {
                continue;
            }
            let Some(db_number) = detail.wp_extras.redis_db_number else {
                continue;
            };
            let secret_id = hyperion_types::SecretId(format!("redis-{}", detail.id.as_str()));
            let Ok(password) = self.secrets.get::<String>(&secret_id).await else {
                continue;
            };
            let username = redis_username_for(detail.id.as_str());
            match self
                .adapters
                .redis_ensure_acl(&username, &password, db_number)
                .await
            {
                Ok(()) => fixed += 1,
                Err(e) => {
                    tracing::warn!(error = %e, user = %username, "redis ACL re-assert failed")
                }
            }
        }
        Ok(fixed)
    }
}

/// Stable per-hosting Redis ACL username derived from the ULID.
/// `r_` prefix + first 8 chars of the ULID lowercased — short
/// enough to fit in `redis-cli ACL LIST` output without wrapping,
/// long enough to avoid collisions in any realistic deployment
/// (8 base32 chars = 40 bits = 1T combinations).
pub(super) fn redis_username_for(hosting_id: &str) -> String {
    let suffix: String = hosting_id.chars().take(8).collect();
    format!("r_{}", suffix.to_lowercase())
}

/// Generate a 32-char alphanumeric password for Redis. Same shape
/// as `adapters::random_password` but inlined here to avoid pulling
/// in the whole adapters crate from this module path (already
/// indirectly available via Arc<A: AdapterPort>, but cleaner to
/// reuse the same RNG without crossing the trait boundary).
pub(super) fn generate_redis_password() -> String {
    hyperion_adapters::random_password()
}
