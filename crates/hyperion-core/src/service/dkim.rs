//! Per-hosting DKIM signing keys and their DNS status.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ── DKIM outbound-mail signing (OpenDKIM milter) ──────────────────────
    // Per-hosting: generate an RSA key for the domain, add it to OpenDKIM's
    // signing tables, and surface the DNS TXT record the operator must
    // publish. We never touch DNS (see `dns_spf_check` for the same split).
    // All four run ON the owning node — the web layer dispatches them there,
    // because the key + tables live where the mail is actually injected.

    pub(super) async fn dkim_kv_get(&self, hosting_id: &str) -> DkimKv {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, "dkim").await {
            Ok(Some(v)) => serde_json::from_str(&v).unwrap_or_default(),
            _ => DkimKv::default(),
        }
    }

    pub(super) async fn dkim_kv_set(&self, hosting_id: &str, kv: &DkimKv) -> Result<(), RpcError> {
        let v = serde_json::to_string(kv)
            .map_err(|e| RpcError::Internal_with(format!("dkim kv encode: {e}")))?;
        hyperion_state::hosting_kv::set(&self.pool, hosting_id, "dkim", &v, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("dkim kv set: {e}")))
    }

    /// Assemble the wire status from the KV record + the key on disk.
    pub(super) async fn dkim_status_for(
        &self,
        detail: &HostingDetail,
    ) -> hyperion_types::DkimStatus {
        let domain = detail.domain.clone();
        let mut st = hyperion_types::DkimStatus {
            domain: domain.clone(),
            ..Default::default()
        };
        if !hyperion_adapters::dkim::is_installed().await {
            st.unavailable = true;
            return st;
        }
        let kv = self.dkim_kv_get(detail.id.as_str()).await;
        let selector = if kv.selector.is_empty() {
            hyperion_adapters::dkim::DEFAULT_SELECTOR.to_string()
        } else {
            kv.selector.clone()
        };
        st.dns_name = hyperion_adapters::dkim::dkim_dns_name(&domain, &selector);
        st.selector = selector.clone();
        st.enabled = kv.enabled;
        st.verify_status = kv.verify_status.clone();
        st.verified_at = kv.verified_at;
        if kv.enabled {
            if let Some(pk) = hyperion_adapters::dkim::read_pubkey(&domain, &selector).await {
                st.txt_value = hyperion_adapters::dkim::dkim_txt_value(&pk);
            }
        }
        st
    }

    pub async fn dkim_status(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::DkimStatus, RpcError> {
        let detail = self.get(sel).await?;
        Ok(self.dkim_status_for(&detail).await)
    }

    pub async fn dkim_enable(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::DkimStatus, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state == HostingState::Deleting {
            return Err(RpcError::Conflict {
                message: "cannot enable DKIM on a deleting hosting".into(),
            });
        }
        // Lazy node infra: install + configure OpenDKIM the first time any
        // domain on this node opts in, so mail-less nodes never carry it.
        hyperion_adapters::dkim::ensure_installed()
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "opendkim_install".into(),
                reason: e.to_string(),
            })?;
        hyperion_adapters::dkim::ensure_configured()
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "opendkim_config".into(),
                reason: e.to_string(),
            })?;
        let selector = hyperion_adapters::dkim::DEFAULT_SELECTOR.to_string();
        hyperion_adapters::dkim::genkey(&detail.domain, &selector)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "opendkim_genkey".into(),
                reason: e.to_string(),
            })?;
        if let Err(e) = hyperion_adapters::dkim::enable_signing(&detail.domain, &selector).await {
            // Roll the partial table rows back so we never sign with a key the
            // stored state reports as disabled (an unpublished-key signature is
            // worse than none). Best-effort — the original error is what we
            // surface.
            let _ = hyperion_adapters::dkim::disable_signing(&detail.domain, &selector).await;
            return Err(RpcError::ProvisioningFailed {
                stage: "opendkim_sign".into(),
                reason: e.to_string(),
            });
        }
        // Enabling resets any prior verification — the operator has a new (or
        // re-attached) record to (re)publish.
        self.dkim_kv_set(
            detail.id.as_str(),
            &DkimKv {
                selector: selector.clone(),
                enabled: true,
                verify_status: String::new(),
                verified_at: 0,
            },
        )
        .await?;
        // Move this site's envelope sender onto its own domain now that
        // the operator manages that domain's mail DNS. Best-effort: the
        // signing itself is already live and correct, so a postfix hiccup
        // here must not report DKIM as failed. It is re-asserted on the
        // next enable/disable and on every mta_reconfigure.
        if let Err(e) = self.sync_sender_canonical().await {
            tracing::warn!(error = %e, domain = %detail.domain,
                "dkim: envelope-sender map not updated; this site's SPF record \
                 stays unconsulted until the next reconfigure");
        }
        self.append_audit(
            "hosting.dkim.enable",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain, "selector": selector}).to_string(),
            "ok",
        )
        .await;
        Ok(self.dkim_status_for(&detail).await)
    }

    pub async fn dkim_disable(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::DkimStatus, RpcError> {
        let detail = self.get(sel).await?;
        let kv = self.dkim_kv_get(detail.id.as_str()).await;
        let selector = if kv.selector.is_empty() {
            hyperion_adapters::dkim::DEFAULT_SELECTOR.to_string()
        } else {
            kv.selector.clone()
        };
        // Propagate a failure instead of swallowing it: if the tables can't be
        // rewritten / OpenDKIM can't reload, mail is STILL being signed, so we
        // must not flip the stored flag to "off" (that would report disabled
        // while signing continues). The operator sees the error and retries.
        hyperion_adapters::dkim::disable_signing(&detail.domain, &selector)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "opendkim_unsign".into(),
                reason: e.to_string(),
            })?;
        self.dkim_kv_set(
            detail.id.as_str(),
            &DkimKv {
                selector,
                enabled: false,
                verify_status: String::new(),
                verified_at: 0,
            },
        )
        .await?;
        // Move this site's envelope sender onto its own domain now that
        // the operator manages that domain's mail DNS. Best-effort: the
        // signing itself is already live and correct, so a postfix hiccup
        // here must not report DKIM as failed. It is re-asserted on the
        // next enable/disable and on every mta_reconfigure.
        if let Err(e) = self.sync_sender_canonical().await {
            tracing::warn!(error = %e, domain = %detail.domain,
                "dkim: envelope-sender map not updated; this site's SPF record \
                 stays unconsulted until the next reconfigure");
        }
        self.append_audit(
            "hosting.dkim.disable",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        Ok(self.dkim_status_for(&detail).await)
    }

    pub async fn dkim_verify(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::DkimStatus, RpcError> {
        let detail = self.get(sel).await?;
        let mut kv = self.dkim_kv_get(detail.id.as_str()).await;
        if !kv.enabled {
            // Nothing published to verify against yet.
            return Ok(self.dkim_status_for(&detail).await);
        }
        let selector = if kv.selector.is_empty() {
            hyperion_adapters::dkim::DEFAULT_SELECTOR.to_string()
        } else {
            kv.selector.clone()
        };
        let status = match hyperion_adapters::dkim::read_pubkey(&detail.domain, &selector).await {
            None => "missing".to_string(),
            Some(pubkey) => {
                let name = hyperion_adapters::dkim::dkim_dns_name(&detail.domain, &selector);
                // A dig FAILURE (resolver down, timeout) must NOT be reported as
                // "missing" — that would tell the operator to re-add a record
                // that's already there. Only an empty *successful* lookup is
                // genuinely missing.
                match dig_records(&name, "TXT").await {
                    Err(_) => "unknown".to_string(),
                    Ok(txts) => {
                        let stitched: Vec<String> =
                            txts.iter().map(|r| stitch_dig_txt(r)).collect();
                        if stitched
                            .iter()
                            .any(|s| hyperion_adapters::dkim::published_key_matches(s, &pubkey))
                        {
                            "verified".to_string()
                        } else if stitched
                            .iter()
                            .any(|s| s.to_ascii_lowercase().contains("v=dkim1"))
                        {
                            "mismatch".to_string()
                        } else {
                            "missing".to_string()
                        }
                    }
                }
            }
        };
        kv.selector = selector;
        kv.verify_status = status.clone();
        kv.verified_at = now_secs();
        self.dkim_kv_set(detail.id.as_str(), &kv).await?;
        self.append_audit(
            "hosting.dkim.verify",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain, "status": status}).to_string(),
            "ok",
        )
        .await;
        Ok(self.dkim_status_for(&detail).await)
    }
}

/// Per-hosting DKIM state persisted in `hosting_kv` under the `dkim` key.
/// The private key + signing-table rows are the real state on disk; this is
/// just the enabled flag, the selector, and the last verification outcome.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct DkimKv {
    pub(super) selector: String,
    pub(super) enabled: bool,
    #[serde(default)]
    pub(super) verify_status: String,
    #[serde(default)]
    pub(super) verified_at: i64,
}
