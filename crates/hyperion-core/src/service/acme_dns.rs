//! acme-dns: the delegated `_acme-challenge` zone the master answers for,
//! so wildcard certificates renew unattended.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// The acme-dns config with the responder's runtime status. A node that
    /// was never configured answers an empty, disabled config.
    pub async fn acme_dns_config_get(&self) -> Result<hyperion_types::AcmeDnsConfig, RpcError> {
        let mut cfg = hyperion_state::acme_dns::config_get(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("acme-dns config: {e}")))?
            .unwrap_or_else(|| hyperion_types::AcmeDnsConfig {
                zone: None,
                ns_host: String::new(),
                public_ipv4: None,
                public_ipv6: None,
                enabled: false,
                check_token: String::new(),
                listening: Vec::new(),
                last_error: None,
            });
        let status = crate::acme_dns_status::get();
        cfg.listening = status.listening;
        cfg.last_error = status.last_error;
        Ok(cfg)
    }

    /// Save the acme-dns config. Enabling checks nothing else holds port 53
    /// first; the agent's responder loop picks the change up on its own.
    pub async fn acme_dns_config_set(
        &self,
        zone: Option<String>,
        ns_host: String,
        public_ipv4: Option<String>,
        public_ipv6: Option<String>,
        enabled: bool,
    ) -> Result<hyperion_types::AcmeDnsConfig, RpcError> {
        let mut ss = String::new();
        if enabled {
            for flags in ["-Hlunp", "-Hltnp"] {
                match tokio::process::Command::new("/usr/bin/ss")
                    .arg(flags)
                    .output()
                    .await
                {
                    Ok(o) if o.status.success() => {
                        ss.push_str(&String::from_utf8_lossy(&o.stdout));
                    }
                    _ => {
                        return Err(RpcError::Internal_with(
                            "could not run ss to check port 53 is free".into(),
                        ))
                    }
                }
            }
        }
        let firewall = |open: bool| async move {
            if open {
                self.firewall_apply_template("acme-dns").await
            } else {
                self.firewall_remove_template("acme-dns").await
            }
        };
        self.acme_dns_config_save(
            zone,
            ns_host,
            public_ipv4,
            public_ipv6,
            enabled,
            &ss,
            firewall,
        )
        .await
    }

    /// The delegation label of `base`, minted on first use.
    pub async fn acme_dns_label_ensure(
        &self,
        base: Domain,
        hosting_id: Option<String>,
    ) -> Result<hyperion_types::AcmeDnsLabel, RpcError> {
        hyperion_state::acme_dns::label_ensure(
            &self.pool,
            base.as_str(),
            hosting_id.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("acme-dns label ensure: {e}")))
    }

    pub async fn acme_dns_labels(&self) -> Result<Vec<hyperion_types::AcmeDnsLabel>, RpcError> {
        hyperion_state::acme_dns::labels_all(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("acme-dns labels: {e}")))
    }

    pub async fn acme_dns_label_mark(
        &self,
        base: Domain,
        ok: bool,
        error: Option<String>,
    ) -> Result<(), RpcError> {
        hyperion_state::acme_dns::label_mark(
            &self.pool,
            base.as_str(),
            ok,
            error.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("acme-dns label mark: {e}")))
    }

    pub async fn acme_dns_label_delete(&self, base: Domain) -> Result<(), RpcError> {
        hyperion_state::acme_dns::label_delete(&self.pool, base.as_str())
            .await
            .map_err(|e| RpcError::Internal_with(format!("acme-dns label delete: {e}")))
    }

    pub async fn acme_dns_labels_delete_for_hosting(
        &self,
        hosting_id: String,
    ) -> Result<(), RpcError> {
        hyperion_state::acme_dns::labels_delete_for_hosting(&self.pool, &hosting_id)
            .await
            .map(|_| ())
            .map_err(|e| RpcError::Internal_with(format!("acme-dns labels delete: {e}")))
    }

    /// Publish TXT values under `label`. They lapse after a day, so a
    /// renewal that dies half-way cannot leave a stale challenge served.
    pub async fn acme_dns_values_set(
        &self,
        label: String,
        values: Vec<String>,
    ) -> Result<(), RpcError> {
        hyperion_state::acme_dns::values_set(&self.pool, &label, &values, now_secs() + 86_400)
            .await
            .map_err(|e| RpcError::Internal_with(format!("acme-dns values set: {e}")))
    }

    pub async fn acme_dns_values_clear(&self, label: String) -> Result<(), RpcError> {
        hyperion_state::acme_dns::values_clear(&self.pool, &label)
            .await
            .map_err(|e| RpcError::Internal_with(format!("acme-dns values clear: {e}")))
    }

    /// A node finished (or failed) a delegated renewal. Always audited; a
    /// failure also tells the operators, per domain, linking to the
    /// hosting when one owns the cert (`has_hosting`), else the preview.
    pub async fn acme_dns_renew_report(
        &self,
        domain: String,
        node_id: String,
        ok: bool,
        detail: String,
        days_left: i64,
        has_hosting: bool,
    ) -> Result<(), RpcError> {
        self.append_audit(
            "cert.renew.dns01_delegated",
            None,
            &serde_json::json!({
                "domain": &domain,
                "node_id": &node_id,
                "detail": &detail,
                "days_left": days_left,
            })
            .to_string(),
            if ok { "ok" } else { "failed" },
        )
        .await;
        if !ok {
            self.notify_admins_say(
                if days_left <= 0 { "error" } else { "warn" },
                "ops.cert_wildcard_auto_failed",
                &[
                    ("domain", &domain),
                    ("reason", &detail),
                    ("days", &days_left.to_string()),
                ],
                &cert_alert_href(&domain, has_hosting, true),
                &format!("cert.wildcard_auto_failed:{domain}"),
            )
            .await;
        }
        Ok(())
    }

    /// The delegated zone stopped resolving to the responder.
    pub async fn acme_dns_zone_broken(&self, detail: String) -> Result<(), RpcError> {
        self.notify_admins_say(
            "warn",
            "ops.acme_dns_zone_broken",
            &[("reason", &detail)],
            "/settings/https",
            "acme_dns.zone_broken",
        )
        .await;
        Ok(())
    }

    /// Flag (or clear) a cert as renewed over the delegated acme zone.
    pub async fn cert_set_delegated(
        &self,
        domain: Domain,
        delegated: bool,
    ) -> Result<(), RpcError> {
        certificates::set_delegated(&self.pool, domain.as_str(), delegated)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cert set delegated: {e}")))
    }

    /// [`Self::acme_dns_config_set`] with the `ss` listing and the firewall
    /// step (`true` = open the `acme-dns` preset, `false` = close it, as
    /// `firewall_apply_template` / `firewall_remove_template` answer) passed in.
    pub(super) async fn acme_dns_config_save<F, Fut>(
        &self,
        zone: Option<String>,
        ns_host: String,
        public_ipv4: Option<String>,
        public_ipv6: Option<String>,
        enabled: bool,
        ss: &str,
        firewall: F,
    ) -> Result<hyperion_types::AcmeDnsConfig, RpcError>
    where
        F: FnOnce(bool) -> Fut,
        Fut: std::future::Future<Output = Result<(bool, String, String), RpcError>>,
    {
        let invalid = |message: String| RpcError::Validation { message };
        let blank = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let zone = match blank(zone) {
            Some(z) => Some(
                Domain::parse(&z)
                    .map_err(|e| invalid(format!("zone: {e}")))?
                    .as_str()
                    .to_string(),
            ),
            None => None,
        };
        let ns_host = match blank(Some(ns_host)) {
            Some(n) => Domain::parse(&n)
                .map_err(|e| invalid(format!("NS host: {e}")))?
                .as_str()
                .to_string(),
            None => String::new(),
        };
        let public_ipv4 = blank(public_ipv4);
        if let Some(ip) = &public_ipv4 {
            ip.parse::<std::net::Ipv4Addr>()
                .map_err(|_| invalid(format!("not an IPv4 address: {ip}")))?;
        }
        let public_ipv6 = blank(public_ipv6);
        if let Some(ip) = &public_ipv6 {
            ip.parse::<std::net::Ipv6Addr>()
                .map_err(|_| invalid(format!("not an IPv6 address: {ip}")))?;
        }
        if enabled {
            let Some(z) = &zone else {
                return Err(invalid("set the delegated zone before enabling".into()));
            };
            if ns_host.is_empty() {
                return Err(invalid("set the NS host name before enabling".into()));
            }
            // The NS host's address record lives in the PARENT zone; one
            // inside the delegated zone could never be resolved (the
            // responder only serves TXT, NS and SOA).
            if ns_host == *z || ns_host.ends_with(&format!(".{z}")) {
                return Err(invalid(format!(
                    "the NS host {ns_host} must be outside the zone {z}"
                )));
            }
        }
        let prev = hyperion_state::acme_dns::config_get(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("acme-dns config: {e}")))?;
        let check_token = prev
            .as_ref()
            .map(|p| p.check_token.clone())
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| {
                use rand::Rng;
                const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
                let mut rng = rand::thread_rng();
                (0..32)
                    .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                    .collect()
            });
        let holders = if enabled {
            port_53_holders_from_ss(ss)
        } else {
            Vec::new()
        };
        let mut cfg = hyperion_types::AcmeDnsConfig {
            zone,
            ns_host,
            public_ipv4,
            public_ipv6,
            // Stored enabled only once the firewall is open: the responder
            // loop starts from this row.
            enabled: false,
            check_token,
            listening: Vec::new(),
            last_error: None,
        };
        let save = |cfg: &hyperion_types::AcmeDnsConfig| {
            let cfg = cfg.clone();
            async move {
                hyperion_state::acme_dns::config_put(&self.pool, &cfg)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("acme-dns config: {e}")))
            }
        };
        save(&cfg).await?;
        let firewall_error = |r: Result<(bool, String, String), RpcError>| match r {
            Ok((true, _, _)) => None,
            Ok((false, _, err)) => Some(err),
            Err(e) => Some(e.to_string()),
        };
        if !holders.is_empty() {
            if prev.is_some_and(|p| p.enabled) {
                if let Some(e) = firewall_error(firewall(false).await) {
                    tracing::warn!(error = %e, "acme-dns: closing port 53 failed");
                }
            }
            return Err(invalid(format!(
                "port 53 is already in use ({}); saved the zone with the responder off. \
                 Stop that DNS server or bind it to loopback only, then enable again.",
                holders.join(", ")
            )));
        }
        if enabled {
            if let Some(e) = firewall_error(firewall(true).await) {
                return Err(RpcError::Internal_with(format!(
                    "could not open port 53 in the firewall ({e}); saved the zone with the \
                     responder off"
                )));
            }
            cfg.enabled = true;
            save(&cfg).await?;
        } else if let Some(e) = firewall_error(firewall(false).await) {
            return Err(RpcError::Internal_with(format!(
                "the responder is off, but closing port 53 in the firewall failed, so it \
                 may still be open: {e}"
            )));
        }
        let status = crate::acme_dns_status::get();
        cfg.listening = status.listening;
        cfg.last_error = status.last_error;
        Ok(cfg)
    }
}
