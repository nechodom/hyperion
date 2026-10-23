//! TLS certificates: DNS pre-check, ACME HTTP-01/DNS-01 issuance, uploads,
//! renewal.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Cluster-wide certificate inventory. One row per cert
    /// known to this agent, computed `days_left` + `band` so the
    /// UI can render without arithmetic. Sorted by expiry —
    /// expiring soonest at the top. The `node_id` field carries
    /// where the cert lives so the panel's cross-node fanout can
    /// merge multiple agents' results into one screen.
    pub async fn cert_overview(&self) -> Result<Vec<hyperion_types::CertOverviewItem>, RpcError> {
        let rows = hyperion_state::certificates::list_all(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cert_overview list: {e}")))?;
        // A trashed site's certificate is still on disk (and still renewed,
        // so a restore comes back with a valid one), but it is not a site the
        // operator runs. Rows with no hosting at all — the panel's own
        // certificate — are kept.
        let trashed: std::collections::HashSet<String> = hostings::list_trashed(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cert_overview trashed: {e}")))?
            .into_iter()
            .map(|h| h.domain)
            .collect();
        let now = now_secs();
        let mut items = Vec::with_capacity(rows.len());
        for r in rows.into_iter().filter(|r| !trashed.contains(&r.domain)) {
            let wildcard = certificates::is_wildcard(&self.pool, &r.domain)
                .await
                .unwrap_or(false);
            let hosting_id = hostings::get_by_domain(&self.pool, &r.domain)
                .await
                .ok()
                .flatten()
                .map(|h| h.id.to_string());
            items.push({
                let days_left = (r.not_after - now) / 86400;
                let band = if r.not_after <= now {
                    "expired"
                } else if days_left < 7 {
                    "critical"
                } else if days_left < 30 {
                    "warning"
                } else {
                    "ok"
                };
                hyperion_types::CertOverviewItem {
                    domain: r.domain,
                    issuer: r.issuer,
                    issued_at: r.issued_at,
                    not_after: r.not_after,
                    days_left,
                    band: band.into(),
                    // Local agent — handler fills this when fanning
                    // out across nodes.
                    node_id: String::new(),
                    wildcard,
                    renewal_type: r.renewal_type,
                    hosting_id,
                    delegated: r.dns01_delegated,
                }
            });
        }
        Ok(items)
    }

    // ================================================================
    //  DNS pre-check + real ACME issuance
    // ================================================================

    /// Resolve `domain`'s A + AAAA records via `dig`, fetch our agent's
    /// public IP, and report whether the records point here.
    pub async fn dns_check(&self, domain: Domain) -> Result<DnsCheckResult, RpcError> {
        let d = domain.as_str().to_string();
        // All four lookups are independent — run them concurrently.
        // Sequential, the worst case was ~20s (2× dig at 3s×2 tries
        // + 2× curl at 4s; api6.ipify.org reliably burns its full
        // 4s timeout on IPv4-only boxes). Joined, the worst case is
        // the single slowest probe.
        let (resolved_a, resolved_aaaa, our_ipv4, our_ipv6) = tokio::join!(
            dig_records(&d, "A"),
            dig_records(&d, "AAAA"),
            fetch_public_ip_v4("https://api4.ipify.org"),
            fetch_public_ip_v6("https://api6.ipify.org"),
        );
        let resolved_a = resolved_a.unwrap_or_default();
        let resolved_aaaa = resolved_aaaa.unwrap_or_default();

        let our_ipv4 = our_ipv4.ok();
        let our_ipv6 = our_ipv6.ok();

        // What Let's Encrypt will see. The lookups above went through this
        // box's resolver, which can serve a stale answer for as long as the
        // OLD TTL — so a domain repointed an hour ago still looks wrong here
        // while LE, which asks the authoritative servers, would validate it
        // without complaint. Asking authoritatively is the only way to answer
        // the question the operator is actually asking: "will the certificate
        // issue?"
        let auth_a = dig_records_authoritative(&d, "A").await.ok().flatten();
        let auth_matches = match (&auth_a, &our_ipv4) {
            (Some(list), Some(ip)) => list.iter().any(|r| r == ip),
            _ => false,
        };

        let mut matches = false;
        if let Some(ref ip) = our_ipv4 {
            if resolved_a.iter().any(|r| r == ip) {
                matches = true;
            }
        }
        if let Some(ref ip) = our_ipv6 {
            if resolved_aaaa.iter().any(|r| r == ip) {
                matches = true;
            }
        }
        // Behind Cloudflare's proxy the apex NEVER resolves to this node —
        // that is the entire point of the proxy — so "DNS points elsewhere"
        // was a standing false alarm on every proxied site, teaching
        // operators to ignore the banner right up until it was reporting a
        // genuinely mispointed domain. A proxied site is a working
        // configuration and is reported as one; the note still tells the
        // operator what it means for cert issuance (HTTP-01 rides the
        // proxied traffic and works; what breaks it is Cloudflare's own
        // TLS mode, which no DNS check here can see).
        let proxied = !resolved_a.is_empty()
            && resolved_a.iter().all(|ip| is_cloudflare_ipv4(ip))
            && resolved_aaaa.iter().all(|ip| is_cloudflare_ipv6(ip));
        let note = if resolved_a.is_empty() && resolved_aaaa.is_empty() {
            format!("{} has no A or AAAA records (NXDOMAIN or DNS error)", d)
        } else if matches {
            "DNS resolves here — cert issuance will work.".into()
        } else if proxied {
            "Proxied through Cloudflare — the visible addresses are Cloudflare's, \
             which is how the proxy works, not a misconfiguration. Certificate \
             issuance works normally through the proxy: Let's Encrypt fetches \
             the challenge from Cloudflare's edge and Cloudflare forwards it \
             here. The one thing that breaks it is Cloudflare's SSL/TLS mode \
             set to 'Full (strict)' while this server is still on its \
             self-signed bootstrap certificate — issue the certificate with the \
             mode on 'Full', then switch back."
                .into()
        } else if auth_matches {
            // The disagreement that matters: this box has a stale cached
            // answer, but the zone itself is already correct — and the zone
            // is what Let's Encrypt reads.
            format!(
                "This server's DNS cache still has the OLD address ({:?}), but the \
                 domain's own nameservers already answer {:?} — which is us. \
                 Let's Encrypt asks the nameservers directly and ignores caches, \
                 so issuance will work now. The stale entry here expires on its \
                 own when the previous record's TTL runs out.",
                resolved_a,
                auth_a.as_deref().unwrap_or(&[]),
            )
        } else {
            let authoritative = match &auth_a {
                Some(list) if list.is_empty() => {
                    " The domain's own nameservers return no A record at all, so \
                     Let's Encrypt will not be able to validate it either."
                        .to_string()
                }
                Some(list) => format!(
                    " Asked directly, the domain's own nameservers also answer {list:?} \
                     — so this is not a stale cache here, and Let's Encrypt will see \
                     the same thing. Point the A record at us and try again."
                ),
                // Could not reach the authoritative servers; say so rather
                // than implying the local answer is the whole story.
                None => " (the domain's own nameservers could not be reached from \
                         this box, so this is only what our resolver sees)"
                    .to_string(),
            };
            format!(
                "DNS points elsewhere. We see A={:?} AAAA={:?}; our IPs are {}/{}.{}",
                resolved_a,
                resolved_aaaa,
                our_ipv4.as_deref().unwrap_or("?"),
                our_ipv6.as_deref().unwrap_or("?"),
                authoritative,
            )
        };
        // A proxied site counts as matching: the domain is routed to this
        // server, merely not visibly so. Everything that gates on
        // `matches` (the banner's severity, create-preflight wording)
        // should treat it as healthy.
        let matches = matches || proxied;

        // Is the cert we serve for this domain still the self-signed
        // bootstrap? A real cert's issuer names a CA (Let's Encrypt / ISRG,
        // or an uploaded one); the bootstrap is `rcgen self signed cert`.
        // Only worth reporting on a proxied site — that is the one place it
        // silently becomes a 525 under Full (strict).
        let origin_cert_self_signed = if proxied {
            match certificates::get(&self.pool, &d).await {
                Ok(Some(c)) => {
                    let issuer = c.issuer.to_ascii_lowercase();
                    !(issuer.contains("let's encrypt")
                        || issuer.contains("lets encrypt")
                        || issuer.contains("isrg"))
                }
                // No cert row at all ⇒ whatever nginx serves is the
                // bootstrap; treat as self-signed.
                _ => true,
            }
        } else {
            false
        };

        Ok(DnsCheckResult {
            domain: d,
            resolved_a,
            resolved_aaaa,
            our_public_ipv4: our_ipv4,
            our_public_ipv6: our_ipv6,
            matches,
            note,
            proxied,
            origin_cert_self_signed,
        })
    }

    /// Throw away a hosting's certificate and fall back to the self-signed
    /// bootstrap.
    ///
    /// This is what makes re-issuance a two-step action. Issuing over a
    /// healthy certificate is nearly always a mistake: it spends Let's
    /// Encrypt's per-hostname budget (5 failed validations an hour, 5
    /// duplicate certificates a week) on a certificate that was already
    /// working, and if the attempt fails the operator is left worse off than
    /// before they touched it. Making the destructive step explicit means
    /// nobody reaches it by clicking the obvious button twice.
    ///
    /// Deleting the FILES is what actually downgrades the site, because
    /// `nginx_write_vhost` self-heals a missing cert by generating a
    /// bootstrap one — so the vhost re-render below both restores a
    /// serveable cert and reloads nginx onto it. The DB row goes too, or the
    /// renewal sweep would keep trying to renew a certificate that is no
    /// longer on disk.
    pub async fn cert_delete(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        let domain = detail.domain.clone();

        // Serialize against issuance for the same domain — otherwise a
        // delete racing an in-flight issue can remove the files the issue
        // just wrote and leave the row pointing at nothing.
        let lock = {
            let mut locks = self.cert_issue_locks.lock().await;
            locks.entry(domain.clone()).or_default().clone()
        };
        let _guard = lock.lock().await;

        let dir = format!("/etc/hyperion/certs/{domain}");
        if let Err(e) = tokio::fs::remove_dir_all(&dir).await {
            // Already gone is success — this is a "make it so" operation.
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(RpcError::Internal_with(format!(
                    "could not remove {dir}: {e}"
                )));
            }
        }
        certificates::delete(&self.pool, &domain)
            .await
            .map_err(|e| RpcError::Internal_with(format!("certificates delete: {e}")))?;

        // Re-render: regenerates the bootstrap cert and reloads nginx, so the
        // site keeps answering on :443 (untrusted, but up) instead of taking
        // nginx down over a missing ssl_certificate file.
        let mut fresh = detail.clone();
        fresh.cert_path = None;
        fresh.cert_key_path = None;
        self.adapters
            .nginx_write_vhost(&fresh)
            .await
            .map_err(|e| RpcError::Internal_with(format!("vhost re-render: {e}")))?;

        self.append_audit(
            "cert.delete",
            Some(detail.id.as_str()),
            &serde_json::json!({ "domain": &domain }).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn issue_real_cert(
        &self,
        sel: HostingSelector,
        req: CertIssueRequest,
    ) -> Result<CertInfo, RpcError> {
        let detail = self.get(sel).await?;
        let domain = Domain::parse(&detail.domain)?;

        // Serialize issuance per domain so two concurrent runs can't
        // produce a mismatched cert+key pair on disk (cert from run A,
        // key from run B → TLS handshake breaks). The lock outlives
        // the full ACME flow including the vhost rewrite at the end.
        let lock = {
            let mut map = self.cert_issue_locks.lock().await;
            map.entry(detail.domain.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;

        if req.require_dns_match {
            let check = self.dns_check(domain.clone()).await?;
            if !check.matches {
                return Err(RpcError::Conflict {
                    message: format!(
                        "DNS pre-check failed for {}: {} (set require_dns_match=false to override)",
                        detail.domain, check.note
                    ),
                });
            }
        } else {
            // Issuing without the DNS-ownership pre-check is a privileged
            // override — it lets a cert be requested for a domain that doesn't
            // (yet) resolve to this node. Record it loudly so the audit trail
            // shows the bypass instead of it being silent.
            tracing::warn!(
                domain = %detail.domain,
                "issuing certificate with DNS pre-check DISABLED (require_dns_match=false)"
            );
            self.append_audit(
                "cert.dns_check_skipped",
                Some(detail.id.as_str()),
                &serde_json::json!({ "domain": detail.domain }).to_string(),
                "warn",
            )
            .await;
        }

        // SANs = aliases + any extras
        let mut sans: Vec<String> = detail.aliases.clone();
        sans.extend(req.extra_sans.iter().cloned());
        sans.sort();
        sans.dedup();

        // Prefer the per-hosting override (if set + non-empty), fall
        // back to the agent-wide default. Lets one operator-managed
        // host get expiry notices at the end-customer's address while
        // siblings keep the default.
        let row = hostings::get_by_id(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get hosting: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.as_str().to_string(),
            })?;
        let effective_email = row
            .acme_contact_email
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(self.acme_contact_email.as_str());
        // Reject obvious placeholder addresses early so we don't burn a
        // failed-account round trip with Let's Encrypt.
        let email = effective_email.trim();
        if email.is_empty()
            || email.ends_with("@example.com")
            || email.ends_with("@example.org")
            || email.ends_with("@example.net")
            || email.ends_with("@hyperion.invalid")
            || !email.contains('@')
        {
            return Err(RpcError::Validation {
                message: format!(
                    "acme contact email \"{}\" is invalid or a placeholder. \
                     Edit /etc/hyperion/agent.toml [acme] contact_email and \
                     restart hyperion-agent.",
                    email
                ),
            });
        }
        // Re-render the vhost BEFORE we ask LE to validate. This is a
        // self-heal: if an older agent build wrote a broken vhost (e.g.
        // the `root` instead of `alias` bug for .well-known/acme-challenge),
        // re-rendering with the current template fixes it. Cheap, safe,
        // idempotent. Without this an operator hitting "Issue Cert" on an
        // existing hosting would keep getting Invalid from LE forever
        // because the broken vhost stays on disk.
        if let Err(e) = self.adapters.nginx_write_vhost(&detail).await {
            tracing::warn!(
                error=%e,
                domain=%detail.domain,
                "pre-issue vhost re-render failed (continuing anyway)"
            );
        }

        // Ensure the acme-challenge root exists with the right perms
        // BEFORE we ask LE. nginx (www-data) must be able to traverse +
        // read; the dir itself only needs world-x.
        if let Err(e) = tokio::fs::create_dir_all(&self.paths.acme_challenge_root).await {
            tracing::warn!(
                error=%e,
                path=%self.paths.acme_challenge_root,
                "could not pre-create acme challenge root"
            );
        }
        let _ = tokio::process::Command::new("/usr/bin/chmod")
            .arg("0755")
            .arg(&self.paths.acme_challenge_root)
            .output()
            .await;

        // Proxy status no longer selects a validation method — it only makes
        // the failure message better, because the Full (strict) deadlock is
        // invisible from the CA's error text alone.
        let proxied = domain_is_cloudflare_proxied(&detail.domain).await;

        // ONE path: HTTP-01, always. This used to refuse outright for any
        // Cloudflare-proxied domain and force DNS-01 through a Cloudflare API
        // token, on the theory that the edge makes HTTP-01 unreliable. That
        // reasoning was wrong, and the refusal was the direct cause of an
        // outage: a proxied site could not get a certificate, stayed on the
        // self-signed bootstrap cert, and Cloudflare's Full (strict) mode then
        // served visitors error 525/526 while nginx here was perfectly healthy.
        //
        // HTTP-01 has no concept of an "origin". Let's Encrypt resolves the
        // name, connects to whatever answers on port 80 and compares the body.
        // When Cloudflare answers and forwards here, validation succeeds by
        // construction. "Always Use HTTPS" is not a problem either: Boulder
        // follows redirects and does not verify the certificate on an https
        // hop. Two properties of our own vhost template are what make this
        // hold, and both are load-bearing rather than redundant:
        //
        //   * the challenge location lives inside the shared HTTPS macro as
        //     well as the :80 block. Under Full / Full (strict) Cloudflare
        //     fetches the origin over :443 even though LE arrived on :80, so a
        //     challenge wired only into :80 would 404.
        //   * in the :80 block the challenge location is ordered ABOVE the
        //     catch-all `return 301 https://`, so Flexible mode cannot spin up
        //     an edge<->origin redirect loop.
        //
        // See the regression test in the nginx adapter guarding both.
        let cert = hyperion_adapters::acme::issue_http01(hyperion_adapters::acme::IssueRequest {
            domain: &detail.domain,
            sans: &sans,
            contact_email: email,
            staging: req.staging,
            challenge_root: std::path::Path::new(&self.paths.acme_challenge_root),
            certs_root: "/etc/hyperion/certs",
        })
        .await
        .map_err(|e| RpcError::ProvisioningFailed {
            stage: "acme".into(),
            reason: acme_failure_message(&detail.domain, proxied, &e.to_string()),
        })?;

        // Persist cert info in DB
        let cert_path = format!("/etc/hyperion/certs/{}/fullchain.pem", detail.domain);
        let key_path = format!("/etc/hyperion/certs/{}/privkey.pem", detail.domain);
        let _ = certificates::upsert(
            &self.pool,
            &detail.domain,
            now_secs(),
            cert.not_after,
            &cert_path,
            &key_path,
            &cert.issuer,
        )
        .await;

        // Re-render vhost so nginx picks up new cert (paths are same but
        // reload triggers fresh load + cert chain pickup).
        let new_detail = HostingDetail {
            cert: Some(cert.clone()),
            // Freshly-issued per-site cert lives at the per-domain default
            // path; clear any inherited shared-wildcard override.
            cert_path: None,
            cert_key_path: None,
            ..detail.clone()
        };
        if let Err(e) = self.adapters.nginx_write_vhost(&new_detail).await {
            return Err(RpcError::ProvisioningFailed {
                stage: "nginx_reload".into(),
                reason: e.to_string(),
            });
        }

        self.append_audit(
            "cert.issue.acme",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "issuer": cert.issuer,
                "staging": req.staging,
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok(cert)
    }

    /// Install an operator-supplied certificate for the hosting at `sel`,
    /// for the non-ACME cases (private CA, pre-purchased multi-year cert,
    /// self-signed bootstrap). The PEM is validated before anything touches
    /// disk: the cert + key must parse, the key must match the leaf's public
    /// key, and the leaf's CN/SANs must cover the hosting's domain + every
    /// alias. The cert is then marked `renewal_type = "manual"` so the ACME
    /// renewal sweep never overwrites it.
    pub async fn upload_cert(
        &self,
        sel: HostingSelector,
        cert_pem: String,
        key_pem: String,
        ca_bundle_pem: Option<String>,
    ) -> Result<CertInfo, RpcError> {
        let detail = self.get(sel).await?;

        // Serialize per domain against a concurrent ACME issuance so we
        // can't interleave writes and leave a mismatched cert+key pair on
        // disk (same lock issue_real_cert takes).
        let lock = {
            let mut map = self.cert_issue_locks.lock().await;
            map.entry(detail.domain.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;

        // The cert must cover the primary domain AND every alias the vhost
        // serves — a cert that doesn't is a misconfiguration we refuse
        // rather than silently install (it would produce name-mismatch
        // warnings on the uncovered names).
        let mut required: Vec<String> = Vec::with_capacity(1 + detail.aliases.len());
        required.push(detail.domain.clone());
        required.extend(detail.aliases.iter().cloned());

        // Validate. CertError Display is safe to surface and never carries
        // key material; we likewise never log the key below.
        let validated = hyperion_adapters::cert::validate_upload(
            &cert_pem,
            &key_pem,
            ca_bundle_pem.as_deref(),
            &required,
        )
        .map_err(|e| RpcError::Validation {
            message: e.to_string(),
        })?;

        // Write fullchain (leaf + CA bundle) world-readable and the private
        // key 0600 to the per-domain default location the vhost points at.
        let domain_dir = std::path::PathBuf::from("/etc/hyperion/certs").join(&detail.domain);
        let cert_path = domain_dir.join("fullchain.pem");
        let key_path = domain_dir.join("privkey.pem");
        hyperion_adapters::fs::ensure_dir(&domain_dir, 0o700)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "cert_write".into(),
                reason: e.to_string(),
            })?;
        hyperion_adapters::fs::atomic_write(&cert_path, validated.fullchain_pem.as_bytes(), 0o644)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "cert_write".into(),
                reason: e.to_string(),
            })?;
        hyperion_adapters::fs::atomic_write(&key_path, key_pem.as_bytes(), 0o600)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "key_write".into(),
                reason: e.to_string(),
            })?;

        // Persist metadata. issuer is the cert's real issuer (never
        // "letsencrypt" for a real CA), and we flag it manual so the
        // renewal sweep skips it. Clear any stale wildcard flag — an
        // uploaded cert is not a DNS-01 wildcard reference.
        let cert_path_str = cert_path.to_string_lossy().to_string();
        let key_path_str = key_path.to_string_lossy().to_string();
        let _ = certificates::upsert(
            &self.pool,
            &detail.domain,
            now_secs(),
            validated.not_after,
            &cert_path_str,
            &key_path_str,
            &validated.issuer,
        )
        .await;
        let _ = certificates::set_wildcard(&self.pool, &detail.domain, false).await;
        if let Err(e) = certificates::set_renewal_type(&self.pool, &detail.domain, "manual").await {
            return Err(RpcError::Internal_with(format!(
                "mark cert renewal_type=manual: {e}"
            )));
        }

        // Build the CertInfo we return + hand to the vhost render. SANs for
        // display exclude the primary domain (mirrors the ACME path).
        let sans: Vec<String> = validated
            .covered_names
            .iter()
            .filter(|n| *n != &detail.domain)
            .cloned()
            .collect();
        let cert = CertInfo {
            domain: detail.domain.clone(),
            sans,
            issuer: validated.issuer.clone(),
            not_after: validated.not_after,
            fingerprint_sha256: validated.fingerprint.clone(),
        };

        // Re-render the vhost at the per-domain default path (clearing any
        // inherited shared-wildcard override) and reload nginx.
        let new_detail = HostingDetail {
            cert: Some(cert.clone()),
            cert_path: None,
            cert_key_path: None,
            ..detail.clone()
        };
        if let Err(e) = self.adapters.nginx_write_vhost(&new_detail).await {
            return Err(RpcError::ProvisioningFailed {
                stage: "nginx_reload".into(),
                reason: e.to_string(),
            });
        }

        self.append_audit(
            "cert.upload",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "issuer": validated.issuer,
                "not_after": validated.not_after,
                "covered_names": validated.covered_names,
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok(cert)
    }

    /// Resolve the effective ACME contact email for a hosting (per-hosting
    /// override → agent default), rejecting placeholders.
    pub(super) fn effective_acme_email<'a>(
        &'a self,
        row_email: Option<&'a str>,
    ) -> Result<&'a str, RpcError> {
        let email = row_email
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(self.acme_contact_email.as_str())
            .trim();
        if email.is_empty()
            || email.ends_with("@example.com")
            || email.ends_with("@example.org")
            || email.ends_with("@example.net")
            || email.ends_with("@hyperion.invalid")
            || !email.contains('@')
        {
            return Err(RpcError::Validation {
                message: format!(
                    "acme contact email \"{email}\" is invalid or a placeholder. \
                     Edit /etc/hyperion/agent.toml [acme] contact_email and \
                     restart hyperion-agent."
                ),
            });
        }
        Ok(email)
    }

    /// DNS-01 phase 1 for a wildcard cert (`<domain>` + `*.<domain>`).
    /// Returns the TXT records for the operator to publish, then
    /// returns `completed = true`.
    pub async fn cert_dns01_begin(
        &self,
        sel: HostingSelector,
        staging: bool,
    ) -> Result<(bool, Vec<(String, String)>), RpcError> {
        let detail = self.get(sel).await?;
        let row = hostings::get_by_id(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get hosting: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.as_str().to_string(),
            })?;
        let email = self
            .effective_acme_email(row.acme_contact_email.as_deref())?
            .to_string();
        let wildcard = format!("*.{}", detail.domain);
        let sans = vec![wildcard];

        let pending = hyperion_adapters::acme::dns01_begin(&detail.domain, &sans, &email, staging)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "acme_dns01_begin".into(),
                reason: e.to_string(),
            })?;

        self.append_audit(
            "cert.dns01.begin",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain, "staging": staging}).to_string(),
            "ok",
        )
        .await;
        let records = pending
            .records
            .into_iter()
            .map(|r| (r.name, r.value))
            .collect();
        Ok((false, records))
    }

    /// DNS-01 phase 2: validate the published TXT, install the wildcard
    /// cert, persist it, and reload nginx. Mirrors the HTTP-01 post-issue
    /// path.
    pub async fn cert_dns01_finish(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::CertInfo, RpcError> {
        self.cert_dns01_finish_with(sel, false).await
    }

    /// Fail-closed [`Self::cert_dns01_finish`]: never asks Let's Encrypt
    /// without a passing DNS pre-flight (unattended renewal).
    pub async fn cert_dns01_finish_strict(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::CertInfo, RpcError> {
        self.cert_dns01_finish_with(sel, true).await
    }

    async fn cert_dns01_finish_with(
        &self,
        sel: HostingSelector,
        strict: bool,
    ) -> Result<hyperion_types::CertInfo, RpcError> {
        let detail = self.get(sel).await?;
        let cert = hyperion_adapters::acme::dns01_finish_with(
            &detail.domain,
            "/etc/hyperion/certs",
            strict,
        )
        .await
        .map_err(|e| RpcError::ProvisioningFailed {
            stage: "acme_dns01_finish".into(),
            reason: e.to_string(),
        })?;

        self.install_dns01_cert(&detail, &cert).await?;
        Ok(cert)
    }

    /// Persist a freshly issued DNS-01 wildcard cert for a hosting and make
    /// nginx pick it up. A suspended or trashed site is re-applied through
    /// its suspended vhost, with the SAME notice it is already showing:
    /// `nginx_write_vhost` renders the serving vhost and would silently
    /// un-suspend the site (same reasoning as `cert_renew_tick`).
    pub(super) async fn install_dns01_cert(
        &self,
        detail: &HostingDetail,
        cert: &hyperion_types::CertInfo,
    ) -> Result<(), RpcError> {
        let cert_path = format!("/etc/hyperion/certs/{}/fullchain.pem", detail.domain);
        let key_path = format!("/etc/hyperion/certs/{}/privkey.pem", detail.domain);
        let _ = certificates::upsert(
            &self.pool,
            &detail.domain,
            now_secs(),
            cert.not_after,
            &cert_path,
            &key_path,
            &cert.issuer,
        )
        .await;
        // Mark it wildcard so the renewal sweep uses DNS-01, not HTTP-01.
        let _ = certificates::set_wildcard(&self.pool, &detail.domain, true).await;

        let applied = if matches!(
            detail.state,
            HostingState::Suspended | HostingState::Trashed
        ) {
            let reason = self.suspended_notice(&detail.id, detail.state).await;
            self.adapters
                .nginx_apply_suspended(&detail.domain, detail.aliases.clone(), reason)
                .await
        } else {
            let new_detail = HostingDetail {
                cert: Some(cert.clone()),
                // Per-hosting wildcard cert lives at the per-domain default
                // path; clear any inherited shared-cert override.
                cert_path: None,
                cert_key_path: None,
                ..detail.clone()
            };
            self.adapters.nginx_write_vhost(&new_detail).await
        };
        if let Err(e) = applied {
            return Err(RpcError::ProvisioningFailed {
                stage: "nginx_reload".into(),
                reason: e.to_string(),
            });
        }

        self.append_audit(
            "cert.dns01.finish",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain, "issuer": cert.issuer}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// DNS-01 issuance for a bare domain that is NOT tied to a hosting —
    /// e.g. a test node's `*.<base>` wildcard, issued once in Settings and
    /// reused by every auto-subdomain on the node. Mirrors
    /// [`Self::cert_dns01_begin`] but resolves the ACME contact email from
    /// the agent-wide default (no per-hosting override) and writes no vhost
    /// (there's no site to serve — sibling hostings' vhosts reference it).
    pub async fn cert_dns01_begin_domain(
        &self,
        domain: &str,
        email: Option<&str>,
        staging: bool,
    ) -> Result<(bool, Vec<(String, String)>), RpcError> {
        let base = Domain::parse(domain).map_err(|e| RpcError::Validation {
            message: format!("invalid domain {domain}: {e}"),
        })?;
        let email = self.effective_acme_email(email)?.to_string();
        let sans = vec![format!("*.{}", base.as_str())];

        let pending = hyperion_adapters::acme::dns01_begin(base.as_str(), &sans, &email, staging)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "acme_dns01_begin".into(),
                reason: e.to_string(),
            })?;

        self.append_audit(
            "cert.dns01.begin_domain",
            None,
            &serde_json::json!({"domain": base.as_str(), "staging": staging}).to_string(),
            "ok",
        )
        .await;
        let records = pending
            .records
            .into_iter()
            .map(|r| (r.name, r.value))
            .collect();
        Ok((false, records))
    }

    /// DNS-01 phase 2 for a bare (hosting-less) domain. Installs + persists
    /// the wildcard cert, flags it wildcard for the renewal sweep, then
    /// re-points every existing auto-subdomain hosting under this base at
    /// the freshly-issued shared cert.
    pub async fn cert_dns01_finish_domain(
        &self,
        domain: &str,
    ) -> Result<hyperion_types::CertInfo, RpcError> {
        self.cert_dns01_finish_domain_with(domain, false).await
    }

    /// Fail-closed [`Self::cert_dns01_finish_domain`].
    pub async fn cert_dns01_finish_domain_strict(
        &self,
        domain: &str,
    ) -> Result<hyperion_types::CertInfo, RpcError> {
        self.cert_dns01_finish_domain_with(domain, true).await
    }

    async fn cert_dns01_finish_domain_with(
        &self,
        domain: &str,
        strict: bool,
    ) -> Result<hyperion_types::CertInfo, RpcError> {
        let base = Domain::parse(domain).map_err(|e| RpcError::Validation {
            message: format!("invalid domain {domain}: {e}"),
        })?;
        let cert = hyperion_adapters::acme::dns01_finish_with(
            base.as_str(),
            "/etc/hyperion/certs",
            strict,
        )
        .await
        .map_err(|e| RpcError::ProvisioningFailed {
            stage: "acme_dns01_finish".into(),
            reason: e.to_string(),
        })?;
        let cert_path = format!("/etc/hyperion/certs/{}/fullchain.pem", base.as_str());
        let key_path = format!("/etc/hyperion/certs/{}/privkey.pem", base.as_str());
        let _ = certificates::upsert(
            &self.pool,
            base.as_str(),
            now_secs(),
            cert.not_after,
            &cert_path,
            &key_path,
            &cert.issuer,
        )
        .await;
        let _ = certificates::set_wildcard(&self.pool, base.as_str(), true).await;

        self.append_audit(
            "cert.dns01.finish_domain",
            None,
            &serde_json::json!({"domain": base.as_str(), "issuer": cert.issuer}).to_string(),
            "ok",
        )
        .await;

        // Best-effort: route existing auto-subdomains through the shared cert.
        let _ = self.repoint_hostings_to_wildcard(base.as_str()).await;
        Ok(cert)
    }

    /// Point every active hosting whose domain is a direct subdomain of
    /// `base` (covered by `*.<base>`) at the shared wildcard cert: rewrite
    /// its `certificates` row to the wildcard's files + re-render its
    /// vhost. Best-effort; returns how many vhosts were re-pointed.
    pub async fn repoint_hostings_to_wildcard(&self, base: &str) -> Result<usize, RpcError> {
        let wc = match certificates::get(&self.pool, base).await.ok().flatten() {
            Some(c) => c,
            None => return Ok(0),
        };
        let suffix = format!(".{base}");
        let summaries = self.list().await?;
        let mut repointed = 0usize;
        for s in summaries {
            if s.state != HostingState::Active || !s.domain.ends_with(&suffix) {
                continue;
            }
            // Only DIRECT subdomains — `*.base` covers one label, so
            // `a.b.base` is out of scope.
            let label = &s.domain[..s.domain.len() - suffix.len()];
            if label.is_empty() || label.contains('.') {
                continue;
            }
            let _ = certificates::upsert(
                &self.pool,
                &s.domain,
                wc.issued_at,
                wc.not_after,
                &wc.cert_path,
                &wc.key_path,
                &wc.issuer,
            )
            .await;
            match self.get(HostingSelector::Id(s.id.clone())).await {
                Ok(detail) => {
                    if let Err(e) = self.adapters.nginx_write_vhost(&detail).await {
                        tracing::error!(domain = %s.domain, error = %e, "repoint: vhost re-render failed");
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!(domain = %s.domain, error = %e, "repoint: load detail failed");
                    continue;
                }
            }
            repointed += 1;
        }
        if repointed > 0 {
            tracing::info!(base = %base, repointed, "re-pointed auto-subdomains at node wildcard");
        }
        Ok(repointed)
    }

    /// Sweep `certificates` for LE certs whose `not_after - now` is
    /// below `threshold_days*86400` and re-issue each via
    /// `issue_real_cert` with `require_dns_match=false`. The cert is
    /// already installed for this domain, so refusing on a transient
    /// DNS misconfiguration would only delay the renewal further;
    /// any persistent DNS break surfaces as a structured LE error
    /// inside the per-domain `CertRenewResult`.
    ///
    /// `now` is parameterized (not just `now_secs()`) so the daily
    /// background tick and unit tests share the same code path. The
    /// audit log captures each attempt + outcome so an out-of-band
    /// cron-driven renewal leaves a trace.
    pub async fn cert_renew_tick(
        &self,
        now: i64,
        threshold_days: i64,
    ) -> Result<Vec<CertRenewResult>, RpcError> {
        let horizon = threshold_days.max(0).saturating_mul(86400);
        let rows = certificates::find_expiring_within(&self.pool, now, horizon)
            .await
            .map_err(|e| RpcError::Internal_with(format!("query expiring certs: {e}")))?;
        // Only auto-renew ACME-issued certs. Two independent guards:
        //   - `renewal_type == "manual"` ⇒ an operator-uploaded cert
        //     (private CA / pre-purchased / self-signed bootstrap). The
        //     sweep must NEVER overwrite it with an ACME issuance, even if
        //     its issuer string happened to start with "letsencrypt".
        //   - issuer must start with "letsencrypt" — skips self-signed
        //     bootstrap certs (re-issuing them would also be self-signed;
        //     the dashboard nags the operator separately) and any uploaded
        //     real-CA cert (issuer e.g. "DigiCert Inc"). `starts_with` lets
        //     "letsencrypt-staging" still get renewed.
        let due: Vec<_> = rows
            .into_iter()
            .filter(|r| r.renewal_type != "manual" && r.issuer.starts_with("letsencrypt"))
            .collect();

        let mut out = Vec::with_capacity(due.len());
        for cert in due {
            if let Some(result) = self.renew_one_cert(cert, now, threshold_days).await {
                out.push(result);
            }
        }
        Ok(out)
    }

    /// One certificate of the renewal sweep. `None` = not this sweep's to
    /// renew (a wildcard reference, a hosting being deleted).
    pub(super) async fn renew_one_cert(
        &self,
        cert: certificates::CertRow,
        now: i64,
        threshold_days: i64,
    ) -> Option<CertRenewResult> {
        let domain_str = cert.domain.clone();
        if self.is_wildcard_reference(&cert).await {
            return None;
        }
        // A None row (e.g. the panel cert or a test node's wildcard base,
        // which aren't hostings) is handled by its own arm below — it cannot
        // go through issue_real_cert, which opens by resolving a hosting that
        // does not exist.
        let hosting_row = hostings::get_by_domain(&self.pool, &domain_str)
            .await
            .ok()
            .flatten();
        // Only a hosting being torn down is genuinely un-renewable.
        if let Some(row) = &hosting_row {
            if matches!(row.state, HostingState::Deleting) {
                tracing::debug!(
                    domain = %domain_str,
                    state = %row.state.as_str(),
                    "cert renew: skipping hosting being deleted"
                );
                return None;
            }
        }
        // Suspended and trashed sites DO renew. The old code skipped them
        // on the premise that their vhost 503s the challenge path — but
        // nginx-vhost-suspended.conf.j2 puts the ACME location above
        // `location / { return 503; }` precisely so this keeps working,
        // and a regression test pins that. The skip therefore protected
        // nothing and cost real certificates: a site suspended over its
        // last 30 days came back serving an expired one, because the
        // promised "re-issued on resume" does not exist — resume() only
        // rewrites the vhost.
        //
        // They must NOT go through issue_real_cert, though. That calls
        // nginx_write_vhost, which renders the normal serving vhost with
        // no state check, so renewing a suspended site would quietly
        // un-suspend it — a non-paying customer back online as a side
        // effect of a cron tick. Issue directly instead and re-apply the
        // suspended vhost, which also gives nginx the reload it needs to
        // pick the new certificate up.
        let suspended_like = hosting_row
            .as_ref()
            .is_some_and(|r| matches!(r.state, HostingState::Suspended | HostingState::Trashed));
        self.append_audit(
            "cert.renew.attempt",
            None,
            &serde_json::json!({
                "domain": &domain_str,
                "not_after": cert.not_after,
                "threshold_days": threshold_days,
                "now": now,
            })
            .to_string(),
            "ok",
        )
        .await;

        // Wildcard certs (`*.domain`) can only be validated via
        // DNS-01 — HTTP-01 would fail every tick and burn the LE
        // failed-validation rate limit. Publishing a TXT record needs
        // DNS credentials, which this server deliberately does not hold,
        // so a wildcard is skipped and the operator is told to re-run the
        // manual flow before expiry. That is the standing cost of a
        // wildcard, and the issuance form says so up front.
        let is_wild = certificates::is_wildcard(&self.pool, &domain_str)
            .await
            .unwrap_or(false);
        // A wildcard whose `_acme-challenge` is CNAME-delegated to the
        // panel's acme zone is renewed by the master, not by this tick.
        let delegated = is_wild && cert.dns01_delegated;
        let outcome = match Domain::parse(&domain_str) {
            Err(e) => CertRenewOutcome::Failed {
                error: format!("invalid stored domain {domain_str}: {e}"),
            },
            Ok(_) if delegated => CertRenewOutcome::Skipped {
                reason: self
                    .operator_catalog()
                    .get("ops.cert_wildcard_delegated_skip")
                    .to_string(),
            },
            Ok(_) if is_wild => CertRenewOutcome::Skipped {
                reason: format!(
                    "wildcard cert — wildcards can only be validated over DNS-01, and \
                     this server holds no DNS credentials, so it cannot renew one \
                     unattended. {}",
                    wildcard_renew_hint(hosting_row.is_some())
                ),
            },
            // Renew without going through issue_real_cert. Two cases land
            // here, for the same underlying reason — issue_real_cert
            // resolves a hosting and then rewrites its serving vhost, and
            // neither is wanted:
            //
            //   * no hosting at all (the panel's own certificate). It
            //     opens with `self.get(sel)?`, so these returned NotFound
            //     every tick, forever, while the cert expired anyway.
            //   * a suspended or trashed hosting, where rewriting the
            //     serving vhost would un-suspend the site.
            Ok(_) if hosting_row.is_none() || suspended_like => {
                let email = match self.effective_acme_email(None) {
                    Ok(e) => e.to_string(),
                    // No contact address: recorded, but neither audited
                    // nor paged — nothing was attempted.
                    Err(e) => {
                        return Some(CertRenewResult {
                            domain: domain_str,
                            outcome: CertRenewOutcome::Failed {
                                error: e.to_string(),
                            },
                        })
                    }
                };
                self.renew_cert_directly(&cert, hosting_row.as_ref(), suspended_like, &email, now)
                    .await
            }
            Ok(d) => {
                let req = CertIssueRequest {
                    staging: false,
                    require_dns_match: false,
                    extra_sans: vec![],
                };
                match self.issue_real_cert(HostingSelector::Domain(d), req).await {
                    Ok(info) => CertRenewOutcome::Renewed {
                        new_not_after: info.not_after,
                    },
                    Err(e) => CertRenewOutcome::Failed {
                        error: e.to_string(),
                    },
                }
            }
        };

        let status = match &outcome {
            CertRenewOutcome::Renewed { .. } => "ok",
            CertRenewOutcome::Skipped { .. } => "skipped",
            _ => "failed",
        };
        self.append_audit(
            "cert.renew",
            None,
            &serde_json::json!({
                "domain": &domain_str,
                "outcome": &outcome,
            })
            .to_string(),
            status,
        )
        .await;
        // A trashed site's certificate is still renewed, so a restore does
        // not come back serving an expired one — but nobody is to be paged
        // about it. The usual reason a site is in the trash is that its
        // customer left and pointed DNS elsewhere, so HTTP-01 fails every
        // day, and this was a fresh bell entry every day until the purge,
        // for a site the certificates page no longer lists.
        let trashed = hosting_row
            .as_ref()
            .is_some_and(|r| r.state == HostingState::Trashed);
        let days_left = (cert.not_after - now) / 86400;
        // Delegated: the master renews it. Only nag once that has had its
        // chance and the margin is thin.
        let master_renews =
            delegated && matches!(outcome, CertRenewOutcome::Skipped { .. }) && days_left > 14;
        if !trashed && !master_renews {
            let href = cert_alert_href(&domain_str, hosting_row.is_some(), is_wild);
            self.notify_renew_outcome(&domain_str, &outcome, days_left, &href)
                .await;
        }
        Some(CertRenewResult {
            domain: domain_str,
            outcome,
        })
    }

    /// A subdomain that REUSES a parent wildcard carries a cert row whose
    /// files ARE the parent wildcard's (re-pointed at create / issuance
    /// time). The parent renews itself; the reference is skipped so we never
    /// attempt a doomed per-site issuance for a wildcard-only name. Matching
    /// on the shared cert path means a subdomain with its OWN distinct cert
    /// still renews normally.
    pub(super) async fn is_wildcard_reference(&self, cert: &certificates::CertRow) -> bool {
        let Some((_, parent)) = cert.domain.split_once('.') else {
            return false;
        };
        match certificates::get(&self.pool, parent).await {
            Ok(Some(parent_cert)) if parent_cert.cert_path == cert.cert_path => {
                certificates::is_wildcard(&self.pool, parent)
                    .await
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    /// HTTP-01 issuance straight into the existing cert files, for a cert
    /// that is not a serving hosting's (the panel's own) or belongs to a
    /// suspended/trashed site — followed by the reload nginx needs to see
    /// the new file, via the template that matches what the site is
    /// supposed to be serving.
    pub(super) async fn renew_cert_directly(
        &self,
        cert: &certificates::CertRow,
        hosting_row: Option<&hostings::HostingRow>,
        suspended_like: bool,
        email: &str,
        now: i64,
    ) -> CertRenewOutcome {
        let domain = cert.domain.as_str();
        let info =
            match hyperion_adapters::acme::issue_http01(hyperion_adapters::acme::IssueRequest {
                domain,
                sans: &[],
                contact_email: email,
                staging: false,
                challenge_root: std::path::Path::new(&self.paths.acme_challenge_root),
                certs_root: "/etc/hyperion/certs",
            })
            .await
            {
                Ok(info) => info,
                Err(e) => {
                    return CertRenewOutcome::Failed {
                        error: acme_failure_message(domain, false, &e.to_string()),
                    }
                }
            };
        let _ = certificates::upsert(
            &self.pool,
            domain,
            now,
            info.not_after,
            &cert.cert_path,
            &cert.key_path,
            &info.issuer,
        )
        .await;
        // nginx caches the certificate it loaded, so a renewed FILE is
        // invisible until a reload. The normal path gets that from
        // nginx_write_vhost; neither case here goes through it.
        if let (true, Some(row)) = (suspended_like, hosting_row) {
            // Re-apply with the SAME reason text the site is already
            // showing, so a renewal does not silently reword the operator's
            // suspension notice.
            let reason = self.suspended_notice(&row.id, row.state).await;
            let aliases = hostings::aliases(&self.pool, &row.id)
                .await
                .unwrap_or_default();
            if let Err(e) = self
                .adapters
                .nginx_apply_suspended(domain, aliases, reason)
                .await
            {
                tracing::warn!(
                    error=%e,
                    domain=%domain,
                    "renewed a suspended site's cert but could not re-apply \
                     its suspended vhost"
                );
            }
        }
        let panel_host = read_cluster_section(self.agent_config_path.as_deref()).panel_hostname;
        if !suspended_like && !panel_host.trim().is_empty() && domain == panel_host.trim() {
            let input = hyperion_adapters::nginx::PanelVhostInput {
                domain,
                cert_path: &cert.cert_path,
                key_path: &cert.key_path,
                acme_challenge_root: &self.paths.acme_challenge_root,
            };
            let paths = hyperion_adapters::nginx::Paths::debian_defaults();
            if let Err(e) = hyperion_adapters::nginx::write_panel_vhost(&paths, &input).await {
                tracing::warn!(
                    error=%e,
                    "panel cert renewed but the vhost reload failed — \
                     browsers keep seeing the old cert until nginx reloads"
                );
            }
        }
        CertRenewOutcome::Renewed {
            new_not_after: info.not_after,
        }
    }

    /// Surface a bell-icon notification for a renewal that needs a human.
    /// The kind string carries the domain so the bell can show one distinct
    /// row per failing cert (instead of all failures collapsing to a single
    /// "cert.renew_failed" line). The tick runs daily → at most one
    /// notification per cert per day; admins who miss day 30 still see days
    /// 29..0.
    pub(super) async fn notify_renew_outcome(
        &self,
        domain: &str,
        outcome: &CertRenewOutcome,
        days_left: i64,
        href: &str,
    ) {
        let days = days_left.to_string();
        match outcome {
            CertRenewOutcome::Failed { error } => {
                self.notify_admins_say(
                    // Red once the certificate is actually EXPIRED — that is
                    // the moment a visitor sees a warning instead of the
                    // site. Before that it is urgent, not broken. See the
                    // rule on `notify_admins`.
                    if days_left <= 0 { "error" } else { "warn" },
                    "ops.cert_failed",
                    &[("domain", domain), ("error", error), ("days", &days)],
                    href,
                    &format!("cert.renew_failed:{domain}"),
                )
                .await;
            }
            CertRenewOutcome::Renewed { .. } if days_left < 14 => {
                // Edge case: renewal succeeded but the cert was already
                // inside the red band. Notify so the operator knows their
                // automation caught it before expiry (informational, not a
                // failure).
                self.notify_admins_say(
                    "info",
                    "ops.cert_renewed_late",
                    &[("domain", domain), ("days", &days)],
                    href,
                    &format!("cert.renewed_late:{domain}"),
                )
                .await;
            }
            CertRenewOutcome::Skipped { reason } => {
                // Wildcard cert we can't auto-renew (no DNS token) — nag the
                // operator to re-run DNS-01 before it expires. Per-domain
                // kind → one bell row per cert.
                self.notify_admins_say(
                    if days_left <= 0 { "error" } else { "warn" },
                    "ops.cert_wildcard_manual",
                    &[("domain", domain), ("reason", reason), ("days", &days)],
                    href,
                    &format!("cert.wildcard_manual:{domain}"),
                )
                .await;
            }
            _ => {}
        }
    }

    /// Set or clear the per-hosting ACME contact email override.
    /// `email: None` (or empty) clears the override; the next cert
    /// issuance reverts to `[acme] contact_email` from agent.toml.
    /// Validates RFC-5321-shaped email when present (rejects
    /// placeholders + obviously-malformed addresses).
    pub async fn set_hosting_acme_email(
        &self,
        sel: HostingSelector,
        email: Option<String>,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // Normalise: empty / whitespace → clear.
        let cleaned: Option<String> = email
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(ref e) = cleaned {
            // Same validation as the global acme_contact_email
            // sanity check in issue_real_cert. Refuse placeholders +
            // values that obviously can't reach LE.
            let lc = e.to_lowercase();
            if !e.contains('@')
                || lc.ends_with("@example.com")
                || lc.ends_with("@example.org")
                || lc.ends_with("@example.net")
                || lc.ends_with("@hyperion.invalid")
                || e.len() > 254
            {
                return Err(RpcError::Validation {
                    message: format!(
                        "acme email `{e}` is invalid or a placeholder — \
                         use a real address (or leave blank to fall back to the agent default)."
                    ),
                });
            }
        }
        hostings::set_acme_contact_email(&self.pool, &detail.id, cleaned.as_deref(), now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("update: {e}")))?;
        self.append_audit(
            "hosting.acme_email.set",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "cleared": cleaned.is_none(),
                // We log presence (was-set / was-cleared) but not the
                // actual value — emails are PII.
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }
}

/// True when `ip` parses as IPv4 inside Cloudflare's published proxy
/// ranges (www.cloudflare.com/ips-v4 — a list that has been stable for
/// years). A domain whose A records all sit in these ranges is proxied:
/// the visible addresses belong to Cloudflare BY DESIGN, and comparing
/// them against this node's own IP proves nothing about where traffic
/// actually lands.
/// True when every published address of `domain` sits inside Cloudflare's
/// proxy ranges — the same test the DNS banner uses, packaged for the
/// ACME path. Empty answers are NOT proxied: a domain with no records at
/// all has a different problem, and HTTP-01 will produce the accurate
/// error for it.
/// Turn a raw ACME failure into one that names the fix.
///
/// The CA only ever reports what it saw ("Invalid response", a 5xx, a
/// timeout). On a proxied domain the *cause* is usually a Cloudflare setting
/// the CA cannot see and no amount of DNS checking can reach — most often the
/// Full (strict) deadlock, where the origin is still on the self-signed
/// bootstrap certificate, Cloudflare refuses it, and the operator is told
/// only that validation failed. That gap is what turned one setting into an
/// outage, so the mapping lives here rather than in the UI: renewals and the
/// API surface the same text as the SSL tab.
///
/// The raw CA error is always appended — a hint that guesses wrong must never
/// hide the evidence.
pub(super) fn acme_failure_message(domain: &str, proxied: bool, raw: &str) -> String {
    let low = raw.to_lowercase();

    // Cloudflare's own origin-TLS errors. 525 is a failed handshake, 526 an
    // untrusted origin certificate; both are observed for a self-signed
    // origin under Full (strict), so never name just one.
    let hint = if proxied && (low.contains("525") || low.contains("526")) {
        Some(format!(
            "Cloudflare is refusing this server's certificate, so Let's Encrypt never saw the \
             challenge. {domain} is proxied through Cloudflare and this server is still on its \
             self-signed bootstrap certificate, which Full (strict) rejects — the same reason \
             visitors get error 525/526 while nginx here is healthy. FIX: in Cloudflare, \
             SSL/TLS -> Overview, switch the mode from 'Full (strict)' to 'Full', press \
             'Issue HTTPS certificate' again, then switch back once the certificate is \
             installed. It takes about a minute and does not interrupt visitors. Alternatively \
             upload a Cloudflare Origin CA certificate here, which Full (strict) accepts."
        ))
    } else if proxied && (low.contains("403") || low.contains("503") || low.contains("challenge")) {
        Some(format!(
            "Cloudflare answered the challenge itself instead of passing it to this server, so \
             Let's Encrypt got a block or challenge page rather than the token. Let's Encrypt \
             does not run JavaScript and will fail the same way every time. FIX: in Cloudflare, \
             turn off 'I'm Under Attack' under Security -> Settings, or add a WAF skip rule for \
             'URI Path starts with /.well-known/acme-challenge/'. On the Free plan Bot Fight \
             Mode cannot be skipped per-path and has to be off while {domain} is issued."
        ))
    } else if low.contains("404") || low.contains("invalid response") {
        Some(format!(
            "The challenge URL reached a web server, but not this one — something in front of \
             {domain} is answering or rewriting /.well-known/acme-challenge/. Usual causes, in \
             order: a Cloudflare Redirect Rule or Page Rule on /* that drops the path (apex-to-www \
             forwarding is the classic one — it must preserve ${{1}}), a Worker route on /*, an \
             Origin Rule pointing elsewhere, or DNS pointing at a different server."
        ))
    } else if low.contains("poll_ready") || low.contains("timed out") {
        // The order never left pending/processing: challenges were
        // published, but Let's Encrypt's validators could not fetch them
        // in time. On a fresh server this is almost always one of two
        // things, and neither is visible in the CA's message.
        Some(format!(
            "Let's Encrypt accepted the request but never managed to validate it — its \
             servers could not reach {domain} in time. Two usual causes on a new server: \
             the domain's DNS A record does not point at THIS machine yet (check with \
             `dig +short A {domain}` — it must return this server's IP), or inbound port \
             80 is blocked by a firewall (HTTP-01 always starts on port 80; redirecting \
             it to HTTPS is fine, blocking it is not — check the provider's cloud \
             firewall too). Fix whichever applies, then press 'Issue HTTPS certificate' \
             again."
        ))
    } else if low.contains("timeout") || low.contains("connection") || low.contains("refused") {
        Some(format!(
            "Nothing answered on port 80 for {domain}. HTTP-01 always STARTS on port 80 — it \
             will follow a redirect to HTTPS, but it cannot begin on 443. FIX: allow inbound TCP \
             port 80 in this server's firewall, and if Cloudflare has a WAF rule blocking \
             plaintext requests, skip it for '/.well-known/acme-challenge/'. Redirecting port 80 \
             to HTTPS is fine; blocking it is not."
        ))
    } else if low.contains("rate limit") || low.contains("too many") {
        Some(
            "Let's Encrypt is rate-limiting this name. It allows 5 failed validations per \
             hostname per hour, so retrying now only extends the lockout — wait an hour, then \
             fix the underlying error below before trying again."
                .to_string(),
        )
    } else {
        None
    };

    match hint {
        Some(h) => format!("{h}\n\nLet's Encrypt reported: {raw}"),
        None => raw.to_string(),
    }
}

pub(super) async fn domain_is_cloudflare_proxied(domain: &str) -> bool {
    let (a, aaaa) = tokio::join!(dig_records(domain, "A"), dig_records(domain, "AAAA"));
    let a = a.unwrap_or_default();
    let aaaa = aaaa.unwrap_or_default();
    !a.is_empty()
        && a.iter().all(|ip| is_cloudflare_ipv4(ip))
        && aaaa.iter().all(|ip| is_cloudflare_ipv6(ip))
}

pub(super) fn is_cloudflare_ipv4(ip: &str) -> bool {
    let Ok(addr) = ip.trim().parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let a = u32::from(addr);
    const RANGES: &[(u32, u32)] = &[
        (0xadf53000, 20),
        (0x6715f400, 22),
        (0x6716c800, 22),
        (0x671f0400, 22),
        (0x8d654000, 18),
        (0x6ca2c000, 18),
        (0xbe5df000, 20),
        (0xbc726000, 20),
        (0xc5eaf000, 22),
        (0xc6298000, 17),
        (0xa29e0000, 15),
        (0x68100000, 13),
        (0x68180000, 14),
        (0xac400000, 13),
        (0x83004800, 22),
    ];
    RANGES.iter().any(|(net, len)| (a ^ net) >> (32 - len) == 0)
}

/// IPv6 companion of [`is_cloudflare_ipv4`] (www.cloudflare.com/ips-v6).
pub(super) fn is_cloudflare_ipv6(ip: &str) -> bool {
    let Ok(addr) = ip.trim().parse::<std::net::Ipv6Addr>() else {
        return false;
    };
    let a = u128::from(addr);
    const RANGES: &[(&str, u32)] = &[
        ("2400:cb00::", 32),
        ("2606:4700::", 32),
        ("2803:f800::", 32),
        ("2405:b500::", 32),
        ("2405:8100::", 32),
        ("2a06:98c0::", 29),
        ("2c0f:f248::", 32),
    ];
    RANGES.iter().any(|(net, len)| {
        let Ok(n) = net.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        (a ^ u128::from(n)) >> (128 - len) == 0
    })
}
