//! The master panel's own vhost, certificate and deployment mode.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Re-assert the master-panel nginx vhost from the current template, if a
    /// panel hostname is configured and its cert exists on disk. Called on
    /// agent boot so template improvements (e.g. the upstream-down "updating"
    /// page that replaces a bare 502 during `update.sh`) take effect after an
    /// in-place update — the vhost is otherwise only rewritten on hostname
    /// provision / cert issuance — and a deleted panel vhost self-heals.
    ///
    /// Returns `Ok(false)` (no-op) when there's no panel hostname or no cert
    /// yet; `write_panel_vhost` runs `nginx -t` and restores the prior file on
    /// failure, so a bad reload can't take the panel offline.
    /// Write `[cluster] mode` explicitly, once, if it isn't there yet.
    ///
    /// Run at agent boot. Without this the mode is only ever *inferred* at
    /// runtime, and `cat /etc/hyperion/agent.toml` cannot answer "what is
    /// this box". With it, an existing install picks the right answer on
    /// update with no operator action: an empty `nodes` table means nothing
    /// ever enrolled, which is a standalone box.
    ///
    /// Guarded on the KEY being absent, not the section — so a re-run is a
    /// no-op on CONTENT, and an operator who deliberately set "master" on a
    /// box with no workers yet is never overridden. Never touches a worker:
    /// its role comes from the enrollment credential, and writing a
    /// contradicting key would be the exact confusion this avoids.
    pub async fn backfill_deployment_mode(&self) -> Result<(), RpcError> {
        if self.is_worker_node() {
            return Ok(());
        }
        let Some(path) = self.agent_config_path.as_deref() else {
            return Ok(());
        };
        // Read the raw document rather than the parsed view: the view maps
        // "absent" onto "master", which is exactly the distinction we need.
        let already_set = std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| raw.parse::<toml_edit::DocumentMut>().ok())
            .map(|doc| {
                doc.get("cluster")
                    .and_then(|s| s.get("mode"))
                    .and_then(|v| v.as_str())
                    .is_some_and(|m| !m.trim().is_empty())
            })
            .unwrap_or(false);
        if already_set {
            return Ok(());
        }
        let has_nodes = hyperion_state::nodes::list(&self.pool)
            .await
            .map(|n| !n.is_empty())
            .unwrap_or(true); // unreadable ⇒ assume cluster, the safe way
        let mode = if has_nodes { "master" } else { "standalone" };
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("mode".to_string(), mode.to_string());
        self.agent_config_update("cluster".to_string(), fields)
            .await?;
        tracing::info!(
            mode,
            has_nodes,
            "recorded this box's deployment mode in agent.toml"
        );
        Ok(())
    }

    /// Promote a standalone box to master. Called after a node successfully
    /// enrolls, so adding the first worker never requires the operator to
    /// find a setting first — the box just stops being standalone.
    pub(crate) async fn promote_to_master_if_standalone(&self) {
        if !self.is_standalone() {
            return;
        }
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("mode".to_string(), "master".to_string());
        match self
            .agent_config_update("cluster".to_string(), fields)
            .await
        {
            Ok(()) => tracing::info!("a node enrolled — this box is now a cluster master"),
            Err(e) => tracing::warn!(
                error = %e,
                "a node enrolled but the deployment mode could not be updated — \
                 the cluster UI stays hidden until it is set in Settings"
            ),
        }
    }

    pub async fn ensure_panel_vhost(&self) -> Result<bool, RpcError> {
        let hostname = read_cluster_section(self.agent_config_path.as_deref())
            .panel_hostname
            .trim()
            .to_string();
        if hostname.is_empty() {
            return Ok(false);
        }
        let (cert_path, key_path) = panel_cert_paths(&hostname);
        // Skip until the cert exists — otherwise nginx -t would fail and
        // write_panel_vhost would just restore the backup. The panel isn't
        // fully provisioned without it.
        if tokio::fs::metadata(&cert_path).await.is_err() {
            return Ok(false);
        }

        // Adopt a panel cert that predates it being recorded. Panel issuance
        // used to write the cert to disk and nowhere else, so on every install
        // provisioned before that was fixed the panel's certificate exists but
        // has no `certificates` row — and the renewal sweep reads that table
        // and nothing else. Left alone it expires at day 90, and because the
        // panel vhost sets HSTS for two years with includeSubDomains, the
        // result is a browser interstitial with no click-through, on the exact
        // hostname the operator would use to fix it.
        //
        // This runs at agent boot, so the repair reaches existing installs on
        // update with no operator action. Keyed on the row being absent, so it
        // is idempotent and never overwrites a live row (in particular it
        // cannot flip an operator-uploaded "manual" cert into the sweep).
        if certificates::get(&self.pool, &hostname)
            .await
            .ok()
            .flatten()
            .is_none()
        {
            match tokio::fs::read_to_string(&cert_path).await {
                Ok(pem) => match hyperion_adapters::cert::inspect_pem(&pem) {
                    Ok(info) => {
                        let (not_after, issuer) = (info.not_after, info.issuer);
                        match certificates::upsert(
                            &self.pool,
                            &hostname,
                            now_secs(),
                            not_after,
                            &cert_path,
                            &key_path,
                            &issuer,
                        )
                        .await
                        {
                            Ok(_) => {
                                tracing::info!(
                                    domain = %hostname,
                                    not_after,
                                    %issuer,
                                    "adopted the panel certificate into the renewal sweep"
                                );
                                self.append_audit(
                                    "cert.panel_adopted",
                                    None,
                                    &serde_json::json!({
                                        "domain": &hostname,
                                        "not_after": not_after,
                                        "issuer": &issuer,
                                    })
                                    .to_string(),
                                    "ok",
                                )
                                .await;
                            }
                            Err(e) => tracing::warn!(
                                error=%e,
                                domain=%hostname,
                                "could not record the panel cert — it will not auto-renew"
                            ),
                        }
                    }
                    Err(e) => tracing::warn!(
                        error=%e,
                        path=%cert_path,
                        "panel cert on disk did not parse — not adopting"
                    ),
                },
                Err(e) => tracing::warn!(
                    error=%e,
                    path=%cert_path,
                    "could not read the panel cert — not adopting"
                ),
            }
        }

        write_panel_vhost_for(&hostname)
            .await
            .map_err(|e| RpcError::Internal_with(format!("ensure_panel_vhost: {e}")))?;
        Ok(true)
    }

    /// Read the current panel ACME progress. Used by /settings to
    /// drive the HTMX-polled progress card.
    pub async fn panel_cert_status(&self) -> Result<Option<PanelProgress>, RpcError> {
        Ok(self.panel_progress.read().await.clone())
    }

    /// One-shot provisioning of the Hyperion master panel on a
    /// public FQDN. Steps:
    ///   1. Validate hostname shape (FQDN charset, ≤253 chars).
    ///   2. DNS preflight — resolve the FQDN, check it points at
    ///      one of this node's public IPs. Skippable via the
    ///      `skip_dns_check` flag (operator just changed the
    ///      record and the resolver hasn't caught up).
    ///   3. Persist `cluster.panel_hostname` to agent.toml via
    ///      the existing agent_config_update path.
    ///   4. Generate a self-signed bootstrap cert at
    ///      `/etc/hyperion/certs/<hostname>/` so nginx can start.
    ///   5. Render the panel vhost (proxy to 127.0.0.1:8443),
    ///      atomic-write, `nginx -t`, reload.
    ///   6. Kick off a real ACME issuance in the background. The
    ///      operator can hit https://hostname immediately (with
    ///      the self-signed cert producing a browser warning);
    ///      within ~30 seconds the cert renewal swap will land
    ///      the real LE cert in place.
    ///
    /// Returns `(status, message, panel_url)`. `status` ∈
    /// {"ok-cert-pending", "ok", "dns-failed", "nginx-failed",
    /// "validation-failed"}.
    pub async fn panel_provision(
        &self,
        hostname: String,
        skip_dns_check: bool,
    ) -> Result<(String, String, String), RpcError> {
        let hostname = hostname.trim().to_ascii_lowercase();
        let cert_info = match self.panel_provision_steps(&hostname, skip_dns_check).await {
            Ok(c) => c,
            Err((status, message)) => return Ok((status.into(), message, String::new())),
        };
        self.start_panel_acme(&hostname, cert_info.not_after).await;

        self.append_audit(
            "panel.provision",
            None,
            &serde_json::json!({
                "hostname": hostname,
                "skip_dns_check": skip_dns_check,
                "cert_fingerprint": cert_info.fingerprint_sha256,
            })
            .to_string(),
            "ok",
        )
        .await;

        let url = format!("https://{hostname}");
        Ok((
            "ok-cert-pending".to_string(),
            format!(
                "Panel vhost written + nginx reloaded. \
                 You can reach it now at {url} \
                 (the browser will show a self-signed warning \
                 — accept once, real LE cert takes ~30 s).\n\n\
                 If the cert hasn't auto-issued in a minute, \
                 retry from the SSL tab or run `hctl cert renew` on this node."
            ),
            url,
        ))
    }

    /// Steps 1–5 of [`Self::panel_provision`]. `Err` is `(status, message)`.
    pub(super) async fn panel_provision_steps(
        &self,
        hostname: &str,
        skip_dns_check: bool,
    ) -> Result<CertInfo, (&'static str, String)> {
        // ── 1. validation ─────────────────────────────────────
        validate_panel_hostname(hostname).map_err(|m| ("validation-failed", m))?;
        // ── 2. DNS preflight ─────────────────────────────────
        if !skip_dns_check {
            self.panel_dns_preflight(hostname).await?;
        }
        // ── 3. persist in agent.toml ─────────────────────────
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("panel_hostname".to_string(), hostname.to_string());
        self.agent_config_update("cluster".to_string(), fields)
            .await
            .map_err(|e| {
                (
                    "validation-failed",
                    format!("could not persist panel_hostname to agent.toml: {e}"),
                )
            })?;
        // ── 4. self-signed bootstrap cert ────────────────────
        // We always re-issue the bootstrap so nginx -t passes
        // even on a fresh box. The real LE cert will overwrite
        // these same paths once issued.
        let cert_info = self.adapters.acme_issue(hostname, &[]).await.map_err(|e| {
            (
                "validation-failed",
                format!("self-signed bootstrap cert failed: {e}"),
            )
        })?;
        // ── 5. write panel vhost + reload nginx ──────────────
        write_panel_vhost_for(hostname).await.map_err(|e| {
            (
                "nginx-failed",
                format!(
                    "panel vhost write / nginx reload failed: {e}. \
                     The cert files are in /etc/hyperion/certs/{hostname}/ \
                     but nginx isn't serving them yet."
                ),
            )
        })?;
        Ok(cert_info)
    }

    /// The panel hostname must already resolve to this node.
    pub(super) async fn panel_dns_preflight(
        &self,
        hostname: &str,
    ) -> Result<(), (&'static str, String)> {
        let parsed = Domain::parse(hostname).map_err(|e| {
            (
                "validation-failed",
                format!("hostname doesn't pass domain validator: {e}"),
            )
        })?;
        match self.dns_check(parsed).await {
            Ok(r) if r.matches => Ok(()),
            Ok(r) => {
                let our_v4 = r.our_public_ipv4.unwrap_or_default();
                let our_v6 = r.our_public_ipv6.unwrap_or_default();
                Err((
                    "dns-failed",
                    format!(
                        "DNS for {hostname} doesn't resolve to this node's public IP. \
                         Add an A record → {our_v4}{maybe_v6}. \
                         If you've just added it, retry with \"Skip DNS check\" \
                         once propagation completes.\n\nNote: {note}",
                        maybe_v6 = if our_v6.is_empty() {
                            String::new()
                        } else {
                            format!(" (or AAAA → {our_v6})")
                        },
                        note = r.note,
                    ),
                ))
            }
            Err(e) => {
                tracing::warn!(error=%e, "dns_check for panel hostname failed");
                Err((
                    "dns-failed",
                    format!(
                        "DNS probe errored: {e}. \
                         If you're sure the record is set, retry with \
                         \"Skip DNS check\" enabled."
                    ),
                ))
            }
        }
    }

    /// ── 6. ACME issuance — REAL LE cert in background ────
    /// The self-signed cert is already serving. The background task calls
    /// the same `acme::issue_http01` flow used for hostings, updates
    /// `panel_progress` so the UI can poll for live status, and re-renders
    /// the panel vhost when the real cert lands so nginx picks it up.
    pub(super) async fn start_panel_acme(&self, hostname: &str, bootstrap_not_after: i64) {
        let progress = self.panel_progress.clone();
        // Seed progress with "self-signed" so the UI immediately sees a card
        // + can start polling.
        set_panel_progress(
            &progress,
            hostname,
            "self-signed",
            "Bootstrap self-signed cert serving — Let's Encrypt issuance starting…".into(),
            bootstrap_not_after,
        )
        .await;
        let email = self.acme_contact_email.trim().to_string();
        if is_placeholder_acme_email(&email) {
            // Don't burn an ACME account on a placeholder address — surface
            // the actionable error in the progress card.
            set_panel_progress(
                &progress,
                hostname,
                "failed",
                format!(
                    "ACME contact email \"{email}\" is a placeholder. Edit Settings → HTTPS & previews → Let's Encrypt contact and retry."
                ),
                bootstrap_not_after,
            )
            .await;
            return;
        }
        // The renewal sweep reads the `certificates` table and nothing else,
        // so the panel's own cert has to land there or it is never a renewal
        // candidate — see the upsert below.
        let pool = self.pool.clone();
        let challenge_root = self.paths.acme_challenge_root.clone();
        let hostname = hostname.to_string();
        tokio::spawn(async move {
            set_panel_progress(
                &progress,
                &hostname,
                "issuing",
                "Requesting cert from Let's Encrypt + serving HTTP-01 challenge…".into(),
                0,
            )
            .await;
            let result =
                hyperion_adapters::acme::issue_http01(hyperion_adapters::acme::IssueRequest {
                    domain: &hostname,
                    sans: &[],
                    contact_email: &email,
                    staging: false,
                    challenge_root: std::path::Path::new(&challenge_root),
                    certs_root: "/etc/hyperion/certs",
                })
                .await;
            let info = match result {
                Ok(info) => info,
                Err(e) => {
                    tracing::warn!(error=%e, "panel ACME issuance failed");
                    set_panel_progress(
                        &progress,
                        &hostname,
                        "failed",
                        format!("ACME issuance failed: {e}"),
                        bootstrap_not_after,
                    )
                    .await;
                    return;
                }
            };
            // Record it, or it never renews. Until this existed the panel
            // cert lived only in the in-memory progress cell and on disk;
            // cert_renew_tick reads the certificates table, so the one
            // certificate whose expiry locks the operator out of the UI they
            // would use to fix it was the only one nothing was watching. HSTS
            // on the panel vhost is two years with includeSubDomains, so an
            // expired panel cert is a browser interstitial with no
            // click-through, and raw-IP access 308-redirects straight back to
            // the dead hostname.
            //
            // Logged rather than ignored: a silent failure here puts the cert
            // back outside the sweep, which is exactly the bug this closes.
            let (cert_path, key_path) = panel_cert_paths(&hostname);
            if let Err(e) = certificates::upsert(
                &pool,
                &hostname,
                now_secs(),
                info.not_after,
                &cert_path,
                &key_path,
                &info.issuer,
            )
            .await
            {
                tracing::error!(
                    error=%e,
                    domain=%hostname,
                    "panel cert issued but NOT recorded — it will not auto-renew"
                );
            }
            // Re-render panel vhost — paths unchanged, reload picks up the
            // new cert chain.
            let (stage, message) = match write_panel_vhost_for(&hostname).await {
                Err(e) => (
                    "failed",
                    format!("Cert issued but nginx reload failed: {e}"),
                ),
                Ok(()) => (
                    "issued",
                    format!("Real Let's Encrypt cert serving · issuer: {}", info.issuer),
                ),
            };
            set_panel_progress(&progress, &hostname, stage, message, info.not_after).await;
        });
    }
}

/// FQDN charset, ≤253 chars, at least one dot.
pub(super) fn validate_panel_hostname(hostname: &str) -> Result<(), String> {
    if hostname.is_empty() {
        return Err("hostname is empty".into());
    }
    if hostname.len() > 253 || !hostname.contains('.') {
        return Err("hostname must be a real FQDN (e.g. panel.example.com)".into());
    }
    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err("hostname contains invalid characters (only [a-z0-9.-] allowed)".into());
    }
    Ok(())
}

/// An address Let's Encrypt would accept but nobody reads.
pub(super) fn is_placeholder_acme_email(email: &str) -> bool {
    email.is_empty()
        || email.ends_with("@example.com")
        || email.ends_with("@example.org")
        || email.ends_with("@example.net")
        || email.ends_with("@hyperion.invalid")
        || !email.contains('@')
}

fn panel_cert_paths(hostname: &str) -> (String, String) {
    (
        format!("/etc/hyperion/certs/{hostname}/fullchain.pem"),
        format!("/etc/hyperion/certs/{hostname}/privkey.pem"),
    )
}

/// Render the panel vhost (proxy to 127.0.0.1:8443) for `hostname`'s cert
/// files, atomic-write, `nginx -t`, reload.
async fn write_panel_vhost_for(hostname: &str) -> Result<(), hyperion_adapters::AdapterError> {
    let (cert_path, key_path) = panel_cert_paths(hostname);
    let input = hyperion_adapters::nginx::PanelVhostInput {
        domain: hostname,
        cert_path: &cert_path,
        key_path: &key_path,
        acme_challenge_root: "/var/lib/hyperion/acme-challenges",
    };
    let paths = hyperion_adapters::nginx::Paths::debian_defaults();
    hyperion_adapters::nginx::write_panel_vhost(&paths, &input).await
}

async fn set_panel_progress(
    progress: &tokio::sync::RwLock<Option<PanelProgress>>,
    hostname: &str,
    stage: &str,
    message: String,
    not_after: i64,
) {
    *progress.write().await = Some(PanelProgress {
        hostname: hostname.to_string(),
        stage: stage.into(),
        message,
        started_at: now_secs(),
        not_after,
    });
}
