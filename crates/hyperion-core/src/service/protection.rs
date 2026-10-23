//! IP bans, fail2ban scanning, the WAF and ModSecurity/CRS.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Add an IP ban (manual or auto). IPv4 only — validated at the
    /// boundary. `ttl_secs == 0` ⇒ permanent (manual bans only).
    pub async fn ban_add(
        &self,
        ip: String,
        hosting_id: Option<String>,
        reason: String,
        ttl_secs: i64,
        source: String,
    ) -> Result<(), RpcError> {
        let parsed: std::net::IpAddr = ip.trim().parse().map_err(|_| RpcError::Validation {
            message: "not a valid IP address".into(),
        })?;
        // Never let the operator ban a loopback / unspecified address and
        // lock themselves (or the master↔worker link) out by accident.
        if parsed.is_loopback() || parsed.is_unspecified() {
            return Err(RpcError::Validation {
                message: "refusing to ban loopback / unspecified address".into(),
            });
        }
        let ip = parsed.to_string();
        nft_ensure_ban_infra().await?;
        nft_ban(&ip, ttl_secs).await?;
        let now = now_secs();
        let expires = if ttl_secs > 0 { now + ttl_secs } else { 0 };
        hyperion_state::bans::add_or_refresh(
            &self.pool,
            &ip,
            hosting_id.as_deref(),
            &reason,
            &source,
            now,
            expires,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("ban persist: {e}")))?;
        self.append_audit(
            "hosting.ban.add",
            hosting_id.as_deref(),
            &serde_json::json!({"ip": ip, "reason": reason, "source": source, "ttl": ttl_secs})
                .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Lift an IP ban.
    /// Lift a ban. `sel` scopes it: `None` is an unrestricted removal and is
    /// admin-only at the web layer.
    ///
    /// The nftables side is ONE global set dropped on the input hook, so
    /// "unban" is not scoped by anything the packet filter knows — a request
    /// naming only an IP lifted whatever protection that IP had, including a
    /// fail2ban ban raised for a DIFFERENT tenant. Both Customer and Operator
    /// hold SecurityManage on their own hosting, so the per-hosting gate on
    /// the route was not the boundary it looked like.
    pub async fn ban_remove(
        &self,
        ip: String,
        sel: Option<HostingSelector>,
    ) -> Result<(), RpcError> {
        let parsed: std::net::IpAddr = ip.trim().parse().map_err(|_| RpcError::Validation {
            message: "not a valid IP address".into(),
        })?;
        let ip = parsed.to_string();
        if let Some(sel) = sel {
            let detail = self.get(sel).await?;
            let owners = hyperion_state::bans::owners_of_active(&self.pool, &ip)
                .await
                .map_err(|e| RpcError::Internal_with(format!("ban owners: {e}")))?;
            // Every active ban on this IP must belong to this hosting. A
            // node-wide one (hosting_id NULL, what the brute-force scanner
            // raises) protects everybody, so lifting it is an admin decision.
            let mine = !owners.is_empty()
                && owners
                    .iter()
                    .all(|o| o.as_deref() == Some(detail.id.as_str()));
            if !mine {
                return Err(RpcError::Validation {
                    message: format!(
                        "{ip} is not banned for {} alone — it is a node-wide ban or \
                         belongs to another site. Lifting it needs an administrator, \
                         because the firewall set is shared by every site on this node.",
                        detail.domain
                    ),
                });
            }
        }
        nft_unban(&ip).await;
        hyperion_state::bans::deactivate(&self.pool, &ip, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("ban remove: {e}")))?;
        self.append_audit(
            "hosting.ban.remove",
            None,
            &serde_json::json!({"ip": ip}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// List active bans. `hosting_id = Some` ⇒ bans attributed to that
    /// hosting plus node-wide manual bans; `None` ⇒ every active ban.
    pub async fn ban_list(
        &self,
        hosting_id: Option<String>,
    ) -> Result<Vec<hyperion_types::IpBanWire>, RpcError> {
        let now = now_secs();
        // Opportunistic sweep so the list never shows a lapsed ban.
        if let Ok(expired) = hyperion_state::bans::reap_expired(&self.pool, now).await {
            for ip in &expired {
                nft_unban(ip).await;
            }
        }
        let bans = match hosting_id {
            Some(h) => hyperion_state::bans::list_for_hosting(&self.pool, &h, now).await,
            None => hyperion_state::bans::list_active(&self.pool, now).await,
        }
        .map_err(|e| RpcError::Internal_with(format!("ban list: {e}")))?;
        Ok(bans.into_iter().map(ban_to_wire).collect())
    }

    /// Re-apply persisted, unexpired bans to nftables (whose sets are
    /// in-memory and lost on reboot). Called once at agent start.
    pub async fn bans_reapply_on_boot(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let bans = hyperion_state::bans::list_active(&self.pool, now)
            .await
            .map_err(|e| RpcError::Internal_with(format!("ban list: {e}")))?;
        if bans.is_empty() {
            return Ok(0);
        }
        nft_ensure_ban_infra().await?;
        let mut n = 0i64;
        for b in bans {
            let ttl = if b.expires_at > 0 {
                (b.expires_at - now).max(1)
            } else {
                0
            };
            if nft_ban(&b.ip, ttl).await.is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Apply an automatic ban with escalation, unless the IP is already
    /// banned this window. Returns true when a fresh ban was created. A
    /// repeat offender — an IP with a prior ban inside the configured
    /// look-back — earns the longer `repeat_ttl_secs` instead of the
    /// first-offence `ban_ttl_secs`.
    ///
    /// Refuses to auto-ban anything that isn't a public, routable address:
    /// a private / loopback / CGNAT / link-local IP in a log or journal is
    /// almost always internal traffic (webmail hitting dovecot on
    /// 127.0.0.1, the cluster master link, a NAT gateway) whose node-wide
    /// firewall drop would be a self-inflicted outage, not a defence.
    /// Operators can still ban any address manually via `ban_add`.
    pub(super) async fn auto_ban(
        &self,
        ip: &str,
        hosting_id: Option<&str>,
        reason: &str,
        now: i64,
    ) -> bool {
        let cfg = &self.fail2ban;
        if !hyperion_adapters::logscan::is_public_bannable_ip(ip) {
            return false;
        }
        if hyperion_state::bans::is_active(&self.pool, ip, now)
            .await
            .unwrap_or(false)
        {
            return false;
        }
        let repeat =
            hyperion_state::bans::was_banned_since(&self.pool, ip, now - cfg.repeat_lookback_secs)
                .await
                .unwrap_or(false);
        let ttl = if repeat {
            cfg.repeat_ttl_secs
        } else {
            cfg.ban_ttl_secs
        };
        let reason = if repeat {
            format!("{reason} (repeat offender)")
        } else {
            reason.to_string()
        };
        self.ban_add(
            ip.to_string(),
            hosting_id.map(String::from),
            reason,
            ttl,
            "auto".to_string(),
        )
        .await
        .is_ok()
    }

    /// Whether the HTTP brute-force scan — the wp-login / xmlrpc access-log
    /// sweep — may look at this hosting. Per-hosting toggle in `hosting_kv`
    /// (`http_bruteforce_scan_enabled`); **default ON** (absent ⇒ enabled),
    /// so nothing changes for a site that predates the key. "off" opts the
    /// site out.
    ///
    /// A read error also answers "on": a DB hiccup must not quietly stop
    /// protecting a site the customer is paying to have watched.
    pub(super) async fn http_bruteforce_scan_enabled(&self, hosting_id: &str) -> bool {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, FAIL2BAN_HTTP_KV_KEY).await {
            Ok(Some(v)) => v.trim() != "off",
            _ => true,
        }
    }

    /// Record that the brute-force scanner is watching this site.
    ///
    /// Stores BOTH ends of the evidence, `"<since>,<last_scan>"`, because a
    /// start alone cannot describe a gap. Protection that stops and later
    /// resumes — the node down for a week, `[fail2ban] enabled = false`
    /// flipped off and back on, the agent simply not running — would
    /// otherwise keep its original `since` and let the letter back-claim
    /// the dark days. A scan arriving more than
    /// [`FAIL2BAN_COVERAGE_GAP_SECS`] after the last one therefore starts a
    /// new stretch.
    ///
    /// `hosting_kv` is node-local and so is the scanner, which is what
    /// makes this readable by the care report — that runs on the owning
    /// node too.
    pub(super) async fn note_bruteforce_coverage(&self, hosting_id: &str, at: i64) {
        let prev =
            hyperion_state::hosting_kv::get(&self.pool, hosting_id, FAIL2BAN_HTTP_SINCE_KV_KEY)
                .await
                .ok()
                .flatten();
        let since = match prev.as_deref().and_then(parse_coverage_stamp) {
            Some((since, last)) if at.saturating_sub(last) <= FAIL2BAN_COVERAGE_GAP_SECS => since,
            // Never stamped, unparseable, or resuming after a gap.
            _ => at,
        };
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id,
            FAIL2BAN_HTTP_SINCE_KV_KEY,
            &format!("{since},{at}"),
            now_secs(),
        )
        .await;
    }

    /// When protection demonstrably began watching this site, or `None`
    /// when it is not watching now.
    ///
    /// A read failure, an absent stamp, or a stamp whose last scan is stale
    /// all answer `Some(now)` — "we cannot evidence any of this period".
    /// That is the opposite of how [`Self::http_bruteforce_scan_enabled`]
    /// fails, and deliberately so: there, failing open keeps a paying
    /// customer PROTECTED; here, failing open would let the letter CLAIM
    /// protection it cannot evidence. The caller turns a `since` at or past
    /// the period end into "not monitored".
    pub(super) async fn bruteforce_coverage_since(&self, hosting_id: &str) -> Option<i64> {
        if !self.fail2ban.enabled || !self.http_bruteforce_scan_enabled(hosting_id).await {
            return None;
        }
        let now = now_secs();
        let stamp =
            hyperion_state::hosting_kv::get(&self.pool, hosting_id, FAIL2BAN_HTTP_SINCE_KV_KEY)
                .await
                .ok()
                .flatten();
        match stamp.as_deref().and_then(parse_coverage_stamp) {
            // Configured on, but nothing has actually scanned recently —
            // the switch says yes and the evidence says nothing.
            Some((since, last)) if now.saturating_sub(last) <= FAIL2BAN_COVERAGE_GAP_SECS => {
                Some(since)
            }
            _ => Some(now),
        }
    }

    /// This node's ModSecurity engine, and how many of its sites use it.
    pub async fn modsec_status(&self) -> Result<hyperion_types::crs::ModsecStatus, RpcError> {
        let mut st = self.adapters.modsec_status().await;
        st.active_sites = hyperion_state::hostings::count_crs_on(&self.pool)
            .await
            .unwrap_or(0)
            .max(0) as u32;
        Ok(st)
    }

    /// Load the Core Rule Set at http level while some active site on this
    /// node uses it, unload it otherwise — it costs memory in every nginx
    /// process. Idempotent; reloads nginx only when something changed.
    pub async fn crs_sync(&self) -> Result<bool, RpcError> {
        let st = self.adapters.modsec_status().await;
        let users = hyperion_state::hostings::count_crs_on(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("count CRS sites: {e}")))?;
        self.adapters
            .modsec_sync_http(st.available() && users > 0)
            .await
            .map_err(|e| RpcError::Internal_with(format!("ModSecurity: {e}")))
    }

    /// Install ModSecurity + the Core Rule Set on this node. Slow (apt):
    /// the web side runs it as a background job.
    pub async fn modsec_install(&self) -> Result<hyperion_types::crs::ModsecStatus, RpcError> {
        if let Some(rw_err) = check_usr_writable().await {
            return Err(RpcError::Conflict { message: rw_err });
        }
        let res = self.adapters.modsec_install().await;
        self.append_audit(
            "modsec.install",
            None,
            "{}",
            if res.is_ok() { "ok" } else { "error" },
        )
        .await;
        res.map_err(|e| RpcError::Internal_with(e.to_string()))?;
        self.crs_sync().await?;
        self.modsec_status().await
    }

    /// Read the node's ModSecurity audit log from where the last pass
    /// stopped and record each CRS decision against the site it belongs to.
    ///
    /// One log for the whole node (ModSecurity ignores per-site audit logs);
    /// every entry carries the site's id in its transaction id, which the
    /// site's own server block sets — a request cannot choose it. Entries
    /// for ids this node does not host are dropped. CRS decisions never
    /// earn a firewall ban: their tags are not ban-counted.
    pub(super) async fn crs_ingest(&self, audit: &std::path::Path, now: i64) {
        if !tokio::fs::try_exists(audit).await.unwrap_or(false) {
            return;
        }
        let pos = hyperion_state::node_kv::get(&self.pool, MODSEC_AUDIT_POS_KEY)
            .await
            .ok()
            .flatten()
            .and_then(|v| hyperion_adapters::waflog::LogPos::decode(&v));
        let path = audit.to_path_buf();
        let read = tokio::task::spawn_blocking(move || {
            let mut by_site: std::collections::HashMap<String, hyperion_types::waf::WafBatch> =
                std::collections::HashMap::new();
            let r = hyperion_adapters::waflog::read_new_lines(
                &path,
                pos,
                hyperion_adapters::waflog::MAX_READ_BYTES,
                &mut |line| {
                    if let Some((site, hit)) = hyperion_adapters::modsec::parse_audit_line(line) {
                        if by_site.len() < 10_000 || by_site.contains_key(&site) {
                            by_site.entry(site).or_default().push(hit);
                        }
                    }
                },
            );
            r.map(|(p, skipped)| (by_site, p, skipped))
        })
        .await;
        let (by_site, new_pos, skipped) = match read {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "crs: could not read the ModSecurity audit log");
                return;
            }
            Err(_) => return,
        };
        if skipped > 0 {
            tracing::warn!(
                skipped_bytes = skipped,
                "crs: audit log backlog over the per-tick budget; oldest entries skipped"
            );
        }
        let known: std::collections::HashSet<String> = match self.list().await {
            Ok(v) => v.into_iter().map(|s| s.id.as_str().to_string()).collect(),
            Err(_) => return,
        };
        for (site, batch) in &by_site {
            if !known.contains(site) {
                continue;
            }
            if let Err(e) = hyperion_state::waf::record(&self.pool, site, batch).await {
                // Do not advance past entries that were not stored.
                tracing::warn!(error = %e, "crs: could not record audit entries");
                return;
            }
        }
        if Some(new_pos) != pos {
            let _ = hyperion_state::node_kv::set(
                &self.pool,
                MODSEC_AUDIT_POS_KEY,
                &new_pos.encode(),
                now,
            )
            .await;
        }
    }

    /// Addresses no automatic ban may hit, whatever a log says: this
    /// machine's own — a site calling itself on its public address (WP-cron,
    /// Site Health) arrives FROM it, and a tenant's PHP can make that
    /// address look like an attacker in any site's log — and the other
    /// cluster members, whose loss cuts master↔node RPC. Operators can still
    /// ban any of them by hand.
    pub(super) async fn ban_protected_ips(&self) -> std::collections::HashSet<std::net::IpAddr> {
        let mut set: std::collections::HashSet<std::net::IpAddr> =
            hyperion_adapters::logscan::local_interface_ips()
                .await
                .into_iter()
                .collect();
        if let Ok(nodes) = hyperion_state::nodes::list(&self.pool).await {
            for n in nodes {
                for addr in [n.public_ip.as_deref(), n.external_ip.as_deref()] {
                    if let Some(ip) = addr.and_then(|s| s.trim().parse().ok()) {
                        set.insert(ip);
                    }
                }
                if let Some(url) = n.master_url.as_deref() {
                    set.extend(resolve_url_host(url).await);
                }
            }
        }
        if let Some(url) = read_master_url(self.agent_config_path.as_deref()) {
            set.extend(resolve_url_host(&url).await);
        }
        set
    }

    /// Whether WAF refusals on this site may earn an automatic ban. Default
    /// ON (absent ⇒ on) and a read error answers "on" too, matching the
    /// brute-force switch: a DB hiccup must not quietly stop protection.
    pub(super) async fn waf_autoban_enabled(&self, hosting_id: &str) -> bool {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, WAF_AUTOBAN_KV_KEY).await {
            Ok(Some(v)) => v.trim() != "off",
            _ => true,
        }
    }

    /// Read every hosting's WAF hit log from where the last pass stopped,
    /// record the refusals, and return the callers over the WAF threshold.
    ///
    /// The log lives in `dir` (root-owned `/var/log/hyperion-waf` in
    /// production): unlike the tenant's own access log, nothing the site
    /// can write ends up in it, so a ban decided from it cannot be forged
    /// by a tenant. Ban intents are returned only for sites whose auto-ban
    /// switch is on; the caller still checks `[fail2ban] enabled`.
    pub(super) async fn waf_ingest(
        &self,
        dir: &std::path::Path,
        since: i64,
        now: i64,
    ) -> Vec<BanIntent> {
        let mut intents = Vec::new();
        let Ok(summaries) = self.list().await else {
            return intents;
        };
        for s in &summaries {
            let id = s.id.as_str();
            let path = dir.join(format!("{id}.log"));
            if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
                continue;
            }
            let pos = hyperion_state::hosting_kv::get(&self.pool, id, WAF_LOG_POS_KV_KEY)
                .await
                .ok()
                .flatten()
                .and_then(|v| hyperion_adapters::waflog::LogPos::decode(&v));
            let read = {
                let path = path.clone();
                tokio::task::spawn_blocking(move || hyperion_adapters::waflog::read_new(&path, pos))
                    .await
            };
            let (batch, new_pos) = match read {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, domain = %s.domain, "waf: could not read the hit log");
                    continue;
                }
                Err(_) => continue,
            };
            if batch.skipped_bytes > 0 {
                // Kept up with a flood by skipping its oldest lines: the
                // totals undercount, the bans (decided on recent hits) don't.
                tracing::warn!(
                    domain = %s.domain,
                    skipped_bytes = batch.skipped_bytes,
                    "waf: hit log backlog over the per-tick budget; oldest lines skipped"
                );
            }
            if let Err(e) = hyperion_state::waf::record(&self.pool, id, &batch).await {
                // Do not advance past hits that were not stored.
                tracing::warn!(error = %e, domain = %s.domain, "waf: could not record hits");
                continue;
            }
            if Some(new_pos) != pos {
                let _ = hyperion_state::hosting_kv::set(
                    &self.pool,
                    id,
                    WAF_LOG_POS_KV_KEY,
                    &new_pos.encode(),
                    now,
                )
                .await;
            }
            if !self.waf_autoban_enabled(id).await {
                continue;
            }
            let offenders = hyperion_state::waf::ip_offenders(
                &self.pool,
                id,
                since,
                self.fail2ban.waf_threshold,
            )
            .await
            .unwrap_or_default();
            for ip in offenders {
                intents.push(BanIntent {
                    ip,
                    site: Some(BanSite {
                        id: id.to_string(),
                        domain: s.domain.clone(),
                    }),
                    reason: "auto: WAF refusals",
                });
            }
        }
        let _ = hyperion_state::waf::prune(&self.pool, now, self.fail2ban.window_secs).await;
        intents
    }

    /// What the WAF refused on one hosting, for the Protection card's
    /// activity panel. Node-local: answered by the hosting's owning node.
    pub async fn waf_activity(
        &self,
        hosting_id: &str,
    ) -> Result<hyperion_types::waf::WafActivity, RpcError> {
        let now = now_secs();
        let map = |e: hyperion_state::db::StateError| RpcError::Internal_with(format!("waf: {e}"));
        Ok(hyperion_types::waf::WafActivity {
            totals_24h: hyperion_state::waf::totals(&self.pool, hosting_id, now - 86_400)
                .await
                .map_err(map)?,
            totals_7d: hyperion_state::waf::totals(&self.pool, hosting_id, now - 7 * 86_400)
                .await
                .map_err(map)?,
            recent: hyperion_state::waf::recent(&self.pool, hosting_id, WAF_RECENT_SHOWN)
                .await
                .map_err(map)?,
            autoban_enabled: self.waf_autoban_enabled(hosting_id).await,
            fail2ban_enabled: self.fail2ban.enabled,
            threshold: self.fail2ban.waf_threshold,
            window_secs: self.fail2ban.window_secs,
        })
    }

    /// What the cluster Protection page needs from this node: every site's
    /// WAF setup and refusal totals, the hourly refusals over `days`, what
    /// the kept recent refusals look like per rule and per address, and the
    /// ban history over `days`.
    pub async fn waf_overview(
        &self,
        days: u32,
    ) -> Result<hyperion_types::waf::WafOverview, RpcError> {
        use hyperion_types::waf::{WafSiteFacts, RULES};
        let days = days.clamp(1, 30) as i64;
        let now = now_secs();
        let map = |e: hyperion_state::db::StateError| RpcError::Internal_with(format!("waf: {e}"));
        // The same sweep `ban_list` runs, so an active ban on the page is
        // really still in force.
        if let Ok(expired) = hyperion_state::bans::reap_expired(&self.pool, now).await {
            for ip in &expired {
                nft_unban(ip).await;
            }
        }
        let t24 = hyperion_state::waf::totals_by_site(&self.pool, now - 86_400)
            .await
            .map_err(map)?;
        let t7 = hyperion_state::waf::totals_by_site(&self.pool, now - 7 * 86_400)
            .await
            .map_err(map)?;
        let totals_for = |rows: &[(String, hyperion_types::waf::WafRuleCount)], id: &str| {
            rows.iter()
                .filter(|(h, _)| h == id)
                .map(|(_, c)| c.clone())
                .collect::<Vec<_>>()
        };
        let mut sites = Vec::new();
        for s in self.list().await? {
            if s.state == HostingState::Trashed {
                continue;
            }
            let Ok(Some(row)) = hyperion_state::hostings::get_by_id(&self.pool, &s.id).await else {
                continue;
            };
            let opts = &row.vhost_options;
            let level = opts.effective_waf_level();
            let pins = hyperion_types::waf::parse_overrides(&opts.waf_overrides);
            // A site without PHP never renders the PHP-only rules.
            let has_php = s.kind.as_deref().map_or(true, |k| k == "php");
            let rules = hyperion_types::waf::effective_rules(level, &pins, has_php);
            let id = s.id.as_str();
            let active_rules: Vec<String> = RULES
                .iter()
                .filter(|r| rules.get(r.id))
                .map(|r| r.id.to_string())
                .collect();
            sites.push(WafSiteFacts {
                hosting_id: id.to_string(),
                domain: s.domain.clone(),
                level: level.as_str().to_string(),
                rules_on: active_rules.len() as u32,
                active_rules,
                pins: pins.len() as u32,
                autoban: self.waf_autoban_enabled(id).await,
                totals_24h: totals_for(&t24, id),
                totals_7d: totals_for(&t7, id),
            });
        }
        let since = now - days * 86_400;
        Ok(hyperion_types::waf::WafOverview {
            fail2ban_enabled: self.fail2ban.enabled,
            threshold: self.fail2ban.waf_threshold,
            window_secs: self.fail2ban.window_secs,
            ban_ttl_secs: self.fail2ban.ban_ttl_secs,
            sites,
            hourly: hyperion_state::waf::hourly_all(&self.pool, since)
                .await
                .map_err(map)?,
            samples: hyperion_state::waf::rule_samples(&self.pool)
                .await
                .map_err(map)?,
            top_ips: hyperion_state::waf::top_ips(&self.pool, WAF_OVERVIEW_TOP_IPS)
                .await
                .map_err(map)?,
            bans: hyperion_state::bans::list_since(&self.pool, since, WAF_OVERVIEW_BANS)
                .await
                .map_err(|e| RpcError::Internal_with(format!("ban history: {e}")))?
                .into_iter()
                .map(ban_to_wire)
                .collect(),
        })
    }

    /// Everything one tick would ban, in scan order: each active hosting's
    /// own access log first (gated by that site's switch), then the
    /// node-wide ssh / ftp / mail journals.
    ///
    /// Split out of `fail2ban_tick` so the per-hosting opt-out is testable —
    /// applying an intent goes through `ban_add`, which shells out to `nft`
    /// before it writes a row and so cannot run under test.
    pub(super) async fn fail2ban_scan(&self, since: i64) -> Result<Vec<BanIntent>, RpcError> {
        let cfg = &self.fail2ban;
        let mut intents: Vec<BanIntent> = Vec::new();

        // Per-hosting HTTP brute force (wp-login / xmlrpc POST floods).
        let summaries = self.list().await?;
        for s in &summaries {
            if s.state != HostingState::Active {
                continue;
            }
            // Opted out ⇒ this site's access log is not read at all, so the
            // switch costs nothing rather than merely discarding findings.
            if !self.http_bruteforce_scan_enabled(s.id.as_str()).await {
                // Protection stops here, so the coverage stamp stops being
                // true. Dropping it now means re-enabling later starts a
                // fresh, honest "watched since", instead of a stale one
                // that would let the care report claim the gap was covered.
                let _ = hyperion_state::hosting_kv::delete(
                    &self.pool,
                    s.id.as_str(),
                    FAIL2BAN_HTTP_SINCE_KV_KEY,
                )
                .await;
                continue;
            }
            let Some(user) = derive_user_from_summary(s) else {
                continue;
            };
            let access = std::path::PathBuf::from(&self.paths.home_root)
                .join(&user)
                .join(&s.domain)
                .join("logs")
                .join("access.log");
            // Stamp only AFTER the log has actually been opened. `user` is a
            // GUESS derived from the domain and it succeeds for almost any
            // domain, so an imported or renamed site sails past the check
            // above and points at a path that does not exist. Stamping
            // before the read would mark such a site "watched since" forever
            // while its log was never read once — and its letter would say
            // "0 attacks, protection ran for the whole period" beside a
            // traffic section that correctly says "not measured", because
            // `stats_tick` skips the very same site for the very same wrong
            // path. One letter, two sections, opposite claims.
            if !tokio::fs::try_exists(&access).await.unwrap_or(false) {
                continue;
            }
            self.note_bruteforce_coverage(s.id.as_str(), since).await;
            // A sign-up flood, counted on the SAME read as the brute force.
            //
            // The scan below counts repeated requests from one address and
            // bans it. A registration flood is the opposite shape — many
            // addresses, one or two requests each, every one of them
            // SUCCEEDING — so there is no repetition to count and no failure
            // to count it on, and no ban that would help. It gets noticed
            // here instead, and said out loud, because otherwise the first an
            // operator hears of it is a mail queue full of "you have a new
            // account".
            self.warn_on_signup_flood(s, &access, since).await;
            for ip in scan_access_log_for_bruteforce(&access, since, cfg.http_threshold).await {
                intents.push(BanIntent {
                    ip,
                    site: Some(BanSite {
                        id: s.id.as_str().to_string(),
                        domain: s.domain.clone(),
                    }),
                    reason: "auto: wp-login / xmlrpc brute force",
                });
            }
        }

        // Node-wide sources: ssh, ftp, mail auth-failure floods. Not tied to
        // one site, so banned with hosting_id = None — and, for the same
        // reason, never gated by a site's switch.
        let mut node_hits: Vec<(String, &'static str)> = Vec::new();
        for ip in scan_sshd_journal_for_bruteforce(cfg.window_secs, cfg.ssh_threshold).await {
            node_hits.push((ip, "auto: ssh brute force"));
        }
        for ip in scan_ftp_journal_for_bruteforce(cfg.window_secs, cfg.ftp_threshold).await {
            node_hits.push((ip, "auto: ftp brute force"));
        }
        for ip in scan_mail_journal_for_bruteforce(cfg.window_secs, cfg.mail_threshold).await {
            node_hits.push((ip, "auto: mail (smtp/imap) brute force"));
        }
        intents.extend(node_hits.into_iter().map(|(ip, reason)| BanIntent {
            ip,
            site: None,
            reason,
        }));
        Ok(intents)
    }

    /// One tick of the brute-force scanner: sweep expired bans, then scan
    /// every source (per-hosting HTTP access logs + node-wide ssh/ftp/mail
    /// journals) for auth-failure floods and auto-ban offenders. Thresholds,
    /// windows and ban durations come from `[fail2ban]`. Returns the number
    /// of new bans applied.
    pub async fn fail2ban_tick(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        // Always sweep expired bans, even when scanning is disabled, so a
        // lapsed ban is dropped from nftables promptly.
        if let Ok(expired) = hyperion_state::bans::reap_expired(&self.pool, now).await {
            for ip in &expired {
                nft_unban(ip).await;
            }
        }
        let since = now - self.fail2ban.window_secs;
        // The WAF hit logs are read whether or not banning is on: the
        // activity panel is visibility, and a log left unread would only
        // be read later in one oversized gulp.
        let waf_intents = self
            .waf_ingest(
                std::path::Path::new(hyperion_adapters::nginx::WAF_LOG_DIR),
                since,
                now,
            )
            .await;
        self.crs_ingest(
            std::path::Path::new(hyperion_adapters::modsec::AUDIT_LOG),
            now,
        )
        .await;
        if !self.fail2ban.enabled {
            return Ok(0);
        }
        let scan_intents = self.fail2ban_scan(since).await?;
        // Looked up only when something is about to be banned.
        let protected = if waf_intents.is_empty() && scan_intents.is_empty() {
            std::collections::HashSet::new()
        } else {
            self.ban_protected_ips().await
        };
        let is_protected = |ip: &str| {
            ip.parse::<std::net::IpAddr>()
                .map(|a| protected.contains(&a))
                .unwrap_or(false)
        };
        let mut new_bans = 0i64;
        for intent in waf_intents {
            let Some(site) = intent.site.as_ref() else {
                continue;
            };
            let banned = if is_protected(&intent.ip) {
                tracing::warn!(
                    ip = %intent.ip, domain = %site.domain,
                    "fail2ban: WAF refusals from this node's own or a cluster member's address — not banning"
                );
                false
            } else {
                self.auto_ban(&intent.ip, Some(&site.id), intent.reason, now)
                    .await
            };
            // Spent either way. Banned now, or refused because the address
            // is already banned (or never bannable): left in place, the same
            // hits would ban it again the moment an earlier, shorter ban
            // lapsed — a second sentence for one offence, escalated as a
            // "repeat offender".
            let _ = hyperion_state::waf::clear_ip(&self.pool, &site.id, &intent.ip).await;
            if !banned {
                continue;
            }
            new_bans += 1;
            tracing::info!(ip = %intent.ip, domain = %site.domain, "fail2ban: auto-banned (waf)");
        }
        for intent in scan_intents {
            let hosting_id = intent.site.as_ref().map(|s| s.id.as_str());
            if is_protected(&intent.ip) {
                tracing::warn!(
                    ip = %intent.ip, reason = intent.reason,
                    "fail2ban: flood from this node's own or a cluster member's address — not banning"
                );
                continue;
            }
            if !self
                .auto_ban(&intent.ip, hosting_id, intent.reason, now)
                .await
            {
                continue;
            }
            new_bans += 1;
            match &intent.site {
                Some(site) => {
                    tracing::info!(ip = %intent.ip, domain = %site.domain, "fail2ban: auto-banned (http)")
                }
                None => {
                    tracing::info!(ip = %intent.ip, reason = intent.reason, "fail2ban: auto-banned (node)")
                }
            }
        }
        Ok(new_bans)
    }
}

/// nftables binary + our reused `inet hyperion` table (shared with the
/// firewall feature). The ban set auto-expires entries via its `timeout`
/// flag, so a missed sweep still can't keep an IP banned forever.
pub(super) const NFT: &str = "/usr/sbin/nft";

/// Ensure the `banned` set + the drop rule exist in the `inet hyperion`
/// input chain. Idempotent — table/chain/set creation errors ("File
/// exists") are benign and ignored; the drop rule is only inserted when
/// absent.
pub(super) async fn nft_ensure_ban_infra() -> Result<(), RpcError> {
    // Never `add chain … policy accept` here: every new ban would switch a
    // confirmed default-drop back off. See nft_ensure_hyperion_chain.
    let _ = nft_ensure_hyperion_chain().await;
    let _ = hyperion_adapters::cmd::run(
        NFT,
        &[
            "add",
            "set",
            "inet",
            "hyperion",
            "banned",
            "{",
            "type",
            "ipv4_addr",
            ";",
            "flags",
            "timeout",
            ";",
            "}",
        ],
    )
    .await;
    // Parallel IPv6 set — an IPv6 attacker must be bannable too.
    let _ = hyperion_adapters::cmd::run(
        NFT,
        &[
            "add",
            "set",
            "inet",
            "hyperion",
            "banned6",
            "{",
            "type",
            "ipv6_addr",
            ";",
            "flags",
            "timeout",
            ";",
            "}",
        ],
    )
    .await;
    let listing = hyperion_adapters::cmd::run(NFT, &["list", "chain", "inet", "hyperion", "input"])
        .await
        .unwrap_or_default();
    if !listing.contains("\"hyperion:ban-drop\"") {
        // `insert` prepends, so the drop precedes any accept rules.
        hyperion_adapters::cmd::run(
            NFT,
            &[
                "insert",
                "rule",
                "inet",
                "hyperion",
                "input",
                "ip",
                "saddr",
                "@banned",
                "drop",
                "comment",
                "\"hyperion:ban-drop\"",
            ],
        )
        .await
        .map_err(|e| RpcError::ProvisioningFailed {
            stage: "nft_ban_infra".into(),
            reason: e.to_string(),
        })?;
    }
    // NB: the v6 marker must NOT contain the v4 marker as a substring, or
    // `contains("\"hyperion:ban-drop\"")` would also match the v6 rule and skip
    // (re-)creating the v4 rule. "ban6-drop" keeps the two disjoint.
    if !listing.contains("hyperion:ban6-drop") {
        hyperion_adapters::cmd::run(
            NFT,
            &[
                "insert",
                "rule",
                "inet",
                "hyperion",
                "input",
                "ip6",
                "saddr",
                "@banned6",
                "drop",
                "comment",
                "hyperion:ban6-drop",
            ],
        )
        .await
        .map_err(|e| RpcError::ProvisioningFailed {
            stage: "nft_ban_infra".into(),
            reason: e.to_string(),
        })?;
    }
    Ok(())
}

/// nft set holding bans for `ip`'s family: `banned6` for IPv6, else the
/// IPv4 `banned` set. `ip` is always the normalized output of
/// `std::net::IpAddr::to_string()` (every caller parses + re-serializes
/// first), so a colon unambiguously means IPv6 — IPv4 never contains one
/// and there's no port suffix to confuse it.
pub(super) fn nft_ban_set(ip: &str) -> &'static str {
    if ip.contains(':') {
        "banned6"
    } else {
        "banned"
    }
}

/// Add an IP to the nft `banned` set with an optional timeout (0 = no
/// timeout / permanent).
pub(super) async fn nft_ban(ip: &str, ttl_secs: i64) -> Result<(), RpcError> {
    let set = nft_ban_set(ip);
    let ttl = format!("{ttl_secs}s");
    let argv: Vec<&str> = if ttl_secs > 0 {
        vec![
            "add", "element", "inet", "hyperion", set, "{", ip, "timeout", &ttl, "}",
        ]
    } else {
        vec!["add", "element", "inet", "hyperion", set, "{", ip, "}"]
    };
    hyperion_adapters::cmd::run(NFT, &argv)
        .await
        .map_err(|e| RpcError::ProvisioningFailed {
            stage: "nft_ban".into(),
            reason: e.to_string(),
        })?;
    Ok(())
}

/// Remove an IP from its nft ban set (v4 or v6). Best-effort — a missing
/// element (already expired by nft's own timeout) is not an error.
pub(super) async fn nft_unban(ip: &str) {
    let set = nft_ban_set(ip);
    let _ = hyperion_adapters::cmd::run(
        NFT,
        &["delete", "element", "inet", "hyperion", set, "{", ip, "}"],
    )
    .await;
}
pub(super) const FAIL2BAN_HTTP_KV_KEY: &str = "http_bruteforce_scan_enabled";
/// Per-hosting WAF auto-ban switch (`hosting_kv`). Absent ⇒ on; "off" opts
/// the site out. Hits are still recorded either way.
pub(super) const WAF_AUTOBAN_KV_KEY: &str = "waf_autoban_enabled";
/// Where the WAF ingest stopped in the site's hit log (`hosting_kv`),
/// `"<inode>:<offset>"`.
pub(super) const WAF_LOG_POS_KV_KEY: &str = "waf_log_pos";
/// Refusals listed in the activity panel.
pub(super) const WAF_RECENT_SHOWN: i64 = 50;
/// Where the CRS ingest stopped in the node's ModSecurity audit log
/// (`node_kv`), `"<inode>:<offset>"`.
pub(super) const MODSEC_AUDIT_POS_KEY: &str = "modsec_audit_pos";
/// Addresses one node reports to the Protection page.
pub(super) const WAF_OVERVIEW_TOP_IPS: i64 = 25;
/// Bans one node reports to the Protection page's history.
pub(super) const WAF_OVERVIEW_BANS: i64 = 500;

pub(super) fn ban_to_wire(b: hyperion_state::bans::IpBan) -> hyperion_types::IpBanWire {
    hyperion_types::IpBanWire {
        id: b.id,
        ip: b.ip,
        hosting_id: b.hosting_id,
        reason: b.reason,
        source: b.source,
        banned_at: b.banned_at,
        expires_at: b.expires_at,
        active: b.active,
        ended_at: b.ended_at,
        end_reason: b.end_reason,
    }
}

/// Remove one hosting's WAF hit log and its rotated copies (`<id>.log`,
/// `<id>.log.1`, `<id>.log.2.gz`, …) from `dir`. Best-effort.
pub(super) async fn remove_waf_logs(dir: &std::path::Path, hosting_id: &str) {
    let stem = format!("{hosting_id}.log");
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let ours = name == stem
            || name
                .strip_prefix(stem.as_str())
                .is_some_and(|rest| rest.starts_with('.'));
        if ours {
            let _ = tokio::fs::remove_file(entry.path()).await;
        }
    }
}

/// Epoch seconds of the first scan of the current protected stretch —
/// written by the scanner, cleared the moment a site is opted out. The
/// care report reads it to bound "attacks blocked" to the days it can
/// actually evidence, instead of inferring coverage from a toggle that
/// only ever describes the present.
pub(super) const FAIL2BAN_HTTP_SINCE_KV_KEY: &str = "http_bruteforce_scan_since";

/// How long a silence breaks a stretch of proven coverage. The scanner
/// runs every scheduler tick (minutes), so an hour without one means it
/// was not running — the node was down, the agent was restarting, or
/// `[fail2ban] enabled` was off. Generous on purpose: the cost of being
/// too strict is a letter that under-claims, which is the safe direction.
pub(super) const FAIL2BAN_COVERAGE_GAP_SECS: i64 = 3600;

/// Whether a site sold brute-force protection lacks recent proof that the
/// scanner looked at it. The scanner stamps every tick; twice the coverage
/// gap without a stamp means it is not running for this site. A plan that
/// started less than that ago gets the scanner's first passes first.
pub(super) fn bruteforce_evidence_missing(
    last_scan: Option<i64>,
    plan_start: i64,
    now: i64,
) -> bool {
    let grace = 2 * FAIL2BAN_COVERAGE_GAP_SECS;
    if now.saturating_sub(plan_start) < grace {
        return false;
    }
    match last_scan {
        Some(last) => now.saturating_sub(last) > grace,
        None => true,
    }
}

/// The window an "attacks blocked" figure may be counted over, given when
/// protection demonstrably started (`since`) and the report period
/// `[from, to)`. `None` means nothing in this period was watched.
///
/// Exists so the COUNT and the sentence describing it cannot come from
/// different windows. They did: the count ran over the whole period while
/// the letter said "watching since the 25th, so this figure covers only
/// that part of it", putting a 21-day total inside a 5-day claim. Ban rows
/// outlive an opt-out and can be attributed by hand at any time, so the
/// two windows genuinely diverge rather than merely being able to.
pub(super) fn attacks_window(since: i64, from: i64, to: i64) -> Option<i64> {
    let effective = since.max(from);
    // `>= to` ⇒ protection began only after the period ended: a zero here
    // would sit beside a start date in the future. That is the shape of
    // the first report after an upgrade, when no site has a stamp yet.
    (effective < to).then_some(effective)
}

/// Parse a `"<since>,<last_scan>"` coverage stamp.
///
/// Also accepts the bare `"<since>"` written by the first version of this
/// key, treating it as its own last scan — an upgrade then sees one stale
/// stretch and restarts coverage, rather than parsing to nothing and
/// silently claiming "watching since now" on every tick.
pub(super) fn parse_coverage_stamp(raw: &str) -> Option<(i64, i64)> {
    let raw = raw.trim();
    match raw.split_once(',') {
        Some((since, last)) => Some((
            since.trim().parse::<i64>().ok()?,
            last.trim().parse::<i64>().ok()?,
        )),
        None => {
            let since = raw.parse::<i64>().ok()?;
            Some((since, since))
        }
    }
}

/// The site a ban is attributed to: its id for the `ip_bans` row (which is
/// what the care report counts), its domain for the operator-facing log line.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct BanSite {
    pub(super) id: String,
    pub(super) domain: String,
}

/// One ban `fail2ban_scan` decided on, before `auto_ban` gets a say about
/// whether the address may be banned at all.
///
/// `site: None` means node-wide (ssh / ftp / mail): those journals cover the
/// whole machine, so the hit belongs to no single vhost — which is also why
/// no single vhost's switch can suppress it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct BanIntent {
    pub(super) ip: String,
    pub(super) site: Option<BanSite>,
    pub(super) reason: &'static str,
}

/// Scan the recent sshd journal for auth-failure floods. Runs
/// `journalctl` over the ssh unit for the last `window_secs` and counts
/// failed-auth lines per source IPv4. Returns IPs at/over `threshold`.
/// Empty on any error (no journalctl / no systemd) — SSH banning is
/// then simply a no-op, never a hard failure of the tick.
pub(super) async fn scan_sshd_journal_for_bruteforce(
    window_secs: i64,
    threshold: u32,
) -> Vec<String> {
    let mins = (window_secs / 60).max(1);
    let since = format!("{mins} min ago");
    let out = match hyperion_adapters::cmd::run(
        "/usr/bin/journalctl",
        &[
            "-u",
            "ssh",
            "-u",
            "sshd",
            "--since",
            &since,
            "--no-pager",
            "-q",
            "-o",
            "cat",
        ],
    )
    .await
    {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    use std::collections::HashMap;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for line in out.lines() {
        let is_fail = line.contains("Failed password")
            || line.contains("Failed publickey")
            || line.contains("Invalid user")
            || line.contains("authentication failure")
            || line.contains("Connection closed by authenticating user");
        if !is_fail {
            continue;
        }
        // sshd writes "… from <ip> port …" for most lines and
        // "rhost=<ip>" for PAM "authentication failure" lines.
        let ip = if let Some(p) = line.find(" from ") {
            line[p + 6..].split_whitespace().next().unwrap_or("")
        } else if let Some(p) = line.find("rhost=") {
            line[p + 6..].split_whitespace().next().unwrap_or("")
        } else {
            ""
        };
        if ip.parse::<std::net::IpAddr>().is_ok() {
            *counts.entry(ip.to_string()).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .filter(|(_, c)| *c >= threshold)
        .map(|(ip, _)| ip)
        .collect()
}

/// Read the recent journal for a set of syslog identifiers, `-o cat` (message
/// only). Empty on any error (no journalctl / no systemd) so a scan is always
/// best-effort, never a hard failure of the tick.
pub(super) async fn journal_by_identifiers(identifiers: &[&str], window_secs: i64) -> String {
    let mins = (window_secs / 60).max(1);
    let since = format!("{mins} min ago");
    let mut argv: Vec<&str> = Vec::new();
    for id in identifiers {
        argv.push("-t");
        argv.push(id);
    }
    argv.extend_from_slice(&["--since", &since, "--no-pager", "-q", "-o", "cat"]);
    hyperion_adapters::cmd::run("/usr/bin/journalctl", &argv)
        .await
        .unwrap_or_default()
}

/// vsftpd failed logins from the journal (syslog identifier `vsftpd`; the
/// agent sets `syslog_enable=YES` so these reach journald). Returns source
/// IPs at/over `threshold` in the window.
pub(super) async fn scan_ftp_journal_for_bruteforce(
    window_secs: i64,
    threshold: u32,
) -> Vec<String> {
    let out = journal_by_identifiers(&["vsftpd"], window_secs).await;
    let counts = hyperion_adapters::logscan::parse_vsftpd_fail_logins(&out);
    hyperion_adapters::logscan::over_threshold(&counts, threshold)
}

/// SMTP + IMAP/POP SASL auth failures from the postfix and dovecot journals.
/// Returns source IPs at/over `threshold` in the window.
pub(super) async fn scan_mail_journal_for_bruteforce(
    window_secs: i64,
    threshold: u32,
) -> Vec<String> {
    // SASL AUTH lands on 25 (smtpd), 587 (submission) and 465 (smtps), each a
    // distinct journal identifier — include all so a 587-only brute is caught.
    let out = journal_by_identifiers(
        &[
            "postfix/smtpd",
            "postfix/submission/smtpd",
            "postfix/smtps/smtpd",
            "dovecot",
        ],
        window_secs,
    )
    .await;
    let counts = hyperion_adapters::logscan::parse_mail_fail_logins(&out);
    hyperion_adapters::logscan::over_threshold(&counts, threshold)
}

/// Scan an nginx access.log (combined format) for brute-force probes:
/// repeated POSTs to wp-login.php / xmlrpc.php from one IPv4 address
/// inside the `since` window. Returns IPs at/over `threshold`.
pub(super) async fn scan_access_log_for_bruteforce(
    path: &std::path::Path,
    since: i64,
    threshold: u32,
) -> Vec<String> {
    let Ok(body) = tokio::fs::read_to_string(path).await else {
        return Vec::new();
    };
    use chrono::{DateTime, FixedOffset};
    use std::collections::HashMap;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for line in body.lines() {
        let ip = line.split_whitespace().next().unwrap_or("");
        // IPv4 or IPv6 — both have their own nft ban set.
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let Some(start) = line.find('[') else {
            continue;
        };
        let Some(end_rel) = line[start..].find(']') else {
            continue;
        };
        let ts_str = &line[start + 1..start + end_rel];
        let Ok(dt) = DateTime::<FixedOffset>::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z") else {
            continue;
        };
        if dt.timestamp() < since {
            continue;
        }
        // The request line is the first quoted field: "METHOD path proto".
        let Some(q1) = line.find('"') else { continue };
        let Some(q2_rel) = line[q1 + 1..].find('"') else {
            continue;
        };
        let req = &line[q1 + 1..q1 + 1 + q2_rel];
        let is_probe = req.starts_with("POST ")
            && (req.contains("/wp-login.php") || req.contains("/xmlrpc.php"));
        if is_probe {
            *counts.entry(ip.to_string()).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .filter(|(_, c)| *c >= threshold)
        .map(|(ip, _)| ip)
        .collect()
}

/// Successful WordPress sign-ups in an access log, counted across ALL callers.
///
/// The one thing the brute-force sweep beside this cannot do. That one counts
/// repeated `POST /wp-login.php` from a SINGLE address and bans it past a
/// threshold, which is right for a brute force and blind to what actually
/// fills a mail queue: a botnet registering once or twice per address, every
/// request returning 200. There is no repetition to count and no failure to
/// count it on.
///
/// So this counts the ACT, not the actor. A site taking more sign-ups a minute
/// than any honest site takes is the signal, whoever is making them.
///
/// Returns `(registrations, distinct_ips)`. Both matter: fifty sign-ups from
/// two addresses is a broken script, fifty from forty-eight addresses is a
/// botnet, and the operator's next move differs.
pub(super) fn count_registrations(log: &str, since: i64) -> (u32, usize) {
    let mut total = 0u32;
    let mut ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in log.lines() {
        let Some((ip, ts, _)) = parse_access_line(line) else {
            continue;
        };
        if ts < since {
            continue;
        }
        let Some(q1) = line.find('"') else { continue };
        let Some(q2_rel) = line[q1 + 1..].find('"') else {
            continue;
        };
        let req = &line[q1 + 1..q1 + 1 + q2_rel];
        // Both shapes WordPress offers: the query-string form on wp-login.php
        // and the multisite sign-up page.
        let is_signup = req.starts_with("POST ")
            && (req.contains("action=register") || req.contains("/wp-signup.php"));
        if is_signup {
            total += 1;
            ips.insert(ip.to_string());
        }
    }
    (total, ips.len())
}

/// One nginx combined-format line → (client ip, unix ts, bytes sent).
///
/// Split rather than regex: this runs once per line over files that reach
/// hundreds of thousands of lines, and the format is positional. A line
/// that does not fit is skipped — an access log always contains something
/// odd, and one malformed entry must not cost the whole window.
pub(super) fn parse_access_line(line: &str) -> Option<(&str, i64, i64)> {
    let ip = line.split_whitespace().next()?;
    // [10/Oct/2026:13:55:36 +0200]
    let start = line.find('[')? + 1;
    let end = line[start..].find(']')? + start;
    let ts = chrono::DateTime::<chrono::FixedOffset>::parse_from_str(
        &line[start..end],
        "%d/%b/%Y:%H:%M:%S %z",
    )
    .ok()?
    .timestamp();
    // Status and bytes follow the quoted REQUEST — not the last quote on
    // the line, which closes the user-agent and has nothing after it.
    let after_ts = &line[end + 1..];
    let q1 = after_ts.find('"')?;
    let q2 = after_ts[q1 + 1..].find('"')? + q1 + 1;
    // "<status> <bytes>" — nginx writes "-" for a response with no body,
    // which is zero bytes, not a reason to drop the request from the count.
    let bytes = after_ts[q2 + 1..]
        .split_whitespace()
        .nth(1)
        .and_then(|b| b.parse::<i64>().ok())
        .unwrap_or(0);
    Some((ip, ts, bytes))
}

pub(super) async fn parse_access_log_window(
    path: &std::path::Path,
    since: i64,
    until: Option<i64>,
) -> (i64, i64, i64, i64) {
    // The freshly rotated sibling is read too, and the time window does the
    // rest of the work: logrotate can fire in the MIDDLE of an hour, and
    // the part of that hour written before the rotation is then only in
    // `access.log.1`. Without this the hour is re-measured from an almost
    // empty file and the earlier traffic is lost. Entries outside `[since,
    // until)` are skipped anyway, so reading the older file costs nothing
    // but the read. A compressed or date-suffixed rotation is not covered —
    // `upsert_usage`'s caller never lowers an existing bucket, which is the
    // backstop for those.
    let mut body = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let rotated = path.with_extension(match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.1"),
        None => "1".to_string(),
    });
    if let Ok(older) = tokio::fs::read_to_string(&rotated).await {
        body.push('\n');
        body.push_str(&older);
    }
    if body.trim().is_empty() {
        return (0, 0, 0, 0);
    }
    use chrono::{DateTime, FixedOffset};
    let mut bw_in: i64 = 0;
    let mut bw_out: i64 = 0;
    let mut reqs: i64 = 0;
    let mut last_ts: i64 = 0;
    for line in body.lines() {
        // Extract bracketed timestamp.
        let Some(start) = line.find('[') else {
            continue;
        };
        let Some(end) = line[start..].find(']') else {
            continue;
        };
        let ts_str = &line[start + 1..start + end];
        let Ok(dt) = DateTime::<FixedOffset>::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z") else {
            continue;
        };
        let ts = dt.timestamp();
        if ts < since {
            continue;
        }
        // Half-open on purpose: `until` is the next bucket's `since`, so a
        // request landing exactly on an hour boundary is counted once, by
        // the later bucket, never by both.
        if until.is_some_and(|u| ts >= u) {
            continue;
        }
        reqs += 1;
        last_ts = last_ts.max(ts);
        // body_bytes_sent is the field right after status code.
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() > 10 {
            if let Ok(n) = parts[9].parse::<i64>() {
                bw_out += n;
            }
        }
        // If log_format extended with $request_length, it's usually parts[10..].
        if parts.len() > 11 {
            if let Ok(n) = parts[10].parse::<i64>() {
                bw_in += n;
            }
        }
    }
    (bw_in, bw_out, reqs, last_ts)
}
