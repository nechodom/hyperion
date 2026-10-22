//! nftables: templates, the default-drop policy with its rollback deadline,
//! boot re-apply.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Where the pending default-drop rollback deadline lives.
    ///
    /// A FILE, not memory: if the agent is restarted or crashes while the
    /// firewall is dropping and nobody has confirmed access yet, an in-memory
    /// timer dies with it and the box stays locked. On boot the agent reads
    /// this and reverts a deadline that has passed.
    pub(super) fn firewall_arm_file(&self) -> std::path::PathBuf {
        self.firewall_state_dir()
            .join("firewall-default-drop-armed.json")
    }

    /// What this node's firewall is meant to look like: which presets are
    /// applied, whether default-drop is on and confirmed, and which ports the
    /// panel itself needs kept open. Re-applied by the agent at startup.
    ///
    /// nft rules live in kernel memory and vanish on reboot. This used to be
    /// answered by overwriting `/etc/nftables.conf` with the whole live
    /// ruleset — the operator's own file, plus Docker's chains and the ban
    /// sets — which only ever came back if `nftables.service` was enabled
    /// (it is not, by default, on Debian). So presets silently disappeared on
    /// reboot, and default-drop was never persisted at all.
    pub(super) fn firewall_state_file(&self) -> std::path::PathBuf {
        self.firewall_state_dir().join("firewall-state.json")
    }

    pub(super) fn firewall_state_dir(&self) -> std::path::PathBuf {
        // Beside the state DB — root-owned, 0700, and node-local, which is
        // what this is: one node's firewall, not cluster state.
        std::path::Path::new(&self.paths.acme_challenge_root)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/var/lib/hyperion"))
            .to_path_buf()
    }

    /// The recorded firewall state, or — on a node that predates the state
    /// file — one read off the live ruleset, so the first save after an
    /// upgrade does not forget presets that are already applied.
    pub(super) async fn firewall_state_current(&self) -> FirewallState {
        if let Ok(body) = tokio::fs::read_to_string(self.firewall_state_file()).await {
            if let Ok(st) = serde_json::from_str::<FirewallState>(&body) {
                return st;
            }
        }
        let listing = nft_chain_listing(false).await;
        let armed = tokio::fs::metadata(self.firewall_arm_file()).await.is_ok();
        FirewallState::from_live(&listing, armed)
    }

    pub(super) async fn firewall_state_save(&self, st: &FirewallState) {
        let body = serde_json::to_string_pretty(st).unwrap_or_default();
        if let Err(e) = tokio::fs::write(self.firewall_state_file(), body).await {
            tracing::warn!(error=%e, "firewall: could not record the firewall state");
        }
    }

    /// The port sshd actually listens on, read from its config.
    ///
    /// Not assumed to be 22. Switching the chain to `policy drop` with a rule
    /// for 22 on a box whose sshd is on 2222 locks the operator out of a
    /// remote VPS, and the panel would report success while doing it.
    /// Multiple `Port` lines are all honoured — sshd accepts several.
    pub(super) async fn sshd_ports() -> Vec<u16> {
        let body = tokio::fs::read_to_string("/etc/ssh/sshd_config")
            .await
            .unwrap_or_default();
        sshd_ports_from(&body)
    }

    /// Public TCP ports hyperion's own daemons listen on — the panel
    /// (hyperion-web, 8443 by default) and the master→node RPC listener
    /// (hyperion-agent, 9443).
    ///
    /// Read from the live sockets rather than assumed. Default-drop used to
    /// keep only SSH and web open, so on a worker it cut the master's RPC —
    /// and with it the very "confirm" call that would have kept it on — and on
    /// the master it dropped the panel the operator was clicking in. Either way
    /// it reverted itself five minutes later, every time.
    pub(super) async fn hyperion_listen_ports() -> Vec<u16> {
        match tokio::process::Command::new("/usr/bin/ss")
            .args(["-Hltnp"])
            .output()
            .await
        {
            Ok(o) if o.status.success() => {
                hyperion_listen_ports_from_ss(&String::from_utf8_lossy(&o.stdout))
            }
            _ => Vec::new(),
        }
    }

    /// Run one `nft` invocation, returning its combined output.
    pub(super) async fn nft(args: &[&str]) -> Result<String, String> {
        let out = tokio::process::Command::new(NFT)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("spawn nft: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.success() {
            return Ok(stdout);
        }
        Err(format!(
            "`nft {}`: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }

    /// Add `argv` (a full `add rule …` command whose last arg is the
    /// `"hyperion:<tag>"` comment) unless a rule with that tag is already in
    /// the chain. Returns whether it added one.
    ///
    /// `add rule` is not idempotent — nft happily appends the same rule again
    /// — so re-applying a preset or re-enabling default-drop used to stack
    /// duplicate rules every time.
    pub(super) async fn nft_ensure_rule(argv: &[String]) -> Result<bool, String> {
        let listing = nft_chain_listing(false).await;
        if let Some(tag) = nft_rule_tag(argv) {
            if nft_has_tag(&listing, &tag) {
                return Ok(false);
            }
        }
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        Self::nft(&args).await.map(|_| true)
    }

    /// Put in everything default-drop must never cut off, and check it is
    /// really there. Does NOT flip the policy — the caller does, only after
    /// this returns Ok.
    ///
    /// Returns a human list of what is now allowed.
    pub(super) async fn default_drop_install(
        &self,
        remembered_keep: &[u16],
    ) -> Result<Vec<String>, RpcError> {
        let internal = |e: String| RpcError::Internal { message: e };
        nft_ensure_hyperion_chain().await.map_err(internal)?;

        let ssh = Self::sshd_ports().await;
        // Remembered ports matter at boot: the agent starts before
        // hyperion-web is listening, so a live read alone would miss the panel.
        let mut keep: Vec<u16> = ssh.clone();
        keep.extend(Self::hyperion_listen_ports().await);
        keep.extend_from_slice(remembered_keep);
        keep.sort_unstable();
        keep.dedup();

        // 1. Survival rules, while the chain is still permissive.
        let mut rules = default_drop_survival_rules(&keep);
        // 2b. What a hosting node serves. Web is unconditional — this is a
        // hosting panel. FTP is added only when vsftpd is configured, and then
        // BOTH halves: the control port alone gives a connection that hangs on
        // the first directory listing.
        let mut opened = vec![
            format!(
                "TCP {} (SSH and the panel)",
                keep.iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "80, 443 (web)".to_string(),
        ];
        rules.push(rule(
            &["tcp", "dport", "{", "80,", "443", "}", "accept"],
            "keep-web",
        ));
        rules.push(rule(&["udp", "dport", "443", "accept"], "keep-web-quic"));
        if hyperion_adapters::ftp::vsftpd_configured().await {
            let ftp_port = hyperion_adapters::ftp::read_listen_port().await.to_string();
            rules.push(rule(&["tcp", "dport", &ftp_port, "accept"], "keep-ftp"));
            opened.push(format!("{ftp_port} (FTP control)"));
            if let Some((lo, hi)) = hyperion_adapters::ftp::passive_range().await {
                let range = format!("{lo}-{hi}");
                rules.push(rule(
                    &["tcp", "dport", &range, "accept"],
                    "keep-ftp-passive",
                ));
                opened.push(format!("{range} (FTP passive)"));
            }
        }
        for r in &rules {
            Self::nft_ensure_rule(r).await.map_err(internal)?;
        }

        // 2. Read back. Trusting the exit codes above is not enough: a rule
        // can be accepted and still not be what we meant.
        let listed = nft_chain_listing(false).await;
        let missing: Vec<String> = default_drop_required_tags(&keep)
            .into_iter()
            .filter(|t| !nft_has_tag(&listed, t))
            .collect();
        if !missing.is_empty() {
            return Err(RpcError::Validation {
                message: format!(
                    "refusing to switch the firewall to default-drop: the rules that keep \
                     you connected are not in the ruleset (missing: {}). The policy has \
                     not been changed.",
                    missing.join(", ")
                ),
            });
        }
        let mut st = self.firewall_state_current().await;
        st.keep_tcp = keep;
        self.firewall_state_save(&st).await;
        Ok(opened)
    }

    pub(super) async fn nft_set_policy(policy: &str) -> Result<(), RpcError> {
        Self::nft(&[
            "add", "chain", "inet", "hyperion", "input", "{", "type", "filter", "hook", "input",
            "priority", "0", ";", "policy", policy, ";", "}",
        ])
        .await
        .map(|_| ())
        .map_err(|e| RpcError::Internal { message: e })
    }

    /// Turn hyperion's input chain into a real firewall: default DROP, with
    /// only what is explicitly allowed getting through.
    ///
    /// The single most dangerous thing the panel can do: get it wrong on a
    /// remote VPS and the operator loses SSH with no way back except the
    /// provider's console. So the order matters and is not negotiable:
    ///
    /// 1. add the survival rules while the chain still accepts everything —
    ///    loopback, established/related, ICMP (IPv6 does not work without
    ///    neighbour discovery), every port sshd listens on, and the panel's
    ///    own ports;
    /// 2. read the chain BACK and refuse to continue unless they are really
    ///    there;
    /// 3. only then set `policy drop`;
    /// 4. arm a deadline. If nobody confirms from the panel that they can
    ///    still get in, the policy goes back to accept — including after an
    ///    agent restart, which is why the deadline is a file and not a timer.
    pub async fn firewall_enable_default_drop(
        &self,
        rollback_after_secs: i64,
    ) -> Result<String, RpcError> {
        let keep = self.firewall_state_current().await.keep_tcp;
        let opened = self.default_drop_install(&keep).await?;

        // 3. Flip the policy.
        Self::nft_set_policy("drop").await?;

        // 4. Arm the rollback.
        let deadline = now_secs() + rollback_after_secs.clamp(60, 3600);
        let _ = tokio::fs::write(
            self.firewall_arm_file(),
            serde_json::json!({ "deadline": deadline }).to_string(),
        )
        .await;

        self.append_audit(
            "firewall.default_drop.enable",
            None,
            &serde_json::json!({ "allowed": opened, "deadline": deadline }).to_string(),
            "ok",
        )
        .await;
        Ok(format!(
            "Default-drop is on. Allowed: {}, loopback, ICMP and established \
             connections. Anything else — mail, a database reachable from outside — \
             is now DROPPED until you apply its preset. CONFIRM after checking you \
             can still get in from a new session; without that confirmation the \
             firewall reverts to accepting everything.",
            opened.join(", ")
        ))
    }

    /// The operator got back in: cancel the automatic revert.
    pub async fn firewall_confirm_default_drop(&self) -> Result<String, RpcError> {
        let f = self.firewall_arm_file();
        if tokio::fs::metadata(&f).await.is_err() {
            return Ok("Nothing was waiting for confirmation.".into());
        }
        let _ = tokio::fs::remove_file(&f).await;
        // Only now does it survive a reboot: an unconfirmed drop must never be
        // the thing a node boots into.
        let mut st = self.firewall_state_current().await;
        st.default_drop = true;
        self.firewall_state_save(&st).await;
        self.append_audit("firewall.default_drop.confirm", None, "{}", "ok")
            .await;
        Ok("Confirmed — the firewall stays on default-drop, also after a reboot.".into())
    }

    /// Put the chain back to accepting everything.
    pub async fn firewall_disable_default_drop(&self, reason: &str) -> Result<String, RpcError> {
        Self::nft_set_policy("accept").await?;
        let _ = tokio::fs::remove_file(self.firewall_arm_file()).await;
        let mut st = self.firewall_state_current().await;
        st.default_drop = false;
        self.firewall_state_save(&st).await;
        self.append_audit(
            "firewall.default_drop.disable",
            None,
            &serde_json::json!({ "reason": reason }).to_string(),
            "ok",
        )
        .await;
        Ok("The firewall accepts everything again.".into())
    }

    /// Seconds left to confirm, or `None` when nothing is armed.
    pub async fn firewall_arm_remaining(&self) -> Option<i64> {
        let body = tokio::fs::read_to_string(self.firewall_arm_file())
            .await
            .ok()?;
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let deadline = v.get("deadline")?.as_i64()?;
        Some(deadline - now_secs())
    }

    /// Revert an armed default-drop whose deadline has passed.
    ///
    /// Called from the agent's scheduler AND once at startup: a crash or a
    /// restart between arming and confirming would otherwise leave the box
    /// dropping with nobody watching, which is exactly the state this whole
    /// dance exists to prevent.
    pub async fn firewall_rollback_tick(&self) {
        let Some(remaining) = self.firewall_arm_remaining().await else {
            return;
        };
        if remaining > 0 {
            return;
        }
        tracing::warn!("firewall default-drop was not confirmed in time — reverting to accept");
        let _ = self
            .firewall_disable_default_drop("not confirmed before the deadline")
            .await;
    }

    /// Add a preset's rules (without recording anything). Rules already
    /// present — by their `hyperion:<tag>` comment — are left alone.
    pub(super) async fn firewall_template_install(
        template_id: &str,
    ) -> Result<(usize, usize), String> {
        let mut cmds = firewall_template_commands(template_id)
            .ok_or_else(|| format!("unknown firewall preset: {template_id}"))?;
        // The FTP preset's control port is a literal 21 in the table, but the
        // installer lets the operator pick another one and writes it into
        // vsftpd.conf. Applying a rule for 21 on a box listening on 2121
        // reports success and leaves FTP blocked.
        if template_id == "ftp" {
            let port = hyperion_adapters::ftp::read_listen_port().await.to_string();
            if port != "21" {
                for cmd in cmds.iter_mut() {
                    for arg in cmd.iter_mut() {
                        if arg == "21" {
                            *arg = port.clone();
                        }
                    }
                }
            }
        }
        nft_ensure_hyperion_chain().await?;
        let (mut added, mut present) = (0, 0);
        for cmd in &cmds {
            if Self::nft_ensure_rule(cmd).await? {
                added += 1;
            } else {
                present += 1;
            }
        }
        Ok((added, present))
    }

    /// Delete every rule carrying one of the preset's tags. Returns how many.
    pub(super) async fn firewall_template_uninstall(template_id: &str) -> Result<usize, String> {
        let tags = firewall_template_tags(template_id)
            .ok_or_else(|| format!("unknown firewall preset: {template_id}"))?;
        let listing = nft_chain_listing(true).await;
        let handles = nft_handles_for_tags(&listing, &tags);
        for h in &handles {
            Self::nft(&["delete", "rule", "inet", "hyperion", "input", "handle", h]).await?;
        }
        Ok(handles.len())
    }

    /// Apply a preset (one of `FIREWALL_TEMPLATE_IDS`) to this node. Every
    /// rule lives in hyperion's own `inet hyperion` table, tagged
    /// `comment "hyperion:<tag>"`, so the operator's own rules in other tables
    /// stay untouched. Recorded in the firewall state so it is re-applied
    /// after a reboot.
    ///
    /// Returns `(applied, output, error)`.
    pub async fn firewall_apply_template(
        &self,
        template_id: &str,
    ) -> Result<(bool, String, String), RpcError> {
        if firewall_template_tags(template_id).is_none() {
            return Err(RpcError::Validation {
                message: format!("unknown firewall preset: {template_id}"),
            });
        }
        let (applied, out, err) = match Self::firewall_template_install(template_id).await {
            Ok((added, present)) => {
                let mut st = self.firewall_state_current().await;
                if !st.templates.iter().any(|t| t == template_id) {
                    st.templates.push(template_id.to_string());
                }
                self.firewall_state_save(&st).await;
                (
                    true,
                    format!("{added} rule(s) added, {present} already present"),
                    String::new(),
                )
            }
            Err(e) => (false, String::new(), e),
        };
        self.append_audit(
            "firewall.apply_template",
            Some(template_id),
            &serde_json::json!({"applied": applied, "error_first_line": err}).to_string(),
            if applied { "ok" } else { "failed" },
        )
        .await;
        Ok((applied, out, err))
    }

    /// Take a preset's rules back out. Refuses to remove the SSH preset while
    /// the chain is dropping, unless default-drop's own SSH rule covers every
    /// port sshd listens on — otherwise this is the button that locks the
    /// operator out.
    pub async fn firewall_remove_template(
        &self,
        template_id: &str,
    ) -> Result<(bool, String, String), RpcError> {
        if firewall_template_tags(template_id).is_none() {
            return Err(RpcError::Validation {
                message: format!("unknown firewall preset: {template_id}"),
            });
        }
        let listing = nft_chain_listing(false).await;
        if template_id == "ssh" && nft_chain_policy(&listing).as_deref() == Some("drop") {
            let uncovered: Vec<String> = Self::sshd_ports()
                .await
                .into_iter()
                .filter(|p| !nft_has_tag(&listing, &format!("keep-tcp-{p}")))
                .map(|p| p.to_string())
                .collect();
            if !uncovered.is_empty() {
                return Err(RpcError::Validation {
                    message: format!(
                        "refusing to remove the SSH preset while the firewall drops by \
                         default: it is what keeps port {} open. Switch default-drop off \
                         first, or switch it on again so its own SSH rule is added.",
                        uncovered.join(", ")
                    ),
                });
            }
        }
        let (applied, out, err) = match Self::firewall_template_uninstall(template_id).await {
            Ok(n) => {
                let mut st = self.firewall_state_current().await;
                st.templates.retain(|t| t != template_id);
                self.firewall_state_save(&st).await;
                (true, format!("{n} rule(s) removed"), String::new())
            }
            Err(e) => (false, String::new(), e),
        };
        self.append_audit(
            "firewall.remove_template",
            Some(template_id),
            &serde_json::json!({"removed": applied, "error_first_line": err}).to_string(),
            if applied { "ok" } else { "failed" },
        )
        .await;
        Ok((applied, out, err))
    }

    /// Rebuild hyperion's chain from the recorded state. Called once at agent
    /// start, BEFORE bans are re-applied.
    ///
    /// nft rules do not survive a reboot. Without this, presets vanished and
    /// a confirmed default-drop came back as `policy accept` — the page then
    /// still looked configured. Idempotent, so an agent restart (every
    /// update) is a no-op.
    ///
    /// A node upgrading from before the state file has nothing recorded; its
    /// current ruleset is taken as the record and nothing is changed. Presets
    /// found live but not recorded are adopted, never removed.
    pub async fn firewall_reapply_on_boot(&self) -> Result<String, RpcError> {
        let recorded = tokio::fs::read_to_string(self.firewall_state_file())
            .await
            .ok()
            .and_then(|b| serde_json::from_str::<FirewallState>(&b).ok());
        let Some(st) = recorded else {
            let st = self.firewall_state_current().await;
            if st != FirewallState::default() {
                self.firewall_state_save(&st).await;
            }
            return Ok("recorded the current firewall as the baseline".into());
        };
        let mut done: Vec<String> = Vec::new();
        for id in st.templates.iter() {
            match Self::firewall_template_install(id).await {
                Ok((added, _)) if added > 0 => done.push(format!("re-applied {id}")),
                Ok(_) => {}
                Err(e) => tracing::warn!(preset = %id, error=%e, "firewall: re-apply failed"),
            }
        }
        // A preset pasted in by hand over SSH (the page offers the commands)
        // is adopted, never removed: deleting an operator's rules on the next
        // agent restart would be far worse than keeping one they forgot.
        let live = FirewallState::from_live(&nft_chain_listing(false).await, true);
        let mut st = st;
        let mut adopted = false;
        for id in live.templates {
            if !st.templates.contains(&id) {
                st.templates.push(id);
                adopted = true;
            }
        }
        if adopted {
            self.firewall_state_save(&st).await;
        }
        let armed = tokio::fs::metadata(self.firewall_arm_file()).await.is_ok();
        if st.default_drop {
            // Survival rules first, verified, exactly as when switching on.
            self.default_drop_install(&st.keep_tcp).await?;
            Self::nft_set_policy("drop").await?;
            done.push("default-drop restored".into());
        } else if !armed
            && nft_chain_policy(&nft_chain_listing(false).await).as_deref() == Some("drop")
        {
            // Dropping with no record of a confirmation and nothing armed: an
            // old persisted ruleset. Fail open, never closed.
            Self::nft_set_policy("accept").await?;
            done.push("unconfirmed drop policy reset to accept".into());
        }
        Ok(done.join(", "))
    }

    /// Dump the firewall ruleset. Tries `nft list ruleset` first
    /// (Debian 12+ default); falls back to `iptables -L -n -v` on
    /// boxes that still run legacy iptables. The parsed port list is
    /// best-effort; the raw output is always present so the operator
    /// can verify by eye. Read-only.
    pub async fn firewall_list(&self) -> Result<hyperion_types::FirewallView, RpcError> {
        // Try nft first.
        let nft = tokio::process::Command::new(NFT)
            .args(["list", "ruleset"])
            .output()
            .await;
        let (backend, raw, error) = match nft {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => (
                "nft".to_string(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::new(),
            ),
            Ok(o) => {
                // nft is present but errored (e.g. empty ruleset on
                // a fresh box, or operator running without root).
                // Fall through to iptables — the legacy binary is
                // still available on Debian as a compat shim.
                let nft_err = String::from_utf8_lossy(&o.stderr).into_owned();
                match tokio::process::Command::new("/usr/sbin/iptables")
                    .args(["-L", "-n", "-v"])
                    .output()
                    .await
                {
                    Ok(o2) if o2.status.success() => (
                        "iptables".to_string(),
                        String::from_utf8_lossy(&o2.stdout).into_owned(),
                        String::new(),
                    ),
                    Ok(o2) => (
                        "unknown".to_string(),
                        String::new(),
                        format!(
                            "nft: {} / iptables: {}",
                            nft_err.trim(),
                            String::from_utf8_lossy(&o2.stderr).trim()
                        ),
                    ),
                    Err(e) => (
                        "unknown".to_string(),
                        String::new(),
                        format!("nft: {} / iptables spawn: {e}", nft_err.trim()),
                    ),
                }
            }
            Err(_e) => match tokio::process::Command::new("/usr/sbin/iptables")
                .args(["-L", "-n", "-v"])
                .output()
                .await
            {
                Ok(o) if o.status.success() => (
                    "iptables".to_string(),
                    String::from_utf8_lossy(&o.stdout).into_owned(),
                    String::new(),
                ),
                Ok(o) => (
                    "unknown".to_string(),
                    String::new(),
                    String::from_utf8_lossy(&o.stderr).into_owned(),
                ),
                Err(e) => ("unknown".to_string(), String::new(), e.to_string()),
            },
        };
        let ports = parse_open_ports(&raw, backend == "nft");
        Ok(hyperion_types::FirewallView {
            backend,
            ports,
            raw,
            error,
        })
    }
}

/// Parse nginx access.log (default combined format) over the half-open
/// range `[since, until)`. `until = None` means "up to the end of the
/// file". Returns (bw_in_bytes, bw_out_bytes, requests, last_request_ts).
///
/// **The range must match the granularity of the bucket it is written
/// into.** This used to be a `since`-only window of 24 h whose result was
/// stored under an HOURLY `period` key, so every hourly bucket held a
/// rolling 24 h total and every consumer that SUMs buckets — the care
/// report's period traffic, /stats' per-site breakdown, the hosting
/// detail's `*_24h` figures — multiplied the real number by roughly the
/// bucket count. A customer's monthly letter quoted about 24× the traffic
/// their site actually served.
///
/// Nginx combined format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent ...'.
/// We only have body_bytes_sent (bw_out) — bw_in is approximated as
/// `request_length` if available, else 0.
/// Map a (port, proto) pair to a friendly label + category. Used by
/// the /firewall page to render each open port as "443 tcp · HTTPS
/// (nginx)" instead of a bare number. The mapping covers the
/// services Hyperion provisions itself, plus the standard
/// well-known ports operators care about most. Unknown ports get
/// `("Unknown", "unknown")` and the UI renders a neutral pill.
///
/// Categories drive the colour of the pill in the UI:
///   - "infra"     → SSH, DNS, NTP, …            (gray-ish)
///   - "web"       → HTTP / HTTPS                (blue)
///   - "mail"      → SMTP/submission/IMAP/POP3   (purple)
///   - "db"        → MySQL/PG/Redis/Memcached    (amber)
///   - "hyperion"  → panel + master RPC          (accent)
///   - "unknown"   → everything else             (neutral)
pub(super) fn well_known_port_label(port: u16, proto: &str) -> (String, String) {
    // proto is checked because e.g. 53 is both tcp + udp (DNS), 25
    // is only ever tcp. The table below uses tcp by default; udp-
    // specific mappings live in the explicit match arms.
    let (label, cat) = match (port, proto) {
        // --- infra ---
        (22, "tcp") => ("SSH", "infra"),
        (53, _) => ("DNS", "infra"),
        (67 | 68, "udp") => ("DHCP", "infra"),
        (123, "udp") => ("NTP", "infra"),

        // --- web (nginx) ---
        (80, "tcp") => ("HTTP (nginx)", "web"),
        (443, "tcp") => ("HTTPS (nginx)", "web"),
        (443, "udp") => ("HTTPS / QUIC (nginx)", "web"),

        // --- mail ---
        (25, "tcp") => ("SMTP (postfix)", "mail"),
        (110, "tcp") => ("POP3", "mail"),
        (143, "tcp") => ("IMAP", "mail"),
        (465, "tcp") => ("SMTPS (submission)", "mail"),
        (587, "tcp") => ("SMTP submission", "mail"),
        (993, "tcp") => ("IMAPS", "mail"),
        (995, "tcp") => ("POP3S", "mail"),

        // --- db ---
        (3306, "tcp") => ("MySQL / MariaDB", "db"),
        (5432, "tcp") => ("PostgreSQL", "db"),
        (6379, "tcp") => ("Redis", "db"),
        (11211, "tcp" | "udp") => ("Memcached", "db"),

        // --- hyperion ---
        (8443, "tcp") => ("Hyperion panel (web UI)", "hyperion"),
        (8447, "tcp") => ("Hyperion phpMyAdmin", "hyperion"),
        (9443, "tcp") => ("Hyperion RPC (master ↔ worker)", "hyperion"),

        // --- FTP / SFTP (vsftpd) ---
        (21, "tcp") => ("FTP control (vsftpd)", "infra"),
        (20, "tcp") => ("FTP data (vsftpd)", "infra"),

        // --- ICMP-ish / common diagnostic ---
        (3478, _) => ("STUN / TURN", "infra"),

        _ => ("Unknown", "unknown"),
    };
    (label.to_string(), cat.to_string())
}

pub(super) fn sshd_ports_from(body: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let rest = l.strip_prefix("Port")?;
            // A bare prefix match would also take "PortForwarding"; the
            // directive is only this one when a space follows.
            if !rest.starts_with(char::is_whitespace) {
                return None;
            }
            rest.split_whitespace().next()?.parse::<u16>().ok()
        })
        .collect();
    if ports.is_empty() {
        ports.push(22);
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Preset ids `firewall_template_commands` knows, in the order the boot
/// re-apply walks them. "worker_rpc" is snippet-only in the UI (it needs the
/// master's IP) and deliberately absent.
pub(super) const FIREWALL_TEMPLATE_IDS: [&str; 5] = ["web", "mail", "hyperion", "ssh", "ftp"];

/// One port the operator opened from the panel, outside the presets. Travels
/// as a preset id — `custom:<proto>:<port>[:<source>]` — so apply, remove,
/// the recorded state and the boot re-apply all reuse the preset path, and
/// an older agent answers "unknown preset" instead of misreading it.
///
/// The rule's tag encodes the same fields (`custom-tcp-8080[-from-<src>]`),
/// so the rule alone is enough to rebuild the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CustomPort {
    pub(super) proto: &'static str,
    pub(super) port: u16,
    /// Canonical `addr/prefix`, or None for "anyone".
    pub(super) source: Option<String>,
}

impl CustomPort {
    pub(super) fn new(proto: &str, port: &str, source: Option<&str>) -> Option<Self> {
        let proto = match proto {
            "tcp" => "tcp",
            "udp" => "udp",
            _ => return None,
        };
        let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
        let source = match source.map(str::trim).filter(|s| !s.is_empty()) {
            None => None,
            Some(s) => {
                // Strictly an address or CIDR: this lands in an nft argv.
                let (addr, prefix) = match s.split_once('/') {
                    Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
                    None => (s, None),
                };
                let ip: std::net::IpAddr = addr.parse().ok()?;
                let max = if ip.is_ipv4() { 32 } else { 128 };
                let prefix = prefix.unwrap_or(max);
                if prefix > max {
                    return None;
                }
                Some(format!("{ip}/{prefix}"))
            }
        };
        Some(Self {
            proto,
            port,
            source,
        })
    }

    pub(super) fn from_id(id: &str) -> Option<Self> {
        let mut it = id.strip_prefix("custom:")?.splitn(3, ':');
        let proto = it.next()?;
        let port = it.next()?;
        Self::new(proto, port, it.next())
    }

    pub(super) fn id(&self) -> String {
        match &self.source {
            Some(s) => format!("custom:{}:{}:{s}", self.proto, self.port),
            None => format!("custom:{}:{}", self.proto, self.port),
        }
    }

    pub(super) fn tag(&self) -> String {
        match &self.source {
            Some(s) => format!("custom-{}-{}-from-{s}", self.proto, self.port),
            None => format!("custom-{}-{}", self.proto, self.port),
        }
    }

    pub(super) fn from_tag(tag: &str) -> Option<Self> {
        let rest = tag.strip_prefix("custom-")?;
        let (proto, rest) = rest.split_once('-')?;
        let (port, source) = match rest.split_once("-from-") {
            Some((p, s)) => (p, Some(s)),
            None => (rest, None),
        };
        Self::new(proto, port, source)
    }

    /// Every custom rule in a chain listing.
    pub(super) fn all_in(listing: &str) -> Vec<Self> {
        let mut out: Vec<Self> = listing
            .split("comment \"hyperion:")
            .skip(1)
            .filter_map(|r| Self::from_tag(&r[..r.find('"')?]))
            .collect();
        out.dedup();
        out
    }

    pub(super) fn rule(&self) -> Vec<String> {
        let port = self.port.to_string();
        let mut body: Vec<&str> = Vec::new();
        if let Some(s) = &self.source {
            body.push(if s.contains(':') { "ip6" } else { "ip" });
            body.push("saddr");
            body.push(s);
        }
        body.extend([self.proto, "dport", &port, "accept"]);
        rule(&body, &self.tag())
    }
}

/// The recorded shape of this node's firewall — see
/// `HostingService::firewall_state_file`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct FirewallState {
    /// Applied preset ids.
    #[serde(default)]
    pub(super) templates: Vec<String>,
    /// Default-drop is on AND was confirmed. An armed, unconfirmed drop is
    /// never recorded here, so a node can never boot into one.
    #[serde(default)]
    pub(super) default_drop: bool,
    /// TCP ports default-drop keeps open (SSH + the panel's own), remembered
    /// so the boot re-apply keeps them even before hyperion-web is listening.
    #[serde(default)]
    pub(super) keep_tcp: Vec<u16>,
}

impl FirewallState {
    /// Read the state off a live `nft list chain inet hyperion input`.
    pub(super) fn from_live(listing: &str, armed: bool) -> Self {
        let templates = FIREWALL_TEMPLATE_IDS
            .iter()
            .filter(|id| {
                firewall_template_tags(id)
                    .is_some_and(|tags| tags.iter().all(|t| nft_has_tag(listing, t)))
            })
            .map(|id| id.to_string())
            .chain(CustomPort::all_in(listing).into_iter().map(|c| c.id()))
            .collect();
        Self {
            templates,
            default_drop: !armed && nft_chain_policy(listing).as_deref() == Some("drop"),
            keep_tcp: Vec::new(),
        }
    }
}

/// An `add rule inet hyperion input <body> comment "hyperion:<tag>"` argv.
pub(super) fn rule(body: &[&str], tag: &str) -> Vec<String> {
    ["add", "rule", "inet", "hyperion", "input"]
        .iter()
        .chain(body.iter())
        .map(|s| s.to_string())
        .chain(["comment".to_string(), format!("\"hyperion:{tag}\"")])
        .collect()
}

/// The rules that must be in place before the chain may drop by default.
pub(super) fn default_drop_survival_rules(keep_tcp: &[u16]) -> Vec<Vec<String>> {
    let mut rules = vec![
        // Answers to connections we made, and to anything already open —
        // without this, flipping the policy kills the very SSH session doing
        // the flipping. `related` also carries ICMP errors (PMTU discovery).
        rule(
            &["ct", "state", "established,related", "accept"],
            "established",
        ),
        rule(&["iif", "lo", "accept"], "loopback"),
        // IPv6 does not work at all without neighbour discovery, which is
        // ICMPv6 and never "established". Ping on v4 is kept for monitoring.
        rule(&["meta", "l4proto", "ipv6-icmp", "accept"], "keep-icmpv6"),
        rule(&["meta", "l4proto", "icmp", "accept"], "keep-icmp"),
    ];
    for p in keep_tcp {
        let port = p.to_string();
        rules.push(rule(
            &["tcp", "dport", &port, "accept"],
            &format!("keep-tcp-{p}"),
        ));
    }
    rules
}

/// Tags that must read back from the chain before the policy may flip.
pub(super) fn default_drop_required_tags(keep_tcp: &[u16]) -> Vec<String> {
    let mut tags: Vec<String> = ["established", "loopback", "keep-icmpv6"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    tags.extend(keep_tcp.iter().map(|p| format!("keep-tcp-{p}")));
    tags
}

/// `nft list chain inet hyperion input` (with `-a` when `handles`), or empty
/// when the table or chain does not exist yet.
pub(super) async fn nft_chain_listing(handles: bool) -> String {
    let args: &[&str] = if handles {
        &["-a", "list", "chain", "inet", "hyperion", "input"]
    } else {
        &["list", "chain", "inet", "hyperion", "input"]
    };
    hyperion_adapters::cmd::run(NFT, args)
        .await
        .unwrap_or_default()
}

/// Create hyperion's table and input chain if missing — WITHOUT touching the
/// chain's policy when it already exists.
///
/// This used to run `add chain … { …; policy accept; }` before every ban and
/// every preset. On an existing chain nft treats that as "set the policy", so
/// the next auto-ban quietly switched a confirmed default-drop back to
/// accepting everything (verified against nft 1.1 on Debian 13). Leaving the
/// policy out creates the chain as accept and leaves an existing one alone.
pub(super) async fn nft_ensure_hyperion_chain() -> Result<(), String> {
    hyperion_adapters::cmd::run(NFT, &["add", "table", "inet", "hyperion"])
        .await
        .map_err(|e| e.to_string())?;
    hyperion_adapters::cmd::run(
        NFT,
        &[
            "add", "chain", "inet", "hyperion", "input", "{", "type", "filter", "hook", "input",
            "priority", "0", ";", "}",
        ],
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Does the chain listing hold a rule tagged `hyperion:<tag>`? The closing
/// quote is part of the match so `ftp` does not also match `ftp-passive`.
pub(super) fn nft_has_tag(listing: &str, tag: &str) -> bool {
    listing.contains(&format!("comment \"hyperion:{tag}\""))
}

/// The tag of an `add rule` argv built by `rule()` or the preset table.
pub(super) fn nft_rule_tag(argv: &[String]) -> Option<String> {
    let last = argv.last()?;
    last.trim_matches('"')
        .strip_prefix("hyperion:")
        .map(str::to_string)
}

/// `policy accept|drop` of the base chain in a chain listing.
pub(super) fn nft_chain_policy(listing: &str) -> Option<String> {
    let idx = listing.find("policy ")?;
    let rest = &listing[idx + "policy ".len()..];
    let word: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    (!word.is_empty()).then_some(word)
}

/// Rule handles (from `nft -a list chain`) of every rule carrying one of
/// `tags`.
pub(super) fn nft_handles_for_tags(listing: &str, tags: &[String]) -> Vec<String> {
    listing
        .lines()
        .filter(|l| tags.iter().any(|t| nft_has_tag(l, t)))
        .filter_map(|l| {
            let h = l.rsplit_once("# handle ")?.1.trim();
            h.chars().all(|c| c.is_ascii_digit()).then(|| h.to_string())
        })
        .collect()
}

/// Every tag a preset's rules carry.
pub(super) fn firewall_template_tags(id: &str) -> Option<Vec<String>> {
    Some(
        firewall_template_commands(id)?
            .iter()
            .filter_map(|c| nft_rule_tag(c))
            .collect(),
    )
}

/// Public TCP ports hyperion-web / hyperion-agent listen on, from
/// `ss -Hltnp`. Loopback-only listeners are skipped — loopback is always
/// allowed, and nginx in front of a loopback panel is covered by web.
pub(super) fn hyperion_listen_ports_from_ss(out: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = out
        .lines()
        .filter(|l| l.contains("\"hyperion-web\"") || l.contains("\"hyperion-agent\""))
        .filter_map(|l| {
            // State Recv-Q Send-Q Local:Port Peer:Port Process
            let local = l.split_whitespace().nth(3)?;
            let (addr, port) = local.rsplit_once(':')?;
            let addr = addr.trim_start_matches('[').trim_end_matches(']');
            let addr = addr.split('%').next().unwrap_or(addr);
            if addr.starts_with("127.") || addr == "::1" || addr == "localhost" {
                return None;
            }
            port.parse::<u16>().ok()
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Open ports from a ruleset dump, decorated for the /firewall table.
///
/// nft: an `accept` rule with a `tcp|udp dport` match, single port, range or
/// set. Rules in output/forward/pre-/postrouting chains are skipped — they
/// say nothing about what the box accepts. A rule limited to a source address
/// or an interface is reported as restricted rather than open to the world.
/// This used to count any line with `dport` — a `drop` rule listed its ports
/// as open.
///
/// iptables: `ACCEPT … tcp dpt:N` / `dpts:A:B`; restricted when the source
/// column is not `0.0.0.0/0`.
pub(super) fn parse_open_ports(raw: &str, is_nft: bool) -> Vec<hyperion_types::FirewallPort> {
    use std::collections::BTreeMap;
    // (proto, start, end) -> (ours, restricted)
    let mut found: BTreeMap<(&'static str, u16, u16), (bool, bool)> = BTreeMap::new();
    let mut note = |proto: &'static str, a: u16, b: u16, ours: bool, restricted: bool| {
        let e = found.entry((proto, a, b)).or_insert((ours, restricted));
        e.0 |= ours;
        // Open to the world if ANY rule opens it without a restriction.
        e.1 &= restricted;
    };
    let parse_range = |tok: &str, sep: char| -> Option<(u16, u16)> {
        match tok.split_once(sep) {
            Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
            None => {
                let p = tok.trim().parse().ok()?;
                Some((p, p))
            }
        }
    };
    let mut skip_chain = false;
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if !is_nft {
            if l.starts_with("Chain ") {
                skip_chain = l.starts_with("Chain FORWARD") || l.starts_with("Chain OUTPUT");
                continue;
            }
            if skip_chain {
                continue;
            }
            let toks: Vec<&str> = l.split_whitespace().collect();
            if toks.len() < 9 || toks[2] != "ACCEPT" {
                continue;
            }
            let restricted = toks[7] != "0.0.0.0/0" && toks[7] != "::/0";
            for proto in ["tcp", "udp"] {
                for (key, sep) in [("dpt:", ':'), ("dpts:", ':')] {
                    let Some(t) = toks.iter().find(|t| t.starts_with(key)) else {
                        continue;
                    };
                    if toks[3] != proto && !l.contains(&format!(" {proto} ")) {
                        continue;
                    }
                    if let Some((a, b)) = parse_range(&t[key.len()..], sep) {
                        note(proto, a, b, false, restricted);
                    }
                }
            }
            continue;
        }
        if l.starts_with("table ") || l.starts_with("chain ") {
            skip_chain = false;
            continue;
        }
        if l.contains(" hook ") {
            skip_chain = !l.contains("hook input");
            continue;
        }
        if skip_chain || !l.split_whitespace().any(|w| w == "accept") {
            continue;
        }
        let ours = l.contains("comment \"hyperion:");
        let restricted = l.contains("saddr ") || l.contains("iifname ") || l.contains("iif ");
        for proto in ["tcp", "udp"] {
            let Some(idx) = l.find(&format!("{proto} dport ")) else {
                continue;
            };
            let after = l[idx + proto.len() + " dport ".len()..].trim_start();
            let spec = if let Some(rest) = after.strip_prefix('{') {
                &rest[..rest.find('}').unwrap_or(rest.len())]
            } else {
                after.split_whitespace().next().unwrap_or("")
            };
            for tok in spec.split(',') {
                if let Some((a, b)) = parse_range(tok, '-') {
                    note(proto, a, b, ours, restricted);
                }
            }
        }
    }
    let mut ports: Vec<hyperion_types::FirewallPort> = found
        .into_iter()
        .map(|((proto, a, b), (ours, restricted))| {
            let (label, category) = if a == b {
                well_known_port_label(a, proto)
            } else if (a, b) == (40000, 50000) && proto == "tcp" {
                ("FTP passive data (vsftpd)".to_string(), "infra".to_string())
            } else {
                ("Port range".to_string(), "unknown".to_string())
            };
            hyperion_types::FirewallPort {
                port: a,
                port_end: if a == b { 0 } else { b },
                proto: proto.into(),
                label,
                category,
                opened_by_hyperion: ours,
                source_restricted: restricted,
            }
        })
        .collect();
    ports.sort_by(|a, b| a.port.cmp(&b.port).then(a.proto.cmp(&b.proto)));
    ports
}

/// nft argv sequences for each firewall preset. Returns `None` for an
/// unknown id. Each rule's last argument is its `"hyperion:<tag>"` comment —
/// the tag is how a preset is detected, re-applied idempotently and removed.
///
/// Keep the ids in lock-step with `port_templates()` in
/// `bin/hyperion-web/src/handlers/firewall.rs` and `FIREWALL_TEMPLATE_IDS`.
pub(super) fn firewall_template_commands(id: &str) -> Option<Vec<Vec<String>>> {
    if let Some(c) = CustomPort::from_id(id) {
        return Some(vec![c.rule()]);
    }
    // No table/chain header: the caller creates them with
    // `nft_ensure_hyperion_chain`, which — unlike the `add chain … policy
    // accept` header this used to start with — does not reset the policy.
    let body: Vec<Vec<&'static str>> = match id {
        "web" => vec![
            vec![
                "add",
                "rule",
                "inet",
                "hyperion",
                "input",
                "tcp",
                "dport",
                "{",
                "80,",
                "443",
                "}",
                "accept",
                "comment",
                "\"hyperion:web\"",
            ],
            vec![
                "add",
                "rule",
                "inet",
                "hyperion",
                "input",
                "udp",
                "dport",
                "443",
                "accept",
                "comment",
                "\"hyperion:web-quic\"",
            ],
        ],
        "mail" => vec![vec![
            "add",
            "rule",
            "inet",
            "hyperion",
            "input",
            "tcp",
            "dport",
            "{",
            "25,",
            "465,",
            "587,",
            "993,",
            "995",
            "}",
            "accept",
            "comment",
            "\"hyperion:mail\"",
        ]],
        "hyperion" => vec![vec![
            "add",
            "rule",
            "inet",
            "hyperion",
            "input",
            "tcp",
            "dport",
            "{",
            "8443,",
            "8447,",
            "9443",
            "}",
            "accept",
            "comment",
            "\"hyperion:hyperion\"",
        ]],
        "ssh" => vec![vec![
            "add",
            "rule",
            "inet",
            "hyperion",
            "input",
            "tcp",
            "dport",
            "22",
            "accept",
            "comment",
            "\"hyperion:ssh\"",
        ]],
        "ftp" => vec![
            vec![
                "add",
                "rule",
                "inet",
                "hyperion",
                "input",
                "tcp",
                "dport",
                "21",
                "accept",
                "comment",
                "\"hyperion:ftp-control\"",
            ],
            vec![
                "add",
                "rule",
                "inet",
                "hyperion",
                "input",
                "tcp",
                "dport",
                "40000-50000",
                "accept",
                "comment",
                "\"hyperion:ftp-passive\"",
            ],
        ],
        // "worker_rpc" needs <MASTER_IP> substitution which we
        // don't have at apply-time without an extra arg. Surface
        // it as snippet-only in the UI — skipping here returns
        // `None` and the validation error makes it clear.
        _ => return None,
    };
    // Owned strings so the caller can substitute a non-default port; see
    // firewall_apply_template.
    Some(
        body.into_iter()
            .map(|c| c.into_iter().map(String::from).collect())
            .collect(),
    )
}

#[cfg(test)]
mod sshd_ports_tests {
    use super::sshd_ports_from;

    /// The default sshd assumes when nothing says otherwise.
    #[test]
    fn no_directive_means_twenty_two() {
        assert_eq!(sshd_ports_from(""), vec![22]);
        assert_eq!(
            sshd_ports_from("# Port 2222\nPermitRootLogin yes\n"),
            vec![22]
        );
    }

    /// The case that locks someone out: a box on a non-standard port. A rule
    /// for 22 here would report success and take SSH away.
    #[test]
    fn a_moved_port_is_found() {
        assert_eq!(sshd_ports_from("Port 2222\n"), vec![2222]);
        assert_eq!(sshd_ports_from("  Port   2222   \n"), vec![2222]);
    }

    /// sshd accepts several; all of them have to survive the flip.
    #[test]
    fn every_listening_port_is_kept() {
        assert_eq!(sshd_ports_from("Port 22\nPort 2222\n"), vec![22, 2222]);
        assert_eq!(
            sshd_ports_from("Port 2222\nPort 22\nPort 2222\n"),
            vec![22, 2222]
        );
    }

    /// Lookalikes and junk must not be read as a port — silently dropping the
    /// real one is how the rule ends up naming a port nothing listens on.
    #[test]
    fn lookalike_directives_are_not_ports() {
        assert_eq!(sshd_ports_from("PortForwarding yes\n"), vec![22]);
        assert_eq!(sshd_ports_from("Ports 2222\n"), vec![22]);
        assert_eq!(sshd_ports_from("Port notanumber\n"), vec![22]);
        assert_eq!(sshd_ports_from("Port 99999\n"), vec![22]);
        // A commented-out move must not be honoured.
        assert_eq!(sshd_ports_from("#Port 2222\nPort 22\n"), vec![22]);
    }
}

#[cfg(test)]
mod firewall_tests {
    use super::*;

    const LIVE: &str = r#"table inet hyperion {
	set banned {
		type ipv4_addr
		flags timeout
	}
	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @banned drop comment "hyperion:ban-drop"
		ct state established,related accept comment "hyperion:established"
		tcp dport { 80, 443 } accept comment "hyperion:web"
		udp dport 443 accept comment "hyperion:web-quic"
		tcp dport 40000-50000 accept comment "hyperion:ftp-passive"
		tcp dport 21 accept comment "hyperion:ftp-control"
		ip saddr 10.0.0.1 tcp dport 9443 accept
		tcp dport { 25, 465 } drop
	}
}
table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		tcp dport 8080 accept
	}
}
"#;

    #[test]
    fn drop_rules_are_not_open_ports() {
        let p = parse_open_ports(LIVE, true);
        assert!(!p.iter().any(|x| x.port == 25 || x.port == 465), "{p:?}");
    }

    #[test]
    fn non_input_chains_are_skipped() {
        let p = parse_open_ports(LIVE, true);
        assert!(!p.iter().any(|x| x.port == 8080), "{p:?}");
    }

    #[test]
    fn sets_ranges_and_restrictions_are_read() {
        let p = parse_open_ports(LIVE, true);
        let get = |port, proto: &str| p.iter().find(|x| x.port == port && x.proto == proto);
        assert!(get(80, "tcp").unwrap().opened_by_hyperion);
        assert!(get(443, "udp").is_some());
        let r = get(40000, "tcp").unwrap();
        assert_eq!(r.port_end, 50000);
        let rpc = get(9443, "tcp").unwrap();
        assert!(rpc.source_restricted && !rpc.opened_by_hyperion);
        assert!(!get(21, "tcp").unwrap().source_restricted);
    }

    #[test]
    fn an_unrestricted_rule_wins_over_a_restricted_one() {
        let raw = "chain input {\n type filter hook input priority 0; policy accept;\n \
                   ip saddr 1.2.3.4 tcp dport 22 accept\n tcp dport 22 accept\n}\n";
        let p = parse_open_ports(raw, true);
        assert_eq!(p.len(), 1);
        assert!(!p[0].source_restricted);
    }

    #[test]
    fn iptables_accepts_are_read() {
        let raw = "Chain INPUT (policy DROP 0 packets, 0 bytes)\n \
            pkts bytes target     prot opt in     out     source               destination\n \
               0     0 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22\n \
               0     0 ACCEPT     6    --  *      *       10.0.0.1             0.0.0.0/0            tcp dpt:9443\n \
               0     0 DROP       6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:25\n";
        let p = parse_open_ports(raw, false);
        // iptables -n prints the protocol number; the dpt: match is what counts.
        let ports: Vec<u16> = p.iter().map(|x| x.port).collect();
        assert!(
            ports.contains(&22) && ports.contains(&9443) && !ports.contains(&25),
            "{p:?}"
        );
        assert!(p.iter().find(|x| x.port == 9443).unwrap().source_restricted);
    }

    #[test]
    fn policy_and_tags() {
        assert_eq!(nft_chain_policy(LIVE).as_deref(), Some("drop"));
        assert!(nft_has_tag(LIVE, "ftp-passive"));
        // A prefix of another tag is not that tag.
        assert!(!nft_has_tag(LIVE, "ftp"));
        assert_eq!(nft_chain_policy(""), None);
    }

    #[test]
    fn handles_are_found_by_tag() {
        let l = "\t\ttcp dport 80 accept comment \"hyperion:web\" # handle 4\n\
                 \t\tudp dport 443 accept comment \"hyperion:web-quic\" # handle 7\n\
                 \t\ttcp dport 22 accept comment \"hyperion:ssh\" # handle 9\n";
        let tags = firewall_template_tags("web").unwrap();
        assert_eq!(nft_handles_for_tags(l, &tags), vec!["4", "7"]);
    }

    #[test]
    fn preset_tags_come_from_the_commands() {
        assert_eq!(
            firewall_template_tags("ftp").unwrap(),
            vec!["ftp-control", "ftp-passive"]
        );
        assert!(firewall_template_tags("worker_rpc").is_none());
        for id in FIREWALL_TEMPLATE_IDS {
            assert!(!firewall_template_tags(id).unwrap().is_empty(), "{id}");
        }
    }

    #[test]
    fn state_is_read_off_a_live_chain() {
        let st = FirewallState::from_live(LIVE, false);
        assert_eq!(st.templates, vec!["web", "ftp"]);
        assert!(st.default_drop);
        // An armed drop is not a confirmed one.
        assert!(!FirewallState::from_live(LIVE, true).default_drop);
    }

    #[test]
    fn custom_ports_round_trip_through_id_and_tag() {
        let c = CustomPort::from_id("custom:tcp:8080:203.0.113.7").unwrap();
        assert_eq!(c.id(), "custom:tcp:8080:203.0.113.7/32");
        assert_eq!(CustomPort::from_tag(&c.tag()), Some(c.clone()));
        let argv = c.rule();
        assert_eq!(
            argv[5..].join(" "),
            "ip saddr 203.0.113.7/32 tcp dport 8080 accept comment \"hyperion:custom-tcp-8080-from-203.0.113.7/32\""
        );
        let v6 = CustomPort::from_id("custom:udp:51820:2001:db8::/32").unwrap();
        assert_eq!(v6.source.as_deref(), Some("2001:db8::/32"));
        assert_eq!(v6.rule()[5], "ip6");
        assert_eq!(CustomPort::from_tag(&v6.tag()), Some(v6));
        let open = CustomPort::from_id("custom:udp:51820").unwrap();
        assert_eq!(
            firewall_template_tags(&open.id()).unwrap(),
            vec!["custom-udp-51820"]
        );
    }

    #[test]
    fn custom_ports_refuse_anything_odd() {
        for bad in [
            "custom:icmp:1",
            "custom:tcp:0",
            "custom:tcp:70000",
            "custom:tcp:22:1.2.3.4/33",
            "custom:tcp:22:1.2.3.4; drop",
            "custom:tcp:22:example.com",
            "custom:tcp",
        ] {
            assert!(CustomPort::from_id(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn custom_ports_are_read_off_a_live_chain() {
        let l = "tcp dport 8080 accept comment \"hyperion:custom-tcp-8080\"\n\
                 ip saddr 10.0.0.0/8 udp dport 53 accept comment \"hyperion:custom-udp-53-from-10.0.0.0/8\"\n";
        let st = FirewallState::from_live(l, false);
        assert_eq!(
            st.templates,
            vec!["custom:tcp:8080", "custom:udp:53:10.0.0.0/8"]
        );
    }

    #[test]
    fn panel_and_rpc_ports_come_from_ss() {
        let ss = "LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:((\"hyperion-web\",pid=10,fd=9))\n\
                  LISTEN 0 4096 [::]:9443 [::]:* users:((\"hyperion-agent\",pid=11,fd=7))\n\
                  LISTEN 0 4096 127.0.0.1:9000 0.0.0.0:* users:((\"hyperion-agent\",pid=11,fd=8))\n\
                  LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=6))\n";
        assert_eq!(hyperion_listen_ports_from_ss(ss), vec![8443, 9443]);
    }

    #[test]
    fn survival_rules_cover_what_is_verified() {
        let keep = [22u16, 8443];
        let rules = default_drop_survival_rules(&keep);
        let tags: Vec<String> = rules.iter().filter_map(|r| nft_rule_tag(r)).collect();
        for t in default_drop_required_tags(&keep) {
            assert!(tags.contains(&t), "{t} is verified but never added");
        }
    }
}
