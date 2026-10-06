//! Node-level system work: service installs, updates, setup and health.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Whitelist of unit names we'll restart/install. Refusing
    /// anything else prevents a compromised UI from convincing the
    /// agent to enable a random unit ("docker", "ssh", "ufw"…).
    /// Refusing `hyperion-agent` specifically prevents tearing the
    /// RPC pipe out from under our own response.
    pub(super) fn service_whitelist_for(
        name: &str,
        allow_self_restart: bool,
    ) -> Option<&'static str> {
        match name {
            "nginx" => Some("nginx"),
            "mariadb" => Some("mariadb-server"),
            "postgresql" => Some("postgresql"),
            "redis-server" => Some("redis-server"),
            "vsftpd" => Some("vsftpd"),
            // postfix provides /usr/sbin/sendmail for PHP mail().
            // Install path runs the same debconf preseeding as
            // update.sh (Internet Site, hostname-derived mailname)
            // — see `run_service_install`.
            "postfix" => Some("postfix"),
            // PHP installs pull the FULL extension set, not just -fpm:
            // wp-cli `core download` needs ZipArchive (php*-zip) and a
            // bare WordPress needs gd/mbstring/xml/curl/mysql. soap is in
            // too — many WordPress plugins (shipping, invoicing, payment
            // gateways) hard-require it and refuse to run otherwise.
            // Installing only -fpm left every fresh PHP version unable to
            // run a WP install ("Extracting a zip file requires ZipArchive").
            // run_service_install splits this on whitespace into apt args.
            "php8.1-fpm" => Some(
                "php8.1-fpm php8.1-cli php8.1-mysql php8.1-pgsql \
                 php8.1-curl php8.1-gd php8.1-mbstring php8.1-xml php8.1-zip php8.1-soap",
            ),
            "php8.2-fpm" => Some(
                "php8.2-fpm php8.2-cli php8.2-mysql php8.2-pgsql \
                 php8.2-curl php8.2-gd php8.2-mbstring php8.2-xml php8.2-zip php8.2-soap",
            ),
            "php8.3-fpm" => Some(
                "php8.3-fpm php8.3-cli php8.3-mysql php8.3-pgsql \
                 php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip php8.3-soap",
            ),
            "php8.4-fpm" => Some(
                "php8.4-fpm php8.4-cli php8.4-mysql php8.4-pgsql \
                 php8.4-curl php8.4-gd php8.4-mbstring php8.4-xml php8.4-zip php8.4-soap",
            ),
            // ClamAV for the per-hosting malware scan. The scanner is the
            // `clamscan` CLI (from the `clamav` package), not a daemon, so
            // there is no unit to "start" — but `clamav-freshclam` IS a
            // service, and it is what keeps the virus database current, so
            // that is the unit the Services page tracks. Installing it
            // pulls `clamav` (hence clamscan) as a dependency; naming both
            // is belt-and-braces. First `freshclam` run downloads a few
            // hundred MB of signatures, so the first scan afterwards may
            // lag briefly.
            "clamav-freshclam" => Some("clamav clamav-freshclam"),
            "hyperion-web" => Some("hyperion-web"),
            "hyperion-agent" if allow_self_restart => Some("hyperion-agent"),
            _ => None,
        }
    }

    pub async fn service_restart(&self, name: String) -> Result<(), RpcError> {
        let _pkg = Self::service_whitelist_for(&name, false).ok_or_else(|| {
            RpcError::Validation {
                message: format!(
                    "service `{name}` is not on the restart whitelist (refuse self-restart of hyperion-agent — would kill this RPC; SSH for that)"
                ),
            }
        })?;
        let out = tokio::process::Command::new("/usr/bin/systemctl")
            .args(["restart", &name])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("systemctl: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(RpcError::Internal_with(format!(
                "systemctl restart {name} failed: {stderr}"
            )));
        }
        self.append_audit(
            "service.restart",
            None,
            &serde_json::json!({"name": name}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// `systemctl start|stop|enable|disable <name>` on a whitelisted unit.
    pub async fn service_control(&self, name: String, action: String) -> Result<(), RpcError> {
        service_control_allowed(&name, &action)
            .map_err(|message| RpcError::Validation { message })?;
        Self::service_whitelist_for(&name, false).ok_or_else(|| RpcError::Validation {
            message: format!("service `{name}` is not on the services whitelist"),
        })?;
        let out = tokio::process::Command::new("/usr/bin/systemctl")
            .args([action.as_str(), name.as_str()])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("systemctl: {e}")))?;
        let outcome = if out.status.success() { "ok" } else { "failed" };
        self.append_audit(
            &format!("service.{action}"),
            None,
            &serde_json::json!({"name": name}).to_string(),
            outcome,
        )
        .await;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(RpcError::Internal_with(format!(
                "systemctl {action} {name} failed: {stderr}"
            )));
        }
        Ok(())
    }

    /// Last `lines` journal lines of a whitelisted unit. Read-only, so the
    /// agent's own unit is allowed; capped so one request can't pull the
    /// whole journal over the wire.
    pub async fn service_journal(&self, name: String, lines: u32) -> Result<String, RpcError> {
        Self::service_whitelist_for(&name, true).ok_or_else(|| RpcError::Validation {
            message: format!("service `{name}` is not on the services whitelist"),
        })?;
        let n = lines.clamp(1, 500).to_string();
        let run = tokio::process::Command::new("journalctl")
            .args([
                "-u",
                name.as_str(),
                "-n",
                n.as_str(),
                "--no-pager",
                "-o",
                "short-iso",
            ])
            .kill_on_drop(true)
            .output();
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run)
            .await
            .map_err(|_| RpcError::Internal_with("journalctl timed out after 10 s".into()))?
            .map_err(|e| RpcError::Internal_with(format!("journalctl: {e}")))?;
        if !out.status.success() {
            return Err(RpcError::Internal_with(format!(
                "journalctl failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Compare the running binary's compile-time git SHA against the
    /// SHA the upstream `rolling` tag points to. Cached for
    /// `UPDATE_CHECK_TTL_SECS` so the dashboard banner doesn't trigger
    /// a network call on every page load.
    ///
    /// We use `git ls-remote` rather than the GitHub REST API — git is
    /// already installed on every node (the installer uses it), and
    /// ls-remote against the public mirror is unauthenticated, has no
    /// rate limit per IP, and returns the answer in one round trip
    /// without JSON parsing. The downside (slightly slower TCP/TLS
    /// vs. a HEAD request) is irrelevant once per hour.
    pub async fn update_check(
        &self,
        force_refresh: bool,
    ) -> Result<hyperion_types::UpdateStatus, RpcError> {
        let now = now_secs();
        // Fast path: serve cached if still fresh and caller didn't ask
        // for a forced refresh. We use a separate read scope so the
        // (uncommon) refresh path can take the write lock without
        // upgrading.
        if !force_refresh {
            let cache = self.update_cache.read().await;
            if let Some(s) = cache.as_ref() {
                if now - s.last_checked_at < UPDATE_CHECK_TTL_SECS {
                    return Ok(s.clone());
                }
            }
        }

        // One probe at a time. Every caller that found the cache stale used
        // to run its own `git ls-remote` + download, so the hourly expiry
        // with a few dashboards open was a burst of identical probes. Who
        // waited here re-reads the cache: the probe that held the gate has
        // usually just stored an answer. A forced refresh (the operator's
        // "check now") takes it too when that probe started within a few
        // seconds of the click — re-asking GitHub would say the same.
        const FORCED_FRESH_SECS: i64 = 10;
        static PROBE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _probe = PROBE_GATE.lock().await;
        {
            let cache = self.update_cache.read().await;
            if let Some(s) = cache.as_ref() {
                let fresh = if force_refresh {
                    s.last_checked_at >= now - FORCED_FRESH_SECS
                } else {
                    now - s.last_checked_at < UPDATE_CHECK_TTL_SECS
                };
                if fresh {
                    return Ok(s.clone());
                }
            }
        }

        // Re-probe upstream. We don't read /etc/hyperion/agent.toml for
        // a configurable repo URL because the install scripts hard-code
        // nechodom/hyperion too — if the operator forks, they patch the
        // installer and this together.
        let repo_url = "https://github.com/nechodom/hyperion";
        // Read the VERSION marker OF THE RELEASE, not the git tag.
        //
        // These are not the same thing and drifted apart for two months.
        // Publishing a release under an existing tag overwrites the
        // assets but does NOT move the tag, so `refs/tags/rolling` still
        // pointed at the commit where the tag was first created while the
        // binaries tracked main. The panel read the tag and nagged
        // "update available" forever; `update.sh` read the VERSION marker,
        // correctly answered "already up to date", and the two called each
        // other liars on the same box.
        //
        // VERSION is also the RIGHT question: it is the commit the
        // published binaries were built from, so comparing against it
        // means "what I would install differs from what I run" rather than
        // "some ref somewhere moved".
        let version_url = format!("{repo_url}/releases/download/rolling/VERSION");
        let probe = tokio::process::Command::new("/usr/bin/curl")
            .args(["-fsSL", "--max-time", "15", &version_url])
            .output()
            .await;

        let mut status = hyperion_types::UpdateStatus {
            current_sha: self.current_git_sha.clone(),
            latest_sha: String::new(),
            latest_tag: "rolling".into(),
            latest_built: String::new(),
            last_checked_at: now,
            update_available: false,
            message: String::new(),
        };

        match probe {
            Ok(out) if out.status.success() => {
                // The marker is a bare 40-char sha plus a newline.
                let raw = String::from_utf8_lossy(&out.stdout);
                let sha = raw.trim().to_string();
                // Guard the shape: a 404 page or a CDN error page would
                // otherwise become a "latest version" that never matches,
                // which is the same permanent-nag failure in a new coat.
                let sha = if sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
                    sha
                } else {
                    String::new()
                };
                if sha.is_empty() {
                    status.message =
                        "probe failed: the rolling release has no usable VERSION marker".into();
                } else {
                    status.latest_sha = sha;
                    let (avail, msg) = compare_git_shas(&status.current_sha, &status.latest_sha);
                    if avail {
                        // SHAs differ. Before flagging "update available",
                        // check whether `current` is actually a descendant
                        // of `latest` — i.e. we're *ahead* of the rolling
                        // tag, not behind. This is the common false
                        // positive: an operator runs `update.sh` which
                        // `git pull`s main, then GHA hasn't yet moved the
                        // `rolling` tag to the new HEAD. Without this
                        // check the dashboard nags about an update that
                        // doesn't exist.
                        match ahead_of_remote(&status.latest_sha).await {
                            AheadResult::AheadOrEqual => {
                                status.update_available = false;
                                status.message = "up to date (ahead of rolling tag)".into();
                            }
                            AheadResult::Behind => {
                                status.update_available = true;
                                status.message = msg.to_string();
                            }
                            AheadResult::Unknown => {
                                // No local git — fall back to the naive
                                // string compare. Better to nag a dev box
                                // occasionally than to silently miss a
                                // real production update.
                                status.update_available = avail;
                                status.message = msg.to_string();
                            }
                        }
                    } else {
                        status.update_available = false;
                        status.message = msg.to_string();
                    }
                }
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                status.message = format!(
                    "probe failed: git ls-remote exit {}: {stderr}",
                    out.status.code().unwrap_or(-1),
                );
            }
            Err(e) => {
                status.message = format!("probe failed: spawn git: {e}");
            }
        }

        // Persist into cache (write lock) regardless of probe outcome —
        // a recent failure is still worth caching so we don't spam the
        // upstream on every page load when the network's flaky.
        {
            let mut w = self.update_cache.write().await;
            *w = Some(status.clone());
        }
        Ok(status)
    }

    /// Start an apt-get install + systemctl enable for a whitelisted
    /// service. Returns immediately after spawning the background
    /// task — operator polls `service_install_status()` for the live
    /// log tail.
    ///
    /// Previously this awaited the apt-get call up to 5 min,
    /// blocking the operator's browser. apt-get also runs with
    /// `-qq` which suppressed the actual error reason; the operator
    /// got "Sub-process /usr/bin/dpkg returned an error code (1)"
    /// with no clue what went wrong. The async refactor lets us
    /// drop `-qq` (we now stream output), capture stdout+stderr in
    /// the slot, and surface the real failure.
    pub async fn service_install(&self, name: String) -> Result<(), RpcError> {
        let pkg =
            Self::service_whitelist_for(&name, false).ok_or_else(|| RpcError::Validation {
                message: format!("service `{name}` is not on the install whitelist"),
            })?;
        {
            let guard = self.service_install_progress.lock().await;
            if guard.state == "running" {
                return Err(RpcError::Conflict {
                    message: format!(
                        "another service install ({} → {}) is already running on this node; \
                         wait for it to finish — apt would dpkg-lock anyway.",
                        guard.service_name, guard.pkg
                    ),
                });
            }
        }
        // Preflight: apt fails with a confusing "Read-only file system"
        // error when /usr is RO (immutable VPS / snap / unprivileged
        // LXC). Detect upfront + refuse with a clear message instead
        // of spending 30s on apt-get only to surface dpkg noise.
        if let Some(rw_err) = check_usr_writable().await {
            return Err(RpcError::Conflict { message: rw_err });
        }
        let now = now_secs();
        {
            let mut g = self.service_install_progress.lock().await;
            *g = hyperion_types::ServiceInstallStatus {
                service_name: name.clone(),
                pkg: pkg.to_string(),
                started_at: now,
                finished_at: 0,
                state: "running".into(),
                log_tail: String::new(),
                exit_code: 0,
                action: "install".into(),
            };
        }
        // Audit-log the START. The finish state is audited separately
        // by the background task below.
        self.append_audit(
            "service.install.start",
            None,
            &serde_json::json!({"name": name, "pkg": pkg}).to_string(),
            "ok",
        )
        .await;
        // Spawn detached — caller returns immediately, UI polls.
        let slot = self.service_install_progress.clone();
        let svc_name = name.clone();
        let pkg_owned = pkg.to_string();
        tokio::spawn(async move {
            run_service_install(slot, svc_name, pkg_owned).await;
        });
        Ok(())
    }

    /// Current state of the most-recent / in-progress service-install
    /// job. Cheap — clones the in-memory slot. Empty
    /// ServiceInstallStatus (state="" / started_at=0) when no
    /// install has ever run.
    pub async fn service_install_status(
        &self,
    ) -> Result<hyperion_types::ServiceInstallStatus, RpcError> {
        Ok(self.service_install_progress.lock().await.clone())
    }

    /// Start the node update job on THIS node: the operating-system upgrade
    /// and/or `update.sh`, in that order.
    ///
    /// The job runs as its own transient systemd unit (see
    /// `hyperion_adapters::node_update` for why it must not be a child of the
    /// agent), so it survives the agent restart `update.sh` performs, and its
    /// state is read back from disk by [`Self::node_update_status`].
    ///
    /// Refuses while a job is already running — one per node.
    pub async fn node_update_run(
        &self,
        do_apt: bool,
        do_hyperion: bool,
        safe: bool,
    ) -> Result<i64, RpcError> {
        use hyperion_adapters::node_update;
        if !do_apt && !do_hyperion {
            return Err(RpcError::Validation {
                message: "node_update_run: nothing to do (do_apt=false, do_hyperion=false)".into(),
            });
        }
        if node_update::is_running().await {
            let since = node_update::status()
                .await
                .spec
                .map(|s| s.started_at)
                .unwrap_or_default();
            return Err(RpcError::Conflict {
                message: format!(
                    "another update is already running on this node (started at unix:{since}). \
                     Wait for it to finish before starting a new one."
                ),
            });
        }
        let spec = node_update::JobSpec {
            started_at: now_secs(),
            do_apt,
            do_hyperion,
            safe,
        };
        let started = node_update::start(&spec).await;
        self.append_audit(
            "node.update.start",
            None,
            &serde_json::json!({"do_apt": do_apt, "do_hyperion": do_hyperion, "safe": safe})
                .to_string(),
            if started.is_ok() { "ok" } else { "error" },
        )
        .await;
        started.map_err(|e| RpcError::Internal_with(format!("start node update: {e}")))?;
        Ok(spec.started_at)
    }

    /// The current (or last) node update job, read from disk and systemd —
    /// never from agent memory, which `update.sh` wipes by restarting us.
    pub async fn node_update_status(&self) -> Result<hyperion_types::NodeUpdateStatus, RpcError> {
        use hyperion_adapters::node_update::{self, JobState};
        let st = node_update::status().await;
        let spec = st.spec.unwrap_or_default();
        let (state, finished_at, exit_code) = match st.state {
            JobState::Never => ("idle", 0, 0),
            JobState::Running => ("running", 0, 0),
            JobState::Finished {
                exit_code: 0,
                finished_at,
            } => ("succeeded", finished_at, 0),
            JobState::Finished {
                exit_code,
                finished_at,
            } => ("failed", finished_at, exit_code),
            JobState::Interrupted => ("interrupted", 0, -1),
        };
        // An OS upgrade just changed what is installed, so the stored update
        // check is wrong in both halves. Re-check once per finished job, with
        // the strict refresh (the job's own `apt-get update` is not what the
        // panel trusts). Done here, lazily, because the job outlives the agent
        // that started it — nothing is left waiting on it to finish.
        if spec.do_apt && finished_at > 0 {
            let done = hyperion_state::node_kv::get(&self.pool, NODE_UPDATE_RECHECKED_KV)
                .await
                .ok()
                .flatten()
                .and_then(|v| v.parse::<i64>().ok());
            if done != Some(spec.started_at) {
                let _ = hyperion_state::node_kv::set(
                    &self.pool,
                    NODE_UPDATE_RECHECKED_KV,
                    &spec.started_at.to_string(),
                    now_secs(),
                )
                .await;
                let pool = self.pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = os_updates_check_in(&pool, true).await {
                        tracing::warn!(error = %e, "os updates re-check after node update failed");
                    }
                });
            }
        }
        Ok(hyperion_types::NodeUpdateStatus {
            started_at: spec.started_at,
            finished_at,
            state: state.into(),
            do_apt: spec.do_apt,
            do_hyperion: spec.do_hyperion,
            log_tail: st.log_tail,
            exit_code,
        })
    }
    /// Setup wizard: start installing the chosen server software.
    pub async fn setup_stack_start(
        &self,
        components: Vec<String>,
        ftp_port: u16,
    ) -> Result<i64, RpcError> {
        use hyperion_adapters::setup_stack;
        let components = setup_stack::normalize_components(&components)
            .map_err(|message| RpcError::Validation { message })?;
        // apt inside an install and apt inside an update would fight over the
        // dpkg lock; the second just waits, and the operator sees nothing move.
        if self.adapters.package_job_running().await {
            return Err(RpcError::Conflict {
                message: "the software install or a server update is already running — \
                          wait for it to finish"
                    .into(),
            });
        }
        let started_at = now_secs();
        let spec = setup_stack::JobSpec {
            started_at,
            components: components.clone(),
            ftp_port: if ftp_port == 0 { 21 } else { ftp_port },
        };
        self.adapters
            .setup_stack_start(&spec)
            .await
            .map_err(RpcError::from)?;
        self.append_audit(
            "setup.stack.start",
            None,
            &serde_json::json!({"components": components, "ftp_port": spec.ftp_port}).to_string(),
            "ok",
        )
        .await;
        Ok(started_at)
    }

    /// Setup wizard: where the software install stands.
    pub async fn setup_stack_status(&self) -> Result<hyperion_types::SetupStackStatus, RpcError> {
        use hyperion_adapters::setup_stack::JobState;
        let st = self.adapters.setup_stack_status().await;
        let spec = st.spec.unwrap_or_default();
        let (state, finished_at, exit_code) = match st.state {
            JobState::Never => ("idle", 0, 0),
            JobState::Running => ("running", 0, 0),
            JobState::Finished {
                exit_code: 0,
                finished_at,
            } => ("succeeded", finished_at, 0),
            JobState::Finished {
                exit_code,
                finished_at,
            } => ("failed", finished_at, exit_code),
            JobState::Interrupted => ("interrupted", 0, -1),
        };
        Ok(hyperion_types::SetupStackStatus {
            state: state.into(),
            started_at: spec.started_at,
            finished_at,
            exit_code,
            components: st
                .progress
                .into_iter()
                .map(|(name, state)| hyperion_types::SetupComponentProgress { name, state })
                .collect(),
            log_tail: st.log_tail,
        })
    }

    /// Setup wizard: hostname, time zone and ACME contact. Everything is
    /// validated before anything is changed, so a refusal leaves the box as
    /// it was. Returns whether the agent is about to restart.
    pub async fn setup_system_apply(
        &self,
        hostname: String,
        timezone: String,
        contact_email: String,
    ) -> Result<bool, RpcError> {
        use hyperion_adapters::system_identity as ident;
        let hostname = hostname.trim().to_string();
        let timezone = timezone.trim().to_string();
        let contact_email = contact_email.trim().to_string();

        let new_host = if hostname.is_empty() {
            None
        } else {
            let h = ident::validate_hostname(&hostname)
                .map_err(|message| RpcError::Validation { message })?;
            (h != self.adapters.current_hostname().await).then_some(h)
        };
        if new_host.is_some() {
            let n = hostings::count_all(&self.pool)
                .await
                .map_err(|e| RpcError::Internal_with(format!("count hostings: {e}")))?;
            if n > 0 {
                return Err(RpcError::Conflict {
                    message: format!(
                        "this server already hosts {n} site(s) — its hostname is the node id \
                         they are filed under, so it can no longer be changed here"
                    ),
                });
            }
        }
        let new_tz = if timezone.is_empty() {
            None
        } else {
            let tz = ident::validate_timezone(&timezone)
                .map_err(|message| RpcError::Validation { message })?;
            (tz != self.adapters.current_timezone().await).then_some(tz)
        };
        let new_email = if contact_email.is_empty() {
            None
        } else {
            let lc = contact_email.to_lowercase();
            let (local, domain) = contact_email.split_once('@').unwrap_or(("", ""));
            if local.is_empty()
                || !domain.contains('.')
                || contact_email.len() > 254
                || contact_email.chars().any(|c| c.is_whitespace() || c == '"')
                || lc.ends_with("@example.com")
                || lc.ends_with("@example.org")
                || lc.ends_with("@example.net")
                || lc.ends_with("@hyperion.invalid")
            {
                return Err(RpcError::Validation {
                    message: format!(
                        "\"{contact_email}\" is not an address Let's Encrypt will accept — use a real mailbox"
                    ),
                });
            }
            Some(contact_email)
        };

        if let Some(h) = &new_host {
            self.adapters
                .apply_hostname(h)
                .await
                .map_err(RpcError::from)?;
        }
        if let Some(tz) = &new_tz {
            self.adapters
                .apply_timezone(tz)
                .await
                .map_err(RpcError::from)?;
        }
        if let Some(email) = &new_email {
            let path = self
                .agent_config_path
                .as_ref()
                .ok_or_else(|| RpcError::Validation {
                    message: "agent_config_path not wired — cannot save the contact email".into(),
                })?;
            crate::config_persist::set_string(path, "acme", "contact_email", email)
                .map_err(|e| RpcError::Internal_with(format!("config write failed: {e}")))?;
        }
        self.append_audit(
            "setup.system.apply",
            None,
            &serde_json::json!({
                "hostname": new_host,
                "timezone": new_tz,
                "contact_email_changed": new_email.is_some(),
            })
            .to_string(),
            "ok",
        )
        .await;

        // The ACME contact is read once at boot, and so is the local time
        // zone for everything scheduled. Restart so the next certificate
        // (usually the panel's own, one step later) and the next backup run
        // use what was just set. Delayed so this reply gets out first — the
        // same approach as `email_config_set`.
        let restart = new_email.is_some() || new_tz.is_some() || new_host.is_some();
        if restart {
            self.adapters.schedule_self_restart();
        }
        Ok(restart)
    }

    /// Status of every system service Hyperion depends on. Run via
    /// `systemctl is-active/is-enabled` so the answer is always live
    /// — we don't cache because operator restarts/disables happen
    /// out-of-band.
    ///
    /// "Critical" services (severity=error if down): nginx,
    /// hyperion-agent, hyperion-web.
    /// "Warning" services (severity=warn if down): mariadb, postgresql,
    /// any installed php-fpm version, vsftpd (FTP optional).
    /// "Missing optional" (severity=info): php-fpm units / vsftpd
    /// that aren't installed.
    pub async fn services_health(&self) -> Result<hyperion_types::ServicesHealth, RpcError> {
        // Workers don't run hyperion-web — only the master does. On a
        // worker node we'd otherwise flag hyperion-web as a "critical
        // service down" on every page load, which is confusing
        // ("CRITICAL: missing thing that's not supposed to be here").
        // Drop the entry entirely on workers so the table reflects
        // what the operator actually needs to care about.
        let is_worker = self.is_worker_node();
        let critical: Vec<(&str, &str)> = if is_worker {
            vec![
                ("nginx", "nginx (web server)"),
                ("hyperion-agent", "hyperion-agent (RPC daemon)"),
            ]
        } else {
            vec![
                ("nginx", "nginx (web server)"),
                ("hyperion-agent", "hyperion-agent (RPC daemon)"),
                ("hyperion-web", "hyperion-web (admin UI)"),
            ]
        };
        let optional: &[(&str, &str)] = &[
            ("mariadb", "MariaDB (database)"),
            ("postgresql", "PostgreSQL (database)"),
            ("redis-server", "Redis (object cache)"),
            ("vsftpd", "vsftpd (FTP)"),
            // MTA — provides /usr/sbin/sendmail for PHP mail().
            // When down/missing every hosted site's mail() returns
            // false and the per-hosting "Mail sent by this site"
            // log stays empty. Surface here so the operator can
            // see "MTA down" at a glance instead of grep'ing the
            // wrapper's stderr breadcrumbs.
            ("postfix", "postfix (MTA for PHP mail)"),
            ("php8.1-fpm", "PHP 8.1 FPM"),
            ("php8.2-fpm", "PHP 8.2 FPM"),
            ("php8.3-fpm", "PHP 8.3 FPM"),
            ("php8.4-fpm", "PHP 8.4 FPM"),
            // ClamAV malware scanner. Tracked by its freshclam service
            // (the DB updater); installing it provides the `clamscan` the
            // per-hosting File-integrity scan uses. Absent until installed,
            // which is exactly when the integrity card says "Install
            // clamav on the node" — this is where the Install button is.
            ("clamav-freshclam", "ClamAV (malware scanner)"),
        ];
        // Fan ALL the probes out in parallel — was serial loop +
        // serial(rich + present) per unit, ~10 units × ~100 ms =
        // up to a full second of page-render latency. Now bounded
        // by the slowest single probe.
        let mut tasks: Vec<_> = Vec::with_capacity(critical.len() + optional.len());
        for (unit, label) in critical.iter().copied() {
            tasks.push(tokio::spawn(async move {
                let (status, present) = tokio::join!(
                    hyperion_adapters::systemctl_status_rich(unit),
                    hyperion_adapters::systemctl_unit_present(unit),
                );
                (unit, label, true, status, present)
            }));
        }
        for (unit, label) in optional.iter().copied() {
            tasks.push(tokio::spawn(async move {
                let (status, present) = tokio::join!(
                    hyperion_adapters::systemctl_status_rich(unit),
                    hyperion_adapters::systemctl_unit_present(unit),
                );
                (unit, label, false, status, present)
            }));
        }
        // One dpkg-query for every package we know the unit of, and one read
        // of /proc/uptime to turn systemd's monotonic stamps into wall time.
        let pkgs: Vec<&str> = critical
            .iter()
            .chain(optional.iter())
            .filter_map(|(u, _)| hyperion_adapters::unit_package(u))
            .collect();
        let versions = hyperion_adapters::dpkg_versions(&pkgs).await;
        let uptime = hyperion_adapters::uptime_secs();
        let now = now_secs();
        let mut services: Vec<hyperion_types::ServiceHealth> = Vec::new();
        let mut critical_down = 0usize;
        let mut warn_down = 0usize;
        for h in tasks {
            let Ok((unit, label, is_critical, status, mut present)) = h.await else {
                continue;
            };
            if status.active || status.enabled {
                present = true;
            }
            let mut sub = status.sub_state.clone();
            // "masked" is operator-intentional — surface it
            // distinctly so the operator doesn't see it as a
            // failure to fix.
            let masked = status.unit_file_state == "masked";
            if masked {
                sub = "masked".into();
            } else if !present {
                sub = if is_critical {
                    "missing".into()
                } else {
                    "not installed".into()
                };
            }
            let transient = status.transient();
            let severity = if masked {
                // masked = operator decided this shouldn't run.
                // Don't count it against health.
                "info".to_string()
            } else if !present {
                if is_critical {
                    critical_down += 1;
                    "error".to_string()
                } else {
                    "info".to_string()
                }
            } else if !status.active {
                if is_critical {
                    critical_down += 1;
                    "error".to_string()
                } else {
                    warn_down += 1;
                    "warn".to_string()
                }
            } else {
                "ok".to_string()
            };
            services.push(hyperion_types::ServiceHealth {
                name: unit.to_string(),
                label: label.to_string(),
                active: status.active,
                enabled: status.enabled,
                present,
                sub_state: sub,
                severity,
                since: {
                    let mono = if status.active {
                        status.active_enter_mono_us
                    } else {
                        status.inactive_enter_mono_us
                    };
                    match (mono, uptime) {
                        (Some(m), Some(up)) if present => {
                            Some(hyperion_adapters::boot_relative_to_unix(m, now, up))
                        }
                        _ => None,
                    }
                },
                memory_bytes: status.memory_bytes.filter(|_| status.active),
                main_pid: status.main_pid,
                restarts: status.restarts.filter(|_| present),
                result: status.result.clone().filter(|_| present),
                version: hyperion_adapters::unit_package(unit)
                    .and_then(|p| versions.get(p).cloned()),
                active_state: status.active_state,
                transient,
            });
        }
        // Preserve operator-meaningful display order — critical first,
        // then optional in the order they were declared. Sorted by
        // the position in the source lists.
        let order: std::collections::HashMap<&str, usize> = critical
            .iter()
            .chain(optional.iter())
            .enumerate()
            .map(|(i, (u, _))| (*u, i))
            .collect();
        services.sort_by_key(|s| *order.get(s.name.as_str()).unwrap_or(&usize::MAX));
        Ok(hyperion_types::ServicesHealth {
            services,
            critical_down,
            warn_down,
        })
    }
}

/// Cache TTL for the GitHub release check. One hour is enough to
/// keep the dashboard banner fresh without hammering the API or
/// hitting their unauthenticated rate limit (60 req/hour/IP).
pub const UPDATE_CHECK_TTL_SECS: i64 = 3600;

/// How much of a service job's output the status slot keeps.
const LOG_TAIL_BYTES: usize = 8 * 1024;

/// Append one line to a service job's log tail, keeping the newest
/// `LOG_TAIL_BYTES`.
pub(super) async fn append_line(
    slot: &std::sync::Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
    line: &str,
) {
    let mut g = slot.lock().await;
    g.log_tail.push_str(line);
    g.log_tail.push('\n');
    if g.log_tail.len() > LOG_TAIL_BYTES {
        let drop = g.log_tail.len() - LOG_TAIL_BYTES;
        let mut cut = drop;
        while !g.log_tail.is_char_boundary(cut) && cut < g.log_tail.len() {
            cut += 1;
        }
        g.log_tail.drain(..cut);
    }
}

/// Run one command of a service job, streaming its output into the slot.
/// Returns the exit code (127 = could not spawn).
pub(super) async fn run_one(
    slot: &std::sync::Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
    label: &str,
    cmd: &str,
    args: &[&str],
) -> i32 {
    use tokio::io::AsyncBufReadExt;
    append_line(
        slot,
        &format!("──── {label}: {cmd} {} ────", args.join(" ")),
    )
    .await;
    let mut child = match tokio::process::Command::new(cmd)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            append_line(slot, &format!("spawn {cmd} failed: {e}")).await;
            return 127;
        }
    };
    if let Some(stdout) = child.stdout.take() {
        let s = slot.clone();
        let label = label.to_string();
        tokio::spawn(async move {
            let r = tokio::io::BufReader::new(stdout);
            let mut lines = r.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                append_line(&s, &format!("[{label}] {line}")).await;
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let s = slot.clone();
        let label = label.to_string();
        tokio::spawn(async move {
            let r = tokio::io::BufReader::new(stderr);
            let mut lines = r.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                append_line(&s, &format!("[{label}!] {line}")).await;
            }
        });
    }
    match child.wait().await {
        Ok(status) => status.code().unwrap_or(-1),
        Err(e) => {
            append_line(slot, &format!("wait {label} failed: {e}")).await;
            -1
        }
    }
}

/// Drive a service-install job (apt-get install + systemctl
/// enable --now) and stream output into the shared status slot.
///
/// Notable changes vs. the old synchronous service_install path:
///   - Drops `-qq` from apt-get so we actually see the real
///     diagnostic. The old "dpkg returned an error code (1)"
///     bubble-up was useless — the actual cause (postinst script
///     failure, missing dep, etc.) was suppressed.
///   - Uses `-q -o Dpkg::Options::=--force-confold` so apt is
///     non-interactive but still emits status lines.
///   - Streams stdout/stderr line-by-line into log_tail (capped
///     at ~8 kB) so the UI can show live progress instead of
///     hanging the operator's browser for minutes.
pub(super) async fn run_service_install(
    slot: std::sync::Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
    service_name: String,
    pkg: String,
) {
    // Per-package debconf preseeding — without this, packages with
    // interactive postinst questions (postfix's "type of mail server",
    // "mailname", iptables-persistent, mariadb-server root password,
    // etc.) hang forever even with DEBIAN_FRONTEND=noninteractive
    // because the question is mandatory.
    if pkg == "postfix" {
        // Internet Site = direct MX delivery. Same default as
        // update.sh's MTA install block. Operators on networks
        // where outbound TCP/25 is blocked can switch to smart-host
        // mode manually after install (postconf -e relayhost=...).
        let mailname = match tokio::process::Command::new("/bin/hostname")
            .arg("-f")
            .output()
            .await
        {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    "localhost".to_string()
                } else {
                    s
                }
            }
            _ => "localhost".to_string(),
        };
        let selections = format!(
            "postfix postfix/main_mailer_type select Internet Site\n\
             postfix postfix/mailname string {mailname}\n",
        );
        // Pipe selections via stdin to debconf-set-selections. The
        // child process exits 0 even if input is malformed (it just
        // doesn't apply), so we treat any non-zero as a real spawn
        // failure rather than a config problem.
        let mut child = match tokio::process::Command::new("/usr/bin/debconf-set-selections")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                append_line(&slot, &format!("debconf-set-selections spawn failed: {e}")).await;
                let mut g = slot.lock().await;
                g.state = "failed".to_string();
                g.finished_at = now_secs();
                g.exit_code = 127;
                return;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(selections.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }
        let _ = child.wait().await;
        append_line(
            &slot,
            &format!("──── preseeded postfix: Internet Site, mailname={mailname} ────"),
        )
        .await;
    }

    // Step 1: apt-get install. Hard-cap at 10 min via timeout above
    // (tokio::spawn'd, so we wrap with timeout here). `pkg` may be a
    // whitespace-separated SET (PHP installs pull -cli + the WordPress
    // extension bundle), so split it into individual apt args —
    // otherwise apt-get tries to install one package literally named
    // "php8.3-fpm php8.3-cli …" and fails.
    let mut apt_args: Vec<&str> = vec![
        "install",
        "-y",
        "-q",
        "-o",
        "Dpkg::Options::=--force-confold",
    ];
    apt_args.extend(pkg.split_whitespace());
    let install_code = tokio::time::timeout(
        std::time::Duration::from_secs(10 * 60),
        run_one(&slot, "apt-install", "/usr/bin/apt-get", &apt_args),
    )
    .await
    .unwrap_or_else(|_| {
        // The timeout fired — log it and treat as failure.
        let s = slot.clone();
        // Fire-and-forget: the spawned task runs; we deliberately drop the handle.
        tokio::spawn(async move {
            append_line(
                &s,
                "apt-install timed out after 10 min — check dpkg lock or mirror outage",
            )
            .await;
        });
        124 // GNU `timeout`-style exit code
    });

    let mut final_code = install_code;

    // Step 2: systemctl enable --now (only if install succeeded).
    if install_code == 0 {
        final_code = run_one(
            &slot,
            "systemctl-enable",
            "/usr/bin/systemctl",
            &["enable", "--now", &service_name],
        )
        .await;
    }

    let final_state = if final_code == 0 {
        "succeeded"
    } else {
        "failed"
    };
    if final_code == 0 {
        if let Some(c) = hyperion_adapters::setup_stack::component_for_service(&service_name) {
            if let Err(e) = hyperion_adapters::setup_stack::record_component(c).await {
                tracing::warn!(error = %e, component = c, "could not record installed component");
            }
        }
    }
    let mut g = slot.lock().await;
    g.state = final_state.to_string();
    g.finished_at = now_secs();
    g.exit_code = final_code;
    tracing::info!(
        service = %service_name,
        pkg = %pkg,
        exit_code = final_code,
        state = final_state,
        "service install job finished"
    );
}

/// Result of `ahead_of_remote` — whether the local HEAD is at or
/// past the remote SHA, behind it, or whether we couldn't tell
/// because there's no local git checkout to inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AheadResult {
    /// Local HEAD == remote OR remote is reachable from HEAD via
    /// first-parent ancestry. We're at-or-after the remote.
    AheadOrEqual,
    /// Local HEAD is behind the remote — a `git pull` would
    /// fast-forward. This is the "update available" case.
    Behind,
    /// No usable local git checkout (typical: `cargo install`
    /// without a clone, or a dev machine where the binary's build
    /// SHA doesn't correspond to /opt/hyperion/.git). Caller should
    /// fall back to the naive string compare.
    Unknown,
}

/// Check whether `/opt/hyperion`'s git HEAD is at or past `latest`.
///
/// The classic false positive this fixes: `update.sh` does
/// `git pull origin main` and rebuilds. The just-built agent's
/// `current_git_sha` is now main HEAD, which may be ahead of the
/// `rolling` tag because the GitHub Action that fast-forwards the
/// tag hasn't run yet. Without this check the dashboard nags about
/// "update available" pointing at a SHA the operator just installed
/// past.
///
/// Runs as the agent (typically root), reads `/opt/hyperion/.git`
/// directly via `git -C /opt/hyperion merge-base --is-ancestor
/// <latest> HEAD`. Exit 0 means "yes, latest is reachable from HEAD"
/// → we're at-or-after latest. Exit 1 means the opposite. Anything
/// else → Unknown.
pub(super) async fn ahead_of_remote(latest: &str) -> AheadResult {
    // If /opt/hyperion/.git doesn't exist, we can't tell — common on
    // dev boxes where the binary was `cargo run`'d from somewhere
    // else. Return Unknown so the caller falls back to string compare.
    if !std::path::Path::new("/opt/hyperion/.git").exists() {
        return AheadResult::Unknown;
    }
    // Trim noise the caller might have included — exact 40-char hex
    // please.
    let latest = latest.trim();
    if latest.is_empty() || !latest.chars().all(|c| c.is_ascii_hexdigit()) {
        return AheadResult::Unknown;
    }
    let out = tokio::process::Command::new("/usr/bin/git")
        .args([
            "-C",
            "/opt/hyperion",
            "merge-base",
            "--is-ancestor",
            latest,
            "HEAD",
        ])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => AheadResult::AheadOrEqual,
        Ok(o) if o.status.code() == Some(1) => AheadResult::Behind,
        // Status 128 = "fatal: Not a valid commit name" — the remote
        // SHA isn't in our local object store. That happens after a
        // shallow clone or after a force-push. Try `git fetch` once
        // to make the SHA reachable, then retry.
        Ok(o) if o.status.code() == Some(128) => {
            match tokio::process::Command::new("/usr/bin/git")
                .args(["-C", "/opt/hyperion", "fetch", "--tags", "origin"])
                .output()
                .await
            {
                Ok(f) if !f.status.success() => tracing::debug!(
                    stderr = %String::from_utf8_lossy(&f.stderr).trim(),
                    "git fetch during version check failed — version may read Unknown"
                ),
                Err(e) => {
                    tracing::debug!(error = %e, "git fetch during version check could not spawn")
                }
                _ => {}
            }
            let retry = tokio::process::Command::new("/usr/bin/git")
                .args([
                    "-C",
                    "/opt/hyperion",
                    "merge-base",
                    "--is-ancestor",
                    latest,
                    "HEAD",
                ])
                .output()
                .await;
            match retry {
                Ok(o) if o.status.success() => AheadResult::AheadOrEqual,
                Ok(o) if o.status.code() == Some(1) => AheadResult::Behind,
                _ => AheadResult::Unknown,
            }
        }
        _ => AheadResult::Unknown,
    }
}

/// Decide whether `current` and `latest` git SHAs identify the same
/// commit. Both sides are lowercased, then compared on the shorter
/// length (a 7-char short SHA vs. a 40-char full SHA from the remote
/// must match if the short is a prefix of the long).
///
/// "dev-unknown" / empty `current` always reports "no update" — a
/// developer running an unversioned local build shouldn't see a nag
/// banner just because their SHA isn't known.
///
/// Returns (`update_available`, `message_suffix`).
pub fn compare_git_shas(current: &str, latest: &str) -> (bool, &'static str) {
    let cur = current.to_lowercase();
    let lat = latest.to_lowercase();
    if cur == "dev-unknown" || cur.is_empty() {
        return (false, "running an unversioned dev build");
    }
    if lat.is_empty() {
        return (false, "probe failed: empty latest sha");
    }
    let n = cur.len().min(lat.len());
    if n > 0 && cur[..n] == lat[..n] {
        (false, "up to date")
    } else {
        (true, "update available")
    }
}

/// Which `systemctl` verbs the Services page may send, and for which units.
/// Stop and disable are refused for the panel's own path — nginx serves it,
/// hyperion-web renders it, hyperion-agent carries the order — because
/// either leaves the operator locked out with no button to undo it.
pub(crate) fn service_control_allowed(name: &str, action: &str) -> Result<(), String> {
    if !matches!(action, "start" | "stop" | "enable" | "disable") {
        return Err(format!("unknown service action `{action}`"));
    }
    let core = matches!(name, "nginx" | "hyperion-web" | "hyperion-agent");
    if core && matches!(action, "stop" | "disable") {
        return Err(format!(
            "refusing to {action} `{name}` from the panel — it would cut off access to the panel itself; use SSH"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod service_control_tests {
    use super::service_control_allowed;

    #[test]
    fn core_units_cannot_be_stopped_or_disabled() {
        for unit in ["nginx", "hyperion-web", "hyperion-agent"] {
            assert!(service_control_allowed(unit, "stop").is_err());
            assert!(service_control_allowed(unit, "disable").is_err());
        }
        assert!(service_control_allowed("nginx", "start").is_ok());
        assert!(service_control_allowed("nginx", "enable").is_ok());
        assert!(service_control_allowed("postfix", "stop").is_ok());
        assert!(service_control_allowed("postfix", "disable").is_ok());
    }

    #[test]
    fn only_four_verbs() {
        for bad in ["restart", "mask", "kill", "", "start; reboot"] {
            assert!(service_control_allowed("postfix", bad).is_err(), "{bad}");
        }
    }
}
