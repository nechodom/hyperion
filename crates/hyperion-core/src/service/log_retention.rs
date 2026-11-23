//! `[log_retention]`: every log this node writes is kept only as long as the
//! setting says. Read from agent.toml each time, so a save (or the settings
//! sync delivering one) applies at the next tick without a restart.
//!
//! What runs where:
//!   * files — each site's nginx logs are rotated here
//!     ([`hyperion_adapters::site_logs`]); the WAF, ModSecurity and PHP slow
//!     logs by logrotate rules whose day count the adapter re-renders; the
//!     system journal by a journald drop-in;
//!   * tables — the WAF samples, the ban history, the email log and the
//!     panel sessions' addresses are pruned in [`HostingService::log_retention_tick`];
//!     the audit log and the notifications on the scheduler tick that
//!     always pruned them.

use super::*;

const DAY: i64 = 86_400;

/// `[log_retention]` as agent.toml holds it, with `[cluster]
/// audit_retention_days` as the audit window's fallback. Unreadable file or
/// missing keys: 30 days.
pub(crate) fn read_log_retention(
    cfg_path: Option<&std::path::Path>,
) -> hyperion_types::log_retention::LogRetention {
    let doc = read_agent_doc(cfg_path);
    let section = doc.as_ref().and_then(|d| d.get("log_retention"));
    let legacy = doc
        .as_ref()
        .and_then(|d| d.get("cluster"))
        .and_then(|c| c.get("audit_retention_days"))
        .and_then(|v| v.as_integer());
    hyperion_types::log_retention::LogRetention::from_lookup(
        |k| section?.get(k)?.as_integer(),
        legacy,
    )
}

/// What one retention pass did, for the log line and the tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LogRetentionOutcome {
    pub site_logs_rotated: u32,
    pub site_logs_removed: u32,
    pub waf_samples: u64,
    pub bans: u64,
    pub emails: u64,
    pub sessions_scrubbed: u64,
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// The node's retention windows, read now.
    pub fn log_retention(&self) -> hyperion_types::log_retention::LogRetention {
        read_log_retention(self.agent_config_path.as_deref())
    }

    /// One retention pass: node-wide rules, every local site's logs, and the
    /// tables that hold addresses. Hourly; each step is best-effort, so one
    /// failure never keeps the others from running.
    pub async fn log_retention_tick(&self) -> LogRetentionOutcome {
        let r = self.log_retention();
        let now = now_secs();
        let mut out = LogRetentionOutcome::default();

        self.adapters.apply_log_retention(r).await;

        // Each site's own access.log / error.log.
        let sites = self.list().await.unwrap_or_default();
        let users = hyperion_state::hostings::system_users_by_hosting(&self.pool)
            .await
            .unwrap_or_default();
        let home_root = std::path::PathBuf::from(&self.paths.home_root);
        for s in &sites {
            let Some((user, _)) = users.get(s.id.as_str()) else {
                continue;
            };
            let (home, user, domain) = (home_root.clone(), user.clone(), s.domain.clone());
            let days = r.web_days;
            let res = tokio::task::spawn_blocking(move || {
                hyperion_adapters::site_logs::rotate(&home, &user, &domain, days, now)
            })
            .await;
            match res {
                Ok(Ok(o)) => {
                    out.site_logs_rotated += o.rotated;
                    out.site_logs_removed += o.removed;
                }
                Ok(Err(e)) => {
                    tracing::warn!(domain = %s.domain, error = %e, "site log rotation skipped")
                }
                Err(e) => {
                    tracing::warn!(domain = %s.domain, error = %e, "site log rotation panicked")
                }
            }
        }

        let cutoff = |days: u32| now - i64::from(days) * DAY;
        match hyperion_state::waf::prune_recent_before(&self.pool, cutoff(r.firewall_days)).await {
            Ok(n) => out.waf_samples = n,
            Err(e) => tracing::warn!(error = %e, "WAF sample retention failed"),
        }
        // The care report counts a period's bans by when they began, so
        // nothing of a period not reported yet goes (see
        // `care_report_open_floor`; a ban ending before the floor began
        // before it too).
        let bans_cutoff = match self.care_report_open_floor(now).await {
            Some(floor) => cutoff(r.bans_days).min(floor - DAY),
            None => cutoff(r.bans_days),
        };
        match hyperion_state::bans::prune_ended_before(&self.pool, bans_cutoff).await {
            Ok(n) => out.bans = n,
            Err(e) => tracing::warn!(error = %e, "ban history retention failed"),
        }
        match hyperion_state::email_log::prune_before(&self.pool, cutoff(r.email_days)).await {
            Ok(n) => out.emails = n,
            Err(e) => tracing::warn!(error = %e, "email log retention failed"),
        }
        match hyperion_state::web_sessions::scrub_before(&self.pool, cutoff(r.sessions_days)).await
        {
            Ok(n) => out.sessions_scrubbed = n,
            Err(e) => tracing::warn!(error = %e, "panel session retention failed"),
        }
        if out != LogRetentionOutcome::default() {
            tracing::info!(?out, "log retention");
        }
        out
    }
}
