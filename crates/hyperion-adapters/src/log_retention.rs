//! The node-wide half of `[log_retention]`: how many days the logrotate
//! rules Hyperion writes keep, and the journald drop-in.
//!
//! The rules are written from several places (a vhost write ensures the WAF
//! rule, a pool write the slow-log rule, the CRS install the ModSecurity
//! one), none of which has the config at hand. They read the days from here;
//! the agent's retention tick sets them from agent.toml and then calls
//! [`reapply_rules`], so a saved change reaches every rule already on disk.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::AdapterError;

static WEB_DAYS: AtomicU32 = AtomicU32::new(hyperion_types::log_retention::DEFAULT_DAYS);
static FIREWALL_DAYS: AtomicU32 = AtomicU32::new(hyperion_types::log_retention::DEFAULT_DAYS);

/// Days the per-site and PHP slow-request logs are kept.
pub fn web_days() -> u32 {
    WEB_DAYS.load(Ordering::Relaxed)
}

/// Days the WAF and ModSecurity logs are kept.
pub fn firewall_days() -> u32 {
    FIREWALL_DAYS.load(Ordering::Relaxed)
}

/// Take the windows from a freshly read `[log_retention]`.
pub fn set(r: &hyperion_types::log_retention::LogRetention) {
    WEB_DAYS.store(r.web_days.max(1), Ordering::Relaxed);
    FIREWALL_DAYS.store(r.firewall_days.max(1), Ordering::Relaxed);
}

/// A daily logrotate block for `pattern`, keeping `days` rotations and
/// nothing older than `days` (`maxage`: a quiet log is not rotated every day,
/// so a count alone would keep its oldest copy for longer). `copytruncate`
/// throughout: nginx workers and FPM keep the file open, and the readers
/// (`waflog::read_new`) finish `<log>.1` after a truncation.
pub fn render_rule(pattern: &str, days: u32, extra: &[&str]) -> String {
    let days = days.max(1);
    let mut s = format!(
        "# Auto-managed by Hyperion. Retention: Settings → Log retention.\n\
         {pattern} {{\n\
         \x20   daily\n\
         \x20   rotate {days}\n\
         \x20   maxage {days}\n"
    );
    for line in extra {
        s.push_str(&format!("    {line}\n"));
    }
    s.push_str(
        "    missingok\n    notifempty\n    compress\n    delaycompress\n    copytruncate\n}\n",
    );
    s
}

/// Rewrite every rotation rule Hyperion has already put on this node with
/// the current windows. A rule that is absent belongs to a feature this node
/// does not use yet; whoever installs it writes it then.
pub async fn reapply_rules() {
    let rules = [
        (
            crate::nginx::WAF_LOGROTATE,
            crate::nginx::render_waf_logrotate(),
        ),
        (crate::modsec::LOGROTATE, crate::modsec::render_logrotate()),
        (
            crate::phpfpm::SLOWLOG_LOGROTATE,
            crate::phpfpm::render_slowlog_logrotate(),
        ),
    ];
    for (path, want) in rules {
        let Ok(current) = tokio::fs::read_to_string(path).await else {
            continue;
        };
        if current != want {
            if let Err(e) =
                crate::fs::atomic_write(std::path::Path::new(path), want.as_bytes(), 0o644).await
            {
                tracing::warn!(path, error = %e, "could not rewrite a logrotate rule");
            }
        }
    }
}

/// Where journald reads drop-ins from.
const JOURNALD_DIR: &str = "/etc/systemd/journald.conf.d";

/// journald drop-in carrying the system journal's retention.
pub const JOURNALD_DROPIN: &str = "/etc/systemd/journald.conf.d/hyperion-retention.conf";

/// The drop-in's text. `MaxRetentionSec` removes journal files whose newest
/// entry is older than this; journald checks it whenever it rotates or
/// vacuums, which it does at least daily (`MaxFileSec` defaults to a month,
/// so it is pinned to a day here too, or a quiet box would keep a whole
/// month in its one open file).
pub fn render_journald_dropin(days: u32) -> String {
    let days = days.max(1);
    format!(
        "# Auto-managed by Hyperion. Retention: Settings → Log retention.\n\
         [Journal]\n\
         MaxRetentionSec={days}day\n\
         MaxFileSec=1day\n"
    )
}

/// Write the journald drop-in and restart journald when it changed. Returns
/// whether it changed. A node without systemd (or a dev box) has no
/// `/etc/systemd` and is left alone.
pub async fn ensure_journald(days: u32) -> Result<bool, AdapterError> {
    if !std::path::Path::new("/etc/systemd").is_dir() {
        return Ok(false);
    }
    let want = render_journald_dropin(days);
    if tokio::fs::read_to_string(JOURNALD_DROPIN)
        .await
        .ok()
        .as_deref()
        == Some(want.as_str())
    {
        return Ok(false);
    }
    let dir = std::path::Path::new(JOURNALD_DIR);
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| AdapterError::Other(format!("create {}: {e}", dir.display())))?;
    crate::fs::atomic_write(
        std::path::Path::new(JOURNALD_DROPIN),
        want.as_bytes(),
        0o644,
    )
    .await?;
    // journald reads its config only at start. A restart keeps the stream
    // connections of running services (they live in its fd store).
    crate::cmd::run("/usr/bin/systemctl", &["restart", "systemd-journald"]).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_keeps_exactly_the_window() {
        let r = render_rule("/var/log/x/*.log", 14, &["maxsize 20M"]);
        assert!(r.contains("/var/log/x/*.log {\n"));
        assert!(r.contains("    rotate 14\n"));
        assert!(r.contains("    maxage 14\n"));
        assert!(r.contains("    maxsize 20M\n"));
        assert!(r.contains("    copytruncate\n"));
        assert!(r.ends_with("}\n"));
        assert!(!r.contains("rotate 7"));
        // Zero would delete on every run: floored to one day.
        assert!(render_rule("/a", 0, &[]).contains("rotate 1\n"));
    }

    #[test]
    fn journald_dropin_names_the_window_in_days() {
        let d = render_journald_dropin(30);
        assert!(d.contains("[Journal]\n"));
        assert!(d.contains("MaxRetentionSec=30day\n"));
        assert!(d.contains("MaxFileSec=1day\n"));
    }

    #[test]
    fn the_windows_follow_the_setting() {
        let r = hyperion_types::log_retention::LogRetention {
            web_days: 9,
            firewall_days: 11,
            ..Default::default()
        };
        set(&r);
        assert_eq!((web_days(), firewall_days()), (9, 11));
        assert!(crate::nginx::render_waf_logrotate().contains("rotate 11\n"));
        assert!(crate::modsec::render_logrotate().contains("rotate 11\n"));
        assert!(crate::phpfpm::render_slowlog_logrotate().contains("rotate 9\n"));
        set(&Default::default());
    }
}
