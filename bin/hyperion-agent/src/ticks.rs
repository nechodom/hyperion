//! The agent's periodic background work. Every tick is a method on
//! `HostingService`; this module only decides WHEN each one runs.
//!
//! Offsets are staggered on purpose: the wp-cli sweeps (vuln 4 min,
//! integrity 6 min, care drift 7 min, care reports 9 min) would double the
//! load on the same sites if they started together, and none of them should
//! compete with provisioning right after boot.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

pub(crate) type Svc = Arc<hyperion_core::HostingService<hyperion_core::RealAdapter>>;

const MIN: u64 = 60;
const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

/// Run `work` once `offset_secs` after boot, then every `period_secs`.
///
/// A run that overruns its period delays the next one rather than being
/// followed by a burst of catch-up runs.
fn every<F, Fut>(svc: &Svc, offset_secs: u64, period_secs: u64, work: F)
where
    F: Fn(Svc) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let svc = svc.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(offset_secs)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(period_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            work(svc.clone()).await;
        }
    });
}

/// Start every periodic tick. Called once, after the service is built.
pub(crate) fn spawn_all(svc: &Svc, cert_renewal_window_days: i64) {
    spawn_scheduler(svc);
    spawn_auto_update(svc);
    spawn_rofs_watchdog(svc);
    spawn_stats(svc);
    spawn_net_sampler(svc);
    spawn_monitor(svc);
    spawn_php_mem_auto(svc);
    spawn_php_workers(svc);
    spawn_site_check(svc);
    // acme-dns responder: idle unless the master's operator enabled it in
    // Settings → HTTPS (the row is never synced to workers).
    crate::acme_dns::spawn(svc.pool.clone());
    spawn_cert_renewal(svc, cert_renewal_window_days.max(1));
    spawn_wp_defender(svc);
    spawn_wp_integrity(svc);
    spawn_billing_sweep(svc);
    spawn_package_enforce(svc);
    spawn_care_reports(svc);
    spawn_scheduled_backups(svc);
    spawn_snapshot_retention(svc);
    spawn_os_updates(svc);
}

/// Background-job closures run in the hyperion-web process, so a web
/// restart/redeploy (or a panicking closure / failed JobFinish) leaves the
/// row stuck in `running` forever — the /jobs card spins, the sidebar badge
/// over-counts, and retry is permanently blocked ("job is still running").
/// The reaper marks rows whose updated_at is older than this as failed.
/// JobReporter::step bumps updated_at, so a genuinely-live job is never
/// reaped.
const JOB_STALE_SECS: i64 = HOUR as i64; // 1h with no progress update

/// A backup run is `running` only during the local tar+hash (state flips to
/// `ok` before the off-site push), which even on a big site is under an
/// hour — so a run still `running` after 6h is a crash, not a slow backup.
const BACKUP_STALE_SECS: i64 = 6 * HOUR as i64;

/// The scheduler (expiry sweep) every 5 minutes, plus the cheap per-tick
/// sweeps riding on it. Before the loop starts it runs the once-at-boot
/// re-applies that must happen before anything else touches the same state.
fn spawn_scheduler(svc: &Svc) {
    let tick_svc = svc.clone();
    tokio::spawn(async move {
        reapply_on_boot(&tick_svc).await;

        // The firewall's default-drop rollback runs on its OWN loop, and a
        // tight one. The deadline is measured in minutes and the operator
        // is, by construction, possibly locked out while it runs — a
        // five-minute scheduler tick could hold a closed box shut for five
        // minutes longer than promised. Checked once immediately too: an
        // agent that restarted between arming and confirming would
        // otherwise leave the policy dropping with nobody watching, which
        // is the exact state the deadline exists to prevent.
        every(&tick_svc, 0, 15, |svc| async move {
            svc.firewall_rollback_tick().await;
        });

        let mut interval = tokio::time::interval(Duration::from_secs(5 * MIN));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            scheduler_pass(&tick_svc).await;
        }
    });
}

/// Once at startup, before the scheduler loop.
async fn reapply_on_boot(svc: &Svc) {
    if let Ok(n) = svc.jobs_reap_stale(JOB_STALE_SECS).await {
        if n > 0 {
            tracing::warn!(rows = n, "startup: reaped stale jobs");
        }
    }
    // Reap it so it stops spinning forever.
    if let Ok(n) = svc.backups_reap_stale(BACKUP_STALE_SECS).await {
        if n > 0 {
            tracing::warn!(rows = n, "startup: reaped stale backup runs");
        }
    }
    // Rebuild hyperion's firewall chain (presets, confirmed
    // default-drop) BEFORE the bans: nft rules do not survive a
    // reboot, and the ban infra would otherwise create the chain
    // first as plain accept.
    match svc.firewall_reapply_on_boot().await {
        Ok(s) if !s.is_empty() => tracing::info!(what=%s, "startup: firewall re-applied"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "startup: firewall re-apply failed"),
    }
    // Re-apply persisted IP bans to nftables ONCE at startup —
    // nft sets are in-memory and lost across reboots.
    match svc.bans_reapply_on_boot().await {
        Ok(n) if n > 0 => tracing::info!(bans = n, "startup: re-applied IP bans"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "startup: ban re-apply failed"),
    }
    // Re-push stored disk caps into the kernel ONCE at startup. A cap
    // saved while quotas needed a reboot to activate is otherwise never
    // written: the reboot brings the subsystem up (fstab) but the
    // per-user setquota limit was never applied. This delivers on the
    // "enforced after the node reboots" promise.
    match svc.quotas_reapply_on_boot().await {
        Ok(n) if n > 0 => tracing::info!(quotas = n, "startup: re-applied disk caps"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "startup: quota re-apply failed"),
    }
    // Re-assert Redis ACLs at startup. The rule set is only written
    // at enable/rotate, so a site keeps whatever rules were current
    // the day Redis was switched on — and when a missing grant is
    // what breaks the site, every existing site stays broken until
    // someone thinks to rotate the password.
    match svc.redis_acl_reassert_on_boot().await {
        Ok(n) if n > 0 => tracing::info!(sites = n, "startup: re-asserted Redis ACLs"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "startup: Redis ACL re-assert failed"),
    }
    // Disable the logins of sites that are suspended or in the trash.
    // Versions before this locked only the site user's password, which
    // left extra FTP logins and SFTP keys working on an offline site.
    match svc.offline_logins_lock_on_boot().await {
        Ok(n) if n > 0 => tracing::info!(
            sites = n,
            "startup: disabled every login of offline sites locked by an older version"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "startup: offline login lock failed"),
    }
    // Repoint any stale vsftpd local_root ONCE at startup, before the
    // loop. The loop skips its first tick, so without this an FTP
    // population broken by a bug the deploy just fixed would stay
    // broken for another five minutes after the upgrade.
    match svc.ftp_autoheal_tick().await {
        Ok(n) if n > 0 => tracing::info!(healed = n, "startup: repaired FTP roots"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "startup: FTP autoheal failed"),
    }
}

/// One five-minute scheduler pass.
async fn scheduler_pass(svc: &Svc) {
    match svc.scheduler_tick().await {
        Ok(n) if n > 0 => tracing::info!(processed = n, "scheduler tick"),
        Ok(_) => tracing::debug!("scheduler tick: nothing due"),
        Err(e) => tracing::warn!(error=%e, "scheduler tick failed"),
    }
    // Also sweep stale jobs each tick (cheap UPDATE).
    if let Ok(n) = svc.jobs_reap_stale(JOB_STALE_SECS).await {
        if n > 0 {
            tracing::warn!(rows = n, "reaped stale jobs");
        }
    }
    // …and stuck backup runs (crashed mid-tar), same cheap UPDATE.
    if let Ok(n) = svc.backups_reap_stale(BACKUP_STALE_SECS).await {
        if n > 0 {
            tracing::warn!(rows = n, "reaped stale backup runs");
        }
    }
    // Brute-force scan + auto-ban each tick.
    match svc.fail2ban_tick().await {
        Ok(n) if n > 0 => tracing::info!(banned = n, "fail2ban: new bans"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "fail2ban tick failed"),
    }
    // Enforce per-hosting disk-overage policy (notify / suspend +
    // auto-resume) for sites that crossed their disk hard cap.
    match svc.quota_enforce_tick().await {
        Ok(n) if n > 0 => tracing::info!(acted = n, "quota enforce: acted on sites"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "quota enforce tick failed"),
    }
    // Self-heal trees nginx cannot read (archive modes from an
    // import, a root-shell unzip). Probe is a few stats per
    // site; the chown/chmod runs only when it fires.
    match svc.permissions_autoheal_tick().await {
        Ok(n) if n > 0 => {
            tracing::warn!(healed = n, "permissions autoheal: repaired site trees")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "permissions autoheal tick failed"),
    }
    // Keep every WordPress site's sender pinned to its own
    // domain, and record the sends that fail. Silent when it
    // works; only mail that is STILL failing after Hyperion
    // took it over reaches the notification centre.
    match svc.wp_mail_tick().await {
        Ok(n) if n > 0 => {
            tracing::info!(configured = n, "wp mail: wrote configuration")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "wp mail tick failed"),
    }
    // The one Hyperion plugin every WordPress site carries: old
    // single-file copies moved into it, the loader and spam
    // guard kept current, and the wp-admin status page told what
    // this node last saw.
    match svc.wp_plugin_tick().await {
        Ok(n) if n > 0 => {
            tracing::info!(sites = n, "wp plugin: wrote plugin files")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "wp plugin tick failed"),
    }
    // Repoint a stale vsftpd local_root, fix web-root ownership
    // and ancestor traversal. Never touches the daemon, a
    // node-wide file, or any password state — see the doc comment
    // on ftp_autoheal_tick for why those are operator decisions.
    match svc.ftp_autoheal_tick().await {
        Ok(n) if n > 0 => {
            tracing::warn!(healed = n, "ftp autoheal: repaired FTP roots")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "ftp autoheal tick failed"),
    }
    // Finish any unlock of a returned site's logins that did not
    // complete — without this a login whose restore failed once
    // stayed disabled on a live site with nothing to retry it.
    match svc.offline_logins_reconcile().await {
        Ok(n) if n > 0 => {
            tracing::warn!(accounts = n, "re-enabled logins of sites back online")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error=%e, "login reconcile tick failed"),
    }
}

/// Auto-update, when the operator has opted in. Hourly probe, but the
/// release check itself is cached agent-side for an hour, so this costs
/// one HTTP request a day in the common case and applies a new release
/// within the hour otherwise.
///
/// Not at boot: an update that restarts the agent, at the moment the agent
/// starts, is a loop waiting to happen if anything goes wrong. Give the box
/// time to prove it is healthy first.
fn spawn_auto_update(svc: &Svc) {
    every(svc, 15 * MIN, HOUR, |svc| async move {
        if svc.auto_update_tick().await {
            tracing::info!("auto-update started — this process may be replaced");
        }
    });
}

/// Read-only rootfs watchdog. ext4 remounts itself ro on I/O errors,
/// and from that moment the panel the operator would use to fix it may
/// itself be broken — so this cannot wait for a click. One-minute
/// cadence: the check is a read of /proc/mounts, and every minute a box
/// spends read-only is a minute of failed writes for every site on it.
/// The tick carries its own guard rails (attempt cap, immutable-image
/// refusal, loud notifications) — see rofs_watchdog_tick.
fn spawn_rofs_watchdog(svc: &Svc) {
    every(svc, 90, MIN, |svc| async move {
        svc.rofs_watchdog_tick().await;
    });
}

/// Stats sampler every 5 minutes. Offset by 30s so it doesn't collide with
/// the scheduler tick.
fn spawn_stats(svc: &Svc) {
    every(svc, 30, 5 * MIN, |svc| async move {
        match svc.stats_tick().await {
            Ok(n) => tracing::info!(sampled = n, "stats tick"),
            Err(e) => tracing::warn!(error=%e, "stats tick failed"),
        }
    });
}

/// Dedicated high-resolution network sampler. Separate from the 5-minute
/// stats sampler (which also runs a per-hosting `du` and must stay coarse):
/// this only diffs /proc/net/dev, so it can tick every few seconds to feed
/// the realtime rx/tx sparkline. `prev` holds the last counters+time so the
/// delta is over real elapsed wall-clock; the tick prunes its own ring.
fn spawn_net_sampler(svc: &Svc) {
    let net_svc = svc.clone();
    tokio::spawn(async move {
        let mut prev: hyperion_core::NetSamplerState = None;
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            if let Err(e) = net_svc.net_sample_tick(&mut prev).await {
                tracing::debug!(error=%e, "net sample tick failed");
            }
        }
    });
}

/// Per-hosting HTTP monitor: every 60s the tick walks all enabled hostings
/// whose `monitor_interval_secs` has elapsed since the last sample, probes
/// each, records, and dispatches alerts. 60s is a fine outer cadence because
/// the per-hosting interval gates work; we just want enough resolution that
/// a 60s interval (the minimum) actually fires every minute.
fn spawn_monitor(svc: &Svc) {
    every(svc, 45, MIN, |svc| async move {
        match svc.monitor_tick().await {
            Ok(0) => tracing::debug!("monitor tick: nothing due"),
            Ok(n) => tracing::info!(sampled = n, "monitor tick"),
            Err(e) => tracing::warn!(error=%e, "monitor tick failed"),
        }
    });
}

/// Automatic PHP memory_limit: answer "Allowed memory size … exhausted" in
/// a site's error.log by raising its pool one step (bounded), and step it
/// back down after a quiet fortnight. Its own two-minute task: a site
/// erroring out should not wait for the five-minute loop, and reading
/// tenant logs must never hold fail2ban or quota enforcement up.
fn spawn_php_mem_auto(svc: &Svc) {
    every(svc, 90, 2 * MIN, |svc| async move {
        match svc.php_mem_auto_tick().await {
            Ok(n) if n > 0 => tracing::info!(pools = n, "php mem auto: rewrote pools"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error=%e, "php mem auto tick failed"),
        }
    });
}

/// PHP-FPM pools that ran out of workers ("server reached
/// pm.max_children"): read from each version's FPM log, recorded per site
/// for its limits card, and reported. Own one-minute task for the same
/// reason as the memory automation above; the read positions live here,
/// so a restart starts at the end of each log rather than re-reporting.
fn spawn_php_workers(svc: &Svc) {
    let workers_svc = svc.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(MIN)).await;
        let mut cursors = std::collections::HashMap::new();
        let mut interval = tokio::time::interval(Duration::from_secs(MIN));
        loop {
            interval.tick().await;
            match workers_svc
                .php_workers_tick(std::path::Path::new("/var/log"), &mut cursors)
                .await
            {
                Ok(n) if n > 0 => {
                    tracing::info!(sites = n, "php workers: pools at their limit")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error=%e, "php workers tick failed"),
            }
        }
    });
}

/// The weekly page walk. On its OWN task, not in the five-minute loop:
/// one pass fetches up to eight pages plus forty links PER SITE, each
/// with a 20-second ceiling, so on a node with a few dozen care-plan
/// sites a bad week could hold the shared loop for longer than its own
/// period — and everything behind it (fail2ban bans, quota enforcement,
/// permission repair) would stop running while it waited on somebody
/// else's slow site.
///
/// Hourly outer cadence; the per-site weekly interval is enforced inside
/// the tick from each report's own timestamp, so this only decides how
/// promptly a site that has become due is picked up. The first pass waits
/// well clear of boot so it does not compete with provisioning and the
/// initial stats sample.
fn spawn_site_check(svc: &Svc) {
    every(svc, 5 * MIN, HOUR, |svc| async move {
        match svc.site_check_tick().await {
            Ok(n) if n > 0 => tracing::info!(sites = n, "site check: walked sites"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error=%e, "site check tick failed"),
        }
    });
}

/// Cert renewal — every 24h, sweep certificates for LE certs whose
/// `not_after` is within `renewal_window_days` (default 30) and
/// re-issue. Without this tick every LE cert silently expires at
/// day 90. Daily cadence is fine: LE certs are 90-day-lived and
/// the renewal window gives 30 days of retry headroom; an
/// operator restart never lengthens that window because the next
/// tick lines up within 24h of boot.
fn spawn_cert_renewal(svc: &Svc, threshold: i64) {
    every(svc, 3 * MIN, DAY, move |svc| async move {
        let now = hyperion_types::now_secs();
        match svc.cert_renew_tick(now, threshold).await {
            Ok(results) if !results.is_empty() => {
                let renewed = results
                    .iter()
                    .filter(|r| {
                        matches!(r.outcome, hyperion_types::CertRenewOutcome::Renewed { .. })
                    })
                    .count();
                let failed = results
                    .iter()
                    .filter(|r| {
                        matches!(r.outcome, hyperion_types::CertRenewOutcome::Failed { .. })
                    })
                    .count();
                tracing::info!(due = results.len(), renewed, failed, "cert renewal tick");
            }
            Ok(_) => tracing::debug!("cert renewal tick: nothing due"),
            Err(e) => tracing::warn!(error=%e, "cert renewal tick failed"),
        }
    });
}

/// WordPress defender sweep — once per day. Scans every active WP
/// hosting for outdated plugins/themes (keyless — via wp-cli's own
/// update status), auto-applies safe minor/patch updates when enabled,
/// stores the result for the cluster dashboard, and notifies admins
/// about NEW major updates needing manual review.
fn spawn_wp_defender(svc: &Svc) {
    every(svc, 4 * MIN, DAY, |svc| async move {
        match svc.wp_vuln_scan_tick().await {
            Ok(n) if n > 0 => tracing::info!(new_majors = n, "wp defender tick"),
            Ok(_) => tracing::debug!("wp defender tick: no new major updates"),
            Err(e) => tracing::warn!(error=%e, "wp defender tick failed"),
        }
    });
}

/// WordPress integrity sweep — once per day. The other half of the
/// defender: verifies core + plugin files against the checksums
/// WordPress.org publishes and (where clamscan exists) sweeps each
/// docroot, then notifies admins about NEWLY-appeared findings.
fn spawn_wp_integrity(svc: &Svc) {
    every(svc, 6 * MIN, DAY, |svc| async move {
        match svc.wp_integrity_scan_tick().await {
            Ok(n) if n > 0 => tracing::warn!(flagged = n, "wp integrity tick"),
            Ok(_) => tracing::debug!("wp integrity tick: no new findings"),
            Err(e) => tracing::warn!(error=%e, "wp integrity tick failed"),
        }
    });
}

/// Billing sweep — once per hour. Sends Slack reminders for hostings
/// with next_billing_at <= now + 3d.
fn spawn_billing_sweep(svc: &Svc) {
    every(svc, 2 * MIN, HOUR, |svc| async move {
        match svc.billing_sweep().await {
            Ok(n) if n > 0 => tracing::info!(notified = n, "billing sweep"),
            Ok(_) => tracing::debug!("billing sweep: nothing due"),
            Err(e) => tracing::warn!(error=%e, "billing sweep failed"),
        }
    });
}

/// Care-package drift enforcement — hourly. Re-asserts the features
/// every ACTIVE package promises, so a paid capability someone switched
/// off comes back instead of quietly staying off until the customer
/// notices. Cheap when idle: it reads state and only writes where
/// something actually moved, and returns immediately on a node with no
/// activations at all.
fn spawn_package_enforce(svc: &Svc) {
    every(svc, 7 * MIN, HOUR, |svc| async move {
        match svc.package_enforce_tick().await {
            Ok(n) if n > 0 => tracing::info!(corrected = n, "care package enforce tick"),
            Ok(_) => tracing::debug!("care package enforce tick: nothing drifted"),
            Err(e) => tracing::warn!(error=%e, "care package enforce tick failed"),
        }
    });
}

/// Care reports — hourly check of which LOCAL hostings are due their
/// periodic report to the customer. The sibling of the drift tick and
/// the other half of the same feature: that one keeps the paid work
/// happening, this one is the only part the person paying ever sees.
///
/// Runs on EVERY node, and must: every metric behind a report (bans,
/// usage buckets, monitor samples, backup runs, the audit log, the
/// stored integrity scan) lives on the node that owns the hosting. The
/// same sweep on the master would truthfully report "not measured" for
/// a worker's site — honest, and worthless.
///
/// Hourly is the CHECK cadence, not the send cadence: the tick sends
/// only once a full weekly/monthly/quarterly period has elapsed since
/// the last report, and it returns immediately on a node with no
/// activations at all.
fn spawn_care_reports(svc: &Svc) {
    every(svc, 9 * MIN, HOUR, |svc| async move {
        match svc.care_report_tick().await {
            Ok(n) if n > 0 => tracing::info!(sent = n, "care report tick"),
            Ok(_) => tracing::debug!("care report tick: nothing due"),
            Err(e) => tracing::warn!(error=%e, "care report tick failed"),
        }
    });
}

/// Scheduled backups — checks every 5 minutes which LOCAL hostings are due
/// per their backup_cadence (off by default) and optional time of day, and
/// runs backup_now for each. Five minutes, not an hour, so "at 03:00" starts
/// close to 03:00; the check itself is a few hosting_kv reads per site.
/// Runs on every node since backups are node-local.
fn spawn_scheduled_backups(svc: &Svc) {
    every(svc, 5 * MIN, 5 * MIN, |svc| async move {
        match svc.scheduled_backups_tick().await {
            Ok(n) if n > 0 => tracing::info!(started = n, "scheduled backups tick"),
            Ok(_) => tracing::debug!("scheduled backups tick: nothing due"),
            Err(e) => tracing::warn!(error=%e, "scheduled backups tick failed"),
        }
    });
}

/// Snapshot retention — daily. Deletes snapshots older than `[snapshots]
/// keep_days` (keeping the newest `keep_last`) on every site that has a
/// repository. Retention also runs after each new snapshot, but a site
/// with nothing to update takes none, and without this sweep its old
/// snapshots were never deleted at all.
///
/// 13 minutes in: clear of the wp-cli sweeps and the OS update check, which
/// is also where restic spends its disk time.
fn spawn_snapshot_retention(svc: &Svc) {
    every(svc, 13 * MIN, DAY, |svc| async move {
        match svc.snapshot_retention_tick().await {
            Ok(n) if n > 0 => tracing::info!(deleted = n, "snapshot retention sweep"),
            Ok(_) => tracing::debug!("snapshot retention sweep: nothing old enough"),
            Err(e) => tracing::warn!(error=%e, "snapshot retention sweep failed"),
        }
    });
}

/// Operating-system updates — every 6 hours, refresh the apt index and
/// record what is waiting (and whether a reboot is owed) in node_kv, so the
/// Nodes page can say how far behind this machine is without running apt
/// on a page load. Read-only: it never installs anything.
///
/// Runs on every node, because every node has its own packages. The first
/// check comes 11 minutes after start — clear of the wp-cli sweeps — so a
/// freshly updated agent has a real answer within the hour instead of
/// "never checked" for six.
fn spawn_os_updates(svc: &Svc) {
    every(svc, 11 * MIN, 6 * HOUR, |svc| async move {
        match svc.os_updates_check(true).await {
            Ok(s) if !s.error.is_empty() => {
                tracing::warn!(error = %s.error, "os updates check: incomplete")
            }
            Ok(s) => tracing::debug!(
                pending = s.pending.len(),
                security = s.security_count,
                reboot = s.reboot_required,
                "os updates check"
            ),
            Err(e) => tracing::warn!(error=%e, "os updates check failed"),
        }
    });
}
