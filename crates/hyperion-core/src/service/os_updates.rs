//! Operating-system package updates: check and report.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Check what the operating system has waiting.
    ///
    /// `refresh` runs `apt-get update` first — the slow, network half. The
    /// scheduled tick refreshes; the panel's "check now" button can too. When a
    /// refresh FAILS, the pending list is still read from the old index and
    /// returned, but `index_refreshed_at` keeps its previous value and `error`
    /// says what happened. What must never come out of this is "0 pending"
    /// standing in for "we could not reach the mirrors".
    pub async fn os_updates_check(
        &self,
        refresh: bool,
    ) -> Result<hyperion_types::OsUpdateStatus, RpcError> {
        os_updates_check_in(&self.pool, refresh).await
    }

    /// The last recorded OS update check, brought up to date cheaply.
    ///
    /// Meant for page loads, so it never refreshes the package index. It does
    /// re-read the pending list when dpkg has changed since the stored check (a
    /// second or two of `apt list`, no network), and it always re-reads the
    /// reboot marker. On a machine without dpkg it answers with what is stored,
    /// and a node never checked comes back with `checked_at` 0, which the panel
    /// renders as "not checked yet" — never as "up to date".
    pub async fn os_updates_status(&self) -> Result<hyperion_types::OsUpdateStatus, RpcError> {
        use hyperion_adapters::os_updates;
        let mut status = self.os_updates_stored().await?;
        // Re-read the list (no index refresh — that is the slow, network half)
        // when it cannot be trusted as stored: never read at all, or read
        // before packages last changed. Without this, the card went on saying
        // "40 updates, 6 security" for up to six hours after they had been
        // installed, from this panel or from a shell.
        //
        // Not while a check is already running, though: that one may be an
        // index refresh taking minutes, and a page load must not queue behind
        // it and time out. It answers with what is stored, and the running
        // check stores a fresh answer when it finishes.
        let busy = OS_UPDATES_RUNNING.try_lock().is_err();
        if !busy {
            if let Some(changed) = os_updates::dpkg_changed_at().await {
                if !status.was_checked() || changed > status.checked_at {
                    return self.os_updates_check(false).await;
                }
            }
        }
        // The reboot marker is a file read, so it is always live: a reboot
        // clears it, and the stored answer would not know.
        let (reboot, reboot_pkgs) = os_updates::reboot_required().await;
        status.reboot_required = reboot;
        status.reboot_packages = reboot_pkgs;
        Ok(status)
    }

    /// The last check exactly as persisted, with nothing re-read.
    pub(super) async fn os_updates_stored(
        &self,
    ) -> Result<hyperion_types::OsUpdateStatus, RpcError> {
        os_updates_stored_in(&self.pool).await
    }

    /// Sign-ups per scan window past which a site is not being used, it is
    /// being farmed.
    ///
    /// Any honest WordPress site takes single digits an hour. This sits where
    /// a real site will not reach it and a bot passes it in under a minute.
    pub(super) const SIGNUP_FLOOD_THRESHOLD: u32 = 30;

    /// `hosting_kv` stamp of the last sign-up flood we spoke up about, so a
    /// flood that runs for a day is one message and not one per tick.
    pub(super) const SIGNUP_FLOOD_KV_KEY: &'static str = "signup_flood_warned_at";
}

/// `node_kv` key holding the last OS update check, as JSON.
///
/// Persisted rather than cached in memory, because the agent restarts on
/// every hyperion update and a cold cache would render as "never checked"
/// on exactly the page an operator opens right after updating.
pub(super) const OS_UPDATES_KV: &str = "os_updates.last";

/// `node_kv` key: when security updates were first seen pending.
///
/// Its own key, so it survives a check that fails part-way: the age of an
/// unapplied security update must not reset because one refresh timed out.
pub(super) const OS_SECURITY_SINCE_KV: &str = "os_updates.security_since";

/// `node_kv` key: `started_at` of the last node update job whose finish
/// already triggered an OS update re-check, so it triggers exactly one.
pub(super) const NODE_UPDATE_RECHECKED_KV: &str = "node_update.rechecked_for";

/// The last OS update check exactly as persisted, with nothing re-read.
pub(super) async fn os_updates_stored_in(
    pool: &sqlx::SqlitePool,
) -> Result<hyperion_types::OsUpdateStatus, RpcError> {
    let raw = hyperion_state::node_kv::get(pool, OS_UPDATES_KV)
        .await
        .map_err(|e| RpcError::Internal_with(format!("os updates read: {e}")))?;
    Ok(raw
        .and_then(|r| serde_json::from_str(&r).ok())
        .unwrap_or_default())
}

/// [`HostingService::os_updates_check`], for callers holding only the pool
/// (the node update job runs in a detached task).
pub(super) async fn os_updates_check_in(
    pool: &sqlx::SqlitePool,
    refresh: bool,
) -> Result<hyperion_types::OsUpdateStatus, RpcError> {
    use hyperion_adapters::os_updates;
    let _one_at_a_time = OS_UPDATES_RUNNING.lock().await;
    // A node update owns apt for its whole run, and runs outside this process,
    // so the mutex above cannot see it. Refreshing now would lose the race for
    // apt's lock and record a "could not refresh" that is not a mirror
    // problem. Read the list without refreshing; the job's finish triggers a
    // proper re-check (`node_update_status`).
    let refresh = refresh && !hyperion_adapters::node_update::is_running().await;
    let now = now_secs();
    let mut status = os_updates_stored_in(pool).await.unwrap_or_default();

    // A check that does not refresh keeps the last refresh's verdict: it
    // learned nothing new about the mirrors.
    if refresh {
        match os_updates::refresh_index().await {
            Ok(()) => {
                status.index_refreshed_at = now;
                status.refresh_error.clear();
            }
            Err(e) => {
                status.refresh_error = format!(
                    "could not refresh the package index ({e}) — any pending list shown is \
                     from the last index that did download, and may be out of date"
                );
            }
        }
    }
    status.error = status.refresh_error.clone();

    let mut list_read = false;
    match os_updates::list_pending().await {
        Ok(pkgs) => {
            list_read = true;
            status.pending = pkgs
                .iter()
                .map(|p| hyperion_types::OsPendingPackage {
                    name: p.name.clone(),
                    installed: p.installed.clone(),
                    candidate: p.candidate.clone(),
                    security: p.is_security(),
                })
                .collect();
            status.security_count = pkgs.iter().filter(|p| p.is_security()).count() as i64;
            status.checked_at = now;
        }
        Err(e) => {
            // Could not READ the list at all. Keep the previous one rather
            // than blanking it — an empty list here would read as "nothing
            // to install" — and say so.
            let msg = format!("could not read pending updates: {e}");
            status.error = if status.error.is_empty() {
                msg
            } else {
                format!("{}; {msg}", status.error)
            };
        }
    }

    let (reboot, reboot_pkgs) = os_updates::reboot_required().await;
    status.reboot_required = reboot;
    status.reboot_packages = reboot_pkgs;

    // The age of pending SECURITY updates. Stamped on the first check that
    // sees any, cleared on the first that sees none — and only on a check
    // that actually READ the list, so a failed read cannot reset the clock.
    if list_read {
        if status.security_count > 0 {
            let since = hyperion_state::node_kv::get(pool, OS_SECURITY_SINCE_KV)
                .await
                .ok()
                .flatten()
                .and_then(|v| v.parse::<i64>().ok());
            match since {
                Some(t) => status.security_pending_since = t,
                None => {
                    status.security_pending_since = now;
                    let _ = hyperion_state::node_kv::set(
                        pool,
                        OS_SECURITY_SINCE_KV,
                        &now.to_string(),
                        now,
                    )
                    .await;
                }
            }
        } else {
            status.security_pending_since = 0;
            let _ = hyperion_state::node_kv::delete(pool, OS_SECURITY_SINCE_KV).await;
        }
    }

    if let Ok(json) = serde_json::to_string(&status) {
        let _ = hyperion_state::node_kv::set(pool, OS_UPDATES_KV, &json, now).await;
    }
    Ok(status)
}

/// Held for the duration of an OS update check.
///
/// One check at a time: the six-hourly tick and a "check now" click can land
/// together, and two `apt-get update`s fight over apt's lock — the loser would
/// report a refresh failure that is not a real one.
pub(super) static OS_UPDATES_RUNNING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// How long security updates may wait before the dashboard says so.
///
/// Not zero: unattended-upgrades and a weekly maintenance window both leave
/// updates pending for a day or two as a matter of course, and an alert that is
/// always on is one nobody reads.
pub(super) const OS_SECURITY_GRACE_SECS: i64 = 3 * 86_400;

/// How old a package index may get before the update count stops meaning much.
pub(super) const OS_INDEX_STALE_SECS: i64 = 3 * 86_400;

/// Dashboard alerts for this node's operating-system updates.
///
/// Pure, so the thresholds are testable: `dpkg_changed_at` is the live dpkg
/// database timestamp. When packages changed after the stored check, the stored
/// count is not repeated — it may be describing updates already installed.
pub(super) fn os_update_alerts(
    os: &hyperion_types::OsUpdateStatus,
    now: i64,
    dpkg_changed_at: Option<i64>,
) -> Vec<DashboardAlert> {
    let mut out = Vec::new();
    let list_current = os.was_checked() && dpkg_changed_at.map_or(true, |t| t <= os.checked_at);
    if list_current
        && os.security_count > 0
        && os.security_pending_since > 0
        && now - os.security_pending_since >= OS_SECURITY_GRACE_SECS
    {
        let days = (now - os.security_pending_since) / 86_400;
        out.push(DashboardAlert {
            kind: "os_security_updates".into(),
            // Exposed, not broken: the server is up and serving.
            severity: "warn".into(),
            message: format!(
                "This server has {} security update{} waiting, first seen {days} day{} ago. \
                 Review and install them under Nodes → This server.",
                os.security_count,
                if os.security_count == 1 { "" } else { "s" },
                if days == 1 { "" } else { "s" },
            ),
            hosting: None,
        });
    }
    if os.reboot_required {
        let why = if os.reboot_packages.is_empty() {
            String::new()
        } else {
            let mut names: Vec<&str> = os
                .reboot_packages
                .iter()
                .take(3)
                .map(String::as_str)
                .collect();
            if os.reboot_packages.len() > 3 {
                names.push("…");
            }
            format!(" ({})", names.join(", "))
        };
        out.push(DashboardAlert {
            kind: "os_reboot_required".into(),
            severity: "warn".into(),
            message: format!(
                "This server needs a reboot to finish applying updates{why}. Until it \
                 restarts it keeps running the old versions."
            ),
            hosting: None,
        });
    }
    // Only once an index refresh has ever succeeded: before that there is no
    // age to report, and the Nodes page already says "never refreshed".
    if os.index_refreshed_at > 0 && now - os.index_refreshed_at >= OS_INDEX_STALE_SECS {
        let days = (now - os.index_refreshed_at) / 86_400;
        let error = if os.error.is_empty() {
            String::new()
        } else {
            format!(" Last error: {}", os.error)
        };
        out.push(DashboardAlert {
            kind: "os_index_stale".into(),
            severity: "warn".into(),
            message: format!(
                "The package index on this server has not refreshed for {days} days, so its \
                 update count may be out of date.{error}"
            ),
            hosting: None,
        });
    }
    out
}
