//! Locking every login of an offline (suspended or trashed) site, and undoing
//! it.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ─────────────────── Logins of a site that is offline ───────────────────
    //
    // While a site is suspended or in the trash nobody may log in to it. It
    // used to be `usermod -L` on the site's system user alone, which left two
    // ways in: extra FTP logins are accounts of their own and were never
    // touched, and with `UsePAM yes` OpenSSH lets an SFTP key in to an
    // account whose password is locked. A customer whose site was suspended
    // or thrown away could still write into the tree — including PHP that
    // would run the moment the site came back.
    //
    // Logins are now disabled by account EXPIRY (see
    // `hyperion_adapters::users::set_login_expiry`): every PAM service
    // refuses it, root's `sudo -u` still works, and the password field — an
    // operator's `*` or `!` — is not touched, so nothing can flip it.
    //
    // Two kinds of account, two rules:
    //
    // * A site's extra FTP logins belong to it alone. They are disabled while
    //   the site is offline, with each one's previous expiry recorded in the
    //   site's `hosting_kv` BEFORE it is changed.
    // * The system user can be shared by several hostings. Its state is not
    //   remembered per site but DERIVED every time from all of them: disabled
    //   exactly when none is online and at least one is offline. Its previous
    //   expiry is recorded once, node-wide.
    //
    // Every transition writes the site's state FIRST and then applies this,
    // under one node-wide mutex, re-reading the state inside it — so the
    // last application always sees the final state, whatever raced. A
    // five-minute reconcile repeats it for anything a failure left behind.

    /// Bring a hosting's logins, and its system user, in line with its state.
    ///
    /// `legacy` says what a missing record means: `Some(true)` only where the
    /// caller has established, under [`LOGIN_LOCKS`], that the site was offline
    /// with no record — taken offline by a version that ran just `usermod -L`
    /// on the system user, which then needs a `usermod -U` on the way back.
    /// `None` infers exactly that from the state read here. Every site this
    /// code takes offline gets its record in the same critical section as its
    /// state, so a missing record on an offline site is never a race.
    pub(super) async fn apply_login_policy(&self, id: &HostingId, legacy: Option<bool>) {
        let _serial = LOGIN_LOCKS.lock().await;
        self.apply_login_policy_held(id, legacy).await;
    }

    /// Returns how many accounts it re-enabled.
    pub(super) async fn apply_login_policy_held(
        &self,
        id: &HostingId,
        legacy: Option<bool>,
    ) -> usize {
        // A record that cannot be read is not "no record": acting on it would
        // record our own "1" as the value to restore. Change nothing.
        let Ok(record) = self.login_lock_record(id).await else {
            return 0;
        };
        let detail = match self.get(HostingSelector::Id(id.clone())).await {
            Ok(d) => d,
            Err(RpcError::NotFound { .. }) => {
                // The row is gone. Its extra logins belong to no site any
                // more: an account that survived the teardown stays shut, and
                // the record has nothing left to track.
                if record.is_some() {
                    let _ =
                        hyperion_state::hosting_kv::delete(&self.pool, id.as_str(), LOGIN_LOCK_KV)
                            .await;
                }
                return 0;
            }
            Err(e) => {
                tracing::error!(
                    error = %e, hosting = %id.as_str(),
                    "could not read a hosting to apply its login policy — unchanged"
                );
                return 0;
            }
        };
        let mut enabled = 0;
        let offline = matches!(
            detail.state,
            HostingState::Suspended | HostingState::Trashed
        );
        // Once the boot pass has recorded every site an older version took
        // offline, a missing record never means an old-style lock again, so no
        // race can make this run `usermod -U` on an operator's own `!`.
        let legacy =
            legacy.unwrap_or(offline && record.is_none()) && !self.login_policy_migrated().await;
        if offline {
            let mut record = record.unwrap_or(LoginLock {
                legacy_password_lock: legacy,
                ..LoginLock::default()
            });
            let logins = hyperion_state::ftp_accounts::logins_for_hosting(&self.pool, id)
                .await
                .unwrap_or_default();
            for login in &logins {
                // Recorded already: the real value is in the record, and the
                // account itself now reads our "1".
                if record.prior_expiry.contains_key(login) {
                    continue;
                }
                match self.adapters.linux_login_expiry(login).await {
                    Ok(Some(prior)) => {
                        record.prior_expiry.insert(login.clone(), prior);
                    }
                    Ok(None) => {}
                    Err(e) => tracing::error!(
                        error = %e, domain = %detail.domain, login = %login,
                        "could not read a login's account expiry — it is NOT disabled"
                    ),
                }
            }
            // The record goes down before any account changes, so there is
            // always an exact way back. No record, no lock.
            if self.save_login_lock_record(id, &record).await {
                for login in logins
                    .iter()
                    .filter(|l| record.prior_expiry.contains_key(*l))
                {
                    if let Err(e) = self.adapters.linux_set_login_expiry(login, "1").await {
                        tracing::error!(
                            error = %e, domain = %detail.domain, login = %login,
                            "could not disable a login of an offline site"
                        );
                    }
                }
            } else {
                tracing::error!(
                    domain = %detail.domain,
                    "could not record the logins' expiry — extra logins left enabled"
                );
            }
        } else {
            // Online again, or being deleted.
            match record {
                Some(mut record) => {
                    if detail.state == HostingState::Deleting {
                        // The site's extra logins go with it; one that
                        // survives the teardown must not come back open.
                        record.prior_expiry.clear();
                    } else {
                        let before = record.prior_expiry.len();
                        record = self.restore_extra_logins(id, &detail.domain, record).await;
                        enabled += before - record.prior_expiry.len();
                    }
                    if record.legacy_password_lock
                        && self
                            .adapters
                            .linux_unlock_login(&detail.system_user)
                            .await
                            .is_ok()
                    {
                        record.legacy_password_lock = false;
                        enabled += 1;
                    }
                    self.store_or_clear_login_record(id, &record).await;
                }
                None if legacy => {
                    let unlocked = self
                        .adapters
                        .linux_unlock_login(&detail.system_user)
                        .await
                        .is_ok();
                    enabled += usize::from(unlocked);
                }
                None => {}
            }
        }
        enabled
            + self
                .apply_system_user_policy_held(&detail.system_user)
                .await
    }

    /// Mark a hosting that is going offline right now as managed by this code:
    /// an empty record, written in the same critical section as its state, so
    /// no racing resume can mistake it for an older version's lock.
    pub(super) async fn mark_login_policy_managed_held(&self, id: &HostingId) {
        if let Ok(None) = self.login_lock_record(id).await {
            self.save_login_lock_record(id, &LoginLock::default()).await;
        }
    }

    /// Put back every extra login in `record`; what fails stays in it.
    pub(super) async fn restore_extra_logins(
        &self,
        id: &HostingId,
        domain: &str,
        mut record: LoginLock,
    ) -> LoginLock {
        let recorded: Vec<(String, String)> = record
            .prior_expiry
            .iter()
            .map(|(l, p)| (l.clone(), p.clone()))
            .collect();
        for (login, prior) in recorded {
            match self.adapters.linux_set_login_expiry(&login, &prior).await {
                Ok(()) => {
                    record.prior_expiry.remove(&login);
                }
                Err(e) => tracing::error!(
                    error = %e, hosting = %id.as_str(), domain = %domain, login = %login,
                    "could not re-enable a login — it stays disabled, and the agent retries \
                     every five minutes"
                ),
            }
        }
        record
    }

    /// Disable or re-enable a system user from the state of EVERY hosting on
    /// it: disabled exactly when none is online and at least one is suspended
    /// or in the trash. A hosting being deleted counts as neither. Returns 1
    /// when it re-enabled the account.
    pub(super) async fn apply_system_user_policy_held(&self, user: &str) -> usize {
        let user = user.trim();
        if user.is_empty() {
            return 0;
        }
        let Ok((online, offline)) = sqlx::query_as::<_, (i64, i64)>(
            "SELECT \
               COALESCE(SUM(h.state NOT IN ('suspended', 'trashed', 'deleting')), 0), \
               COALESCE(SUM(h.state IN ('suspended', 'trashed')), 0) \
             FROM hostings h JOIN system_users u ON u.id = h.system_user_id \
             WHERE u.name = ?",
        )
        .bind(user)
        .fetch_one(&self.pool)
        .await
        else {
            // Unknown: change nothing either way.
            return 0;
        };
        let want_disabled = online == 0 && offline > 0;
        let Ok(mut users) = self.system_user_lock_records().await else {
            return 0;
        };
        match (want_disabled, users.get(user).cloned()) {
            (true, None) => {
                match self.adapters.linux_login_expiry(user).await {
                    Ok(Some(prior)) => {
                        users.insert(user.to_string(), prior);
                        if !self.save_system_user_lock_records(&users).await {
                            tracing::error!(
                                login = %user,
                                "could not record a system user's expiry — left enabled"
                            );
                            return 0;
                        }
                    }
                    Ok(None) => return 0,
                    Err(e) => {
                        tracing::error!(
                            error = %e, login = %user,
                            "could not read a system user's account expiry — it is NOT disabled"
                        );
                        return 0;
                    }
                }
                if let Err(e) = self.adapters.linux_set_login_expiry(user, "1").await {
                    tracing::error!(error = %e, login = %user, "could not disable a system user");
                }
                0
            }
            (true, Some(_)) => {
                if let Err(e) = self.adapters.linux_set_login_expiry(user, "1").await {
                    tracing::error!(error = %e, login = %user, "could not disable a system user");
                }
                0
            }
            (false, Some(prior)) => {
                match self.adapters.linux_set_login_expiry(user, &prior).await {
                    Ok(()) => {
                        users.remove(user);
                        self.save_system_user_lock_records(&users).await;
                        1
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e, login = %user,
                            "could not re-enable a system user — the agent retries every five minutes"
                        );
                        0
                    }
                }
            }
            (false, None) => 0,
        }
    }

    /// Re-apply the policy to a system user after a hosting was added to it.
    pub(super) async fn apply_system_user_policy(&self, user: &str) {
        let _serial = LOGIN_LOCKS.lock().await;
        self.apply_system_user_policy_held(user).await;
    }

    /// Disable the logins of every site that is suspended or in the trash, once
    /// at agent start, then reconcile the rest. Sites taken offline by an older
    /// version had only the system user's password locked; their extra FTP
    /// logins and SFTP keys work until this runs. Returns how many offline
    /// sites it found without a record (taken offline by an older version).
    pub async fn offline_logins_lock_on_boot(&self) -> Result<i64, RpcError> {
        let mut migrated = 0i64;
        let mut complete = true;
        for id in self.offline_hosting_ids().await? {
            let _serial = LOGIN_LOCKS.lock().await;
            // Decided here, under the lock, from a fresh read: the RPC server
            // is already answering, and a site resumed since the list was
            // taken is online and has nothing to migrate.
            let Ok(detail) = self.get(HostingSelector::Id(id.clone())).await else {
                complete = false;
                continue;
            };
            let offline = matches!(
                detail.state,
                HostingState::Suspended | HostingState::Trashed
            );
            let legacy = match self.login_lock_record(&id).await {
                Ok(record) => offline && record.is_none() && !self.login_policy_migrated().await,
                Err(()) => {
                    complete = false;
                    continue;
                }
            };
            self.apply_login_policy_held(&id, Some(legacy)).await;
            if offline && !matches!(self.login_lock_record(&id).await, Ok(Some(_))) {
                // Not recorded after all (a failed write): try again next start.
                complete = false;
            }
            if !legacy {
                continue;
            }
            migrated += 1;
            // A session opened since (an sshfs mount, a long-running cron job)
            // outlives a new expiry, so end it the way suspend and trash do —
            // but only if the account is now disabled, i.e. it runs no site
            // that is online, whose PHP workers those would be.
            let disabled = self
                .system_user_lock_records()
                .await
                .is_ok_and(|users| users.contains_key(detail.system_user.trim()));
            if disabled {
                let _ = self.adapters.kill_user_procs(&detail.system_user).await;
            }
        }
        if complete && !self.login_policy_migrated().await {
            let _ =
                hyperion_state::node_kv::set(&self.pool, LOGIN_POLICY_MIGRATED_KV, "1", now_secs())
                    .await;
        }
        let _ = self.offline_logins_reconcile().await;
        Ok(migrated)
    }

    /// Repair whatever a failure or a race left behind: re-apply the policy to
    /// every hosting that is offline or still has a login record (online ones
    /// get their logins back, offline ones are re-asserted, deleted ones
    /// release theirs) and to every system user on record. Runs at start and
    /// every five minutes. Returns how many accounts it re-enabled.
    pub async fn offline_logins_reconcile(&self) -> Result<i64, RpcError> {
        let mut ids: std::collections::BTreeSet<String> =
            hyperion_state::hosting_kv::list_by_key(&self.pool, LOGIN_LOCK_KV)
                .await
                .map_err(|e| RpcError::Internal_with(format!("login locks: {e}")))?
                .into_iter()
                .map(|(hid, _)| hid)
                .collect();
        ids.extend(
            self.offline_hosting_ids()
                .await?
                .into_iter()
                .map(|h| h.as_str().to_string()),
        );
        let mut enabled = 0usize;
        for hid in ids {
            let _serial = LOGIN_LOCKS.lock().await;
            enabled += self.apply_login_policy_held(&HostingId(hid), None).await;
        }
        let users: Vec<String> = self
            .system_user_lock_records()
            .await
            .map(|u| u.into_keys().collect())
            .unwrap_or_default();
        for user in users {
            let _serial = LOGIN_LOCKS.lock().await;
            enabled += self.apply_system_user_policy_held(&user).await;
        }
        Ok(enabled as i64)
    }

    /// Has the boot pass recorded every site an older version took offline?
    /// An unreadable flag counts as yes: the harm of skipping a legacy
    /// `usermod -U` (a password lock stays) is smaller than stripping an
    /// operator's own `!`.
    pub(super) async fn login_policy_migrated(&self) -> bool {
        !matches!(
            hyperion_state::node_kv::get(&self.pool, LOGIN_POLICY_MIGRATED_KV).await,
            Ok(None)
        )
    }

    /// Every hosting on this node that is suspended or in the trash.
    pub(super) async fn offline_hosting_ids(&self) -> Result<Vec<HostingId>, RpcError> {
        let mut ids: Vec<HostingId> = self
            .list()
            .await?
            .into_iter()
            .filter(|h| h.state == HostingState::Suspended)
            .map(|h| h.id)
            .collect();
        ids.extend(
            hostings::list_trashed(&self.pool)
                .await
                .map_err(|e| RpcError::Internal_with(format!("list trashed: {e}")))?
                .into_iter()
                .map(|h| h.id),
        );
        Ok(ids)
    }

    /// `Ok(None)` only when there really is no record. A failed read or an
    /// unparseable value is an error, so no caller mistakes it for "never
    /// locked".
    pub(super) async fn login_lock_record(&self, id: &HostingId) -> Result<Option<LoginLock>, ()> {
        match hyperion_state::hosting_kv::get(&self.pool, id.as_str(), LOGIN_LOCK_KV).await {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => serde_json::from_str(&raw).map(Some).map_err(|e| {
                tracing::error!(error = %e, hosting = %id.as_str(), "unreadable login record");
            }),
            Err(e) => {
                tracing::error!(error = %e, hosting = %id.as_str(), "could not read login record");
                Err(())
            }
        }
    }

    pub(super) async fn save_login_lock_record(&self, id: &HostingId, record: &LoginLock) -> bool {
        let Ok(json) = serde_json::to_string(record) else {
            return false;
        };
        hyperion_state::hosting_kv::set(&self.pool, id.as_str(), LOGIN_LOCK_KV, &json, now_secs())
            .await
            .is_ok()
    }

    /// Keep a record that still holds something to undo; drop an empty one.
    pub(super) async fn store_or_clear_login_record(&self, id: &HostingId, record: &LoginLock) {
        if record.prior_expiry.is_empty() && !record.legacy_password_lock {
            let _ =
                hyperion_state::hosting_kv::delete(&self.pool, id.as_str(), LOGIN_LOCK_KV).await;
        } else {
            self.save_login_lock_record(id, record).await;
        }
    }

    /// System user → its account expiry before it was disabled. An error, not
    /// an empty map, when it cannot be read: saving over it would lose every
    /// other user's value.
    pub(super) async fn system_user_lock_records(
        &self,
    ) -> Result<std::collections::BTreeMap<String, String>, ()> {
        match hyperion_state::node_kv::get(&self.pool, SYSTEM_USER_LOCK_KV).await {
            Ok(None) => Ok(Default::default()),
            Ok(Some(raw)) => serde_json::from_str(&raw).map_err(|e| {
                tracing::error!(error = %e, "unreadable system user lock records");
            }),
            Err(e) => {
                tracing::error!(error = %e, "could not read system user lock records");
                Err(())
            }
        }
    }

    pub(super) async fn save_system_user_lock_records(
        &self,
        users: &std::collections::BTreeMap<String, String>,
    ) -> bool {
        if users.is_empty() {
            return hyperion_state::node_kv::delete(&self.pool, SYSTEM_USER_LOCK_KV)
                .await
                .is_ok();
        }
        let Ok(json) = serde_json::to_string(users) else {
            return false;
        };
        hyperion_state::node_kv::set(&self.pool, SYSTEM_USER_LOCK_KV, &json, now_secs())
            .await
            .is_ok()
    }
}

/// `hosting_kv` key: a site's extra FTP logins disabled while it is suspended
/// or in the trash, and what to put back. Present exactly while they are.
pub(super) const LOGIN_LOCK_KV: &str = "logins_locked";

/// `node_kv` key: system users disabled because every hosting on them is
/// offline, each with its account expiry from before (JSON map).
pub(super) const SYSTEM_USER_LOCK_KV: &str = "logins_locked.system_users";

/// `node_kv` key, present once a boot pass has recorded every site that an
/// older version took offline. From then on a missing record is never a
/// password lock to undo.
pub(super) const LOGIN_POLICY_MIGRATED_KV: &str = "logins_locked.migrated";

/// One application of the login policy at a time, node-wide. Records are
/// read, changed and written back, hostings can share a system user, and the
/// boot pass and the five-minute reconcile run beside RPC-driven suspends and
/// resumes.
pub(super) static LOGIN_LOCKS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// See `HostingService::apply_login_policy`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct LoginLock {
    /// Extra FTP login → its account-expiry field before it was disabled
    /// (`""` = never).
    #[serde(default)]
    pub(super) prior_expiry: std::collections::BTreeMap<String, String>,
    /// The system user's password was locked with `usermod -L` by a version
    /// from before this record existed, and needs `usermod -U` on the way out.
    #[serde(default)]
    pub(super) legacy_password_lock: bool,
}
