//! FTP/SFTP logins: passwords, extra accounts, FTPS, self-check and autoheal.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Set / replace the FTP (Linux) password for the hosting's
    /// system user. Empty input → generate a random 20-char password
    /// and return it. Caller is expected to show the returned password
    /// to the operator exactly once.
    pub async fn ftp_set_password(
        &self,
        sel: HostingSelector,
        new_password: String,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state == HostingState::Deleting {
            return Err(RpcError::Conflict {
                message: "cannot set FTP password on a deleting hosting".into(),
            });
        }
        let password = if new_password.trim().is_empty() {
            hyperion_adapters::random_password()
        } else {
            if new_password.len() < 12 {
                return Err(RpcError::Validation {
                    message: "FTP password must be at least 12 characters".into(),
                });
            }
            new_password
        };
        hyperion_adapters::ftp::ensure_vsftpd_running()
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "vsftpd".into(),
                reason: e.to_string(),
            })?;
        // Ensure vsftpd is actually CONFIGURED for local-user FTP (config +
        // /etc/shells). Without this, a node whose vsftpd wasn't set up by the
        // installer refuses every login with 530 even though the password is set.
        hyperion_adapters::ftp::ensure_vsftpd_configured()
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "vsftpd_config".into(),
                reason: e.to_string(),
            })?;
        hyperion_adapters::ftp::set_user_password(&detail.system_user, &password)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "chpasswd".into(),
                reason: e.to_string(),
            })?;
        // Land the FTP client directly in the site's writable web root
        // (htdocs, owned by the user) rather than the root-owned home — else
        // STOR at the chroot root fails with 550.
        //
        // `root_dir` IS the htdocs. Create stores it that way
        // (`let htdocs = format!("{}/htdocs", hosting_root); ... root_dir:
        // htdocs`) and every other consumer reads it that way — wp-cli's
        // `--path`, `root_dir/wp-content/debug.log`, the file-manager jail.
        // Appending "/htdocs" here produced `<site>/htdocs/htdocs`, so vsftpd
        // answered EVERY login with "500 OOPS: cannot change directory" and
        // FTP had never worked for any hosting.
        let web_root = detail.root_dir.clone();
        hyperion_adapters::ftp::set_user_web_root(&detail.system_user, &web_root)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "vsftpd_user_root".into(),
                reason: e.to_string(),
            })?;
        // Self-heal ownership: a restored/imported site keeps the source box's
        // uid, so the local user can't write (STOR/MKD → 550) even though login
        // works. Best-effort — a partial chown shouldn't block setting the
        // password; the operator can retry.
        if let Err(e) =
            hyperion_adapters::ftp::ensure_web_root_owned(&detail.system_user, &web_root).await
        {
            tracing::warn!(
                error = %e, user = %detail.system_user, web_root = %web_root,
                "ftp: chown of web root failed — uploads may still be denied"
            );
        }
        self.append_audit(
            "hosting.ftp.set_password",
            Some(detail.id.as_str()),
            &serde_json::json!({"user": detail.system_user}).to_string(),
            "ok",
        )
        .await;
        Ok(password)
    }

    // ── FTP self-check / repair ───────────────────────────────────────────
    //
    // Runs on the OWNING node. Everything FTP depends on — the per-user
    // vsftpd config, the passwd/shadow entry, the web root and its ancestors
    // — is node-local, so a master-local scan would report every remote
    // hosting as broken.

    /// Diagnose one hosting's FTP setup. STRICTLY read-only: no writes, no
    /// daemon restarts, nothing an operator has to undo.
    pub async fn ftp_self_check(&self, sel: HostingSelector) -> Result<FtpCheckReport, RpcError> {
        let detail = self.get(sel).await?;
        let user = detail.system_user.trim().to_string();
        let expected_root = detail.root_dir.trim().to_string();

        let shadow_state = if user.is_empty() {
            "no_user".to_string()
        } else {
            hyperion_adapters::ftp::password_state(&user).await
        };
        // "Is FTP meant to be on?" gates how loudly the rest is reported. A
        // site that never enabled FTP must not light up the card in red.
        let ftp_intended = shadow_state == "hash";

        let listen_port = hyperion_adapters::ftp::read_listen_port().await;
        let mut items = ftp_node_items(ftp_intended, listen_port).await;
        let mut report = FtpCheckReport {
            items: Vec::new(),
            local_root: String::new(),
            expected_root,
            listen_port,
            shadow_state,
            // Filled in by the web layer, which already knows which node it
            // dispatched to. The agent has no reliable name for itself here —
            // the master stores its own rows under its hostname while a
            // worker knows only its node id.
            node_id: String::new(),
        };

        // ── per-hosting scope ─────────────────────────────────────────────
        if user.is_empty() {
            items.push(check_item(
                "system_user",
                "System user",
                "error",
                "this hosting has no system user".into(),
                "",
            ));
            report.items = items;
            return Ok(report);
        }
        items.push(ftp_shadow_item(&report.shadow_state, detail.state));

        let local_root = hyperion_adapters::ftp::read_user_web_root(&user)
            .await
            .ok()
            .flatten();
        items.push(ftp_local_root_item(
            local_root.as_deref(),
            &report.expected_root,
            ftp_intended,
            &user,
        ));

        let (shell, shell_listed) = hyperion_adapters::ftp::shell_state(&user).await;
        items.push(check_item(
            "shell",
            "Login shell accepted by PAM",
            if shell_listed || !ftp_intended {
                "ok"
            } else {
                "error"
            },
            if shell.is_empty() {
                "could not read the passwd entry".into()
            } else if shell_listed {
                format!("{shell} is listed in /etc/shells")
            } else {
                format!("{shell} is NOT in /etc/shells — vsftpd's PAM stack refuses with 530")
            },
            // /etc/shells is a box-wide file gating chsh and every pam_shells
            // consumer; only ensure_vsftpd_configured's allowlist touches it.
            if shell_listed { "" } else { "node_config" },
        ));

        if let Some(reason) = hyperion_adapters::ftp::userlist_blocks(&user).await {
            // Hyperion writes no userlist, so anything here is foreign and
            // deliberate. Report both senses; never offer to change it.
            items.push(check_item(
                "userlist",
                "Access lists",
                "warn",
                format!("{reason} — Hyperion did not set this up and will not change it"),
                "",
            ));
        }

        if !report.expected_root.is_empty() {
            items.extend(ftp_web_root_items(&user, &report.expected_root).await);
        }
        items.extend(self.ftp_extra_login_items(&detail, &user).await);

        report.items = items;
        report.local_root = local_root.unwrap_or_default();
        Ok(report)
    }

    /// Extra FTP logins. An extra login works only because it SHARES the
    /// site's uid; if the site's own account is ever recreated it hands out a
    /// NEW uid, every extra login keeps the old one, and they still
    /// authenticate while being unable to write a byte. That reads as an FTP
    /// fault and is a uid mismatch, so it is named here rather than left to
    /// be guessed.
    pub(super) async fn ftp_extra_login_items(
        &self,
        detail: &HostingDetail,
        user: &str,
    ) -> Vec<FtpCheckItem> {
        let site = hyperion_adapters::users::lookup_raw(user)
            .await
            .ok()
            .flatten();
        let rows = hyperion_state::ftp_accounts::list_for_hosting(&self.pool, &detail.id)
            .await
            .unwrap_or_default();
        let mut items = Vec::new();
        for acct in rows {
            let label = format!("Extra login {}", acct.login);
            let info = hyperion_adapters::users::lookup_raw(&acct.login)
                .await
                .ok()
                .flatten();
            let item = match (&site, &info) {
                (_, None) => check_item(
                    "extra_login",
                    &label,
                    "error",
                    "the panel lists this login but the system has no such account — \
                     delete it here and add it again"
                        .into(),
                    "",
                ),
                (Some(site), Some(info)) if info.uid != site.uid || info.gid != site.gid => {
                    check_item(
                        "extra_login",
                        &label,
                        "error",
                        format!(
                            "runs as uid {} while the site is uid {} — it can log in but \
                             cannot write anything in the site's own files. The automatic \
                             FTP repair puts this back within five minutes.",
                            info.uid, site.uid
                        ),
                        "",
                    )
                }
                (_, Some(_)) => {
                    let have = hyperion_adapters::ftp::read_user_web_root(&acct.login)
                        .await
                        .ok()
                        .flatten();
                    let want = acct.local_root.trim();
                    if !want.is_empty() && have.as_deref() != Some(want) {
                        check_item(
                            "extra_login",
                            &label,
                            "warn",
                            format!(
                                "lands in {} instead of {want} — its vsftpd override \
                                 drifted. The automatic FTP repair rewrites it within \
                                 five minutes.",
                                have.unwrap_or_else(|| "the account's home".into())
                            ),
                            "",
                        )
                    } else {
                        check_item(
                            "extra_login",
                            &label,
                            "ok",
                            format!("shares the site's uid and lands in {want}"),
                            "",
                        )
                    }
                }
            };
            items.push(item);
        }
        items
    }

    /// Repair the per-hosting half of FTP. Idempotent, touches no daemon and
    /// no node-wide file, so it is safe to run unattended.
    pub async fn ftp_repair_site(&self, sel: HostingSelector) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let (user, root) = (
            detail.system_user.trim().to_string(),
            detail.root_dir.trim().to_string(),
        );
        if user.is_empty() || root.is_empty() {
            return Err(RpcError::Validation {
                message: "this hosting has no system user or web root to repair".into(),
            });
        }
        // Refuse rather than swap one dead local_root for another.
        if tokio::fs::metadata(&root).await.is_err() {
            return Err(RpcError::Validation {
                message: format!("{root} does not exist — repair the site's files first"),
            });
        }
        let mut done: Vec<String> = Vec::new();
        // Order matters: point local_root at the right place BEFORE chowning,
        // or the chown lands on whatever the stale path was.
        hyperion_adapters::ftp::set_user_web_root(&user, &root)
            .await
            .map_err(|e| RpcError::Validation {
                message: format!("set local_root: {e}"),
            })?;
        done.push(format!("local_root → {root}"));
        if let Err(e) = hyperion_adapters::ftp::ensure_web_root_owned(&user, &root).await {
            tracing::warn!(error = %e, user = %user, "ftp_repair_site: chown failed");
        } else {
            done.push(format!("web root owned by {user}"));
        }
        hyperion_adapters::fs::ensure_ancestors_traversable(std::path::Path::new(&root)).await;
        done.push("parent directories traversable".into());
        self.append_audit(
            "hosting.ftp.repair",
            Some(detail.id.as_str()),
            &serde_json::json!({"user": user, "root": root}).to_string(),
            "ok",
        )
        .await;
        Ok(done.join("; "))
    }

    /// Repair the node-wide vsftpd config. Kept separate from
    /// `ftp_repair_site` because it can restart a daemon every hosting on the
    /// box shares — never call it from a background tick.
    pub async fn ftp_repair_node_config(&self) -> Result<String, RpcError> {
        hyperion_adapters::ftp::ensure_vsftpd_configured()
            .await
            .map_err(|e| RpcError::Validation {
                message: format!("vsftpd config repair: {e}"),
            })?;
        self.append_audit("node.ftp.repair_config", None, "{}", "ok")
            .await;
        Ok("vsftpd configuration checked and repaired".into())
    }

    /// Turn FTPS on or off for this node.
    ///
    /// Never called from a tick and never implied by another action: it
    /// restarts a daemon every site on the node shares, and with
    /// `require_tls` it locks out any client that cannot negotiate TLS. The
    /// adapter rolls the config back if vsftpd does not come back up.
    pub async fn ftp_set_ftps(&self, enabled: bool, require_tls: bool) -> Result<String, RpcError> {
        let (cert, key) = if enabled {
            // Prefer this node's real panel certificate — clients then see no
            // trust prompt at all. Self-signed is the fallback, and still
            // encrypts, which is the property that matters.
            let panel = read_cluster_section(self.agent_config_path.as_deref()).panel_hostname;
            let panel_pair = if panel.is_empty() {
                None
            } else {
                Some((
                    format!("/etc/hyperion/certs/{panel}/fullchain.pem"),
                    format!("/etc/hyperion/certs/{panel}/privkey.pem"),
                ))
            };
            let hostname = tokio::process::Command::new("hostname")
                .arg("-f")
                .output()
                .await
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_default();
            hyperion_adapters::ftp::ensure_ftps_cert(
                panel_pair.as_ref().map(|(c, k)| (c.as_str(), k.as_str())),
                &hostname,
            )
            .await
            .map_err(|e| RpcError::Validation {
                message: format!("FTPS certificate: {e}"),
            })?
        } else {
            (String::new(), String::new())
        };
        hyperion_adapters::ftp::set_ftps(enabled, require_tls, &cert, &key)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "node.ftp.ftps",
            None,
            &serde_json::json!({"enabled": enabled, "require_tls": require_tls, "cert": cert})
                .to_string(),
            "ok",
        )
        .await;
        Ok(if !enabled {
            "FTPS switched off".to_string()
        } else if require_tls {
            format!(
                "FTPS is on and REQUIRED — plaintext logins are refused.                  Certificate: {cert}. Passive data ports 40000-50000 must be open                  in the firewall; with TLS the kernel cannot open them on demand."
            )
        } else {
            format!("FTPS is available but not required. Certificate: {cert}")
        })
    }

    /// Background self-heal for the per-hosting half of FTP.
    ///
    /// Deliberately narrow. It repoints a stale `local_root` and fixes
    /// ownership/traversal — small, idempotent, no auth change, no daemon
    /// touch. It never installs or restarts vsftpd, never edits a node-wide
    /// file, and never changes a password state: those are operator
    /// decisions, and a background restart of a shared daemon is not a
    /// self-heal.
    pub async fn ftp_autoheal_tick(&self) -> Result<i64, RpcError> {
        let mut healed = 0i64;
        for s in self.list().await? {
            // A suspended or trashed site's locked account is intentional.
            if s.state != HostingState::Active {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            let (user, root) = (
                detail.system_user.trim().to_string(),
                detail.root_dir.trim().to_string(),
            );
            if user.is_empty()
                || root.is_empty()
                || matches!(detail.kind.as_str(), "reverse_proxy" | "redirect")
            {
                continue;
            }
            // Only sites where FTP is actually on. Creating a per-user config
            // for a site that never enabled FTP would be inventing state.
            if hyperion_adapters::ftp::password_state(&user).await != "hash" {
                continue;
            }
            if tokio::fs::metadata(&root).await.is_err() {
                continue;
            }
            let current = hyperion_adapters::ftp::read_user_web_root(&user)
                .await
                .ok()
                .flatten();
            if current.as_deref() != Some(root.as_str()) {
                match hyperion_adapters::ftp::set_user_web_root(&user, &root).await {
                    Ok(()) => {
                        healed += 1;
                        // Audited on success so a REPEATING heal is visible as
                        // a pattern rather than looking like steady state.
                        self.append_audit(
                            "hosting.ftp.autoheal",
                            Some(detail.id.as_str()),
                            &serde_json::json!({
                                "user": user,
                                "was": current.unwrap_or_default(),
                                "now": root,
                            })
                            .to_string(),
                            "ok",
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, user = %user, "ftp_autoheal: local_root");
                    }
                }
            }
            // Extra FTP logins, which nothing has ever re-checked.
            //
            // They work only because they SHARE the site's uid — that is what
            // lets a file uploaded over FTP be edited by PHP and the other way
            // round. Nothing kept the two in step. If the site's own account
            // is recreated (a delete and a fresh provision hands out a new
            // uid), every extra login keeps the old number, still
            // authenticates, and can no longer write a single byte of the
            // tree. It presents as "the login works but has no write
            // permission", which reads as an FTP problem and is not one.
            //
            // Their per-user config was never re-asserted either: the site
            // user's local_root is repaired above on every tick, while an
            // extra login whose config drifted or vanished stayed broken
            // forever — vsftpd then falls back to the global
            // `local_root=/home/$USER`, a path that does not exist for a
            // `<name>.<domain>` login.
            if let Ok(Some(site)) = hyperion_adapters::users::lookup_raw(&user).await {
                {
                    let rows =
                        hyperion_state::ftp_accounts::list_for_hosting(&self.pool, &detail.id)
                            .await
                            .unwrap_or_default();
                    for acct in rows {
                        let Ok(Some(info)) =
                            hyperion_adapters::users::lookup_raw(&acct.login).await
                        else {
                            // Gone from passwd. Not recreated here: a login
                            // without its password is a login nobody can use,
                            // and inventing one silently would be worse than
                            // saying so.
                            tracing::warn!(
                                login = %acct.login, domain = %detail.domain,
                                "ftp_autoheal: extra login is missing from passwd"
                            );
                            continue;
                        };
                        if info.uid != site.uid || info.gid != site.gid {
                            match hyperion_adapters::ftp::realign_extra_login(
                                &acct.login,
                                site.uid,
                                site.gid,
                            )
                            .await
                            {
                                Ok(()) => {
                                    healed += 1;
                                    self.append_audit(
                                        "hosting.ftp.autoheal",
                                        Some(detail.id.as_str()),
                                        &serde_json::json!({
                                            "login": acct.login,
                                            "was_uid": info.uid,
                                            "now_uid": site.uid,
                                            "reason": "extra login had lost the site's uid, \
                                                       so it could not write",
                                        })
                                        .to_string(),
                                        "ok",
                                    )
                                    .await;
                                }
                                Err(e) => tracing::warn!(
                                    error = %e, login = %acct.login,
                                    "ftp_autoheal: could not realign an extra login"
                                ),
                            }
                        }
                        // And its landing directory, from the row the panel
                        // shows — not from the site root, which would quietly
                        // move a login the operator pointed at a subdirectory.
                        let want = acct.local_root.trim();
                        if !want.is_empty() {
                            let have = hyperion_adapters::ftp::read_user_web_root(&acct.login)
                                .await
                                .ok()
                                .flatten();
                            if have.as_deref() != Some(want) {
                                if let Err(e) =
                                    hyperion_adapters::ftp::set_user_web_root(&acct.login, want)
                                        .await
                                {
                                    tracing::warn!(
                                        error = %e, login = %acct.login,
                                        "ftp_autoheal: extra login local_root"
                                    );
                                } else {
                                    healed += 1;
                                }
                            }
                        }
                    }
                }
            }

            // Ownership + traversal only — NOT repair_tree_permissions, which
            // chmods every directory to 0755 and would widen logs/ and tmp/
            // from the 0750 create deliberately gives them.
            if let Ok(Some(_)) = hyperion_adapters::ftp::web_root_owner_drift(&user, &root).await {
                let _ = hyperion_adapters::ftp::ensure_web_root_owned(&user, &root).await;
            }
            if !hyperion_adapters::fs::ancestors_traversable(std::path::Path::new(&root)).await {
                hyperion_adapters::fs::ensure_ancestors_traversable(std::path::Path::new(&root))
                    .await;
            }
        }
        Ok(healed)
    }

    // ── Extra FTP logins ──────────────────────────────────────────────────
    //
    // See migration 061 for why these share the hosting's uid. The short
    // version: PHP-FPM runs as the site user, so a login with its own uid
    // would write files PHP cannot then modify. Sharing the uid means every
    // login writes files the site already owns — and it means every login can
    // reach every file the site owns, which the UI says out loud.

    pub async fn ftp_account_list(
        &self,
        sel: HostingSelector,
    ) -> Result<Vec<hyperion_types::FtpExtraAccount>, RpcError> {
        let detail = self.get(sel).await?;
        let rows = hyperion_state::ftp_accounts::list_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list ftp accounts: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(hyperion_types::FtpExtraAccount {
                id: r.id,
                login: r.login.clone(),
                local_root: r.local_root,
                label: r.label,
                created_at: r.created_at,
                created_by: r.created_by,
                password_state: hyperion_adapters::ftp::password_state(&r.login).await,
            });
        }
        Ok(out)
    }

    /// Create an extra FTP login. Returns the generated password.
    ///
    /// `subdir` is relative to the hosting's document root and is where the
    /// client LANDS. It is convenience, not a boundary: the login shares the
    /// site's uid, so it can walk out of that directory into anything the
    /// site owns. Validated anyway so the landing path cannot be pointed
    /// outside the hosting entirely.
    pub async fn ftp_account_create(
        &self,
        sel: HostingSelector,
        login: String,
        subdir: String,
        label: String,
        actor: String,
    ) -> Result<(String, String), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: format!(
                    "hosting {} is {} — resume it before adding FTP logins",
                    detail.domain,
                    detail.state.as_str()
                ),
            });
        }
        let root = detail.root_dir.trim().to_string();
        if root.is_empty() || detail.system_user.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "this hosting has no document root or system user".into(),
            });
        }
        // The operator names the account; Hyperion qualifies it with the
        // domain. The rule and the 32-byte budget live in the adapter, next
        // to the useradd call that enforces them — see
        // `ftp::compose_extra_login` for why a long domain is shortened
        // instead of refused.
        let login =
            hyperion_adapters::ftp::compose_extra_login(&login, &detail.domain).map_err(|e| {
                RpcError::Validation {
                    message: e.to_string(),
                }
            })?;

        // Resolve the landing directory inside the hosting, refusing to
        // follow a symlink out of it — the site user owns this tree and can
        // plant one.
        let sub = subdir.trim().trim_matches('/').to_string();
        let landing = if sub.is_empty() {
            root.clone()
        } else {
            let candidate =
                hyperion_adapters::files::resolve_inside_jail(std::path::Path::new(&root), &sub)
                    .await
                    .map_err(|e| RpcError::Validation {
                        message: format!("landing directory: {e}"),
                    })?;
            if !candidate.is_dir() {
                return Err(RpcError::Validation {
                    message: format!("{sub} is not a directory inside the site"),
                });
            }
            candidate.display().to_string()
        };

        let info = hyperion_adapters::users::lookup_raw(&detail.system_user)
            .await
            .map_err(|e| RpcError::Internal_with(format!("lookup site user: {e}")))?
            .ok_or_else(|| RpcError::Validation {
                message: format!(
                    "the site's system user {} does not exist",
                    detail.system_user
                ),
            })?;

        hyperion_adapters::ftp::create_extra_login(&login, info.uid, info.gid, &root)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;

        // Everything after the account exists is rolled back on failure —
        // a half-made login that cannot be seen in the panel is worse than
        // none, because nothing will ever clean it up.
        let password = hyperion_adapters::random_password();
        let finish = async {
            hyperion_adapters::ftp::set_user_password(&login, &password).await?;
            hyperion_adapters::ftp::set_user_web_root(&login, &landing).await?;
            Ok::<(), hyperion_adapters::AdapterError>(())
        }
        .await;
        if let Err(e) = finish {
            let _ = hyperion_adapters::ftp::delete_extra_login(&login).await;
            return Err(RpcError::ProvisioningFailed {
                stage: "ftp_account".into(),
                reason: e.to_string(),
            });
        }
        if let Err(e) = hyperion_state::ftp_accounts::insert(
            &self.pool,
            &detail.id,
            &login,
            &landing,
            label.trim(),
            &actor,
            now_secs(),
        )
        .await
        {
            let _ = hyperion_adapters::ftp::delete_extra_login(&login).await;
            return Err(RpcError::Internal_with(format!("record ftp account: {e}")));
        }
        self.append_audit(
            "hosting.ftp.account_create",
            Some(detail.id.as_str()),
            &serde_json::json!({"login": login, "landing": landing}).to_string(),
            "ok",
        )
        .await;
        Ok((login, password))
    }

    /// Replace an extra login's password. Returns the new one.
    pub async fn ftp_account_reset(
        &self,
        sel: HostingSelector,
        id: i64,
    ) -> Result<(String, String), RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::ftp_accounts::get_owned(&self.pool, &detail.id, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("ftp account: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "ftp_account".into(),
                id: id.to_string(),
            })?;
        let password = hyperion_adapters::random_password();
        hyperion_adapters::ftp::set_user_password(&row.login, &password)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "hosting.ftp.account_reset",
            Some(detail.id.as_str()),
            &serde_json::json!({"login": row.login}).to_string(),
            "ok",
        )
        .await;
        Ok((row.login, password))
    }

    pub async fn ftp_account_delete(
        &self,
        sel: HostingSelector,
        id: i64,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::ftp_accounts::get_owned(&self.pool, &detail.id, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("ftp account: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "ftp_account".into(),
                id: id.to_string(),
            })?;
        hyperion_adapters::ftp::delete_extra_login(&row.login)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        hyperion_state::ftp_accounts::delete_owned(&self.pool, &detail.id, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete ftp account: {e}")))?;
        self.append_audit(
            "hosting.ftp.account_delete",
            Some(detail.id.as_str()),
            &serde_json::json!({"login": row.login}).to_string(),
            "ok",
        )
        .await;
        Ok(format!(
            "FTP login {} removed. The site's files are untouched.",
            row.login
        ))
    }

    /// Disable FTP for the hosting's system user (`passwd -d <user>`).
    pub async fn ftp_disable(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        hyperion_adapters::ftp::clear_user_password(&detail.system_user)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "passwd_disable".into(),
                reason: e.to_string(),
            })?;
        // Best-effort: drop the per-user vsftpd override (no password ⇒ no login
        // anyway, but keep the config dir tidy).
        let _ = hyperion_adapters::ftp::clear_user_web_root(&detail.system_user).await;
        self.append_audit(
            "hosting.ftp.disable",
            Some(detail.id.as_str()),
            &serde_json::json!({"user": detail.system_user}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub(super) fn home_dir_for(&self, system_user: &str) -> String {
        format!("{}/{}", self.paths.home_root, system_user)
    }

    /// Current key-only SFTP status for a hosting.
    pub async fn sftp_status(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::SftpStatus, RpcError> {
        let detail = self.get(sel).await?;
        let home = self.home_dir_for(&detail.system_user);
        let (enabled, keys) = hyperion_adapters::ssh::read_status(&detail.system_user, &home)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "sftp_status".into(),
                reason: e.to_string(),
            })?;
        Ok(hyperion_types::SftpStatus {
            enabled,
            system_user: detail.system_user.clone(),
            keys,
            host_hint: detail.domain.clone(),
        })
    }

    /// Enable/disable key-only chrooted SFTP for a hosting and replace
    /// the authorized public keys. Validates every key at the boundary.
    pub async fn sftp_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
        public_keys: Vec<String>,
    ) -> Result<hyperion_types::SftpStatus, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state == HostingState::Deleting {
            return Err(RpcError::Conflict {
                message: "cannot change SFTP on a deleting hosting".into(),
            });
        }
        let home = self.home_dir_for(&detail.system_user);
        if enabled {
            // Validate every key before touching the system. An empty
            // list with enabled=true is allowed (group access set up,
            // operator pastes keys next) but warned in the UI.
            let mut keys = Vec::with_capacity(public_keys.len());
            for k in &public_keys {
                let v = hyperion_adapters::ssh::validate_public_key(k).map_err(|e| {
                    RpcError::Validation {
                        message: format!("invalid SSH key: {e}"),
                    }
                })?;
                keys.push(v);
            }
            hyperion_adapters::ssh::enable_sftp(&detail.system_user, &home, &keys)
                .await
                .map_err(|e| RpcError::ProvisioningFailed {
                    stage: "sftp_enable".into(),
                    reason: e.to_string(),
                })?;
        } else {
            hyperion_adapters::ssh::disable_sftp(&detail.system_user, &home)
                .await
                .map_err(|e| RpcError::ProvisioningFailed {
                    stage: "sftp_disable".into(),
                    reason: e.to_string(),
                })?;
        }
        self.append_audit(
            "hosting.sftp.set",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "user": detail.system_user,
                "enabled": enabled,
                "keys": public_keys.len(),
            })
            .to_string(),
            "ok",
        )
        .await;
        self.sftp_status(HostingSelector::Id(detail.id.clone()))
            .await
    }

    /// Read the site-mail wrapper's JSONL for one user. Returns
    /// the most recent `limit` lines, newest first.
    ///
    /// Filesystem path is
    /// `/var/lib/hyperion/site-mail/<system_user>.jsonl`. Missing
    /// file → empty vec (sites that haven't sent mail yet). Lines
    /// that fail to parse are silently skipped so a corrupted
    /// entry can't take down the whole log.
    /// List every Linux user on this node with an FTP-usable shadow
    /// password + join with the hostings table so the operator sees
    /// domain + state alongside the user. Users without a matching
    /// hosting row are still listed (they're operator-created
    /// accounts) with empty domain/state.
    pub async fn ftp_accounts_list(
        &self,
    ) -> Result<Vec<hyperion_types::FtpAccountSummary>, RpcError> {
        let states = hyperion_adapters::ftp::account_password_states()
            .await
            .map_err(|e| RpcError::Internal_with(format!("read shadow: {e}")))?;
        // Index hostings by system_user for the join.
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT su.name, h.domain, h.state \
             FROM hostings h \
             JOIN system_users su ON su.id = h.system_user_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RpcError::Internal_with(format!("join hostings: {e}")))?;
        let by_user: std::collections::HashMap<String, (String, String)> =
            rows.into_iter().map(|(u, d, s)| (u, (d, s))).collect();
        let mut out = Vec::new();
        for (user, password_state) in states {
            // Only accounts that belong to a hosting. /etc/shadow holds root
            // and every human operator too, and the old code listed them —
            // presenting system accounts as "FTP accounts", and telling
            // whoever could open the page which local accounts exist and
            // which have passwords.
            let Some((domain, state)) = by_user.get(&user).cloned() else {
                continue;
            };
            out.push(hyperion_types::FtpAccountSummary {
                user,
                domain,
                hosting_state: state,
                password_state,
                node_id: String::new(),
            });
        }
        // Stable alphabetical for the UI.
        out.sort_by(|a, b| a.user.cmp(&b.user));
        Ok(out)
    }

    /// Forwards to the adapter's curl-based probe. Validates the
    /// username shape upfront so a malicious caller can't smuggle
    /// curl args via "user".
    pub async fn ftp_verify_login(&self, user: String, password: String) -> Result<bool, RpcError> {
        if !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            || user.is_empty()
            || user.len() > 32
        {
            return Err(RpcError::Validation {
                message: format!("invalid user: {user:?}"),
            });
        }
        hyperion_adapters::ftp::probe_login(&user, &password)
            .await
            .map_err(|e| RpcError::Internal_with(format!("ftp probe: {e}")))
    }
}

/// The node half of the FTP self-check: vsftpd itself, its control and
/// passive ports, FTPS.
pub(super) async fn ftp_node_items(ftp_intended: bool, listen_port: u16) -> Vec<FtpCheckItem> {
    let mut items = Vec::new();
    if !hyperion_adapters::systemctl_unit_present("vsftpd").await {
        // Not installed is a legitimate opt-out (the installer asks), so
        // it is only an error for a hosting that actually has FTP on.
        items.push(check_item(
            "vsftpd_present",
            "vsftpd installed",
            if ftp_intended { "error" } else { "info" },
            "vsftpd is not installed on this node".into(),
            "",
        ));
    } else {
        let st = hyperion_adapters::systemctl_status_rich("vsftpd").await;
        let masked = st.unit_file_state == "masked";
        items.push(check_item(
            "vsftpd_unit",
            "vsftpd running",
            if st.active_state == "active" {
                "ok"
            } else if masked || !ftp_intended {
                // Masked is an operator decision, not drift.
                "info"
            } else {
                "error"
            },
            format!(
                "active_state={} sub_state={} unit_file_state={}",
                st.active_state, st.sub_state, st.unit_file_state
            ),
            "",
        ));

        let missing = hyperion_adapters::ftp::missing_conf_directives().await;
        items.push(check_item(
            "vsftpd_conf",
            "vsftpd configured for local-user FTP",
            if missing.is_empty() {
                "ok"
            } else if ftp_intended {
                "error"
            } else {
                "warn"
            },
            if missing.is_empty() {
                "all required directives set".into()
            } else {
                format!("missing (or commented out): {}", missing.join(", "))
            },
            if missing.is_empty() {
                ""
            } else {
                "node_config"
            },
        ));
    }

    items.push(check_item(
        "listen_port",
        "Control port",
        "info",
        format!("vsftpd listens on {listen_port}"),
        "",
    ));

    // Passive data ports. Reported loudly when TLS is on, because an
    // encrypted control channel stops the kernel's conntrack helper
    // reading the PASV reply and opening the port on demand — so an
    // unopened range means every directory listing hangs AFTER a
    // successful login, which looks like anything except a firewall.
    // Hyperion cannot prove a cloud security group is open, so this
    // states the requirement rather than claiming a verdict.
    let ftps_on = hyperion_adapters::ftp::ftps_enabled().await;
    items.push(match hyperion_adapters::ftp::passive_range().await {
        Some((lo, hi)) => check_item(
            "pasv_range",
            "Passive data ports",
            if ftps_on { "warn" } else { "info" },
            if ftps_on {
                format!(
                    "vsftpd uses {lo}-{hi}. With FTPS the kernel can no longer open \
                     these on demand, so {lo}-{hi} MUST be open in every firewall in \
                     front of this node — including your provider's cloud firewall. \
                     If logins work but directory listings hang, this is why."
                )
            } else {
                format!("vsftpd uses {lo}-{hi}")
            },
            "",
        ),
        None => check_item(
            "pasv_range",
            "Passive data ports",
            if ftps_on { "error" } else { "info" },
            "no passive range is pinned — vsftpd will pick arbitrary high ports, \
             which no firewall rule can match"
                .into(),
            "node_config",
        ),
    });

    items.push(if ftps_on {
        // Reported as OK with its own fix slot, so the card can offer to
        // turn it back OFF. Without this row the operator who enabled it
        // has no way back from the UI — and this is the one setting most
        // likely to need reverting in a hurry.
        check_item(
            "ftps",
            "FTP over TLS",
            "ok",
            "FTPS is enabled — FTP sessions on this node are encrypted".into(),
            "disable_ftps",
        )
    } else {
        // Reported, never auto-enabled: switching FTPS on restarts a
        // daemon every hosting shares and locks out clients that cannot
        // negotiate TLS. The operator decides.
        check_item(
            "ftps",
            "FTP over TLS",
            "warn",
            "FTPS is not enabled — the FTP password crosses the network in \
             cleartext, and it is the site's real Linux password. Turn on FTPS \
             below, or use SFTP (port 22), which is key-only and already \
             encrypted."
                .into(),
            "enable_ftps",
        )
    });
    items
}

/// What the site user's password field says about FTP.
pub(super) fn ftp_shadow_item(shadow_state: &str, state: HostingState) -> FtpCheckItem {
    let offline = state != HostingState::Active;
    check_item(
        "shadow",
        "FTP password",
        match shadow_state {
            "hash" => "ok",
            // `!` is also what suspension sets, so say which it is rather
            // than guessing — the operator reads this and acts on it.
            "locked" if offline => "info",
            "empty" => "warn",
            _ => "info",
        },
        match shadow_state {
            "hash" => "a password is set — FTP login is possible".into(),
            "locked" if offline => format!("locked because the hosting is {}", state.as_str()),
            "locked" => "the account is locked — a `!` in its password field, or an \
                         account expiry in the past"
                .into(),
            "star" => "FTP is switched off for this site".into(),
            "empty" => "the password field is EMPTY — a pre-0.37 disable left it \
                        that way, which some PAM stacks accept as a valid login. \
                        Set a password or disable FTP again to replace it."
                .into(),
            _ => "no such system user".into(),
        },
        if shadow_state == "empty" {
            "site_repair"
        } else {
            ""
        },
    )
}

/// Where vsftpd would put the site user after login. Compared to root_dir,
/// NOT string-matched for "htdocs/htdocs" and NOT tested for mere existence:
/// drift onto a sibling site's real directory passes both of those weaker
/// checks.
pub(super) fn ftp_local_root_item(
    local_root: Option<&str>,
    expected_root: &str,
    ftp_intended: bool,
    user: &str,
) -> FtpCheckItem {
    let label = "FTP lands in the web root";
    match local_root {
        Some(v) if v == expected_root => check_item("local_root", label, "ok", v.to_string(), ""),
        Some(v) => check_item(
            "local_root",
            label,
            "error",
            format!("vsftpd would chdir to {v} — it should be {expected_root}"),
            "site_repair",
        ),
        None if ftp_intended => check_item(
            "local_root",
            label,
            "error",
            format!(
                "no per-user config, so vsftpd falls back to /home/{user} — \
                 which is root-owned, so uploads fail"
            ),
            "site_repair",
        ),
        None => check_item(
            "local_root",
            label,
            "info",
            "FTP has never been enabled for this site".into(),
            "",
        ),
    }
}

/// The web root exists, is owned by the site user, and vsftpd can chdir
/// into it.
pub(super) async fn ftp_web_root_items(user: &str, expected_root: &str) -> Vec<FtpCheckItem> {
    let root_exists = tokio::fs::metadata(expected_root).await.is_ok();
    let mut items = vec![check_item(
        "web_root",
        "Web root exists",
        if root_exists { "ok" } else { "error" },
        if root_exists {
            expected_root.to_string()
        } else {
            format!("{expected_root} does not exist")
        },
        "",
    )];
    if !root_exists {
        return items;
    }
    let owned = hyperion_adapters::ftp::web_root_owner_drift(user, expected_root)
        .await
        .unwrap_or(None);
    items.push(check_item(
        "web_root_owner",
        "Web root owned by the site user",
        if owned.is_none() { "ok" } else { "error" },
        match &owned {
            None => format!("owned by {user}"),
            Some(p) => format!("{p} is not owned by {user} — uploads there fail 550"),
        },
        if owned.is_none() { "" } else { "site_repair" },
    ));
    let traversable =
        hyperion_adapters::fs::ancestors_traversable(std::path::Path::new(expected_root)).await;
    items.push(check_item(
        "ancestors",
        "Parent directories traversable",
        if traversable { "ok" } else { "error" },
        if traversable {
            "every parent has o+x".into()
        } else {
            "a parent directory is missing o+x, so vsftpd cannot chdir into the \
             web root even though it exists"
                .into()
        },
        if traversable { "" } else { "site_repair" },
    ));
    items
}
