//! WordPress operations: install, repair, reinstall, plugins, themes, rescue
//! tools.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Install WordPress into an existing hosting.
    ///
    /// Preconditions: hosting state is Active, hosting has a MariaDB
    /// (Postgres is rejected — WordPress doesn't support it natively),
    /// admin credentials are well-formed.
    ///
    /// Side effects: downloads WP core into `htdocs`, writes
    /// `wp-config.php`, populates the DB with WP tables, records a row
    /// in `wp_installs`, appends an audit entry.
    pub async fn install_wordpress(
        &self,
        sel: HostingSelector,
        req: WpInstallRequest,
    ) -> Result<WpInstallStatus, RpcError> {
        // Light validation here. Adapter does locale/version regex.
        if req.site_url.trim().is_empty()
            || req.title.trim().is_empty()
            || req.admin_user.trim().is_empty()
            || req.admin_email.trim().is_empty()
        {
            return Err(RpcError::Validation {
                message: "site_url, title, admin_user, admin_email must all be non-empty".into(),
            });
        }
        if req.admin_password.is_empty() {
            return Err(RpcError::Validation {
                message: "admin_password must be non-empty".into(),
            });
        }
        if !req.admin_email.contains('@') {
            return Err(RpcError::Validation {
                message: "admin_email must be a valid address".into(),
            });
        }
        if !req.site_url.starts_with("http://") && !req.site_url.starts_with("https://") {
            return Err(RpcError::Validation {
                message: "site_url must include http(s):// scheme".into(),
            });
        }

        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: format!(
                    "hosting {} is in state {:?}; resume it before installing WordPress",
                    detail.domain, detail.state
                ),
            });
        }
        let db_row = databases::get_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("db lookup: {e}")))?
            .ok_or(RpcError::Conflict {
                message: format!(
                    "hosting {} has no database — WordPress needs MariaDB",
                    detail.domain
                ),
            })?;
        if db_row.engine != DbProvision::MariaDB {
            return Err(RpcError::Conflict {
                message: format!(
                    "WordPress requires MariaDB; hosting {} uses {:?}",
                    detail.domain, db_row.engine
                ),
            });
        }

        // Read the plaintext DB password from the secrets store.
        #[derive(serde::Deserialize)]
        struct StoredDbCred {
            password: String,
        }
        let stored: StoredDbCred = self
            .secrets
            .get(&db_row.secret_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("secret read: {e}")))?;

        // Reject re-install for now — operator must manually clear
        // wp_installs + wipe DB to redo. This avoids stomping on a live
        // site through fat-fingered UI.
        if wordpress::get_install(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp lookup: {e}")))?
            .is_some()
        {
            return Err(RpcError::Conflict {
                message: format!(
                    "WordPress already installed on {} — drop the row from wp_installs first",
                    detail.domain
                ),
            });
        }
        // Belt-and-braces: even if the DB row is missing, an
        // existing wp-config.php on disk means WP IS installed
        // (Hyperion-managed install that lost its row, SSH
        // install, migration). Refuse the install rather than
        // wipe the DB + clobber the directory with `wp core
        // download`. wp_status() would have already adopted it
        // into the row on the previous page load, but a stale
        // tab whose form was authored before adoption could
        // still land here.
        if let Some(ver) = detect_wp_install_on_disk(&detail.root_dir).await {
            return Err(RpcError::Conflict {
                message: format!(
                    "WordPress is already on disk at {} (version {ver}). \
                     Refresh the hosting detail page — the install was \
                     adopted into the panel and the install form should \
                     no longer be shown.",
                    detail.root_dir
                ),
            });
        }

        let installed_version = self
            .adapters
            .wp_install_run(
                &detail.system_user,
                &detail.root_dir,
                &db_row.db_name,
                &db_row.db_user,
                &stored.password,
                "localhost",
                &req,
            )
            .await
            .map_err(|e| match e {
                AdapterError::Command { code, .. } => RpcError::ProvisioningFailed {
                    stage: "wp_install".into(),
                    reason: format!("wp-cli failed with exit {code}: {e}"),
                },
                other => other.into(),
            })?;

        // Stable hash describing what we installed. Without an app_pack
        // this is just "vanilla-<version>-<locale>" so re-applying the
        // same options is detectable later.
        let manifest_marker = format!("vanilla-{}-{}", installed_version.trim(), req.locale.trim());
        let pack_hash = wordpress::pack_hash(&manifest_marker);
        let now = now_secs();
        wordpress::record_install(
            &self.pool,
            &detail.id,
            &req.site_url,
            &installed_version,
            &pack_hash,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("record_install: {e}")))?;

        self.append_audit(
            "wordpress.install",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "site_url": req.site_url,
                "locale": req.locale,
                "version": installed_version.trim(),
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok(WpInstallStatus {
            hosting_id: detail.id.clone(),
            site_url: req.site_url,
            wp_version: installed_version.trim().to_string(),
            installed_at: now,
            last_pack_hash: pack_hash,
        })
    }

    /// Reset the WordPress admin password via `wp user update --user_pass`.
    pub async fn wp_reset_password(
        &self,
        sel: HostingSelector,
        wp_user: String,
        new_password: String,
    ) -> Result<(), RpcError> {
        if new_password.len() < 8 {
            return Err(RpcError::Validation {
                message: "new password must be at least 8 characters".into(),
            });
        }
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to reset WP password".into(),
            });
        }
        // The password rides on STDIN through wp-cli's `--prompt`, the same
        // way `wp config create` and `wp core install` already do it in
        // wpcli.rs. It used to be `--user_pass=<pw>` on argv "for simplicity",
        // which answered shell injection and not the real exposure:
        // /proc/<pid>/cmdline is world-readable, build_argv puts the value on
        // THREE command lines (sudo, env and the wp PHP process), and it sits
        // there for the seconds wp-cli takes to boot WordPress. On a node
        // whose tenants have shell or PHP access, that is another site's
        // WordPress admin password handed out.
        let wp_args: [&str; 5] = [
            "user",
            "update",
            &wp_user,
            "--prompt=user_pass",
            "--skip-email",
        ];
        let argv =
            hyperion_adapters::wpcli::build_argv(&detail.system_user, &detail.root_dir, &wp_args);
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        // wp-cli's --prompt reads one "value\n" line per missing argument.
        let stdin = format!("{new_password}\n");
        hyperion_adapters::cmd::run_with_stdin("/usr/bin/sudo", &argv_refs, stdin.as_bytes())
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_reset_password".into(),
                reason: e.to_string(),
            })?;
        self.append_audit(
            "wordpress.reset_password",
            Some(detail.id.as_str()),
            &serde_json::json!({"wp_user": wp_user}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Replace WordPress core files, keeping wp-content, wp-config.php and
    /// the database. Non-destructive by construction.
    pub async fn wp_core_repair(&self, sel: HostingSelector) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let (user, root) = (detail.system_user.clone(), detail.root_dir.clone());
        if user.is_empty() || root.is_empty() {
            return Err(RpcError::Validation {
                message: "this hosting has no system user or document root".into(),
            });
        }
        // Repair to the version that is already installed, not to `latest`:
        // silently upgrading a site during what the operator asked to be a
        // REPAIR is a different operation with different consequences.
        let version = detect_wp_install_on_disk(&root)
            .await
            .unwrap_or_else(|| "latest".into());
        let out = hyperion_adapters::wpcli::core_repair(&user, &root, &version)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "hosting.wp.core_repair",
            Some(detail.id.as_str()),
            &serde_json::json!({"version": version}).to_string(),
            "ok",
        )
        .await;
        Ok(format!(
            "WordPress {version} core files replaced. wp-content, wp-config.php and the \
             database were not touched.{}",
            if out.trim().is_empty() {
                String::new()
            } else {
                format!(" ({})", out.trim())
            }
        ))
    }

    /// Wipe the site and install WordPress fresh.
    ///
    /// DESTRUCTIVE: the document tree and every table in the site's database
    /// are removed. The caller is expected to have taken a backup — the web
    /// layer orchestrates that and refuses to reach this call when the
    /// backup did not succeed, because a failed backup followed by a wipe is
    /// the single worst outcome this feature can produce.
    ///
    /// `confirm_domain` is checked HERE as well as in the browser. The
    /// type-to-confirm dialog is a UX guard against a misclick; it is not a
    /// control, because a POST can skip it entirely.
    pub async fn wp_reinstall(
        &self,
        sel: HostingSelector,
        req: hyperion_types::WpInstallRequest,
        confirm_domain: String,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel.clone()).await?;
        if !confirm_domain.trim().eq_ignore_ascii_case(&detail.domain) {
            return Err(RpcError::Validation {
                message: format!(
                    "confirmation does not match: type {} exactly to reinstall it",
                    detail.domain
                ),
            });
        }
        let (user, root) = (detail.system_user.clone(), detail.root_dir.clone());
        if user.is_empty() || root.is_empty() {
            return Err(RpcError::Validation {
                message: "this hosting has no system user or document root".into(),
            });
        }
        let db_row = databases::get_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("db lookup: {e}")))?
            .ok_or(RpcError::Conflict {
                message: format!(
                    "hosting {} has no database — WordPress needs MariaDB",
                    detail.domain
                ),
            })?;
        if db_row.engine != DbProvision::MariaDB {
            return Err(RpcError::Conflict {
                message: format!(
                    "WordPress requires MariaDB; hosting {} uses {:?}",
                    detail.domain, db_row.engine
                ),
            });
        }
        #[derive(serde::Deserialize)]
        struct StoredDbCred {
            password: String,
        }
        let stored: StoredDbCred = self
            .secrets
            .get(&db_row.secret_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("secret read: {e}")))?;

        // 1. Drop the tables FIRST, while wp-config.php still exists — that
        //    file is where the credentials are. Doing it after the wipe
        //    would leave the old tables in place, and `wp core install`
        //    refuses when WordPress is already installed.
        if let Err(e) = hyperion_adapters::wpcli::db_reset(&user, &root).await {
            return Err(RpcError::Validation {
                message: format!(
                    "could not reset the database ({e}). Nothing has been deleted. This \
                     usually means wp-config.php is missing or its credentials are wrong \
                     — fix that first, or the fresh install would fail with the old \
                     tables still in place."
                ),
            });
        }

        // 2. Now the files.
        hyperion_adapters::wpcli::wipe_site_tree(&user, &root)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wipe_site_tree".into(),
                reason: format!(
                    "{e}. The DATABASE HAS ALREADY BEEN RESET, so this site is now empty \
                     either way — restore the backup, or finish the reinstall."
                ),
            })?;

        // 3. Fresh install, using the hosting's existing database.
        self.adapters
            .wp_install_run(
                &user,
                &root,
                &db_row.db_name,
                &db_row.db_user,
                &stored.password,
                "localhost",
                &req,
            )
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_install".into(),
                reason: format!(
                    "{e}. The site's files and database were already cleared, so it is \
                     empty — restore the backup, or retry the reinstall."
                ),
            })?;

        self.append_audit(
            "hosting.wp.reinstall",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain, "version": req.version}).to_string(),
            "ok",
        )
        .await;
        Ok(format!(
            "{} was reinstalled. Everything that was on it is gone — restore a backup if \
             that was not what you wanted.",
            detail.domain
        ))
    }

    // ── WordPress permissions self-check ──────────────────────────────────
    //
    // Runs on the OWNING node: modes, uids and the nginx user are all
    // node-local facts.
    //
    // What "correct" means here is decided by this architecture, not by
    // internet advice. PHP-FPM runs AS the site user, so the site user must
    // own and be able to write what WordPress writes. nginx runs as a
    // DIFFERENT user and only reads, so static files need world-read and
    // every directory needs world-traverse. That last part is why the
    // popular "chmod 750 everything" hardening advice produces a site that
    // 404s here, and why an imported CloudPanel tree (nginx inside the
    // site's group there) breaks on arrival.

    /// Diagnose one hosting's file permissions. Read-only.
    pub async fn wp_perm_check(&self, sel: HostingSelector) -> Result<FtpCheckReport, RpcError> {
        let detail = self.get(sel).await?;
        let user = detail.system_user.trim().to_string();
        let root = detail.root_dir.trim().to_string();
        let items = self.perm_check_items(&detail, &user, &root).await;
        Ok(FtpCheckReport {
            items,
            local_root: root.clone(),
            expected_root: root,
            listen_port: 0,
            shadow_state: String::new(),
            node_id: String::new(),
        })
    }

    pub(super) async fn perm_check_items(
        &self,
        detail: &HostingDetail,
        user: &str,
        root: &str,
    ) -> Vec<FtpCheckItem> {
        // Same skip set as permissions_autoheal_tick: these have no document
        // tree of their own to judge.
        if user.is_empty()
            || root.is_empty()
            || matches!(detail.kind.as_str(), "reverse_proxy" | "redirect")
        {
            return vec![check_item(
                "not_applicable",
                "File permissions",
                "info",
                "this hosting serves no document tree of its own".into(),
                "",
            )];
        }
        match tokio::fs::symlink_metadata(root).await {
            Ok(md) if md.is_dir() => {}
            _ => {
                return vec![check_item(
                    "docroot",
                    "Document root",
                    "error",
                    format!("{root} is missing or is not a directory"),
                    "",
                )];
            }
        }
        let Some(site_uid) = uid_of_user(user).await else {
            return vec![check_item(
                "system_user",
                "System user",
                "error",
                format!("no system user named {user} on this node"),
                "",
            )];
        };

        let mut items = vec![self.nginx_traverse_item(root).await];
        let is_wp = detect_wp_install_on_disk(root).await.is_some();
        let entries = hyperion_adapters::fs::scan_tree(root)
            .await
            .unwrap_or_default();
        if entries.is_empty() {
            items.push(check_item(
                "scan",
                "Tree scan",
                "warn",
                "could not read the document tree — the checks below are incomplete".into(),
                "",
            ));
        }
        items.extend(tree_mode_findings(&entries, site_uid, user));
        if is_wp {
            items.extend(wp_write_probe_item(user, root).await);
            items.extend(wp_writable_dir_items(root, site_uid, user).await);
            items.extend(wp_config_item(root, user).await);
        }
        items.extend(site_private_dir_items(root, site_uid, user).await);
        items
    }

    /// nginx must be able to path-resolve into the docroot. Probed as the
    /// real nginx user rather than inferred from modes, because that is the
    /// question the operator actually has ("does the site 404?").
    pub(super) async fn nginx_traverse_item(&self, root: &str) -> FtpCheckItem {
        let nginx_user = self.adapters.nginx_user();
        let traverse_ok = hyperion_adapters::cmd::run(
            "/usr/bin/sudo",
            &["-u", &nginx_user, "/usr/bin/find", root, "-maxdepth", "0"],
        )
        .await
        .is_ok();
        check_item(
            "nginx_traverse",
            "nginx can reach the document root",
            if traverse_ok { "ok" } else { "error" },
            if traverse_ok {
                format!("{nginx_user} can path-resolve into {root}")
            } else {
                format!(
                    "{nginx_user} cannot path-resolve into {root} — every request 404s \
                     regardless of what the files themselves say"
                )
            },
            if traverse_ok { "" } else { "site_repair" },
        )
    }

    /// Repair what the permissions check found, at the level the operator
    /// asked for.
    ///
    /// `scope`:
    ///   * `tree` — ownership + 0755/0644 across the document tree. This is
    ///     the existing repair the panel button and the import pipeline
    ///     already use; one behaviour, not a fourth implementation.
    ///   * `wp_config` — tighten wp-config.php to 0640. Separate because it
    ///     is the only fix that makes something MORE restrictive than the
    ///     tree repair would leave it, and the tree repair would undo it.
    ///   * `site_dirs` — put logs/ and tmp/ back to 0750. Deliberately not
    ///     part of the tree repair, which chmods directories to 0755 and
    ///     would widen exactly these two.
    pub async fn wp_perm_repair(
        &self,
        sel: HostingSelector,
        scope: String,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let user = detail.system_user.trim().to_string();
        let root = detail.root_dir.trim().to_string();
        if user.is_empty() || root.is_empty() {
            return Err(RpcError::Validation {
                message: "this hosting has no system user or document root".into(),
            });
        }
        let site_dir = std::path::Path::new(&root)
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| RpcError::Validation {
                message: format!("{root} has no parent directory"),
            })?;
        let msg = match scope.as_str() {
            "tree" => {
                repair_tree_permissions(&user, std::path::Path::new(&root))
                    .await
                    .map_err(|e| RpcError::Validation { message: e })?;
                // The tree repair sets directories to 0755, which would widen
                // logs/ and tmp/ if they were inside it. They are siblings,
                // so they are untouched — but wp-config.php IS inside, and
                // 0644 is the mode we just applied to it. Re-tighten in the
                // same action rather than leaving the operator to notice.
                let _ = chmod_path(&format!("{root}/wp-config.php"), 0o640).await;
                format!("ownership and modes repaired under {root}")
            }
            "wp_config" => {
                chmod_path(&format!("{root}/wp-config.php"), 0o640)
                    .await
                    .map_err(|e| RpcError::Validation { message: e })?;
                "wp-config.php is now 0640 — readable by the site user only".to_string()
            }
            "site_dirs" => {
                // `site_dir` is `/home/<user>/<domain>`, whose components the
                // site user owns and can replace with symlinks. Resolve the
                // repair through a descriptor opened O_DIRECTORY|O_NOFOLLOW on
                // `<domain>` and chmod/chown logs/ and tmp/ fd-relative — never
                // a path-based chmod + `chown -R`, which a swapped `<domain>`
                // symlink would redirect onto a system directory as root.
                let Some(uid) = uid_of_user(&user).await else {
                    return Err(RpcError::Validation {
                        message: format!("no such system user {user}"),
                    });
                };
                let gid = gid_of_user(&user).await.unwrap_or(uid);
                let done = hyperion_adapters::fs::repair_site_dirs_no_follow(&site_dir, uid, gid)
                    .await
                    .map_err(|e| RpcError::Validation {
                        message: e.to_string(),
                    })?;
                if done.is_empty() {
                    "no logs/ or tmp/ directory to repair".to_string()
                } else {
                    format!("{} set to 0750", done.join(" and "))
                }
            }
            other => {
                return Err(RpcError::Validation {
                    message: format!("unknown repair scope {other:?}"),
                })
            }
        };
        self.append_audit(
            "hosting.permissions.repair",
            Some(detail.id.as_str()),
            &serde_json::json!({"scope": scope, "user": user}).to_string(),
            "ok",
        )
        .await;
        Ok(msg)
    }

    /// Park or restore `wp-content/object-cache.php` by hand.
    ///
    /// The escape hatch for a site already down. Everything else that could
    /// remove this drop-in — deactivating the plugin, deleting it, disabling
    /// Redis through the panel — needs a WordPress that boots, and the
    /// drop-in is precisely what stops it booting. This touches the file
    /// directly.
    pub async fn wp_dropin_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let moved = hyperion_adapters::wpcli::set_object_cache_dropin(
            &detail.system_user,
            &detail.root_dir,
            enabled,
        )
        .await
        .map_err(|e| RpcError::Validation {
            message: e.to_string(),
        })?;
        self.append_audit(
            "hosting.wp.object_cache_dropin",
            Some(detail.id.as_str()),
            &serde_json::json!({"enabled": enabled, "moved": moved}).to_string(),
            "ok",
        )
        .await;
        Ok(if !moved {
            "Nothing to move — there is no object-cache drop-in here.".to_string()
        } else if enabled {
            "object-cache.php restored. If Redis is still unreachable the site will \
             fatal again."
                .to_string()
        } else {
            "object-cache.php parked as object-cache.php.hyperion-disabled. WordPress \
             falls back to its database cache, so the site should load again."
                .to_string()
        })
    }

    /// Does this site take public sign-ups, and what do they become?
    pub async fn wp_registration_get(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpRegistrationView, RpcError> {
        let detail = self.get(sel).await?;
        self.adapters
            .wp_registration_get(&detail.system_user, &detail.root_dir)
            .await
            .map_err(|e| RpcError::Internal_with(format!("registration read: {e}")))
    }

    /// Open or close public sign-ups.
    ///
    /// The one control on this card that actually closes the door. A rate
    /// limit narrows it and a ban counts the ones already through; this stops
    /// WordPress creating the account at all.
    pub async fn wp_registration_set(
        &self,
        sel: HostingSelector,
        open: bool,
    ) -> Result<hyperion_types::WpRegistrationView, RpcError> {
        let detail = self.get(sel).await?;
        self.adapters
            .wp_registration_set(&detail.system_user, &detail.root_dir, open)
            .await
            .map_err(|e| RpcError::Internal_with(format!("registration write: {e}")))?;
        self.append_audit(
            "hosting.wp_registration",
            Some(detail.id.as_str()),
            &serde_json::json!({ "open": open }).to_string(),
            "ok",
        )
        .await;
        // Read it BACK rather than reporting what was asked for. wp-cli can
        // exit 0 on a site whose database is unreachable, and a card that
        // says "closed" over a site still taking sign-ups is worse than one
        // that says nothing.
        self.wp_registration_get(HostingSelector::Id(detail.id))
            .await
    }

    /// Notice a registration flood and tell somebody.
    ///
    /// No ban, deliberately. Every request here returned 200 — the accounts
    /// exist — so blocking the addresses afterwards neither undoes them nor
    /// stops the next batch from somewhere else. What helps is the operator
    /// knowing within the hour, and knowing that the fix is WordPress's own
    /// registration switch rather than a firewall rule.
    pub(super) async fn warn_on_signup_flood(
        &self,
        s: &hyperion_types::HostingSummary,
        access: &std::path::Path,
        since: i64,
    ) {
        // The site user owns this log: read it no-follow, as a regular file,
        // and only its last megabyte — a link to /dev/zero or a FIFO, or a
        // log grown to gigabytes, must not take the protection tick down.
        let Ok(body) = hyperion_adapters::fs::tail_lines(access, usize::MAX).await else {
            // Unreadable is not calm. It produces no message rather than a
            // reassuring one, and the brute-force coverage stamp above
            // already records what was and was not read.
            return;
        };
        let (count, ips) = count_registrations(&body, since);
        if count < Self::SIGNUP_FLOOD_THRESHOLD {
            return;
        }
        // One message per day per site. A flood lasting hours must not turn
        // into hourly alerts — an operator who mutes the channel to stop the
        // noise is worse off than one who was never told.
        let now = now_secs();
        let last =
            hyperion_state::hosting_kv::get(&self.pool, s.id.as_str(), Self::SIGNUP_FLOOD_KV_KEY)
                .await
                .ok()
                .flatten()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
        if now - last < 86_400 {
            return;
        }
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            s.id.as_str(),
            Self::SIGNUP_FLOOD_KV_KEY,
            &now.to_string(),
            now,
        )
        .await;

        // The two numbers together are the diagnosis, and the advice differs.
        // Many addresses means a botnet, and the operator's first instinct —
        // ban the address — is the wrong move and costs the hour that matters.
        let shape = if ips > 10 {
            format!(
                "from {ips} different addresses. Banning them one at a time will not help:                  each one signs up once and every request succeeds, so there is no repeated                  failure for the ban sweep to count"
            )
        } else {
            format!("from {ips} address(es)")
        };
        tracing::warn!(
            domain = %s.domain, registrations = count, addresses = ips,
            "sign-up flood: WordPress registrations far above normal"
        );
        self.notify_slack(
            None,
            &format!(
                "{}: {} WordPress sign-ups in the last scan window, {}.

                 If the site does not need public registration, switch it off on its                  Security card — that closes the door. If it does, the same card can                  rate-limit sign-ups, and the registration form needs a CAPTCHA.",
                s.domain, count, shape
            ),
        )
        .await;
        // Nothing is down — accounts are being created — so a warning.
        self.notify_admins_say(
            "warn",
            "ops.signup_flood",
            &[
                ("domain", s.domain.as_str()),
                ("count", count.to_string().as_str()),
                ("ips", ips.to_string().as_str()),
            ],
            &format!("/hostings/{}#wordpress", s.domain),
            &format!("wp.signup_flood:{}", s.domain),
        )
        .await;
    }

    /// Return the recorded WordPress install for a hosting, if any.
    ///
    /// Self-healing: when the `wp_installs` row is missing but
    /// `<root_dir>/wp-config.php` + `<root_dir>/wp-includes/
    /// version.php` are both present on disk, WordPress IS installed
    /// (most likely Hyperion's record_install lost the write to a
    /// network glitch / DB lock; or the operator installed via SSH /
    /// migrated from another panel). We:
    ///   1. Parse `$wp_version` out of `wp-includes/version.php`
    ///      with a regex (no shell-out — fast, no wp-cli dep).
    ///   2. Insert the recovered row into `wp_installs` so the
    ///      next call hits the fast DB path.
    ///   3. Append an audit entry so the operator can trace the
    ///      adoption back to a specific moment.
    /// This means a fresh-create that "lost" the install record
    /// recovers transparently on the very next page load — the
    /// operator never sees a spurious "Install WordPress" form
    /// for an already-installed site.
    pub async fn wp_status(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<WpInstallStatus>, RpcError> {
        let detail = self.get(sel).await?;
        if let Some(row) = wordpress::get_install(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp lookup: {e}")))?
        {
            // The recorded version is the one it was installed with; what
            // is on disk now is the truth (one small file read).
            let wp_version = self
                .refresh_wp_version(&detail.id, &detail.root_dir, &row.wp_version)
                .await;
            return Ok(Some(WpInstallStatus {
                hosting_id: row.hosting_id,
                site_url: row.site_url,
                wp_version,
                installed_at: row.installed_at,
                last_pack_hash: row.last_pack_hash,
            }));
        }
        // Filesystem fallback. Skip for non-php hostings (no WP
        // possible) and for empty root_dir (provisioning state).
        if detail.root_dir.is_empty() {
            return Ok(None);
        }
        let Some(detected_version) = detect_wp_install_on_disk(&detail.root_dir).await else {
            return Ok(None);
        };
        // Self-heal: record the detected install so subsequent
        // page loads don't re-probe the filesystem.
        let site_url = format!("https://{}", detail.domain);
        let pack_hash = wordpress::pack_hash(&format!(
            "detected-{}-{}",
            detected_version.trim(),
            detail.id.as_str()
        ));
        let now = now_secs();
        if let Err(e) = wordpress::record_install(
            &self.pool,
            &detail.id,
            &site_url,
            &detected_version,
            &pack_hash,
            now,
        )
        .await
        {
            tracing::warn!(
                hosting_id = %detail.id.as_str(),
                error = %e,
                "wp_status: detected WP on disk but record_install failed (will retry next call)"
            );
        } else {
            self.append_audit(
                "wordpress.detected",
                Some(detail.id.as_str()),
                &serde_json::json!({
                    "site_url": site_url,
                    "version": detected_version.trim(),
                    "reason": "filesystem fallback in wp_status",
                })
                .to_string(),
                "ok",
            )
            .await;
            tracing::info!(
                hosting_id = %detail.id.as_str(),
                version = %detected_version,
                "wp_status: adopted on-disk WP install into wp_installs"
            );
        }
        Ok(Some(WpInstallStatus {
            hosting_id: detail.id.clone(),
            site_url,
            wp_version: detected_version,
            installed_at: now,
            last_pack_hash: pack_hash,
        }))
    }

    /// Bring a recorded install's version in line with
    /// `wp-includes/version.php`, returning the version to show.
    ///
    /// Core updates happen behind the panel's back — WordPress's own
    /// background updater, wp-admin, the nightly sweep — so a version
    /// written once at install goes stale with the first one. An unreadable
    /// or unparseable file never overwrites a real version with "unknown".
    pub(crate) async fn refresh_wp_version(
        &self,
        id: &HostingId,
        root_dir: &str,
        recorded: &str,
    ) -> String {
        if root_dir.trim().is_empty() {
            return recorded.to_string();
        }
        let Some(on_disk) = detect_wp_install_on_disk(root_dir).await else {
            return recorded.to_string();
        };
        if on_disk == "unknown" || on_disk == recorded {
            return recorded.to_string();
        }
        match wordpress::set_version(&self.pool, id, &on_disk).await {
            Ok(true) => tracing::info!(
                hosting_id = %id.as_str(),
                from = %recorded,
                to = %on_disk,
                "wp version: recorded version corrected from disk"
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!(
                hosting_id = %id.as_str(),
                error = %e,
                "wp version: could not record the version on disk"
            ),
        }
        on_disk
    }

    /// Re-read every recorded install's version from disk, so the hostings
    /// list shows the release each site runs now rather than the one it was
    /// installed with. Returns how many rows changed.
    pub async fn wp_version_refresh_tick(&self) -> Result<usize, RpcError> {
        let rows = wordpress::list_install_roots(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp installs: {e}")))?;
        let mut changed = 0;
        for (id, root, recorded) in rows {
            if self.refresh_wp_version(&id, &root, &recorded).await != recorded {
                changed += 1;
            }
        }
        Ok(changed)
    }

    /// List installed WordPress plugins for a hosting. Returns the
    /// plugin table + wp version + Hyperion's bulk auto-update flag
    /// (which controls whether the daily updater touches plugins at
    /// all; per-plugin auto-update is a separate WP-level setting).
    pub async fn wp_plugin_list(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpPluginListResponse, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to list plugins".into(),
            });
        }
        let (mut plugins, wp_version) = self
            .adapters
            .wp_plugin_list(&detail.system_user, &detail.root_dir)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_plugin_list".into(),
                reason: e.to_string(),
            })?;
        // Overlay the keyless defender's auto-update PAUSE state (the agent
        // doesn't know about the master-side skip-list) so the panel can badge
        // commercial plugins whose auto-update keeps failing.
        let skips = self.wp_update_skips(detail.id.as_str()).await;
        let now = now_secs();
        for p in &mut plugins {
            if let Some(e) = skips.get(&p.slug) {
                if e.paused_until > now {
                    p.auto_update_blocked = true;
                    p.auto_update_block_reason = Some(e.last_error.clone());
                }
            }
        }
        let bulk_auto_update = wordpress::get_install(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp lookup: {e}")))?
            .map(|r| r.auto_update_plugins)
            .unwrap_or(false);
        let updates_pending = plugins.iter().filter(|p| p.update_available).count() as i64;
        Ok(hyperion_types::WpPluginListResponse {
            plugins,
            wp_version,
            updates_pending,
            bulk_auto_update,
            error: None,
        })
    }

    /// Apply one plugin action (install/activate/deactivate/update/
    /// delete/auto-update toggle) via wp-cli. Every action is
    /// audit-logged with the action kind + slug (never the source URL
    /// when it carries auth).
    /// Empty this hosting's FastCGI page cache (the panel's "Purge cache"
    /// button). Returns how many cached pages were dropped; 0 when the site
    /// has no page cache. Allowed in any state — a suspended site's stale
    /// pages are exactly what someone may want gone.
    pub async fn page_cache_purge(&self, sel: HostingSelector) -> Result<u64, RpcError> {
        let detail = self.get(sel).await?;
        let pages = hyperion_adapters::nginx::purge_fastcgi_cache(detail.id.as_str())
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "page_cache_purge".into(),
                reason: e.to_string(),
            })?;
        self.append_audit(
            "hosting.page_cache.purge",
            Some(detail.id.as_str()),
            &serde_json::json!({ "domain": detail.domain, "pages": pages }).to_string(),
            "ok",
        )
        .await;
        Ok(pages)
    }

    /// Best-effort purge after something changed what the site renders
    /// (a plugin/theme change, a restore, a deploy, an auto-update). Without
    /// it a page-cached site kept serving the old HTML — the old theme, a
    /// plugin's markup that no longer exists — for up to its whole TTL,
    /// which reads to the operator as "the update did not work". A failure
    /// is logged, never surfaced: the change itself succeeded.
    pub(super) async fn purge_page_cache_after(&self, hosting_id: &str, why: &str) {
        match hyperion_adapters::nginx::purge_fastcgi_cache(hosting_id).await {
            Ok(0) => {}
            Ok(pages) => tracing::info!(hosting = hosting_id, why, pages, "page cache purged"),
            Err(e) => {
                tracing::warn!(hosting = hosting_id, why, error = %e, "page cache purge failed")
            }
        }
    }

    pub async fn wp_plugin_action(
        &self,
        sel: HostingSelector,
        slug: String,
        action: hyperion_types::WpPluginAction,
    ) -> Result<hyperion_types::WpPluginActionResult, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to manage plugins".into(),
            });
        }
        // ResumeAutoUpdate is service-only: drop the slug from the pause map so
        // the next defender sweep retries it. No wp-cli involved.
        if matches!(action, hyperion_types::WpPluginAction::ResumeAutoUpdate) {
            let mut skips = self.wp_update_skips(detail.id.as_str()).await;
            let removed = skips.remove(&slug).is_some();
            if removed {
                self.set_wp_update_skips(detail.id.as_str(), &skips).await;
            }
            self.append_audit(
                "wp.plugin.action",
                Some(detail.id.as_str()),
                &serde_json::json!({ "action": "resume_auto_update", "slug": slug, "cleared": removed })
                    .to_string(),
                "ok",
            )
            .await;
            return Ok(hyperion_types::WpPluginActionResult {
                state: "ok".into(),
                message: if removed {
                    format!("Auto-update resumed for {slug}; it'll be retried on the next sweep.")
                } else {
                    format!("{slug} was not paused.")
                },
                output_tail: String::new(),
            });
        }
        let out = self
            .adapters
            .wp_plugin_action(&detail.system_user, &detail.root_dir, &slug, &action)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_plugin_action".into(),
                reason: e.to_string(),
            })?;
        let action_label = match &action {
            hyperion_types::WpPluginAction::Install { .. } => "install",
            hyperion_types::WpPluginAction::Activate => "activate",
            hyperion_types::WpPluginAction::Deactivate => "deactivate",
            hyperion_types::WpPluginAction::Update => "update",
            hyperion_types::WpPluginAction::UpdateAll => "update_all",
            hyperion_types::WpPluginAction::Delete => "delete",
            hyperion_types::WpPluginAction::SetAutoUpdate { enabled } => {
                if *enabled {
                    "auto_update_enable"
                } else {
                    "auto_update_disable"
                }
            }
            // Handled + returned above; never reaches the adapter path.
            hyperion_types::WpPluginAction::ResumeAutoUpdate => "resume_auto_update",
            hyperion_types::WpPluginAction::Reinstall => "reinstall",
        };
        self.append_audit(
            "wp.plugin.action",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "action": action_label,
                "slug": slug,
                "state": out.state,
                // The reason, on failure only. Without it the explanation
                // lived in a flash message and nowhere else: once the
                // operator navigated away it was gone, and the audit row
                // recorded that something failed while saying nothing about
                // what. Bounded, because wp-cli output can be long.
                "reason": if out.state == "failed" {
                    let mut r = out.message.clone();
                    r.truncate(600);
                    Some(r)
                } else {
                    None
                },
            })
            .to_string(),
            &out.state,
        )
        .await;
        if !matches!(action, hyperion_types::WpPluginAction::SetAutoUpdate { .. }) {
            self.purge_page_cache_after(detail.id.as_str(), "wp.plugin.action")
                .await;
        }
        Ok(out)
    }

    /// `wp theme list` for a hosting. Mirrors wp_plugin_list shape.
    pub async fn wp_theme_list(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpThemeListResponse, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to list themes".into(),
            });
        }
        let (themes, wp_version) = self
            .adapters
            .wp_theme_list(&detail.system_user, &detail.root_dir)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_theme_list".into(),
                reason: e.to_string(),
            })?;
        let updates_pending = themes.iter().filter(|t| t.update_available).count() as i64;
        Ok(hyperion_types::WpThemeListResponse {
            themes,
            wp_version,
            updates_pending,
            error: None,
        })
    }

    /// Apply one theme action (install / activate / update / delete /
    /// update-all) via wp-cli. Audit-logged with the action label +
    /// slug.
    pub async fn wp_theme_action(
        &self,
        sel: HostingSelector,
        slug: String,
        action: hyperion_types::WpThemeAction,
    ) -> Result<hyperion_types::WpThemeActionResult, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to manage themes".into(),
            });
        }
        let out = self
            .adapters
            .wp_theme_action(&detail.system_user, &detail.root_dir, &slug, &action)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_theme_action".into(),
                reason: e.to_string(),
            })?;
        let action_label = match &action {
            hyperion_types::WpThemeAction::Install { .. } => "install",
            hyperion_types::WpThemeAction::Activate => "activate",
            hyperion_types::WpThemeAction::Update => "update",
            hyperion_types::WpThemeAction::UpdateAll => "update_all",
            hyperion_types::WpThemeAction::Delete => "delete",
        };
        self.append_audit(
            "wp.theme.action",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "action": action_label,
                "slug": slug,
                "state": out.state,
            })
            .to_string(),
            &out.state,
        )
        .await;
        self.purge_page_cache_after(detail.id.as_str(), "wp.theme.action")
            .await;
        Ok(out)
    }

    /// Issue a real Let's Encrypt cert via HTTP-01 + install it.
    /// Refuses unless DNS resolves here (override via req.require_dns_match=false).
    /// Follow `domain`'s redirect chain against THIS server and report a
    /// cycle, or `None` when the site settles.
    ///
    /// Aimed at loopback with an explicit Host/SNI, so it tests the vhost we
    /// just wrote rather than whatever public DNS or a CDN in front of it
    /// currently points at — and so it works before DNS has moved, and on a
    /// proxied domain where the edge would answer instead of us.
    ///
    /// `-k` because the bootstrap certificate is self-signed and a TLS
    /// complaint would mask the answer we came for; this probe asks "where
    /// does this redirect to", not "is the certificate trusted", and it never
    /// leaves the machine.
    ///
    /// A non-loop failure (curl missing, connection refused, timeout) returns
    /// `None`: an inconclusive probe must not block a legitimate change. This
    /// catches the certain case and stays out of the way otherwise.
    /// Probe a site for a WordPress fatal and, when there is one, name the
    /// plugin or theme that caused it.
    ///
    /// Two independent measurements, deliberately:
    ///
    ///   1. HTTP over loopback with the site's own Host — what a VISITOR
    ///      sees. A production WP fatal is a 500 with a friendly page and
    ///      no diagnostic, because display_errors is off.
    ///   2. A wp-cli run — a plugin that fatals during bootstrap kills
    ///      every wp-cli call with a stack trace that NAMES the file. The
    ///      trace visitors never see is exactly the diagnostic the panel
    ///      needs: it says what to deactivate.
    ///
    /// Neither alone is enough: the probe knows THAT it is broken, the
    /// trace knows WHY. `-k` because the origin may be on the bootstrap
    /// cert; the probe asks "does PHP answer", not "is TLS trusted".
    pub async fn wp_fatal_check(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpFatalReport, RpcError> {
        let detail = self.get(sel).await?;
        let mut report = hyperion_types::WpFatalReport::default();

        let out = tokio::process::Command::new("curl")
            .args([
                "-sS",
                "-o",
                "/dev/null",
                "-k",
                "--max-time",
                "15",
                "--resolve",
                &format!("{}:443:127.0.0.1", detail.domain),
                "-w",
                "%{http_code}",
                &format!("https://{}/", detail.domain),
            ])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("probe: {e}")))?;
        report.http_status = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<i64>()
            .unwrap_or(0);
        report.fatal = report.http_status >= 500;
        if report.http_status == 0 {
            report.probe_error = curl_failure_reason(&String::from_utf8_lossy(&out.stderr));
        }

        // Only chase a culprit when something is actually wrong — a healthy
        // site does not need a wp-cli round trip on every panel load.
        if report.fatal {
            if let Err(e) =
                hyperion_adapters::wpcli::plugin_list(&detail.system_user, &detail.root_dir).await
            {
                let text = e.to_string();
                if let Some((slug, kind)) = hyperion_adapters::wpcli::culprit_from_output(&text) {
                    report.culprit = Some(slug);
                    report.culprit_kind = kind;
                }
                // The first fatal line is the readable part; the trace
                // below it is noise at panel level.
                if let Some(line) = text
                    .lines()
                    .find(|l| l.contains("Fatal error") || l.contains("PHP Fatal"))
                {
                    report.error_excerpt = line.chars().take(300).collect();
                }
            }
        }
        report.parked_plugins = hyperion_adapters::wpcli::parked_plugins(&detail.root_dir).await;
        report.object_cache_dropin =
            hyperion_adapters::wpcli::object_cache_dropin_present(&detail.root_dir).await;
        report.object_cache_parked = tokio::fs::metadata(format!(
            "{}/wp-content/object-cache.php.hyperion-disabled",
            detail.root_dir
        ))
        .await
        .is_ok();
        Ok(report)
    }

    /// Park a fataling plugin by renaming its directory — the fix that works
    /// when WordPress cannot boot and therefore wp-cli cannot run. See the
    /// adapter for the mechanism and its refusals.
    pub async fn wp_emergency_disable(
        &self,
        sel: HostingSelector,
        slug: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        hyperion_adapters::wpcli::emergency_rename_plugin(&detail.root_dir, &slug, true)
            .await
            .map_err(|e| RpcError::Internal_with(e.to_string()))?;
        self.append_audit(
            "wp.plugin.emergency_disable",
            Some(detail.id.as_str()),
            &serde_json::json!({"slug": &slug}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Put a parked plugin's directory back — and leave it INACTIVE.
    ///
    /// The rename alone is not enough: if WordPress never booted between
    /// park and restore, `active_plugins` still lists the plugin, so the
    /// restored folder would be live again with the same fatal. A
    /// best-effort `wp plugin deactivate` right after the rename pins the
    /// deterministic outcome — folder back, plugin off — and the operator
    /// reactivates from the plugin list once an update fixed it. wp-cli
    /// works here by definition: restore is only offered when the site is
    /// answering again.
    pub async fn wp_emergency_restore(
        &self,
        sel: HostingSelector,
        slug: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel.clone()).await?;
        hyperion_adapters::wpcli::emergency_rename_plugin(&detail.root_dir, &slug, false)
            .await
            .map_err(|e| RpcError::Internal_with(e.to_string()))?;
        let _ = self
            .wp_plugin_action(
                sel,
                slug.clone(),
                hyperion_types::WpPluginAction::Deactivate,
            )
            .await;
        self.append_audit(
            "wp.plugin.emergency_restore",
            Some(detail.id.as_str()),
            &serde_json::json!({"slug": &slug}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Point WordPress's `siteurl` and `home` at `canonical_host`.
    ///
    /// Best-effort and deliberately quiet: a site that is not WordPress, has
    /// no wp-cli, or stores an address this cannot safely edit is left alone
    /// and the redirect-loop probe still guards the change. Only the HOST is
    /// rewritten — the scheme and any subdirectory are the operator's, and
    /// replacing the whole value would move a site out of its subdirectory.
    ///
    /// Runs on the node that owns the hosting, which is where wp-cli and the
    /// site's database are.
    pub(super) async fn wp_align_site_url(
        &self,
        detail: &hyperion_types::HostingDetail,
        canonical: &str,
    ) {
        // Filesystem check, not wp_status: this must work on a hosting whose
        // install record is missing, and it must not pay for a wp-cli boot on
        // a site that has no WordPress at all.
        if detect_wp_install_on_disk(&detail.root_dir).await.is_none() {
            return;
        }
        for option in ["home", "siteurl"] {
            let current = match hyperion_adapters::wpcli::run(
                &detail.system_user,
                &detail.root_dir,
                &["option", "get", option],
            )
            .await
            {
                Ok(v) => v.trim().to_string(),
                Err(e) => {
                    tracing::warn!(
                        domain = %detail.domain, option, error = %e,
                        "canonical host: could not read the WordPress address —                          leaving it to the redirect-loop probe"
                    );
                    return;
                }
            };
            let Some(next) = hyperion_adapters::wpcli::rewrite_url_host(&current, canonical) else {
                tracing::warn!(
                    domain = %detail.domain, option, %current,
                    "canonical host: WordPress address is not a plain http(s) URL —                      not touching it"
                );
                return;
            };
            if next == current {
                continue;
            }
            match hyperion_adapters::wpcli::run(
                &detail.system_user,
                &detail.root_dir,
                &["option", "update", option, &next],
            )
            .await
            {
                Ok(_) => {
                    tracing::info!(
                        domain = %detail.domain, option, from = %current, to = %next,
                        "canonical host: WordPress address updated to match"
                    );
                    self.append_audit(
                        "hosting.canonical_host.wp_aligned",
                        Some(detail.id.as_str()),
                        &serde_json::json!({
                            "option": option,
                            "from": current,
                            "to": next,
                        })
                        .to_string(),
                        "ok",
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(
                        domain = %detail.domain, option, error = %e,
                        "canonical host: could not update the WordPress address"
                    );
                    self.append_audit(
                        "hosting.canonical_host.wp_aligned",
                        Some(detail.id.as_str()),
                        &serde_json::json!({"option": option, "error": e.to_string()}).to_string(),
                        "failed",
                    )
                    .await;
                    return;
                }
            }
        }
    }

    pub(super) async fn redirect_loop_probe(&self, domain: &str) -> Option<String> {
        const MAX_HOPS: u8 = 6;
        let url = format!("https://{domain}/");
        let out = tokio::process::Command::new("curl")
            .args([
                "-sS",
                "-o",
                "/dev/null",
                "-L",
                "-k",
                "--max-redirs",
                &MAX_HOPS.to_string(),
                "--max-time",
                "10",
                "--resolve",
                &format!("{domain}:443:127.0.0.1"),
                "-D",
                "-",
                &url,
            ])
            .output()
            .await
            .ok()?;

        // curl exit 47 is "Maximum (N) redirects followed" — with a cap this
        // small on a site's own front page, that is a cycle, not a deep chain.
        if out.status.code() != Some(47) {
            return None;
        }
        let headers = String::from_utf8_lossy(&out.stdout).to_lowercase();
        let culprit = if headers.contains("x-redirect-by: wordpress") {
            // Name it. Every minute spent looking at nginx here is wasted,
            // and this is the overwhelmingly common cause.
            "WordPress is redirecting in the opposite direction, and it kept doing so \
             after its Site Address was set to match — so something else is forcing \
             the address: a `WP_HOME`/`WP_SITEURL` constant hard-coded in \
             wp-config.php (which overrides the setting and cannot be changed from \
             the database), or a redirect plugin. Check those, or pick the canonical \
             host that matches what the site already does."
                .to_string()
        } else {
            "Something on the site redirects in the opposite direction — most often the \
             application's own canonical-URL setting, or a redirect plugin. The two take \
             turns bouncing visitors, so the site fails with ERR_TOO_MANY_REDIRECTS."
                .to_string()
        };
        Some(format!(
            "Refused: this setting makes {domain} redirect in a loop, so the change has \
             been rolled back and the site is serving as it was. {culprit}"
        ))
    }
}

pub(crate) async fn detect_wp_install_on_disk(root_dir: &str) -> Option<String> {
    use std::path::Path;
    let root = Path::new(root_dir);
    // wp-config.php — proof that WP setup has run at all.
    let wp_config = root.join("wp-config.php");
    if tokio::fs::metadata(&wp_config).await.is_err() {
        return None;
    }
    // wp-includes/version.php — has the version string.
    let version_php = root.join("wp-includes").join("version.php");
    if tokio::fs::symlink_metadata(&version_php).await.is_err() {
        // wp-config exists but core is missing — this is a partial
        // install. Treat as "no WP" rather than fake a version,
        // so the operator's install button stays available to
        // recover it.
        return None;
    }
    // Root reads a file the SITE USER owns, now every few minutes for every
    // site (the version refresh): no symlinks or hard links (open_no_follow,
    // which also refuses a FIFO without blocking) and a bounded read, so a
    // version.php pointed at /dev/zero or grown to gigabytes cannot stall or
    // exhaust the agent. A real one is ~1 KiB. Present but unreadable is
    // still WordPress, just of unknown version.
    let body = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let f = hyperion_adapters::fs::open_no_follow(&version_php).ok()?;
        let mut buf = Vec::new();
        f.take(64 * 1024).read_to_end(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    })
    .await
    .ok()
    .flatten();
    let Some(body) = body else {
        return Some("unknown".to_string());
    };
    // Parse `$wp_version = '<x.y.z>'` (single or double quotes,
    // any amount of whitespace around the `=`). Defensive: only
    // accept versions of the shape [digit.][...] so we never
    // surface garbage from a corrupt file.
    for raw in body.lines() {
        let line = raw.trim_start();
        // Skip comments — both `//` and `#` and `/*` styles can
        // legally appear above the version line.
        if line.starts_with("//") || line.starts_with('#') || line.starts_with("/*") {
            continue;
        }
        let Some(rest) = line.strip_prefix("$wp_version") else {
            continue;
        };
        // Allow optional whitespace, then `=`, then any whitespace,
        // then a quote.
        let after_eq = match rest.split_once('=') {
            Some((_, r)) => r.trim_start(),
            None => continue,
        };
        let quote_char = after_eq.chars().next();
        let inside = match quote_char {
            Some(q @ ('\'' | '"')) => {
                let s = &after_eq[1..];
                match s.find(q) {
                    Some(end) => &s[..end],
                    None => continue,
                }
            }
            _ => continue,
        };
        if inside.is_empty() {
            continue;
        }
        if !inside
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c.is_ascii_alphanumeric())
        {
            continue;
        }
        return Some(inside.to_string());
    }
    // version.php existed but didn't match the expected shape —
    // still WP, just unknown version. The detail UI shows "unknown"
    // as the version which is honest about what we observed.
    Some("unknown".to_string())
}

/// "`first` (and N more)" for a finding that names its first offender.
fn first_and_more(n: usize) -> String {
    if n > 1 {
        format!(" (and {} more)", n - 1)
    } else {
        String::new()
    }
}

/// The mode/ownership findings over one scanned document tree.
pub(super) fn tree_mode_findings(
    entries: &[hyperion_adapters::fs::TreeEntry],
    site_uid: u32,
    user: &str,
) -> Vec<FtpCheckItem> {
    let fix_if = |bad: bool| if bad { "site_repair" } else { "" };
    let grade = |bad: bool| if bad { "error" } else { "ok" };
    let mut items = Vec::new();

    // Ownership. PHP runs as this user; anything it does not own, it
    // cannot write — the state a restore or an import from another box
    // leaves behind.
    let foreign: Vec<&hyperion_adapters::fs::TreeEntry> =
        entries.iter().filter(|e| e.uid != site_uid).collect();
    items.push(check_item(
        "owner",
        "Owned by the site user",
        grade(!foreign.is_empty()),
        match foreign.first() {
            None => format!("everything is owned by {user}"),
            Some(e) => format!(
                "{} is owned by uid {}, not {user}{}",
                e.path,
                e.uid,
                first_and_more(foreign.len())
            ),
        },
        fix_if(!foreign.is_empty()),
    ));

    // Directories need world-traverse and static files world-read,
    // because nginx opens them itself as a different user.
    let unreadable_dirs: Vec<&str> = entries
        .iter()
        .filter(|e| e.kind == 'd' && e.mode & 0o001 == 0)
        .map(|e| e.path.as_str())
        .collect();
    items.push(check_item(
        "dir_traverse",
        "Directories traversable by nginx",
        grade(!unreadable_dirs.is_empty()),
        match unreadable_dirs.first() {
            None => "every directory has o+x".into(),
            Some(p) => format!(
                "{p} has no o+x, so nginx cannot enter it ({} affected)",
                unreadable_dirs.len()
            ),
        },
        fix_if(!unreadable_dirs.is_empty()),
    ));

    // .php is served through PHP-FPM (which reads as the site user), and
    // the vhost already denies dotfiles and a list of archive/backup
    // extensions — flagging those would be noise about files nginx will
    // never serve anyway.
    let denied_ext = [
        "sql", "bak", "old", "orig", "save", "swp", "tar", "gz", "tgz", "zip", "log", "ini", "sh",
        "php",
    ];
    let unreadable_files: Vec<&str> = entries
        .iter()
        .filter(|e| e.kind == 'f' && e.mode & 0o004 == 0)
        .filter(|e| {
            let name = e.path.rsplit('/').next().unwrap_or("");
            if name.starts_with('.') {
                return false;
            }
            !denied_ext
                .iter()
                .any(|x| name.to_ascii_lowercase().ends_with(&format!(".{x}")))
        })
        .map(|e| e.path.as_str())
        .collect();
    items.push(check_item(
        "static_readable",
        "Static files readable by nginx",
        grade(!unreadable_files.is_empty()),
        match unreadable_files.first() {
            None => "every servable file has o+r".into(),
            Some(p) => format!(
                "{p} has no o+r, so it 403s ({} affected)",
                unreadable_files.len()
            ),
        },
        fix_if(!unreadable_files.is_empty()),
    ));

    // World-writable is a real finding on a shared box — every other
    // hosting has a local user. Symlinks are excluded: their mode is
    // unconditionally 0777 on Linux and chmod cannot change it, so
    // flagging them would be a finding no repair can ever clear.
    let ww: Vec<&str> = entries
        .iter()
        .filter(|e| e.kind != 'l' && e.mode & 0o002 != 0)
        .map(|e| e.path.as_str())
        .collect();
    items.push(check_item(
        "world_writable",
        "Nothing world-writable",
        grade(!ww.is_empty()),
        match ww.first() {
            None => "no world-writable files or directories".into(),
            Some(p) => format!(
                "{p} is writable by every local user on this node ({} affected) — \
                 usually the result of a chmod 777 'fix'",
                ww.len()
            ),
        },
        fix_if(!ww.is_empty()),
    ));

    let suid: Vec<&str> = entries
        .iter()
        .filter(|e| e.kind == 'f' && e.mode & 0o6000 != 0)
        .map(|e| e.path.as_str())
        .collect();
    if let Some(first) = suid.first() {
        // Reported, never auto-cleared: a setuid binary in a web root is
        // either a compromise or something deliberate, and both deserve a
        // human rather than a silent chmod.
        items.push(check_item(
            "setuid",
            "No setuid/setgid files",
            "warn",
            format!(
                "{first} carries setuid/setgid ({} total) — investigate before removing it",
                suid.len()
            ),
            "",
        ));
    }
    items
}

/// The definitive test, before any mode-based inference: can the site user
/// ACTUALLY create a directory where WordPress needs one? "Could not create
/// directory" has several causes that look identical from outside and only
/// one of them is a permission — an exhausted disk quota, a filesystem out
/// of inodes, a mount gone read-only, open_basedir. A mode check calls all
/// of those healthy and sends the operator hunting for a bug that is not
/// there.
///
/// Probed inside wp-content, because that is the directory WordPress
/// creates `upgrade/<plugin>` under during an install.
pub(super) async fn wp_write_probe_item(user: &str, root: &str) -> Option<FtpCheckItem> {
    let probe_dir = format!("{root}/wp-content");
    tokio::fs::metadata(&probe_dir).await.ok()?;
    let e = match hyperion_adapters::fs::write_probe(user, &probe_dir).await {
        Ok(()) => {
            return Some(check_item(
                "write_probe",
                "WordPress can create directories",
                "ok",
                format!("{user} created and removed a directory in wp-content"),
                "",
            ))
        }
        Err(e) => e,
    };
    let (bytes, inodes) = hyperion_adapters::fs::filesystem_headroom(&probe_dir).await;
    // Inodes reported separately on purpose: a filesystem with gigabytes
    // free and no inodes left fails every mkdir, and looking only at bytes
    // makes that look impossible.
    let headroom = format!(
        "filesystem has {} free and {} free inodes",
        bytes
            .map(|b| format!("{:.1} GiB", b as f64 / 1024.0 / 1024.0 / 1024.0))
            .unwrap_or_else(|| "unknown".into()),
        inodes
            .map(|i| i.to_string())
            .unwrap_or_else(|| "an unknown number of".into()),
    );
    let cause_hint = if e.contains("Disk quota exceeded") || e.contains("quota") {
        " This is the hosting's DISK QUOTA, not a permission — \
         raise it under Settings & limits, or free space in the site."
    } else if inodes == Some(0) {
        " The filesystem is OUT OF INODES — no file can be created \
         anywhere on it, whatever the free space says."
    } else if e.contains("Read-only file system") {
        " The filesystem is mounted READ-ONLY — see Services → \
         Read-only rootfs."
    } else {
        ""
    };
    Some(check_item(
        "write_probe",
        "WordPress can create directories",
        "error",
        format!("{user} could not create a directory in wp-content: {e}.{cause_hint} ({headroom})"),
        // Only offer the permission repair when it could plausibly be the
        // cause — offering it for a full disk would waste the operator's
        // time and teach them the button does nothing.
        if cause_hint.is_empty() {
            "site_repair"
        } else {
            ""
        },
    ))
}

/// What WordPress itself must be able to write. 0o300, not 0o200: creating
/// an entry needs write AND search, so a 0600 plugins directory passes
/// "owner can write" and still fails every install.
pub(super) async fn wp_writable_dir_items(
    root: &str,
    site_uid: u32,
    user: &str,
) -> Vec<FtpCheckItem> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let mut items = Vec::new();
    for (rel, label) in [
        ("wp-content", "wp-content"),
        ("wp-content/plugins", "Plugins directory"),
        ("wp-content/themes", "Themes directory"),
        ("wp-content/uploads", "Uploads directory"),
        ("wp-content/upgrade", "Upgrade directory"),
    ] {
        // upgrade/ and uploads/ are created on demand; absent is not a fault.
        let Ok(md) = tokio::fs::metadata(format!("{root}/{rel}")).await else {
            continue;
        };
        let mode = md.permissions().mode() & 0o7777;
        let ok = md.uid() == site_uid && mode & 0o300 == 0o300;
        items.push(check_item(
            "wp_writable",
            label,
            if ok { "ok" } else { "error" },
            if ok {
                format!("{rel} is writable by {user}")
            } else {
                format!(
                    "{rel} is uid {} mode {:o} — WordPress cannot write here, so \
                     plugin/theme installs and updates fail",
                    md.uid(),
                    mode
                )
            },
            if ok { "" } else { "site_repair" },
        ));
    }
    items
}

/// wp-config.php holds the database credentials and is read by PHP running
/// as the site user — nginx never serves it (the vhost sends .php to FPM).
/// Every OTHER hosting on this node has a local user who can read a
/// world-readable file.
pub(super) async fn wp_config_item(root: &str, user: &str) -> Option<FtpCheckItem> {
    use std::os::unix::fs::PermissionsExt;
    // symlink_metadata, like the session_dir and logs_dir checks: the site
    // user owns this tree, so `metadata` would follow a symlink they planted
    // and report the mode of whatever it aims at — a check that passes while
    // the real file is wide open.
    let md = tokio::fs::symlink_metadata(format!("{root}/wp-config.php"))
        .await
        .ok()?;
    let mode = md.permissions().mode() & 0o7777;
    let is_link = md.file_type().is_symlink();
    let exposed = is_link || mode & 0o004 != 0;
    Some(check_item(
        "wp_config",
        "wp-config.php not readable by other users",
        // ERROR, not warn. The test is exact — `mode & 0o004` — and nothing
        // on this node needs o+r on the file: PHP-FPM renders `user =
        // <site_user>` so PHP reads it as the OWNER, nginx never reads it
        // (.php goes to FPM), and `useradd -U` gives the site its own group.
        // So a world-readable wp-config.php is not a smell, it is another
        // tenant already able to read it — the same class as session_dir,
        // which is graded `error` too. Graded `warn`, it sat under the triage
        // line and looked like housekeeping.
        if exposed { "error" } else { "ok" },
        if is_link {
            "wp-config.php is a SYMLINK — whatever it points at is what \
             PHP reads, and its permissions are not this file's. Replace it \
             with the real file."
                .to_string()
        } else if exposed {
            format!(
                "mode {mode:o} — every other site's system user on this node can \
                 read the database password AND the auth salts, which let any \
                 local user forge an admin login cookie for this site. 0640 is \
                 enough for PHP, which runs as {user}."
            )
        } else {
            format!("mode {mode:o}")
        },
        // A symlink is not fixed by chmod — chmod_path refuses to follow
        // one, so offering the button would only produce a failure the
        // operator cannot act on.
        if exposed && !is_link {
            "wp_config_tighten"
        } else {
            ""
        },
    ))
}

/// The site's tmp (PHP sessions) and logs directories beside htdocs.
/// World-readable sessions on a shared box means another tenant can read
/// (and forge) logged-in sessions.
pub(super) async fn site_private_dir_items(
    root: &str,
    site_uid: u32,
    user: &str,
) -> Vec<FtpCheckItem> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let mut items = Vec::new();
    let Some(site_dir) = std::path::Path::new(root)
        .parent()
        .map(|p| p.display().to_string())
        .filter(|s| !s.is_empty())
    else {
        return items;
    };
    let tmp = format!("{site_dir}/tmp");
    if let Ok(md) = tokio::fs::symlink_metadata(&tmp).await {
        let mode = md.permissions().mode() & 0o7777;
        let bad =
            !md.is_dir() || md.uid() != site_uid || mode & 0o300 != 0o300 || mode & 0o007 != 0;
        items.push(check_item(
            "session_dir",
            "PHP session directory private",
            if bad { "error" } else { "ok" },
            if bad {
                format!(
                    "{tmp} is uid {} mode {:o} — sessions live here \
                     (session.save_path), so any other local user who can read it \
                     can hijack a logged-in session",
                    md.uid(),
                    mode
                )
            } else {
                format!("{tmp} is {mode:o}, owned by {user}")
            },
            if bad { "site_dirs_tighten" } else { "" },
        ));
    }
    let logs = format!("{site_dir}/logs");
    if let Ok(md) = tokio::fs::symlink_metadata(&logs).await {
        let mode = md.permissions().mode() & 0o7777;
        // 0750 by design — a check must not demand 0755 here.
        if mode & 0o007 != 0 {
            items.push(check_item(
                "logs_dir",
                "Log directory private",
                "warn",
                format!("{logs} is {mode:o}; access logs record visitor IPs"),
                "site_dirs_tighten",
            ));
        }
    }
    items
}
