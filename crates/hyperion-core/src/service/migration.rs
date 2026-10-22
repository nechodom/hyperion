//! Moving and copying hostings between nodes: export, bundle transfer, import.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Export a hosting as a self-contained migration bundle: an
    /// archive (tar+gz of htdocs + optional DB dump) plus a JSON
    /// manifest describing how to recreate the hosting on a different
    /// node. The bundle lives at `/var/lib/hyperion/migration/<id>/`
    /// — the operator transfers it out-of-band (scp/rsync/S3) and
    /// runs `hctl hosting import --bundle <file>` on the target.
    /// Read one whitelisted file from
    /// `/var/lib/hyperion/migration/<bundle_id>/` and return its
    /// bytes as base64. Used by the master to pull a bundle off
    /// a worker source during worker-to-X migration.
    ///
    /// Whitelist: "manifest.json", "archive.tar.gz" or "archive.sql". Both
    /// the bundle_id and the filename are validated to refuse
    /// path traversal — ULID-shape for bundle_id, exact match for
    /// filename.
    ///
    /// `len > 0`: one slice of at most 16 MiB at `offset`, with the file's
    /// total size and whether this slice reaches its end. `len == 0`: the
    /// whole file at once (an older master's call), capped at 1 GiB — in
    /// practice the master's response cap stops it near 144 MiB, which is
    /// why the master now asks in slices.
    pub async fn hosting_migration_fetch_bundle_file(
        &self,
        bundle_id: String,
        filename: String,
        offset: u64,
        len: u32,
    ) -> Result<(String, u64, bool), RpcError> {
        use base64::Engine;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        if !bundle_id_ok(&bundle_id) {
            return Err(RpcError::Validation {
                message: format!("bundle_id has illegal chars: {bundle_id:?}"),
            });
        }
        if !matches!(
            filename.as_str(),
            "manifest.json" | "archive.tar.gz" | "archive.sql"
        ) {
            return Err(RpcError::Validation {
                message: format!(
                    "filename must be `manifest.json`, `archive.tar.gz` or `archive.sql`, \
                     got {filename:?}"
                ),
            });
        }
        let path = std::path::PathBuf::from("/var/lib/hyperion/migration")
            .join(&bundle_id)
            .join(&filename);
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|e| RpcError::NotFound {
                kind: "migration_bundle_file".into(),
                id: format!("{bundle_id}/{filename}: {e}"),
            })?;
        let total = file
            .metadata()
            .await
            .map_err(|e| RpcError::Internal_with(format!("stat: {e}")))?
            .len();
        let want: u64 = if len == 0 {
            const MAX: u64 = 1024 * 1024 * 1024; // whole-file mode: 1 GiB cap
            if total > MAX {
                return Err(RpcError::Validation {
                    message: format!("bundle file {total} bytes exceeds 1 GiB cap"),
                });
            }
            total
        } else {
            u64::from(len).min(16 * 1024 * 1024)
        };
        let start = if len == 0 { 0 } else { offset.min(total) };
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| RpcError::Internal_with(format!("seek: {e}")))?;
        let mut buf = Vec::with_capacity(want.min(total - start) as usize);
        (&mut file)
            .take(want)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| RpcError::Internal_with(format!("read: {e}")))?;
        let eof = start + buf.len() as u64 >= total;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
        Ok((b64, total, eof))
    }

    /// Everything about a site beyond what `create` takes, for the bundle.
    ///
    /// Each read is best-effort: a setting that cannot be read is left out
    /// (and the importer reports "not set" for it) rather than failing an
    /// export whose files and database are fine.
    pub(crate) async fn collect_carried_settings(
        &self,
        detail: &HostingDetail,
    ) -> hyperion_types::migration::HostingCarriedSettings {
        use hyperion_types::migration as m;
        let id = detail.id.as_str();
        let mut out = m::HostingCarriedSettings {
            vhost_options: Some(detail.vhost_options.clone()),
            redis_enabled: detail.wp_extras.redis_enabled,
            ..Default::default()
        };
        if let Ok(Some(row)) = hyperion_state::limits::get(&self.pool, &detail.id).await {
            out.limits = Some(row_to_limits(row));
        }
        if let Ok(row) = hyperion_state::hosting_quotas::read(&self.pool, id).await {
            out.quota = Some(hyperion_types::HostingQuotaView {
                hosting_id: row.hosting_id,
                disk_soft_kib: row.disk_soft_kib,
                disk_hard_kib: row.disk_hard_kib,
                mem_limit_mib: row.mem_limit_mib,
                bw_soft_mib: row.bw_soft_mib,
                bw_hard_mib: row.bw_hard_mib,
                applied_at: None,
                last_error: None,
                updated_at: row.updated_at,
                exceed_action: self.hosting_quota_action(id).await.as_str().to_string(),
            });
        }
        if detail.vhost_options.basic_auth_set {
            out.basic_auth_hash =
                hyperion_state::hostings::get_basic_auth_hash(&self.pool, &detail.id)
                    .await
                    .ok()
                    .filter(|h| !h.is_empty());
        }
        let wp = &detail.wp_extras;
        if wp.wp_debug_enabled {
            out.wp_debug = Some(m::CarriedWpDebug {
                enabled: true,
                log: wp.wp_debug_log,
                display: wp.wp_debug_display,
            });
        }
        let kv = hyperion_state::hosting_kv::list(&self.pool, id)
            .await
            .unwrap_or_default();
        let kv_get = |k: &str| {
            kv.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
                .unwrap_or("")
        };
        out.kv = kv
            .iter()
            .filter(|(k, _)| carried_kv_scope(k).is_some())
            .cloned()
            .collect();
        if let Ok(st) = self
            .sftp_status(HostingSelector::Id(detail.id.clone()))
            .await
        {
            if st.enabled || !st.keys.is_empty() {
                out.sftp_enabled = st.enabled;
                out.sftp_keys = st.keys;
            }
        }
        if let Ok(rows) =
            hyperion_state::ftp_accounts::list_for_hosting(&self.pool, &detail.id).await
        {
            let root = detail.root_dir.trim_end_matches('/');
            out.ftp_logins = rows
                .into_iter()
                .map(|r| m::CarriedFtpLogin {
                    name: r.login.split('.').next().unwrap_or_default().to_string(),
                    path: r
                        .local_root
                        .strip_prefix(root)
                        .unwrap_or("")
                        .trim_matches('/')
                        .to_string(),
                    label: r.label,
                })
                .collect();
        }
        if let Ok(e) = self
            .get_expiry(HostingSelector::Id(detail.id.clone()))
            .await
        {
            out.expiry = Some(e);
        }
        if let Ok(Some(mc)) = hyperion_state::monitors::get(&self.pool, &detail.id).await {
            out.monitor = Some(m::CarriedMonitor {
                enabled: mc.enabled,
                url_path: mc.url_path,
                interval_secs: mc.interval_secs,
                alert_after_fails: mc.alert_after_fails,
                alert_email: mc.alert_email,
                alert_slack_webhook: mc.alert_slack_webhook,
                alert_webhook_url: mc.alert_webhook_url,
            });
        }
        if let Ok(Some(a)) = profiles::get_apply(&self.pool, &detail.id).await {
            out.billing = Some(m::CarriedBilling {
                profile_id: a.profile_id,
                price_minor: a.price_minor,
                price_currency: a.price_currency,
                price_interval: a.price_interval,
                next_billing_at: a.next_billing_at,
                slack_webhook: a.slack_webhook,
                alert_emails: a.alert_emails,
                applied_at: a.applied_at,
                price_pinned: a.price_pinned,
            });
        }
        if let Ok(rows) = hyperion_state::packages::list_for_hosting(&self.pool, &detail.id).await {
            out.care_plans = rows
                .into_iter()
                .map(|r| m::CarriedCarePlan {
                    package_id: r.package_id,
                    package_name: r.package_name,
                    price_minor: r.price_minor,
                    price_currency: r.price_currency,
                    price_interval: r.price_interval,
                    features: r.features,
                    next_billing_at: r.next_billing_at,
                    activated_at: r.activated_at,
                    prior_state_json: r.prior_state_json,
                    letters_lang: r.letters_lang,
                    check_items: r.check_items,
                    report_omit: r.report_omit,
                    valid_from: r.valid_from,
                    enforcement_started: r.enforcement_started,
                })
                .collect();
        }

        // What exists here and deliberately stays: secrets the target makes
        // its own, and things that belong to this node.
        if self.dkim_kv_get(id).await.enabled {
            out.not_carried.push(
                "DKIM signing: the private key never leaves its node. Turn DKIM on for the \
                 new site and publish the new TXT record it shows."
                    .into(),
            );
        }
        let pat_set = tokio::fs::try_exists(gitsync_pat_path(id))
            .await
            .unwrap_or(false);
        if !kv_get("gitsync_pubkey").is_empty()
            || !kv_get("gitsync_webhook_secret").is_empty()
            || pat_set
        {
            out.not_carried.push(
                "Git deploy: the repository, branch and folder came along; the deploy key, \
                 access token and webhook secret did not. Generate a new key (or enter the \
                 token) and, if you used the webhook, turn it on again and update it at the \
                 Git host."
                    .into(),
            );
        }
        if !kv_get("staging_domain").is_empty() {
            out.not_carried.push(format!(
                "Staging copy {}: it stays where it is, as its own site.",
                kv_get("staging_domain")
            ));
        }
        out
    }

    pub async fn hosting_export(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingMigrationBundle, RpcError> {
        let detail = self.get(sel.clone()).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: format!(
                    "hosting must be active to export (current state: {})",
                    detail.state.as_str()
                ),
            });
        }
        // Reuse the backup path to produce the archive — it's already the
        // most-tested code path for "snapshot this hosting to disk".
        // Internal/transient safety backup — local only, and `NotWanted`
        // says so: nothing off-site was ever promised here, so a site pinned
        // to a target must not collect a red "no off-site copy" row for a
        // snapshot that exists only to be turned into a bundle.
        let run = self
            .backup_run(sel.clone(), Vec::new(), OffsiteSource::NotWanted, None)
            .await?;
        let archive_path_str = run
            .archive_path
            .as_ref()
            .ok_or_else(|| RpcError::Internal_with("backup did not produce an archive".into()))?;
        let archive_path = std::path::PathBuf::from(archive_path_str);
        if !archive_path.exists() {
            return Err(RpcError::Internal_with(
                "backup ran but archive missing on disk".into(),
            ));
        }

        // Bundle dir + paths.
        let bundle_id = format!("mig_{}", ulid::Ulid::new());
        let bundle_dir = std::path::PathBuf::from("/var/lib/hyperion/migration").join(&bundle_id);
        tokio::fs::create_dir_all(&bundle_dir)
            .await
            .map_err(|e| RpcError::Internal_with(format!("mkdir migration: {e}")))?;
        // SECURITY (sec-findings #6): the bundle dir holds the DB dump + manifest
        // (secrets). Lock it to 0700 so other local users can't read it.
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&bundle_dir, std::fs::Permissions::from_mode(0o700))
                .await;
        }
        let archive_dest = bundle_dir.join("archive.tar.gz");
        // Hardlink the archive into the migration dir — keeps a stable
        // path while costing zero disk (same inode). Fall back to copy
        // if the FS doesn't support hardlinks (NFS, certain overlayfs).
        if tokio::fs::hard_link(&archive_path, &archive_dest)
            .await
            .is_err()
        {
            tokio::fs::copy(&archive_path, &archive_dest)
                .await
                .map_err(|e| RpcError::Internal_with(format!("copy archive into bundle: {e}")))?;
        }

        // Compute SHA-256 of the archive for the manifest. The full
        // archive can be many GB — do it via a streaming hasher rather
        // than loading the file into memory.
        let sha = compute_sha256(&archive_dest).await?;
        let archive_bytes = tokio::fs::metadata(&archive_dest)
            .await
            .map(|m| m.len() as i64)
            .unwrap_or(0);

        // The database dump. `backup_run` writes it as a SIBLING of the
        // archive (`<domain>-<ts>.sql` next to `<domain>-<ts>.tar.gz`), not
        // inside it — so linking only the archive shipped every Move and Copy
        // without its data: the target restored the files, found no dump,
        // and reported "ok" over the empty database `create` had just made.
        // Ship it as `archive.sql`, the name `backup_restore` looks for next
        // to `archive.tar.gz`.
        let db_dump_sha256 = if detail.database.is_some() {
            let src_dump = archive_path_str
                .strip_suffix(".tar.gz")
                .map(|stem| std::path::PathBuf::from(format!("{stem}.sql")))
                .filter(|p| p.exists())
                .ok_or_else(|| {
                    RpcError::Internal_with(
                        "the backup taken for the export has no database dump".into(),
                    )
                })?;
            let dump_dest = bundle_dir.join(hyperion_types::HostingMigrationManifest::DB_DUMP_FILE);
            if tokio::fs::hard_link(&src_dump, &dump_dest).await.is_err() {
                tokio::fs::copy(&src_dump, &dump_dest)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("copy dump into bundle: {e}")))?;
            }
            Some(compute_sha256(&dump_dest).await?)
        } else {
            None
        };

        // Pull the per-hosting cron tab + WP version best-effort. The
        // operator doesn't need these to succeed for migration to work
        // — they're nice-to-have metadata.
        let crontab = self.cron_list(sel.clone()).await.unwrap_or_default();
        let wp_version = self
            .wp_status(sel.clone())
            .await
            .ok()
            .flatten()
            .map(|w| w.wp_version);

        let manifest = hyperion_types::HostingMigrationManifest {
            schema_version: hyperion_types::HostingMigrationManifest::CURRENT_SCHEMA_VERSION,
            source_hosting_id: detail.id.clone(),
            source_node_id: self.current_node_id(),
            source_hyperion_version: self.current_git_sha.clone(),
            exported_at: now_secs(),
            domain: detail.domain.clone(),
            aliases: detail.aliases.clone(),
            kind: detail.kind.clone(),
            php_version: detail.php_version,
            db_engine: detail.database.as_ref().map(|d| match d.engine {
                hyperion_types::DbProvision::MariaDB => "mariadb".to_string(),
                hyperion_types::DbProvision::Postgres => "postgres".to_string(),
            }),
            had_real_cert: detail
                .cert
                .as_ref()
                .map(|c| !c.issuer.contains("self-signed"))
                .unwrap_or(false),
            wp_version,
            crontab,
            archive_sha256: sha.clone(),
            proxy_upstream_url: detail.proxy_upstream_url.clone(),
            db_dump_sha256,
            renamed_from: None,
            source_tree: std::path::Path::new(&detail.root_dir)
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            source_home: self.home_dir_for(&detail.system_user),
            settings: Some(self.collect_carried_settings(&detail).await),
        };
        let manifest_path = bundle_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| RpcError::Internal_with(format!("manifest serialize: {e}")))?;
        tokio::fs::write(&manifest_path, manifest_json)
            .await
            .map_err(|e| RpcError::Internal_with(format!("manifest write: {e}")))?;

        self.append_audit(
            "hosting.migration.export",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "bundle_id": &bundle_id,
                "archive_bytes": archive_bytes,
                "archive_sha256": &sha,
            })
            .to_string(),
            "ok",
        )
        .await;

        // download_base_url + bundle_token are filled in by the web
        // handler (only it knows the master's externally-reachable
        // URL + has the signing key). Service returns empty strings;
        // the handler enriches them before responding.
        Ok(hyperion_types::HostingMigrationBundle {
            bundle_id,
            archive_path: archive_dest.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            archive_sha256: sha,
            archive_bytes,
            created_at: now_secs(),
            source_hosting_id: detail.id,
            source_node_id: self.current_node_id(),
            source_hyperion_version: self.current_git_sha.clone(),
            download_base_url: String::new(),
            bundle_token: String::new(),
            token_expires_at: 0,
        })
    }

    /// A system user no site on this node has and no account in passwd
    /// holds: the domain's derived name, or the first free `_<n>` variant.
    /// Used for every site that did not ask for an account by name. See
    /// [`import_user_candidates`] for why such a site may not share: the
    /// account would be the source's (a Copy on the same node) or an
    /// unrelated site's (any domain whose name folds onto one already here —
    /// `my-shop.cz` and `my.shop.cz` both derive `my_shop_cz`).
    pub(super) async fn free_system_user(&self, domain: &str) -> Result<SystemUserName, RpcError> {
        for name in import_user_candidates(domain)? {
            let known = system_users::get_by_name(&self.pool, name.as_str())
                .await
                .map_err(|e| RpcError::Internal_with(format!("system user lookup: {e}")))?;
            if known.is_some() {
                continue;
            }
            // passwd too: an account Hyperion never recorded (a leftover, an
            // extra login's namespace) would be silently adopted by `create`.
            if matches!(
                hyperion_adapters::users::lookup_raw(name.as_str()).await,
                Ok(Some(_))
            ) {
                continue;
            }
            return Ok(name);
        }
        Err(RpcError::Conflict {
            message: format!("no free system user name left for {domain}"),
        })
    }

    /// Re-apply a bundle's settings to the site an import just created and
    /// filled. `is_copy` = the bundle lands under a new name (a Copy), which
    /// takes the technical settings but not billing, plans, expiry or
    /// uptime alerts (see [`hyperion_types::migration::HostingCarriedSettings`]).
    ///
    /// Never fails: the site's files and database are already in place, and
    /// a setting that does not take is a line in the report for the operator
    /// to redo by hand — not a reason to throw the import away. Every line
    /// says what happened, so "the site moved" never silently means "the
    /// site moved without its limits".
    pub(crate) async fn apply_carried_settings(
        &self,
        detail: &HostingDetail,
        settings: Option<&hyperion_types::migration::HostingCarriedSettings>,
        is_copy: bool,
    ) -> Vec<String> {
        let mut report = Vec::new();
        let Some(s) = settings else {
            report.push(
                "settings NOT carried: this bundle was exported by an older Hyperion. Limits, \
                 quota, vhost options, schedules, plans and billing must be set on the new \
                 site by hand (or update the source and run the move again)."
                    .into(),
            );
            return report;
        };
        let sel = || HostingSelector::Id(detail.id.clone());
        let id = detail.id.as_str();
        let fail = |what: &str, e: &dyn std::fmt::Display| format!("{what}: NOT carried ({e})");

        // Limits before the kv: `set_limits` rebases the PHP-memory floor on
        // a changed value, and the carried floor (php.mem_auto_state) must
        // be what stays.
        if let Some(limits) = s.limits.clone() {
            report.push(match self.set_limits(sel(), limits).await {
                Ok(l) => format!(
                    "limits: carried (PHP memory {} MB, {} workers)",
                    l.php_memory_mb, l.php_max_children
                ),
                Err(e) => fail("limits", &e),
            });
        }

        let mut kv_done = 0usize;
        let mut kv_skipped = Vec::new();
        for (k, v) in &s.kv {
            match carried_kv_scope(k) {
                Some(CarryScope::Always) => {}
                Some(CarryScope::MoveOnly) if !is_copy => {}
                Some(CarryScope::MoveOnly) => {
                    kv_skipped.push(k.as_str());
                    continue;
                }
                // Not on this node's list (a newer source, a tampered
                // manifest): leave it out rather than write unknown state.
                None => continue,
            }
            match hyperion_state::hosting_kv::set(&self.pool, id, k, v, now_secs()).await {
                Ok(()) => kv_done += 1,
                Err(e) => report.push(fail(&format!("setting {k}"), &e)),
            }
        }
        if kv_done > 0 {
            report.push(format!(
                "site settings carried: {kv_done} (backup schedule, PHP memory automation, \
                 update and protection switches, …)"
            ));
        }
        if !kv_skipped.is_empty() {
            report.push(format!(
                "not carried to the copy (they belong to the original's care service): {}",
                kv_skipped.join(", ")
            ));
        }

        if let Some(q) = s.quota.as_ref() {
            let any_cap = q.disk_soft_kib > 0
                || q.disk_hard_kib > 0
                || q.mem_limit_mib > 0
                || q.bw_soft_mib > 0
                || q.bw_hard_mib > 0;
            if any_cap || q.exceed_action == "suspend" {
                report.push(
                    match self
                        .quota_set(
                            sel(),
                            q.disk_soft_kib,
                            q.disk_hard_kib,
                            q.mem_limit_mib,
                            q.bw_soft_mib,
                            q.bw_hard_mib,
                            &q.exceed_action,
                        )
                        .await
                    {
                        Ok(v) => match v.last_error {
                            Some(e) => format!(
                                "quota: saved, but the kernel did not take the disk cap yet ({e})"
                            ),
                            None => format!(
                                "quota: carried (disk hard {} MiB, on overage: {})",
                                q.disk_hard_kib / 1024,
                                v.exceed_action
                            ),
                        },
                        Err(e) => fail("quota", &e),
                    },
                );
            }
        }

        if let Some(opts) = s.vhost_options.clone() {
            report.extend(
                self.apply_carried_vhost(detail, opts, s.basic_auth_hash.as_deref())
                    .await,
            );
        }

        if let Some(d) = s.wp_debug {
            report.push(
                match self.set_wp_debug(sel(), d.enabled, d.log, d.display).await {
                    Ok(_) => "WP_DEBUG: carried".into(),
                    Err(e) => fail("WP_DEBUG", &e),
                },
            );
        }

        if s.redis_enabled {
            report.push(match self.set_redis(sel(), true).await {
                Ok(_) => {
                    // The import parked the source's drop-in; with Redis
                    // provisioned here it can come back.
                    let _ = hyperion_adapters::wpcli::set_object_cache_dropin(
                        &detail.system_user,
                        &detail.root_dir,
                        true,
                    )
                    .await;
                    "Redis object cache: on, with new credentials on this node".into()
                }
                Err(e) => fail("Redis object cache", &e),
            });
        }

        if s.sftp_enabled || !s.sftp_keys.is_empty() {
            report.push(
                match self
                    .sftp_set(sel(), s.sftp_enabled, s.sftp_keys.clone())
                    .await
                {
                    Ok(st) => format!(
                        "SFTP: carried ({}, {} key(s))",
                        if st.enabled { "on" } else { "off" },
                        st.keys.len()
                    ),
                    Err(e) => fail("SFTP", &e),
                },
            );
        }

        for f in &s.ftp_logins {
            report.push(
                match self
                    .ftp_account_create(
                        sel(),
                        f.name.clone(),
                        f.path.clone(),
                        f.label.clone(),
                        "migration".into(),
                    )
                    .await
                {
                    // The fresh password is dropped on purpose: it is never
                    // logged, and the operator resets the login to hand one out.
                    Ok((login, _password)) => format!(
                        "extra FTP login {login}: recreated with a new password — reset it \
                         in the FTP card to hand it out"
                    ),
                    Err(e) => fail(&format!("extra FTP login {}", f.name), &e),
                },
            );
        }

        if is_copy {
            let mut left = Vec::new();
            if s.billing.is_some() {
                left.push("profile and price".to_string());
            }
            if !s.care_plans.is_empty() {
                left.push(format!("care plans ({})", s.care_plans.len()));
            }
            if s.expiry.as_ref().is_some_and(|e| e.expires_at.is_some()) {
                left.push("renewal date".to_string());
            }
            if s.monitor.as_ref().is_some_and(|m| m.enabled) {
                left.push("uptime monitor".to_string());
            }
            if !left.is_empty() {
                report.push(format!(
                    "not carried to the copy (a copy is a new site): {}",
                    left.join(", ")
                ));
            }
        } else {
            report.extend(self.apply_carried_commercial(detail, s).await);
        }

        report.extend(s.not_carried.iter().map(|n| format!("not carried: {n}")));
        report
    }

    /// The vhost half of [`Self::apply_carried_settings`]. Validated like a
    /// panel save, then written to the row and rendered — not through
    /// `set_vhost_options` itself, whose redirect-loop probe follows DNS,
    /// which still points at the source during a move.
    pub(super) async fn apply_carried_vhost(
        &self,
        detail: &HostingDetail,
        mut opts: hyperion_types::VhostOptions,
        basic_auth_hash: Option<&str>,
    ) -> Vec<String> {
        use hyperion_types::crs::CrsMode;
        let mut report = Vec::new();
        // "www" needs www.<domain> on the site; a Copy arrives without the
        // source's aliases, and redirecting to a name with no vhost and no
        // certificate takes the copy down.
        if opts.canonical_host == "www" {
            let www = format!("www.{}", detail.domain);
            if !detail.aliases.iter().any(|a| a == &www) {
                opts.canonical_host.clear();
                report.push(format!(
                    "canonical host www: NOT carried — the new site has no alias {www}; add it, \
                     issue the certificate, then turn the redirect on"
                ));
            }
        }
        if opts.crs_settings().mode != CrsMode::Off
            && !self.adapters.modsec_status().await.available()
        {
            opts.crs_mode = CrsMode::Off.as_str().to_string();
            report.push(
                "OWASP Core Rule Set: NOT carried — ModSecurity is not installed on this node; \
                 install it from the Protection card and turn the rule set on again"
                    .into(),
            );
        }
        // The same checks a panel save gets: every value lands in nginx
        // config, and a bundle is input like any other.
        let mut opts = match self.normalize_vhost_options(detail, opts).await {
            Ok(o) => o,
            Err(e) => {
                report.push(format!(
                    "vhost options: NOT carried — refused ({e}); the site runs with default \
                     options, set them again in the vhost card"
                ));
                return report;
            }
        };
        let hash = basic_auth_hash.filter(|h| !h.is_empty());
        if opts.basic_auth_enabled {
            match hash {
                Some(h) => {
                    if let Err(e) = self
                        .adapters
                        .nginx_write_htpasswd(detail.id.as_str(), &opts.basic_auth_user, h)
                        .await
                    {
                        opts.basic_auth_enabled = false;
                        report.push(format!(
                            "basic auth: NOT carried ({e}) — the site is NOT password-protected; \
                             set a password in the vhost card"
                        ));
                    }
                }
                None => {
                    opts.basic_auth_enabled = false;
                    report.push(
                        "basic auth: NOT carried (no password on record) — the site is NOT \
                         password-protected; set a password in the vhost card"
                            .into(),
                    );
                }
            }
        }
        opts.basic_auth_set = opts.basic_auth_enabled;
        let stored_hash = if opts.basic_auth_enabled {
            hash
        } else {
            Some("")
        };
        if let Err(e) = hyperion_state::hostings::set_vhost_options(
            &self.pool,
            &detail.id,
            &opts,
            stored_hash,
            now_secs(),
        )
        .await
        {
            report.push(format!("vhost options: NOT carried ({e})"));
            return report;
        }
        if opts.crs_settings().mode != CrsMode::Off {
            if let Err(e) = self.crs_sync().await {
                report.push(format!(
                    "OWASP Core Rule Set: could not load the rule set ({e})"
                ));
            }
        }
        let mut rendered = detail.clone();
        rendered.vhost_options = opts.clone();
        match self.write_vhost_for_state(&rendered).await {
            Ok(()) => report.push(format!(
                "vhost options: carried (WAF {}, HTTPS redirect {}{}{})",
                opts.effective_waf_level().as_str(),
                if opts.force_https { "on" } else { "off" },
                if opts.noindex { ", noindex" } else { "" },
                if opts.basic_auth_enabled {
                    ", basic auth"
                } else {
                    ""
                },
            )),
            Err(e) => {
                // nginx refused it: serve the plain vhost the import made
                // rather than a half-applied one, and say so.
                let _ = hyperion_state::hostings::set_vhost_options(
                    &self.pool,
                    &detail.id,
                    &detail.vhost_options,
                    Some(""),
                    now_secs(),
                )
                .await;
                let _ = self.write_vhost_for_state(detail).await;
                let _ = self
                    .adapters
                    .nginx_delete_htpasswd(detail.id.as_str())
                    .await;
                report.push(format!(
                    "vhost options: NOT carried — nginx refused them ({e}); the site runs \
                     with default options, set them again in the vhost card"
                ));
            }
        }
        report
    }

    /// The Move-only half of [`Self::apply_carried_settings`]: what the
    /// customer pays for and is promised. A Copy never gets here.
    pub(super) async fn apply_carried_commercial(
        &self,
        detail: &HostingDetail,
        s: &hyperion_types::migration::HostingCarriedSettings,
    ) -> Vec<String> {
        let mut report = Vec::new();
        let sel = || HostingSelector::Id(detail.id.clone());
        let fail = |what: &str, e: &dyn std::fmt::Display| format!("{what}: NOT carried ({e})");

        if let Some(e) = s.expiry.clone() {
            if e.expires_at.is_some() || e.owner_email.is_some() || e.customer_since.is_some() {
                report.push(match self.set_expiry(sel(), e).await {
                    Ok(_) => "renewal date and owner address: carried".into(),
                    Err(err) => fail("renewal date", &err),
                });
            }
        }

        if let Some(m) = s.monitor.clone() {
            if m.enabled || m.alert_email.is_some() || m.alert_webhook_url.is_some() {
                report.push(
                    match self
                        .monitor_set(
                            sel(),
                            m.enabled,
                            Some(m.url_path),
                            Some(m.interval_secs),
                            Some(m.alert_after_fails),
                            m.alert_email,
                            m.alert_slack_webhook,
                            false,
                            m.alert_webhook_url,
                        )
                        .await
                    {
                        Ok(()) => format!(
                            "uptime monitor: carried ({})",
                            if m.enabled { "on" } else { "off" }
                        ),
                        Err(e) => fail("uptime monitor", &e),
                    },
                );
            }
        }

        if let Some(b) = s.billing.as_ref() {
            let applied_at = if b.applied_at > 0 {
                b.applied_at
            } else {
                now_secs()
            };
            // The link is a foreign key into this node's profiles table. A
            // profile this node does not know cannot be linked; the price,
            // the clock and the alert snapshots — what billing actually
            // reads — travel regardless.
            let profile_id = match b.profile_id {
                Some(pid) if matches!(profiles::get(&self.pool, pid).await, Ok(Some(_))) => {
                    Some(pid)
                }
                Some(pid) => {
                    report.push(format!(
                        "profile link: NOT kept — profile #{pid} is not defined on this node;                          the price and billing clock were carried, re-apply the profile to                          link it again"
                    ));
                    None
                }
                None => None,
            };
            let mut res = profiles::upsert_apply(
                &self.pool,
                &detail.id,
                profile_id,
                b.price_minor,
                b.price_currency.as_deref(),
                b.price_interval.as_deref(),
                b.next_billing_at,
                b.slack_webhook.as_deref(),
                b.alert_emails.as_deref(),
                applied_at,
            )
            .await;
            if res.is_ok() && b.price_pinned {
                res = profiles::set_price(
                    &self.pool,
                    &detail.id,
                    b.price_minor,
                    b.price_currency.as_deref(),
                    b.price_interval.as_deref(),
                    b.next_billing_at,
                    true,
                    applied_at,
                )
                .await;
            }
            report.push(match res {
                Ok(()) => format!(
                    "profile and price: carried{} (billing clock unchanged)",
                    if b.price_pinned {
                        ", price kept across profile re-apply"
                    } else {
                        ""
                    }
                ),
                Err(e) => fail("profile and price", &e),
            });
        }

        for p in &s.care_plans {
            let Some(package_id) = p.package_id else {
                report.push(format!(
                    "care plan {}: NOT carried — its definition was deleted, so it cannot be \
                     re-activated; it stays in the source's history",
                    p.package_name
                ));
                continue;
            };
            let a = hyperion_state::packages::NewActivation {
                hosting_id: detail.id.clone(),
                package_id,
                package_name: p.package_name.clone(),
                price_minor: p.price_minor,
                price_currency: p.price_currency.clone(),
                price_interval: p.price_interval.clone(),
                features: p.features,
                next_billing_at: p.next_billing_at,
                prior_state_json: p.prior_state_json.clone(),
                letters_lang: p.letters_lang.clone(),
                check_items: p.check_items.clone(),
                report_omit: p.report_omit.clone(),
                valid_from: p.valid_from,
                enforcement_started: p.enforcement_started,
            };
            let at = if p.activated_at > 0 {
                p.activated_at
            } else {
                now_secs()
            };
            report.push(
                match hyperion_state::packages::activate(&self.pool, &a, at).await {
                    Ok(_) => format!("care plan {}: carried", p.package_name),
                    Err(e) => fail(&format!("care plan {}", p.package_name), &e),
                },
            );
        }
        report
    }

    /// Import a migration bundle on the target node. Reads the
    /// manifest at `manifest_path`, refuses unknown future schema
    /// versions and SHA-256 mismatches on the sibling archive, creates
    /// a fresh hosting with the same config, and restores the archive.
    pub async fn hosting_import(
        &self,
        manifest_path: String,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        let manifest_bytes =
            tokio::fs::read(&manifest_path)
                .await
                .map_err(|e| RpcError::Validation {
                    message: format!("manifest read failed: {e}"),
                })?;
        let manifest: hyperion_types::HostingMigrationManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| RpcError::Validation {
                message: format!("manifest parse failed: {e}"),
            })?;
        if manifest.schema_version
            > hyperion_types::HostingMigrationManifest::CURRENT_SCHEMA_VERSION
        {
            return Err(RpcError::Validation {
                message: format!(
                    "manifest schema_version {} > supported {} — upgrade hyperion-agent first",
                    manifest.schema_version,
                    hyperion_types::HostingMigrationManifest::CURRENT_SCHEMA_VERSION,
                ),
            });
        }

        // Locate the archive next to the manifest, regardless of how
        // the operator named the manifest file. Convention is
        // `archive.tar.gz` alongside `manifest.json`.
        let manifest_pb = std::path::PathBuf::from(&manifest_path);
        let archive_path = manifest_pb
            .parent()
            .map(|p| p.join("archive.tar.gz"))
            .ok_or_else(|| RpcError::Validation {
                message: "manifest_path must have a parent dir".into(),
            })?;
        if !archive_path.exists() {
            return Err(RpcError::Validation {
                message: format!("archive missing at {}", archive_path.display()),
            });
        }
        // SHA verify — refuse a tampered or truncated archive.
        let live_sha = compute_sha256(&archive_path).await?;
        if live_sha != manifest.archive_sha256 {
            return Err(RpcError::Validation {
                message: format!(
                    "archive sha mismatch — manifest={} archive={}",
                    manifest.archive_sha256, live_sha
                ),
            });
        }
        let archive_bytes = tokio::fs::metadata(&archive_path)
            .await
            .map(|m| m.len() as i64)
            .unwrap_or(0);

        // The database dump, checked BEFORE anything is created. A site with
        // a database whose bundle carries no dump would arrive with the empty
        // database `create` makes and be reported as imported — exactly what
        // every Move/Copy did before the export shipped the dump.
        let dump_path =
            archive_path.with_file_name(hyperion_types::HostingMigrationManifest::DB_DUMP_FILE);
        if manifest.db_engine.is_some() {
            let Some(want) = manifest.db_dump_sha256.as_deref() else {
                return Err(RpcError::Validation {
                    message: "this bundle carries no database dump, so importing it would \
                              leave the site with an empty database — it was exported by an \
                              older Hyperion; update the source node and export again"
                        .into(),
                });
            };
            if !dump_path.exists() {
                return Err(RpcError::Validation {
                    message: format!("database dump missing at {}", dump_path.display()),
                });
            }
            let live = compute_sha256(&dump_path).await?;
            if live != want {
                return Err(RpcError::Validation {
                    message: format!("database dump sha mismatch — manifest={want} dump={live}"),
                });
            }
        }

        // Provision the hosting with the same config. We re-issue the
        // cert (never copy private keys across the network) and let
        // the operator click "Issue Cert" once DNS resolves on the
        // target — same flow as a brand-new hosting.
        let domain = hyperion_validate::Domain::parse(&manifest.domain).map_err(|e| {
            RpcError::Validation {
                message: format!("domain parse: {e}"),
            }
        })?;
        let aliases: Vec<hyperion_validate::Domain> = manifest
            .aliases
            .iter()
            .filter_map(|a| hyperion_validate::Domain::parse(a).ok())
            .collect();
        // An account of its own, never whichever one the name folds onto.
        let system_user = self
            .free_system_user(domain.clone().without_www().as_str())
            .await?;
        let create = HostingCreateReq {
            domain,
            aliases,
            php_version: manifest.php_version,
            database: manifest.db_engine.as_deref().and_then(|s| match s {
                "mariadb" => Some(hyperion_types::DbProvision::MariaDB),
                "postgres" => Some(hyperion_types::DbProvision::Postgres),
                _ => None,
            }),
            system_user: Some(system_user),
            kind: manifest.kind.clone(),
            // Carry the reverse-proxy upstream from the manifest —
            // previously the importer silently dropped it, leaving
            // every migrated reverse-proxy hosting pointing at no
            // upstream. The validate_proxy_upstream_url check on
            // create() still runs.
            proxy_upstream_url: manifest.proxy_upstream_url.clone(),
        };
        let created = self.create(create).await?;

        // Restore the archive. backup_restore() looks for an archive
        // at the given path + a sibling .sql for the dump.
        //
        // If restore fails, we have a half-state hosting on the
        // target: the create() succeeded but the data import didn't.
        // Roll back by deleting the hosting (cleans up dirs, db,
        // system_user, etc.) so the operator can retry without
        // hitting "AlreadyExists" on the second attempt.
        let restore_path = archive_path.display().to_string();
        if let Err(restore_err) = self
            .backup_restore(
                HostingSelector::Id(created.id.clone()),
                restore_path,
                hyperion_types::BackupRestoreMode::FilesAndDb,
            )
            .await
        {
            tracing::warn!(
                hosting = %created.id.as_str(),
                error = %restore_err,
                "migration import: restore failed — rolling back half-created hosting"
            );
            self.roll_back_created(&created.id).await;
            return Err(restore_err);
        }
        let new_domain = self
            .get(HostingSelector::Id(created.id.clone()))
            .await
            .map(|d| d.domain)
            .unwrap_or_else(|_| manifest.domain.clone());

        // WordPress: the restored wp-config.php still names the SOURCE's
        // database, user and password (and its Redis ACL user). On another
        // node that is "Error establishing a database connection"; on the
        // same node a Copy would run against — and panel actions like a WP
        // reset would drop — the production tables. Point it at the database
        // `create` just made, before any wp-cli runs.
        if let Some(db) = created.db.as_ref() {
            match crate::panel_import::repoint_wp_config_db(
                &created.root_dir,
                &db.db_name,
                &db.db_user,
                &db.password,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        hosting = %created.id.as_str(), error = %e,
                        "migration import: could not repoint wp-config.php — rolling back"
                    );
                    self.roll_back_created(&created.id).await;
                    return Err(RpcError::ProvisioningFailed {
                        stage: "wp_config".into(),
                        reason: format!("could not point wp-config.php at the new database: {e}"),
                    });
                }
            }
        }
        // The source's Redis settings belong to the source: its ACL user does
        // not exist here (or, on a same-node Copy, is production's cache).
        // Park the drop-in FIRST — a drop-in that cannot connect fatals every
        // request, wp-cli included — then drop the WP_REDIS_* constants. The
        // operator turns Redis on for the new site from its panel.
        if hyperion_adapters::wpcli::set_object_cache_dropin(
            &created.system_user,
            &created.root_dir,
            false,
        )
        .await
        .unwrap_or(false)
        {
            let _ = self
                .adapters
                .wp_set_redis(&created.system_user, &created.root_dir, None)
                .await;
        }
        // A Copy lands under a new name: rewrite the WordPress URLs so the
        // copy does not redirect to (and link) the source.
        if let Some(from) = manifest.renamed_from.as_deref() {
            if from != new_domain {
                self.wp_rewrite_domain(&created.system_user, &created.root_dir, from, &new_domain)
                    .await;
            }
        }

        // Re-apply the crontab when present, pointed at the new tree: its
        // lines name absolute paths under the source's account.
        let mut carry_report = Vec::new();
        if !manifest.crontab.trim().is_empty() {
            let new_tree = std::path::Path::new(&created.root_dir)
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let (body, notes) = if manifest.source_tree.is_empty() {
                (manifest.crontab.clone(), Vec::new())
            } else {
                rewrite_crontab_paths(
                    &manifest.crontab,
                    &manifest.source_tree,
                    &new_tree,
                    &manifest.source_home,
                    &self.home_dir_for(created.system_user.as_str()),
                )
            };
            carry_report.push(
                match self
                    .cron_replace(HostingSelector::Id(created.id.clone()), body)
                    .await
                {
                    Ok(()) => format!(
                        "cron: carried ({} line(s))",
                        manifest.crontab.lines().count()
                    ),
                    Err(e) => format!("cron: NOT carried ({e})"),
                },
            );
            carry_report.extend(notes);
        }
        match self.get(HostingSelector::Id(created.id.clone())).await {
            Ok(detail) => carry_report.extend(
                self.apply_carried_settings(
                    &detail,
                    manifest.settings.as_ref(),
                    manifest.renamed_from.is_some(),
                )
                .await,
            ),
            Err(e) => carry_report.push(format!("settings NOT carried: {e}")),
        }

        self.append_audit(
            "hosting.migration.import",
            Some(created.id.as_str()),
            &serde_json::json!({
                "source_hosting_id": manifest.source_hosting_id.as_str(),
                "source_node_id": manifest.source_node_id,
                "archive_bytes": archive_bytes,
                "schema_version": manifest.schema_version,
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok(hyperion_types::HostingImportResult {
            new_hosting_id: created.id,
            // What `create` actually made (it folds `www.` into the alias),
            // not what the manifest asked for.
            domain: new_domain,
            restored_bytes: archive_bytes,
            state: "ok".into(),
            message: format!(
                "imported from {} on node {}",
                manifest.source_hosting_id.as_str(),
                manifest.source_node_id
            ),
            carry_report,
        })
    }

    /// One-shot backfill called at agent startup: every hostings row
    /// with NULL node_id (i.e. created before migration 016) gets
    /// tagged with the current node's id. Idempotent — running it
    /// twice is a no-op. Returns the row count touched so the boot
    /// log can surface non-zero backfills as a one-liner.
    pub async fn backfill_local_node_id(&self) -> Result<u64, RpcError> {
        let nid = self.current_node_id();
        hostings::backfill_node_id(&self.pool, &nid)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backfill node_id: {e}")))
    }

    /// Import a migration bundle by URL. The source node's
    /// hyperion-web serves a signed `?t=…` URL pair (manifest.json
    /// + archive.tar.gz). The target agent downloads both into a
    /// staging dir, then delegates to `hosting_import`.
    ///
    /// Why curl: same reason as `update_check` — every node has
    /// curl already (the installer uses it) and pulling reqwest in
    /// just for this would double-link a TLS stack.
    pub async fn hosting_import_from_url(
        &self,
        base_url: String,
        token: String,
        override_domain: Option<String>,
        override_aliases: Vec<String>,
        master_minted: bool,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        // Validate the URL shape before shelling out — we'd rather
        // refuse `file://` or random garbage at the boundary than
        // hand it to curl.
        if !base_url.starts_with("https://") && !base_url.starts_with("http://") {
            return Err(RpcError::Validation {
                message: "import URL must be http(s)://".into(),
            });
        }
        let base = base_url.trim_end_matches('/').to_string();
        // Quote-stripped, but otherwise opaque to us — the source's
        // signature is what controls access.
        let token_q = token.trim().to_string();
        if token_q.is_empty() {
            return Err(RpcError::Validation {
                message: "import URL missing ?t=<token>".into(),
            });
        }

        // SSRF guard (sec-findings #4): resolve the base host ONCE and refuse
        // internal/loopback/link-local targets (e.g. 169.254.169.254 metadata,
        // 127.0.0.1 admin APIs) before any curl runs. Both the manifest and the
        // archive live under `base`, so the same pins cover both fetches and
        // also defeat DNS rebinding between the two requests.
        //
        // `master_minted` admits loopback and PRIVATE-network addresses only:
        // the master's own copy/move job built this URL to its own bundle
        // endpoint, and the master's FQDN resolves to 127.0.1.1 via Debian's
        // /etc/hosts when the copy lands on the master itself, and to 10.x on
        // a private-network cluster. Link-local (169.254.169.254 metadata),
        // unspecified and the rest stay refused even then — the URL's host
        // comes from the browser's Host header. A URL a person typed (import
        // form, hctl) always goes through the full guard.
        let policy = if master_minted {
            InternalAddrs::AllowOwnNetwork
        } else {
            InternalAddrs::Refuse
        };
        let resolve_pins = resolve_url_pins(&base, policy).await.map_err(|e| {
            tracing::warn!(error = %e, "import-from-url SSRF guard rejected base URL");
            // A typed URL gets the bare refusal: echoing what its host
            // resolved to would turn the form into a probe of the node's
            // view of the network. A URL the master minted to itself is no
            // such probe, and the bare message left nothing to go on when
            // one was refused — the reason is all there is to debug.
            let message = if master_minted {
                format!("import URL points at a disallowed (internal) address: {e}")
            } else {
                "import URL points at a disallowed (internal) address".into()
            };
            RpcError::Validation { message }
        })?;

        let staging = make_incoming_staging().await?;
        // Everything from here runs inside one block so EVERY exit — a
        // timed-out or refused download included — wipes staging. The early
        // `?` returns used to skip the cleanup and leave partial archives of
        // plaintext site data in migration-incoming for good.
        let outcome = self
            .import_from_url_staged(
                &staging,
                &base,
                &token_q,
                &resolve_pins,
                override_domain.as_deref(),
                &override_aliases,
                master_minted,
            )
            .await;
        let _ = tokio::fs::remove_dir_all(&staging).await;

        let result = outcome?;
        self.append_audit(
            "hosting.migration.import_url",
            Some(result.new_hosting_id.as_str()),
            &serde_json::json!({
                "source_url": &base,
                "bytes": result.restored_bytes,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(result)
    }

    /// Import a bundle that already sits in this node's own migration dir —
    /// the master's Copy and Move when the target is the master itself.
    ///
    /// Those used to go through [`Self::hosting_import_from_url`] with the
    /// master's public name, so a copy onto the master depended on what that
    /// name resolves to ON the master: 127.0.1.1 from Debian's /etc/hosts, a
    /// private address, a split-horizon answer, or nothing at all inside the
    /// agent — and any of those failed the job at the import step with
    /// "disallowed (internal) address". The files are right here; nothing
    /// needs to travel.
    ///
    /// The bundle itself stays untouched (a retry, or the source's own
    /// cleanup, still finds it whole): its files are hard-linked — copied if
    /// that fails — into a fresh staging dir, the clone overrides rewrite the
    /// STAGED manifest, and [`Self::hosting_import`] runs there exactly as it
    /// does after a download, sha checks included.
    pub async fn hosting_import_local_bundle(
        &self,
        bundle_id: String,
        override_domain: Option<String>,
        override_aliases: Vec<String>,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        if !bundle_id_ok(&bundle_id) {
            return Err(RpcError::Validation {
                message: format!("bundle_id has illegal chars: {bundle_id:?}"),
            });
        }
        let source = std::path::PathBuf::from("/var/lib/hyperion/migration").join(&bundle_id);
        if !source.join("manifest.json").is_file() {
            return Err(RpcError::NotFound {
                kind: "migration_bundle".into(),
                id: bundle_id,
            });
        }
        let staging = make_incoming_staging().await?;
        let outcome = self
            .import_local_bundle_staged(
                &staging,
                &source,
                override_domain.as_deref(),
                &override_aliases,
            )
            .await;
        let _ = tokio::fs::remove_dir_all(&staging).await;

        let result = outcome?;
        self.append_audit(
            "hosting.migration.import_local",
            Some(result.new_hosting_id.as_str()),
            &serde_json::json!({
                "bundle_id": &bundle_id,
                "bytes": result.restored_bytes,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(result)
    }

    /// The staging half of [`Self::hosting_import_local_bundle`], writing
    /// only under `staging` (which the caller always removes).
    pub(super) async fn import_local_bundle_staged(
        &self,
        staging: &std::path::Path,
        source: &std::path::Path,
        override_domain: Option<&str>,
        override_aliases: &[String],
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        let manifest_path = staging.join("manifest.json");
        tokio::fs::copy(source.join("manifest.json"), &manifest_path)
            .await
            .map_err(|e| RpcError::Internal_with(format!("stage manifest: {e}")))?;
        if let Some(new_dom) = override_domain {
            rewrite_manifest_domain(&manifest_path, new_dom, override_aliases).await?;
        }
        // A file the bundle lacks is left out: `hosting_import` names exactly
        // what is missing (the archive always; the dump only when the
        // manifest says the site has a database).
        for name in [
            "archive.tar.gz",
            hyperion_types::HostingMigrationManifest::DB_DUMP_FILE,
        ] {
            let from = source.join(name);
            if !from.is_file() {
                continue;
            }
            let to = staging.join(name);
            if tokio::fs::hard_link(&from, &to).await.is_err() {
                tokio::fs::copy(&from, &to)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("stage {name}: {e}")))?;
            }
        }
        self.hosting_import(manifest_path.display().to_string())
            .await
    }

    /// The download + import half of [`Self::hosting_import_from_url`],
    /// writing only under `staging` (which the caller always removes).
    pub(super) async fn import_from_url_staged(
        &self,
        staging: &std::path::Path,
        base: &str,
        token_q: &str,
        resolve_pins: &[String],
        override_domain: Option<&str>,
        override_aliases: &[String],
        master_minted: bool,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        let manifest_path = staging.join("manifest.json");
        let archive_path = staging.join("archive.tar.gz");
        let dump_file = hyperion_types::HostingMigrationManifest::DB_DUMP_FILE;

        // Per-node cap on each big download (default 64 GB). The archive can
        // legitimately be tens of GB; the cap only stops a runaway upstream
        // from filling /var/lib.
        let max_archive_bytes =
            read_migration_max_download_bytes(self.agent_config_path.as_deref());

        // Download manifest first — small file, fail fast on bad
        // signature / wrong URL before we burn time on the archive. The manifest
        // is JSON (KBs); cap it tight so a bogus URL can't stream GBs here.
        curl_to_file(
            &format!("{base}/manifest.json?t={token_q}"),
            &manifest_path,
            resolve_pins,
            64 * 1024 * 1024,
            false,
        )
        .await?;

        // CLONE OVERRIDES: when the caller passed `override_domain`
        // (the typical `hosting clone` flow), rewrite the manifest
        // on disk BEFORE the downstream importer reads it. The
        // archive itself is unchanged — the importer creates a new
        // hosting under the new domain and untars the same files +
        // DB dump into it. The archive_sha256 in the manifest is
        // preserved (it's the archive's checksum, not the
        // manifest's), so the integrity check still passes.
        if let Some(new_dom) = override_domain {
            rewrite_manifest_domain(&manifest_path, new_dom, override_aliases).await?;
        }
        // A bundle from a URL someone pasted comes from another
        // installation: its raw nginx snippet would be root-level config
        // written on this node on that installation's say-so. Only the
        // master's own Move/Copy (a site this cluster already ran) keeps it.
        if !master_minted {
            strip_raw_nginx_snippet(&manifest_path).await?;
        }
        let has_dump = tokio::fs::read(&manifest_path)
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .is_some_and(|v| v.get("db_dump_sha256").is_some_and(|d| d.is_string()));

        // Then the archive — can be many GB. curl streams to disk
        // directly so RSS stays flat.
        curl_to_file(
            &format!("{base}/archive.tar.gz?t={token_q}"),
            &archive_path,
            resolve_pins,
            max_archive_bytes,
            true,
        )
        .await?;
        // And the database dump beside it, under the name `hosting_import`
        // (via backup_restore) looks for.
        if has_dump {
            curl_to_file(
                &format!("{base}/{dump_file}?t={token_q}"),
                &staging.join(dump_file),
                resolve_pins,
                max_archive_bytes,
                true,
            )
            .await?;
        }

        // Delegate to the existing path-based importer. It re-reads
        // the SHA from disk and refuses on mismatch — that doubles
        // as our integrity check after the HTTP transfer.
        self.hosting_import(manifest_path.display().to_string())
            .await
    }

    /// Self-service import wizard token ops. One entry point (the op enum keeps
    /// the RPC surface to a single method). Tokens are stored hashed; the
    /// plaintext is returned ONCE on Mint. See hyperion_state::import_tokens.
    pub async fn import_token(
        &self,
        op: hyperion_types::ImportTokenOp,
    ) -> Result<hyperion_types::ImportTokenResult, RpcError> {
        use hyperion_state::import_tokens as toks;
        use hyperion_types::{ImportTokenInfo, ImportTokenOp, ImportTokenResult};

        fn to_info(r: toks::ImportTokenRow) -> ImportTokenInfo {
            // Computed here, not in the UI: the evidence rule for "is there
            // enough data to state a rate" must have exactly one implementation,
            // and 0 means "render no rate", never "stalled".
            let rate_bytes_per_sec = toks::rate_bytes_per_sec(&r).unwrap_or(0);
            ImportTokenInfo {
                id: r.id,
                target_node: r.target_node,
                source_kind: r.source_kind,
                status: r.status,
                received_bytes: r.received_bytes,
                job_id: r.job_id,
                expires_at: r.expires_at,
                created_by: r.created_by,
                created_at: r.created_at,
                manifest_json: r.manifest_json.unwrap_or_default(),
                selection_json: r.selection_json.unwrap_or_default(),
                expected_bytes: r.expected_bytes,
                bundle_sha256: r.bundle_sha256.unwrap_or_default(),
                received_at: r.received_at,
                rate_bytes_per_sec,
                source_progress_json: r.source_progress_json.unwrap_or_default(),
                source_progress_at: r.source_progress_at,
            }
        }
        let map = |what: &'static str| {
            move |e: hyperion_state::db::StateError| {
                RpcError::Internal_with(format!("import token {what}: {e}"))
            }
        };

        match op {
            ImportTokenOp::Mint {
                target_node,
                source_kind,
                created_by,
                ttl_secs,
            } => {
                use rand::RngCore;
                let mut buf = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut buf);
                let token = hex::encode(buf);
                let hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());
                let now = now_secs();
                let expires_at = now + ttl_secs.clamp(60, 86_400);
                let id = toks::create(
                    &self.pool,
                    &hash,
                    &target_node,
                    &source_kind,
                    &created_by,
                    now,
                    expires_at,
                )
                .await
                .map_err(map("mint"))?;
                Ok(ImportTokenResult::Minted {
                    token,
                    id,
                    expires_at,
                })
            }
            ImportTokenOp::Resolve { token, consume } => {
                let hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());
                let now = now_secs();
                let row = if consume {
                    toks::consume_for_ingest(&self.pool, &hash, now)
                        .await
                        .map_err(map("consume"))?
                } else {
                    toks::get_fetchable(&self.pool, &hash, now)
                        .await
                        .map_err(map("resolve"))?
                };
                Ok(ImportTokenResult::Resolved(row.map(to_info)))
            }
            ImportTokenOp::Update {
                id,
                status,
                job_id,
                received_bytes,
            } => {
                if let Some(s) = status {
                    toks::set_status(&self.pool, id, &s)
                        .await
                        .map_err(map("status"))?;
                }
                if let Some(j) = job_id {
                    toks::set_job(&self.pool, id, &j)
                        .await
                        .map_err(map("job"))?;
                }
                if let Some(b) = received_bytes {
                    toks::set_received_bytes(&self.pool, id, b)
                        .await
                        .map_err(map("bytes"))?;
                }
                Ok(ImportTokenResult::Ack)
            }
            ImportTokenOp::ClaimUpload {
                token,
                expected_bytes,
                bundle_sha256,
            } => {
                let hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());
                let row = toks::claim_upload(
                    &self.pool,
                    &hash,
                    expected_bytes,
                    &bundle_sha256,
                    now_secs(),
                )
                .await
                .map_err(map("claim_upload"))?;
                Ok(ImportTokenResult::Resolved(row.map(to_info)))
            }
            ImportTokenOp::RecordUpload { id, received_bytes } => {
                toks::record_upload(&self.pool, id, received_bytes, now_secs())
                    .await
                    .map_err(map("record_upload"))?;
                Ok(ImportTokenResult::Ack)
            }
            ImportTokenOp::SetSourceProgress {
                token,
                progress_json,
            } => {
                let hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());
                toks::set_source_progress(&self.pool, &hash, &progress_json, now_secs())
                    .await
                    .map_err(map("set_source_progress"))?;
                Ok(ImportTokenResult::Ack)
            }
            ImportTokenOp::List => {
                let rows = toks::list_active(&self.pool, now_secs())
                    .await
                    .map_err(map("list"))?;
                Ok(ImportTokenResult::Listed(
                    rows.into_iter().map(to_info).collect(),
                ))
            }
            ImportTokenOp::SetManifest {
                token,
                manifest_json,
            } => {
                let hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());
                toks::set_manifest(&self.pool, &hash, &manifest_json, now_secs())
                    .await
                    .map_err(map("set_manifest"))?;
                Ok(ImportTokenResult::Ack)
            }
            ImportTokenOp::SetSelection { id, selection_json } => {
                toks::set_selection(&self.pool, id, &selection_json)
                    .await
                    .map_err(map("set_selection"))?;
                Ok(ImportTokenResult::Ack)
            }
            ImportTokenOp::Cancel { id } => {
                toks::cancel(&self.pool, id).await.map_err(map("cancel"))?;
                Ok(ImportTokenResult::Ack)
            }
        }
    }
}

/// Remove stale migration artifacts under `root` whose mtime is older than
/// `max_age`. Returns the count removed. Extracted as a free function so it has
/// a fs-only signature that's easy to unit-test with `tempfile::tempdir`. Caller
/// (`prune_old_migration_bundles`) passes the real `/var/lib/hyperion/migration`
/// root.
///
/// Sweeps three artifact families WE create (and nothing else an operator may
/// have stashed there):
///   * `mig_*`     sub-dirs   — export bundles (migration.rs)
///   * `bundle-*`  sub-dirs   — panel-import archive staging (panel_import.rs)
///   * `bundle-*.tar` files   — self-service ingested bundles (import_wizard.rs)
///
/// SECURITY (sec-findings #6): the flat `bundle-<id>.tar` files contain
/// plaintext DB dumps + wp-config secrets; before this they were never swept and
/// lingered forever. They're normally deleted at job end, but this is the
/// belt-and-braces backstop for crashed/orphaned imports.
pub(super) async fn prune_migration_bundle_dir(
    root: &std::path::Path,
    max_age: std::time::Duration,
) -> Result<u32, RpcError> {
    let mut dir = match tokio::fs::read_dir(root).await {
        Ok(d) => d,
        // Root doesn't exist yet (no exports ever run) — nothing to
        // do, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(RpcError::Internal_with(format!("read migration root: {e}")));
        }
    };
    let cutoff = std::time::SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut removed: u32 = 0;
    while let Ok(Some(entry)) = dir.next_entry().await {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        if mtime >= cutoff {
            continue;
        }
        // Stale `mig_*` / `bundle-*` sub-dirs.
        if meta.is_dir()
            && (name.starts_with("mig_") || name.starts_with("bundle-") || name.starts_with("inc_"))
        {
            match tokio::fs::remove_dir_all(&path).await {
                Ok(()) => {
                    tracing::info!(bundle=%name, "pruned stale migration bundle dir");
                    removed = removed.saturating_add(1);
                }
                Err(e) => {
                    tracing::warn!(bundle=%name, error=%e, "could not prune bundle dir");
                }
            }
        // Stale flat `bundle-*.tar` files (self-service ingested bundles).
        } else if meta.is_file() && name.starts_with("bundle-") && name.ends_with(".tar") {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    tracing::info!(bundle=%name, "pruned stale migration bundle file");
                    removed = removed.saturating_add(1);
                }
                Err(e) => {
                    tracing::warn!(bundle=%name, error=%e, "could not prune bundle file");
                }
            }
        }
    }
    Ok(removed)
}

/// Default hard cap on imported migration archives. The cap only exists so a
/// malicious or accidentally-huge upstream can't fill the /var/lib partition;
/// it is NOT a statement about a "normal" site. Real ones with a big uploads or
/// media library legitimately reach tens of GB, so the default is generous and
/// the operator can raise it per node via `[migration] max_download_gb`.
pub(super) const MIGRATION_MAX_DOWNLOAD_BYTES_DEFAULT: u64 = 64 * 1024 * 1024 * 1024;

/// Per-node override for the migration download cap, from
/// `[migration] max_download_gb`. Clamped to 1..=1024 GB so a typo (0, or a
/// petabyte) can't disable the disk-fill guard or overflow. Absent / unreadable
/// / out of range ⇒ the 64 GB default.
pub(super) fn read_migration_max_download_bytes(cfg_path: Option<&std::path::Path>) -> u64 {
    let parsed = (|| {
        let raw = std::fs::read_to_string(cfg_path?).ok()?;
        let doc = raw.parse::<toml_edit::DocumentMut>().ok()?;
        let gb = doc
            .get("migration")?
            .as_table_like()?
            .get("max_download_gb")?
            .as_integer()?;
        u64::try_from(gb).ok()
    })();
    match parsed {
        Some(gb) if (1..=1024).contains(&gb) => gb * 1024 * 1024 * 1024,
        _ => MIGRATION_MAX_DOWNLOAD_BYTES_DEFAULT,
    }
}

/// Rewrite a freshly-downloaded migration manifest in place to
/// substitute `new_domain` (and optionally `new_aliases`) for the
/// ones captured at export time. Powers the `hosting clone` flow:
/// the archive stays bit-for-bit identical (its sha256 still
/// matches the manifest's archive_sha256) but the importer creates
/// a new hosting under the new domain.
///
/// Validates the new domain via the same parser the wizard uses —
/// a malformed `staging..example.cz` is rejected here, NOT after
/// the importer has half-created a hosting.
pub(super) async fn rewrite_manifest_domain(
    manifest_path: &std::path::Path,
    new_domain: &str,
    new_aliases: &[String],
) -> Result<(), RpcError> {
    // Parse-check first so a typo doesn't burn the archive download.
    let _ok = hyperion_validate::Domain::parse(new_domain).map_err(|e| RpcError::Validation {
        message: format!("clone override_domain invalid: {e}"),
    })?;
    for a in new_aliases {
        let _ = hyperion_validate::Domain::parse(a).map_err(|e| RpcError::Validation {
            message: format!("clone override_aliases entry '{a}' invalid: {e}"),
        })?;
    }
    let raw = tokio::fs::read(manifest_path)
        .await
        .map_err(|e| RpcError::Internal_with(format!("read manifest for rewrite: {e}")))?;
    let mut json: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| RpcError::Validation {
            message: format!("manifest is not valid JSON: {e}"),
        })?;
    if let Some(obj) = json.as_object_mut() {
        // Remember the exported name so the importer can rewrite the
        // WordPress URLs from it. Kept if already set (a re-rewrite).
        if !obj.get("renamed_from").is_some_and(|v| v.is_string()) {
            if let Some(old) = obj.get("domain").cloned() {
                obj.insert("renamed_from".into(), old);
            }
        }
        obj.insert(
            "domain".into(),
            serde_json::Value::String(new_domain.to_string()),
        );
        // ALWAYS replace the aliases, even with an empty list. A clone lands on
        // a NEW domain, so it must NOT carry the source's aliases: alias domains
        // are globally unique, so keeping e.g. `www.<source>` makes the import
        // die on `UNIQUE constraint failed: hosting_aliases.alias_domain`
        // against the still-present source. Empty override ⇒ no aliases (the
        // operator adds `www.<new>` afterward); the previous `if !is_empty()`
        // guard left the source's aliases in place and broke every clone whose
        // source had one.
        obj.insert(
            "aliases".into(),
            serde_json::Value::Array(
                new_aliases
                    .iter()
                    .map(|a| serde_json::Value::String(a.clone()))
                    .collect(),
            ),
        );
    } else {
        return Err(RpcError::Validation {
            message: "manifest must be a JSON object".into(),
        });
    }
    let bytes = serde_json::to_vec_pretty(&json)
        .map_err(|e| RpcError::Internal_with(format!("re-serialize manifest: {e}")))?;
    tokio::fs::write(manifest_path, bytes)
        .await
        .map_err(|e| RpcError::Internal_with(format!("write rewritten manifest: {e}")))?;
    Ok(())
}

/// System-user names an import may use for a site, best first: the name
/// `create` would derive, then `<base>_2` … `<base>_99`, each trimmed so it
/// still fits the 32-character limit.
///
/// The derived name is not unique: `my-shop.cz` and `my.shop.cz` both become
/// `my_shop_cz`, and so does a Copy of a site under a name that folds the same
/// way. `create` reuses an existing account by design (several sites may share
/// one), so an import that let it derive the name could land a copy ON the
/// source's account — same uid, same home, same crontab, each site able to
/// rewrite the other's files.
pub(super) fn import_user_candidates(domain: &str) -> Result<Vec<SystemUserName>, RpcError> {
    let base = SystemUserName::derive_from_domain(domain)?;
    let mut out = vec![base.clone()];
    for n in 2..=99u32 {
        let suffix = format!("_{n}");
        let mut stem = base.as_str().to_string();
        stem.truncate(32 - suffix.len());
        let stem = stem.trim_end_matches('_');
        if let Ok(name) = SystemUserName::parse(&format!("{stem}{suffix}")) {
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    Ok(out)
}

/// Drop the raw nginx snippet from a downloaded manifest's carried vhost
/// options, leaving a note for the import report when there was one. See
/// the caller for why only pasted-URL imports go through this.
pub(super) async fn strip_raw_nginx_snippet(
    manifest_path: &std::path::Path,
) -> Result<(), RpcError> {
    let raw = tokio::fs::read(manifest_path)
        .await
        .map_err(|e| RpcError::Internal_with(format!("read manifest: {e}")))?;
    let mut json: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| RpcError::Validation {
            message: format!("manifest is not valid JSON: {e}"),
        })?;
    if !strip_raw_nginx_snippet_json(&mut json) {
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(&json)
        .map_err(|e| RpcError::Internal_with(format!("re-serialize manifest: {e}")))?;
    tokio::fs::write(manifest_path, bytes)
        .await
        .map_err(|e| RpcError::Internal_with(format!("write manifest: {e}")))
}

/// The JSON half of [`strip_raw_nginx_snippet`]. True when it changed
/// something.
pub(super) fn strip_raw_nginx_snippet_json(json: &mut serde_json::Value) -> bool {
    let Some(settings) = json.get_mut("settings").and_then(|v| v.as_object_mut()) else {
        return false;
    };
    let had = settings
        .get("vhost_options")
        .and_then(|v| v.get("custom_nginx_snippet"))
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty());
    if !had {
        return false;
    }
    if let Some(v) = settings
        .get_mut("vhost_options")
        .and_then(|v| v.as_object_mut())
    {
        v.insert(
            "custom_nginx_snippet".into(),
            serde_json::Value::String(String::new()),
        );
    }
    let note = serde_json::Value::String(
        "Custom nginx snippet: dropped — it came from another installation by URL; review it \
         there and add it again by hand if it is wanted."
            .into(),
    );
    match settings
        .get_mut("not_carried")
        .and_then(|v| v.as_array_mut())
    {
        Some(list) => list.push(note),
        None => {
            settings.insert("not_carried".into(), serde_json::Value::Array(vec![note]));
        }
    }
    true
}

/// Which imports a carried `hosting_kv` key applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CarryScope {
    /// Move and Copy: how the site is run.
    Always,
    /// Move only: what the customer is promised or billed for, and the
    /// bookkeeping of that promise. A Copy is a new site with none of it.
    MoveOnly,
}

/// The allow-list of `hosting_kv` keys a migration bundle carries. `None` =
/// never: run state (last-run stamps, log positions, scan results, warning
/// de-dup markers) is the source node's own bookkeeping, and secrets (DKIM
/// record, git deploy key and webhook secret) are made fresh on the target.
/// An allow-list rather than a deny-list so a key added later stays home
/// until someone decides it should travel.
pub(super) fn carried_kv_scope(key: &str) -> Option<CarryScope> {
    use hyperion_types::phpmem;
    const ALWAYS: &[&str] = &[
        BACKUP_KV_CADENCE,
        BACKUP_KV_INTERVAL_DAYS,
        BACKUP_KV_AT,
        BACKUP_KV_KEEP_DAYS,
        BACKUP_KV_KEEP_LAST,
        BACKUP_KV_TARGET,
        phpmem::KV_ENABLED,
        phpmem::KV_MAX_MB,
        // The floor and raise history: limits travel with the raised value,
        // and without the floor the automation would adopt it as the
        // operator's own and never come back down.
        phpmem::KV_STATE,
        INTEGRITY_ENABLED_KV_KEY,
        PERM_AUTOHEAL_KV_KEY,
        WP_MAIL_AUTOFIX_KV_KEY,
        WP_MAIL_OVERRIDE_KV_KEY,
        WP_MAIL_FROM_KV_KEY,
        // Matches the mail module restored with the files.
        WP_MAIL_FORCE_LOCAL_KV_KEY,
        FAIL2BAN_HTTP_KV_KEY,
        WAF_AUTOBAN_KV_KEY,
        "regguard_enabled",
        "wp_auto_update",
        "wp_update_skips",
        // = HostingService::LETTER_LANG_KV_KEY (checked in a test).
        "letters.lang",
        // Git deploy settings. NOT the key, token or webhook secret (fresh
        // on the target), and NOT the webhook switch: on without a secret
        // would be a deploy trigger anyone can pull.
        "gitsync_repo",
        "gitsync_branch",
        "gitsync_subdir",
        "gitsync_auth",
    ];
    const MOVE_ONLY: &[&str] = &[
        CARE_CHECKS_KV_KEY,
        CARE_REPORT_RECIPIENTS_KV_KEY,
        // Which period the last care report covered: without it the target
        // reports a period the customer already has, or skips one.
        CARE_REPORT_KV_PERIOD_END,
        // The "new site" Slack announcement already went out for this one.
        "created_announced",
    ];
    if ALWAYS.contains(&key) {
        Some(CarryScope::Always)
    } else if MOVE_ONLY.contains(&key) {
        Some(CarryScope::MoveOnly)
    } else {
        None
    }
}

/// Replace every occurrence of the path `from` in `line` with `to`, but only
/// where `from` stands as a whole path: not preceded by a name character or
/// `/`, and not followed by a name character. `/home/a/x.cz` must not match
/// inside `/home/a/x.cz.old` or `/srv/home/a/x.cz`. With `subpaths` false a
/// following `/` does not match either — the path itself, never what is
/// under it.
pub(super) fn replace_bounded_path(line: &str, from: &str, to: &str, subpaths: bool) -> String {
    let is_name = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(pos) = rest.find(from) {
        let before = rest[..pos].chars().next_back();
        let after = rest[pos + from.len()..].chars().next();
        let bounded = !before.is_some_and(|c| is_name(c) || c == '/')
            && !after.is_some_and(|c| is_name(c) || (!subpaths && c == '/'));
        out.push_str(&rest[..pos]);
        out.push_str(if bounded { to } else { from });
        rest = &rest[pos + from.len()..];
    }
    out.push_str(rest);
    out
}

/// Point a carried crontab at the site's new place.
///
/// `crontab -u <user> -l` is the whole ACCOUNT's crontab, and its lines name
/// absolute paths: `/home/<srcuser>/<srcdomain>/htdocs/wp-cron.php`. Restored
/// as-is on a Copy, every job kept running against the SOURCE tree under the
/// copy's account — its `wp cron` against production's files and database.
///
/// The source site's tree becomes the new tree and the bare source home the
/// new home. A line that still names something else under the source home —
/// another site that shared the source account — is commented out and
/// reported: it belongs to a site that did not travel, and run here it would
/// act on that site (on the same node) or on nothing (on another).
///
/// Returns the new body and one note per disabled line.
pub(super) fn rewrite_crontab_paths(
    body: &str,
    from_tree: &str,
    to_tree: &str,
    from_home: &str,
    to_home: &str,
) -> (String, Vec<String>) {
    let from_tree = from_tree.trim_end_matches('/');
    let to_tree = to_tree.trim_end_matches('/');
    let from_home = from_home.trim_end_matches('/');
    let to_home = to_home.trim_end_matches('/');
    let mut out = String::with_capacity(body.len());
    let mut notes = Vec::new();
    for line in body.lines() {
        if line.trim_start().starts_with('#') || from_tree.is_empty() {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let moved = replace_bounded_path(line, from_tree, to_tree, true);
        let moved = if from_home.is_empty() {
            moved
        } else {
            replace_bounded_path(&moved, from_home, to_home, false)
        };
        // Anything still under the source home, once the new tree's own
        // paths are set aside, belongs to a site that stayed behind.
        let foreign = !from_home.is_empty()
            && replace_bounded_path(&moved, to_tree, "", true).contains(&format!("{from_home}/"));
        if foreign {
            notes.push(format!(
                "cron line disabled (it points at another site of the source account): {}",
                line.trim()
            ));
            out.push_str("# hyperion: disabled on import, points at another site: ");
            out.push_str(line);
        } else {
            out.push_str(&moved);
        }
        out.push('\n');
    }
    (out, notes)
}

pub(super) async fn curl_to_file(
    url: &str,
    dest: &std::path::Path,
    resolve_pins: &[String],
    max_bytes: u64,
    // Whether `max_bytes` is the operator-raisable archive cap. The archive
    // download's cap can be lifted via `[migration] max_download_gb`; the
    // manifest's tight cap cannot, so its refusal must NOT point there.
    cap_is_raisable: bool,
) -> Result<(), RpcError> {
    // -f: fail with non-zero exit on 4xx/5xx (otherwise curl happily
    //     writes the error body to disk and we'd "import" garbage).
    // Stall detection, not a wall clock: abort below 1 KiB/s for 5 minutes
    //   (speed-limit/speed-time) and after 30 s without a connection. The old
    //   `max-time 1800` killed every archive over ~20 GB at 100 Mbit/s while
    //   the cap allows 64 GB — and with no resume each retry started over.
    //   `max-time` stays as a 24 h backstop.
    // --max-filesize: refuse a download larger than `max_bytes` (the caller's
    //   cap — the configured archive limit, or the tight manifest limit).
    //   Without this a malicious upstream could fill the disk.
    // --max-redirs 0: do NOT follow redirects. With -L set, an
    //   attacker who got the operator to paste their URL into the
    //   import form could 302 us to file:// / DNS-rebind /
    //   internal IP, opening a SSRF pivot. The legitimate source
    //   serves the bundle on a known URL and doesn't need
    //   redirects; if a future deployment does, the operator can
    //   set up a proxy.
    // --proto =https,http: refuse file:// / gopher:// / dict://
    //   even if the URL parser somehow accepts them.
    // -k upfront, not inserted later. The previous version called
    // args.insert(2, "-k") AFTER building the vec — index 2 was the
    // "1800" slot, so the insertion left curl seeing `--max-time -k`
    // and the import failed with
    //   "curl: option --max-time: expected a proper numerical parameter"
    // every single migration. Spot the bug by listing the indices:
    // vec is [-fsS, --max-time, 1800, --max-filesize, …], so
    // insert(2, "-k") yields [-fsS, --max-time, -k, 1800, …].
    //
    // -k is required because the migration source serves on a
    // self-signed cert (same chicken-egg as enrollment — no DNS at
    // install). Trust on first use: the bundle's signed token +
    // BLAKE3 digest are the integrity guarantees, NOT TLS.
    //
    // The URL carries the bundle TOKEN in its query string, so it does not go
    // on argv: /proc/<pid>/cmdline is world-readable, this download holds for
    // hours on a big site, and the token grants a fetch of the full site export
    // — every database dump and wp-config in the bundle — from anywhere.
    // Options ride on stdin instead. Every interpolated value is escaped, so
    // a crafted URL cannot close its quotes and inject further directives.
    use hyperion_adapters::cmd::curl_config_quote as q;
    let mut config = format!(
        concat!(
            "url = \"{url}\"\n",
            "output = \"{dest}\"\n",
            "fail\n",
            "silent\n",
            "show-error\n",
            "insecure\n",
            "connect-timeout = 30\n",
            "speed-limit = 1024\n",
            "speed-time = 300\n",
            "max-time = 86400\n",
            "max-filesize = {maxsize}\n",
            "max-redirs = 0\n",
            "proto = \"=https,http\"\n",
        ),
        url = q(url),
        dest = q(&dest.display().to_string()),
        maxsize = max_bytes,
    );
    // SSRF guard (sec-findings #4): pin curl to the IP(s) the caller already
    // validated as non-internal, so a DNS-rebind can't swing the host to an
    // internal address between our resolve and curl's.
    for pin in resolve_pins {
        config.push_str(&format!("resolve = \"{}\"\n", q(pin)));
    }
    let (_stdout, stderr_tail, code) = hyperion_adapters::cmd::curl_with_config_capture(&config)
        .await
        .map_err(|e| RpcError::Internal_with(format!("spawn curl: {e}")))?;
    if code != 0 {
        // SECURITY (sec-findings #4): do NOT reflect the raw curl stderr/exit
        // code back to the caller. The distinct messages for 404 vs connection-
        // refused vs timeout turn this into an internal-reachability oracle for
        // port/host enumeration. Log the detail server-side; return a generic,
        // non-distinguishing error (the over-limit case keeps a friendlier hint).
        let stderr = stderr_tail.trim().to_string();
        tracing::warn!(code, %stderr, "migration download failed");
        let message = if code == 63 {
            // Report the cap in the unit it actually is — GB for the archive
            // cap, MB for the tight sub-GB manifest cap (which floored to
            // "0 GB" before). Only point at the config knob for the cap it
            // actually governs.
            let gib = 1024 * 1024 * 1024;
            let human = if max_bytes >= gib {
                format!("{} GB", max_bytes / gib)
            } else {
                format!("{} MB", max_bytes / (1024 * 1024))
            };
            let mut m =
                format!("download failed: file larger than {human} — refusing to download.");
            if cap_is_raisable {
                m.push_str(
                    " If this site is legitimately that large, raise the limit with \
                     `[migration] max_download_gb` in the target node's agent.toml.",
                );
            }
            m
        } else {
            "download failed: could not fetch the bundle from the source URL \
             (check the URL and token, and that the source is reachable)"
                .to_string()
        };
        return Err(RpcError::Validation { message });
    }
    Ok(())
}

/// Compute the BLAKE3 digest of a file by streaming 64 KiB chunks
/// through the hasher. Used by the migration export/import path to
/// detect tampering or transport corruption without ever loading
/// the whole archive into memory. Returns hex-encoded.
///
/// The field is named "sha256" in the manifest for historical
/// reasons; the actual algorithm is BLAKE3. Both sides recompute
/// with the same code, so cross-tool verification is a non-goal.
pub(super) async fn compute_sha256(path: &std::path::Path) -> Result<String, RpcError> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| RpcError::Internal_with(format!("digest open: {e}")))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .await
            .map_err(|e| RpcError::Internal_with(format!("digest read: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize().as_bytes()))
}

/// A migration bundle id is one path component of ULID/timestamp shape:
/// letters, digits, `-` and `_` only — no `/`, no dots, so never `..`.
pub(super) fn bundle_id_ok(bundle_id: &str) -> bool {
    !bundle_id.is_empty()
        && bundle_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A fresh `/var/lib/hyperion/migration-incoming/inc_<ulid>/` for one
/// incoming bundle. The caller removes it on every exit.
pub(super) async fn make_incoming_staging() -> Result<std::path::PathBuf, RpcError> {
    // Staging area lives next to the export dir so /var/lib has
    // a single migration namespace operators can grep / delete.
    let staging_id = format!("inc_{}", ulid::Ulid::new());
    let staging =
        std::path::PathBuf::from("/var/lib/hyperion/migration-incoming").join(&staging_id);
    tokio::fs::create_dir_all(&staging)
        .await
        .map_err(|e| RpcError::Internal_with(format!("mkdir staging: {e}")))?;
    // 0700 on the staging dir AND its parent. A migration bundle holds
    // plaintext database dumps and wp-config secrets for every site being
    // moved; the outbound half already did this, the inbound half did
    // not. The parent matters too — without it another local user can
    // traverse in and read by name.
    {
        use std::os::unix::fs::PermissionsExt;
        let p700 = std::fs::Permissions::from_mode(0o700);
        let _ =
            tokio::fs::set_permissions("/var/lib/hyperion/migration-incoming", p700.clone()).await;
        let _ = tokio::fs::set_permissions(&staging, p700).await;
    }
    Ok(staging)
}
