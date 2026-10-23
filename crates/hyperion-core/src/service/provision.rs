//! Creating, listing, reading and deleting hostings, with LIFO rollback.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Provision a hosting end-to-end with LIFO rollback on partial failure.
    pub async fn create(&self, mut req: HostingCreateReq) -> Result<HostingCreated, RpcError> {
        // A typed `www.example.cz` is the alias of `example.cz`, never a site
        // of its own (it would offer `www.www.example.cz` as canonical host).
        // Every caller (panel, API, CLI) lands here, so normalise once.
        req.domain = req.domain.without_www();
        let bare = req.domain.as_str().to_string();
        req.aliases.retain(|a| a.as_str() != bare);
        // A site shares an existing account ONLY when the caller named it.
        // A derived name that is already taken is somebody else's account —
        // two domains fold onto one name easily (`my-shop.cz`, `my.shop.cz`)
        // — and attaching to it would run this site's PHP as that tenant.
        if req.system_user.is_none() {
            req.system_user = Some(self.free_system_user(&bare).await?);
        }
        let user = req.system_user.clone();
        let result = self.create_provision(req).await;
        // A create on an existing system user re-enables it once its row is in
        // (a new online site needs the account). If the create then failed and
        // rolled its row back, the account's other sites may all be offline
        // again: decide it again now rather than at the next reconcile.
        if result.is_err() {
            if let Some(user) = user {
                self.apply_system_user_policy(user.as_str()).await;
            }
        }
        result
    }

    pub(super) async fn create_provision(
        &self,
        req: HostingCreateReq,
    ) -> Result<HostingCreated, RpcError> {
        // 1. Validate (parse already did most). Derive system user if absent.
        let system_user = match req.system_user.clone() {
            Some(u) => u,
            None => SystemUserName::derive_from_domain(req.domain.as_str())?,
        };
        self.reclaim_trashed_domain(req.domain.as_str()).await;

        // Every step that changes the box pushes its undo; any failure rolls
        // all of them back, newest first.
        let mut stack = RollbackStack::new();
        let created = match self.provision_steps(&req, &system_user, &mut stack).await {
            Ok(created) => created,
            Err(e) => {
                rollback_and_log(&mut stack).await;
                return Err(e);
            }
        };
        // success — discard rollback
        stack.forget();

        // Auto-enable uptime monitoring with sane defaults so a new site
        // is watched from the moment it goes live (HTTP probe of `/` every
        // 60s, alert after 3 consecutive fails). Best-effort + no alert
        // destination yet — it populates the monitoring dashboard
        // immediately; the operator adds an email/Slack target and tunes
        // or disables it on the Monitor tab.
        let _ = hyperion_state::monitors::set_config(
            &self.pool,
            &created.id,
            true,
            Some("/"),
            Some(60),
            Some(3),
            None,
            // A brand-new hosting has no webhook to keep or clear.
            hyperion_state::monitors::SecretField::Keep,
            None,
            now_secs(),
        )
        .await;
        Ok(created)
    }

    /// Reclaim a trashed slot. A previous delete with trash ENABLED leaves
    /// the row in place (state='trashed') so it can be restored — but the
    /// row still holds the domain under the UNIQUE(hostings.domain)
    /// constraint. The hosting is gone from the operator's list AND from the
    /// create-wizard's preflight (both filter out trashed rows), so
    /// re-creating the exact same domain blew up with a cryptic "entity
    /// already exists … UNIQUE constraint failed" even though, as far as the
    /// operator could see, the hosting didn't exist. Re-creating the SAME
    /// domain is an unambiguous signal the operator wants it back, so we
    /// hard-purge the trashed row first to free the slot. A row in any OTHER
    /// state is a genuine live conflict and is left for the INSERT to reject
    /// with AlreadyExists.
    pub(super) async fn reclaim_trashed_domain(&self, domain: &str) {
        let Ok(Some(existing)) = hostings::get_by_domain(&self.pool, domain).await else {
            return;
        };
        if existing.state != HostingState::Trashed {
            return;
        }
        let Ok(detail) = self.get(HostingSelector::Id(existing.id.clone())).await else {
            return;
        };
        tracing::info!(
            domain = %domain,
            id = %existing.id,
            "create: reclaiming domain from a trashed hosting (purging it)"
        );
        self.append_audit(
            "hosting.create.reclaim_trashed",
            Some(existing.id.as_str()),
            &serde_json::json!({"domain": domain}).to_string(),
            "ok",
        )
        .await;
        // Best-effort: on purge failure we fall through and let the INSERT
        // surface the original conflict rather than masking it.
        let _ = self
            .hard_delete_internal(detail, DeleteOpts::default())
            .await;
    }

    /// The provisioning steps proper. Each one that changes the box pushes
    /// its undo onto `stack`; the caller rolls the stack back on `Err`.
    pub(super) async fn provision_steps(
        &self,
        req: &HostingCreateReq,
        system_user: &SystemUserName,
        stack: &mut RollbackStack,
    ) -> Result<HostingCreated, RpcError> {
        let domain = req.domain.as_str();
        let home_dir = format!("{}/{}", self.paths.home_root, system_user);
        let hosting_root = format!("{}/{}", home_dir, domain);
        let htdocs = format!("{}/htdocs", hosting_root);
        let logs = format!("{}/logs", hosting_root);
        let tmp = format!("{}/tmp", hosting_root);

        // Is the system user already known to Hyperion (i.e. shared with
        // another hosting)? If so, THIS create did not create it, and the
        // rollback must NOT `userdel -r` it or drop its system_users row
        // — that would delete the OTHER hosting's entire /home tree and
        // orphan its UID. The original code pushed both destructive
        // steps unconditionally, so any later create failure (most
        // commonly ACME on un-pointed DNS) wiped a shared user. Only push
        // them when WE are the user's creator. (Checked before
        // ensure_user; the reclaim-trashed purge already ran, so a
        // reclaimed name correctly reads as absent here.)
        let user_pre_existed = system_users::get_by_name(&self.pool, system_user.as_str())
            .await
            .ok()
            .flatten()
            .is_some();

        // 2. ensure_user
        let uid = self
            .adapters
            .ensure_user(system_user.as_str(), &home_dir)
            .await?;
        if !user_pre_existed {
            stack.push(Box::new(DeleteUser {
                adapters: self.adapters.clone(),
                name: system_user.as_str().to_string(),
            }));
        }

        // 3. ensure_dirs
        self.adapters.ensure_dirs(&htdocs, &logs, &tmp, uid).await?;
        stack.push(Box::new(RemoveTree {
            adapters: self.adapters.clone(),
            root: hosting_root.clone(),
        }));

        // 4. system_users row (needed for the hosting row's FK)
        let suid_row = self
            .insert_system_user_row(system_user.as_str(), uid, &home_dir)
            .await?;
        // Now that the system_users row exists, push a rollback step
        // that removes it on later failures. Without this, the
        // DeleteUser rollback (Linux user) runs but the DB row keeps
        // the UID, claiming it permanently. The next create's
        // useradd reuses the freed UID and trips UNIQUE(uid).
        // Only register the system_users-row rollback when WE inserted
        // it (see user_pre_existed above) — never drop a row shared with
        // another hosting.
        if !user_pre_existed {
            stack.push(Box::new(DeleteSystemUsersRow {
                pool: self.pool.clone(),
                row_id: suid_row,
            }));
        }
        // For reverse_proxy validate upstream URL is present + parseable.
        // NOTE: this runs after user/dirs/system_users are already
        // created, so a refusal MUST roll back — otherwise an
        // invalid/missing upstream URL leaks a Linux user + /home tree +
        // DB row (the web form only checks the URL is non-empty, not the
        // scheme).
        if req.kind == "reverse_proxy" {
            validate_proxy_upstream(req.proxy_upstream_url.as_deref())?;
        }
        // NOTE: kind="php" with NO php_version is deliberately ALLOWED.
        //
        // It is tempting to reject it here the way reverse_proxy rejects a
        // missing upstream — such a hosting gets no FPM pool and answers
        // "requires a PHP hosting" to every WordPress action. But it is a
        // state an operator asks for on purpose: the create form offers PHP
        // "none", and the hosting detail page has a converter built for
        // exactly this row ("no PHP version yet" → pick a version). Refusing
        // it here would break creating a site with PHP off.
        //
        // The real defect was upstream: the panel import silently DISCARDED
        // any version outside the 8.1-8.4 allow-list — so a CloudPanel site on
        // 7.4 or "8.2.10" landed in this state without anyone choosing it, and
        // reported a successful import. That is fixed where it belongs, in
        // `panel_import::apply_one_import`, which now substitutes the nearest
        // supported version and says so.
        let hosting_id = HostingId::new_v7();
        let node_id_str = self.current_node_id();
        if let Err(e) = hostings::insert_with_kind(
            &self.pool,
            &hosting_id,
            domain,
            suid_row,
            req.php_version,
            &htdocs,
            &req.kind,
            req.proxy_upstream_url.as_deref(),
            now_secs(),
            Some(node_id_str.as_str()),
        )
        .await
        {
            // The trashed-row case is reclaimed before we get here, so a
            // failure is a genuine live conflict. Translate the raw sqlx
            // UNIQUE message into something an operator can act on
            // instead of "(error returned from database: (code: 2067)
            // UNIQUE constraint failed: hostings.domain)".
            let id = match hostings::get_by_domain(&self.pool, domain).await {
                Ok(Some(other)) => format!(
                    "{domain} is already used by a hosting on this node (state: {})",
                    other.state.as_str()
                ),
                _ => format!("{domain} ({e})"),
            };
            return Err(RpcError::AlreadyExists {
                kind: "hosting".into(),
                id,
            });
        }
        stack.push(Box::new(MarkFailedOrDeleteRow {
            pool: self.pool.clone(),
            id: hosting_id.clone(),
        }));
        // A new site on an existing system user whose other hostings are all
        // offline: that account was disabled, and this site needs it.
        if user_pre_existed {
            self.apply_system_user_policy(system_user.as_str()).await;
        }

        // 4b. aliases
        for alias in &req.aliases {
            if let Err(e) = hostings::insert_alias(&self.pool, &hosting_id, alias.as_str()).await {
                return Err(RpcError::AlreadyExists {
                    kind: "alias".into(),
                    id: format!("{} ({})", alias, e),
                });
            }
        }

        // 5. PHP-FPM pool — only for kind=php hostings.
        if req.kind == "php" {
            if let Some(ver) = req.php_version {
                self.adapters
                    .fpm_ensure(system_user.as_str(), domain, ver)
                    .await?;
                stack.push(Box::new(FpmDelete {
                    adapters: self.adapters.clone(),
                    system_user: system_user.as_str().to_string(),
                    version: ver,
                }));
            }
        }

        // 6. database
        let db_creds = match req.database {
            Some(engine) => Some(
                self.provision_database(engine, &hosting_id, domain, stack)
                    .await?,
            ),
            None => None,
        };

        // 7. TLS cert
        let sans: Vec<String> = req.aliases.iter().map(|d| d.to_string()).collect();
        let (cert, detail_cert_path, detail_cert_key_path) =
            self.provision_cert(domain, &sans, stack).await?;

        // 8. nginx vhost
        let detail = HostingDetail {
            id: hosting_id.clone(),
            domain: domain.to_string(),
            aliases: sans,
            state: HostingState::Provisioning,
            system_user: system_user.as_str().to_string(),
            php_version: req.php_version,
            root_dir: htdocs.clone(),
            database: db_creds.as_ref().map(|c| DbSummary {
                engine: c.engine,
                db_name: c.db_name.clone(),
                db_user: c.db_user.clone(),
            }),
            cert: Some(cert.clone()),
            created_at: now_secs(),
            updated_at: now_secs(),
            acme_contact_email: None,
            kind: req.kind.clone(),
            proxy_upstream_url: req.proxy_upstream_url.clone(),
            node_id: Some(node_id_str),
            vhost_options: hyperion_types::VhostOptions::default(),
            wp_extras: hyperion_types::WpExtras::default(),
            cert_path: detail_cert_path,
            cert_key_path: detail_cert_key_path,
        };
        self.adapters.nginx_write_vhost(&detail).await?;

        // 9. transition to active
        hostings::set_state(&self.pool, &hosting_id, HostingState::Active, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set_state: {e}")))?;

        Ok(HostingCreated {
            id: hosting_id,
            system_user: system_user.as_str().to_string(),
            root_dir: htdocs,
            db: db_creds,
            cert: Some(cert),
            wp: None,
        })
    }

    /// INSERT the system_users row, recovering from the two failures worth
    /// recovering from automatically:
    ///   (a) Same NAME already in the DB — we're re-running a partial create;
    ///       reuse the existing row.
    ///   (b) Same UID already in the DB but DIFFERENT name — stale orphan
    ///       from a previous hosting delete that predated the system_users
    ///       cleanup fix. Verify nothing references it, drop it, retry.
    pub(super) async fn insert_system_user_row(
        &self,
        name: &str,
        uid: u32,
        home_dir: &str,
    ) -> Result<i64, RpcError> {
        let insert = || {
            system_users::insert(
                &self.pool,
                name,
                uid as i64,
                home_dir,
                "/usr/sbin/nologin",
                now_secs(),
            )
        };
        let e = match insert().await {
            Ok(id) => return Ok(id),
            Err(e) => e,
        };
        if let Some(row) = system_users::get_by_name(&self.pool, name)
            .await
            .ok()
            .flatten()
        {
            return Ok(row.id);
        }
        let by_uid = system_users::get_by_uid(&self.pool, uid as i64)
            .await
            .ok()
            .flatten();
        // Orphan detection: a system_users row whose referencing hostings
        // are either (a) absent or (b) ALL in non-active states (failed,
        // provisioning, deleting) is safe to clean — no real hosting depends
        // on it. Only an `active` hosting locks the row.
        let orphan = match &by_uid {
            Some(r) => {
                let rows: Vec<(String,)> =
                    sqlx::query_as("SELECT state FROM hostings WHERE system_user_id = ?")
                        .bind(r.id)
                        .fetch_all(&self.pool)
                        .await
                        .unwrap_or_default();
                (!rows.iter().any(|(s,)| s == "active")).then(|| r.clone())
            }
            None => None,
        };
        let Some(orphan) = orphan else {
            // Either by_uid is None (the UID legitimately belongs to a
            // hosting we shouldn't nuke) or a live hosting references it. In
            // both cases the operator has to investigate by hand — but
            // surface the row id so they can grep the DB.
            if let Some(by_uid_row) = by_uid {
                tracing::error!(
                    uid = uid,
                    existing_name = %by_uid_row.name,
                    "system_users UID conflict + the conflicting row IS referenced by \
                     a hostings record — refusing to auto-clean. Inspect with: \
                     sqlite3 /var/lib/hyperion/state.db \
                     'SELECT * FROM hostings WHERE system_user_id = {row_id};'",
                    row_id = by_uid_row.id
                );
            }
            return Err(RpcError::Internal_with(format!("system_users insert: {e}")));
        };
        tracing::warn!(
            uid = uid,
            old_name = %orphan.name,
            new_name = %name,
            "dropping orphan system_users row to free UID"
        );
        // Also drop any hostings rows that referenced the orphan — they're
        // necessarily stale because none of them is active (the orphan check
        // above gates on that). No-op when there are none, which is the
        // common case.
        let _ = sqlx::query("DELETE FROM hostings WHERE system_user_id = ?")
            .bind(orphan.id)
            .execute(&self.pool)
            .await;
        let _ = system_users::delete(&self.pool, orphan.id).await;
        insert().await.map_err(|e2| {
            RpcError::Internal_with(format!(
                "system_users insert (retry after orphan cleanup): {e2}"
            ))
        })
    }

    /// Create the hosting's database, keep its password in the secrets
    /// store, and record the row.
    pub(super) async fn provision_database(
        &self,
        engine: DbProvision,
        hosting_id: &HostingId,
        domain: &str,
        stack: &mut RollbackStack,
    ) -> Result<DbCredentials, RpcError> {
        let creds = self.adapters.db_create(engine, hosting_id, domain).await?;
        // Pushed straight away: a failure in the two writes below must not
        // leave the database and its user behind.
        stack.push(Box::new(DbDrop {
            adapters: self.adapters.clone(),
            engine,
            db_name: creds.db_name.clone(),
            db_user: creds.db_user.clone(),
        }));
        let secret_id = SecretId::new();
        self.secrets
            .put(
                &secret_id,
                &serde_json::json!({
                    "engine": engine.as_str(),
                    "db_name": creds.db_name,
                    "db_user": creds.db_user,
                    "password": creds.password,
                }),
            )
            .await
            .map_err(|e| RpcError::Internal_with(format!("secret write: {e}")))?;
        databases::insert(
            &self.pool,
            hosting_id,
            engine,
            &creds.db_name,
            &creds.db_user,
            &secret_id,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("databases row: {e}")))?;
        Ok(creds)
    }

    /// The new hosting's certificate and, when it borrows a shared one, that
    /// cert's paths for the vhost. If this hosting's PARENT domain already
    /// carries a wildcard cert on this node — e.g. a test node's `*.<base>`
    /// issued once in Settings — it is reused instead of burning a per-site
    /// ACME issuance. New auto-subdomains get HTTPS instantly and never touch
    /// the Let's Encrypt per-domain rate limit.
    pub(super) async fn provision_cert(
        &self,
        domain: &str,
        sans: &[String],
        stack: &mut RollbackStack,
    ) -> Result<(CertInfo, Option<String>, Option<String>), RpcError> {
        let parent_base = domain.split_once('.').map(|(_, rest)| rest.to_string());
        let shared_wildcard = match parent_base.as_deref() {
            Some(base)
                if certificates::is_wildcard(&self.pool, base)
                    .await
                    .unwrap_or(false) =>
            {
                certificates::get(&self.pool, base).await.ok().flatten()
            }
            _ => None,
        };
        if let Some(wc) = shared_wildcard {
            // Reference the shared wildcard: record a cert row pointing at
            // the wildcard's files (so the SSL tab shows a valid cert) and
            // point the vhost at them. No ACME order, no rollback of files —
            // the cert is owned by the node wildcard, not this hosting, so
            // the renewal sweep skips this reference row.
            let _ = certificates::upsert(
                &self.pool,
                domain,
                wc.issued_at,
                wc.not_after,
                &wc.cert_path,
                &wc.key_path,
                &wc.issuer,
            )
            .await;
            // Roll back the reference row (NOT the shared files) if a later
            // provisioning step fails, so it can't orphan once the
            // half-created hosting row is deleted.
            stack.push(Box::new(CertRowDelete {
                pool: self.pool.clone(),
                domain: domain.to_string(),
            }));
            let info = CertInfo {
                domain: domain.to_string(),
                sans: sans.to_vec(),
                issuer: wc.issuer.clone(),
                not_after: wc.not_after,
                fingerprint_sha256: String::new(),
            };
            return Ok((info, Some(wc.cert_path), Some(wc.key_path)));
        }
        let cert = self.adapters.acme_issue(domain, sans).await?;
        let cert_path = format!("/etc/hyperion/certs/{}/fullchain.pem", domain);
        let key_path = format!("/etc/hyperion/certs/{}/privkey.pem", domain);
        let _ = certificates::upsert(
            &self.pool,
            domain,
            now_secs(),
            cert.not_after,
            &cert_path,
            &key_path,
            &cert.issuer,
        )
        .await;
        stack.push(Box::new(AcmeDelete {
            adapters: self.adapters.clone(),
            domain: domain.to_string(),
        }));
        Ok((cert, None, None))
    }

    pub async fn list(&self) -> Result<Vec<HostingSummary>, RpcError> {
        hostings::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))
    }

    /// Cap the local redis-server and make it evict like a cache (see
    /// `hyperion_adapters::redis`). Run when a site turns its object cache
    /// on and once at boot, so nodes that already use Redis get it too.
    /// Best-effort: Redis without the cap still serves.
    pub async fn ensure_redis_memory_policy(&self) {
        if !self.adapters.redis_is_available().await {
            return;
        }
        let ram = hyperion_adapters::redis::mem_total_kib().await;
        match hyperion_adapters::redis::ensure_cache_memory_policy(ram).await {
            Ok(true) => tracing::info!("redis: object-cache memory cap + LRU eviction applied"),
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, "redis: memory policy not applied"),
        }
    }

    /// Rewrite, once, every Active site vhost rendered before the template
    /// last changed in a way existing sites need.
    ///
    /// update.sh never rewrites vhosts, so a template fix otherwise lands
    /// only when somebody happens to re-save each site. Gated per hosting
    /// on [`VHOST_GEN_KV`] so a boot with nothing new to roll out touches no
    /// vhost and reloads nothing. Returns how many vhosts it rewrote.
    pub async fn rerender_stale_vhosts(&self) -> usize {
        let Ok(summaries) = self.list().await else {
            return 0;
        };
        let want = VHOST_GEN.to_string();
        let mut n = 0;
        for s in summaries {
            if s.state != HostingState::Active {
                continue;
            }
            let id = s.id.as_str().to_string();
            let have = hyperion_state::hosting_kv::get(&self.pool, &id, VHOST_GEN_KV)
                .await
                .ok()
                .flatten();
            if have.as_deref() == Some(want.as_str()) {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            match self.adapters.nginx_write_vhost(&detail).await {
                Ok(()) => {
                    let _ = hyperion_state::hosting_kv::set(
                        &self.pool,
                        &id,
                        VHOST_GEN_KV,
                        &want,
                        now_secs(),
                    )
                    .await;
                    n += 1;
                }
                // Not marked: the next boot tries again. write_vhost has
                // already put the previous, working vhost back.
                Err(e) => tracing::warn!(
                    domain = %detail.domain, error = %e,
                    "boot: vhost re-render failed; keeping the old one"
                ),
            }
        }
        n
    }

    /// Write a hosting's FPM pool WITH its stored limits.
    ///
    /// `fpm_ensure` alone renders the template defaults (256 MB,
    /// five workers). Every path that rewrites an existing site's pool must
    /// come through here instead: the boot re-render used to call
    /// `fpm_ensure`, so each agent restart — every update — silently put
    /// every pool back on the defaults. That threw away the operator's
    /// worker count and every step the automatic memory_limit had taken,
    /// and the automation never noticed: it reads the limit from the DB,
    /// so it ignored the 256 MB fatals as being "below the limit in force".
    pub(super) async fn fpm_ensure_with_limits(
        &self,
        detail: &HostingDetail,
        ver: PhpVersion,
    ) -> Result<(), AdapterError> {
        match hyperion_state::limits::get(&self.pool, &detail.id).await {
            Ok(Some(row)) => {
                self.adapters
                    .apply_php_limits(
                        &detail.system_user,
                        &detail.domain,
                        Some(ver),
                        row.php_memory_mb,
                        row.php_max_exec_secs,
                        row.php_max_children,
                        row.php_max_requests,
                    )
                    .await
            }
            // No row: the site never had limits set, so the defaults ARE
            // its limits.
            Ok(None) => {
                self.adapters
                    .fpm_ensure(&detail.system_user, &detail.domain, ver)
                    .await
            }
            // Never fall back to the defaults on a read error — that is the
            // very reset this function exists to prevent.
            Err(e) => Err(AdapterError::Other(format!("limits get: {e}"))),
        }
    }

    /// Boot-time self-heal: re-render the FPM pool config for every
    /// active hosting that has PHP. We do this because the pool
    /// template's `listen.owner` depends on the nginx user, which is
    /// detected dynamically at startup — old pool files on disk may
    /// hard-code an outdated owner (e.g. `www-data` when nginx now
    /// runs as `vito`).
    ///
    /// IMPORTANT: after the pools are re-written we issue a `systemctl
    /// restart php<ver>-fpm` for every PHP version that owned at least
    /// one rewritten pool. `reload` alone is not enough — FPM keeps
    /// the existing UNIX socket open even when the pool config's
    /// `listen.owner` changes, and `chown(2)` is not re-applied to an
    /// already-bound socket. Only a full restart re-creates the
    /// socket with the new ownership. We accept the (~50ms per
    /// version) brief PHP availability gap on agent startup as a
    /// worthy trade — without it 502 persists until manual fix.
    ///
    /// Errors per-hosting are logged but never propagated — one bad
    /// hosting must not block agent startup. Returns the count of
    /// pools successfully re-rendered.
    pub async fn rerender_fpm_pools(&self) -> usize {
        let summaries = match self.list().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error=%e, "rerender_fpm_pools: list failed");
                return 0;
            }
        };
        let mut ok = 0;
        let mut touched_versions: std::collections::HashSet<PhpVersion> = Default::default();
        for s in summaries {
            let Some(ver) = s.php_version else {
                continue;
            };
            if !matches!(s.state, hyperion_types::HostingState::Active) {
                continue;
            }
            // We need the system_user for fpm_ensure. Pull the detail.
            let detail = match self
                .get(crate::service::HostingSelector::Id(s.id.clone()))
                .await
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        domain = %s.domain,
                        error = %e,
                        "rerender_fpm_pools: could not fetch detail"
                    );
                    continue;
                }
            };
            if detail.system_user.is_empty() {
                tracing::warn!(
                    domain = %detail.domain,
                    "rerender_fpm_pools: skipping (empty system_user)"
                );
                continue;
            }
            if let Err(e) = self.fpm_ensure_with_limits(&detail, ver).await {
                tracing::warn!(
                    domain = %detail.domain,
                    error = %e,
                    "rerender_fpm_pools: pool rewrite failed"
                );
                continue;
            }
            touched_versions.insert(ver);
            ok += 1;
        }

        // Full restart per touched version — see doc comment above for
        // why reload isn't enough. We swallow errors: if FPM can't be
        // restarted by us, the operator will see the pool config is
        // correct on disk and can fix manually.
        for ver in touched_versions {
            let svc = format!("{}.service", ver.service_name());
            let res = tokio::process::Command::new("/usr/bin/systemctl")
                .args(["restart", &svc])
                .output()
                .await;
            match res {
                Ok(out) if out.status.success() => {
                    tracing::info!(service = %svc, "boot self-heal: restarted FPM to apply new listen.owner");
                }
                Ok(out) => {
                    tracing::warn!(
                        service = %svc,
                        stderr = %String::from_utf8_lossy(&out.stderr),
                        "boot self-heal: systemctl restart failed"
                    );
                }
                Err(e) => {
                    tracing::warn!(error=%e, service=%svc, "boot self-heal: could not invoke systemctl");
                }
            }
        }

        ok
    }

    pub async fn get(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError> {
        let row = match sel {
            HostingSelector::Id(id) => hostings::get_by_id(&self.pool, &id).await,
            HostingSelector::Domain(d) => hostings::get_by_domain(&self.pool, d.as_str()).await,
        }
        .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
        .ok_or_else(|| RpcError::NotFound {
            kind: "hosting".into(),
            id: "selector".into(),
        })?;

        let aliases = hostings::aliases(&self.pool, &row.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("aliases: {e}")))?;
        let db = databases::get_for_hosting(&self.pool, &row.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("databases: {e}")))?
            .map(|d| DbSummary {
                engine: d.engine,
                db_name: d.db_name,
                db_user: d.db_user,
            });
        let cert_row = certificates::get(&self.pool, &row.domain)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cert: {e}")))?;
        // Carry the stored cert paths through so the vhost serves the
        // right files — for a reused shared wildcard these point at a
        // different domain's cert dir than this hosting's default.
        let (cert_path, cert_key_path) = match cert_row.as_ref() {
            Some(c) => (Some(c.cert_path.clone()), Some(c.key_path.clone())),
            None => (None, None),
        };
        // The fingerprint is not a column — it is a property of the file on
        // disk, so read it from there rather than rendering an empty field.
        // That is also the more honest answer: it reports what is actually
        // being SERVED, not what we last remembered writing. Best-effort;
        // a missing or unreadable file leaves it blank, exactly as before.
        let cert = match cert_row {
            Some(c) => {
                let inspected = tokio::fs::read_to_string(&c.cert_path)
                    .await
                    .ok()
                    .and_then(|pem| hyperion_adapters::cert::inspect_pem(&pem).ok());
                Some(CertInfo {
                    domain: c.domain,
                    // The names the FILE carries. This used to be filled with
                    // the hosting's alias list, which made the field answer
                    // its own question: add an alias, and the panel showed it
                    // sitting in the certificate's SAN list while browsers
                    // refused the name. An unreadable file leaves it empty,
                    // which reads as "nothing known" rather than "covered".
                    sans: inspected
                        .as_ref()
                        .map(|i| i.covered_names.clone())
                        .unwrap_or_default(),
                    issuer: c.issuer,
                    not_after: c.not_after,
                    fingerprint_sha256: inspected.map(|i| i.fingerprint).unwrap_or_default(),
                })
            }
            None => None,
        };
        let suser = system_users::get_by_name(&self.pool, "")
            .await
            .ok()
            .flatten();
        let system_user_name = match suser {
            Some(_) => String::new(),
            None => {
                match sqlx::query_as::<_, (String,)>("SELECT name FROM system_users WHERE id = ?")
                    .bind(row.system_user_id)
                    .fetch_optional(&self.pool)
                    .await
                {
                    Ok(Some((s,))) => s,
                    _ => String::new(),
                }
            }
        };
        Ok(HostingDetail {
            id: row.id,
            domain: row.domain,
            aliases,
            state: row.state,
            system_user: system_user_name,
            php_version: row.php_version,
            root_dir: row.root_dir,
            database: db,
            cert,
            created_at: row.created_at,
            updated_at: row.updated_at,
            acme_contact_email: row.acme_contact_email,
            kind: row.kind,
            proxy_upstream_url: row.proxy_upstream_url,
            node_id: row.node_id,
            vhost_options: row.vhost_options,
            wp_extras: row.wp_extras,
            cert_path,
            cert_key_path,
        })
    }

    pub async fn delete(&self, sel: HostingSelector, opts: DeleteOpts) -> Result<(), RpcError> {
        let detail = self.get(sel.clone()).await?;

        // Refuse to "delete" an already-trashed row. trash_hosting would
        // re-stamp trashed_at (resetting the GC retention countdown) and
        // fire a duplicate "moved to trash" notification. Trashed rows
        // are managed via restore / purge, not delete (a stale tab,
        // double-submitted delete job, or `hctl delete <domain>` could
        // otherwise hit this).
        if detail.state == HostingState::Trashed {
            return Err(RpcError::Conflict {
                message: "hosting is already in trash — restore or purge it instead".into(),
            });
        }

        // Soft-delete branch: when cluster.trash_enabled = true, route to
        // trash() which preserves files / DB / user and flips the row to
        // state=trashed, GC'd to a hard delete after retention_days.
        //
        // BUT honour an explicit keep_user / keep_database: those flags
        // are a deliberate "delete the hosting, preserve this resource"
        // choice, and trash() takes no opts — the eventual GC/purge runs
        // with DeleteOpts::default() (keep=false) and would silently
        // destroy the DB/user the operator asked to keep, weeks later.
        // When either keep flag is set we hard-delete now (honouring
        // opts) instead of trashing.
        let cluster_cfg = read_cluster_section(self.agent_config_path.as_deref());
        if cluster_cfg.trash_enabled && !opts.keep_user && !opts.keep_database {
            return self.trash_hosting(detail).await;
        }
        self.delete_now(detail, opts).await
    }

    /// Undo a hosting this very call just created and failed to fill
    /// (import, restore-as-new, staging). Always a HARD delete: routing it
    /// through [`Self::delete`] put the half-restored tree, its database and
    /// user into the trash for the whole retention period and announced a
    /// "moved to trash" for a site nobody ever had.
    pub(super) async fn roll_back_created(&self, id: &HostingId) {
        if let Ok(detail) = self.get(HostingSelector::Id(id.clone())).await {
            let _ = self.delete_now(detail, DeleteOpts::default()).await;
        }
    }

    /// The hard-delete half of [`Self::delete`]: tear everything down now,
    /// never via the trash.
    pub(super) async fn delete_now(
        &self,
        detail: HostingDetail,
        opts: DeleteOpts,
    ) -> Result<(), RpcError> {
        hostings::set_state(&self.pool, &detail.id, HostingState::Deleting, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set deleting: {e}")))?;

        // best-effort nginx delete (also drops per-hosting cache zone +
        // htpasswd sidecar so the slot is fully clean for a future
        // hosting reusing this ULID).
        let _ = self
            .adapters
            .nginx_delete_vhost(&detail.domain, Some(detail.id.to_string()))
            .await;
        // best-effort cert delete
        let _ = self.adapters.acme_delete(&detail.domain).await;
        let _ = certificates::delete(&self.pool, &detail.domain).await;
        // db drop
        if let Some(db) = detail.database.as_ref() {
            if !opts.keep_database {
                let _ = self
                    .adapters
                    .db_drop(db.engine, &db.db_name, &db.db_user)
                    .await;
            }
        }
        // fpm pool delete
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        // remove tree
        let hosting_root = format!(
            "{}/{}/{}",
            self.paths.home_root, detail.system_user, detail.domain
        );
        let _ = self.adapters.remove_hosting_tree(&hosting_root).await;

        // Extra FTP logins are real passwd entries that share the site's uid;
        // the ftp_accounts rows cascade away with the hosting, so remove the
        // accounts here or nothing ever will. (hard_delete_internal does the
        // same.)
        if let Ok(logins) =
            hyperion_state::ftp_accounts::logins_for_hosting(&self.pool, &detail.id).await
        {
            for login in logins {
                if let Err(e) = hyperion_adapters::ftp::delete_extra_login(&login).await {
                    tracing::error!(
                        error = %e, login = %login,
                        "delete: could not remove an extra FTP login — it will outlive the hosting"
                    );
                }
            }
        }
        // State is `deleting` by now, so the site counts as neither online
        // nor offline: its extra logins stay shut on the way out, and its
        // system user is decided by whatever hostings remain on it.
        {
            let _serial = LOGIN_LOCKS.lock().await;
            let legacy = matches!(
                detail.state,
                HostingState::Suspended | HostingState::Trashed
            ) && matches!(self.login_lock_record(&detail.id).await, Ok(None));
            self.apply_login_policy_held(&detail.id, Some(legacy)).await;
        }
        if !opts.keep_user {
            // delete user only if no other hostings reference them
            let (others,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM hostings WHERE system_user_id = (SELECT id FROM system_users WHERE name = ?) AND id != ?")
                    .bind(&detail.system_user)
                    .bind(detail.id.as_str())
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("count: {e}")))?;
            if others == 0 {
                // `userdel` refuses (exit 8) while any process still holds the
                // account's UID, and this hosting's PHP-FPM workers do until
                // the pool is gone. The trash and suspend paths already kill
                // them; delete did not, so the failure was swallowed by the
                // `let _ =` below and the Linux user OUTLIVED the hosting —
                // while the `system_users` row was dropped anyway, which is
                // the orphan state the create-rollback goes to some length to
                // avoid. Killing here is right: the hosting is being
                // destroyed, so its processes are meant to stop.
                let _ = self.adapters.kill_user_procs(&detail.system_user).await;
                if let Err(e) = self.adapters.delete_user(&detail.system_user).await {
                    tracing::error!(
                        error = %e, user = %detail.system_user,
                        "delete: the Linux user survived — it will collide with the \
                         next hosting that derives the same name"
                    );
                }
                // Also drop the system_users row so the UID can be reused
                // for a future hosting (Linux frees the UID via userdel;
                // without this cleanup the next useradd allocates the same
                // UID and `system_users` INSERT hits its UNIQUE(uid)
                // constraint).
                if let Ok(Some(row)) =
                    system_users::get_by_name(&self.pool, &detail.system_user).await
                {
                    let _ = system_users::delete(&self.pool, row.id).await;
                }
            }
        }

        hostings::delete(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete row: {e}")))?;
        Ok(())
    }
}

/// Bump when a vhost template change must reach EXISTING sites (see
/// [`HostingService::rerender_stale_vhosts`]). 1: request time in the
/// access log, page-cache skip for logged-in and WooCommerce visitors.
/// 2: per-rule WAF whose refusals are tagged into the root-owned WAF log —
/// without the rewrite an existing site's activity view and WAF auto-ban
/// stay empty until somebody re-saves it. 3: page cache serves the last good
/// copy (and refills one request at a time) while the PHP pool is full.
/// 4: browser-cache lifetimes for static assets, gzip for text assets,
/// `open_file_cache`.
pub(super) const VHOST_GEN: u32 = 4;
/// Node-local `hosting_kv` key holding the generation a vhost was last
/// rendered at.
pub(super) const VHOST_GEN_KV: &str = "nginx.vhost_gen";

/// A reverse proxy needs an `http(s)://` upstream.
pub(super) fn validate_proxy_upstream(url: Option<&str>) -> Result<(), RpcError> {
    let Some(upstream) = url.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(RpcError::Validation {
            message: "reverse_proxy requires proxy_upstream_url".into(),
        });
    };
    if !(upstream.starts_with("http://") || upstream.starts_with("https://")) {
        return Err(RpcError::Validation {
            message: "proxy_upstream_url must start with http:// or https://".into(),
        });
    }
    Ok(())
}
