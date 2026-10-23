//! The hosting detail page and the data it gathers.

use super::*;

/// Per-field append to `CreateForm` for the optional WP install
/// checkbox + its admin fields. Standalone struct so older code that
/// only uses the basic fields keeps compiling — Form picks both
/// because axum Form derives Deserialize on the whole body.

#[derive(Template)]
#[template(path = "hostings_detail.html")]
pub(super) struct DetailTpl<'a> {
    pub(super) username: &'a str,
    pub(super) user_initial: char,
    pub(super) active: &'static str,
    pub(super) css_version: &'static str,
    pub(super) htmx_version: &'static str,
    pub(super) detail: HostingDetail,
    pub(super) limits: hyperion_types::HostingLimits,
    pub(super) mem_auto: PhpMemAutoView,
    pub(super) workers_full: PhpWorkersView,
    pub(super) wp_status: Option<WpInstallStatus>,
    pub(super) expiry: hyperion_types::HostingExpiry,
    pub(super) backups: Vec<hyperion_types::BackupRunWire>,
    pub(super) stats: Option<HostingStats>,
    pub(super) csrf_delete: String,
    pub(super) csrf_suspend: String,
    pub(super) csrf_resume: String,
    pub(super) csrf_limits: String,
    pub(super) csrf_wp_install: String,
    pub(super) csrf_backup_now: String,
    pub(super) csrf_backup_cadence: String,
    /// Per-hosting recurring-backup cadence ("off"|"daily"|"weekly"|"monthly"
    /// |"custom"), read from the owning node's hosting_kv; drives the
    /// Backups-card select.
    pub(super) backup_cadence: String,
    /// The custom period in days (only meaningful for "custom"), 0 = unset.
    pub(super) backup_interval_days: i64,
    /// Local time of day the scheduled backup runs at ("HH:MM"), "" = any time.
    pub(super) backup_at: String,
    /// "Daily at 03:00", "Every 3 days", "Off — only when you click".
    pub(super) backup_schedule_label: String,
    pub(super) csrf_backup_target: String,
    /// The off-site target this hosting is pinned to (`backup_targets.name`),
    /// or "" for the node default. Owning node's hosting_kv, like the cadence.
    pub(super) backup_target: String,
    /// Every configured off-site target + why it can't take a backup, when it
    /// can't. Empty for non-admins, who get no picker at all.
    pub(super) backup_target_options: Vec<BackupTargetOption>,
    /// Label of the "no pin" option — it names how many targets would actually
    /// receive a copy, so leaving it alone isn't a guess.
    pub(super) backup_target_default_label: String,
    /// Non-empty when the pin above resolves to nothing — the site is NOT
    /// going off-site and the card has to say so.
    pub(super) backup_target_warning: String,
    /// The panel keeps snapshots only, so the schedule above is not making
    /// archives (unless a care package sells backups to the site). The mode
    /// is saved on every node, so the master's copy speaks for the owner.
    pub(super) backups_paused_by_mode: bool,
    pub(super) csrf_expiry_set: String,
    pub(super) csrf_expiry_clear: String,
    pub(super) csrf_dns_check: String,
    pub(super) csrf_cert_issue: String,
    pub(super) csrf_cert_delete: String,
    pub(super) csrf_restore: String,
    /// The backups list restores a backup whose LOCAL copy is gone from the
    /// FTP target, through the off-site card's route.
    pub(super) csrf_offsite_restore: String,
    pub(super) csrf_restore_as_new: String,
    pub(super) csrf_logs: String,
    pub(super) csrf_cron: String,
    pub(super) cron_body: String,
    pub(super) csrf_wp_reset: String,
    pub(super) csrf_db_reset: String,
    /// "Open phpMyAdmin" target — `Some` only for a MariaDB hosting whose
    /// viewer may manage databases, while the phpMyAdmin listener is on.
    pub(super) pma_url: Option<String>,
    pub(super) csrf_profile_apply: String,
    pub(super) profile_apply: Option<ProfileApply>,
    pub(super) applied_profile_name: Option<String>,
    pub(super) profiles: Vec<HostingProfile>,
    pub(super) csrf_ftp_set: String,
    pub(super) csrf_ftp_disable: String,
    pub(super) ftp_new_password: Option<String>,
    /// Names this hosting serves that the certificate on disk does NOT
    /// cover — so the browser refuses them with a name mismatch.
    ///
    /// Adding an alias re-renders `server_name` and touches nothing else, so
    /// the new name starts being served immediately over a certificate that
    /// does not carry it. Nothing said so, and the certificate card showed the
    /// alias as covered because the SAN list was filled from the alias list.
    /// Empty when everything is covered, or when there is no certificate yet.
    pub(super) cert_uncovered_names: Vec<String>,
    /// Set when the password belongs to an EXTRA login rather than the site's
    /// own account — the panel must name the right one.
    pub(super) ftp_new_login: Option<String>,
    /// What the login for a name of "deploy" would ACTUALLY be on this
    /// hosting, built by the same function that will build the real one.
    /// The form used to promise `<name>.<domain>` in prose, which stops
    /// being true the moment the domain is too long to fit in Linux's
    /// 32-character login and Hyperion has to shorten it.
    pub(super) ftp_login_example: String,
    /// The cap on the operator's half of that login, for the input's
    /// `maxlength` — so a too-long name is stopped at the keyboard rather
    /// than by a round-trip.
    pub(super) ftp_login_name_max: usize,
    /// Every qualifier a name of 1..=`ftp_login_name_max` characters could
    /// get, so the browser can show a LIVE preview by picking one and
    /// concatenating — no second copy of the composition rules in
    /// JavaScript to drift from the Rust one.
    pub(super) ftp_login_qualifiers: Vec<String>,
    /// Bare host (no scheme/port) the client should point their FTP/FTPS
    /// client at — the owning node's reachable address, resolved in
    /// [`ftp_host_for`]. Only rendered inside the "new password" block.
    pub(super) ftp_host: String,
    pub(super) error: Option<&'a str>,
    pub(super) wp_error: Option<String>,
    pub(super) wp_flash: Option<String>,
    pub(super) backup_error: Option<String>,
    pub(super) backup_flash: Option<String>,
    /// Why an off-site pin was refused (unknown target), carried back through
    /// the redirect so the operator doesn't think the change landed.
    pub(super) backup_target_error: Option<String>,
    pub(super) expiry_error: Option<String>,
    pub(super) expiry_flash: Option<String>,
    /// Lifecycle & billing → Price: outcome of a `/hostings/price/set` save.
    pub(super) price_error: Option<String>,
    pub(super) price_flash: Option<String>,
    pub(super) csrf_price_set: String,
    /// Only a user who may apply profiles may change what a site costs.
    pub(super) can_set_price: bool,
    /// The price form's amount, prefilled from the snapshot ("2400.00").
    pub(super) price_major: String,
    /// The price was set on this hosting and outlives a profile re-apply.
    pub(super) price_pinned: bool,
    /// Reverse-proxy upstream card: outcome of a `/hostings/proxy-upstream` save.
    pub(super) proxy_flash: Option<String>,
    pub(super) proxy_error: Option<String>,
    pub(super) cert_error: Option<String>,
    pub(super) cert_flash: Option<String>,
    /// The wildcard's automatic renewal over the delegated acme zone.
    pub(super) acme_ssl: crate::handlers::acme_dns_ssl::AcmeSslBlock,
    pub(super) restore_error: Option<String>,
    pub(super) restore_flash: Option<String>,
    pub(super) cron_error: Option<String>,
    pub(super) cron_flash: Option<String>,
    pub(super) db_error: Option<String>,
    pub(super) db_flash: Option<String>,
    pub(super) profile_error: Option<String>,
    pub(super) profile_flash: Option<String>,
    pub(super) ftp_error: Option<String>,
    pub(super) ftp_flash: Option<String>,
    pub(super) just_created: Option<HostingCreated>,
    /// When the post-create flow spawned a background WP install /
    /// profile-apply job, this carries the job id so the detail
    /// page can render an inline progress card that HTMX-polls
    /// `/jobs/<id>/progress`. None on the standard GET detail path.
    pub(super) wp_install_job_id: Option<String>,
    /// Drives the per-user Access tab — super_admin only.
    pub(super) is_super_admin: bool,
    /// Existing access grants for this hosting (populated for super_admin).
    pub(super) access_grants: Vec<hyperion_types::WebHostingAccess>,
    /// Users available to grant to (operator/viewer roles; super_admin
    /// and admin are excluded since they already see everything).
    pub(super) users_for_access: Vec<hyperion_types::WebUserSummary>,
    /// Per-hosting monitor config + sample history (for the Monitor tab).
    pub(super) monitor_config: hyperion_types::MonitorConfigView,
    pub(super) monitor_history: hyperion_types::MonitorHistory,
    /// WordPress plugin list — populated only when wp_status is Some.
    /// Empty otherwise; the template's WP tab shows an "install WP first"
    /// state instead of an empty table.
    pub(super) wp_plugins: hyperion_types::WpPluginListResponse,
    /// (value, label, description, checked) for the bot-family checkboxes.
    /// Built server-side so the list of families lives in ONE place — the
    /// renderer that turns them into nginx patterns.
    pub(super) bot_families: Vec<(&'static str, &'static str, &'static str, bool)>,
    /// The WAF level this site runs (`off` | `standard` | `strict`).
    pub(super) waf_level: &'static str,
    /// One row per catalogue rule that applies to this hosting's kind.
    pub(super) waf_rules: Vec<WafRuleRow>,
    /// Any rule pinned on or off — opens the rules fold so a pin is never
    /// hidden behind a level that seems to say otherwise.
    pub(super) waf_has_pins: bool,
    /// What the WAF actually does here, for the pills ("WAF standard",
    /// "WAF off", "WAF off · 2 rules pinned on").
    pub(super) waf_summary: String,
    /// At least one rule is rendered.
    pub(super) waf_on: bool,
    /// This node's ModSecurity engine; `None` when the node did not answer
    /// (an older Hyperion) — the card says so instead of guessing.
    pub(super) modsec: Option<hyperion_types::crs::ModsecStatus>,
    /// The site's Core Rule Set settings, resolved.
    pub(super) crs: CrsView,
    /// Installing a package on a node is an administrator's call.
    pub(super) can_install_modsec: bool,
    /// Whether this kind's vhost renders the Protection card at all. A
    /// reverse proxy and a redirect have their own nginx templates with no
    /// WAF, bot, country, admin-lock or sign-up rules in them.
    pub(super) protection_applies: bool,
    /// Whether `redis-cache` is present. Enabling Redis writes the wp-config
    /// constants and changes nothing observable until that plugin exists, so
    /// the card offers to install it rather than leaving the gap in prose.
    pub(super) redis_plugin_installed: bool,
    /// Per-hosting email log — the newest `SENT_MAIL_PAGE` emails the agent
    /// sent on behalf of this hosting (alerts, cert reminders, monitor
    /// down/up, billing). Older ones load on demand via
    /// `/hostings/:sel/sent-mail`.
    pub(super) email_log: Vec<hyperion_types::EmailLogEntry>,
    /// More rows exist past `email_log` — shows the "Load more" row.
    pub(super) email_log_more: bool,
    /// Last 50 outbound mails sent BY the hosted PHP site itself,
    /// captured by /usr/local/lib/hyperion/site-mail-wrapper into
    /// the per-user JSONL. Distinct from `email_log` above which
    /// is Hyperion-system mail.
    pub(super) site_emails: Vec<hyperion_types::SiteEmailLogEntry>,
    /// Every FTP-usable Linux account on the same node as this
    /// hosting. The FTP tab shows the count + a sortable list so
    /// the operator can see "I created 3 accounts" instead of
    /// trusting the silence after a successful POST.
    pub(super) ftp_accounts: Vec<hyperion_types::FtpAccountSummary>,
    /// Extra FTP logins for THIS hosting. Separate from `ftp_accounts`, which
    /// is the node-wide shadow view filtered to this site.
    pub(super) ftp_extra: Vec<hyperion_types::FtpExtraAccount>,
    pub(super) csrf_ftp_account: String,
    /// One token PER ROUTE, not one for the card. `check_csrf` verifies
    /// against `uri.path()`, so a token minted for `/hostings/ftp/account`
    /// is rejected at `/hostings/ftp/account/reset` and `/delete` — both
    /// forms shipped dead, failing every submit with "CSRF check failed"
    /// while the create form beside them worked because its path matched.
    pub(super) csrf_ftp_account_reset: String,
    pub(super) csrf_ftp_account_delete: String,
    /// Result of `ftp_verify_login` for THIS hosting's system user,
    /// done right after we know there's a password set. Lets the
    /// UI show a green "vsftpd accepts this credential" pill.
    /// None = no password set / didn't probe.
    pub(super) ftp_login_ok: Option<bool>,
    /// Session-wide CSRF token used by the newer forms that don't have
    /// dedicated csrf_* fields plumbed (access, acme-email, monitor,
    /// backup delete). Middleware accepts both.
    pub(super) csrf_token: String,
    /// Which node owns this hosting — "" (master) or the enrolled
    /// `node_id`. Per-hosting action forms render this as a hidden
    /// input so post_suspend / post_delete / post_set_limits / etc.
    /// dispatch the RPC to the correct agent. Empty string is the
    /// safe default for backwards compatibility with single-node
    /// setups.
    pub(super) target_node: String,
    /// Uploaded plugin/theme ZIPs from the master's library —
    /// drives the "Install from library" dropdown on the WP tab.
    /// Library lives on the MASTER (the master web is what
    /// operators upload to), so we always fetch via the local
    /// agent socket regardless of where this hosting lives.
    pub(super) wp_assets: Vec<hyperion_types::WpAssetSummary>,
    /// Installed WP themes for the new Themes tab. Same shape as
    /// wp_plugins above, mirrored across the wp_theme adapter.
    /// Empty when wp_status is None (no WP install).
    pub(super) wp_themes: hyperion_types::WpThemeListResponse,
    /// CSRF token for the vhost options form (basic auth, HSTS,
    /// FastCGI cache, custom snippet, maintenance mode, redirect).
    pub(super) csrf_vhost_options: String,
    /// CSRF token for the reverse-proxy upstream edit form.
    pub(super) csrf_proxy_upstream: String,
    /// Whether this viewer may write the raw nginx snippet. The server
    /// enforces it regardless; this only decides whether the textarea is
    /// shown, so a tenant is not handed a field whose every save 403s.
    pub(super) can_edit_nginx_raw: bool,
    /// Per-hosting quota report (policy + current usage + kernel
    /// enabled flag). Drives the Quota tab. Best-effort: a
    /// `QuotaGet` RPC failure on a worker node yields a default
    /// report so the tab still renders without taking the whole
    /// page down.
    pub(super) quota: hyperion_types::HostingQuotaReport,
    pub(super) csrf_quota_set: String,
    /// Set by the post handler on success — banner in the UI.
    pub(super) vhost_saved: bool,
    /// Set when set_vhost_options returned an error — banner in UI.
    pub(super) vhost_error: Option<String>,
    /// WP debug toggle form CSRF.
    /// Up to 48 hourly buckets of (disk, bw_in, bw_out, php_requests)
    /// for the Stats card sparklines. Newest last, may be shorter
    /// than 48 if the agent is freshly installed.
    pub(super) usage_buckets: Vec<hyperion_types::HostingUsageBucket>,
    pub(super) csrf_wp_debug: String,
    /// Own tokens for the two reinstall paths, so a token minted for the
    /// harmless core repair cannot be replayed against the destructive one.
    pub(super) csrf_wp_core_repair: String,
    pub(super) csrf_wp_reinstall: String,
    /// WP debug.log rotate button CSRF.
    pub(super) csrf_wp_debug_rotate: String,
    /// WP Redis enable/disable form CSRF.
    pub(super) csrf_wp_redis: String,
    /// WP Redis password rotate button CSRF.
    pub(super) csrf_wp_redis_rotate: String,
    /// Set after a successful WP debug/Redis POST — banner in UI.
    pub(super) wp_extras_flash: bool,
    /// Set when set_wp_debug / set_redis returned an error — banner.
    pub(super) wp_extras_error: Option<String>,
    /// All PHP versions Hyperion knows about — drives the "Change
    /// PHP version" dropdown on the PHP row. We pass the full set
    /// (8.1 → 8.4) and let the agent reject a version whose FPM
    /// service isn't installed; that error path is fine because
    /// the operator can install it from /services first. Owned
    /// `String` (not `&str`) so the askama template can compare
    /// directly against `v.as_str()` without a deref dance.
    pub(super) php_options: Vec<String>,
    /// Composite health snapshot + onboarding checklist. `None` on the
    /// post-create in-place render (the auto-reload lands on the full
    /// detail GET which computes it).
    pub(super) health: Option<HostingHealth>,
    /// Free-text operator note for this hosting (panel-side metadata).
    pub(super) notes: String,
    /// Operator tags (already split + cleaned) for filtering/labelling.
    pub(super) tags: Vec<String>,
    pub(super) csrf_notes: String,
    /// Effective staging hostname for this hosting — the saved per-hosting
    /// override (master hosting_kv) or the default `staging.<domain>`.
    /// Drives the staging card's input prefill, confirm text + "Open" link.
    pub(super) staging_domain: String,
    /// Whether a staging site has actually been created.
    ///
    /// `staging_domain` is a computed DEFAULT (`staging.<domain>`) when no
    /// staging site exists, so rendering "Open staging ↗" from it alone
    /// offered a link to a hostname that had never been provisioned — and a
    /// "Push staging → production" button for a source that was not there.
    /// The card now shows the create form OR the live actions, never both.
    pub(super) staging_exists: bool,
    /// Operator php.ini overrides (applied via .user.ini).
    pub(super) php_ini: PhpIniSettings,
    pub(super) csrf_php_ini: String,
    pub(super) csrf_repair_perms: String,
    /// Internal preview hostname on the owner node's `*.<base>` wildcard
    /// cert (e.g. `shop-example-com.s4.testovaciverze.cz`), or `None`
    /// when no preview applies. `Some` ⇒ the detail page shows a
    /// "Preview site" link that works before real DNS cutover. Computed
    /// with the SAME rule the agent uses to render the preview vhost, so
    /// the link always matches a server block that actually exists.
    pub(super) preview_domain: PreviewInfo,
}

impl<'a> DetailTpl<'a> {
    /// A PHP branch that will never get a fix for a known hole (8.1 for the
    /// 2026-10 RCE advisories). The template warns on the site and marks the
    /// branch in every version picker.
    pub(super) fn php_unfixable(&self, branch: &str) -> bool {
        hyperion_types::php_security::branch_unfixable(branch)
    }

    pub(super) fn php_unfixable_cves(&self, branch: &str) -> String {
        hyperion_types::php_security::unfixable_cves(branch)
    }

    /// Where a site with old code should land: the oldest version that still
    /// gets security fixes.
    pub(super) fn php_legacy_pick(&self) -> &str {
        PHP_VERSION_OPTIONS
            .iter()
            .copied()
            .find(|v| !hyperion_types::php_security::branch_unfixable(v))
            .unwrap_or("8.3")
    }

    /// The page with every CSRF token minted and every per-tab field at its
    /// "nothing known yet" value. The detail GET and the create response
    /// both start here and override only what they actually fetched, so a
    /// new field or form needs adding in one place, not two.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn base(
        state: &SharedState,
        ctx: &'a AuthCtx,
        detail: HostingDetail,
        limits: hyperion_types::HostingLimits,
        target_node: String,
        preview_domain: PreviewInfo,
        modsec: Option<hyperion_types::crs::ModsecStatus>,
        wp_assets: Vec<hyperion_types::WpAssetSummary>,
    ) -> Self {
        let csrf = |path: &str| csrf_token_for(state, ctx, path);
        let mem_auto = PhpMemAutoView::from_kv(&[], limits.php_memory_mb);
        let ftp_login_example = ftp_login_example(&detail.domain);
        let ftp_login_qualifiers = hyperion_validate::ftplogin::login_qualifiers(&detail.domain);
        let staging_domain = format!("staging.{}", detail.domain);
        let bot_families = bot_family_rows(&detail.vhost_options.blocked_bots);
        let waf_level = detail.vhost_options.effective_waf_level().as_str();
        let waf_rules = waf_rule_rows(&detail.vhost_options, detail.php_version.is_some());
        let protection_applies = protection_applies(&detail.kind);
        let crs = crs_view(&detail.vhost_options);
        DetailTpl {
            username: &ctx.username,
            user_initial: crate::handlers::user_initial(&ctx.username),
            active: "hostings",
            css_version: crate::handlers::css_version(),
            htmx_version: crate::handlers::htmx_version(),
            detail,
            limits,
            mem_auto,
            workers_full: PhpWorkersView::from_kv(&[], 0),
            wp_status: None,
            expiry: hyperion_types::HostingExpiry::defaults(),
            backups: vec![],
            stats: None,
            csrf_delete: csrf("/hostings/delete"),
            csrf_suspend: csrf("/hostings/suspend"),
            csrf_resume: csrf("/hostings/resume"),
            csrf_limits: csrf("/hostings/set-limits"),
            csrf_wp_install: csrf("/hostings/wp/install"),
            csrf_backup_now: csrf("/hostings/backup-now"),
            csrf_backup_cadence: csrf("/hostings/backup-cadence"),
            backup_cadence: "off".into(),
            backup_interval_days: 0,
            backup_at: String::new(),
            backup_schedule_label: BackupSchedule::default().label(),
            csrf_backup_target: csrf("/hostings/backup-target"),
            backup_target: String::new(),
            backup_target_options: vec![],
            backup_target_default_label: String::new(),
            backup_target_warning: String::new(),
            backups_paused_by_mode: false,
            csrf_expiry_set: csrf("/hostings/expiry/set"),
            csrf_expiry_clear: csrf("/hostings/expiry/clear"),
            csrf_dns_check: csrf("/hostings/dns-check"),
            csrf_cert_issue: csrf("/hostings/cert/issue"),
            csrf_cert_delete: csrf("/hostings/cert/delete"),
            csrf_restore: csrf("/hostings/restore"),
            csrf_offsite_restore: csrf("/hostings/offsite-restore"),
            csrf_restore_as_new: csrf("/hostings/restore-as-new"),
            csrf_logs: csrf("/hostings/logs"),
            csrf_cron: csrf("/hostings/cron"),
            cron_body: String::new(),
            csrf_wp_reset: csrf("/hostings/wp/reset-password"),
            csrf_db_reset: csrf("/hostings/db/reset-password"),
            pma_url: None,
            csrf_profile_apply: csrf("/profiles/apply"),
            profile_apply: None,
            applied_profile_name: None,
            profiles: vec![],
            csrf_ftp_set: csrf("/hostings/ftp/set"),
            csrf_ftp_disable: csrf("/hostings/ftp/disable"),
            cert_uncovered_names: Vec::new(),
            ftp_new_password: None,
            ftp_new_login: None,
            ftp_login_example,
            ftp_login_name_max: hyperion_validate::ftplogin::MAX_LOGIN_NAME_LEN,
            ftp_login_qualifiers,
            ftp_host: String::new(),
            error: None,
            wp_error: None,
            wp_flash: None,
            backup_error: None,
            backup_flash: None,
            backup_target_error: None,
            expiry_error: None,
            expiry_flash: None,
            price_error: None,
            price_flash: None,
            csrf_price_set: csrf("/hostings/price/set"),
            can_set_price: ctx.can(Capability::ProfilesManage),
            price_major: String::new(),
            price_pinned: false,
            proxy_flash: None,
            proxy_error: None,
            cert_error: None,
            cert_flash: None,
            acme_ssl: Default::default(),
            restore_error: None,
            restore_flash: None,
            cron_error: None,
            cron_flash: None,
            db_error: None,
            db_flash: None,
            profile_error: None,
            profile_flash: None,
            ftp_error: None,
            ftp_flash: None,
            just_created: None,
            wp_install_job_id: None,
            is_super_admin: ctx.is_super_admin(),
            access_grants: vec![],
            users_for_access: vec![],
            monitor_config: hyperion_types::MonitorConfigView::default(),
            monitor_history: hyperion_types::MonitorHistory::default(),
            wp_plugins: hyperion_types::WpPluginListResponse::default(),
            bot_families,
            waf_has_pins: waf_rules.iter().any(|r| !r.pin.is_empty()),
            waf_summary: waf_summary(waf_level, &waf_rules),
            waf_on: waf_rules.iter().any(|r| r.effective),
            modsec,
            crs,
            can_install_modsec: ctx.is_admin_or_higher(),
            protection_applies,
            waf_level,
            waf_rules,
            redis_plugin_installed: false,
            email_log: vec![],
            email_log_more: false,
            site_emails: vec![],
            ftp_accounts: vec![],
            ftp_extra: vec![],
            csrf_ftp_account: csrf("/hostings/ftp/account"),
            csrf_ftp_account_reset: csrf("/hostings/ftp/account/reset"),
            csrf_ftp_account_delete: csrf("/hostings/ftp/account/delete"),
            ftp_login_ok: None,
            csrf_token: crate::handlers::session_csrf_token(state, ctx),
            target_node,
            wp_assets,
            wp_themes: hyperion_types::WpThemeListResponse::default(),
            csrf_vhost_options: csrf("/hostings/vhost-options"),
            csrf_proxy_upstream: csrf("/hostings/proxy-upstream"),
            can_edit_nginx_raw: ctx.can(Capability::HostingEditNginxRaw),
            quota: hyperion_types::HostingQuotaReport::default(),
            csrf_quota_set: csrf("/hostings/quota/set"),
            vhost_saved: false,
            vhost_error: None,
            usage_buckets: vec![],
            csrf_wp_debug: csrf("/hostings/wp/debug"),
            csrf_wp_core_repair: csrf("/hostings/wp/core-repair"),
            csrf_wp_reinstall: csrf("/hostings/wp/reinstall"),
            csrf_wp_debug_rotate: csrf("/hostings/wp/debug-log/rotate"),
            csrf_wp_redis: csrf("/hostings/wp/redis"),
            csrf_wp_redis_rotate: csrf("/hostings/wp/redis/rotate"),
            wp_extras_flash: false,
            wp_extras_error: None,
            php_options: PHP_VERSION_OPTIONS.iter().map(|s| s.to_string()).collect(),
            health: None,
            notes: String::new(),
            tags: vec![],
            csrf_notes: csrf("/hostings/notes"),
            staging_domain,
            staging_exists: false,
            php_ini: PhpIniSettings::default(),
            csrf_php_ini: csrf("/hostings/php-ini"),
            csrf_repair_perms: csrf("/hostings/repair-permissions"),
            preview_domain,
        }
    }
}

/// Every PHP version the panel knows how to provision. Drives the
/// PHP-version dropdown on the hosting detail page. Lives here
/// (not in hyperion-types::PhpVersion::all()) so the UI list can
/// be reordered / filtered without touching the type definition.
pub(super) const PHP_VERSION_OPTIONS: &[&str] = &["8.1", "8.2", "8.3", "8.4"];

/// One row in the per-hosting Health card. `severity` drives the dot
/// colour: good=green, warn=amber, bad=red, info=grey.
pub struct HealthCheck {
    pub severity: &'static str,
    pub ok: bool,
    pub label: String,
    pub detail: String,
}

/// Composite "is this hosting healthy?" snapshot, computed purely from
/// data the detail page already fetches (no extra RPC). The non-green
/// rows double as an onboarding checklist for a freshly-created site.
pub struct HostingHealth {
    pub score: i64,
    pub grade: &'static str,
    pub checks: Vec<HealthCheck>,
    /// Count of checks that aren't green — drives the "N things to fix".
    pub todo: i64,
}

pub(super) fn health_grade(score: i64) -> &'static str {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

#[allow(clippy::too_many_arguments)]
/// "in 3 hours", "in 2 days" — the forward-looking twin of `fmt_ago`, which
/// only formats the past and answers "—" for anything not behind us.
///
/// A due-now or overdue interval is reported as "shortly" rather than a
/// negative: the scheduler's next tick is the honest answer, and "in -4
/// minutes" reads as a bug.
pub(super) fn fmt_in(secs: i64) -> String {
    if secs <= 60 {
        return "shortly".into();
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("in {mins} min");
    }
    let hours = mins / 60;
    if hours < 48 {
        return format!("in {hours} h");
    }
    format!("in {} days", hours / 24)
}

/// A hosting's recurring-backup schedule as the OWNING node's hosting_kv
/// holds it — the same three keys `scheduled_backups_tick` reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BackupSchedule {
    /// "off" | "daily" | "weekly" | "monthly" | "custom".
    pub cadence: String,
    /// Days between backups for "custom" (1..=365), 0 = unset.
    pub interval_days: i64,
    /// "HH:MM" local time on the owning node, "" = any time.
    pub at: String,
}

impl BackupSchedule {
    pub(crate) fn from_kv(kv: &[(String, String)]) -> Self {
        let get = |key: &str| {
            kv.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default()
        };
        let cadence = get("backup_cadence");
        Self {
            cadence: match cadence.as_str() {
                "daily" | "weekly" | "monthly" | "custom" => cadence,
                _ => "off".into(),
            },
            interval_days: get("backup_interval_days")
                .parse::<i64>()
                .ok()
                .filter(|d| (1..=BACKUP_INTERVAL_MAX_DAYS).contains(d))
                .unwrap_or(0),
            at: parse_backup_at(&get("backup_at")).unwrap_or_default(),
        }
    }

    /// Seconds between scheduled backups, `None` when nothing schedules one —
    /// including "custom" without a valid period, which the tick skips too.
    pub(crate) fn period_secs(&self) -> Option<i64> {
        match self.cadence.as_str() {
            "daily" => Some(86_400),
            "weekly" => Some(7 * 86_400),
            "monthly" => Some(30 * 86_400),
            "custom" if self.interval_days > 0 => Some(self.interval_days * 86_400),
            _ => None,
        }
    }

    pub(crate) fn label(&self) -> String {
        let base = match self.cadence.as_str() {
            "daily" => "Daily".to_string(),
            "weekly" => "Weekly".to_string(),
            "monthly" => "Monthly".to_string(),
            "custom" if self.interval_days == 1 => "Every day".to_string(),
            "custom" if self.interval_days > 0 => format!("Every {} days", self.interval_days),
            "custom" => return "Every N days — no period set, so not running".into(),
            _ => return "Off — only when you click".into(),
        };
        if self.at.is_empty() {
            base
        } else {
            format!("{base} at {}", self.at)
        }
    }
}

/// Longest custom backup period the scheduler accepts (it skips anything else).
pub(super) const BACKUP_INTERVAL_MAX_DAYS: i64 = 365;

/// Normalise a time-of-day field to "HH:MM" (24-hour), or `None` when it is
/// not one. Mirrors the agent's `parse_backup_at`; the browser's `type=time`
/// sends "HH:MM", a hand-typed "3:05" is accepted too.
pub(super) fn parse_backup_at(s: &str) -> Option<String> {
    let (h, m) = s.trim().split_once(':')?;
    if h.is_empty() || h.len() > 2 || m.len() != 2 {
        return None;
    }
    let (h, m) = (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
    (h < 24 && m < 60).then(|| format!("{h:02}:{m:02}"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_hosting_health(
    detail: &HostingDetail,
    backups: &[hyperion_types::BackupRunWire],
    monitor_enabled: bool,
    wp_installed: bool,
    wp_updates_pending: i64,
    quota: &hyperion_types::HostingQuotaReport,
    // From the OWNING node's hosting_kv.
    backup: &BackupSchedule,
    // Unix seconds of the last scheduled run, 0 for never. Reserved for the
    // overdue calculation once the tick stamps it on every path.
    _backup_last_run_at: i64,
    now: i64,
) -> HostingHealth {
    let mut checks: Vec<HealthCheck> = Vec::new();
    let mut score: i64 = 100;

    // 1. State
    let active = detail.state == hyperion_types::HostingState::Active;
    checks.push(HealthCheck {
        severity: if active { "good" } else { "bad" },
        ok: active,
        label: "Hosting active".into(),
        detail: if active {
            "Serving normally.".into()
        } else {
            format!("State is {}.", detail.state.as_str())
        },
    });
    if !active {
        score -= 40;
    }

    // 2. Trusted TLS
    let trusted = detail
        .cert
        .as_ref()
        .map(|c| c.issuer != "self-signed")
        .unwrap_or(false);
    checks.push(HealthCheck {
        severity: if trusted { "good" } else { "warn" },
        ok: trusted,
        label: "Trusted HTTPS certificate".into(),
        detail: if trusted {
            "A trusted cert is active.".into()
        } else {
            "Self-signed / none — issue a Let's Encrypt cert from the SSL tab.".into()
        },
    });
    if !trusted {
        score -= 20;
    }

    // 3. Recent backup
    // `mark_ok` writes state='ok'. This filtered on "done" — a string
    // nothing ever writes — so the health card reported "No successful
    // backup yet" forever, however many backups had succeeded, and docked
    // 15 points off the score for it. The dashboard alert
    // (service/dashboard.rs) had the comparison right, which is why the two
    // disagreed.
    let last_ok = backups
        .iter()
        .filter(|b| b.state == "ok")
        .filter_map(|b| b.finished_at)
        .max();
    // Scheduled backups are the answer to "is this site protected?", not
    // whether one has happened yet. A hosting created ten minutes ago has no
    // backup and cannot have one — reporting that as a PROBLEM told the
    // operator to go and fix something that was already arranged, and docked
    // the score for it on every freshly created site. What matters is whether
    // a cadence is set; the absence of one is the real problem, at any age.
    let cadence_secs = backup.period_secs();
    let backup_cadence = backup.label();
    let backup_ok = match (cadence_secs, last_ok) {
        // Scheduled and recent enough: fine.
        (Some(c), Some(t)) => now - t < c + 86_400,
        // Scheduled, none yet: fine — it is arranged, and the tick treats
        // "never" as due, so the first one is imminent.
        (Some(_), None) => true,
        // No schedule. A recent manual backup still counts, but nothing is
        // keeping it that way.
        (None, Some(t)) => now - t < 7 * 86400,
        (None, None) => false,
    };
    let next_due = cadence_secs.map(|c| last_ok.map(|t| t + c).unwrap_or(now));
    checks.push(HealthCheck {
        severity: if backup_ok { "good" } else { "warn" },
        ok: backup_ok,
        label: "Recent backup".into(),
        detail: match (cadence_secs, last_ok, next_due) {
            (Some(_), None, _) if backup.at.is_empty() => format!(
                "Automatic backups are on ({backup_cadence}) — the first one runs at the next check."
            ),
            (Some(_), None, _) => format!(
                "Automatic backups are on ({backup_cadence}) — the first one runs at {}.",
                backup.at
            ),
            // With a set time the next run lands on that time, not exactly
            // one period after the last — say the time rather than a
            // countdown that would be off by hours.
            (Some(_), Some(t), Some(_)) if backup_ok && !backup.at.is_empty() => format!(
                "Automatic backups are on ({backup_cadence}). Last {}.",
                crate::handlers::stats::fmt_ago(&t)
            ),
            (Some(_), Some(t), Some(next)) if backup_ok => format!(
                "Automatic backups are on ({backup_cadence}). Last {}, next {}.",
                crate::handlers::stats::fmt_ago(&t),
                fmt_in(next - now)
            ),
            (Some(_), Some(t), _) => format!(
                "Automatic backups are on ({backup_cadence}), but the last one was {} — overdue.",
                crate::handlers::stats::fmt_ago(&t)
            ),
            (None, Some(t), _) if backup_ok => format!(
                "Last backup {} — but no schedule is set, so nothing keeps it current.",
                crate::handlers::stats::fmt_ago(&t)
            ),
            (None, Some(t), _) => format!(
                "Last backup {} and no schedule is set.",
                crate::handlers::stats::fmt_ago(&t)
            ),
            (None, None, _) => {
                "No backups and no schedule — turn one on from the Backups tab.".into()
            }
        },
    });
    if !backup_ok {
        score -= 15;
    }

    // 4. Uptime monitoring
    checks.push(HealthCheck {
        severity: if monitor_enabled { "good" } else { "info" },
        ok: monitor_enabled,
        label: "Uptime monitoring".into(),
        detail: if monitor_enabled {
            "Enabled.".into()
        } else {
            "Off — turn it on in the Monitor tab.".into()
        },
    });
    if !monitor_enabled {
        score -= 5;
    }

    // 5. WordPress up to date (only when WP is installed)
    if wp_installed {
        let current = wp_updates_pending == 0;
        checks.push(HealthCheck {
            severity: if current { "good" } else { "warn" },
            ok: current,
            label: "WordPress up to date".into(),
            detail: if current {
                "All plugins current.".into()
            } else {
                format!("{wp_updates_pending} plugin update(s) pending.")
            },
        });
        if !current {
            score -= 10;
        }
    }

    // 6. Disk headroom (only when quotas are actually enforced)
    if quota.quotas_enabled_on_fs && quota.policy.disk_hard_kib > 0 {
        let pct =
            ((quota.current_disk_kib as f64 / quota.policy.disk_hard_kib as f64) * 100.0) as i64;
        let (sev, ok, penalty) = if pct >= 90 {
            ("bad", false, 15)
        } else if pct >= 75 {
            ("warn", false, 5)
        } else {
            ("good", true, 0)
        };
        checks.push(HealthCheck {
            severity: sev,
            ok,
            label: "Disk headroom".into(),
            detail: format!("{pct}% of the disk quota used."),
        });
        score -= penalty;
    }

    let score = score.clamp(0, 100);
    let todo = checks.iter().filter(|c| !c.ok).count() as i64;
    HostingHealth {
        score,
        grade: health_grade(score),
        checks,
        todo,
    }
}

/// The automatic PHP memory_limit, as the OWNING node stores it
/// (`hyperion_types::phpmem`).
pub struct PhpMemAutoView {
    pub enabled: bool,
    /// The most the automation may set, in MiB.
    pub max_mb: i64,
    /// The operator's own limit, when the automation currently has the pool
    /// above it.
    pub raised_from_mb: Option<i64>,
    /// Last out-of-memory fatal seen; 0 = none since it was turned on.
    pub last_oom_at: i64,
    /// The operator's own limit — what the ceiling must be above.
    pub floor_mb: i64,
}

impl PhpMemAutoView {
    pub(super) fn from_kv(pairs: &[(String, String)], current_mb: i64) -> Self {
        use hyperion_types::phpmem;
        let get = |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        let st = get(phpmem::KV_STATE).and_then(phpmem::State::parse);
        let raised_from_mb = st
            .as_ref()
            .map(|s| s.base_mb)
            .filter(|&b| b > 0 && b < current_mb);
        PhpMemAutoView {
            enabled: get(phpmem::KV_ENABLED) == Some("on"),
            max_mb: get(phpmem::KV_MAX_MB)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(phpmem::DEFAULT_MAX_MB),
            raised_from_mb,
            last_oom_at: st.map(|s| s.last_oom_at).unwrap_or(0),
            floor_mb: raised_from_mb.unwrap_or(current_mb),
        }
    }

    /// Switched on with a ceiling that leaves nothing to raise to.
    pub fn no_room(&self) -> bool {
        self.enabled && hyperion_types::phpmem::ceiling_leaves_no_room(self.max_mb, self.floor_mb)
    }
}

/// "The pool ran out of PHP workers", as the OWNING node records it
/// (`hyperion_types::phpworkers`).
pub struct PhpWorkersView {
    /// Times today (UTC) every worker was busy.
    pub today: i64,
    /// Last time; 0 = never seen.
    pub last_at: i64,
}

impl PhpWorkersView {
    pub(super) fn from_kv(pairs: &[(String, String)], now: i64) -> Self {
        use hyperion_types::phpworkers;
        let st = pairs
            .iter()
            .find(|(k, _)| k == phpworkers::KV_STATE)
            .and_then(|(_, v)| phpworkers::State::parse(v))
            .unwrap_or_default();
        PhpWorkersView {
            today: st.hits_today(now),
            last_at: st.last_at,
        }
    }
}

/// Operator-tunable php.ini settings, applied via a per-hosting
/// `.user.ini` in htdocs (PHP_INI_PERDIR — no FPM pool change, so a bad
/// value can never stop the pool from starting). Empty string = leave
/// the pool/global default. Values are validated before they're written.
#[derive(Default)]
pub struct PhpIniSettings {
    pub memory_limit: String,
    pub upload_max_filesize: String,
    pub post_max_size: String,
    pub max_execution_time: String,
    pub max_input_vars: String,
    pub display_errors: String,
}

impl PhpIniSettings {
    /// Build from a hosting's KV map (keys prefixed `php.`).
    pub(super) fn from_kv(pairs: &[(String, String)]) -> Self {
        let get = |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        PhpIniSettings {
            memory_limit: get("php.memory_limit"),
            upload_max_filesize: get("php.upload_max_filesize"),
            post_max_size: get("php.post_max_size"),
            max_execution_time: get("php.max_execution_time"),
            max_input_vars: get("php.max_input_vars"),
            display_errors: get("php.display_errors"),
        }
    }

    /// True when at least one override is set (drives "managed by
    /// Hyperion" note in the UI).
    pub fn any(&self) -> bool {
        !(self.memory_limit.is_empty()
            && self.upload_max_filesize.is_empty()
            && self.post_max_size.is_empty()
            && self.max_execution_time.is_empty()
            && self.max_input_vars.is_empty()
            && self.display_errors.is_empty())
    }
}

/// Bare host (no scheme/port) an FTP/FTPS client should connect to for a
/// hosting owned by `owner_node`.
///
/// * Master-local hosting (`owner_node` None) → the host the operator
///   reached the panel on, which on a single-node box IS the FTP host.
/// * Worker hosting (`Some(node_id)`) → that worker's public address
///   (its enrollment `label`, then the panel host, as fallbacks) —
///   FTP connects straight to the owning box, never the master.
pub(super) async fn ftp_host_for(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
    owner_node: Option<&str>,
) -> String {
    if let Some(nid) = owner_node {
        if let Ok(RpcResponse::NodesList(nodes)) = crate::dispatcher::cached_nodes(state)
            .await
            .map(hyperion_rpc::codec::Response::NodesList)
        {
            if let Some(n) = nodes.iter().find(|n| n.node_id == nid) {
                // The node's PUBLIC address — not `public_ip` as such, which
                // holds the private RPC address on a node that advertises
                // one and would hand customers an unreachable FTP host.
                if let Some(ip) = n.customer_host() {
                    return ip.to_string();
                }
                if !n.label.is_empty() {
                    return n.label.clone();
                }
            }
        }
    }
    crate::handlers::panel_host(headers).await
}

pub async fn get_detail(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<DetailQuery>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    // Multi-node detail lookup: try master first, then fan out across
    // enrolled workers. Returns the detail PLUS the node id where it
    // was found so every subsequent per-hosting RPC on this page
    // (limits, stats, backups, …) goes to the SAME node. Without
    // this, the detail page would show 404 for any hosting that
    // lives on a worker.
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    let target = owner_node.as_deref();
    // Reachable FTP host for THIS hosting's node — a worker's own address,
    // not the master's (FTP talks straight to the owning box).
    let ftp_host = ftp_host_for(&state, &headers, target).await;
    // phpMyAdmin is MariaDB-only; the click is re-authorised on every
    // request, this only decides whether to offer it.
    let pma_url = match &detail.database {
        Some(db)
            if db.engine == hyperion_types::DbProvision::MariaDB
                && ctx.can(Capability::HostingDatabases) =>
        {
            let host = crate::handlers::panel_host(&headers).await;
            crate::handlers::pma::pma_url(&state, &host, detail.id.as_str())
        }
        _ => None,
    };
    // RBAC guard: operator + viewer must have an access grant.
    // super_admin + admin pass through. Unauthenticated redirects to
    // /login earlier (require_auth middleware), so unwrap to /hostings
    // for the no-access case.
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    {
        return Ok(r);
    }
    let sel_id = HostingSelector::Id(detail.id.clone());

    // === Parallel RPC fan-out ===
    // The hosting detail page used to do ~12 serial RPCs (limits,
    // wp_status, plugins, themes, expiry, backups, stats, cron,
    // profile_apply, profiles, spf, monitor, email_log). On a
    // multi-node setup with 100ms+ per RPC that added up to >1s
    // of page-render latency. tokio::join! buckets them so the
    // whole page is bounded by the SLOWEST single RPC.
    //
    // wp_plugins + wp_themes still depend on wp_status (only
    // probe wp-cli if WP is installed). We get wp_status in the
    // first wave + conditionally fire plugins/themes in a tiny
    // second wave.
    let (
        limits_res,
        wp_status_res,
        expiry_res,
        backups_res,
        stats_res,
        cron_res,
        profile_apply_res,
        profiles_res,
        usage_buckets,
    ) = tokio::join!(
        fetch_limits(&state, target, sel_id.clone()),
        fetch_wp_status(&state, target, sel_id.clone()),
        fetch_expiry(&state, target, sel_id.clone()),
        fetch_backup_list(&state, target, sel_id.clone(), 10),
        fetch_stats(&state, target, sel_id.clone()),
        fetch_cron(&state, target, sel_id.clone()),
        fetch_profile_apply(&state, target, sel_id.clone()),
        fetch_all_profiles(&state),
        fetch_usage_buckets(&state, target, &sel_id),
    );
    let limits = limits_res.unwrap_or_else(|_| hyperion_types::HostingLimits::defaults());
    let wp_status = wp_status_res.unwrap_or(None);
    let expiry = expiry_res.unwrap_or_else(|_| hyperion_types::HostingExpiry::defaults());
    let backups = backups_res.unwrap_or_default();
    let stats = stats_res.ok();
    let cron_body = cron_res.unwrap_or_default();
    let profile_apply = profile_apply_res.unwrap_or(None);
    let profiles = profiles_res.unwrap_or_default();

    // Wave 2 — WP plugins/themes only when WP is installed (wave 1
    // already told us), plus every other independent read.
    //
    // NOTE: the passive DNS preflight banner and the SPF card are
    // NOT part of this join. Both shell out to dig/curl on the agent
    // (up to ~8s worst case on broken DNS), which used to gate the
    // whole page render. They load lazily over HTMX via
    // /hostings/:sel/dns-panel and /hostings/:sel/spf-panel.
    let hosting_id = detail.id.as_str();
    let wp_lists_fut = async {
        if wp_status.is_none() {
            crate::wp_list_cache::WpLists::default()
        } else {
            cached_wp_lists(&state, target, &sel_id, hosting_id).await
        }
    };
    let (
        (
            wp_lists,
            (monitor_config, monitor_history),
            mut email_log,
            site_emails,
            ftp_accounts,
            quota,
        ),
        (
            (access_grants_for_detail, users_for_access_for_detail),
            owner_kv,
            kv_pairs,
            targets,
            preview_domain,
            ftp_extra,
            cluster_cfg,
            wp_assets,
            modsec,
        ),
    ) = tokio::join!(
        async {
            tokio::join!(
                wp_lists_fut,
                fetch_monitor(&state, target, &sel_id),
                fetch_hosting_email_log(&state, target, hosting_id),
                fetch_site_emails(&state, target, &detail.system_user),
                fetch_node_ftp_accounts(&state, target),
                fetch_quota(&state, target, &sel_id),
            )
        },
        async {
            tokio::join!(
                fetch_access_tab(&state, &ctx, hosting_id),
                fetch_kv(&state, target, hosting_id),
                // Operator notes + tags (panel-side metadata on the master's
                // hosting_kv, keyed by ULID — same regardless of which node
                // hosts the site).
                fetch_kv(&state, None, hosting_id),
                // Off-site target list: admin-only (see the picker below).
                async {
                    if ctx.is_admin_or_higher() {
                        configured_backup_targets(&state).await
                    } else {
                        None
                    }
                },
                // Internal preview URL on the owner node's wildcard cert
                // (shown only when the node actually has one + the domain
                // isn't already under it).
                compute_preview_domain(&state, target, &detail.domain),
                fetch_ftp_extra(&state, target, &sel),
                fetch_cluster_config(&state),
                fetch_wp_assets(&state),
                fetch_modsec_status(&state, target),
            )
        },
    );
    let crate::wp_list_cache::WpLists {
        plugins: wp_plugins,
        themes: wp_themes,
    } = wp_lists;
    // If THIS hosting's user has a password, probe vsftpd to
    // verify it actually accepts the credential. We don't know
    // the password (it's only ever shown once), so we can only
    // check "user is in shadow". Login probe is left to the
    // operator via a dedicated button in the UI.
    let ftp_login_ok: Option<bool> = ftp_accounts
        .iter()
        .find(|a| a.user == detail.system_user)
        // Only a real password counts as "FTP works". Locked (which is what
        // suspending does) and empty are both "no usable login", and the
        // button that reads this says "Change the password" vs "Set a
        // password".
        .map(|a| a.password_state == "set");

    let applied_profile_name = profile_apply
        .as_ref()
        .and_then(|a| a.profile_id)
        .and_then(|pid| {
            profiles
                .iter()
                .find(|p| p.id == pid)
                .map(|p| p.name.clone())
        });
    let mem_auto = PhpMemAutoView::from_kv(&owner_kv, limits.php_memory_mb);
    let workers_full = PhpWorkersView::from_kv(&owner_kv, hyperion_types::now_secs());
    let backup_schedule = BackupSchedule::from_kv(&owner_kv);
    // Last successful backup, as the OWNING node recorded it. Needed by the
    // health check below, which is why this is fetched here and not with the
    // rest of the backup UI further down.
    let backup_last_run_at: i64 = kv_get(&owner_kv, "backup_last_run_at")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // Composite health snapshot — computed from data already fetched
    // above (no extra RPC). Borrows `detail` before it's moved into the
    // template below.
    let hosting_health = compute_hosting_health(
        &detail,
        &backups,
        monitor_config.enabled,
        wp_status.is_some(),
        wp_plugins.updates_pending,
        &quota,
        &backup_schedule,
        backup_last_run_at,
        hyperion_types::now_secs(),
    );
    // Operator notes + tags (panel-side metadata on the master's
    // hosting_kv, keyed by ULID — same regardless of which node hosts
    // the site).
    let notes = kv_get(&kv_pairs, "notes").unwrap_or_default().to_string();
    let tags: Vec<String> = kv_get(&kv_pairs, "tags")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    // Effective staging hostname: saved per-hosting override or default.
    // Its presence is the record of a staging create having run.
    let saved_staging = kv_get(&kv_pairs, "staging_domain")
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let staging_exists = saved_staging.is_some();
    let staging_domain = saved_staging
        .map(str::to_string)
        .unwrap_or_else(|| format!("staging.{}", detail.domain));
    // Recurring-backup cadence and the off-site pin live in the OWNING node's
    // hosting_kv (seeded by profile_apply there + overridable here), so read
    // them from the owner rather than the master kv_pairs above.
    let picker = BackupTargetPicker::new(targets, kv_get(&owner_kv, "backup_target"));
    let (ftp_new_login, ftp_new_password) =
        take_ftp_handoff(&state, q.ftp_pw_token.as_deref()).await;
    // The RPC returns the NODE-WIDE list; this page shows ONE hosting, so it
    // is filtered to that hosting for everyone.
    //
    // Scoping it by role was the wrong cut: an admin looking at one site does
    // not want a table of every other site either, and for a tenant the
    // node-wide version leaked the domains and Linux usernames of everyone
    // else on the box. A per-hosting page answers a question about that
    // hosting. The node-wide view belongs on a node page, not here.
    let ftp_accounts: Vec<_> = ftp_accounts
        .into_iter()
        .filter(|a| a.user == detail.system_user)
        .collect();

    // Every name nginx serves for this hosting, checked against what the
    // certificate actually carries. Wildcards are matched with the SAME rule
    // the certificate validator uses, so a `*.example.cz` cert is not reported
    // as missing `www.example.cz`.
    let cert_uncovered_names: Vec<String> = match detail.cert.as_ref() {
        Some(cert) => hyperion_validate::uncovered_names(
            &cert.sans,
            std::iter::once(detail.domain.as_str())
                .chain(detail.aliases.iter().map(String::as_str)),
        ),
        // No certificate at all: the SSL card already says so, and adding a
        // second alarm for one fact helps nobody.
        None => Vec::new(),
    };
    // Same "199.00" shape the profile form prefills with.
    let price_major = profile_apply
        .as_ref()
        .and_then(|a| a.price_minor)
        .map(|m| format!("{:.2}", m as f64 / 100.0))
        .unwrap_or_default();
    let price_pinned = profile_apply.as_ref().is_some_and(|a| a.price_pinned);
    // Cloned, not removed. A credential hand-off is single-use for a
    // reason; a diagnostic is not — taking it would mean a page reload
    // (or the back button) silently loses the only copy of the error the
    // operator is still reading. The 300 s TTL in `stash_error` reclaims
    // it instead.
    let wp_error = match q.wp_error_ref.as_deref() {
        Some(t) if !t.is_empty() => state
            .error_handoff
            .lock()
            .await
            .get(t)
            .map(|(m, _)| m.clone())
            .or(q.wp_error),
        _ => q.wp_error,
    };
    let acme_ssl = crate::handlers::acme_dns_ssl::load_for_hosting(
        &state,
        &ctx,
        &detail,
        owner_node.as_deref(),
    )
    .await;
    let base = DetailTpl::base(
        &state,
        &ctx,
        detail,
        limits,
        owner_node.clone().unwrap_or_default(),
        preview_domain,
        modsec,
        wp_assets.unwrap_or_default(),
    );
    let tpl = DetailTpl {
        acme_ssl,
        mem_auto,
        workers_full,
        wp_status,
        expiry,
        backups,
        stats,
        cron_body,
        pma_url,
        backup_schedule_label: backup_schedule.label(),
        backup_cadence: backup_schedule.cadence,
        backup_interval_days: backup_schedule.interval_days,
        backup_at: backup_schedule.at,
        backup_target: picker.pin,
        backup_target_options: picker.options,
        backup_target_default_label: picker.default_label,
        backup_target_warning: picker.warning,
        backups_paused_by_mode: cluster_cfg.protection_mode == "snapshots",
        profile_apply,
        applied_profile_name,
        profiles,
        cert_uncovered_names,
        ftp_new_password,
        ftp_new_login,
        ftp_host,
        wp_error,
        wp_flash: q.wp.map(|s| {
            if s == "reset" {
                "WordPress admin password reset.".to_string()
            } else {
                "WordPress install succeeded.".into()
            }
        }),
        backup_error: q.backup_error,
        // A bulk delete redirects back with a free-text summary; a "backup
        // started" flash is the other producer. Both render escaped.
        backup_flash: q
            .backup_deleted
            .clone()
            .or_else(|| q.backup.map(|_| "Backup started — see list below.".into())),
        backup_target_error: q.backup_target_error,
        expiry_error: q.expiry_error,
        expiry_flash: q.expiry.map(|s| {
            if s == "cleared" {
                "Expiry cleared.".to_string()
            } else {
                "Expiry updated.".to_string()
            }
        }),
        price_error: q.price_error,
        price_flash: q.price.map(|_| "Price updated.".to_string()),
        price_major,
        price_pinned,
        proxy_flash: q.proxy_saved.map(|_| "Upstream updated.".to_string()),
        proxy_error: q.proxy_error,
        cert_error: q.cert_error,
        cert_flash: q.cert.map(|s| match s.as_str() {
            "staging" => "Staging certificate issued — issuer 'letsencrypt-staging'.".into(),
            "custom" => "Custom certificate uploaded — auto-renewal disabled for it.".into(),
            "wildcard" => "Wildcard certificate issued.".into(),
            _ => "Production HTTPS certificate issued.".into(),
        }),
        restore_error: q.restore_error,
        restore_flash: q.restore.map(|_| "Backup restored.".into()),
        cron_error: q.cron_error,
        cron_flash: q.cron.map(|_| "Crontab saved.".into()),
        db_error: q.db_error,
        db_flash: q.db.map(|_| "Database password reset.".into()),
        profile_error: q.profile_error,
        profile_flash: q.profile.map(|_| "Profile applied.".into()),
        ftp_error: q.ftp_error,
        ftp_flash: q.ftp.map(|s| {
            if s == "disabled" {
                "FTP disabled — password cleared.".into()
            } else {
                "FTP password set.".into()
            }
        }),
        wp_install_job_id: q.wpjob.filter(|s| !s.trim().is_empty()),
        access_grants: access_grants_for_detail,
        users_for_access: users_for_access_for_detail,
        monitor_config,
        monitor_history,
        // `wp plugin list` reports the folder slug; redis-cache is the
        // wordpress.org slug and the folder name both.
        redis_plugin_installed: wp_plugins.plugins.iter().any(|p| p.slug == "redis-cache"),
        wp_plugins,
        email_log_more: {
            let more = email_log.len() > SENT_MAIL_PAGE;
            email_log.truncate(SENT_MAIL_PAGE);
            more
        },
        email_log,
        site_emails,
        ftp_accounts,
        ftp_extra,
        ftp_login_ok,
        wp_themes,
        quota,
        vhost_saved: q.vhost_saved.as_deref() == Some("1"),
        vhost_error: q.vhost_error,
        usage_buckets,
        wp_extras_flash: q.wp_extras_saved.as_deref() == Some("1"),
        wp_extras_error: q.wp_extras_error,
        health: Some(hosting_health),
        notes,
        tags,
        staging_exists,
        staging_domain,
        php_ini: PhpIniSettings::from_kv(&kv_pairs),
        ..base
    };
    Ok(Html(tpl.render()?).into_response())
}

/// The off-site destination picker on the Backups tab.
#[derive(Default)]
pub(super) struct BackupTargetPicker {
    pin: String,
    options: Vec<BackupTargetOption>,
    default_label: String,
    warning: String,
}

impl BackupTargetPicker {
    /// `targets` is `None` for non-admins and when the list can't be read:
    /// the picker then disappears entirely, because pairing a live pin with
    /// an empty list would report a working target as unconfigured. `pin`
    /// is the owning node's `backup_target` (absent = the node default).
    pub(super) fn new(targets: Option<Vec<BackupTargetOption>>, pin: Option<&str>) -> Self {
        let Some(mut options) = targets else {
            return Self::default();
        };
        let pin = pin.unwrap_or_default().trim().to_string();
        let warning = pinned_target_warning(&pin, &options);
        // Say what leaving the picker alone actually does. "Every enabled
        // target" reads like a promise when the answer is sometimes none.
        let default_label = match options.iter().filter(|o| o.unusable.is_empty()).count() {
            0 => "Node default — no target can take a copy, local disk only".to_string(),
            1 => "Node default — the one enabled target".to_string(),
            n => format!("Node default — all {n} enabled targets"),
        };
        // A pin that matches nothing still has to appear in the select —
        // otherwise the picker would read "Node default" for a site whose
        // backups are in fact going nowhere.
        if !pin.is_empty() && !options.iter().any(|o| o.name == pin) {
            options.push(BackupTargetOption {
                name: pin.clone(),
                unusable: "not one of the configured off-site targets".into(),
            });
        }
        Self {
            pin,
            options,
            default_label,
            warning,
        }
    }
}

/// TAKE the one-shot FTP password, so a reload, a shared link or a
/// back-button press cannot show it a second time. Removing it here is the
/// whole point of the hand-off: the credential exists in memory for exactly
/// one render.
///
/// The hand-off carries "login\npassword" for an extra FTP account, and a
/// bare password for the site's own. Returns `(login, password)`, so the
/// panel always knows which login it is showing.
async fn take_ftp_handoff(
    state: &SharedState,
    token: Option<&str>,
) -> (Option<String>, Option<String>) {
    let handoff = match token {
        Some(t) if !t.is_empty() => state
            .ftp_password_handoff
            .lock()
            .await
            .remove(t)
            .map(|(v, _)| v),
        _ => None,
    };
    match handoff {
        Some(v) => match v.split_once('\n') {
            Some((login, pw)) => (Some(login.to_string()), Some(pw.to_string())),
            None => (None, Some(v)),
        },
        None => (None, None),
    }
}

/// The usage sparkline's buckets, newest 48.
async fn fetch_usage_buckets(
    state: &SharedState,
    target: Option<&str>,
    sel: &HostingSelector,
) -> Vec<hyperion_types::HostingUsageBucket> {
    match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::HostingUsage {
            sel: sel.clone(),
            limit: 48,
        },
    )
    .await
    {
        Ok(RpcResponse::HostingUsage(rows)) => rows,
        _ => vec![],
    }
}

/// Plugin + theme lists: two wp-cli runs, each a full WordPress bootstrap
/// on the owning node — the slowest thing on the detail page by far. Served
/// from the stale-while-revalidate cache (see crate::wp_list_cache): fresh
/// answers as is, older ones immediately with a refresh in the background,
/// missing ones inline.
async fn cached_wp_lists(
    state: &SharedState,
    target: Option<&str>,
    sel_id: &HostingSelector,
    hosting_id: &str,
) -> crate::wp_list_cache::WpLists {
    let hid = hosting_id.to_string();
    match state.wp_lists.lookup(&hid) {
        crate::wp_list_cache::Lookup::Fresh(l) => (*l).clone(),
        crate::wp_list_cache::Lookup::Stale(l) => {
            if state.wp_lists.begin_refresh(&hid) {
                let state2 = state.clone();
                let target2 = target.map(str::to_string);
                let sel2 = sel_id.clone();
                tokio::spawn(async move {
                    let gen = state2.wp_lists.generation();
                    let fresh = fetch_wp_lists(&state2, target2.as_deref(), &sel2).await;
                    state2.wp_lists.store(&hid, fresh, gen);
                });
            }
            (*l).clone()
        }
        crate::wp_list_cache::Lookup::Miss => {
            // One inline fetch per hosting: a render that queued behind
            // another one's fetch takes its answer instead of
            // bootstrapping WordPress twice more.
            let lock = state.wp_lists.fetch_lock(&hid);
            let _fetching = lock.lock().await;
            if let crate::wp_list_cache::Lookup::Fresh(l) = state.wp_lists.lookup(&hid) {
                return (*l).clone();
            }
            let gen = state.wp_lists.generation();
            let fresh = fetch_wp_lists(state, target, sel_id).await;
            state.wp_lists.store(&hid, fresh.clone(), gen);
            fresh
        }
    }
}

/// Monitor config/history live on the OWNING node (post_monitor_set writes
/// there) — read from the same node, not the master local socket, or a
/// worker-hosted site's Monitor tab always shows "disabled / no history"
/// even after the operator enabled it.
async fn fetch_monitor(
    state: &SharedState,
    target: Option<&str>,
    sel: &HostingSelector,
) -> (
    hyperion_types::MonitorConfigView,
    hyperion_types::MonitorHistory,
) {
    match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::MonitorGet { sel: sel.clone() },
    )
    .await
    {
        Ok(RpcResponse::MonitorGet { config, history }) => (config, history),
        _ => Default::default(),
    }
}

/// Per-hosting Hyperion mail log, on the owning node — one row past the page,
/// whose presence is what says "there is more".
async fn fetch_hosting_email_log(
    state: &SharedState,
    target: Option<&str>,
    hosting_id: &str,
) -> Vec<hyperion_types::EmailLogEntry> {
    match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::EmailLogList {
            hosting_id: Some(hosting_id.to_string()),
            limit: SENT_MAIL_PAGE as i64 + 1,
        },
    )
    .await
    {
        Ok(RpcResponse::EmailLogList(r)) => r,
        _ => vec![],
    }
}

/// Site-outbound mail — captured by the wrapper on the agent where the
/// hosting lives.
async fn fetch_site_emails(
    state: &SharedState,
    target: Option<&str>,
    system_user: &str,
) -> Vec<hyperion_types::SiteEmailLogEntry> {
    match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::SiteEmailLogList {
            system_user: system_user.to_string(),
            limit: 50,
        },
    )
    .await
    {
        Ok(RpcResponse::SiteEmailLogList(r)) => r,
        _ => vec![],
    }
}

/// Every FTP account on the owning node (shadow read + one SQL join), each
/// tagged with that node. The caller narrows it to one hosting.
async fn fetch_node_ftp_accounts(
    state: &SharedState,
    target: Option<&str>,
) -> Vec<hyperion_types::FtpAccountSummary> {
    match crate::dispatcher::dispatch_to_node(state, target, Request::FtpAccountsList).await {
        Ok(RpcResponse::FtpAccountsList(mut rows)) => {
            for r in &mut rows {
                r.node_id = target.unwrap_or("").to_string();
            }
            rows
        }
        _ => Vec::new(),
    }
}

async fn fetch_quota(
    state: &SharedState,
    target: Option<&str>,
    sel: &HostingSelector,
) -> hyperion_types::HostingQuotaReport {
    match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::QuotaGet {
            hosting: sel.clone(),
        },
    )
    .await
    {
        Ok(RpcResponse::QuotaGet(r)) => r,
        _ => hyperion_types::HostingQuotaReport::default(),
    }
}

/// Access tab data — fetched only for super_admin since they're the only
/// ones who see the tab. Empty for everyone else is cheap and keeps the
/// template happy.
async fn fetch_access_tab(
    state: &SharedState,
    ctx: &AuthCtx,
    hosting_id: &str,
) -> (
    Vec<hyperion_types::WebHostingAccess>,
    Vec<hyperion_types::WebUserSummary>,
) {
    if !ctx.is_super_admin() {
        return (vec![], vec![]);
    }
    let grants = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebListHostingAccess {
            hosting_id: hosting_id.to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::WebListHostingAccess(g)) => g,
        _ => vec![],
    };
    let users = match hyperion_rpc_client::call(&state.agent_socket, Request::WebUserList).await {
        Ok(RpcResponse::WebUserList(u)) => u
            .into_iter()
            // Only operators + viewers can be granted per-web access;
            // super_admin and admin already see everything.
            .filter(|u| u.role == "operator" || u.role == "viewer")
            .collect(),
        _ => vec![],
    };
    (grants, users)
}

/// One hosting's hosting_kv on `target` (`None` = the master's own copy).
async fn fetch_kv(
    state: &SharedState,
    target: Option<&str>,
    hosting_id: &str,
) -> Vec<(String, String)> {
    let req = Request::HostingKvList {
        hosting_id: hosting_id.to_string(),
    };
    let resp = match target {
        Some(_) => crate::dispatcher::dispatch_to_node(state, target, req)
            .await
            .ok(),
        None => hyperion_rpc_client::call(&state.agent_socket, req)
            .await
            .ok(),
    };
    match resp {
        Some(RpcResponse::HostingKvList(v)) => v,
        _ => vec![],
    }
}

/// Extra FTP logins for this hosting. Best-effort: a node that cannot
/// answer must not take the whole detail page down, and an empty list
/// renders as "no extra logins" rather than a broken card.
async fn fetch_ftp_extra(
    state: &SharedState,
    target: Option<&str>,
    sel: &HostingSelector,
) -> Vec<hyperion_types::FtpExtraAccount> {
    match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::FtpAccountList { sel: sel.clone() },
    )
    .await
    {
        Ok(RpcResponse::FtpAccountList(v)) => v,
        _ => Vec::new(),
    }
}

/// `wp plugin list` + `wp theme list` on the owning node, concurrently.
/// Failures come back as `error: Some(..)` rather than empty lists — an
/// empty table reads as "no plugins installed", which is a lie when wp-cli
/// could not bootstrap WordPress at all (DB down, PHP fatal, permissions).
pub(super) async fn fetch_wp_lists(
    state: &SharedState,
    target: Option<&str>,
    sel_id: &HostingSelector,
) -> crate::wp_list_cache::WpLists {
    let plugins = async {
        match crate::dispatcher::dispatch_to_node(
            state,
            target,
            Request::WpPluginList {
                hosting: sel_id.clone(),
            },
        )
        .await
        {
            Ok(RpcResponse::WpPluginList(r)) => r,
            // Surface the real failure instead of swallowing it into an
            // empty list (which the panel renders as "no plugins
            // installed"). WP core files exist on disk (wp_status is
            // Some), but the live `wp plugin list` couldn't run — almost
            // always a DB connection / PHP error during WordPress
            // bootstrap, or a permissions problem.
            Ok(RpcResponse::Error(e)) => {
                tracing::warn!(hosting=?sel_id, error=%e, "wp plugin list failed");
                hyperion_types::WpPluginListResponse {
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
            Ok(_) => hyperion_types::WpPluginListResponse {
                error: Some("unexpected response from the agent".into()),
                ..Default::default()
            },
            Err(e) => {
                tracing::warn!(hosting=?sel_id, error=%e, "wp plugin list dispatch failed");
                hyperion_types::WpPluginListResponse {
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        }
    };
    let themes = async {
        match crate::dispatcher::dispatch_to_node(
            state,
            target,
            Request::WpThemeList {
                hosting: sel_id.clone(),
            },
        )
        .await
        {
            Ok(RpcResponse::WpThemeList(r)) => r,
            // Same as plugins: surface the failure instead of an empty list.
            Ok(RpcResponse::Error(e)) => {
                tracing::warn!(hosting=?sel_id, error=%e, "wp theme list failed");
                hyperion_types::WpThemeListResponse {
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
            Ok(_) => hyperion_types::WpThemeListResponse {
                error: Some("unexpected response from the agent".into()),
                ..Default::default()
            },
            Err(e) => {
                tracing::warn!(hosting=?sel_id, error=%e, "wp theme list dispatch failed");
                hyperion_types::WpThemeListResponse {
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        }
    };
    let (plugins, themes) = tokio::join!(plugins, themes);
    crate::wp_list_cache::WpLists { plugins, themes }
}

pub(super) async fn fetch_profile_apply(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<Option<ProfileApply>, AppError> {
    let resp = crate::dispatcher::dispatch_to_node(state, target, Request::ProfileGetApply { sel })
        .await?;
    match resp {
        RpcResponse::ProfileGetApply(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub(super) async fn fetch_all_profiles(
    state: &SharedState,
) -> Result<Vec<HostingProfile>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::ProfileList).await?;
    match resp {
        RpcResponse::ProfileList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub(super) async fn fetch_cron(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<String, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::CronList { sel }).await?;
    match resp {
        RpcResponse::CronList(s) => Ok(s),
        RpcResponse::Error(_) => Ok(String::new()),
        _ => Ok(String::new()),
    }
}

pub(super) async fn fetch_stats(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<HostingStats, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::HostingStats { sel }).await?;
    match resp {
        RpcResponse::HostingStats(s) => Ok(s),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize, Default)]
pub struct DetailQuery {
    /// Set to "installed" via the redirect after a successful WP install.
    #[serde(default)]
    pub wp: Option<String>,
    /// Job id of a running WP-install / profile-apply job — when
    /// present the detail page renders the live polling progress
    /// card. Set by the /profiles/apply redirect (and usable by
    /// any future flow that wants the same card).
    #[serde(default)]
    pub wpjob: Option<String>,
    /// Surface WP install failures back into the detail page.
    #[serde(default)]
    pub wp_error: Option<String>,
    /// Single-use token for a failure message held server-side. The old
    /// `wp_error` query param stays readable so a link already in a
    /// browser's history still renders something.
    pub wp_error_ref: Option<String>,
    #[serde(default)]
    pub backup: Option<String>,
    #[serde(default)]
    pub backup_error: Option<String>,
    /// Free-text success summary from a bulk archive delete (e.g. "3 archives
    /// deleted"). Rendered escaped as the backups-card flash.
    #[serde(default)]
    pub backup_deleted: Option<String>,
    /// Refusal from the off-site-target POST (unknown target), so the page
    /// says the pin did NOT change instead of redirecting silently.
    #[serde(default)]
    pub backup_target_error: Option<String>,
    #[serde(default)]
    pub expiry: Option<String>,
    #[serde(default)]
    pub expiry_error: Option<String>,
    /// Lifecycle & billing → Price saved (any value ⇒ success flash).
    #[serde(default)]
    pub price: Option<String>,
    #[serde(default)]
    pub price_error: Option<String>,
    /// Reverse-proxy upstream save landed (any value ⇒ success flash).
    #[serde(default)]
    pub proxy_saved: Option<String>,
    #[serde(default)]
    pub proxy_error: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub cert_error: Option<String>,
    #[serde(default)]
    pub restore: Option<String>,
    #[serde(default)]
    pub restore_error: Option<String>,
    #[serde(default)]
    pub cron: Option<String>,
    #[serde(default)]
    pub cron_error: Option<String>,
    #[serde(default)]
    pub db: Option<String>,
    #[serde(default)]
    pub db_error: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub profile_error: Option<String>,
    #[serde(default)]
    pub ftp: Option<String>,
    #[serde(default)]
    pub ftp_error: Option<String>,
    /// Newly-set FTP password — shown ONCE then dropped. Carried in
    /// the query string after a successful POST so the redirect lands
    /// the operator on the page WITH the password visible.
    /// Single-use token for the freshly generated FTP password. The
    /// password itself never travels in the URL — see the hand-off store
    /// on AppState.
    #[serde(default)]
    pub ftp_pw_token: Option<String>,
    /// "1" after a successful vhost-options POST → green banner.
    #[serde(default)]
    pub vhost_saved: Option<String>,
    /// nginx -t error / validation error from the vhost-options POST,
    /// surfaced back through the redirect.
    #[serde(default)]
    pub vhost_error: Option<String>,
    /// "1" after WP debug / Redis form was applied successfully.
    #[serde(default)]
    pub wp_extras_saved: Option<String>,
    /// Error from WP debug / Redis form, surfaced via redirect.
    #[serde(default)]
    pub wp_extras_error: Option<String>,
}

pub(super) async fn fetch_expiry(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<hyperion_types::HostingExpiry, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::HostingGetExpiry(sel)).await?;
    match resp {
        RpcResponse::HostingGetExpiry(e) => Ok(e),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub(super) async fn fetch_backup_list(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
    limit: i64,
) -> Result<Vec<hyperion_types::BackupRunWire>, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::BackupList { sel, limit })
            .await?;
    match resp {
        RpcResponse::BackupList(rows) => Ok(rows),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub(super) async fn fetch_wp_status(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<Option<WpInstallStatus>, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::WpStatus { sel }).await?;
    match resp {
        RpcResponse::WpStatus(s) => Ok(s),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub(super) async fn fetch_limits(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<hyperion_types::HostingLimits, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::HostingGetLimits(sel)).await?;
    match resp {
        RpcResponse::HostingGetLimits(l) => Ok(l),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn get_health_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let card = |report, target_node: String, wp_debug: bool, error: Option<String>| {
        Html(
            FatalCardTpl {
                report,
                selector: selector.clone(),
                csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
                csrf_wp_debug: csrf_token_for(&state, &ctx, "/hostings/wp/debug"),
                csrf_dropin: csrf_token_for(&state, &ctx, "/hostings/wp/dropin"),
                target_node,
                wp_debug_enabled: wp_debug,
                error,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return Ok(card(
                Default::default(),
                String::new(),
                false,
                Some(format!("could not read the selector: {e}")),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(card(
                Default::default(),
                String::new(),
                false,
                Some(format!("could not look up this site: {e}")),
            ))
        }
    };
    if require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    .is_err()
    {
        return Ok(card(
            Default::default(),
            String::new(),
            false,
            Some("not permitted".into()),
        ));
    }
    let tn = owner.clone().unwrap_or_default();
    let dbg = detail.wp_extras.wp_debug_enabled;
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::WpFatalCheck { sel },
    )
    .await
    {
        Ok(RpcResponse::WpFatalCheck(r)) => Ok(card(r, tn, dbg, None)),
        Ok(RpcResponse::Error(e)) => Ok(card(Default::default(), tn, dbg, Some(e.to_string()))),
        Ok(_) => Ok(card(
            Default::default(),
            tn,
            dbg,
            Some("unexpected response from the node".into()),
        )),
        Err(e) => Ok(card(Default::default(), tn, dbg, Some(e.to_string()))),
    }
}
