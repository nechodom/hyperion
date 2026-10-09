//! Human-readable rendering of every agent `Response`.
//!
//! `--json` bypasses all of this and prints the response verbatim; this is
//! the table/line form an operator reads in a terminal.

use hyperion_rpc::codec::Response;

pub fn print_pretty(resp: &Response) {
    match resp {
        Response::HostingRepairPermissions(msg) => println!("{msg}"),
        Response::AgentInfo(i) => {
            println!(
                "agent:  {} version={} hostings={}",
                i.hostname, i.version, i.hostings_count
            );
            // Enrollment block — answers "did this node phone home to
            // the master OK?" without SSHing in to cat node-id.json.
            match (&i.node_id, &i.master_url) {
                (Some(node_id), Some(master_url)) => {
                    let when = i
                        .enrolled_at
                        .map(|t| format!("unix:{t}"))
                        .unwrap_or_else(|| "?".into());
                    println!("node:   {node_id} → {master_url} (enrolled {when})");
                }
                _ => {
                    println!(
                        "node:   NOT ENROLLED — check /etc/hyperion/agent.toml [enrollment] \
                         and `journalctl -u hyperion-agent | grep -i enroll`"
                    );
                }
            }
        }
        Response::NodeHostingsReassigned { moved } => {
            println!("✓ reassigned {moved} hosting(s) to the target node");
        }
        Response::AgentRepin { cleared } => match cleared {
            Some(pk) => println!(
                "✓ cleared pinned master key (was {pk}); the next heartbeat (≤60s) will \
                 re-pin the master's current key"
            ),
            None => println!(
                "✓ no master key was pinned; the next heartbeat will pin the master's current key"
            ),
        },
        Response::HostingCreate(c) => {
            println!("✓ created {} (id={})", c.system_user, c.id);
            println!("  root: {}", c.root_dir);
            if let Some(db) = &c.db {
                println!(
                    "  db:   {} (user={}, password={})",
                    db.db_name, db.db_user, db.password
                );
            }
            if let Some(cert) = &c.cert {
                println!(
                    "  cert: issuer={}, not_after={}",
                    cert.issuer, cert.not_after
                );
            }
        }
        Response::HostingList(rows) => {
            if rows.is_empty() {
                println!("no hostings");
                return;
            }
            // Full ids: a truncated one cannot be pasted back into
            // `hctl hosting get <id>`. Column widths follow the data.
            let dw = rows.iter().map(|r| r.domain.len()).max().unwrap_or(0).max(6);
            let iw = rows.iter().map(|r| r.id.0.len()).max().unwrap_or(0).max(2);
            println!("{:<dw$}  {:<iw$}  {:<5}  {:<12}  NODE", "DOMAIN", "ID", "PHP", "STATE");
            for r in rows {
                println!(
                    "{:<dw$}  {:<iw$}  {:<5}  {:<12}  {}",
                    r.domain,
                    r.id.0,
                    r.php_version.map(|v| v.as_str()).unwrap_or("-"),
                    r.state.as_str(),
                    r.node_id.as_deref().unwrap_or("-")
                );
            }
        }
        Response::HostingGet(d) => {
            println!("{}  ({})", d.domain, d.id);
            println!("  state:       {}", d.state.as_str());
            println!("  system user: {}", d.system_user);
            if let Some(v) = d.php_version {
                println!("  PHP:         {}", v.as_str());
            }
            println!("  root:        {}", d.root_dir);
            if !d.aliases.is_empty() {
                println!("  aliases:     {}", d.aliases.join(", "));
            }
            if let Some(db) = &d.database {
                println!("  db:          {} (user={})", db.db_name, db.db_user);
            }
            if let Some(cert) = &d.cert {
                println!(
                    "  cert:        {} (not_after={})",
                    cert.issuer, cert.not_after
                );
            }
        }
        Response::HostingDelete => {
            println!("✓ deleted");
        }
        Response::HostingSetLimits(l) | Response::HostingGetLimits(l) => {
            println!("limits:");
            println!("  php_memory_mb       = {}", l.php_memory_mb);
            println!("  php_max_exec_secs   = {}", l.php_max_exec_secs);
            println!("  php_max_children    = {}", l.php_max_children);
            println!("  php_max_requests    = {}", l.php_max_requests);
            println!("  db_max_connections  = {}", l.db_max_connections);
            println!(
                "  disk_hard_bytes     = {}",
                l.disk_hard_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!(
                "  bw_monthly_bytes    = {}",
                l.bw_monthly_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!("  over_bw_policy      = {}", l.over_bw_policy.as_str());
        }
        Response::HostingSuspend => println!("✓ suspended"),
        Response::HostingResume => println!("✓ resumed"),
        Response::HostingSetPhpVersion(v) => println!("✓ PHP version set to {v}"),
        Response::MtaDiagnostics(d) => {
            println!("mode             {}", d.mode);
            println!("sendmail exec    {}", d.sendmail_executable);
            println!("service active   {}", d.service_active);
            println!("service enabled  {}", d.service_enabled);
            println!("myhostname       {}", d.myhostname);
            println!("myhostname FQDN  {}", d.myhostname_is_fqdn);
            println!(
                "relayhost        {}",
                if d.relayhost.is_empty() {
                    "(direct MX)"
                } else {
                    d.relayhost.as_str()
                }
            );
            println!("mailq            {}", d.mailq_summary);
            if !d.recent_log_tail.is_empty() {
                println!("recent log tail:");
                for line in d.recent_log_tail.iter() {
                    println!("  {line}");
                }
            }
        }
        Response::MtaReconfigure { mode } => println!("✓ postfix reconfigured: {mode}"),
        Response::MtaTestSend { exit_code, output } => {
            if *exit_code == 0 {
                println!("✓ sendmail queued the message (exit 0)");
            } else {
                println!("✗ sendmail exit {exit_code}");
                if !output.is_empty() {
                    println!("{output}");
                }
            }
        }
        Response::MtaQueueFlush { attempted, output } => {
            println!("✓ queue flush requested · {attempted} message(s) still in queue after flush");
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Response::MtaQueueClear { cleared, output } => {
            println!("✓ queue clear · {cleared} message(s) discarded");
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Response::PanelProvision {
            status,
            message,
            panel_url,
        } => {
            println!("status: {status}");
            if !panel_url.is_empty() {
                println!("panel:  {panel_url}");
            }
            println!("{message}");
        }
        Response::PanelCertStatus(snap) => match snap {
            None => println!("panel cert: no issuance in progress"),
            Some(p) => {
                println!("panel:    {}", p.hostname);
                println!("stage:    {}", p.stage);
                println!("message:  {}", p.message);
                if p.not_after > 0 {
                    println!("not_after: {} (unix)", p.not_after);
                }
            }
        },
        Response::RemountUsrRw { success, message } => {
            if *success {
                println!("✓ /usr is now writable");
            } else {
                println!("✗ remount failed");
            }
            if !message.is_empty() {
                println!("{message}");
            }
        }
        Response::TrashList(entries) => {
            if entries.is_empty() {
                println!("trash is empty");
                return;
            }
            println!(
                "{:<32} {:<14} {:<14} NODE",
                "DOMAIN", "TRASHED_AT", "PURGE_IN"
            );
            for e in entries.iter() {
                println!(
                    "{:<32} {:<14} {:<14} {}",
                    e.domain, e.trashed_at, e.seconds_remaining, e.node_id
                );
            }
        }
        Response::TrashRestore => println!("✓ restored"),
        Response::TrashPurge => println!("✓ purged"),
        Response::FtpAccountsList(accounts) => {
            println!("{:<24} {:<28} {:<10} STATUS", "USER", "DOMAIN", "STATE");
            for a in accounts.iter() {
                println!(
                    "{:<24} {:<28} {:<10} {}",
                    a.user,
                    a.domain,
                    a.hosting_state,
                    a.password_state.as_str()
                );
            }
        }
        Response::FtpVerifyLogin { accepted } => {
            if *accepted {
                println!("✓ FTP login OK");
            } else {
                println!("✗ FTP login refused (530)");
            }
        }
        Response::SiteEmailLogList(entries) => {
            println!("{:<14} {:<28} {:<28} SUBJECT", "TS", "FROM", "TO");
            for e in entries.iter() {
                println!(
                    "{:<14} {:<28} {:<28} {}",
                    e.ts, e.from_address, e.to_address, e.subject
                );
            }
        }
        Response::HostingSetVhostOptions(o) => {
            println!("✓ vhost options applied");
            println!("  basic_auth_enabled  = {}", o.basic_auth_enabled);
            println!("  basic_auth_user     = {}", o.basic_auth_user);
            println!("  basic_auth_set      = {}", o.basic_auth_set);
            println!("  force_https         = {}", o.force_https);
            println!("  hsts_max_age        = {}", o.hsts_max_age);
            println!("  maintenance_mode    = {}", o.maintenance_mode);
            println!("  fastcgi_cache       = {}", o.fastcgi_cache_enabled);
            println!("  fastcgi_cache_ttl   = {}", o.fastcgi_cache_ttl);
            println!("  custom_snippet_len  = {}", o.custom_nginx_snippet.len());
            println!("  redirect_url        = {}", o.redirect_url);
            println!("  redirect_code       = {}", o.redirect_code);
            println!("  redirect_preserve   = {}", o.redirect_preserve_path);
        }
        Response::HostingSetProxyUpstream(d) => {
            println!("✓ upstream updated for {}", d.domain);
            println!(
                "  upstream = {}",
                d.proxy_upstream_url.as_deref().unwrap_or("—")
            );
        }
        Response::HostingSetAliases(d) => {
            println!("✓ aliases updated for {}", d.domain);
            if d.aliases.is_empty() {
                println!("  (no aliases)");
            } else {
                for a in &d.aliases {
                    println!("  - {a}");
                }
            }
        }
        Response::HostingSetWpDebug(e)
        | Response::HostingSetRedis(e)
        | Response::HostingRotateRedisPassword(e) => {
            println!("✓ WP extras applied");
            println!("  wp_debug_enabled    = {}", e.wp_debug_enabled);
            println!("  wp_debug_log        = {}", e.wp_debug_log);
            println!("  wp_debug_display    = {}", e.wp_debug_display);
            println!("  debug_log_size_bytes= {}", e.wp_debug_log_size_bytes);
            println!("  redis_enabled       = {}", e.redis_enabled);
            println!(
                "  redis_db_number     = {}",
                e.redis_db_number
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!("  redis_password_set  = {}", e.redis_password_set);
        }
        Response::RegGuardView(v) | Response::RegGuardSet(v) => {
            println!("✓ registration spam guard");
            println!("  enabled     = {}", v.enabled);
            println!("  installed   = {}", v.installed);
            println!("  is_wordpress= {}", v.is_wordpress);
        }
        Response::HostingRotateWpDebugLog => println!("✓ debug.log rotated"),
        Response::NotificationsFeed(f) => {
            println!("unread total: {}", f.unread_total);
            for n in &f.items {
                let mark = if n.read_at.is_some() { " " } else { "•" };
                println!(
                    "  [{}] {:>5} {} {:<8} {}",
                    mark, n.id, n.created_at, n.severity, n.title
                );
                if !n.body.is_empty() {
                    println!("           {}", n.body);
                }
            }
        }
        Response::NotificationsMarkRead => println!("✓ marked read"),
        Response::NotificationsMarkAllRead { marked } => {
            println!("✓ marked {marked} notifications read");
        }
        Response::NotificationsSearch(r) => {
            println!("unread total: {}", r.unread_total);
            for n in &r.items {
                let mark = if n.read_at.is_some() { " " } else { "•" };
                println!(
                    "  [{}] {:>5} {} {:<8} {}",
                    mark, n.id, n.created_at, n.severity, n.title
                );
            }
        }
        Response::NotificationsGet(n) => match n {
            Some(n) => println!("{} {} {} → {}", n.id, n.severity, n.title, n.href),
            None => println!("(no such notification)"),
        },
        Response::NotificationsOutbox(items) => {
            for n in items {
                println!("  {:>5} {} {:<8} {}", n.id, n.created_at, n.severity, n.title);
            }
        }
        Response::NotificationsNodeCursor(n) => println!("cursor: {n}"),
        Response::NotificationsIngest { written } => println!("✓ wrote {written} notifications"),
        Response::HostingFileDownload {
            rel_path,
            bytes_b64,
            mime,
        } => {
            println!(
                "✓ downloaded {rel_path} ({mime}, {} bytes b64)",
                bytes_b64.len()
            );
        }
        Response::HostingFileWrite => println!("✓ file written"),
        Response::HostingFileDelete => println!("✓ file deleted"),
        Response::HostingFileMkdir => println!("✓ directory created"),
        Response::HostingFileRename => println!("✓ renamed"),
        Response::HostingMigrationFetchBundleFile { bytes_b64 } => {
            println!("✓ fetched bundle file ({} bytes b64)", bytes_b64.len());
        }
        Response::AvatarFilename(f) => match f {
            Some(name) => println!("avatar: {name}"),
            None => println!("avatar: (none)"),
        },
        Response::AvatarSet => println!("✓ avatar updated"),
        Response::EmailChangeRequest { masked_to } => {
            println!("✓ verification code sent to {masked_to}");
        }
        Response::EmailChangeConfirm => println!("✓ email changed"),
        Response::EmailChangeCancel => println!("✓ pending email change cancelled"),
        Response::MonitorOverview(items) => {
            println!(
                "{:<32} {:<10} {:>5} {:>7} {:>4} NODE",
                "DOMAIN", "STATE", "SUCC%", "AVG_MS", "SAMP"
            );
            for it in items.iter() {
                println!(
                    "{:<32} {:<10} {:>5} {:>7} {:>4} {}",
                    it.domain,
                    it.alert_state,
                    it.success_pct_24h,
                    it.avg_response_ms_24h,
                    it.samples_24h,
                    it.node_id
                );
            }
        }
        Response::HostingUsage(rows) => {
            println!(
                "{:<14} {:>10} {:>10} {:>10} {:>10}",
                "PERIOD", "DISK", "BW IN", "BW OUT", "PHP REQ"
            );
            for r in rows {
                println!(
                    "{:<14} {:>10} {:>10} {:>10} {:>10}",
                    r.period, r.disk_used_bytes, r.bw_in_bytes, r.bw_out_bytes, r.php_requests
                );
            }
        }
        Response::AuditVerifyChain {
            ok,
            rows_checked,
            message,
        } => {
            if *ok {
                println!("audit chain OK ({rows_checked} rows verified)");
            } else {
                println!("audit chain BROKEN — {rows_checked} rows checked, error: {message}");
            }
        }
        Response::AuditList(rows) | Response::AuditSearch { rows, .. } => {
            println!(
                "{:>5} {:<19} {:<14} {:<22} {:<10}",
                "ID", "TS", "ACTOR", "ACTION", "RESULT"
            );
            for r in rows {
                println!(
                    "{:>5} {:<19} {:<14} {:<22} {:<10}",
                    r.id, r.ts, r.actor_label, r.action, r.result
                );
            }
        }
        Response::HostingSetExpiry(e) | Response::HostingGetExpiry(e) => {
            println!("expiry:");
            println!(
                "  expires_at = {}",
                e.expires_at
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!(
                "  owner_email = {}",
                e.owner_email.as_deref().unwrap_or("—")
            );
            println!("  grace_days  = {}", e.grace_days);
            println!("  warnings    = {}", e.warning_offsets_days);
        }
        Response::HostingClearExpiry => println!("✓ cleared"),
        Response::HostingKvSet => println!("✓ saved"),
        Response::HostingKvList(pairs) => {
            for (k, v) in pairs {
                println!("{k} = {v}");
            }
        }
        Response::UpcomingExpiries(rows) => {
            println!("{:<24} {:>14} {:<25}", "DOMAIN", "EXPIRES AT", "OWNER");
            for r in rows {
                println!(
                    "{:<24} {:>14} {:<25}",
                    r.domain,
                    r.expires_at,
                    r.owner_email.as_deref().unwrap_or("—")
                );
            }
        }
        Response::SchedulerTick { actions_processed } => {
            println!("scheduler tick processed {} action(s)", actions_processed);
        }
        Response::BackupNow(r) => {
            println!("✓ backup {} {}", r.id, r.state);
            if let Some(p) = &r.archive_path {
                println!("  archive: {p}");
            }
            if let Some(p) = &r.db_dump_path {
                println!("  db_dump: {p}");
            }
            println!("  bytes:   {}", r.bytes_total);
        }
        Response::BackupList(rows) => {
            println!(
                "{:>4} {:<19} {:<8} {:>12} ARCHIVE",
                "ID", "STARTED", "STATE", "BYTES"
            );
            for r in rows {
                println!(
                    "{:>4} {:<19} {:<8} {:>12} {}",
                    r.id,
                    r.started_at,
                    r.state,
                    r.bytes_total,
                    r.archive_path.as_deref().unwrap_or("—")
                );
            }
        }
        Response::InviteCreate(m) => {
            println!(
                "✓ invite minted for '{}' (expires {})",
                m.label, m.expires_at
            );
            println!();
            println!("  Token (shown ONCE — copy it now):");
            println!("    {}", m.token);
            println!();
            println!("  Hash (use to revoke): {}", m.token_hash);
        }
        Response::InviteList(rows) => {
            println!(
                "{:<32} {:>12} {:>12} TOKEN HASH",
                "LABEL", "CREATED", "EXPIRES"
            );
            for r in rows {
                println!(
                    "{:<32} {:>12} {:>12} {}",
                    r.label, r.created_at, r.expires_at, r.token_hash
                );
            }
        }
        Response::InviteRevoke => println!("✓ invite revoked"),
        Response::CertIssue(c) => {
            println!("✓ issued {} (not_after={})", c.domain, c.not_after);
        }
        Response::CertRenewAll(rows) => {
            for r in rows {
                println!("{} -> {:?}", r.domain, r.outcome);
            }
        }
        Response::WpInstall(s) => {
            println!("✓ WordPress installed");
            println!("  site:    {}", s.site_url);
            println!("  version: {}", s.wp_version);
        }
        Response::WpStatus(maybe) => match maybe {
            Some(s) => {
                println!("site:    {}", s.site_url);
                println!("version: {}", s.wp_version);
                println!("at:      {}", s.installed_at);
            }
            None => println!("(no WordPress install on this hosting)"),
        },
        Response::DnsSpfCheck(s) => {
            println!("domain:    {}", s.domain);
            println!("status:    {}", s.status);
            println!("existing:  {:?}", s.existing);
            println!("suggested: {}", s.suggested);
        }
        Response::DnsCheck(c) => {
            println!("domain:   {}", c.domain);
            println!("A:        {:?}", c.resolved_a);
            println!("AAAA:     {:?}", c.resolved_aaaa);
            println!("our v4:   {}", c.our_public_ipv4.as_deref().unwrap_or("?"));
            println!("our v6:   {}", c.our_public_ipv6.as_deref().unwrap_or("?"));
            println!("matches:  {}", if c.matches { "yes ✓" } else { "no ✗" });
            println!("note:     {}", c.note);
        }
        Response::WpEmergencyDisable => println!("✓ plugin folder parked as <slug>-old — the site boots without it"),
        Response::WpEmergencyRestore => println!("✓ plugin folder restored — left INACTIVE; activate it from the plugin list"),
        Response::WpFatalCheck(r) => {
            if r.fatal {
                println!("✗ site answers HTTP {} — WordPress fatal", r.http_status);
                if let Some(c) = &r.culprit {
                    println!("  culprit {}: {} (deactivate it)", r.culprit_kind, c);
                }
                if !r.error_excerpt.is_empty() {
                    println!("  {}", r.error_excerpt);
                }
            } else if r.verdict() == "no_answer" {
                if r.probe_error.is_empty() {
                    println!("✗ site did not answer");
                } else {
                    println!("✗ site did not answer — {}", r.probe_error);
                }
            } else if r.verdict() == "error_page" {
                println!("! site answers HTTP {} — not a WordPress fatal, but an error page", r.http_status);
            } else {
                println!("✓ site answers HTTP {} — no fatal", r.http_status);
            }
        }
        Response::WebSessionRevokeAll(n) => println!("✓ signed out of {n} session(s)"),
        Response::HostingCountryTraffic(rows) => {
            println!("{:<6} {:<28} {:>10} {:>7}", "CODE", "COUNTRY", "REQUESTS", "SHARE");
            for r in rows {
                println!("{:<6} {:<28} {:>10} {:>6}%", r.code, r.name, r.requests, r.share_pct);
            }
        }
        Response::GeoipCredsAccount(v) => match v {
            Some(id) => println!("geoip account: {id}"),
            None => println!("geoip: no credentials configured"),
        },
        Response::GeoipSetCreds(n) => println!("✓ credentials saved and verified — {n} ranges"),
        Response::GeoipRefresh(n) => println!("✓ GeoIP database refreshed — {n} ranges"),
        Response::GeoipStatus {
            installed,
            updated_at,
        } => println!(
            "geoip: {} (updated_at {updated_at})",
            if *installed { "installed" } else { "not installed" }
        ),
        Response::EmailLogoSet => println!("✓ e-mail logo updated"),
        Response::EmailLogoGet(v) => match v {
            Some(_) => println!("e-mail logo: set"),
            None => println!("e-mail logo: none"),
        },
        Response::CertDelete => println!("✓ certificate deleted — the site is on a self-signed bootstrap cert until you issue a new one"),
        Response::CertIssueAcme(c)
        | Response::CertDns01Finish(c)
        | Response::CertDns01FinishDomain(c)
        | Response::CertUpload(c) => {
            println!("✓ certificate issued");
            println!("  issuer:    {}", c.issuer);
            println!("  not_after: {}", c.not_after);
            println!("  fp:        {}", c.fingerprint_sha256);
        }
        Response::CertDns01Begin { completed, records }
        | Response::CertDns01BeginDomain { completed, records } => {
            if *completed {
                println!("✓ DNS-01 completed");
            } else {
                println!("Publish these TXT records, then run cert dns01-finish:");
                for (name, value) in records {
                    println!("  {name}  IN TXT  \"{value}\"");
                }
            }
        }
        Response::HostingStats(s) => {
            println!("{}", s.domain);
            println!("  disk:     {} B", s.disk_bytes);
            println!("  bw_in:    {} B (24h)", s.bw_in_bytes_24h);
            println!("  bw_out:   {} B (24h)", s.bw_out_bytes_24h);
            println!("  requests: {} (24h)", s.requests_24h);
        }
        Response::HostingStatsAll(rows) => {
            // One line per site (raw bytes, like the single-hosting arm
            // above) so the output stays awk/sort-able from a shell.
            println!(
                "{:<32} {:>14} {:>13} {:>14} {:>10} {:>13} {:>7}",
                "DOMAIN", "DISK_B", "BW_IN_B/24H", "BW_OUT_B/24H", "REQS/24H", "MEM_RSS_B", "CPU%"
            );
            for s in rows {
                println!(
                    "{:<32} {:>14} {:>13} {:>14} {:>10} {:>13} {:>7.2}",
                    s.domain,
                    s.disk_bytes,
                    s.bw_in_bytes_24h,
                    s.bw_out_bytes_24h,
                    s.requests_24h,
                    s.mem_rss_bytes,
                    s.cpu_pct_x100 as f64 / 100.0
                );
            }
            println!("{} hostings", rows.len());
        }
        Response::NodeStats(n) => {
            println!("{} ({})", n.label, n.node_id);
            println!(
                "  hostings: {} (active={}, suspended={}, failed={})",
                n.hostings_count, n.hostings_active, n.hostings_suspended, n.hostings_failed
            );
            println!("  disk:     {} B total", n.total_disk_bytes);
            println!("  bw_out:   {} B (24h)", n.total_bw_out_24h);
            println!("  reqs:     {} (24h)", n.total_requests_24h);
            println!("  load1:    {:.2}", n.loadavg_1m_x100 as f64 / 100.0);
            println!("  mem:      {} / {} kiB", n.mem_used_kib, n.mem_total_kib);
            println!("  uptime:   {}s", n.uptime_secs);
        }
        Response::ClusterStats(c) => {
            println!("nodes: {}", c.nodes.len());
            for n in &c.nodes {
                println!(
                    "  - {} ({}), {} hostings",
                    n.label, n.node_id, n.hostings_count
                );
            }
            println!(
                "totals: hostings={} (active={}/susp={}/fail={}), disk={} B, bw_out_24h={} B",
                c.total_hostings,
                c.total_active,
                c.total_suspended,
                c.total_failed,
                c.total_disk_bytes,
                c.total_bw_out_24h
            );
        }
        Response::StatsTick { hostings_sampled } => {
            println!("✓ {} hostings sampled", hostings_sampled);
        }
        Response::BackupRestore => println!("✓ backup restored"),
        Response::BackupFetchChunk {
            total_size,
            filename,
            eof,
            ..
        } => {
            println!("chunk of {filename} ({total_size} bytes total, eof={eof})");
        }
        Response::BackupRestoreAsNew { hosting_id, domain } => {
            println!("✓ restored as new hosting {domain} ({hosting_id})");
        }
        Response::HostingLogs(s) => print!("{s}"),
        Response::CronList(s) => print!("{s}"),
        Response::CronReplace => println!("✓ crontab updated"),
        Response::EnrollConsume {
            node_id,
            secret,
            master_rpc_pubkey,
        } => {
            println!("✓ node enrolled");
            println!("  node_id: {node_id}");
            println!("  secret: {secret}");
            if let Some(pk) = master_rpc_pubkey {
                println!("  master_rpc_pubkey: {pk}");
            }
        }
        Response::NodeHeartbeat { master_rpc_pubkey } => {
            print!("✓ heartbeat ok");
            if master_rpc_pubkey.is_some() {
                print!(" (master_rpc available)");
            }
            println!();
        }
        Response::NodesList(rows) => {
            if rows.is_empty() {
                println!("no enrolled nodes (the node registry lives on the master)");
                return;
            }
            let iw = rows.iter().map(|n| n.node_id.len()).max().unwrap_or(0).max(7);
            let lw = rows.iter().map(|n| n.label.len()).max().unwrap_or(0).max(5);
            println!(
                "{:<iw$}  {:<lw$}  {:<24}  {:<12}  NOTE",
                "NODE_ID", "LABEL", "VERSION", "LAST_SEEN"
            );
            for n in rows {
                println!(
                    "{:<iw$}  {:<lw$}  {:<24}  {:<12}  {}",
                    n.node_id,
                    n.label,
                    n.agent_version,
                    n.last_seen_at,
                    if n.is_drained { "drained" } else { "" }
                );
            }
        }
        Response::WpResetPassword => println!("✓ WordPress admin password reset"),
        Response::DbResetPassword => println!("✓ DB password reset (secret updated)"),
        Response::PmaHttp(r) => println!("phpMyAdmin answered HTTP {}", r.status),
        Response::FtpSetPassword { password } => {
            println!("✓ FTP password set");
            println!("  password (shown once): {password}");
        }
        Response::FtpDisable => println!("✓ FTP disabled (password cleared)"),
        Response::DkimStatus(s)
        | Response::DkimEnable(s)
        | Response::DkimDisable(s)
        | Response::DkimVerify(s) => {
            println!("DKIM for {}", s.domain);
            if s.unavailable {
                println!("  status: unavailable (OpenDKIM not installed on the node)");
            } else if s.enabled {
                let v = if s.verify_status.is_empty() {
                    "not yet verified"
                } else {
                    &s.verify_status
                };
                println!("  status:   enabled ({v})");
                println!("  DNS name: {}", s.dns_name);
                println!("  TXT:      {}", s.txt_value);
            } else {
                println!("  status: disabled");
            }
        }
        Response::BanList(bans) => {
            if bans.is_empty() {
                println!("no active bans");
            } else {
                println!("{:<18} {:<8} {:<12} REASON", "IP", "SOURCE", "EXPIRES");
                for b in bans {
                    let exp = if b.expires_at == 0 {
                        "permanent".to_string()
                    } else {
                        b.expires_at.to_string()
                    };
                    println!("{:<18} {:<8} {:<12} {}", b.ip, b.source, exp, b.reason);
                }
            }
        }
        Response::BanAdd => println!("✓ IP banned"),
        Response::BanRemove => println!("✓ ban lifted"),
        Response::SftpStatus(s) | Response::SftpSet(s) => {
            println!(
                "SFTP {} for {} ({} key(s))",
                if s.enabled { "enabled" } else { "disabled" },
                s.system_user,
                s.keys.len()
            );
            for k in &s.keys {
                let short: String = k.chars().take(50).collect();
                println!("  {short}…");
            }
        }
        Response::ProfileList(rows) => {
            for p in rows {
                println!("{}\t{}\t{}", p.id, p.name, p.pretty_price());
            }
        }
        Response::ProfileGet(p) | Response::ProfileCreate(p) | Response::ProfileUpdate(p) => {
            println!("id:    {}", p.id);
            println!("name:  {}", p.name);
            println!("price: {}", p.pretty_price());
        }
        Response::ProfileDelete => println!("✓ profile deleted"),
        Response::ProfileUsage(ids) => {
            println!("in use by {} hosting(s):", ids.len());
            for id in ids {
                println!("  {id}");
            }
        }
        Response::ProfileUsageCounts(counts) => {
            for (pid, n) in counts {
                println!("profile {pid}\t{n} hosting(s)");
            }
        }
        Response::ProfileApply(a) => {
            println!("✓ profile applied");
            if let Some(ts) = a.next_billing_at {
                println!("  next billing: {ts}");
            }
        }
        Response::ProfileWpItemInstalled { label, activated } => {
            println!(
                "✓ installed {label}{}",
                if *activated { " (activated)" } else { "" }
            );
        }
        Response::PackageList(rows) => {
            for p in rows {
                println!(
                    "{}\t{}\t{}\t{} feature(s)\t{} site(s){}",
                    p.id,
                    p.slug,
                    p.pretty_price(),
                    p.features.forced_count(),
                    p.active_count,
                    if p.enabled { "" } else { "\t(hidden)" }
                );
            }
        }
        Response::PackageGet(p) | Response::PackageCreate(p) | Response::PackageUpdate(p) => {
            println!("id:       {}", p.id);
            println!("name:     {}", p.name);
            println!("slug:     {}", p.slug);
            println!("price:    {}", p.pretty_price());
            println!("offered:  {}", if p.enabled { "yes" } else { "no" });
            println!("in use:   {} site(s)", p.active_count);
            // "leave" is not "off" — print every feature so the operator can
            // see which ones this package has no opinion about.
            println!("features:");
            println!("  wp_auto_update:  {}", p.features.wp_auto_update);
            println!("  integrity_scan:  {}", p.features.integrity_scan);
            println!("  monitoring:      {}", p.features.monitoring);
            println!("  hardening:       {}", p.features.hardening);
            println!("  backup_cadence:  {}", p.features.backup_cadence);
        }
        Response::BackupOffsiteList(listing) => {
            // Three states, three different things to do about them.
            if !listing.directory_exists {
                println!(
                    "no directory on the off-site store for this site — nothing has ever been \
                     pushed for it (the folder is created by the first upload). Use the \
                     \"Copy existing backups off-site\" button in Settings."
                );
            } else if listing.files.is_empty() {
                println!("the off-site directory exists but is EMPTY");
            }
            for f in &listing.files {
                println!("{:>14}  {}", f.bytes, f.name);
            }
        }
        Response::BackupOffsiteBackfill(r) | Response::BackupOffsitePushDrop(r) => {
            println!("considered: {}", r.considered);
            println!("pushed:     {}", r.pushed);
            println!("failed:     {}", r.failed);
            // Said separately from `failed`, because no retry fixes it: those
            // archives were pruned off local disk before anything copied them
            // anywhere, so they are gone.
            if r.missing_locally > 0 {
                println!(
                    "GONE:       {} backup(s) had no local archive left to send",
                    r.missing_locally
                );
            }
            if r.dropped > 0 {
                println!("dropped:    {} local copy(ies) removed after verify", r.dropped);
            }
            if r.kept_local > 0 {
                println!(
                    "kept:       {} local copy(ies) kept — could not confirm off-site",
                    r.kept_local
                );
            }
        }
        Response::WafOverview(o) => {
            for s in &o.sites {
                let n: i64 = s.totals_24h.iter().map(|c| c.hits).sum();
                println!("{:<40} {:<9} {:>6} (24h)", s.domain, s.level, n);
            }
            println!("{} ban(s) in the history", o.bans.len());
        }
        Response::HostingWafActivity(a) => {
            for c in &a.totals_24h {
                println!("{:<18} {:>6} (24h)", c.rule, c.hits);
            }
            for h in &a.recent {
                println!("{}  {:<15} {:<16} {} {}", h.ts, h.ip, h.rule, h.method, h.uri);
            }
        }
        Response::NetHistory(h) => {
            println!("net samples: {}", h.samples.len());
            if let Some(s) = h.samples.last() {
                println!("  latest: ↓ {} B/s ↑ {} B/s", s.rx_bps, s.tx_bps);
            }
        }
        Response::BackupOffsiteRestore(msg) => println!("✓ {msg}"),
        Response::BackupProgress(subs) => {
            if subs.is_empty() {
                println!("(no sub-step progress reported)");
            }
            for s in subs {
                let pct = if s.pct < 0 {
                    "…".to_string()
                } else {
                    format!("{}%", s.pct)
                };
                println!("  [{}] {} — {}", s.state, s.label, pct);
            }
        }
        Response::OsUpdates(s) => {
            if !s.was_checked() {
                println!("OS updates: never checked on this node");
            } else {
                println!(
                    "OS updates: {} pending, {} of them security",
                    s.pending.len(),
                    s.security_count
                );
                // The age of the index is the age of the answer. Without it
                // "0 pending" reads as "up to date" when it may mean "nobody
                // has refreshed the package list in a month".
                println!("  package index last refreshed: unix:{}", s.index_refreshed_at);
                for p in &s.pending {
                    println!(
                        "  {}{} {} -> {}",
                        if p.security { "[security] " } else { "" },
                        p.name,
                        p.installed,
                        p.candidate
                    );
                }
            }
            if s.reboot_required {
                println!("REBOOT REQUIRED{}", if s.reboot_packages.is_empty() {
                    String::new()
                } else {
                    format!(" (for: {})", s.reboot_packages.join(", "))
                });
            }
            if !s.error.is_empty() {
                println!("! {}", s.error);
            }
        }
        Response::WpRegistration(r) => {
            println!(
                "public sign-ups: {}",
                if r.open { "OPEN" } else { "closed" }
            );
            if !r.default_role.is_empty() {
                println!("new accounts get: {}", r.default_role);
            }
            // Said loudly, because this is the difference between an annoyance
            // and an incident: a stranger filling in a form and landing in a
            // role that can write is not spam.
            if r.grants_privilege() {
                println!(
                    "  WARNING: open registration hands every stranger the \"{}\" role, \
                     which can do more than read",
                    r.default_role
                );
            }
        }
        Response::SnapshotRestore(r) => {
            // Every line is a distinction the operator has to be able to make
            // afterwards, so none of them is folded into a bare tick.
            println!("✓ restored snapshot {}", r.snapshot);
            println!(
                "  files:    {}",
                if r.files_restored { "restored" } else { "left alone" }
            );
            println!(
                "  database: {}",
                if r.db_restored { "restored" } else { "left alone" }
            );
            if r.safety_snapshot.is_empty() {
                println!("  WARNING:  no snapshot of the replaced state could be taken");
            } else {
                println!("  replaced state kept as snapshot {}", r.safety_snapshot);
            }
            if !r.previous_site_kept_at.is_empty() {
                println!("  previous files kept at {}", r.previous_site_kept_at);
            }
        }
        Response::PackageDelete => {
            println!("✓ package deleted (existing activations keep their price, unenforced)")
        }
        // Say ZERO out loud rather than printing a bare tick. The master fans
        // this out to every node, and most of them own no site on the package
        // — but "0 sites moved" is also exactly what a node whose activations
        // reference a different package_id reports, and the two must not look
        // the same to whoever is debugging a plan edit that did not land.
        Response::PackageRelist {
            relanguaged,
            relisted,
        } => {
            println!(
                "✓ {relisted} activation(s) relisted, {relanguaged} relanguaged on this node"
            )
        }
        // The three self-check responses share one shape; print them the
        // same way the FTP check already is.
        Response::WpMailSelfCheck(r) | Response::WpMailRepair(r) => {
            for it in &r.items {
                println!("[{}] {}: {}", it.severity, it.label, it.detail);
            }
        }
        Response::SiteCheck(r) | Response::SiteCheckLast(Some(r)) => {
            if !r.error.is_empty() {
                println!("could not check: {}", r.error);
            }
            println!(
                "{} page(s) ok of {}, {} link(s) checked, slowest {} ms",
                r.pages_ok(),
                r.pages.len(),
                r.links_checked,
                r.slowest_ttfb_ms()
            );
            for f in &r.findings {
                println!("[{}] {} {}: {}", f.severity, f.kind, f.url, f.detail);
            }
        }
        Response::SiteCheckLast(None) => println!("(no page check has run for this site yet)"),
        Response::PerformanceView(v) => {
            println!(
                "cwv source: {}   strategy: {}   lighthouse: {}   psi key: {}",
                v.cwv_source,
                v.strategy,
                if v.lighthouse_available { "installed" } else { "no" },
                if v.psi_key_set { "set" } else { "no" }
            );
            if v.care.has_site_check() {
                println!(
                    "render: {}/{} pages ok, {} errors; ttfb median {} ms, slowest {} ms",
                    v.care.pages_ok,
                    v.care.pages_checked,
                    v.care.findings_error,
                    v.care.median_ttfb_ms,
                    v.care.slowest_ttfb_ms
                );
            }
            if let Some(c) = v.care.cwv.as_ref().and_then(|c| c.best()) {
                println!(
                    "cwv: LCP {:?} ms, CLS {:?}, INP {:?} ms",
                    c.lcp_ms, c.cls_x1000, c.inp_ms
                );
            }
        }
        Response::CwvResult(c) => {
            if c.error.is_empty() {
                println!("measured ({}) at {}", c.source, c.measured_at);
            } else {
                println!("measurement failed: {}", c.error);
            }
        }
        Response::GitSyncView(v) => {
            println!(
                "repo: {}   branch: {}   auth: {}",
                v.config.repo, v.config.branch, v.config.auth
            );
            if v.last.at > 0 {
                println!("last: {} {} {}", v.last.status, v.last.commit, v.last.message);
            }
        }
        Response::GitSyncLast(l) => {
            println!("deploy {}: {} {}", l.status, l.commit, l.message);
        }
        Response::GitSyncPubkey(k) => println!("{k}"),
        Response::GitSyncAck => println!("ok"),
        Response::GitSyncCheck(c) => {
            if c.ok {
                println!("ok: {} (branch at {})", c.message, c.commit);
            } else {
                println!("refused: {}", c.message);
            }
        }
        Response::SnapshotList(rows) => {
            if rows.is_empty() {
                println!("(no snapshots — the snapshot engine may not be installed)");
            }
            for r in rows {
                println!("{:<10} {:<26} {}", r.id, r.time, r.tags.join(","));
            }
        }
        Response::SnapshotOverview(o) => {
            println!(
                "engine: {}   mode: {}   retention: {}   repository: {} bytes",
                o.engine,
                o.protection_mode,
                o.retention.describe(),
                o.repo_bytes
            );
            for r in &o.snapshots {
                println!("{:<10} {:<26} {}", r.id, r.time, r.tags.join(","));
            }
        }
        Response::SnapshotDeleted(n) => println!("deleted {n} snapshot(s)"),
        Response::SnapshotNow(id) => {
            if id.is_empty() {
                println!("no snapshot taken (engine unavailable or site has no document tree)");
            } else {
                println!("snapshot {id}");
            }
        }
        Response::SnapshotDiff(d) => {
            println!("+{} -{} M{}", d.added, d.removed, d.modified);
            for p in &d.sample {
                println!("  {p}");
            }
        }
        Response::WpMailAutofixSet(on) => {
            println!("wp mail self-repair: {}", if *on { "on" } else { "off" });
        }
        Response::CareOverview(rows) => {
            if rows.is_empty() {
                println!("(no site on this node holds a care package)");
            }
            for r in rows {
                let state = if r.outstanding.is_empty() {
                    "checked".to_string()
                } else {
                    format!("{}/{} — {}", r.checks_done, r.checks_total, r.outstanding.join(", "))
                };
                println!("{:<34} {:<24} {state}", r.domain, r.packages.join(","));
            }
        }
        Response::PackageActivations(rows) => {
            if rows.is_empty() {
                println!("(no packages on this hosting)");
            }
            for a in rows {
                println!(
                    "{}\t{}\t{}\t{}{}",
                    a.id,
                    a.state,
                    if a.package_name.is_empty() {
                        "(definition deleted)"
                    } else {
                        a.package_name.as_str()
                    },
                    a.pretty_price(),
                    match a.next_billing_at {
                        Some(ts) => format!("\tnext reminder: {ts}"),
                        None => String::new(),
                    }
                );
            }
        }
        Response::PackageActivate(a) => {
            if a.is_pending() {
                // Recorded, not enforced: say so, or "active" reads as features
                // that are on.
                println!(
                    "✓ package recorded (activation {}) — starts at unix:{}, nothing is enforced until then",
                    a.id,
                    a.effective_start()
                );
            } else {
                println!("✓ package active (activation {})", a.id);
            }
            println!("  price: {}", a.pretty_price());
            if let Some(ts) = a.valid_from {
                println!("  valid from: unix:{ts}");
            }
            if let Some(ts) = a.next_billing_at {
                println!("  next reminder: {ts}");
            }
        }
        Response::PackageSetValidFrom(a) => {
            println!(
                "✓ activation {} valid from unix:{}{}",
                a.id,
                a.effective_start(),
                if a.is_pending() { " (not started yet)" } else { "" }
            );
        }
        Response::PackageCancel(a) => {
            println!("✓ package cancelled (activation {} kept as history)", a.id);
        }
        Response::PackageEnforceTick { corrected } => {
            if *corrected == 0 {
                println!("✓ nothing had drifted");
            } else {
                println!("✓ re-asserted {corrected} paid feature(s) that had been switched off");
            }
        }
        Response::CareReportPreview(m)
        | Response::CareReportSend(m)
        | Response::CareReportPreviewRange(m)
        | Response::CareReportSendRange(m) => {
            // The body is the point — print it verbatim, because the whole
            // reason preview exists is to read exactly what the customer
            // gets. Everything else goes above it as a short header.
            println!("period:   {} → {}", m.period_start, m.period_end);
            println!("cadence:  {}", m.cadence);
            println!(
                "to:       {}",
                if m.to.is_empty() {
                    "(none — this site has no owner e-mail, so nothing can be sent)"
                } else {
                    m.to.as_str()
                }
            );
            if m.entirely_unmeasured {
                println!(
                    "warning:  not one metric could be measured — the scheduled send skips \
                     a report like this (is this the node that owns the site?)"
                );
            }
            println!("subject:  {}", m.subject);
            println!();
            print!("{}", m.body);
        }
        Response::HostingImportPanelPlan(plan) => {
            println!(
                "Import plan — source {} {} ({} site(s)):",
                plan.source.kind,
                plan.source.version,
                plan.items.len()
            );
            for it in &plan.items {
                println!(
                    "  [{:?}] {}  php={}  db={}  — {}",
                    it.action,
                    it.domain,
                    it.php_version.as_deref().unwrap_or("-"),
                    it.db_count,
                    it.reason
                );
            }
            for u in &plan.unsupported {
                println!("  (not imported — {}: {})", u.category, u.detail);
            }
        }
        Response::HostingImportPanel(res) => {
            println!("{}", res.message);
            for c in &res.created {
                println!(
                    "  ✓ created {} ({}) — {} database(s)",
                    c.domain, c.hosting_id, c.databases
                );
            }
            for s in &res.skipped {
                println!("  · skipped {} — {}", s.domain, s.reason);
            }
            for u in &res.unsupported {
                println!("  note: {} not imported — {}", u.category, u.detail);
            }
        }
        Response::ProfileGetApply(maybe) => match maybe {
            Some(a) => {
                println!("profile_id: {:?}", a.profile_id);
                println!("price_minor: {:?}", a.price_minor);
                println!("next_billing_at: {:?}", a.next_billing_at);
            }
            None => println!("(no profile applied to this hosting)"),
        },
        Response::DashboardAlerts(alerts) => {
            if alerts.is_empty() {
                println!("(no alerts)");
            } else {
                for a in alerts {
                    println!("{}  {}  {}", a.severity.to_uppercase(), a.kind, a.message);
                }
            }
        }
        Response::Error(e) => {
            eprintln!("ERROR: {e}");
        }
        Response::NodeMetricsHistory(h) => {
            println!("metrics-history: {} samples", h.samples.len());
            for s in h.samples.iter().rev().take(20) {
                println!(
                    "  ts={} load={:.2} mem={}/{} hosts={}",
                    s.at,
                    s.loadavg_1m_x100 as f64 / 100.0,
                    s.mem_used_kib,
                    s.mem_total_kib,
                    s.hostings_count
                );
            }
        }
        Response::SetHostingAcmeEmail => {
            println!("acme email override updated");
        }
        Response::ServicesHealth(h) => {
            println!(
                "services health: {} critical down, {} optional down",
                h.critical_down, h.warn_down
            );
            for s in &h.services {
                println!(
                    "  [{}] {} active={} enabled={} sub={}",
                    s.severity, s.name, s.active, s.enabled, s.sub_state
                );
            }
        }
        Response::BackupDelete => {
            println!("backup deleted");
        }
        Response::FirewallList(v) => {
            println!("firewall backend: {}", v.backend);
            if !v.ports.is_empty() {
                println!("{:<8} {:<6} {:<10} REASON", "PORT", "PROTO", "CATEGORY");
                for p in &v.ports {
                    println!(
                        "{:<8} {:<6} {:<10} {}",
                        p.port, p.proto, p.category, p.label
                    );
                }
            }
            if !v.error.is_empty() {
                eprintln!("error: {}", v.error);
            }
            if !v.raw.is_empty() {
                println!("--- raw ---");
                println!("{}", v.raw);
            }
        }
        Response::HostingAnnounceCreated(sent) => println!(
            "{}",
            if *sent {
                "new-hosting announcement sent"
            } else {
                "already announced — nothing sent"
            }
        ),
        Response::HostingPermAutohealSet(on) => println!(
            "permission self-repair {}",
            if *on { "enabled" } else { "disabled" }
        ),
        Response::FirewallDefaultDrop {
            message,
            armed_seconds_left,
        } => {
            if !message.is_empty() {
                println!("{message}");
            }
            match armed_seconds_left {
                Some(s) if *s > 0 => println!(
                    "awaiting confirmation: {}s left before the firewall reverts to accept",
                    s
                ),
                Some(_) => println!("awaiting confirmation: the deadline has passed"),
                None => println!("nothing awaiting confirmation"),
            }
        }
        Response::FirewallTemplateApplied {
            applied,
            output,
            error,
        } => {
            if *applied {
                println!("✓ template applied (re-applied by the agent after a reboot)");
            } else {
                eprintln!("✗ template apply failed");
            }
            if !output.is_empty() {
                println!("{output}");
            }
            if !error.is_empty() {
                eprintln!("error: {error}");
            }
        }
        Response::AgentConfigView(c) => {
            println!(
                "agent: {} {} (nginx user: {})",
                c.hostname,
                c.agent_version,
                if c.nginx_user.is_empty() {
                    "unknown"
                } else {
                    c.nginx_user.as_str()
                }
            );
            println!(
                "acme: contact={} challenge_dir={}",
                c.acme.contact_email, c.acme.challenge_dir
            );
            println!(
                "email: enabled={} smtp={}:{} from={} security={}",
                c.email.enabled,
                c.email.smtp_host,
                c.email.smtp_port,
                c.email.from_address,
                c.email.security
            );
            println!("slack: webhook_set={}", c.slack.default_webhook_set);
            println!(
                "backup_remote: enabled={} {}://{}@{}:{}{}",
                c.backup_remote.enabled,
                c.backup_remote.scheme,
                c.backup_remote.user,
                c.backup_remote.host,
                c.backup_remote.port,
                c.backup_remote.base_path
            );
            println!(
                "backup_retention: max_age_days={} keep_latest_n={}",
                c.backup_retention.max_age_days, c.backup_retention.keep_latest_n
            );
        }
        Response::EmailSendTest { smtp_code } => {
            println!("test email sent — SMTP response: {smtp_code}");
        }
        Response::SlackSendTest => {
            println!("test message posted to the Slack webhook");
        }
        Response::FtpSelfCheck(r) => {
            println!("ftp check on {} (port {})", r.node_id, r.listen_port);
            if !r.expected_root.is_empty() {
                println!("  web root: {}", r.expected_root);
                println!(
                    "  local_root: {}",
                    if r.local_root.is_empty() {
                        "(no per-user config)"
                    } else {
                        &r.local_root
                    }
                );
            }
            for it in &r.items {
                // Same glyphs the card uses, so a terminal report and a
                // browser report read the same way.
                let mark = match it.severity.as_str() {
                    "ok" => "ok  ",
                    "warn" => "WARN",
                    "error" => "FAIL",
                    _ => "    ",
                };
                println!("  [{mark}] {}: {}", it.label, it.detail);
            }
        }
        Response::FtpRepairSite(m)
        | Response::FtpRepairNodeConfig(m)
        | Response::FtpSetFtps(m)
        | Response::WpPermRepair(m)
        | Response::WpCoreRepair(m)
        | Response::WpDropinSet(m)
        | Response::WpReinstall(m) => {
            println!("{m}");
        }
        Response::FtpAccountList(rows) => {
            if rows.is_empty() {
                println!("no extra FTP logins");
            }
            for a in rows.iter() {
                println!(
                    "  {:<20} {:<8} {}{}",
                    a.login,
                    a.password_state,
                    a.local_root,
                    if a.label.is_empty() {
                        String::new()
                    } else {
                        format!("  ({})", a.label)
                    }
                );
            }
        }
        Response::FtpAccountCreate(l, p) | Response::FtpAccountReset(l, p) => {
            println!("login:    {l}");
            println!("password (shown once): {p}");
        }
        Response::FtpAccountDelete(m) => println!("{m}"),
        Response::WpPermCheck(r) => {
            println!("permissions check for {}", r.expected_root);
            for it in &r.items {
                let mark = match it.severity.as_str() {
                    "ok" => "ok  ",
                    "warn" => "WARN",
                    "error" => "FAIL",
                    _ => "    ",
                };
                println!("  [{mark}] {}: {}", it.label, it.detail);
            }
        }
        Response::WebLogin(r) => match r {
            hyperion_types::WebLoginResult::Ok {
                user_id,
                username,
                role,
                ..
            } => {
                println!("login ok: id={user_id} user={username} role={role}");
            }
            hyperion_types::WebLoginResult::NeedsTotp { user_id, username } => {
                println!("needs 2FA: id={user_id} user={username}");
            }
            hyperion_types::WebLoginResult::Invalid => {
                println!("invalid credentials");
            }
            hyperion_types::WebLoginResult::Locked { reason } => {
                println!("locked: {reason}");
            }
        },
        Response::WebVerify2fa(r) => match r {
            hyperion_types::WebVerify2faResult::Ok {
                user_id, username, ..
            } => {
                println!("2FA ok: id={user_id} user={username}");
            }
            hyperion_types::WebVerify2faResult::Invalid => {
                println!("2FA invalid");
            }
        },
        Response::WebUserList(users) => {
            println!("{} users:", users.len());
            for u in users {
                println!(
                    "  id={} {} <{}> role={}{}{}",
                    u.id,
                    u.username,
                    u.email,
                    u.role,
                    if u.totp_enrolled { " 2FA✓" } else { "" },
                    if u.locked { " LOCKED" } else { "" }
                );
            }
        }
        Response::WebUserGet(Some(u)) => {
            println!(
                "user id={} {} <{}> role={}",
                u.id, u.username, u.email, u.role
            );
        }
        Response::WebUserGet(None) => {
            println!("user not found");
        }
        Response::WebUserCreate { id } => {
            println!("user created: id={id}");
        }
        Response::WebUserSetPassword => println!("password set"),
        Response::WebUserSetRole => println!("role set"),
        Response::RoleList(roles) => {
            println!("{} custom role(s):", roles.len());
            for r in roles {
                println!(
                    "  id={} {} caps={:#x} scope_all={} in_use={}",
                    r.id, r.name, r.capabilities, r.scope_all, r.in_use
                );
            }
        }
        Response::RoleCreate { id } => println!("role created: id={id}"),
        Response::RoleUpdate => println!("role updated"),
        Response::RoleDelete => println!("role deleted"),
        Response::WebUserSetCustomRole => println!("custom role assigned"),
        Response::ImportToken(r) => println!("import token: {r:?}"),
        Response::WebUserEffectiveRole(er) => {
            println!(
                "effective role: label={} base={} caps={:#x} scope_all={} custom_role_id={}",
                er.label,
                er.base_role,
                er.caps,
                er.scope_all,
                er.custom_role_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into())
            );
        }
        Response::WebUserSetLocked => println!("lock state changed"),
        Response::WebUserDelete => println!("user deleted"),
        Response::Web2faEnrollStart(e) => {
            println!("2FA enrollment started:");
            println!("  secret: {}", e.secret_base32);
            println!("  url:    {}", e.otpauth_url);
            println!("  backup codes (save NOW):");
            for c in &e.backup_codes {
                println!("    {}", c);
            }
        }
        Response::Web2faConfirmEnroll { ok } => {
            println!(
                "2FA enrollment {}",
                if *ok { "confirmed" } else { "rejected" }
            );
        }
        Response::Web2faDisable => println!("2FA disabled"),
        Response::WebGrantHostingAccess => println!("access granted"),
        Response::WebRevokeHostingAccess => println!("access revoked"),
        Response::WebListHostingAccess(rows) => {
            println!("{} grants:", rows.len());
            for r in rows {
                println!(
                    "  user={} ({}) {} level={}",
                    r.user_id, r.username, r.email, r.level
                );
            }
        }
        Response::HostingFileList { rel_path, entries } => {
            println!("{} ({} entries):", rel_path, entries.len());
            for e in entries {
                println!("  [{}] {:>10} {} {}", e.kind, e.size, e.mime, e.name);
            }
        }
        Response::HostingFileRead(c) => {
            println!(
                "{} ({} bytes, {}){}",
                c.rel_path,
                c.size,
                c.mime,
                if c.truncated { " — TRUNCATED" } else { "" }
            );
            println!("---");
            println!("{}", c.content);
        }
        Response::MonitorGet { config, history } => {
            println!(
                "monitor: enabled={} interval={}s alert_after={} state={}",
                config.enabled, config.interval_secs, config.alert_after_fails, config.alert_state
            );
            println!("samples (last {}):", history.samples.len());
            for s in history.samples.iter().rev().take(10) {
                println!(
                    "  ts={} ok={} status={:?} ms={}",
                    s.at, s.success, s.http_status, s.response_ms
                );
            }
        }
        Response::MonitorSet => println!("monitor config saved"),
        Response::MonitorProbeNow(s) => {
            println!(
                "probe: ok={} status={:?} ms={}",
                s.success, s.http_status, s.response_ms
            );
        }
        Response::MonitorTick { sampled } => {
            println!("monitor tick: {sampled} hosting(s) sampled");
        }
        Response::ServiceRestart => println!("service restarted"),
        Response::ServiceInstall => println!("service installed"),
        Response::AgentConfigUpdate => println!("agent.toml updated"),
        Response::EmailConfigSet => println!("email config set + applied (agent restarting)"),
        Response::UpdateCheck(s) => {
            println!("update check:");
            println!("  current: {}", s.current_sha);
            println!("  latest:  {} (tag {})", s.latest_sha, s.latest_tag);
            println!("  status:  {}", s.message);
            if s.update_available {
                println!("  → run `sudo hyperion update` (or `hctl node update --hyperion`) to upgrade");
            }
        }
        Response::WpPluginList(r) => {
            println!(
                "WordPress {} — {} plugin(s), {} update(s) pending:",
                r.wp_version,
                r.plugins.len(),
                r.updates_pending
            );
            println!(
                "{:<40} {:<10} {:<14} {:<20}",
                "SLUG", "STATUS", "VERSION", "LATEST"
            );
            for p in &r.plugins {
                let latest = if p.update_available {
                    &p.latest_version[..]
                } else {
                    "-"
                };
                println!(
                    "{:<40} {:<10} {:<14} {:<20}",
                    p.slug, p.status, p.version, latest
                );
            }
        }
        Response::WpPluginAction(r) => {
            println!("wp plugin action: {} — {}", r.state, r.message);
            if !r.output_tail.is_empty() {
                println!("--- tail ---");
                println!("{}", r.output_tail);
            }
        }
        Response::HostingExport(b) => {
            println!("migration bundle ready:");
            println!("  archive : {}", b.archive_path);
            println!("  manifest: {}", b.manifest_path);
            println!("  size    : {} bytes", b.archive_bytes);
            println!("  digest  : {}", b.archive_sha256);
            println!();
            println!("transfer to the target node, then on the target run:");
            println!("  sudo hctl hosting import --manifest {}", b.manifest_path);
            println!(
                "(typical transfer: scp -r {} root@target:/var/lib/hyperion/migration/)",
                std::path::Path::new(&b.manifest_path)
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
        }
        Response::EmailLogList(rows) => {
            println!(
                "{} email log entr{}:",
                rows.len(),
                if rows.len() == 1 { "y" } else { "ies" }
            );
            for r in rows.iter().take(50) {
                println!(
                    "  [{}] {} → {} · {} · {} · {}",
                    r.sent_at,
                    r.kind,
                    r.to_address,
                    r.state,
                    r.subject,
                    r.error
                        .as_deref()
                        .unwrap_or(r.smtp_code.as_deref().unwrap_or("-"))
                );
            }
        }
        Response::EmailSmtpAutodetect(a) => {
            if a.found {
                println!(
                    "found local SMTP: {}:{} ({})",
                    a.smtp_host, a.smtp_port, a.security
                );
                println!("  suggested_from = {}", a.suggested_from);
                println!("  note: {}", a.notes);
            } else {
                println!("no local SMTP relay detected");
                println!("  note: {}", a.notes);
            }
        }
        Response::HostingImportFromUrl(r) => {
            println!("imported (via url) hosting {}", r.domain);
            println!("  new id : {}", r.new_hosting_id.as_str());
            println!("  bytes  : {}", r.restored_bytes);
            println!("  state  : {}", r.state);
            println!("  note   : {}", r.message);
        }
        Response::HostingImport(r) => {
            println!("imported hosting {}", r.domain);
            println!("  new id : {}", r.new_hosting_id.as_str());
            println!("  bytes  : {}", r.restored_bytes);
            println!("  state  : {}", r.state);
            println!("  note   : {}", r.message);
        }
        Response::WpAssetUpload { id, deduped } => {
            if *deduped {
                println!("wp asset deduped: id={id} (same SHA-256 already in library)");
            } else {
                println!("wp asset uploaded: id={id}");
            }
        }
        Response::WpAssetList(assets) => {
            if assets.is_empty() {
                println!("(no wp assets uploaded yet)");
            } else {
                println!("{:<5} {:<7} {:<10} FILENAME", "ID", "KIND", "SIZE");
                for a in assets {
                    println!(
                        "{:<5} {:<7} {:<10} {}",
                        a.id,
                        a.kind,
                        format!("{} KB", a.size_bytes / 1024),
                        a.original_name
                    );
                }
            }
        }
        Response::WpAssetDelete => {
            println!("wp asset deleted");
        }
        Response::WpInstallFromAsset {
            kind,
            original_name,
        } => {
            println!("wp {kind} installed from library: {original_name}");
        }
        Response::WpAssetReplace => {
            println!("wp asset replaced");
        }
        Response::WpAssetReinstallAll {
            installed_ok,
            installed_failed,
            failure_tail,
        } => {
            println!("wp asset reinstall: {installed_ok} ok, {installed_failed} failed");
            if !failure_tail.is_empty() {
                println!("--- failures ---");
                println!("{failure_tail}");
            }
        }
        Response::WpThemeList(r) => {
            println!("wp core: {}", r.wp_version);
            println!("{:<24} {:<10} {:<10} UPDATE", "SLUG", "STATUS", "VERSION");
            for t in &r.themes {
                println!(
                    "{:<24} {:<10} {:<10} {}",
                    t.slug,
                    t.status,
                    t.version,
                    if t.update_available {
                        t.latest_version.clone()
                    } else {
                        "-".into()
                    }
                );
            }
        }
        Response::WpThemeAction(r) => {
            println!("theme action: {}", r.state);
            println!("  {}", r.message);
        }
        Response::WpVulnScan(r) => {
            if r.feed_unavailable {
                println!("vuln scan: feed unavailable (checked {})", r.checked);
            } else {
                println!(
                    "vuln scan: {} finding(s) across {} item(s)",
                    r.findings.len(),
                    r.checked
                );
                for f in &r.findings {
                    println!(
                        "  [{}] {} {} ({}) — {}{}",
                        f.severity,
                        f.kind,
                        f.slug,
                        f.installed_version,
                        f.title,
                        if f.patched_version.is_empty() {
                            String::new()
                        } else {
                            format!(" → fixed in {}", f.patched_version)
                        }
                    );
                }
            }
        }
        Response::VulnFindingsList(list) => {
            if list.is_empty() {
                println!("no stored vulnerabilities");
            } else {
                for h in list {
                    println!("{} — {} finding(s)", h.domain, h.findings.len());
                    for f in &h.findings {
                        println!(
                            "  [{}] {} {} ({})",
                            f.severity, f.kind, f.slug, f.installed_version
                        );
                    }
                }
            }
        }
        Response::WpIntegrityScan(r) => {
            if let Some(err) = &r.error {
                println!("integrity scan: {err}");
            }
            // "Couldn't check" is printed as loudly as a finding — a
            // missing signal must never read as a pass.
            println!(
                "  core       : {}",
                if !r.wp_cli_ok {
                    "not checked".to_string()
                } else if r.core_ok {
                    "verified against wordpress.org".to_string()
                } else {
                    format!("{} file(s) differ", r.core_issue_count())
                }
            );
            for p in &r.core_modified {
                println!("    modified : {p}");
            }
            for p in &r.core_unexpected {
                println!("    extra    : {p}");
            }
            for p in &r.core_missing {
                println!("    missing  : {p}");
            }
            println!(
                "  plugins    : {} of {} verified, {} failed, {} unverifiable",
                r.plugins_checked,
                r.plugins_total,
                r.plugins_failed.len(),
                r.plugins_unknown.len()
            );
            for p in &r.plugins_failed {
                for i in &p.issues {
                    println!("    {} — {} ({})", p.slug, i.path, i.message);
                }
            }
            if !r.plugins_unknown.is_empty() {
                // Premium plugins publish no checksums; say so, so nobody
                // reads it as a finding.
                println!(
                    "    no published checksums: {}",
                    r.plugins_unknown.join(", ")
                );
            }
            println!(
                "  malware    : {}",
                if !r.clamav_available {
                    "not scanned (clamav not installed)".to_string()
                } else if r.malware.is_empty() {
                    "no signatures matched".to_string()
                } else {
                    format!("{} hit(s)", r.malware.len())
                }
            );
            for h in &r.malware {
                println!("    {} — {}", h.path, h.signature);
            }
        }
        Response::IntegrityFindingsList(list) => {
            if list.is_empty() {
                println!("no stored integrity scans");
            } else {
                for h in list {
                    let state = if h.result.is_clean() {
                        "clean".to_string()
                    } else if !h.result.wp_cli_ok {
                        "COULD NOT CHECK".to_string()
                    } else {
                        format!("{} finding(s)", h.result.total_findings())
                    };
                    println!("{} — {state} (unix:{})", h.domain, h.scanned_at);
                }
            }
        }
        Response::WpStagingCreate { staging_domain } => {
            println!("✓ staging site created: {staging_domain}");
        }
        Response::WpStagingPush => println!("✓ staging pushed to production"),
        Response::ServiceInstallStatus(s) => {
            if s.started_at == 0 {
                println!("no service install has run on this node");
            } else {
                println!("service install ({}):", s.service_name);
                println!("  state      : {}", s.state);
                println!("  pkg        : {}", s.pkg);
                println!("  started_at : {}", s.started_at);
                println!("  finished_at: {}", s.finished_at);
                println!("  exit_code  : {}", s.exit_code);
                println!("  --- log tail ---");
                print!("{}", s.log_tail);
                if !s.log_tail.ends_with('\n') {
                    println!();
                }
            }
        }
        Response::SetupStackStart { started_at } => {
            println!("setup software install started: unix:{started_at}");
        }
        Response::SetupStackStatus(s) => {
            println!("setup software install: {}", s.state);
            for c in &s.components {
                println!("  {:<12} {}", c.name, c.state);
            }
            if !s.log_tail.is_empty() {
                println!("  --- log tail ---");
                print!("{}", s.log_tail);
                if !s.log_tail.ends_with('\n') {
                    println!();
                }
            }
        }
        Response::SetupSystemApply { restarting } => {
            println!(
                "server identity saved{}",
                if *restarting { " — agent restarting" } else { "" }
            );
        }
        Response::NodeUpdateRun { started_at } => {
            println!("node update started: unix:{started_at}");
            println!("follow with: hctl node update-status");
        }
        Response::NodeUpdateStatus(s) => {
            println!("node update:");
            println!("  state      : {}", s.state);
            println!("  started_at : {}", s.started_at);
            println!("  finished_at: {}", s.finished_at);
            println!("  do_apt     : {}", s.do_apt);
            println!("  do_hyperion: {}", s.do_hyperion);
            println!("  exit_code  : {}", s.exit_code);
            println!("  --- log tail ---");
            print!("{}", s.log_tail);
            if !s.log_tail.ends_with('\n') {
                println!();
            }
        }
        Response::FsDiagnoseAndFix(d) => {
            println!("filesystem diagnose:");
            println!("  final_state          : {}", d.final_state);
            println!("  image_kind           : {}", d.image_kind);
            println!("  /  writable now      : {}", d.usr_writable_now);
            println!("  /  writable before   : {}", d.usr_writable_before);
            if !d.root_mount_line.is_empty() {
                println!("  /proc/mounts /       : {}", d.root_mount_line);
            }
            if !d.usr_mount_line.is_empty() {
                println!("  /proc/mounts /usr    : {}", d.usr_mount_line);
            }
            if !d.fstab_root_line.is_empty() {
                println!("  /etc/fstab /         : {}", d.fstab_root_line);
            }
            println!("  /usr immutable attr  : {}", d.immutable_attr_set);
            if !d.fix_steps.is_empty() {
                println!("  fix steps:");
                for s in &d.fix_steps {
                    println!(
                        "    [{:>3}] {}  → {}",
                        s.exit_code,
                        if s.now_writable { "rw" } else { "ro" },
                        s.label
                    );
                    if !s.message.is_empty() {
                        for line in s.message.lines() {
                            println!("        {line}");
                        }
                    }
                }
            }
            if !d.recommendations.is_empty() {
                println!("  recommendations:");
                for r in &d.recommendations {
                    println!("    - {r}");
                }
            }
        }
        Response::JobGet(Some(j)) => print_job(j),
        Response::JobGet(None) => println!("job not found"),
        Response::JobList(list) => {
            if list.is_empty() {
                println!("no jobs");
            } else {
                println!(
                    "{:<26} {:<14} {:<10} {:>4}% {:<8} target",
                    "id", "kind", "state", "pct", "elapsed"
                );
                for j in list {
                    let elapsed = match j.finished_at {
                        Some(f) => f - j.started_at,
                        None => j.updated_at - j.started_at,
                    };
                    println!(
                        "{:<26} {:<14} {:<10} {:>4}% {:<8} {}",
                        j.id,
                        j.kind,
                        j.state,
                        j.progress_pct,
                        format!("{}s", elapsed),
                        j.target.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        Response::JobStarted { job_id } => println!("job started: {job_id}"),
        Response::JobAck => println!("ack"),
        Response::BackupTargetList(list) => {
            if list.is_empty() {
                println!("no backup targets configured");
            } else {
                println!(
                    "{:<5} {:<24} {:<10} {:<40} {:<10}",
                    "id", "name", "enabled", "endpoint", "bucket"
                );
                for t in list {
                    println!(
                        "{:<5} {:<24} {:<10} {:<40} {:<10}",
                        t.id, t.name, t.enabled, t.endpoint, t.bucket
                    );
                }
            }
        }
        Response::BackupTargetUpserted { id } => println!("backup target upserted: id={id}"),
        Response::BackupTargetDeleted => println!("backup target deleted"),
        Response::BackupTargetProbe(p) | Response::BackupRemoteProbe(p) => {
            println!(
                "probe: ok={} latency={}ms message={}",
                p.ok, p.put_latency_ms, p.message
            );
        }
        Response::QuotaGet(r) => {
            println!("quota:");
            println!("  current disk         : {} KiB", r.current_disk_kib);
            println!("  kernel quotas enabled: {}", r.quotas_enabled_on_fs);
            println!("  policy:");
            println!("    disk_soft_kib  : {}", r.policy.disk_soft_kib);
            println!("    disk_hard_kib  : {}", r.policy.disk_hard_kib);
            println!("    mem_limit_mib  : {}", r.policy.mem_limit_mib);
            println!("    bw_soft_mib    : {}", r.policy.bw_soft_mib);
            println!("    bw_hard_mib    : {}", r.policy.bw_hard_mib);
            if let Some(at) = r.policy.applied_at {
                println!("    applied_at     : {at}");
            }
            if let Some(err) = &r.policy.last_error {
                println!("    last_error     : {err}");
            }
            if !r.setup_hint.is_empty() {
                println!("  setup hint:");
                for line in r.setup_hint.lines() {
                    println!("    {line}");
                }
            }
        }
        Response::QuotaEnableKernel(s) => {
            println!(
                "quota enable: ok={} requires_reboot={}",
                s.ok, s.requires_reboot
            );
            println!("  fs={} mount={}", s.fs_type, s.mount_point);
            println!("  {}", s.message);
        }
        Response::QuotaApplied(v) => {
            println!("quota saved:");
            println!(
                "  disk soft={} KiB  hard={} KiB  mem={} MiB  bw_soft={} MiB  bw_hard={} MiB",
                v.disk_soft_kib, v.disk_hard_kib, v.mem_limit_mib, v.bw_soft_mib, v.bw_hard_mib
            );
            if let Some(at) = v.applied_at {
                println!("  applied to kernel at: {at}");
            }
            if let Some(err) = &v.last_error {
                println!("  kernel error: {err}");
            }
        }
        Response::NodeLabelUpdated => println!("node label updated"),
        Response::NodeDrainUpdated => println!("✓ node drain flag updated"),
        Response::NodeRemoved {
            removed,
            hostings_blocking,
        } => {
            if *removed {
                println!("✓ node removed (orphaned hostings: {hostings_blocking})");
            } else if *hostings_blocking > 0 {
                eprintln!(
                    "✗ refused — {hostings_blocking} hosting(s) still here. Re-run with --force to orphan and delete."
                );
            } else {
                eprintln!("✗ node not found");
            }
        }
        Response::NodeCryptoReset { cleared } => {
            if *cleared {
                println!(
                    "✓ pinned crypto cleared — the node re-pins its TLS pin and response-signing key on its next heartbeat"
                );
            } else {
                eprintln!("✗ node not found");
            }
        }
        Response::CertOverview(items) => {
            if items.is_empty() {
                println!("no certificates");
            } else {
                println!("{:<40} {:<14} {:>5} band", "domain", "issuer", "days");
                for it in items {
                    println!(
                        "{:<40} {:<14} {:>5} {}",
                        it.domain, it.issuer, it.days_left, it.band
                    );
                }
            }
        }
        Response::ApiKeyAck => println!("api-key ack"),
        Response::ApiKeyCreated(k) => {
            println!("api key {} created (prefix {})", k.id, k.key_prefix);
            // Raw key is shown once — hctl prints it for scripting.
            println!("  raw: {}", k.raw_key);
        }
        Response::ApiKeyResolved(opt) => match opt {
            Some(k) => println!(
                "api key {} ({}) owner={} caps={:#x} scope_all={}",
                k.id, k.label, k.owner_user_id, k.caps, k.scope_all
            ),
            None => println!("api key not found / revoked / expired"),
        },
        Response::ApiKeyList(rows) => {
            if rows.is_empty() {
                println!("no api keys");
            } else {
                println!(
                    "{:<14} {:<20} {:<10} {:<8}",
                    "prefix", "label", "last_used", "state"
                );
                for r in rows {
                    println!(
                        "{:<14} {:<20} {:<10} {:<8}",
                        r.key_prefix,
                        r.label,
                        r.last_used_at.map(|t| t.to_string()).unwrap_or_default(),
                        if r.is_revoked() { "revoked" } else { "live" }
                    );
                }
            }
        }
        Response::WebSessionAck => println!("session ack"),
        Response::WebSessionTouch(st) => {
            println!(
                "session {}",
                if st.live { "live" } else { "revoked/unknown" }
            );
            // The privilege the session would actually act with right now,
            // which is no longer whatever was stamped into its cookie.
            println!(
                "user      {}",
                if !st.known_user {
                    "gone".to_string()
                } else if st.locked {
                    "locked".to_string()
                } else {
                    format!("{} (caps {:#x}{})", st.role, st.caps, if st.scope_all { ", all hostings" } else { "" })
                }
            );
        }
        Response::WebSessionList(rows) => {
            if rows.is_empty() {
                println!("no sessions");
            } else {
                println!(
                    "{:<26} {:<16} {:<10} {:<10} {:<8}",
                    "sid", "ip", "created", "last_seen", "state"
                );
                for r in rows {
                    println!(
                        "{:<26} {:<16} {:<10} {:<10} {:<8}",
                        r.sid,
                        r.ip.as_deref().unwrap_or("-"),
                        r.created_at,
                        r.last_seen_at,
                        if r.is_revoked() { "revoked" } else { "live" }
                    );
                }
            }
        }
    }
}

/// Pretty-print one job — same fields as the live progress card
/// shows in the web UI, but for the CLI / SSH operator.
pub fn print_job(j: &hyperion_types::JobView) {
    println!("job {}:", j.id);
    println!("  kind        : {}", j.kind);
    println!("  state       : {}", j.state);
    println!(
        "  target      : {}",
        j.target.as_deref().unwrap_or("(none)")
    );
    println!("  actor       : {} (uid={})", j.actor_label, j.actor_uid);
    println!("  started_at  : {}", j.started_at);
    println!("  updated_at  : {}", j.updated_at);
    if let Some(f) = j.finished_at {
        println!("  finished_at : {f} (Δ={}s)", f - j.started_at);
    }
    println!("  step        : {}", j.step_label);
    println!("  progress    : {}%", j.progress_pct);
    if let Some(e) = &j.error {
        println!("  error       : {e}");
    }
    if !j.payload_json.is_empty() && j.payload_json != "{}" {
        println!("  payload     : {}", j.payload_json);
    }
    if !j.log_tail.is_empty() {
        println!("  --- log tail ---");
        print!("{}", j.log_tail);
        if !j.log_tail.ends_with('\n') {
            println!();
        }
    }
}
