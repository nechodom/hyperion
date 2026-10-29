//! One-shot work the agent does at startup: self-heals that bring the box
//! back to a known-good state after an in-place upgrade or a reboot. Each
//! runs on its own task so a slow repair never holds the socket from
//! opening.

use crate::ticks::Svc;
use hyperion_core::AdapterPort;
use std::sync::Arc;

/// Start every boot-time repair that needs the built service.
pub(crate) fn spawn_repairs(svc: &Svc, adapter: Arc<hyperion_core::RealAdapter>) {
    spawn_preview_shims(svc, adapter);
    spawn_rerender(svc);
    spawn_panel_vhost(svc);
    spawn_deployment_mode(svc);
    spawn_nginx_repair(svc);
    spawn_fpm_repair(svc);
    spawn_node_id_backfill(svc);
}

/// Refresh the WordPress preview shim for every hosting. The agent's
/// mu-plugin PHP can change between releases while the preview vhost on
/// disk does not, and update.sh never rewrites vhosts — so without this a
/// corrected shim would not land until each site was re-saved by hand.
/// Shim-only: no nginx touch.
fn spawn_preview_shims(svc: &Svc, adapter: Arc<hyperion_core::RealAdapter>) {
    let svc = svc.clone();
    tokio::spawn(async move {
        let hostings = match svc.list().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let mut n = 0u32;
        for h in hostings {
            if let Ok(d) = svc
                .get(hyperion_rpc::wire::HostingSelector::Id(h.id.clone()))
                .await
            {
                adapter
                    .reconcile_preview_shim(&d.domain, &d.root_dir, &d.system_user)
                    .await;
                n += 1;
            }
        }
        if n > 0 {
            tracing::info!(count = n, "boot: refreshed WordPress preview shims");
        }
    });
}

/// Re-render every Active hosting's FPM pool with the detected nginx user.
/// Old pool files on disk may still encode a stale `listen.owner` (e.g.
/// www-data when nginx now runs as `vito`). Without this an in-place upgrade
/// via update.sh wouldn't unbreak existing 502'ing hostings.
fn spawn_rerender(svc: &Svc) {
    let svc = svc.clone();
    tokio::spawn(async move {
        let n = svc.rerender_fpm_pools().await;
        if n > 0 {
            tracing::info!(
                count = n,
                "boot: re-rendered FPM pools with current nginx user"
            );
        }
        // After the pools, so a vhost never points at a socket whose
        // pool is still being rewritten.
        let n = svc.rerender_stale_vhosts().await;
        if n > 0 {
            tracing::info!(count = n, "boot: rolled the current vhost template out");
        }
        svc.ensure_redis_memory_policy().await;
        // The OWASP Core Rule Set is loaded at http level only while a
        // site on this node uses it; re-assert that after an update (or
        // after the package was removed by hand).
        match svc.crs_sync().await {
            Ok(true) => {
                tracing::info!("boot: ModSecurity rule set loaded/unloaded to match sites")
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, "boot: ModSecurity rule set sync failed"),
        }
    });
}

/// Re-assert the master panel vhost so template changes take effect after
/// an in-place update — notably the upstream-down "updating" page that
/// replaces a bare 502 while update.sh has hyperion-web stopped. No-op
/// unless a panel hostname + cert are already present.
fn spawn_panel_vhost(svc: &Svc) {
    let svc = svc.clone();
    tokio::spawn(async move {
        match svc.ensure_panel_vhost().await {
            Ok(true) => tracing::info!("boot: re-asserted master panel vhost"),
            Ok(false) => tracing::debug!("boot: no panel vhost to assert"),
            Err(e) => tracing::warn!(error=%e, "boot: panel vhost re-assert failed"),
        }
    });
}

/// Record what this box IS, once, so it is a literal in agent.toml rather
/// than something inferred on every read. An install that predates the key
/// gets the right answer here with no operator action.
fn spawn_deployment_mode(svc: &Svc) {
    let svc = svc.clone();
    tokio::spawn(async move {
        if let Err(e) = svc.backfill_deployment_mode().await {
            tracing::warn!(error=%e, "boot: could not record the deployment mode");
        }
    });
}

/// Scan every enabled nginx vhost for `ssl_certificate` paths that no
/// longer exist on disk. For each missing cert we generate a self-signed
/// bootstrap so `nginx -t` passes — without this a single deleted cert dir
/// bricks the WHOLE nginx process and every hosting create/update/delete
/// fails with `nginx -t` exit 1. (Real LE cert gets reissued on the next
/// renewal tick.)
fn spawn_nginx_repair(svc: &Svc) {
    let svc = svc.clone();
    tokio::spawn(async move {
        // ALSO heal missing log dirs in the same pass. nginx opens
        // every access_log / error_log file at startup; a missing
        // parent dir produces the same emerg-exit as a missing
        // cert. We do this BEFORE the cert sweep so a node whose
        // certs AND log dirs are both broken can recover in one
        // nginx_reload at the end.
        let log_dirs = svc.adapters.ensure_vhost_log_dirs().await;
        let mut need_reload = false;
        match log_dirs {
            Ok((0, _)) => tracing::debug!("boot: vhost log dir sweep clean"),
            Ok((created, scanned)) => {
                tracing::warn!(
                    created,
                    scanned,
                    "boot: created missing nginx log dirs — will reload"
                );
                need_reload = true;
            }
            Err(e) => tracing::error!(error = %e, "boot: vhost log dir sweep failed"),
        }
        match svc.adapters.repair_orphan_certs().await {
            Ok((0, _scanned)) => {
                tracing::debug!("boot: orphan cert sweep clean");
                if need_reload {
                    let _ = svc.adapters.nginx_reload().await;
                }
            }
            Ok((repaired, scanned)) => {
                tracing::warn!(
                    repaired,
                    scanned,
                    "boot: regenerated self-signed certs for orphan vhosts — \
                     reloading nginx to recover"
                );
                // Best-effort reload. If nginx was already down
                // because of this exact issue, `reload` will
                // auto-promote to `start` (see nginx::reload
                // self-heal). On reload failure the operator will
                // see the error in journalctl and can investigate.
                if let Err(e) = svc.adapters.nginx_reload().await {
                    tracing::error!(
                        error = %e,
                        "boot: nginx reload after cert repair failed — \
                         manual `systemctl restart nginx` may be needed"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "boot: orphan cert sweep failed"
                );
            }
        }
    });
}

/// Scan every PHP-FPM pool file for `user` / `listen.owner` references to
/// Unix users that no longer exist. A single such pool makes php<ver>-fpm
/// exit 78 EX_CONFIG on start, systemd gives up after 5 retries, and EVERY
/// hosting on that PHP version starts returning 502. We quarantine the bad
/// file (rename → `.conf.hyperion-quarantined-<ts>`) and restart FPM so
/// healthy pools can serve again. Operator can inspect or recover the
/// quarantined file under /etc/php/<ver>/fpm/pool.d/.
fn spawn_fpm_repair(svc: &Svc) {
    let svc = svc.clone();
    tokio::spawn(async move {
        match svc.adapters.repair_orphan_fpm_pools().await {
            Ok((0, _scanned)) => {
                tracing::debug!("boot: orphan FPM pool sweep clean");
            }
            Ok((quarantined, scanned)) => {
                tracing::warn!(
                    quarantined,
                    scanned,
                    "boot: quarantined FPM pools that referenced missing Unix users — \
                     restarting affected php<ver>-fpm services"
                );
                // We don't know which PHP versions had a bad
                // pool, but the cost of restarting all four is
                // tiny (~50ms each) and idempotent for healthy
                // versions (`reset-failed` + `start` is a no-op
                // on a running service).
                for ver in hyperion_types::PhpVersion::all() {
                    if let Err(e) = svc.adapters.fpm_restart(*ver).await {
                        // Most likely the version isn't installed
                        // on this node — log at debug to keep the
                        // boot output clean.
                        tracing::debug!(
                            version = %ver,
                            error = %e,
                            "boot: FPM restart after quarantine returned non-zero \
                             (often means this version isn't installed)"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "boot: orphan FPM pool sweep failed"
                );
            }
        }
        // Belt-and-braces: regardless of what the quarantine
        // pass did, walk every installed php<ver>-fpm service
        // and recover any in "failed" state. This handles the
        // exact stav scenario: an older boot wrote a broken
        // pool, FPM died, systemd marked it failed after 5
        // retries. A later boot fixed the pool (via rerender)
        // but never reset the failed flag — so the service
        // stays dead until we explicitly reset-failed + start.
        // Idempotent for healthy services: is-failed returns
        // false → we skip them.
        match svc.adapters.fpm_recover_failed().await {
            Ok(0) => {
                tracing::debug!("boot: no FPM services in failed state");
            }
            Ok(n) => {
                tracing::warn!(recovered = n, "boot: kicked failed FPM services back up");
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "boot: FPM failed-state recovery sweep errored"
                );
            }
        }
    });
}

/// One-shot backfill: tag every hostings row that has NULL node_id with
/// this node's identifier. Pre-migration-016 rows still show "—" in the UI
/// until this completes — usually within a second of boot — and after that
/// every list/detail render carries a real node chip.
fn spawn_node_id_backfill(svc: &Svc) {
    let svc = svc.clone();
    tokio::spawn(async move {
        match svc.backfill_local_node_id().await {
            Ok(0) => {}
            Ok(n) => tracing::info!(rows = n, "boot: backfilled node_id on legacy rows"),
            Err(e) => tracing::warn!(error = %e, "boot: node_id backfill failed"),
        }
    });
}

/// Postfix self-heal. Postfix is always brought to one of two known-good
/// states at boot (idempotent):
///
///   (A) Smart-host mode — when [email] is enabled AND has a non-empty
///       smtp_host. Site mail() and Hyperion's own outbound share the same
///       authenticated SMTP relay.
///
///   (B) Direct-MX mode — when [email] is empty / disabled. Postfix does
///       its own MX lookup and SMTPs the recipient directly from this
///       node's IP. Works fine for operators who handle their own PTR /
///       SPF / DKIM and aren't behind a port-25-blocked provider. We harden
///       the defaults: myhostname = `hostname -f`, smtp_helo_name =
///       $myhostname, myorigin = $myhostname, inet_interfaces =
///       loopback-only (the public port 25 listener stays closed so this
///       box can never accidentally be an open relay).
///
/// The two modes share a single marker file so a future operator can `cat
/// /etc/postfix/hyperion-relay.marker` to see which one the agent picked.
pub(crate) fn spawn_postfix_config(
    email_cfg: Option<hyperion_core::EmailConfig>,
    direct_opts: hyperion_core::PostfixDirectDeliveryOpts,
    message_size_limit_mb: u32,
) {
    let agent_hostname = crate::hostname_or_unknown();
    tokio::spawn(async move {
        if !hyperion_core::postfix_is_installed().await {
            tracing::debug!("boot: postfix not installed — skipping mail config");
            return;
        }
        // This node's own FQDN — the yardstick for spotting a
        // self-referential "relay" AND postfix's `myhostname` in
        // direct-MX mode. Resolve it ONCE via `hostname -f` (fall back
        // to the short hostname). The smart-host guard below MUST use
        // the FQDN, not the short name: with the short name a relay set
        // to the node's OWN fqdn (e.g. `s4.example.com` on host `s4`)
        // slips past `host_is_local` into `relayhost=`, reintroducing
        // the "loops back to myself" self-relay loop. This mirrors the
        // runtime `mta_reconfigure` path, whose `fqdn` is already `-f`.
        let fqdn = match tokio::process::Command::new("/bin/hostname")
            .arg("-f")
            .output()
            .await
        {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    agent_hostname.clone()
                } else {
                    s
                }
            }
            _ => agent_hostname.clone(),
        };
        match email_cfg {
            // A relay host that points at THIS node (localhost / loopback /
            // our own hostname) can't be a smart-host — postfix would loop
            // back to itself ("mail for localhost loops back to myself").
            // Fall through to direct-MX in that case, same as the reconfigure
            // RPC path does.
            Some(cfg)
                if !cfg.smtp_host.trim().is_empty()
                    && !hyperion_core::postfix_host_is_local(&cfg.smtp_host, &fqdn) =>
            {
                match hyperion_core::postfix_ensure_relay_config(&cfg).await {
                    Ok(()) => {
                        tracing::info!(
                            relay = %cfg.smtp_host,
                            port = cfg.smtp_port,
                            "boot: postfix configured as smart-host via [email] relay"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "boot: postfix smart-host config FAILED — PHP mail() will \
                             not deliver. Fix the error and restart hyperion-agent."
                        );
                    }
                }
            }
            _ => {
                // Direct-MX mode. `fqdn` was resolved above (from
                // `hostname -f`, falling back to the short hostname if
                // the box has no configured DNS domain — the operator
                // can still send, just from an unqualified HELO, which
                // many receivers reject, so we log a warning).
                if !fqdn.contains('.') {
                    tracing::warn!(
                        hostname = %fqdn,
                        "boot: postfix direct-MX configured with a non-FQDN HELO — \
                         most receivers will reject mail. Set a proper FQDN with \
                         `hostnamectl set-hostname <name>.<domain>` and ensure the IP's \
                         PTR record matches."
                    );
                }
                match hyperion_core::postfix_ensure_direct_delivery_config(&fqdn, &direct_opts)
                    .await
                {
                    Ok(()) => {
                        tracing::info!(
                            myhostname = %fqdn,
                            "boot: postfix configured for direct MX delivery — \
                             operator handles PTR / SPF / DKIM"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "boot: postfix direct-MX config FAILED — PHP mail() may not \
                             deliver. Fix the error and restart hyperion-agent."
                        );
                    }
                }
            }
        }
        // Independent of the mode: the limit applies to every message this
        // node queues, relayed or not. 0 = leave postfix's own value.
        if let Err(e) =
            hyperion_core::postfix_ensure_message_size_limit(message_size_limit_mb).await
        {
            tracing::error!(
                error = %e,
                mb = message_size_limit_mb,
                "boot: postfix message_size_limit not applied"
            );
        }
    });
}
