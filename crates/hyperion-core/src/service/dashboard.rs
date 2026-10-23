//! The alerts shown on the master's dashboard.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Compute the operator dashboard alert list. Scans hostings + certs
    /// + backups + scheduler state and surfaces anything that needs
    /// human attention. Read-only — no side effects.
    pub async fn dashboard_alerts(&self) -> Result<Vec<DashboardAlert>, RpcError> {
        let mut out: Vec<DashboardAlert> = Vec::new();
        let now = now_secs();
        let summaries = self.list().await?;

        // Care reports that came due with nowhere to send them. A single
        // query for the whole node — the marker is written by the tick that
        // hit the problem, so this costs nothing on a healthy box and cannot
        // drift out of date the way a re-derived scan would.
        if let Ok(blocked) =
            hyperion_state::hosting_kv::list_by_key(&self.pool, CARE_REPORT_BLOCKED_KEY).await
        {
            for (hid, domain) in blocked {
                // The marker outlives a trip to the trash (only the purge
                // removes it), and nothing is owed to a site that is not
                // running — `summaries` is the non-trashed list.
                if !summaries.iter().any(|s| s.id.as_str() == hid) {
                    continue;
                }
                out.push(DashboardAlert {
                    kind: "care_report_blocked".into(),
                    // The site is up and serving. See the rule on `notify_admins`.
                    severity: "warn".into(),
                    message: format!(
                        "{domain} is paying for a care report that cannot be sent — the site \
                         has no care report e-mail. Set one on its care plan, then the \
                         report goes out on the next sweep with the period intact."
                    ),
                    hosting: Some(if domain.is_empty() { hid } else { domain }),
                });
            }
        }

        // Failed hostings — straight pass.
        for s in &summaries {
            if s.state == HostingState::Failed {
                out.push(DashboardAlert {
                    kind: "hosting_failed".into(),
                    severity: "error".into(),
                    message: format!("{} is in state Failed.", s.domain),
                    hosting: Some(s.domain.clone()),
                });
            }
        }

        // Cert expiry — fetch detail per hosting (cheap; we already have
        // the row in-memory) and check not_after.
        for s in &summaries {
            if let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await {
                if let Some(cert) = detail.cert {
                    let days = (cert.not_after - now) / 86400;
                    if days < 0 {
                        out.push(DashboardAlert {
                            kind: "cert_expired".into(),
                            severity: "error".into(),
                            message: format!(
                                "{} certificate EXPIRED {} day(s) ago — site is now untrusted.",
                                detail.domain,
                                days.abs()
                            ),
                            hosting: Some(detail.domain.clone()),
                        });
                    } else if cert.issuer == "self-signed" {
                        // Bootstrap cert (today RealAdapter::acme_issue
                        // still issues self-signed at hosting create()
                        // time). Surface from day one so operators know
                        // to click Issue Cert once DNS resolves — without
                        // this prompt, the only signal is the browser's
                        // "Not Secure" badge.
                        out.push(DashboardAlert {
                            kind: "cert_self_signed".into(),
                            severity: "warn".into(),
                            message: format!(
                                "{} has a temporary self-signed cert. Issue a real one from the site's SSL tab — \
                                 Let's Encrypt over HTTP-01, which needs the domain's DNS pointing here \
                                 (a Cloudflare proxy is fine).",
                                detail.domain
                            ),
                            hosting: Some(detail.domain.clone()),
                        });
                    } else if days < 7 {
                        // Inside the critical band — renewal tick has
                        // had at least 23 days of daily attempts and
                        // still hasn't succeeded. Operator should
                        // investigate (DNS broke, port 80 closed, …).
                        out.push(DashboardAlert {
                            kind: "cert_expiring".into(),
                            // Still valid, so visitors still see the site.
                            // `cert_expired` is the red one. See the rule
                            // on `notify_admins`.
                            severity: "warn".into(),
                            message: format!(
                                "{} certificate expires in {} day(s) — renew now.",
                                detail.domain, days
                            ),
                            hosting: Some(detail.domain.clone()),
                        });
                    } else if days < 30 {
                        out.push(DashboardAlert {
                            kind: "cert_expiring".into(),
                            severity: "warn".into(),
                            message: format!(
                                "{} certificate expires in {} day(s).",
                                detail.domain, days
                            ),
                            hosting: Some(detail.domain.clone()),
                        });
                    }
                }
            }
        }

        // Stale backups — last ok backup > 7 days OR never. Only check
        // active hostings (suspended ones don't accumulate data).
        for s in &summaries {
            if s.state != HostingState::Active {
                continue;
            }
            let runs = hyperion_state::backups::list_for(&self.pool, &s.id, 5)
                .await
                .unwrap_or_default();
            let last_ok = runs.iter().find(|r| r.state == "ok").map(|r| r.started_at);
            match last_ok {
                Some(ts) if now - ts > 7 * 86400 => {
                    out.push(DashboardAlert {
                        kind: "backup_stale".into(),
                        severity: "warn".into(),
                        message: format!(
                            "{} last successful backup was {} day(s) ago.",
                            s.domain,
                            (now - ts) / 86400
                        ),
                        hosting: Some(s.domain.clone()),
                    });
                }
                None if !runs.is_empty() => {
                    // Has runs but none successful.
                    out.push(DashboardAlert {
                        kind: "backup_failing".into(),
                        // Nothing is broken for a visitor — this is exposure
                        // to a future problem. See the rule on `notify_admins`.
                        severity: "warn".into(),
                        message: format!("{} has no successful backups on record.", s.domain),
                        hosting: Some(s.domain.clone()),
                    });
                }
                _ => {}
            }
        }

        // High load — latest node_metrics sample.
        if let Ok(Some(m)) = hyperion_state::metrics::latest(&self.pool).await {
            // loadavg_1m_x100 / cpu_count > 1.5 → warn. We don't track
            // cpu_count yet; rough heuristic: load > 4.0 always warn.
            if m.loadavg_1m_x100 > 400 {
                out.push(DashboardAlert {
                    kind: "high_load".into(),
                    severity: "warn".into(),
                    message: format!(
                        "1-minute load average is {:.2} — investigate or scale.",
                        m.loadavg_1m_x100 as f64 / 100.0
                    ),
                    hosting: None,
                });
            }
            if m.mem_total_kib > 0 && m.mem_used_kib * 100 / m.mem_total_kib > 90 {
                out.push(DashboardAlert {
                    kind: "high_memory".into(),
                    severity: "warn".into(),
                    message: format!(
                        "Memory usage at {}% — sites may start swapping.",
                        m.mem_used_kib * 100 / m.mem_total_kib
                    ),
                    hosting: None,
                });
            }
        }

        // Disk usage — probe the filesystems that matter to the panel
        // (rootfs + /var where hyperion + sites + dumps + backups
        // live) and emit warn at >=80% / error at >=95%. Without
        // this, the operator only learns rootfs is full when an
        // install / WP plugin upload / cert renewal fails with
        // ENOSPC deep in a stack trace.
        if let Ok(usages) = probe_disk_usages().await {
            for u in &usages {
                if u.used_pct >= 95 {
                    out.push(DashboardAlert {
                        kind: "disk_critical".into(),
                        severity: "error".into(),
                        message: format!(
                            "Disk {} is {}% full ({} free of {}) — installs / cert renewals / backups WILL fail. Free space immediately.",
                            u.mount,
                            u.used_pct,
                            human_bytes(u.total_bytes - u.used_bytes),
                            human_bytes(u.total_bytes)
                        ),
                        hosting: None,
                    });
                } else if u.used_pct >= 80 {
                    out.push(DashboardAlert {
                        kind: "disk_warn".into(),
                        severity: "warn".into(),
                        message: format!(
                            "Disk {} is {}% full ({} free of {}) — clean dumps/logs before it bites.",
                            u.mount,
                            u.used_pct,
                            human_bytes(u.total_bytes - u.used_bytes),
                            human_bytes(u.total_bytes)
                        ),
                        hosting: None,
                    });
                }
            }
        }

        // Operating-system updates on THIS node. The stored check only — the
        // dashboard must not wait on apt — with the live dpkg timestamp passed
        // in, so a list that installs have since overtaken is not quoted.
        if let Ok(os) = self.os_updates_stored().await {
            let (reboot, reboot_pkgs) = hyperion_adapters::os_updates::reboot_required().await;
            let os = hyperion_types::OsUpdateStatus {
                reboot_required: reboot,
                reboot_packages: reboot_pkgs,
                ..os
            };
            let dpkg_changed = hyperion_adapters::os_updates::dpkg_changed_at().await;
            out.extend(os_update_alerts(&os, now, dpkg_changed));
        }

        // Severity sort: error first, then warn, then info.
        out.sort_by_key(|a| match a.severity.as_str() {
            "error" => 0,
            "warn" => 1,
            _ => 2,
        });
        Ok(out)
    }
}

/// Where a certificate alert from the renewal sweep links to. Only a cert a
/// hosting owns has a hosting detail page; the rest are a node's preview
/// wildcard (`*.<base>`, issued from Settings → HTTPS) or the panel's own
/// certificate, and linking those to `/hostings/<domain>` was a 404.
pub(super) fn cert_alert_href(domain: &str, has_hosting: bool, is_wildcard: bool) -> String {
    if has_hosting {
        format!("/hostings/{domain}")
    } else if is_wildcard {
        "/settings/https#preview-wildcard".to_string()
    } else {
        "/settings/https".to_string()
    }
}

/// The "how to renew it by hand" half of the skipped-wildcard alert, pointed
/// at the place the operator can actually do it.
pub(super) fn wildcard_renew_hint(has_hosting: bool) -> &'static str {
    if has_hosting {
        "Re-issue it from the site's SSL tab: start wildcard issuance, publish \
         the TXT records it shows you, then validate."
    } else {
        "Renew it in Settings → HTTPS → Preview certificates: press Renew, \
         publish the TXT records it shows you, then validate."
    }
}
