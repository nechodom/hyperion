//! GeoIP database credentials, refresh, and per-hosting country traffic.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Requests per country for one hosting, from its access log.
    ///
    /// Reads the SAME window the usage sampler uses so the totals here and
    /// on the stats page describe the same traffic — two "requests in 24 h"
    /// figures that disagree are worse than one.
    ///
    /// Addresses the database cannot place are counted under `ZZ` rather
    /// than dropped: a large unknown share is itself the finding (a
    /// stale database, or traffic arriving over IPv6, which the Country
    /// IPv4 table does not cover).
    pub async fn hosting_country_traffic(
        &self,
        sel: HostingSelector,
        hours: i64,
    ) -> Result<Vec<hyperion_types::CountryTraffic>, RpcError> {
        let detail = self.get(sel).await?;
        let ranges = hyperion_adapters::geoip::load_ranges(std::path::Path::new(
            hyperion_adapters::geoip::RANGES_CSV,
        ))
        .await
        .map_err(|_| RpcError::Validation {
            message: "the GeoIP database is not installed — download it in \
                          Settings -> Brute-force & GeoIP -> GeoIP database, then reload this tab."
                .into(),
        })?;

        // Same layout the usage sampler uses: <home_root>/<user>/<domain>/logs.
        let path = std::path::PathBuf::from(&self.paths.home_root)
            .join(&detail.system_user)
            .join(&detail.domain)
            .join("logs")
            .join("access.log");
        let mut body = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        if let Ok(older) = tokio::fs::read_to_string(path.with_extension("log.1")).await {
            body.push('\n');
            body.push_str(&older);
        }
        let since = now_secs() - hours.clamp(1, 24 * 30) * 3600;

        // The box's own requests are noise here, not traffic: the uptime
        // monitor probing the site, wp-cron hitting itself, the cert
        // pre-flight, wp-cli. Counting them inflates whichever country the
        // SERVER sits in — which is exactly the row the operator then
        // mis-reads as visitors. Two filters, each doing half the job:
        // private/loopback addresses (the hairpin cases), and the node's
        // own public IPv4 (probes that go out and come back).
        //
        // The public IP is fetched once per process life — it does not
        // change under a running agent, and a per-request probe would add
        // a network round trip and a failure mode to every panel load. A
        // failed fetch degrades to filtering private addresses only.
        let own_ip = own_public_ipv4().await;

        let mut by_cc: std::collections::HashMap<String, (i64, i64)> = Default::default();
        for line in body.lines() {
            let Some((ip, ts, bytes)) = parse_access_line(line) else {
                continue;
            };
            if ts < since {
                continue;
            }
            if !hyperion_adapters::logscan::is_public_bannable_ip(ip) {
                continue;
            }
            if own_ip.as_deref() == Some(ip) {
                continue;
            }
            let cc = ip
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .and_then(|v4| hyperion_adapters::geoip::lookup(&ranges, v4))
                .map(|r| r.country())
                .unwrap_or_else(|| "ZZ".to_string());
            let e = by_cc.entry(cc).or_insert((0, 0));
            e.0 += 1;
            e.1 += bytes;
        }

        let names = self.geoip_country_names().await;
        let total: i64 = by_cc.values().map(|(r, _)| *r).sum();
        let mut out: Vec<hyperion_types::CountryTraffic> = by_cc
            .into_iter()
            .map(
                |(code, (requests, bytes_out))| hyperion_types::CountryTraffic {
                    name: names.get(&code).cloned().unwrap_or_else(|| {
                        if code == "ZZ" {
                            "Unknown".into()
                        } else {
                            code.clone()
                        }
                    }),
                    share_pct: if total > 0 {
                        (requests * 100 + total / 2) / total
                    } else {
                        0
                    },
                    code,
                    requests,
                    bytes_out,
                },
            )
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.requests));
        Ok(out)
    }

    /// ISO code → English name, from the locations CSV the refresh keeps.
    /// Missing names fall back to the code itself, which is still readable.
    pub(super) async fn geoip_country_names(&self) -> std::collections::HashMap<String, String> {
        let mut out = std::collections::HashMap::new();
        let p = std::path::Path::new(hyperion_adapters::geoip::GEOIP_DIR).join("country-names.csv");
        if let Ok(text) = tokio::fs::read_to_string(&p).await {
            for line in text.lines() {
                if let Some((cc, name)) = line.split_once(',') {
                    out.insert(cc.trim().to_string(), name.trim().to_string());
                }
            }
        }
        out
    }

    /// Store MaxMind credentials, then immediately prove they work by
    /// downloading with them.
    ///
    /// Verifying on save matters: a licence key that is wrong fails at
    /// 03:00 in a background tick otherwise, and the operator finds out
    /// weeks later when a country rule silently never matched.
    pub async fn geoip_set_creds(
        &self,
        account_id: String,
        license_key: String,
    ) -> Result<usize, RpcError> {
        let creds = hyperion_adapters::geoip::MaxmindCreds {
            account_id: account_id.trim().to_string(),
            license_key: license_key.trim().to_string(),
        };
        if creds.account_id.is_empty() || creds.license_key.is_empty() {
            return Err(RpcError::Validation {
                message: "both the account ID and the licence key are required".into(),
            });
        }
        hyperion_adapters::geoip::write_creds(&creds, std::path::Path::new("/etc/GeoIP.conf"))
            .await
            .map_err(|e| RpcError::Internal_with(e.to_string()))?;
        // Never log or audit the key itself — only that it changed.
        self.append_audit(
            "geoip.creds.set",
            None,
            &serde_json::json!({ "account_id": &creds.account_id }).to_string(),
            "ok",
        )
        .await;
        self.geoip_refresh().await
    }

    /// Download / refresh the GeoIP country database, then validate and
    /// reload nginx.
    ///
    /// `nginx -t` before the reload is not optional here: the generated map
    /// is ~400 000 lines included at http{} level, so a truncated or
    /// malformed one takes EVERY site on the box down, not just the ones
    /// using it.
    pub async fn geoip_refresh(&self) -> Result<usize, RpcError> {
        let creds = hyperion_adapters::geoip::discover_creds(None)
            .await
            .ok_or_else(|| RpcError::Validation {
                message: "no MaxMind credentials found. Put an AccountID and LicenseKey in \
                          /etc/GeoIP.conf (the same file geoipupdate uses)."
                    .into(),
            })?;
        let n = hyperion_adapters::geoip::refresh(&creds)
            .await
            .map_err(|e| RpcError::Internal_with(e.to_string()))?;
        // Validate before reloading. If the map is bad, take it back out
        // rather than leaving nginx unable to start.
        let t = tokio::process::Command::new("nginx")
            .arg("-t")
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("nginx -t: {e}")))?;
        if !t.status.success() {
            let _ = tokio::fs::remove_file(hyperion_adapters::geoip::NGINX_GEO_CONF).await;
            return Err(RpcError::Internal_with(format!(
                "the generated geo map was rejected by nginx and has been removed: {}",
                String::from_utf8_lossy(&t.stderr).trim()
            )));
        }
        let _ = tokio::process::Command::new("systemctl")
            .args(["reload", "nginx"])
            .output()
            .await;
        self.append_audit(
            "geoip.refresh",
            None,
            &serde_json::json!({ "ranges": n }).to_string(),
            "ok",
        )
        .await;
        Ok(n)
    }

    /// (ranges on disk, when it was last written) — drives the Settings card.
    pub async fn geoip_status(&self) -> (bool, i64) {
        match tokio::fs::metadata(hyperion_adapters::geoip::RANGES_CSV).await {
            Ok(m) => {
                let at = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                (m.len() > 0, at)
            }
            Err(_) => (false, 0),
        }
    }
}
