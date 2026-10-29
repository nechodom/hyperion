//! The weekly page walk, Core Web Vitals and the performance card.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Walk the site the way a visitor would and report what is broken.
    ///
    /// Fetches the pages the site itself advertises (its sitemap, falling
    /// back to the home page alone), then the links, images and assets those
    /// pages reference. Everything is pinned to loopback, so what is checked
    /// is the copy THIS node serves — a site whose DNS still points at the
    /// old host would otherwise be graded on somebody else's server.
    ///
    /// Never an `Err` for anything about the SITE: a site that does not
    /// answer is the finding, not a failure of the check. `error` on the
    /// report is reserved for the crawl being unable to start at all, which
    /// must not render as "nothing wrong".
    pub async fn site_check(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::SiteCheckReport, RpcError> {
        let detail = self.get(sel).await?;
        let domain = detail.domain.trim().to_string();
        let mut crawl = SiteCrawl::new(&domain);
        if domain.is_empty() {
            crawl.report.error = "this hosting has no domain to fetch".into();
            return Ok(crawl.report);
        }
        // A redirect hosting has no pages of its own; crawling it would
        // report on wherever it points, which is not ours to grade.
        if detail.kind.trim() == "redirect" {
            crawl.report.error = "a redirect hosting serves no pages of its own".into();
            return Ok(crawl.report);
        }
        let Some(home) = crawl.fetch_home().await else {
            return Ok(crawl.report);
        };
        let sitemap = self.sitemap_pages(&domain, &crawl.base).await;
        crawl.fetch_sitemap_pages(sitemap).await;
        crawl.note_slowest_page();
        if home.is_ok() {
            crawl.check_caching(&home).await;
        }
        let weight = crawl.check_links().await;
        crawl.check_page_weight(weight);
        Ok(crawl.report)
    }

    /// URLs from the site's sitemap, or empty when it has none.
    ///
    /// WordPress 5.5+ serves an INDEX at `/wp-sitemap.xml` — a sitemap of
    /// sitemaps — so one level is followed. Anything unreadable yields an
    /// empty list and the caller checks the home page alone; a missing
    /// sitemap is not a finding, plenty of sites do not have one.
    pub(super) async fn sitemap_pages(&self, domain: &str, base: &str) -> Vec<String> {
        use hyperion_adapters::sitecheck;
        for candidate in ["wp-sitemap.xml", "sitemap.xml", "sitemap_index.xml"] {
            let url = format!("{base}{candidate}");
            let Ok(f) = sitecheck::fetch(&url, domain, LOOPBACK, true).await else {
                continue;
            };
            if !f.is_ok() || f.body.trim().is_empty() {
                continue;
            }
            // A sitemap is a list of URLs the SITE supplies, so it is exactly
            // as trustworthy as a link on a page — which is to say, it goes
            // through the same same-site test. Without it a tenant lists
            // `http://169.254.169.254/` in their own sitemap and the crawler
            // fetches it from inside the node.
            let same_site = |raw: &str| sitecheck::resolve_url(raw, base, domain);
            let locs: Vec<String> = sitecheck::sitemap_locs(&f.body)
                .iter()
                .filter_map(|u| same_site(u))
                .collect();
            if locs.is_empty() {
                continue;
            }
            if !sitecheck::is_sitemap_index(&f.body) {
                return locs;
            }
            // An index: follow the first child, which for WordPress is the
            // one listing pages rather than an archive of 10 000 posts.
            for child in locs.into_iter().take(2) {
                let Ok(cf) = sitecheck::fetch(&child, domain, LOOPBACK, true).await else {
                    continue;
                };
                let child_locs: Vec<String> = sitecheck::sitemap_locs(&cf.body)
                    .iter()
                    .filter_map(|u| same_site(u))
                    .collect();
                if cf.is_ok() && !child_locs.is_empty() {
                    return child_locs;
                }
            }
        }
        Vec::new()
    }

    /// The last stored site check, or `None` when one has never run.
    pub async fn site_check_last(
        &self,
        hosting_id: &str,
    ) -> Option<hyperion_types::SiteCheckReport> {
        let raw = hyperion_state::hosting_kv::get(&self.pool, hosting_id, SITE_CHECK_KV_KEY)
            .await
            .ok()??;
        serde_json::from_str(&raw).ok()
    }

    // ─────────────────────────── Page performance ───────────────────────────
    //
    // Two questions a care plan promises to answer and, until now, the report
    // did not: does the site still render, and is it fast? The render/speed
    // half reuses the site check (a real fetch of the pages, from the node).
    // The Core Web Vitals half needs a browser the node does not have, so it
    // is measured by whichever source the operator chose — Google's PageSpeed
    // Insights or a local Lighthouse — or not at all.

    /// This node's `[performance]` settings, read from agent.toml NOW. Live,
    /// for the same reason the snapshot and backup settings are: the panel
    /// saves them on every node and the acting code is here.
    pub(super) fn performance_config(&self) -> PerformanceConfig {
        read_performance_section(self.agent_config_path.as_deref())
    }

    /// Measure Core Web Vitals for one site now, and store the result.
    ///
    /// Respects the node's configured source; with the source `off` there is
    /// nothing to measure with, and that is an error the caller shows rather
    /// than a silent no-op. The site's own public URL is measured — for PSI
    /// that URL is sent to Google, which is the operator's explicit choice in
    /// picking that source.
    pub async fn cwv_measure(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::CwvResult, RpcError> {
        use hyperion_adapters::perf;
        let detail = self.get(sel).await?;
        let cfg = self.performance_config();
        let strategy = cfg.strategy();
        let url = format!("https://{}/", detail.domain.trim());
        let result = match cfg.cwv_source.as_str() {
            "psi" => perf::measure_psi(&url, &cfg.psi_api_key, strategy).await,
            "lighthouse" => {
                if !perf::lighthouse_available().await {
                    return Err(RpcError::Validation {
                        message: "Lighthouse is not installed on the node that owns this site. \
                                  Install it there, or switch the Core Web Vitals source to \
                                  Google PageSpeed Insights in Settings → Customer letters → Core Web Vitals."
                            .into(),
                    });
                }
                perf::measure_lighthouse(
                    &url,
                    strategy,
                    &detail.system_user,
                    &self.home_dir_for(detail.system_user.as_str()),
                )
                .await
            }
            _ => {
                return Err(RpcError::Validation {
                    message: "no Core Web Vitals source is configured — set one in \
                               Settings → Customer letters → Core Web Vitals."
                        .into(),
                })
            }
        };
        match result {
            Ok(mut r) => {
                r.measured_at = now_secs();
                if let Ok(json) = serde_json::to_string(&r) {
                    let _ = hyperion_state::hosting_kv::set(
                        &self.pool,
                        detail.id.as_str(),
                        CWV_KV_KEY,
                        &json,
                        now_secs(),
                    )
                    .await;
                }
                Ok(r)
            }
            Err(e) => {
                // Persist the failure too, timestamped, so the card can say
                // "tried on <date>, this is why" instead of an eternal blank.
                let stored = hyperion_types::CwvResult {
                    measured_at: now_secs(),
                    source: cfg.cwv_source.clone(),
                    strategy: strategy_str(strategy).into(),
                    error: e.to_string(),
                    ..Default::default()
                };
                if let Ok(json) = serde_json::to_string(&stored) {
                    let _ = hyperion_state::hosting_kv::set(
                        &self.pool,
                        detail.id.as_str(),
                        CWV_KV_KEY,
                        &json,
                        now_secs(),
                    )
                    .await;
                }
                Err(RpcError::Internal_with(format!("Core Web Vitals: {e}")))
            }
        }
    }

    /// The last stored Core Web Vitals result, without measuring again.
    pub(super) async fn cwv_last(&self, hosting_id: &str) -> Option<hyperion_types::CwvResult> {
        let raw = hyperion_state::hosting_kv::get(&self.pool, hosting_id, CWV_KV_KEY)
            .await
            .ok()??;
        serde_json::from_str(&raw).ok()
    }

    /// Fold the site check and the last CWV result into the report's
    /// performance section. `None` when neither half has ever been measured.
    pub async fn care_performance(
        &self,
        hosting_id: &str,
    ) -> Option<hyperion_types::CarePerformance> {
        let sc = self.site_check_last(hosting_id).await;
        // Kept even when it holds only an error: the card shows "tried on
        // <date>, this is why". The report's own builder drops a data-less
        // result to "no data yet" — see care_section_performance.
        let cwv = self.cwv_last(hosting_id).await;
        let sc_ran = sc.as_ref().is_some_and(|r| r.ran());
        if !sc_ran && cwv.is_none() {
            return None;
        }
        let mut perf = hyperion_types::CarePerformance {
            cwv,
            ..Default::default()
        };
        if let Some(r) = sc.filter(|r| r.ran()) {
            perf.checked_at = r.checked_at;
            perf.pages_checked = r.pages.len() as i64;
            perf.pages_ok = r.pages_ok() as i64;
            perf.findings_error = r.count("error") as i64;
            perf.findings_warn = r.count("warn") as i64;
            perf.median_ttfb_ms = r.median_ttfb_ms();
            perf.slowest_ttfb_ms = r.slowest_ttfb_ms();
            perf.html_bytes = r.html_bytes();
        }
        Some(perf)
    }

    /// Everything the Performance card needs, from the owning node.
    pub async fn performance_view(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::PerformanceView, RpcError> {
        use hyperion_adapters::perf;
        let detail = self.get(sel).await?;
        let cfg = self.performance_config();
        let care = self
            .care_performance(detail.id.as_str())
            .await
            .unwrap_or_default();
        // Only pay the "is Lighthouse there?" spawn when that is the source.
        let lighthouse_available =
            cfg.cwv_source == "lighthouse" && perf::lighthouse_available().await;
        Ok(hyperion_types::PerformanceView {
            care,
            cwv_source: cfg.cwv_source.clone(),
            strategy: strategy_str(cfg.strategy()).into(),
            lighthouse_available,
            psi_key_set: !cfg.psi_api_key.trim().is_empty(),
        })
    }

    /// Run the check and keep the result.
    pub async fn site_check_run(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::SiteCheckReport, RpcError> {
        let detail = self.get(sel.clone()).await?;
        let report = self.site_check(sel).await?;
        if let Ok(json) = serde_json::to_string(&report) {
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                detail.id.as_str(),
                SITE_CHECK_KV_KEY,
                &json,
                now_secs(),
            )
            .await;
        }
        Ok(report)
    }

    /// Walk every care-plan site on this node, once a week.
    ///
    /// Only sites that hold a package: this is a thing a care plan promises,
    /// and crawling every site on the box would put someone else's traffic
    /// figures up for a service they are not paying for.
    ///
    /// Speaks up only for `error` findings — the site not answering, or a
    /// page its own sitemap advertises crashing. Broken links and missing
    /// images are real and are left in the panel: waking somebody at 3 a.m.
    /// for an image is how alerting gets ignored.
    pub async fn site_check_tick(&self) -> Result<i64, RpcError> {
        let held = packages::list_all_in_force(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("site check: read held failed: {e}")))?;
        if held.is_empty() {
            return Ok(0);
        }
        let mut ids: Vec<HostingId> = Vec::new();
        for row in held {
            if !ids.contains(&row.hosting_id) {
                ids.push(row.hosting_id);
            }
        }
        let now = now_secs();
        let mut ran = 0i64;
        for id in ids {
            // Weekly. The report carries its own timestamp, so the cadence
            // survives a restart without a second piece of state to keep in
            // step with it.
            if let Some(prev) = self.site_check_last(id.as_str()).await {
                if now - prev.checked_at < SITE_CHECK_INTERVAL_SECS {
                    continue;
                }
            }
            let Ok(detail) = self.get(HostingSelector::Id(id.clone())).await else {
                continue;
            };
            if detail.state != HostingState::Active {
                continue;
            }
            let report = match self.site_check_run(HostingSelector::Id(id.clone())).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(domain = %detail.domain, error = %e, "site check failed");
                    continue;
                }
            };
            ran += 1;
            // Core Web Vitals, when a source is set and the site is DUE by the
            // operator's configured cadence ([performance] cwv_interval_days,
            // default 7). It rides this weekly tick, so a longer interval spaces
            // it out further; 0 means only the on-demand "Measure now". Gated on
            // the last result's own timestamp. Best-effort: a Google hiccup or a
            // missing Lighthouse must not fail the site check, and cwv_measure
            // records its own error for the card either way.
            let perf_cfg = self.performance_config();
            let cwv_due = perf_cfg.cwv_interval_days > 0 && {
                let elapsed = self
                    .cwv_last(id.as_str())
                    .await
                    .map(|c| now_secs() - c.measured_at)
                    .unwrap_or(i64::MAX);
                elapsed >= perf_cfg.cwv_interval_days as i64 * 86_400
            };
            if perf_cfg.cwv_source != "off" && cwv_due {
                if let Err(e) = self.cwv_measure(HostingSelector::Id(id.clone())).await {
                    tracing::debug!(domain = %detail.domain, error = %e, "cwv measure failed");
                }
            }
            let broken = report.count("error");
            if broken > 0 {
                let urls = report
                    .findings
                    .iter()
                    .filter(|f| f.severity == "error")
                    .map(|f| f.url.as_str())
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(", ");
                self.notify_admins_say(
                    "error",
                    "ops.pages_broken",
                    &[
                        ("domain", &detail.domain),
                        ("count", &broken.to_string()),
                        ("urls", &urls),
                    ],
                    &format!("/hostings/{}", detail.domain),
                    "site_check_broken",
                )
                .await;
            }
        }
        Ok(ran)
    }
}

/// Last automated page walk, as JSON.
pub(super) const SITE_CHECK_KV_KEY: &str = "site_check_last";

/// `hosting_kv` key: the last Core Web Vitals measurement (JSON `CwvResult`).
pub(super) const CWV_KV_KEY: &str = "cwv_last";

/// This node's `[performance]` settings.
#[derive(Debug, Clone, Default)]
pub(crate) struct PerformanceConfig {
    /// `off` (default), `psi` or `lighthouse`.
    pub cwv_source: String,
    /// PSI API key. Stays on the node; only ever leaves it inside a request
    /// to Google, on curl's stdin.
    pub psi_api_key: String,
    /// `mobile` (default) or `desktop`.
    pub strategy: String,
    /// How often to auto-measure, in days: 7 weekly (default), 14 fortnightly,
    /// 30 monthly, 0 = never (only the on-demand "Measure now"). The measure
    /// rides the weekly site-check tick, so this can space it OUT past a week
    /// but not make it more frequent than the check itself.
    pub cwv_interval_days: u32,
}

impl PerformanceConfig {
    pub(super) fn strategy_label(&self) -> &'static str {
        strategy_str(self.strategy())
    }
    pub(super) fn strategy(&self) -> hyperion_adapters::perf::Strategy {
        match self.strategy.as_str() {
            "desktop" => hyperion_adapters::perf::Strategy::Desktop,
            _ => hyperion_adapters::perf::Strategy::Mobile,
        }
    }
}

pub(super) fn strategy_str(s: hyperion_adapters::perf::Strategy) -> &'static str {
    match s {
        hyperion_adapters::perf::Strategy::Desktop => "desktop",
        hyperion_adapters::perf::Strategy::Mobile => "mobile",
    }
}

/// `[performance]` as it is on disk. A source that is absent or unrecognised
/// resolves to `off` — no measurement — which is the safe default: it never
/// sends a customer URL to Google or spawns a browser without the operator
/// choosing it.
pub(crate) fn read_performance_section(cfg_path: Option<&std::path::Path>) -> PerformanceConfig {
    let Some(doc) = read_agent_doc(cfg_path) else {
        return PerformanceConfig::default();
    };
    let sec = doc.get("performance");
    let str_at = |key: &str| {
        sec.and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let cwv_source = match str_at("cwv_source").as_str() {
        s @ ("psi" | "lighthouse") => s.to_string(),
        _ => "off".to_string(),
    };
    let strategy = match str_at("strategy").as_str() {
        "desktop" => "desktop".to_string(),
        _ => "mobile".to_string(),
    };
    let cwv_interval_days = sec
        .and_then(|s| s.get("cwv_interval_days"))
        .and_then(|v| v.as_integer())
        .map(|v| v.clamp(0, 365) as u32)
        .unwrap_or(7);
    PerformanceConfig {
        cwv_source,
        psi_api_key: str_at("psi_api_key"),
        strategy,
        cwv_interval_days,
    }
}
/// How often the automated walk runs per site. Weekly: every request it
/// makes lands on the customer's own traffic bill, and pages do not rot
/// faster than that.
pub(super) const SITE_CHECK_INTERVAL_SECS: i64 = 7 * 86_400;
/// Every fetch is pinned here, so the check grades the copy THIS node
/// serves rather than whatever the site's DNS currently points at.
pub(super) const LOOPBACK: &str = "127.0.0.1";
/// A single file this big on the home page is worth saying out loud. Chosen
/// as "an unresized camera photo": below it, an image is a judgement call
/// nobody needs a panel's opinion on.
pub(super) const HEAVY_ASSET_BYTES: i64 = 500_000;

/// One `site_check` walk: the report being filled and the bodies of the
/// pages that answered, whose links are checked next.
pub(super) struct SiteCrawl {
    domain: String,
    base: String,
    report: hyperion_types::SiteCheckReport,
    bodies: Vec<(String, String)>,
}

/// What the link pass learnt about the home page's weight.
pub(super) struct PageAssets {
    heaviest: Option<(String, i64)>,
    total_bytes: i64,
}

impl SiteCrawl {
    fn new(domain: &str) -> Self {
        SiteCrawl {
            domain: domain.to_string(),
            base: format!("https://{domain}/"),
            report: hyperion_types::SiteCheckReport {
                checked_at: now_secs(),
                ..Default::default()
            },
            bodies: Vec::new(),
        }
    }

    fn finding(&mut self, severity: &str, kind: &str, url: &str, found_on: &str, detail: String) {
        self.report.findings.push(hyperion_types::SiteCheckFinding {
            severity: severity.into(),
            kind: kind.into(),
            url: url.into(),
            found_on: found_on.into(),
            detail,
        });
    }

    async fn fetch(
        &self,
        url: &str,
        keep_body: bool,
    ) -> Option<hyperion_adapters::sitecheck::Fetched> {
        hyperion_adapters::sitecheck::fetch(url, &self.domain, LOOPBACK, keep_body)
            .await
            .ok()
    }

    fn record_page(&mut self, f: &hyperion_adapters::sitecheck::Fetched) {
        self.report.pages.push(hyperion_types::SiteCheckPage {
            url: f.url.clone(),
            status: f.status,
            ttfb_ms: f.ttfb_ms,
            total_ms: f.total_ms,
            bytes: f.bytes,
        });
    }

    /// The home page. `None` when curl itself could not run — that is our
    /// problem, not the site's, and saying "the site is down" would be a
    /// lie, so it lands in `report.error` instead.
    async fn fetch_home(&mut self) -> Option<hyperion_adapters::sitecheck::Fetched> {
        let base = self.base.clone();
        let home =
            match hyperion_adapters::sitecheck::fetch(&base, &self.domain, LOOPBACK, true).await {
                Ok(f) => f,
                Err(e) => {
                    self.report.error = format!("could not run the check: {e}");
                    return None;
                }
            };
        self.record_page(&home);
        if home.status == 0 {
            self.finding(
                "error",
                "page",
                &base,
                "",
                "The site did not answer at all on this server.".into(),
            );
        } else if !home.is_ok() {
            self.finding(
                "error",
                "page",
                &base,
                "",
                format!("The home page answers HTTP {}.", home.status),
            );
        } else {
            self.bodies.push((home.url.clone(), home.body.clone()));
        }
        Some(home)
    }

    /// The pages the site says it has.
    async fn fetch_sitemap_pages(&mut self, mut page_urls: Vec<String>) {
        self.report.discovery = if page_urls.is_empty() {
            "home page only — no sitemap".into()
        } else {
            "sitemap".into()
        };
        page_urls.retain(|u| u != &self.base);
        page_urls.truncate(hyperion_adapters::sitecheck::MAX_PAGES.saturating_sub(1));
        for url in page_urls {
            let Some(f) = self.fetch(&url, true).await else {
                continue;
            };
            self.record_page(&f);
            if f.is_ok() {
                self.bodies.push((f.url.clone(), f.body.clone()));
            } else if f.status >= 500 || f.status == 0 {
                // The site's own sitemap says this page exists and it
                // crashes. That is broken now.
                self.finding(
                    "error",
                    "page",
                    &f.url,
                    "",
                    format!(
                        "A page the site's own sitemap lists answers HTTP {}.",
                        f.status
                    ),
                );
            } else {
                self.finding(
                    "warn",
                    "page",
                    &f.url,
                    "",
                    format!(
                        "A page the site's own sitemap lists answers HTTP {} — published but missing.",
                        f.status
                    ),
                );
            }
        }
    }

    /// Slowness, once, on the worst offender. One line rather than one per
    /// page: a slow site is slow everywhere, and eight identical findings
    /// bury the broken links underneath.
    fn note_slowest_page(&mut self) {
        let Some(worst) = self
            .report
            .pages
            .iter()
            .filter(|p| p.is_ok())
            .max_by_key(|p| p.ttfb_ms)
        else {
            return;
        };
        if worst.ttfb_ms < hyperion_adapters::sitecheck::SLOW_TTFB_MS {
            return;
        }
        let (url, ms) = (worst.url.clone(), worst.ttfb_ms);
        self.finding(
            "info",
            "slow",
            &url,
            "",
            format!(
                "Slowest page took {ms} ms to start answering, measured on the server \
                 itself — so that is PHP and the database, with no network in it. \
                 Caching is usually what this is about."
            ),
        );
    }

    /// Cache settings, the half of "speed" an operator can fix. "Check the
    /// loading speed and adjust the cache if it needs it" is on the care
    /// list, and a timing number alone does not say what to adjust. These
    /// two do: both are a line of nginx config, and both are invisible until
    /// somebody looks.
    async fn check_caching(&mut self, home: &hyperion_adapters::sitecheck::Fetched) {
        use hyperion_adapters::sitecheck::{self, LinkKind};
        let base = self.base.clone();
        if home.content_encoding.is_empty() {
            self.finding(
                "warn",
                "cache",
                &base,
                "",
                "Pages are sent uncompressed. The browser asked for gzip and the server \
                 sent none, so every visitor downloads several times more HTML than they \
                 need to. This is one line of nginx configuration."
                    .into(),
            );
        }
        // One asset, not all of them: the setting is per-location, so a
        // second finding about a second file is the same finding twice.
        let asset = self.bodies.first().and_then(|(page_url, body)| {
            sitecheck::extract_links(body, page_url, &self.domain)
                .into_iter()
                .find(|(k, _)| matches!(k, LinkKind::Asset | LinkKind::Image))
        });
        let Some((_, asset_url)) = asset else {
            return;
        };
        let Some(f) = self.fetch(&asset_url, false).await else {
            return;
        };
        self.report.links_checked += 1;
        if f.is_ok() && !sitecheck::caches_in_browser(&f.cache_control) {
            let how = if f.cache_control.is_empty() {
                "no Cache-Control header at all".to_string()
            } else {
                format!("Cache-Control: {}", f.cache_control)
            };
            self.finding(
                "warn",
                "cache",
                &asset_url,
                &base,
                format!(
                    "Stylesheets, scripts and images are not cached by the browser \
                     ({how}), so a returning visitor downloads all of them again on \
                     every page. This is the single biggest thing you can change \
                     about how fast the site feels on a second visit."
                ),
            );
        }
    }

    /// What those pages point at: every link, image and asset, once each.
    async fn check_links(&mut self) -> PageAssets {
        use hyperion_adapters::sitecheck::{self, LinkKind};
        let mut targets: Vec<(LinkKind, String, String)> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (page_url, body) in &self.bodies {
            for (kind, url) in sitecheck::extract_links(body, page_url, &self.domain) {
                // A link on ten pages is one request, and it is attributed to
                // the first page it was seen on.
                if seen.insert(url.clone()) {
                    targets.push((kind, url, page_url.clone()));
                }
            }
        }
        // Pages already fetched are not fetched again.
        let fetched: std::collections::BTreeSet<String> =
            self.report.pages.iter().map(|p| p.url.clone()).collect();
        targets.retain(|(_, u, _)| !fetched.contains(u));
        targets.truncate(sitecheck::MAX_LINKS);

        let mut assets = PageAssets {
            heaviest: None,
            total_bytes: 0,
        };
        for (kind, url, found_on) in targets {
            let Some(f) = self.fetch(&url, false).await else {
                continue;
            };
            self.report.links_checked += 1;
            if f.is_ok() {
                // Images and stylesheets are what a page actually weighs;
                // a nav link is a different page, not part of this one.
                if matches!(kind, LinkKind::Image | LinkKind::Asset) {
                    assets.total_bytes += f.bytes;
                    if assets
                        .heaviest
                        .as_ref()
                        .map(|(_, b)| f.bytes > *b)
                        .unwrap_or(true)
                    {
                        assets.heaviest = Some((url.clone(), f.bytes));
                    }
                }
                continue;
            }
            let what = match kind {
                LinkKind::Nav => "A link on this site leads nowhere",
                LinkKind::Image => "An image on this site does not load",
                LinkKind::Asset => "A stylesheet or script does not load",
            };
            let why = match kind {
                // The one that makes a site "look broken" without anything
                // being down, and the one nobody reports because the page
                // still opens.
                LinkKind::Asset => {
                    " — this is what makes a site render as unstyled text while still being up."
                }
                _ => "",
            };
            let status = if f.status == 0 {
                "no answer".to_string()
            } else {
                format!("HTTP {}", f.status)
            };
            self.finding(
                "warn",
                kind.as_str(),
                &url,
                &found_on,
                format!("{what} ({status}){why}"),
            );
        }
        assets
    }

    /// What the page's own HTML does to it.
    ///
    /// Deliberately NOT called Core Web Vitals. Those are FIELD numbers,
    /// from real visitors on real phones and networks; anything measured
    /// here — one fetch, over loopback, on server hardware — would be a
    /// different measurement wearing the same name, and it would flatter
    /// every site we host. What follows is the CAUSES, which are in the
    /// HTML, are what an operator would change anyway, and can be stated
    /// without inventing a score.
    fn check_page_weight(&mut self, assets: PageAssets) {
        let base = self.base.clone();
        if let Some(w) = self
            .bodies
            .first()
            .map(|(_, body)| hyperion_adapters::sitecheck::page_weight(body))
        {
            if w.blocking_scripts > 0 {
                self.finding(
                    "warn",
                    "slow",
                    &base,
                    "",
                    format!(
                        "{} script(s) in the page head have neither `defer` nor `async`, so the \
                         browser stops building the page until each one has downloaded and run. \
                         This is the usual reason a site shows nothing for the first second.",
                        w.blocking_scripts
                    ),
                );
            }
            if w.unsized_images > 0 {
                self.finding(
                    "warn",
                    "slow",
                    &base,
                    "",
                    format!(
                        "{} of {} image(s) have no width and height, so the browser reserves no \
                         space and everything below them jumps as they load. That jumping is \
                         what Google measures as layout shift, and it is the half of a page's \
                         speed score that has nothing to do with how fast the server is.",
                        w.unsized_images, w.images
                    ),
                );
            }
        }
        if let Some((url, bytes)) = assets.heaviest {
            if bytes >= HEAVY_ASSET_BYTES {
                self.finding(
                    "warn",
                    "slow",
                    &url,
                    &base,
                    format!(
                        "One file on the home page is {}. On a phone that is most of the wait \
                         before anything appears; a resized copy usually costs nothing visible.",
                        human_bytes(bytes)
                    ),
                );
            }
        }
        if assets.total_bytes > 0 {
            let html = self.report.pages.first().map(|p| p.bytes).unwrap_or(0);
            self.finding(
                "info",
                "slow",
                &base,
                "",
                format!(
                    "Home page weighs {} in total — {} of HTML plus {} of images, stylesheets \
                     and scripts, as a browser downloads it.",
                    human_bytes(html + assets.total_bytes),
                    human_bytes(html),
                    human_bytes(assets.total_bytes)
                ),
            );
        }
    }
}
