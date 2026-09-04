//! What an automated walk of a site found.
//!
//! This is the machine half of "check the main pages render, the navigation
//! works, the links resolve and the gallery displays". It is not the whole
//! promise and does not pretend to be: nothing here can tell you a layout is
//! broken, a photo is the wrong one, or a form's mail never arrives. What it
//! finds is the other kind of failure — the 404 behind a menu item, the
//! image that stopped loading after a plugin update, the stylesheet that
//! went missing and left the site looking like plain text — which a person
//! would have to click through every page to notice.
//!
//! The monthly checklist keeps its own record precisely because the two are
//! different claims. A green report here is evidence beside the tick, never
//! a substitute for it.

use serde::{Deserialize, Serialize};

/// One page fetched in full.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteCheckPage {
    pub url: String,
    /// 0 when the page could not be fetched at all.
    pub status: u16,
    /// Time to first byte. Measured from inside the same machine, so it is
    /// the server's own thinking time with no network in it.
    pub ttfb_ms: i64,
    pub total_ms: i64,
    pub bytes: i64,
}

impl SiteCheckPage {
    pub fn is_ok(&self) -> bool {
        (200..400).contains(&self.status)
    }
}

/// Something worth an operator's attention.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteCheckFinding {
    /// `error` = broken now, `warn` = will bite, `info` = noted. Same
    /// meaning as everywhere else in the panel.
    pub severity: String,
    /// `page`, `link`, `image`, `asset`, `slow`.
    pub kind: String,
    pub url: String,
    /// Which page it was found on. Empty for a finding about a page itself.
    pub found_on: String,
    pub detail: String,
}

/// The whole run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteCheckReport {
    pub checked_at: i64,
    pub pages: Vec<SiteCheckPage>,
    pub findings: Vec<SiteCheckFinding>,
    /// Links, images and assets actually requested.
    pub links_checked: i64,
    /// How the pages were found: `sitemap`, `home only`.
    pub discovery: String,
    /// Set when the run could not happen at all — a site with no document
    /// root, a node without curl. Distinct from "ran and found nothing",
    /// which is the good outcome and must not look the same.
    pub error: String,
}

impl SiteCheckReport {
    /// Worst severity present, for the card's header pill.
    pub fn worst(&self) -> &'static str {
        if !self.error.is_empty() {
            return "unknown";
        }
        if self.findings.iter().any(|f| f.severity == "error") {
            "error"
        } else if self.findings.iter().any(|f| f.severity == "warn") {
            "warn"
        } else {
            "ok"
        }
    }

    pub fn ran(&self) -> bool {
        self.error.is_empty() && !self.pages.is_empty()
    }

    /// Slowest page's time to first byte — the number an operator tunes
    /// against.
    pub fn slowest_ttfb_ms(&self) -> i64 {
        self.pages.iter().map(|p| p.ttfb_ms).max().unwrap_or(0)
    }

    /// Middle page's TTFB. Reported beside the slowest because one heavy
    /// archive page should not be read as "the site is slow".
    pub fn median_ttfb_ms(&self) -> i64 {
        let mut v: Vec<i64> = self
            .pages
            .iter()
            .filter(|p| p.is_ok())
            .map(|p| p.ttfb_ms)
            .collect();
        if v.is_empty() {
            return 0;
        }
        v.sort_unstable();
        v[v.len() / 2]
    }

    /// Total bytes of the pages themselves — not their images. Named
    /// accordingly wherever it is shown: "page weight" that silently
    /// excluded the images would be the misleading half of the figure.
    pub fn html_bytes(&self) -> i64 {
        self.pages.iter().map(|p| p.bytes).sum()
    }

    pub fn pages_ok(&self) -> usize {
        self.pages.iter().filter(|p| p.is_ok()).count()
    }

    /// Count of findings at `severity`.
    pub fn count(&self, severity: &str) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(status: u16, ttfb: i64) -> SiteCheckPage {
        SiteCheckPage {
            url: "https://example.cz/".into(),
            status,
            ttfb_ms: ttfb,
            total_ms: ttfb + 10,
            bytes: 1000,
        }
    }

    /// "Could not run" and "ran and found nothing" are different answers and
    /// must not render the same. A crawl that never happened reporting "ok"
    /// is the one failure this type exists to prevent.
    #[test]
    fn a_run_that_could_not_happen_is_not_ok() {
        let mut r = SiteCheckReport {
            error: "no document root".into(),
            ..Default::default()
        };
        assert_eq!(r.worst(), "unknown");
        assert!(!r.ran());
        r.error.clear();
        assert!(!r.ran(), "no pages fetched is still not a run");
        r.pages.push(page(200, 40));
        assert!(r.ran());
        assert_eq!(r.worst(), "ok");
    }

    #[test]
    fn worst_takes_the_highest_severity() {
        let mut r = SiteCheckReport {
            pages: vec![page(200, 10)],
            ..Default::default()
        };
        r.findings.push(SiteCheckFinding {
            severity: "warn".into(),
            ..Default::default()
        });
        assert_eq!(r.worst(), "warn");
        r.findings.push(SiteCheckFinding {
            severity: "error".into(),
            ..Default::default()
        });
        assert_eq!(r.worst(), "error");
        assert_eq!(r.count("warn"), 1);
    }

    /// One heavy archive page must not be read as "the site is slow", which
    /// is why the median is reported beside the slowest.
    #[test]
    fn median_ignores_the_one_slow_outlier() {
        let r = SiteCheckReport {
            pages: vec![page(200, 30), page(200, 40), page(200, 5000)],
            ..Default::default()
        };
        assert_eq!(r.median_ttfb_ms(), 40);
        assert_eq!(r.slowest_ttfb_ms(), 5000);
    }

    /// A page that did not answer has no timing to average in.
    #[test]
    fn a_failed_page_does_not_count_towards_the_median() {
        let r = SiteCheckReport {
            pages: vec![page(500, 0), page(200, 100)],
            ..Default::default()
        };
        assert_eq!(r.median_ttfb_ms(), 100);
        assert_eq!(r.pages_ok(), 1);
    }

    #[test]
    fn an_empty_report_reports_zero_rather_than_dividing_by_nothing() {
        let r = SiteCheckReport::default();
        assert_eq!(r.median_ttfb_ms(), 0);
        assert_eq!(r.slowest_ttfb_ms(), 0);
        assert_eq!(r.html_bytes(), 0);
    }
}
