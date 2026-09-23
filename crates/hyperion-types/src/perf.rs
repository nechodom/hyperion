//! Page performance: how fast the site is and how it scores on the metrics
//! Google grades it by (Core Web Vitals).
//!
//! Two very different kinds of number live here and the difference is
//! load-bearing, so they never share a field:
//!
//! * **Lab** measurements are one synthetic load of the page from a machine
//!   under controlled conditions — Lighthouse, whether run locally or by
//!   Google's PageSpeed Insights. Reproducible, available for any site, and
//!   an approximation of what a real visitor gets.
//! * **Field** measurements are what real visitors actually experienced,
//!   aggregated by Google from Chrome users (the CrUX dataset). This is the
//!   truth, but it only exists for a site with enough traffic, so it is
//!   frequently absent — and absent is not zero.
//!
//! Every metric is an `Option`: a value that could not be measured is `None`,
//! never a fabricated zero, the same honesty rule the care report follows
//! everywhere else.

use serde::{Deserialize, Serialize};

/// One set of Core Web Vitals, either lab or field. Milliseconds and a
/// CLS scaled by 1000 (`0.10` → `100`) so the whole struct stays integer and
/// `Eq` — floats would forbid that and buy nothing at this precision.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwvMetrics {
    /// Largest Contentful Paint — when the main content finished painting.
    #[serde(default)]
    pub lcp_ms: Option<i64>,
    /// Cumulative Layout Shift × 1000. How much the page jumped around while
    /// loading; lower is better.
    #[serde(default)]
    pub cls_x1000: Option<i64>,
    /// Interaction to Next Paint — responsiveness to input. FIELD only:
    /// there is no lab equivalent, which is why lab reports fall back to TBT.
    #[serde(default)]
    pub inp_ms: Option<i64>,
    /// Total Blocking Time — the LAB stand-in for responsiveness.
    #[serde(default)]
    pub tbt_ms: Option<i64>,
    /// First Contentful Paint — when the first pixel of content appeared.
    #[serde(default)]
    pub fcp_ms: Option<i64>,
}

/// Google's three-band verdict for one metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vital {
    Good,
    NeedsImprovement,
    Poor,
}

impl Vital {
    /// The word for a customer letter or a card pill.
    pub fn label(self) -> &'static str {
        match self {
            Vital::Good => "good",
            Vital::NeedsImprovement => "needs-improvement",
            Vital::Poor => "poor",
        }
    }

    fn band(value: i64, good: i64, poor: i64) -> Vital {
        if value <= good {
            Vital::Good
        } else if value <= poor {
            Vital::NeedsImprovement
        } else {
            Vital::Poor
        }
    }
}

impl CwvMetrics {
    /// Anything here at all?
    pub fn is_empty(&self) -> bool {
        self.lcp_ms.is_none()
            && self.cls_x1000.is_none()
            && self.inp_ms.is_none()
            && self.tbt_ms.is_none()
            && self.fcp_ms.is_none()
    }

    /// LCP against Google's thresholds (good ≤ 2.5 s, poor > 4 s).
    pub fn lcp_rating(&self) -> Option<Vital> {
        self.lcp_ms.map(|v| Vital::band(v, 2500, 4000))
    }

    /// CLS against Google's thresholds (good ≤ 0.10, poor > 0.25).
    pub fn cls_rating(&self) -> Option<Vital> {
        self.cls_x1000.map(|v| Vital::band(v, 100, 250))
    }

    /// INP against Google's thresholds (good ≤ 200 ms, poor > 500 ms).
    pub fn inp_rating(&self) -> Option<Vital> {
        self.inp_ms.map(|v| Vital::band(v, 200, 500))
    }

    /// CLS as its real decimal, for display (`100` → `"0.10"`).
    pub fn cls_display(&self) -> Option<String> {
        self.cls_x1000
            .map(|v| format!("{}.{:02}", v / 1000, (v % 1000) / 10))
    }
}

/// The result of one Core Web Vitals measurement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwvResult {
    /// Unix seconds when it was measured. 0 = never.
    #[serde(default)]
    pub measured_at: i64,
    /// `psi` (Google PageSpeed Insights) or `lighthouse` (local).
    #[serde(default)]
    pub source: String,
    /// `mobile` or `desktop` — the profile the lab run used.
    #[serde(default)]
    pub strategy: String,
    /// Real-visitor data (CrUX). Present only for a site with enough traffic.
    #[serde(default)]
    pub field: Option<CwvMetrics>,
    /// The synthetic run. Present whenever the measurement ran at all.
    #[serde(default)]
    pub lab: Option<CwvMetrics>,
    /// Lighthouse performance score, 0..100.
    #[serde(default)]
    pub perf_score: Option<i64>,
    /// Why the measurement produced nothing. Empty on success.
    #[serde(default)]
    pub error: String,
}

impl CwvResult {
    /// Did the measurement produce any numbers?
    pub fn has_data(&self) -> bool {
        self.field.as_ref().is_some_and(|m| !m.is_empty())
            || self.lab.as_ref().is_some_and(|m| !m.is_empty())
    }

    /// Field first, lab as the fallback — the set a summary should quote.
    pub fn best(&self) -> Option<&CwvMetrics> {
        self.field
            .as_ref()
            .filter(|m| !m.is_empty())
            .or(self.lab.as_ref().filter(|m| !m.is_empty()))
    }

    /// Is `best()` real-visitor data?
    pub fn best_is_field(&self) -> bool {
        self.field.as_ref().is_some_and(|m| !m.is_empty())
    }
}

/// The performance section of the care report and the site's Performance card.
///
/// Two halves: what a fetch of the pages found (fast/slow, rendered/broken —
/// from the existing site check, run on the node), and the Core Web Vitals
/// (from Google or a local Lighthouse). Either can be `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarePerformance {
    /// Unix seconds of the site-check fetch. 0 when no fetch is on record.
    #[serde(default)]
    pub checked_at: i64,
    #[serde(default)]
    pub pages_checked: i64,
    #[serde(default)]
    pub pages_ok: i64,
    /// Broken things found while fetching (dead pages, 404 links, missing
    /// images): the "does it still render" half.
    #[serde(default)]
    pub findings_error: i64,
    #[serde(default)]
    pub findings_warn: i64,
    /// Server think-time, from inside the node (no network): the honest
    /// "how fast is the server" number.
    #[serde(default)]
    pub median_ttfb_ms: i64,
    #[serde(default)]
    pub slowest_ttfb_ms: i64,
    #[serde(default)]
    pub html_bytes: i64,
    /// Core Web Vitals. `None` when the source is off or has not run.
    #[serde(default)]
    pub cwv: Option<CwvResult>,
}

impl CarePerformance {
    /// Was the render/speed half measured?
    pub fn has_site_check(&self) -> bool {
        self.checked_at > 0 && self.pages_checked > 0
    }
}

/// The whole Performance card of a site, in one round trip to the owning node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceView {
    #[serde(default)]
    pub care: CarePerformance,
    /// `off`, `psi` or `lighthouse` — the node's Core Web Vitals source.
    #[serde(default)]
    pub cwv_source: String,
    /// `mobile` or `desktop`.
    #[serde(default)]
    pub strategy: String,
    /// Is a local Lighthouse usable on the node? (Only meaningful when the
    /// source is `lighthouse`.)
    #[serde(default)]
    pub lighthouse_available: bool,
    /// Is a PSI API key configured? (The key itself never leaves the node.)
    #[serde(default)]
    pub psi_key_set: bool,
}

/// `[performance]` as the Settings page renders it. The API key is never
/// carried — only whether one is set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceConfigView {
    #[serde(default)]
    pub cwv_source: String,
    #[serde(default)]
    pub strategy: String,
    #[serde(default)]
    pub psi_key_set: bool,
    #[serde(default)]
    pub lighthouse_available: bool,
    /// How often to auto-measure, in days (7/14/30, or 0 = on demand only).
    #[serde(default)]
    pub cwv_interval_days: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratings_follow_google_thresholds() {
        let m = CwvMetrics {
            lcp_ms: Some(2000),
            cls_x1000: Some(50),
            inp_ms: Some(150),
            ..Default::default()
        };
        assert_eq!(m.lcp_rating(), Some(Vital::Good));
        assert_eq!(m.cls_rating(), Some(Vital::Good));
        assert_eq!(m.inp_rating(), Some(Vital::Good));

        let bad = CwvMetrics {
            lcp_ms: Some(5000),
            cls_x1000: Some(300),
            inp_ms: Some(600),
            ..Default::default()
        };
        assert_eq!(bad.lcp_rating(), Some(Vital::Poor));
        assert_eq!(bad.cls_rating(), Some(Vital::Poor));
        assert_eq!(bad.inp_rating(), Some(Vital::Poor));

        let mid = CwvMetrics {
            lcp_ms: Some(3000),
            cls_x1000: Some(150),
            inp_ms: Some(300),
            ..Default::default()
        };
        assert_eq!(mid.lcp_rating(), Some(Vital::NeedsImprovement));
        assert_eq!(mid.cls_rating(), Some(Vital::NeedsImprovement));
        assert_eq!(mid.inp_rating(), Some(Vital::NeedsImprovement));
    }

    #[test]
    fn boundaries_land_in_the_lower_band() {
        // Exactly at the "good" ceiling is still good; one past it is not.
        let at = CwvMetrics {
            lcp_ms: Some(2500),
            cls_x1000: Some(100),
            inp_ms: Some(200),
            ..Default::default()
        };
        assert_eq!(at.lcp_rating(), Some(Vital::Good));
        assert_eq!(at.cls_rating(), Some(Vital::Good));
        assert_eq!(at.inp_rating(), Some(Vital::Good));
    }

    #[test]
    fn cls_displays_as_a_decimal() {
        assert_eq!(
            CwvMetrics {
                cls_x1000: Some(100),
                ..Default::default()
            }
            .cls_display()
            .as_deref(),
            Some("0.10")
        );
        assert_eq!(
            CwvMetrics {
                cls_x1000: Some(5),
                ..Default::default()
            }
            .cls_display()
            .as_deref(),
            Some("0.00")
        );
        assert_eq!(
            CwvMetrics {
                cls_x1000: Some(1234),
                ..Default::default()
            }
            .cls_display()
            .as_deref(),
            Some("1.23")
        );
    }

    #[test]
    fn best_prefers_field_but_falls_back_to_lab() {
        let lab = CwvMetrics {
            lcp_ms: Some(3000),
            ..Default::default()
        };
        let field = CwvMetrics {
            lcp_ms: Some(2000),
            ..Default::default()
        };
        let r = CwvResult {
            lab: Some(lab.clone()),
            field: Some(field.clone()),
            ..Default::default()
        };
        assert_eq!(r.best(), Some(&field));
        assert!(r.best_is_field());

        let lab_only = CwvResult {
            lab: Some(lab.clone()),
            ..Default::default()
        };
        assert_eq!(lab_only.best(), Some(&lab));
        assert!(!lab_only.best_is_field());

        // An empty field block is not a data source.
        let empty_field = CwvResult {
            lab: Some(lab.clone()),
            field: Some(CwvMetrics::default()),
            ..Default::default()
        };
        assert_eq!(empty_field.best(), Some(&lab));
        assert!(!empty_field.best_is_field());
        assert!(empty_field.has_data());
        assert!(!CwvResult::default().has_data());
    }
}
