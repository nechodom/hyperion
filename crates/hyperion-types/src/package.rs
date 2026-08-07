//! Care-package ("balíček péče") DTOs — the paid entitlement layer.
//!
//! Sibling of `profile.rs`, with two deliberate differences. A profile is a
//! TEMPLATE whose values are copied onto a hosting once and then forgotten;
//! a package is an ENTITLEMENT that stays bound to the hosting — it records
//! that the customer paid for a set of features, and it is re-asserted
//! continuously, so a paid feature switched off by hand comes back. And a
//! hosting carries exactly one profile but may hold several packages at
//! once, which is why every feature below is tri-state instead of a bool.
//!
//! Nothing here charges anyone: pricing is display text plus the reminder
//! clock the existing billing sweep already reads.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::HostingId;

/// Tri-state intent a package expresses about ONE boolean feature.
///
/// `Leave` — not `Off` — is the default, and it is what makes packages
/// composable: a "Backup" package and a "Monitoring" package can be active
/// on the same hosting without each switching the other's feature off.
/// Only `On`/`Off` are enforced; `Leave` means the package has no opinion,
/// so whatever the customer set themselves survives.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FeatureToggle {
    #[default]
    Leave,
    On,
    Off,
}

impl FeatureToggle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Leave => "leave",
            Self::On => "on",
            Self::Off => "off",
        }
    }

    /// What this package forces the feature to, or `None` when it does not
    /// care. Enforcement and restore code should branch on THIS rather than
    /// on the string — the tri-state only buys anything if "no opinion" is
    /// impossible to confuse with "off".
    pub fn forces(self) -> Option<bool> {
        match self {
            Self::Leave => None,
            Self::On => Some(true),
            Self::Off => Some(false),
        }
    }

    pub fn is_leave(self) -> bool {
        matches!(self, Self::Leave)
    }

    /// Lenient parse of a value read back from the DB or an older agent.
    /// Anything unrecognised becomes `Leave`, the fail-safe direction: a
    /// garbled value makes the package ignore the feature rather than force
    /// a state nobody asked for.
    pub fn from_stored(s: &str) -> Self {
        Self::from_str(s.trim()).unwrap_or(Self::Leave)
    }

    /// Resolve what two packages on the SAME hosting say about one feature.
    /// `On` wins over `Off`, and `Leave` never overrides anything: a
    /// customer paying for a feature must not lose it because another
    /// package they also hold pins it off or says nothing.
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::On, _) | (_, Self::On) => Self::On,
            (Self::Off, _) | (_, Self::Off) => Self::Off,
            _ => Self::Leave,
        }
    }
}

impl fmt::Display for FeatureToggle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FeatureToggle {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "leave" => Ok(Self::Leave),
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            other => Err(format!("unknown feature toggle: {other}")),
        }
    }
}

/// The backup feature — the one that is not a boolean. A package either
/// leaves the site's cadence alone or pins it to one of the four values the
/// per-node scheduled-backup driver understands (`hosting_kv` key
/// `backup_cadence`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackupCadence {
    #[default]
    Leave,
    Off,
    Daily,
    Weekly,
    Monthly,
}

impl BackupCadence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Leave => "leave",
            Self::Off => "off",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }

    /// The value to write into `hosting_kv` `backup_cadence`, or `None`
    /// when the package leaves the cadence alone. `Off` is a real value
    /// here ("this package pins backups off"), which is precisely what
    /// `Leave` is not.
    pub fn kv_value(self) -> Option<&'static str> {
        match self {
            Self::Leave => None,
            other => Some(other.as_str()),
        }
    }

    pub fn is_leave(self) -> bool {
        matches!(self, Self::Leave)
    }

    /// See [`FeatureToggle::from_stored`] — same fail-safe to `Leave`.
    pub fn from_stored(s: &str) -> Self {
        Self::from_str(s.trim()).unwrap_or(Self::Leave)
    }

    /// How much backup this cadence buys. Only used to resolve two packages
    /// that both pin a cadence.
    fn frequency_rank(self) -> u8 {
        match self {
            Self::Leave => 0,
            Self::Off => 1,
            Self::Monthly => 2,
            Self::Weekly => 3,
            Self::Daily => 4,
        }
    }

    /// Resolve two packages on the same hosting: the more frequent cadence
    /// wins, for the same reason `On` beats `Off` — a customer who bought
    /// daily backups keeps them even while holding a package that only
    /// promises monthly.
    pub fn combine(self, other: Self) -> Self {
        if other.frequency_rank() > self.frequency_rank() {
            other
        } else {
            self
        }
    }
}

impl fmt::Display for BackupCadence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BackupCadence {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "leave" => Ok(Self::Leave),
            "off" => Ok(Self::Off),
            "daily" => Ok(Self::Daily),
            "weekly" => Ok(Self::Weekly),
            "monthly" => Ok(Self::Monthly),
            other => Err(format!("unknown backup cadence: {other}")),
        }
    }
}

/// How often the customer receives the CARE REPORT — the periodic e-mail
/// that tells them, in plain language, what the package actually did for
/// their site: attacks blocked, updates applied, backups taken, uptime.
///
/// Modelled on [`BackupCadence`] rather than on [`FeatureToggle`] because
/// it is the same kind of feature: not a boolean, and part of the same
/// tri-state bundle. `Leave` means the package has no opinion, `Off` is a
/// real instruction ("this package pins reports off"), and the three
/// cadences are the values written to `hosting_kv` (`report_cadence`).
///
/// `Monthly` is the cadence to sell: it lines up with the usual billing
/// interval, so the report lands next to the invoice it justifies.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReportCadence {
    #[default]
    Leave,
    Off,
    Weekly,
    Monthly,
    Quarterly,
}

impl ReportCadence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Leave => "leave",
            Self::Off => "off",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Quarterly => "quarterly",
        }
    }

    /// The value to write into `hosting_kv` `report_cadence`, or `None`
    /// when the package leaves the cadence alone. Same split as
    /// [`BackupCadence::kv_value`]: `Off` is a value, `Leave` is not.
    pub fn kv_value(self) -> Option<&'static str> {
        match self {
            Self::Leave => None,
            other => Some(other.as_str()),
        }
    }

    pub fn is_leave(self) -> bool {
        matches!(self, Self::Leave)
    }

    /// See [`FeatureToggle::from_stored`] — same fail-safe to `Leave`.
    pub fn from_stored(s: &str) -> Self {
        Self::from_str(s.trim()).unwrap_or(Self::Leave)
    }

    /// How much reporting this cadence buys. Only used to resolve two
    /// packages that both pin a cadence.
    fn frequency_rank(self) -> u8 {
        match self {
            Self::Leave => 0,
            Self::Off => 1,
            Self::Quarterly => 2,
            Self::Monthly => 3,
            Self::Weekly => 4,
        }
    }

    /// Resolve two packages on the same hosting: the more frequent
    /// cadence wins, for the same reason it does for backups — a customer
    /// who bought a weekly report keeps it while also holding a package
    /// that only promises quarterly.
    pub fn combine(self, other: Self) -> Self {
        if other.frequency_rank() > self.frequency_rank() {
            other
        } else {
            self
        }
    }
}

impl fmt::Display for ReportCadence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReportCadence {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "leave" => Ok(Self::Leave),
            "off" => Ok(Self::Off),
            "weekly" => Ok(Self::Weekly),
            "monthly" => Ok(Self::Monthly),
            "quarterly" => Ok(Self::Quarterly),
            other => Err(format!("unknown report cadence: {other}")),
        }
    }
}

/// The bundle of capabilities a package sells.
///
/// Each field names a feature hyperion already has, and each lives
/// somewhere different — which is exactly why the package layer exists.
/// Activation must go through the existing setter/RPC for each one (they do
/// real work: rewriting vhosts, seeding schedules); this struct only says
/// WHAT the package wants, never how to get there.
///
/// Everything defaults to `Leave`, so a freshly created package is a no-op
/// until the admin turns something on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageFeatures {
    /// Keyless WP minor/patch auto-updates — `hosting_kv` `wp_auto_update`
    /// on the owning node.
    #[serde(default)]
    pub wp_auto_update: FeatureToggle,
    /// Core/plugin checksum + malware scanning — `hosting_kv`
    /// `integrity_scan` on the owning node.
    #[serde(default)]
    pub integrity_scan: FeatureToggle,
    /// Uptime monitoring — `hostings.monitor_enabled`, set via the monitor
    /// RPC.
    #[serde(default)]
    pub monitoring: FeatureToggle,
    /// WAF-lite + wp-admin lock — `hostings.waf_enabled`, set via the
    /// vhost-options RPC.
    #[serde(default)]
    pub hardening: FeatureToggle,
    /// Recurring backups — `hosting_kv` `backup_cadence` on the owning
    /// node.
    #[serde(default)]
    pub backup_cadence: BackupCadence,
    /// Periodic care report to the customer — `hosting_kv`
    /// `report_cadence` on the owning node. The only feature here the
    /// customer SEES; the other five are invisible when they work, which
    /// is precisely what the report exists to fix.
    #[serde(default)]
    pub report_cadence: ReportCadence,
}

impl PackageFeatures {
    /// True when the package forces nothing at all — it sells no
    /// capability, which is worth warning the admin about before they
    /// charge for it.
    pub fn is_noop(&self) -> bool {
        self.forced_count() == 0
    }

    /// How many features this package actually forces. Drives the
    /// "N features" badge.
    pub fn forced_count(&self) -> usize {
        [
            self.wp_auto_update.is_leave(),
            self.integrity_scan.is_leave(),
            self.monitoring.is_leave(),
            self.hardening.is_leave(),
            self.backup_cadence.is_leave(),
            self.report_cadence.is_leave(),
        ]
        .iter()
        .filter(|left_alone| !**left_alone)
        .count()
    }

    /// Fold the bundles of two packages held by the SAME hosting into the
    /// single state to enforce. Per-field rules in [`FeatureToggle::combine`]
    /// and [`BackupCadence::combine`]; the short version is that the
    /// customer keeps the most they paid for.
    pub fn combine(self, other: Self) -> Self {
        Self {
            wp_auto_update: self.wp_auto_update.combine(other.wp_auto_update),
            integrity_scan: self.integrity_scan.combine(other.integrity_scan),
            monitoring: self.monitoring.combine(other.monitoring),
            hardening: self.hardening.combine(other.hardening),
            backup_cadence: self.backup_cadence.combine(other.backup_cadence),
            report_cadence: self.report_cadence.combine(other.report_cadence),
        }
    }
}

/// Lifecycle of one activation. Two states on purpose: a package is either
/// being enforced and carrying a reminder clock, or it is history. Anything
/// richer (past-due, suspended) would be billing-system machinery this
/// feature deliberately does not have.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PackageState {
    #[default]
    Active,
    Cancelled,
}

impl PackageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Lenient parse of a stored value. Unlike the feature toggles this
    /// fails safe to `Cancelled`: a state we cannot read must not be
    /// enforced or billed. The column's CHECK constraint makes it
    /// unreachable in practice.
    pub fn from_stored(s: &str) -> Self {
        Self::from_str(s.trim()).unwrap_or(Self::Cancelled)
    }
}

impl fmt::Display for PackageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PackageState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(format!("unknown package state: {other}")),
        }
    }
}

/// Shape version written into `hosting_packages.prior_state_json`. Bump
/// only for a change an older reader would misinterpret.
pub const PRIOR_STATE_VERSION: u32 = 1;

fn default_prior_state_version() -> u32 {
    PRIOR_STATE_VERSION
}

/// The live values of the five package features for one hosting, read from
/// the owning node immediately before an activation writes to it. Input to
/// [`PackagePriorState::capture`].
///
/// No `Default`: every field must be a value actually observed on the node.
/// A guessed "prior" state is worse than none, because cancellation will
/// faithfully restore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveFeatureState {
    pub wp_auto_update: bool,
    pub integrity_scan: bool,
    pub monitoring: bool,
    pub hardening: bool,
    /// Concrete cadence currently in `hosting_kv` — never `Leave`, which is
    /// a package intent, not a site state ("no cadence" is `Off`).
    pub backup_cadence: BackupCadence,
}

/// What each feature a package FORCES was set to immediately before the
/// activation touched it — the exact thing cancellation restores.
///
/// A field is `Some` only when the package forced that feature. `None`
/// means "this package left the feature alone", and deactivation must leave
/// it alone too. Without that distinction a cancel has only bad options:
/// leave every paid feature switched on forever, or switch off a feature
/// the customer had enabled themselves long before they bought anything.
///
/// Persisted on the ACTIVATION row, never on the definition, so a cancel
/// still restores correctly after the definition was edited or deleted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackagePriorState {
    #[serde(rename = "v", default = "default_prior_state_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wp_auto_update: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_scan: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardening: Option<bool>,
    /// Prior cadence, e.g. `Weekly`. `None` is the "wasn't forced" case —
    /// `Leave` never appears here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_cadence: Option<BackupCadence>,
}

impl Default for PackagePriorState {
    fn default() -> Self {
        Self {
            version: PRIOR_STATE_VERSION,
            wp_auto_update: None,
            integrity_scan: None,
            monitoring: None,
            hardening: None,
            backup_cadence: None,
        }
    }
}

impl PackagePriorState {
    /// Record the pre-activation value of ONLY the features `features`
    /// forces. `live` is what the owning node reports right now.
    pub fn capture(features: &PackageFeatures, live: &LiveFeatureState) -> Self {
        Self {
            version: PRIOR_STATE_VERSION,
            // `.forces().map(...)` rather than a match on on/off: the value
            // recorded is the SITE's, the toggle only decides whether we
            // record it at all.
            wp_auto_update: features
                .wp_auto_update
                .forces()
                .map(|_| live.wp_auto_update),
            integrity_scan: features
                .integrity_scan
                .forces()
                .map(|_| live.integrity_scan),
            monitoring: features.monitoring.forces().map(|_| live.monitoring),
            hardening: features.hardening.forces().map(|_| live.hardening),
            backup_cadence: (!features.backup_cadence.is_leave()).then_some(live.backup_cadence),
        }
    }

    /// Nothing to restore — either the package forced nothing, or the row
    /// predates the field.
    pub fn is_empty(&self) -> bool {
        self.wp_auto_update.is_none()
            && self.integrity_scan.is_none()
            && self.monitoring.is_none()
            && self.hardening.is_none()
            && self.backup_cadence.is_none()
    }
}

/// A package DEFINITION as shown in the panel / returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServicePackage {
    pub id: i64,
    pub name: String,
    /// URL/API handle derived from the name ("pece-plus"); unique.
    pub slug: String,
    /// Customer-facing text — what the customer is buying, not an operator
    /// note.
    pub description: String,
    /// `false` hides the package from the "activate" picker without
    /// touching existing activations.
    pub enabled: bool,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    #[serde(default)]
    pub features: PackageFeatures,
    /// How many hostings currently hold this package (active activations).
    /// Computed at list/get time — drives the "N sites" badge and the
    /// delete-confirm warning. `#[serde(default)]` so an older agent that
    /// doesn't send it deserialises with 0.
    #[serde(default)]
    pub active_count: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ServicePackage {
    /// Pretty price like "490.00 Kč/month" or "—" when free/unpriced.
    pub fn pretty_price(&self) -> String {
        pretty_price(
            self.price_minor,
            self.price_currency.as_deref(),
            self.price_interval.as_deref(),
        )
    }
}

/// Create/update form for a package definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageInput {
    pub name: String,
    /// Empty = derive it from `name` at the web layer.
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub enabled: bool,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    #[serde(default)]
    pub features: PackageFeatures,
}

impl Default for PackageInput {
    /// `enabled` defaults to TRUE — a package the admin just created should
    /// be offerable. Hand-written rather than derived, because
    /// `#[derive(Default)]` would silently make every new package hidden.
    fn default() -> Self {
        Self {
            name: String::new(),
            slug: String::new(),
            description: String::new(),
            enabled: true,
            price_minor: None,
            price_currency: None,
            price_interval: None,
            features: PackageFeatures::default(),
        }
    }
}

/// One ACTIVATION — this hosting holds this package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingPackage {
    pub id: i64,
    pub hosting_id: HostingId,
    /// `None` once the definition was deleted: the record and its price
    /// survive, but there is no bundle left to enforce.
    pub package_id: Option<i64>,
    /// Name of the definition, filled in by the panel/API for display.
    /// Empty when the definition is gone. `#[serde(default)]` so an older
    /// agent still deserialises.
    #[serde(default)]
    pub package_name: String,
    /// Price the customer agreed to, snapshotted at activation — a later
    /// re-price or delete of the definition never rewrites it.
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    /// Reminder clock, same meaning as `ProfileApply::next_billing_at`.
    pub next_billing_at: Option<i64>,
    pub state: PackageState,
    pub activated_at: i64,
    pub cancelled_at: Option<i64>,
    /// See [`PackagePriorState`]. Carried as raw JSON so a shape the panel
    /// does not understand still round-trips to the node that wrote it.
    #[serde(default)]
    pub prior_state_json: Option<String>,
}

impl HostingPackage {
    /// Pretty snapshot price like "490.00 Kč/month" or "—".
    pub fn pretty_price(&self) -> String {
        pretty_price(
            self.price_minor,
            self.price_currency.as_deref(),
            self.price_interval.as_deref(),
        )
    }
}

/// Shared price formatter for definitions and activations, so an edit to
/// the wording can't make the two disagree.
fn pretty_price(minor: Option<i64>, currency: Option<&str>, interval: Option<&str>) -> String {
    match (minor, currency, interval) {
        (Some(m), Some(c), Some(iv)) => {
            let major = m as f64 / 100.0;
            let iv_word = match iv {
                "monthly" => "/month",
                "quarterly" => "/quarter",
                "yearly" => "/year",
                other => other,
            };
            format!("{major:.2} {c}{iv_word}")
        }
        _ => "—".into(),
    }
}

// =====================================================================
//  The care report — what the customer gets for the money.
//
//  A well-run site is invisible: nothing breaks, so nothing is noticed.
//  These are the numbers that make the work visible, and every one of
//  them is OPTIONAL BY MEASUREMENT. `None` means "we did not measure
//  this"; `Some(0)` means "we measured, and nothing happened". Collapsing
//  the two would turn the report into a written overstatement to a paying
//  customer — 100 % uptime for a site nobody ever monitored, "clean" for
//  a scan that never ran. The distinction is produced by
//  `hyperion_state::reports` from the rows themselves; a renderer must
//  never infer it.
// =====================================================================

/// Traffic and footprint over the period, as observed by the hourly
/// stats sampler.
///
/// Absent entirely (the field is `Option<CareUsage>`) when the sampler
/// produced no row for this site in the period — a site that was never
/// sampled has no traffic figure, which is not the same as no traffic.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CareUsage {
    /// Inbound bytes. `None` when the node's nginx log format carries no
    /// request size (the default one does not), which is indistinguishable
    /// in the data from a real zero — and "0 B received" on a site serving
    /// traffic is a claim we cannot make.
    #[serde(default)]
    pub bw_in_bytes: Option<i64>,
    pub bw_out_bytes: i64,
    pub requests: i64,
    /// Peak disk footprint seen in the period. A level, not a flow: it is
    /// the MAX of the samples, never their sum.
    pub disk_peak_bytes: i64,
    /// Days of the period that actually carry a sample, and how many days
    /// the period has. The traffic figures cover `days_counted` days —
    /// print both, so a month with a four-day gap in sampling says so
    /// instead of quietly reporting 26 days of traffic as a month.
    pub days_counted: i64,
    pub days_in_period: i64,
}

impl CareUsage {
    /// True when every day of the period carries a sample — the only case
    /// where the traffic numbers may be presented as the period's total
    /// without a coverage caveat.
    pub fn is_complete(&self) -> bool {
        self.days_counted >= self.days_in_period
    }
}

/// Uptime checks over the period.
///
/// Both counts travel together and the ratio is derived, never stored:
/// the whole point is that a period with zero samples can produce no
/// percentage at all rather than a 0/0 that renders as a flattering
/// 100 %.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CareUptime {
    pub samples: i64,
    pub successes: i64,
    /// Days of the period that carry at least one check, and how many days
    /// the period has — the same coverage pair [`CareUsage`] carries, and
    /// for the same reason.
    ///
    /// Zero samples already means "not monitored", but PARTIAL monitoring
    /// used to be invisible: a node offline for five days records no
    /// checks for them, and the surviving 25 days were divided among
    /// themselves into "100.00 %, no outage" — a perfect score computed
    /// from the days the site was up, printed beside a traffic section
    /// that admitted the same five days were missing.
    #[serde(default)]
    pub days_counted: i64,
    #[serde(default)]
    pub days_in_period: i64,
}

impl CareUptime {
    /// Success ratio in hundredths of a percent (9995 = 99.95 %), or
    /// `None` when there is nothing to divide by.
    pub fn success_ratio_x100(&self) -> Option<i64> {
        (self.samples > 0).then(|| self.successes * 10_000 / self.samples)
    }

    /// True when every day of the period carries at least one check — the
    /// only case where the percentage may be presented as the period's
    /// availability without a coverage caveat.
    ///
    /// `days_in_period == 0` is the pre-coverage wire shape (an older node
    /// serialising without these fields). Treating it as complete keeps
    /// the sentence it used to print rather than inventing a caveat about
    /// a denominator we did not receive.
    pub fn is_complete(&self) -> bool {
        self.days_in_period == 0 || self.days_counted >= self.days_in_period
    }

    /// How many checks failed. Named the way the customer thinks about
    /// it: outages, not "non-successes".
    pub fn failures(&self) -> i64 {
        (self.samples - self.successes).max(0)
    }
}

/// Backups over the period.
///
/// Absent entirely when the site has no backup history AT ALL — backups
/// were evidently never running, and "0 backups" would read as a failure
/// rather than as a feature the customer never bought. Present with
/// `taken == 0` is the genuinely alarming case: this site does take
/// backups, and none happened in this period.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CareBackups {
    pub taken: i64,
    pub failed: i64,
    /// Finish time of the last successful backup IN THE PERIOD. `None`
    /// when none succeeded — the report must not reach outside the period
    /// for a comforting older date.
    #[serde(default)]
    pub last_success_at: Option<i64>,
}

/// Outcome of the file-integrity + malware scan.
///
/// Absent entirely when no scan ran inside the period. The two `*_ran`
/// flags carry the same honesty inside a scan that did happen: zero
/// malware hits with `malware_scan_ran == false` means "not looked for",
/// never "none found".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CareIntegrity {
    pub scanned_at: i64,
    /// Whether the core/plugin checksum comparison actually ran.
    pub checksums_ran: bool,
    /// Whether a malware scanner actually walked the docroot. False is a
    /// normal state (no scanner installed on the node), not an error.
    pub malware_scan_ran: bool,
    pub core_issues: i64,
    pub plugin_issues: i64,
    pub malware_hits: i64,
}

impl CareIntegrity {
    pub fn total_findings(&self) -> i64 {
        self.core_issues + self.plugin_issues + self.malware_hits
    }

    /// True only when BOTH signals ran and both came back empty — the
    /// same rule as `WpIntegrityScanResult::is_clean`. A scan half of
    /// which could not run is "unknown", and the report must say so.
    pub fn is_clean(&self) -> bool {
        self.checksums_ran && self.malware_scan_ran && self.total_findings() == 0
    }
}

/// One hosting's care report for ONE period.
///
/// `[period_start, period_end)` is half-open, so two adjacent reports can
/// never both claim the same event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CareReport {
    pub hosting_id: HostingId,
    pub domain: String,
    pub period_start: i64,
    pub period_end: i64,
    /// Ban events attributed to THIS site. `None` when the ban subsystem
    /// was not running at all for the period (`[fail2ban] enabled =
    /// false`), which the database cannot see and the caller must supply:
    /// with the scanner off, zero bans means nobody was watching.
    #[serde(default)]
    pub attacks_blocked: Option<i64>,
    /// When protection demonstrably started watching THIS site, if that
    /// is later than `period_start`.
    ///
    /// `attacks_blocked` alone cannot tell a quiet month from a month
    /// nobody watched for, and the enabled/disabled flags behind it are
    /// present-tense: a site protected only since the 29th still reported
    /// "0 — protection ran for the whole period". This is the evidence
    /// that bounds the claim, stamped by the scanner itself rather than
    /// inferred from a toggle, so it survives the toggle being flipped
    /// back and forth. `None` means the whole period is covered.
    #[serde(default)]
    pub attacks_covered_since: Option<i64>,
    /// Plugin/theme updates applied. `None` when the audit log cannot
    /// account for the whole period (retention purged part of it, or the
    /// node is younger than the period) — an incomplete count presented
    /// as a total would understate the work done.
    #[serde(default)]
    pub updates_applied: Option<i64>,
    #[serde(default)]
    pub usage: Option<CareUsage>,
    #[serde(default)]
    pub uptime: Option<CareUptime>,
    #[serde(default)]
    pub backups: Option<CareBackups>,
    #[serde(default)]
    pub integrity: Option<CareIntegrity>,
}

impl CareReport {
    /// An empty report for a period, with every metric unmeasured. The
    /// honest starting point: a caller that fails to fill a section
    /// leaves it saying "not measured", never zero.
    pub fn empty(
        hosting_id: HostingId,
        domain: String,
        period_start: i64,
        period_end: i64,
    ) -> Self {
        Self {
            hosting_id,
            domain,
            period_start,
            period_end,
            attacks_blocked: None,
            // No count ⇒ nothing to bound. The caller sets this only
            // alongside a count it is about to qualify.
            attacks_covered_since: None,
            updates_applied: None,
            usage: None,
            uptime: None,
            backups: None,
            integrity: None,
        }
    }

    /// True when not a single section could be measured. Worth checking
    /// before sending: a report that says "not measured" six times tells
    /// the customer nothing and invites the question of what they pay
    /// for.
    pub fn is_entirely_unmeasured(&self) -> bool {
        self.attacks_blocked.is_none()
            && self.updates_applied.is_none()
            && self.usage.is_none()
            && self.uptime.is_none()
            && self.backups.is_none()
            && self.integrity.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_str_round_trip() {
        for t in [FeatureToggle::Leave, FeatureToggle::On, FeatureToggle::Off] {
            assert_eq!(FeatureToggle::from_str(t.as_str()).unwrap(), t);
            assert_eq!(FeatureToggle::from_stored(t.as_str()), t);
        }
    }

    #[test]
    fn cadence_str_round_trip() {
        for c in [
            BackupCadence::Leave,
            BackupCadence::Off,
            BackupCadence::Daily,
            BackupCadence::Weekly,
            BackupCadence::Monthly,
        ] {
            assert_eq!(BackupCadence::from_str(c.as_str()).unwrap(), c);
            assert_eq!(BackupCadence::from_stored(c.as_str()), c);
        }
    }

    #[test]
    fn report_cadence_str_round_trip() {
        for c in [
            ReportCadence::Leave,
            ReportCadence::Off,
            ReportCadence::Weekly,
            ReportCadence::Monthly,
            ReportCadence::Quarterly,
        ] {
            assert_eq!(ReportCadence::from_str(c.as_str()).unwrap(), c);
            assert_eq!(ReportCadence::from_stored(c.as_str()), c);
        }
        // Same fail-safe as every other stored feature value: unreadable ⇒
        // the package has no opinion, so nobody starts getting mail they
        // did not buy.
        assert_eq!(ReportCadence::from_stored("daily"), ReportCadence::Leave);
        assert_eq!(ReportCadence::from_stored(""), ReportCadence::Leave);
        assert_eq!(
            ReportCadence::from_stored(" monthly "),
            ReportCadence::Monthly
        );
        assert_eq!(ReportCadence::Off.kv_value(), Some("off"));
        assert_eq!(ReportCadence::Leave.kv_value(), None);
    }

    #[test]
    fn report_cadence_combine_keeps_the_more_frequent() {
        assert_eq!(
            ReportCadence::Quarterly.combine(ReportCadence::Monthly),
            ReportCadence::Monthly
        );
        assert_eq!(
            ReportCadence::Monthly.combine(ReportCadence::Quarterly),
            ReportCadence::Monthly
        );
        assert_eq!(
            ReportCadence::Weekly.combine(ReportCadence::Monthly),
            ReportCadence::Weekly
        );
        // A package that pins reports off cannot silence one that sells
        // them, and `Leave` never overrides anything.
        assert_eq!(
            ReportCadence::Off.combine(ReportCadence::Quarterly),
            ReportCadence::Quarterly
        );
        assert_eq!(
            ReportCadence::Leave.combine(ReportCadence::Off),
            ReportCadence::Off
        );
    }

    #[test]
    fn features_serde_round_trip() {
        let f = PackageFeatures {
            wp_auto_update: FeatureToggle::On,
            integrity_scan: FeatureToggle::Off,
            monitoring: FeatureToggle::Leave,
            hardening: FeatureToggle::On,
            backup_cadence: BackupCadence::Weekly,
            report_cadence: ReportCadence::Monthly,
        };
        let s = serde_json::to_string(&f).expect("ser");
        let back: PackageFeatures = serde_json::from_str(&s).expect("de");
        assert_eq!(f, back);
        // The wire form is the same lowercase vocabulary the DB stores, so
        // a value can move between column and JSON without translation.
        assert!(s.contains("\"wp_auto_update\":\"on\""), "{s}");
        assert!(s.contains("\"backup_cadence\":\"weekly\""), "{s}");
        assert!(s.contains("\"report_cadence\":\"monthly\""), "{s}");
    }

    #[test]
    fn missing_features_default_to_leave() {
        // An older agent sending a partial bundle must not be read as
        // "force everything off".
        let f: PackageFeatures = serde_json::from_str("{}").expect("de");
        assert_eq!(f, PackageFeatures::default());
        assert!(f.is_noop());
        assert_eq!(f.wp_auto_update.forces(), None);
        assert_eq!(f.backup_cadence.kv_value(), None);
        assert_eq!(f.report_cadence.kv_value(), None);
    }

    #[test]
    fn leave_is_not_off() {
        assert_eq!(FeatureToggle::Off.forces(), Some(false));
        assert_eq!(FeatureToggle::Leave.forces(), None);
        assert_eq!(BackupCadence::Off.kv_value(), Some("off"));
        assert_eq!(BackupCadence::Leave.kv_value(), None);
    }

    #[test]
    fn garbage_stored_value_falls_back_to_leave() {
        assert_eq!(FeatureToggle::from_stored(""), FeatureToggle::Leave);
        assert_eq!(FeatureToggle::from_stored("ON"), FeatureToggle::Leave);
        assert_eq!(BackupCadence::from_stored("hourly"), BackupCadence::Leave);
        // Whitespace is not garbage — a padded column value still parses.
        assert_eq!(FeatureToggle::from_stored(" on "), FeatureToggle::On);
    }

    #[test]
    fn combining_two_packages_keeps_the_most_paid_for() {
        let backups = PackageFeatures {
            backup_cadence: BackupCadence::Daily,
            ..Default::default()
        };
        let monitoring = PackageFeatures {
            monitoring: FeatureToggle::On,
            backup_cadence: BackupCadence::Monthly,
            ..Default::default()
        };
        let merged = backups.combine(monitoring);
        assert_eq!(merged.monitoring, FeatureToggle::On);
        assert_eq!(merged.backup_cadence, BackupCadence::Daily);
        // The feature neither package speaks about stays untouched.
        assert_eq!(merged.hardening, FeatureToggle::Leave);
        // On beats Off, whichever side it comes from.
        let on = PackageFeatures {
            hardening: FeatureToggle::On,
            ..Default::default()
        };
        let off = PackageFeatures {
            hardening: FeatureToggle::Off,
            ..Default::default()
        };
        assert_eq!(on.combine(off).hardening, FeatureToggle::On);
        assert_eq!(off.combine(on).hardening, FeatureToggle::On);
    }

    #[test]
    fn forced_count_counts_only_non_leave() {
        let f = PackageFeatures {
            wp_auto_update: FeatureToggle::On,
            hardening: FeatureToggle::Off,
            backup_cadence: BackupCadence::Daily,
            report_cadence: ReportCadence::Monthly,
            ..Default::default()
        };
        assert_eq!(f.forced_count(), 4);
        assert!(!f.is_noop());
        // A package that sells only the report is still a real package.
        let report_only = PackageFeatures {
            report_cadence: ReportCadence::Monthly,
            ..Default::default()
        };
        assert_eq!(report_only.forced_count(), 1);
        assert!(!report_only.is_noop());
    }

    #[test]
    fn prior_state_records_only_forced_features() {
        let features = PackageFeatures {
            wp_auto_update: FeatureToggle::On,
            backup_cadence: BackupCadence::Daily,
            ..Default::default()
        };
        let live = LiveFeatureState {
            wp_auto_update: false,
            integrity_scan: true,
            monitoring: true,
            hardening: false,
            backup_cadence: BackupCadence::Weekly,
        };
        let prior = PackagePriorState::capture(&features, &live);
        // Forced → the SITE's prior value is recorded, not the package's.
        assert_eq!(prior.wp_auto_update, Some(false));
        assert_eq!(prior.backup_cadence, Some(BackupCadence::Weekly));
        // Left alone → absent, so a cancel never touches it. `monitoring`
        // is the load-bearing case: the customer had it on themselves and
        // must keep it.
        assert_eq!(prior.monitoring, None);
        assert_eq!(prior.integrity_scan, None);
        assert_eq!(prior.hardening, None);
        assert!(!prior.is_empty());

        let s = serde_json::to_string(&prior).expect("ser");
        assert!(!s.contains("monitoring"), "absent keys stay absent: {s}");
        let back: PackagePriorState = serde_json::from_str(&s).expect("de");
        assert_eq!(prior, back);
    }

    #[test]
    fn prior_state_of_a_noop_package_is_empty() {
        let live = LiveFeatureState {
            wp_auto_update: true,
            integrity_scan: true,
            monitoring: true,
            hardening: true,
            backup_cadence: BackupCadence::Daily,
        };
        let prior = PackagePriorState::capture(&PackageFeatures::default(), &live);
        assert!(prior.is_empty());
        assert_eq!(serde_json::to_string(&prior).expect("ser"), r#"{"v":1}"#);
    }

    #[test]
    fn prior_state_without_version_still_parses() {
        // Rows written before the tag existed must remain restorable.
        let back: PackagePriorState = serde_json::from_str(r#"{"monitoring":true}"#).expect("de");
        assert_eq!(back.version, PRIOR_STATE_VERSION);
        assert_eq!(back.monitoring, Some(true));
        assert_eq!(back.wp_auto_update, None);
    }

    #[test]
    fn package_state_round_trip_and_fallback() {
        for s in [PackageState::Active, PackageState::Cancelled] {
            assert_eq!(PackageState::from_str(s.as_str()).unwrap(), s);
            assert_eq!(PackageState::from_stored(s.as_str()), s);
        }
        // Unreadable state ⇒ not enforced, not billed.
        assert_eq!(PackageState::from_stored("paused"), PackageState::Cancelled);
    }

    #[test]
    fn pretty_price_needs_all_three_parts() {
        let mut p = ServicePackage {
            id: 1,
            name: "Péče Plus".into(),
            slug: "pece-plus".into(),
            description: String::new(),
            enabled: true,
            price_minor: Some(49_000),
            price_currency: Some("Kč".into()),
            price_interval: Some("monthly".into()),
            features: PackageFeatures::default(),
            active_count: 0,
            created_at: 0,
            updated_at: 0,
        };
        assert_eq!(p.pretty_price(), "490.00 Kč/month");
        p.price_interval = None;
        assert_eq!(p.pretty_price(), "—");
    }

    #[test]
    fn new_package_input_is_offerable() {
        assert!(
            PackageInput::default().enabled,
            "a package created from the default form must not be born hidden"
        );
    }

    #[test]
    fn activation_serde_round_trip() {
        let a = HostingPackage {
            id: 7,
            hosting_id: HostingId("h1".into()),
            package_id: Some(3),
            package_name: "Péče Plus".into(),
            price_minor: Some(49_000),
            price_currency: Some("Kč".into()),
            price_interval: Some("monthly".into()),
            next_billing_at: Some(1_800_000_000),
            state: PackageState::Active,
            activated_at: 1_700_000_000,
            cancelled_at: None,
            prior_state_json: Some(r#"{"v":1,"monitoring":false}"#.into()),
        };
        let s = serde_json::to_string(&a).expect("ser");
        let back: HostingPackage = serde_json::from_str(&s).expect("de");
        assert_eq!(a, back);
        assert_eq!(back.pretty_price(), "490.00 Kč/month");
    }

    // ---------------------------------------------------------- report

    #[test]
    fn an_empty_report_measures_nothing() {
        // The load-bearing default: a section the assembler never filled
        // says "not measured", so a bug upstream can only ever cost the
        // customer information — never invent a reassuring number.
        let r = CareReport::empty(HostingId("h1".into()), "a.cz".into(), 100, 200);
        assert!(r.is_entirely_unmeasured());
        assert_eq!(r.attacks_blocked, None);
        assert_eq!(r.uptime, None);
        assert_eq!(r.integrity, None);
    }

    #[test]
    fn zero_is_not_the_same_as_unmeasured() {
        let mut r = CareReport::empty(HostingId("h1".into()), "a.cz".into(), 100, 200);
        r.attacks_blocked = Some(0);
        assert!(
            !r.is_entirely_unmeasured(),
            "'we watched, nothing happened' is a measurement"
        );
        // …and it survives the wire as such: `null` and `0` must not
        // collapse into each other on the way to the node that renders.
        let s = serde_json::to_string(&r).expect("ser");
        assert!(s.contains("\"attacks_blocked\":0"), "{s}");
        assert!(s.contains("\"uptime\":null"), "{s}");
        let back: CareReport = serde_json::from_str(&s).expect("de");
        assert_eq!(back, r);
    }

    #[test]
    fn uptime_without_samples_yields_no_percentage() {
        // The exact failure this type exists to prevent: 0/0 rendered as
        // a flattering 100 %.
        let none = CareUptime::default();
        assert_eq!(none.success_ratio_x100(), None);
        let good = CareUptime {
            samples: 2000,
            successes: 1999,
            days_counted: 30,
            days_in_period: 30,
        };
        assert_eq!(good.success_ratio_x100(), Some(9995));
        assert_eq!(good.failures(), 1);
        assert!(good.is_complete());
    }

    /// A perfect score computed from part of the period is still only a
    /// score for that part. The five days a node spent offline record no
    /// checks, so they cannot fail any — and dividing the survivors among
    /// themselves yields exactly 100 %.
    #[test]
    fn uptime_with_a_sampling_gap_is_not_complete() {
        let gappy = CareUptime {
            samples: 7200,
            successes: 7200,
            days_counted: 25,
            days_in_period: 30,
        };
        assert_eq!(gappy.success_ratio_x100(), Some(10_000));
        assert!(
            !gappy.is_complete(),
            "25 of 30 days must not present as the period's availability"
        );

        // Wire compatibility: a node that predates these fields sends no
        // denominator. Inventing a caveat from a zero would be its own
        // kind of lie, so the letter keeps the sentence it always printed.
        let old_wire: CareUptime =
            serde_json::from_str(r#"{"samples":100,"successes":100}"#).expect("de");
        assert_eq!(old_wire.days_in_period, 0);
        assert!(old_wire.is_complete());
    }

    #[test]
    fn integrity_is_clean_only_when_both_signals_ran() {
        // No findings, but the malware scanner never ran ⇒ "unknown".
        let half = CareIntegrity {
            scanned_at: 10,
            checksums_ran: true,
            malware_scan_ran: false,
            ..Default::default()
        };
        assert!(!half.is_clean(), "an absent scanner never means clean");
        assert_eq!(half.total_findings(), 0);

        let full = CareIntegrity {
            malware_scan_ran: true,
            ..half
        };
        assert!(full.is_clean());

        let dirty = CareIntegrity {
            malware_hits: 1,
            ..full
        };
        assert!(!dirty.is_clean());
        assert_eq!(dirty.total_findings(), 1);
    }

    #[test]
    fn usage_coverage_is_explicit() {
        let full = CareUsage {
            days_counted: 31,
            days_in_period: 31,
            ..Default::default()
        };
        assert!(full.is_complete());
        let gappy = CareUsage {
            days_counted: 26,
            ..full
        };
        assert!(
            !gappy.is_complete(),
            "26 sampled days must not be presented as a month"
        );
    }
}
