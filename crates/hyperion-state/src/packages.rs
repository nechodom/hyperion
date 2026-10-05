//! `service_packages` + `hosting_packages` — care packages, the paid
//! entitlement layer over features hyperion already has (migration 057).
//!
//! Sibling of `profiles.rs`, and separate from it for one structural
//! reason: `hosting_profile_apply` keys on hosting_id, so a hosting carries
//! exactly ONE profile. An activation here is its own row, so a hosting can
//! hold several packages at once and they compose.
//!
//! This module stores intent and never enforces it. Turning a package's
//! features on happens through the existing per-feature setters/RPCs (they
//! rewrite vhosts, seed schedules, …); a raw write here would record a
//! promise the node never kept.

use crate::db::StateError;
use hyperion_types::package::{
    BackupCadence, FeatureToggle, PackageFeatures, PackageState, ReportCadence,
};
use hyperion_types::HostingId;
use sqlx::SqlitePool;

/// A row of `service_packages` — the definition an admin created.
///
/// The tri-state feature columns stay `String` here because `FromRow` maps
/// by column name; [`PackageRow::features`] is the one place they become
/// typed, so nothing downstream compares raw strings.
#[derive(Debug, Clone, PartialEq, Eq, Default, sqlx::FromRow)]
pub struct PackageRow {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub description: String,
    /// 0/1 — read it through [`PackageRow::is_enabled`].
    pub enabled: i64,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub feat_wp_auto_update: String,
    pub feat_integrity_scan: String,
    pub feat_monitoring: String,
    pub feat_hardening: String,
    pub feat_backup_cadence: String,
    pub feat_report_cadence: String,
    /// Migration 071 — custom backup FREQUENCY (days, used when
    /// `feat_backup_cadence = 'custom'`) and RETENTION overrides. Seeded into
    /// the site's hosting_kv while the package is active; 0 = the preset /
    /// node-wide rule. `#[sqlx(default)]` so an older row (or a partial
    /// SELECT) reads 0 rather than failing the map.
    #[sqlx(default)]
    pub feat_backup_interval_days: i64,
    #[sqlx(default)]
    pub feat_backup_keep_days: i64,
    #[sqlx(default)]
    pub feat_backup_keep_last: i64,
    /// Default letter language for this package's customers. Empty = no
    /// opinion. Column order matters: this sits before the timestamps, matching
    /// SELECT_PACKAGES and the migration.
    pub letters_lang: String,
    /// The monthly checklist, as a JSON array of {id,label,detail}. Empty = the
    /// built-in four.
    pub check_items: String,
    /// Migration 075 — care-report sections the plan leaves out (comma list).
    /// Empty = every section is sent.
    pub report_omit: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl PackageRow {
    /// Whether the package may still be offered. Disabled definitions keep
    /// every existing activation running.
    pub fn is_enabled(&self) -> bool {
        self.enabled != 0
    }

    /// The typed feature bundle. Unparseable column values degrade to
    /// "leave" (see `FeatureToggle::from_stored`), so a bad row makes the
    /// package inert rather than forcing something nobody bought.
    pub fn features(&self) -> PackageFeatures {
        PackageFeatures {
            wp_auto_update: FeatureToggle::from_stored(&self.feat_wp_auto_update),
            integrity_scan: FeatureToggle::from_stored(&self.feat_integrity_scan),
            monitoring: FeatureToggle::from_stored(&self.feat_monitoring),
            hardening: FeatureToggle::from_stored(&self.feat_hardening),
            backup_cadence: BackupCadence::from_stored(&self.feat_backup_cadence),
            backup_interval_days: self.feat_backup_interval_days,
            backup_keep_days: self.feat_backup_keep_days,
            backup_keep_last: self.feat_backup_keep_last,
            report_cadence: ReportCadence::from_stored(&self.feat_report_cadence),
        }
    }
}

/// Values for [`insert`] / [`update`].
#[derive(Debug, Clone)]
pub struct NewPackage {
    pub name: String,
    pub slug: String,
    pub description: String,
    pub enabled: bool,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub features: PackageFeatures,
    /// Default language for this package's customers' letters. Empty = no
    /// opinion, so the site's own setting or the cluster default decides.
    pub letters_lang: String,
    /// The monthly checklist. Empty = the built-in four.
    pub check_items: String,
    /// Care-report sections left out (comma list). Empty = send them all.
    pub report_omit: String,
}

impl Default for NewPackage {
    /// `enabled` defaults to TRUE. Hand-written rather than derived,
    /// because a derived `false` would make every `..Default::default()`
    /// package silently un-offerable.
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
            // No opinion by default: a package that says nothing about language
            // must not quietly override the cluster setting.
            letters_lang: String::new(),
            // Empty = the built-in four, which is what every package meant
            // before the list was editable.
            check_items: String::new(),
            // Nothing left out: every section is sent.
            report_omit: String::new(),
        }
    }
}

/// A row of `hosting_packages` — one activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingPackageRow {
    pub id: i64,
    pub hosting_id: HostingId,
    /// Back-link to the definition, for display and history only. NOT a
    /// foreign key and never resolved to decide behaviour — definitions are
    /// master-only, while an activation is enforced on the node that owns
    /// the hosting, where `service_packages` is empty.
    pub package_id: Option<i64>,
    /// Name snapshot, so a renamed or deleted definition still says what the
    /// customer bought.
    pub package_name: String,
    /// Price snapshot taken at activation — never rewritten by a later edit
    /// or delete of the definition.
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    /// The bundle as it stood at activation. This — not the definition — is
    /// what the drift tick enforces and what a cancel reasons about, so the
    /// activation is self-contained and works on a worker node.
    pub features: PackageFeatures,
    pub next_billing_at: Option<i64>,
    pub state: PackageState,
    pub activated_at: i64,
    pub cancelled_at: Option<i64>,
    /// Serialised `PackagePriorState` — what the forced features were set
    /// to before this activation touched them. See migration 057.
    pub prior_state_json: Option<String>,
    /// Language for the CUSTOMER letters of this site, snapshotted from the
    /// definition at activation. Empty = no opinion, so the site's own setting
    /// or the cluster default decides.
    ///
    /// Snapshotted rather than looked up, like the name and price above: this
    /// row is read on the node that OWNS the hosting, where `service_packages`
    /// is empty. Resolving through `package_id` would give the right language
    /// on the master and the cluster default on every worker.
    pub letters_lang: String,
    /// The monthly checklist as it stood at activation, same reasoning.
    pub check_items: String,
    /// Care-report sections this activation leaves out, same reasoning as the
    /// checklist: read on the owning node, which has no definitions.
    pub report_omit: String,
    /// Operator-set start of the term. `None` = `activated_at`.
    pub valid_from: Option<i64>,
    /// `false` while the activation waits for `valid_from`: nothing has been
    /// captured or forced yet. See migration 075.
    pub enforcement_started: bool,
}

impl HostingPackageRow {
    /// Waiting for its start date: nothing is captured or enforced yet.
    pub fn is_pending(&self) -> bool {
        !self.enforcement_started
    }
}

/// Values for [`activate`]. A struct rather than nine positional arguments:
/// two adjacent `Option<i64>` (price_minor / next_billing_at) and two
/// adjacent `Option<String>` (currency / interval) are exactly the shape
/// that swaps silently at a call site.
#[derive(Debug, Clone)]
pub struct NewActivation {
    pub hosting_id: HostingId,
    pub package_id: i64,
    /// Snapshotted alongside the price + bundle: what the customer bought,
    /// frozen at activation.
    pub package_name: String,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub features: PackageFeatures,
    pub next_billing_at: Option<i64>,
    pub prior_state_json: Option<String>,
    /// Copied from the definition at activation. See [`HostingPackageRow`].
    pub letters_lang: String,
    /// Copied from the definition at activation. See [`HostingPackageRow`].
    pub check_items: String,
    /// Copied from the definition at activation. See [`HostingPackageRow`].
    pub report_omit: String,
    /// The operator's start date. `None` = now.
    pub valid_from: Option<i64>,
    /// `false` for an activation dated in the future: the features are not
    /// forced and the prior state is not captured until it starts.
    pub enforcement_started: bool,
}

// ---------------------------------------------------------------- definitions

const SELECT_PACKAGES: &str =
    "SELECT id, name, slug, description, enabled, price_minor, price_currency,
            price_interval, feat_wp_auto_update, feat_integrity_scan, feat_monitoring,
            feat_hardening, feat_backup_cadence, feat_report_cadence,
            feat_backup_interval_days, feat_backup_keep_days, feat_backup_keep_last,
            letters_lang, check_items, report_omit, created_at, updated_at
     FROM service_packages";

/// Create a definition. A duplicate `name` or `slug` surfaces as a
/// `StateError` (the web layer turns it into a flash).
pub async fn insert(pool: &SqlitePool, p: &NewPackage, now: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO service_packages
           (name, slug, description, enabled, price_minor, price_currency, price_interval,
            feat_wp_auto_update, feat_integrity_scan, feat_monitoring, feat_hardening,
            feat_backup_cadence, feat_report_cadence,
            feat_backup_interval_days, feat_backup_keep_days, feat_backup_keep_last,
            letters_lang, check_items, report_omit,
            created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING id"#,
    )
    // 21 columns, 21 placeholders, 21 binds — in column order.
    .bind(&p.name)
    .bind(&p.slug)
    .bind(&p.description)
    .bind(p.enabled as i64)
    .bind(p.price_minor)
    .bind(&p.price_currency)
    .bind(&p.price_interval)
    .bind(p.features.wp_auto_update.as_str())
    .bind(p.features.integrity_scan.as_str())
    .bind(p.features.monitoring.as_str())
    .bind(p.features.hardening.as_str())
    .bind(p.features.backup_cadence.as_str())
    .bind(p.features.report_cadence.as_str())
    .bind(p.features.backup_interval_days)
    .bind(p.features.backup_keep_days)
    .bind(p.features.backup_keep_last)
    .bind(&p.letters_lang)
    .bind(&p.check_items)
    .bind(&p.report_omit)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Overwrite a definition. Edits affect only activations made AFTERWARDS:
/// each activation snapshots the bundle it was sold with, alongside its
/// price. Re-scoping a package therefore cannot silently change — or stop —
/// what an existing customer already bought, and cannot desynchronise what
/// the drift tick enforces from what a cancel restores.
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    p: &NewPackage,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"UPDATE service_packages SET
            name = ?, slug = ?, description = ?, enabled = ?,
            price_minor = ?, price_currency = ?, price_interval = ?,
            feat_wp_auto_update = ?, feat_integrity_scan = ?, feat_monitoring = ?,
            feat_hardening = ?, feat_backup_cadence = ?, feat_report_cadence = ?,
            feat_backup_interval_days = ?, feat_backup_keep_days = ?, feat_backup_keep_last = ?,
            letters_lang = ?, check_items = ?, report_omit = ?, updated_at = ?
           WHERE id = ?"#,
    )
    // 19 SET placeholders + the WHERE id — the trailing `.bind(id)` is what
    // keeps this from becoming `WHERE id = NULL` (a silent zero-row update).
    .bind(&p.name)
    .bind(&p.slug)
    .bind(&p.description)
    .bind(p.enabled as i64)
    .bind(p.price_minor)
    .bind(&p.price_currency)
    .bind(&p.price_interval)
    .bind(p.features.wp_auto_update.as_str())
    .bind(p.features.integrity_scan.as_str())
    .bind(p.features.monitoring.as_str())
    .bind(p.features.hardening.as_str())
    .bind(p.features.backup_cadence.as_str())
    .bind(p.features.report_cadence.as_str())
    .bind(p.features.backup_interval_days)
    .bind(p.features.backup_keep_days)
    .bind(p.features.backup_keep_last)
    .bind(&p.letters_lang)
    .bind(&p.check_items)
    .bind(&p.report_omit)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a definition. Existing activations SURVIVE with `package_id`
/// NULLed (FK `ON DELETE SET NULL`): they keep the price the customer
/// agreed to and the prior state needed to cancel cleanly, but stop being
/// enforced. Hiding a package is what `enabled = false` is for — callers
/// should warn when [`count_active`] is non-zero.
pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM service_packages WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Every definition, enabled or not, by name.
pub async fn list(pool: &SqlitePool) -> Result<Vec<PackageRow>, StateError> {
    let q = format!("{SELECT_PACKAGES} ORDER BY name");
    let rows: Vec<PackageRow> = sqlx::query_as::<_, PackageRow>(&q).fetch_all(pool).await?;
    Ok(rows)
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Option<PackageRow>, StateError> {
    let q = format!("{SELECT_PACKAGES} WHERE id = ?");
    let row: Option<PackageRow> = sqlx::query_as::<_, PackageRow>(&q)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Look up by the stable handle `/api/v1` addresses packages with.
pub async fn get_by_slug(pool: &SqlitePool, slug: &str) -> Result<Option<PackageRow>, StateError> {
    let q = format!("{SELECT_PACKAGES} WHERE slug = ?");
    let row: Option<PackageRow> = sqlx::query_as::<_, PackageRow>(&q)
        .bind(slug)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// How many LIVE hostings hold this package right now. Cancelled
/// activations and trashed sites are excluded — a site in the bin must not
/// inflate the badge or the delete-confirm warning.
pub async fn count_active(pool: &SqlitePool, package_id: i64) -> Result<i64, StateError> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM hosting_packages a
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.package_id = ? AND a.state = 'active' AND h.state != 'trashed'",
    )
    .bind(package_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Active count per package `{package_id: count}`, for the packages list.
pub async fn counts_active(pool: &SqlitePool) -> Result<Vec<(i64, i64)>, StateError> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT a.package_id, COUNT(*) FROM hosting_packages a
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.package_id IS NOT NULL AND a.state = 'active' AND h.state != 'trashed'
          GROUP BY a.package_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ---------------------------------------------------------------- activations

/// Column list for every activation read, in the exact order
/// [`map_activation`] destructures it. One constant so a future column
/// cannot shift the tuple under one query and not another.
const SELECT_ACTIVATIONS: &str =
    "SELECT a.id, a.hosting_id, a.package_id, a.package_name, a.price_minor,
            a.price_currency, a.price_interval, a.next_billing_at, a.state,
            a.activated_at, a.cancelled_at, a.prior_state_json,
            a.feat_wp_auto_update, a.feat_integrity_scan, a.feat_monitoring,
            a.feat_hardening, a.feat_backup_cadence, a.feat_report_cadence,
            a.feat_backup_interval_days, a.feat_backup_keep_days, a.feat_backup_keep_last,
            a.letters_lang, a.check_items, a.report_omit, a.valid_from,
            a.enforcement_started
     FROM hosting_packages a";

/// Raw activation row. A `FromRow` struct rather than a tuple: sqlx only
/// implements `FromRow` for tuples up to 16 elements and this has more, and
/// name-mapping means adding a column can never silently shift the others.
#[derive(sqlx::FromRow)]
struct ActivationRowRaw {
    id: i64,
    hosting_id: String,
    package_id: Option<i64>,
    package_name: String,
    price_minor: Option<i64>,
    price_currency: Option<String>,
    price_interval: Option<String>,
    next_billing_at: Option<i64>,
    state: String,
    activated_at: i64,
    cancelled_at: Option<i64>,
    prior_state_json: Option<String>,
    feat_wp_auto_update: String,
    feat_integrity_scan: String,
    feat_monitoring: String,
    feat_hardening: String,
    feat_backup_cadence: String,
    feat_report_cadence: String,
    #[sqlx(default)]
    feat_backup_interval_days: i64,
    #[sqlx(default)]
    feat_backup_keep_days: i64,
    #[sqlx(default)]
    feat_backup_keep_last: i64,
    letters_lang: String,
    check_items: String,
    report_omit: String,
    valid_from: Option<i64>,
    enforcement_started: i64,
}

fn map_activation(r: ActivationRowRaw) -> HostingPackageRow {
    HostingPackageRow {
        id: r.id,
        hosting_id: HostingId(r.hosting_id),
        package_id: r.package_id,
        package_name: r.package_name,
        price_minor: r.price_minor,
        price_currency: r.price_currency,
        price_interval: r.price_interval,
        letters_lang: r.letters_lang,
        check_items: r.check_items,
        report_omit: r.report_omit,
        valid_from: r.valid_from,
        enforcement_started: r.enforcement_started != 0,
        features: PackageFeatures {
            wp_auto_update: FeatureToggle::from_stored(&r.feat_wp_auto_update),
            integrity_scan: FeatureToggle::from_stored(&r.feat_integrity_scan),
            monitoring: FeatureToggle::from_stored(&r.feat_monitoring),
            hardening: FeatureToggle::from_stored(&r.feat_hardening),
            backup_cadence: BackupCadence::from_stored(&r.feat_backup_cadence),
            backup_interval_days: r.feat_backup_interval_days,
            backup_keep_days: r.feat_backup_keep_days,
            backup_keep_last: r.feat_backup_keep_last,
            report_cadence: ReportCadence::from_stored(&r.feat_report_cadence),
        },
        next_billing_at: r.next_billing_at,
        state: PackageState::from_stored(&r.state),
        activated_at: r.activated_at,
        cancelled_at: r.cancelled_at,
        prior_state_json: r.prior_state_json,
    }
}

/// Record that a hosting now holds a package, returning the activation id.
///
/// `prior_state_json` must already hold what the forced features were set
/// to BEFORE the caller flipped them — captured first, written here, and
/// read back by [`cancel`]. Activating the same package twice on one
/// hosting is rejected by the partial unique index: the second activation
/// would snapshot the state the first one had already forced, and a later
/// cancel would then "restore" the package's own values.
pub async fn activate(pool: &SqlitePool, a: &NewActivation, now: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO hosting_packages
           (hosting_id, package_id, package_name, price_minor, price_currency,
            price_interval, next_billing_at, state, activated_at, cancelled_at,
            prior_state_json, feat_wp_auto_update, feat_integrity_scan,
            feat_monitoring, feat_hardening, feat_backup_cadence, feat_report_cadence,
            feat_backup_interval_days, feat_backup_keep_days, feat_backup_keep_last,
            letters_lang, check_items, report_omit, valid_from, enforcement_started)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING id"#,
    )
    // 22 placeholders (state / cancelled_at are literals), 22 binds.
    .bind(a.hosting_id.as_str())
    .bind(a.package_id)
    .bind(&a.package_name)
    .bind(a.price_minor)
    .bind(&a.price_currency)
    .bind(&a.price_interval)
    .bind(a.next_billing_at)
    .bind(now)
    .bind(&a.prior_state_json)
    .bind(a.features.wp_auto_update.as_str())
    .bind(a.features.integrity_scan.as_str())
    .bind(a.features.monitoring.as_str())
    .bind(a.features.hardening.as_str())
    .bind(a.features.backup_cadence.as_str())
    .bind(a.features.report_cadence.as_str())
    .bind(a.features.backup_interval_days)
    .bind(a.features.backup_keep_days)
    .bind(a.features.backup_keep_last)
    .bind(&a.letters_lang)
    .bind(&a.check_items)
    .bind(&a.report_omit)
    .bind(a.valid_from)
    .bind(a.enforcement_started as i64)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_activation(
    pool: &SqlitePool,
    id: i64,
) -> Result<Option<HostingPackageRow>, StateError> {
    let q = format!("{SELECT_ACTIVATIONS} WHERE a.id = ?");
    let row: Option<ActivationRowRaw> = sqlx::query_as(&q).bind(id).fetch_optional(pool).await?;
    Ok(row.map(map_activation))
}

/// The packages this hosting currently holds — what the detail card renders
/// and what the drift tick enforces for one site.
pub async fn list_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<Vec<HostingPackageRow>, StateError> {
    let q = format!(
        "{SELECT_ACTIVATIONS} WHERE a.hosting_id = ? AND a.state = 'active' \
         ORDER BY a.activated_at"
    );
    let rows: Vec<ActivationRowRaw> = sqlx::query_as(&q)
        .bind(hosting_id.as_str())
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(map_activation).collect())
}

/// The activations that are actually IN FORCE on this hosting: active and past
/// their start date. A plan dated for the future is still shown on the card
/// ([`list_for_hosting`]) but must not be enforced, reported on, billed as a
/// service the customer already has, or counted as a promise the site owes —
/// every consumer that acts on a plan wants this one.
pub async fn list_in_force_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<Vec<HostingPackageRow>, StateError> {
    let q = format!(
        "{SELECT_ACTIVATIONS} WHERE a.hosting_id = ? AND a.state = 'active' \
         AND a.enforcement_started = 1 ORDER BY a.activated_at"
    );
    let rows: Vec<ActivationRowRaw> = sqlx::query_as(&q)
        .bind(hosting_id.as_str())
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(map_activation).collect())
}

/// Every activation the hosting ever had, cancelled ones included, newest
/// first — the "what did this customer buy, and when did it stop" history.
pub async fn history_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<Vec<HostingPackageRow>, StateError> {
    let q = format!(
        "{SELECT_ACTIVATIONS} WHERE a.hosting_id = ? ORDER BY a.activated_at DESC, a.id DESC"
    );
    let rows: Vec<ActivationRowRaw> = sqlx::query_as(&q)
        .bind(hosting_id.as_str())
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(map_activation).collect())
}

/// Every active activation across all LIVE hostings — the drift tick's work
/// list. Trashed sites are excluded: re-asserting features on a site that
/// is on its way out would just churn it.
pub async fn list_all_active(pool: &SqlitePool) -> Result<Vec<HostingPackageRow>, StateError> {
    let q = format!(
        "{SELECT_ACTIVATIONS}
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.state = 'active' AND h.state != 'trashed'
          ORDER BY a.hosting_id, a.activated_at"
    );
    let rows: Vec<ActivationRowRaw> = sqlx::query_as(&q).fetch_all(pool).await?;
    Ok(rows.into_iter().map(map_activation).collect())
}

/// [`list_all_active`] minus the activations still waiting for their start
/// date — the work list for every tick that ACTS on a plan (enforcement,
/// reports, site checks, the care dashboard).
pub async fn list_all_in_force(pool: &SqlitePool) -> Result<Vec<HostingPackageRow>, StateError> {
    let q = format!(
        "{SELECT_ACTIVATIONS}
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.state = 'active' AND a.enforcement_started = 1 AND h.state != 'trashed'
          ORDER BY a.hosting_id, a.activated_at"
    );
    let rows: Vec<ActivationRowRaw> = sqlx::query_as(&q).fetch_all(pool).await?;
    Ok(rows.into_iter().map(map_activation).collect())
}

/// Activations whose start date has arrived but that have not been started
/// yet: `valid_from <= now` and `enforcement_started = 0`. The tick starts
/// these before it enforces anything.
pub async fn list_due_to_start(
    pool: &SqlitePool,
    now: i64,
) -> Result<Vec<HostingPackageRow>, StateError> {
    let q = format!(
        "{SELECT_ACTIVATIONS}
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.state = 'active' AND a.enforcement_started = 0
            AND a.valid_from IS NOT NULL AND a.valid_from <= ?
            AND h.state != 'trashed'
          ORDER BY a.valid_from, a.id"
    );
    let rows: Vec<ActivationRowRaw> = sqlx::query_as(&q).bind(now).fetch_all(pool).await?;
    Ok(rows.into_iter().map(map_activation).collect())
}

/// End an activation: mark it cancelled and stop its billing reminders.
///
/// Returns `false` when the row was already cancelled or does not exist —
/// the guard that keeps a double-cancel from restoring `prior_state_json` a
/// second time, on top of whatever the customer changed in between.
/// `prior_state_json` is kept for the audit trail; the restore has already
/// happened by the time this is called.
/// Push a definition's letter language onto its ACTIVE activations.
///
/// Deliberately unlike the price and the feature bundle, which are snapshotted
/// and never rewritten: those are what the customer AGREED to, and a later
/// re-price must not reach back into a sold plan. A language is not part of
/// that agreement — it is a presentation default the operator changes when they
/// discover the setting, expecting it to apply to the sites already on the
/// package. Without this the field is write-once at activation, and the panel
/// says the opposite in three places.
///
/// Cancelled activations are left alone: their language is history.
pub async fn set_letters_lang(
    pool: &SqlitePool,
    package_id: i64,
    lang: &str,
) -> Result<u64, StateError> {
    let n = sqlx::query(
        "UPDATE hosting_packages SET letters_lang = ? \
         WHERE package_id = ? AND state = 'active'",
    )
    .bind(lang)
    .bind(package_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Push a definition's monthly checklist onto its ACTIVE activations.
///
/// Same reasoning as [`set_letters_lang`], and the same limit: the checklist is
/// what the operator promises to LOOK AT from now on, not a price the customer
/// agreed to, so editing the plan has to reach the sites already on it —
/// otherwise a plan edited today keeps checking yesterday's list forever and
/// the package page is lying.
///
/// It does NOT rewrite history: months already ticked keep their own frozen
/// list (see `CareServiceChecks::applied`), so a March scored out of four stays
/// out of four after the fifth item is added in April.
///
/// Cancelled activations are left alone: their checklist is history.
pub async fn set_check_items(
    pool: &SqlitePool,
    package_id: i64,
    items: &str,
) -> Result<u64, StateError> {
    let n = sqlx::query(
        "UPDATE hosting_packages SET check_items = ? \
         WHERE package_id = ? AND state = 'active'",
    )
    .bind(items)
    .bind(package_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Push a definition's care-report section choice onto its ACTIVE activations.
///
/// Same reasoning, and same limit, as [`set_check_items`]: which sections the
/// letter carries is a presentation promise the operator edits expecting the
/// sites already on the plan to follow — not a price the customer agreed to.
/// A report already sent is history and is not touched; the next one uses the
/// new choice.
///
/// Cancelled activations are left alone.
pub async fn set_report_omit(
    pool: &SqlitePool,
    package_id: i64,
    omit: &str,
) -> Result<u64, StateError> {
    let n = sqlx::query(
        "UPDATE hosting_packages SET report_omit = ? \
         WHERE package_id = ? AND state = 'active'",
    )
    .bind(omit)
    .bind(package_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Move one ACTIVE activation's start date and re-aim its reminder clock.
///
/// `next_billing_at` is passed in rather than derived: the billing interval
/// math lives with the billing sweep in the service layer, and this module
/// stores intent without interpreting it. Returns `false` when the row is
/// cancelled or absent.
pub async fn set_valid_from(
    pool: &SqlitePool,
    id: i64,
    valid_from: i64,
    next_billing_at: Option<i64>,
) -> Result<bool, StateError> {
    let r = sqlx::query(
        "UPDATE hosting_packages SET valid_from = ?, next_billing_at = ? \
         WHERE id = ? AND state = 'active'",
    )
    .bind(valid_from)
    .bind(next_billing_at)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Flip a waiting activation to started and record the prior state captured at
/// THAT moment. Compare-and-set on `enforcement_started = 0`, so two passes
/// racing to start the same row cannot both capture (the second would capture
/// the state the first had already forced, and a cancel would then "restore"
/// the package's own values). Returns `true` only for the winner.
pub async fn mark_started(
    pool: &SqlitePool,
    id: i64,
    prior_state_json: Option<&str>,
) -> Result<bool, StateError> {
    let r = sqlx::query(
        "UPDATE hosting_packages SET enforcement_started = 1, prior_state_json = ? \
         WHERE id = ? AND state = 'active' AND enforcement_started = 0",
    )
    .bind(prior_state_json)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn cancel(pool: &SqlitePool, id: i64, now: i64) -> Result<bool, StateError> {
    let r = sqlx::query(
        "UPDATE hosting_packages
            SET state = 'cancelled', cancelled_at = ?, next_billing_at = NULL
          WHERE id = ? AND state = 'active'",
    )
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Move one activation's reminder clock — used by the billing sweep after a
/// reminder fires, so the same package doesn't re-notify every tick forever.
/// `None` clears it (an activation with no interval stops being due).
pub async fn set_next_billing(
    pool: &SqlitePool,
    id: i64,
    next_billing_at: Option<i64>,
) -> Result<(), StateError> {
    sqlx::query("UPDATE hosting_packages SET next_billing_at = ? WHERE id = ?")
        .bind(next_billing_at)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Active activations on LIVE hostings whose reminder falls at or before
/// `now + within_secs`. Same contract as `profiles::due_billings`: this
/// selects who gets a REMINDER, it does not charge anyone.
pub async fn due_billings(
    pool: &SqlitePool,
    now: i64,
    within_secs: i64,
) -> Result<Vec<HostingPackageRow>, StateError> {
    let q = format!(
        "{SELECT_ACTIVATIONS}
           JOIN hostings h ON h.id = a.hosting_id
          WHERE a.state = 'active'
            AND a.next_billing_at IS NOT NULL
            AND a.next_billing_at <= ?
            AND h.state != 'trashed'
          ORDER BY a.next_billing_at"
    );
    let rows: Vec<ActivationRowRaw> = sqlx::query_as(&q)
        .bind(now + within_secs)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(map_activation).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;
    use hyperion_types::package::{LiveFeatureState, PackagePriorState};

    /// Two hostings, because half of what packages promise is that one
    /// site's activation never touches another's.
    async fn fresh() -> SqlitePool {
        let p = open_memory().await.expect("open mem");
        for (n, id, domain) in [(1, "h1", "a.cz"), (2, "h2", "b.cz")] {
            sqlx::query(
                r#"INSERT INTO system_users (id, name, uid, home_dir, shell, created_at)
                   VALUES (?, ?, ?, ?, '/usr/sbin/nologin', 0)"#,
            )
            .bind(n)
            .bind(format!("site_{id}"))
            .bind(1000 + n)
            .bind(format!("/home/site_{id}"))
            .execute(&p)
            .await
            .expect("seed system_user");
            sqlx::query(
                r#"INSERT INTO hostings (id, domain, system_user_id, root_dir, state, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'active', 0, 0)"#,
            )
            .bind(id)
            .bind(domain)
            .bind(n)
            .bind(format!("/home/site_{id}/{domain}"))
            .execute(&p)
            .await
            .expect("seed hosting");
        }
        p
    }

    fn care_package() -> NewPackage {
        NewPackage {
            name: "Péče Plus".into(),
            slug: "pece-plus".into(),
            description: "Aktualizace, zálohy, monitoring".into(),
            price_minor: Some(49_000),
            price_currency: Some("Kč".into()),
            price_interval: Some("monthly".into()),
            features: PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                monitoring: FeatureToggle::On,
                backup_cadence: BackupCadence::Daily,
                report_cadence: ReportCadence::Monthly,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn definition_crud_round_trips() {
        let pool = fresh().await;
        let id = insert(&pool, &care_package(), 100).await.expect("insert");
        assert!(id > 0);

        let row = get(&pool, id).await.expect("get").expect("row");
        assert_eq!(row.name, "Péče Plus");
        assert!(row.is_enabled(), "a new package is offerable");
        assert_eq!(row.price_minor, Some(49_000));
        let f = row.features();
        assert_eq!(f.wp_auto_update, FeatureToggle::On);
        assert_eq!(f.monitoring, FeatureToggle::On);
        assert_eq!(f.backup_cadence, BackupCadence::Daily);
        assert_eq!(f.report_cadence, ReportCadence::Monthly);
        // Untouched features must come back as "leave", never as "off".
        assert_eq!(f.hardening, FeatureToggle::Leave);
        assert_eq!(f.integrity_scan, FeatureToggle::Leave);

        assert_eq!(
            get_by_slug(&pool, "pece-plus")
                .await
                .expect("by slug")
                .map(|r| r.id),
            Some(id)
        );
        assert_eq!(list(&pool).await.expect("list").len(), 1);

        delete(&pool, id).await.expect("delete");
        assert!(list(&pool).await.expect("list").is_empty());
    }

    #[tokio::test]
    async fn update_persists_changes() {
        // Regression guard: update()'s bind chain must stay aligned with its
        // SQL placeholders. A missing bind makes the trailing params NULL,
        // so the statement becomes `WHERE id = NULL` and silently updates
        // zero rows while the caller still sees Ok.
        let pool = fresh().await;
        let id = insert(&pool, &care_package(), 100).await.expect("insert");

        update(
            &pool,
            id,
            &NewPackage {
                name: "Péče Basic".into(),
                slug: "pece-basic".into(),
                description: "Jen zálohy".into(),
                enabled: false,
                price_minor: Some(19_000),
                price_currency: Some("Kč".into()),
                price_interval: Some("yearly".into()),
                letters_lang: "cs".into(),
                check_items: r#"[{"id":"gdpr","label":"GDPR"}]"#.into(),
                report_omit: "attacks,uptime".into(),
                features: PackageFeatures {
                    wp_auto_update: FeatureToggle::Off,
                    hardening: FeatureToggle::On,
                    backup_cadence: BackupCadence::Custom,
                    backup_interval_days: 3,
                    backup_keep_days: 90,
                    backup_keep_last: 8,
                    report_cadence: ReportCadence::Quarterly,
                    ..Default::default()
                },
            },
            200,
        )
        .await
        .expect("update");

        let row = get(&pool, id).await.expect("get").expect("row");
        assert_eq!(row.name, "Péče Basic");
        assert_eq!(row.slug, "pece-basic");
        assert_eq!(row.description, "Jen zálohy");
        assert!(!row.is_enabled());
        assert_eq!(row.price_minor, Some(19_000));
        assert_eq!(row.price_interval.as_deref(), Some("yearly"));
        let f = row.features();
        assert_eq!(f.wp_auto_update, FeatureToggle::Off);
        assert_eq!(f.hardening, FeatureToggle::On);
        assert_eq!(f.backup_cadence, BackupCadence::Custom);
        // The custom period + retention overrides must survive the round-trip
        // — a dropped bind here silently NULLs them and the site quietly
        // reverts to the preset schedule / the node-wide retention rule.
        assert_eq!(f.backup_interval_days, 3);
        assert_eq!(f.backup_keep_days, 90);
        assert_eq!(f.backup_keep_last, 8);
        assert_eq!(
            row.check_items, r#"[{"id":"gdpr","label":"GDPR"}]"#,
            "a custom checklist must survive an edit, or the plan silently \
             reverts to the built-in four"
        );
        assert_eq!(
            row.report_omit, "attacks,uptime",
            "the section choice must survive an edit, or the plan silently \
             goes back to sending every section"
        );
        // The last SET column before `updated_at` — if its bind were
        // missing, `updated_at` would absorb the id and the whole UPDATE
        // would silently address no row at all.
        assert_eq!(f.report_cadence, ReportCadence::Quarterly);
        // Cleared in the edit: on → leave, not on → off.
        assert_eq!(f.monitoring, FeatureToggle::Leave);
        assert_eq!(row.updated_at, 200, "updated_at must advance, not go NULL");
    }

    #[tokio::test]
    async fn duplicate_name_or_slug_rejected() {
        let pool = fresh().await;
        insert(&pool, &care_package(), 1).await.expect("first");
        assert!(insert(&pool, &care_package(), 2).await.is_err(), "name");
        let same_slug = NewPackage {
            name: "Jiný název".into(),
            ..care_package()
        };
        assert!(insert(&pool, &same_slug, 3).await.is_err(), "slug");
    }

    /// A definition's language must reach the sites ALREADY on it.
    ///
    /// Unlike the price and the bundle, which stay snapshotted because they are
    /// what the customer agreed to. The panel tells the operator in three places
    /// that an edit "picks up on the next enforcement pass"; before this the
    /// language was write-once at activation and all three were false.
    #[tokio::test]
    async fn a_package_language_edit_reaches_active_sites_but_not_cancelled_ones() {
        let pool = fresh().await;
        // `fresh()` seeds exactly h1 and h2, hosting_id is a real FK, and
        // (hosting_id, package_id) is UNIQUE — so the three rows are three
        // distinct pairs: h1 on the edited package (must move), h2 on the same
        // package but cancelled (must not), h1 on another package (must not).
        activate(&pool, &activation("h1", 7, 100), 0).await.unwrap();
        let gone_id = activate(&pool, &activation("h2", 7, 100), 0).await.unwrap();
        activate(&pool, &activation("h1", 9, 100), 0).await.unwrap();
        cancel(&pool, gone_id, 1).await.unwrap();

        let moved = set_letters_lang(&pool, 7, "en").await.unwrap();
        assert_eq!(moved, 1, "only the ACTIVE activation of package 7 moves");

        let read = |h: &str| {
            let pool = pool.clone();
            let h = h.to_string();
            async move {
                list_for_hosting(&pool, &HostingId(h))
                    .await
                    .unwrap()
                    .first()
                    .map(|r| r.letters_lang.clone())
            }
        };
        // h1 holds two activations; the edited package's is the one that moved.
        let h1: Vec<(i64, String)> = list_for_hosting(&pool, &HostingId("h1".into()))
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.package_id.unwrap_or(0), r.letters_lang))
            .collect();
        assert!(
            h1.contains(&(7, "en".to_string())),
            "the edited package's activation must move: {h1:?}"
        );
        assert!(
            h1.contains(&(9, "cs".to_string())),
            "a different package on the same site must not: {h1:?}"
        );
        // A cancelled activation keeps its language: it is history.
        // (list_for_hosting only returns active rows, so read it directly.)
        let gone_lang: (String,) =
            sqlx::query_as("SELECT letters_lang FROM hosting_packages WHERE id = ?")
                .bind(gone_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(gone_lang.0, "cs", "a cancelled activation is not rewritten");
        // A different package is untouched.
        let _ = read;
    }

    /// The plan's section choice must reach the sites ALREADY on it, like the
    /// checklist and the language — and only the active ones.
    #[tokio::test]
    async fn a_report_section_edit_reaches_active_sites_but_not_cancelled_ones() {
        let pool = fresh().await;
        activate(&pool, &activation("h1", 7, 100), 0).await.unwrap();
        let gone_id = activate(&pool, &activation("h2", 7, 100), 0).await.unwrap();
        activate(&pool, &activation("h1", 9, 100), 0).await.unwrap();
        cancel(&pool, gone_id, 1).await.unwrap();

        let moved = set_report_omit(&pool, 7, "attacks,traffic").await.unwrap();
        assert_eq!(moved, 1, "only the ACTIVE activation of package 7 moves");

        let h1: Vec<(i64, String)> = list_for_hosting(&pool, &HostingId("h1".into()))
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.package_id.unwrap_or(0), r.report_omit))
            .collect();
        assert!(h1.contains(&(7, "attacks,traffic".to_string())), "{h1:?}");
        assert!(
            h1.contains(&(9, "uptime".to_string())),
            "other plan untouched: {h1:?}"
        );
        let gone: (String,) =
            sqlx::query_as("SELECT report_omit FROM hosting_packages WHERE id = ?")
                .bind(gone_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(gone.0, "uptime", "a cancelled activation is history");
    }

    #[tokio::test]
    async fn the_start_date_and_started_flag_round_trip() {
        let pool = fresh().await;
        let mut a = activation("h1", 7, 100);
        a.valid_from = Some(5_000);
        a.enforcement_started = false;
        let id = activate(&pool, &a, 10).await.unwrap();
        let row = get_activation(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.valid_from, Some(5_000));
        assert!(!row.enforcement_started);
        assert_eq!(
            row.activated_at, 10,
            "activated_at stays the click, not the term"
        );

        assert!(set_valid_from(&pool, id, 9_000, Some(12_345))
            .await
            .unwrap());
        let row = get_activation(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.valid_from, Some(9_000));
        assert_eq!(row.next_billing_at, Some(12_345));

        // A cancelled activation's term is history.
        cancel(&pool, id, 20).await.unwrap();
        assert!(!set_valid_from(&pool, id, 1, None).await.unwrap());
    }

    /// Only one pass may start a waiting activation, or the second would
    /// capture the state the first had already forced as the "prior" one.
    #[tokio::test]
    async fn starting_an_activation_is_compare_and_set() {
        let pool = fresh().await;
        let mut a = activation("h1", 7, 100);
        a.enforcement_started = false;
        let id = activate(&pool, &a, 0).await.unwrap();

        assert!(
            mark_started(&pool, id, Some(r#"{"v":1,"monitoring":false}"#))
                .await
                .unwrap()
        );
        assert!(
            !mark_started(&pool, id, Some(r#"{"v":1,"monitoring":true}"#))
                .await
                .unwrap(),
            "the second pass lost the race"
        );
        let row = get_activation(&pool, id).await.unwrap().unwrap();
        assert!(row.enforcement_started);
        assert_eq!(
            row.prior_state_json.as_deref(),
            Some(r#"{"v":1,"monitoring":false}"#),
            "the winner's capture stands"
        );
    }

    #[tokio::test]
    async fn a_waiting_activation_is_listed_but_not_in_force_until_it_starts() {
        let pool = fresh().await;
        let mut waiting = activation("h1", 7, 100);
        waiting.valid_from = Some(1_000);
        waiting.enforcement_started = false;
        let w = activate(&pool, &waiting, 0).await.unwrap();
        activate(&pool, &activation("h1", 9, 100), 0).await.unwrap();

        let h1 = HostingId("h1".into());
        assert_eq!(
            list_for_hosting(&pool, &h1).await.unwrap().len(),
            2,
            "the card shows both"
        );
        let live = list_in_force_for_hosting(&pool, &h1).await.unwrap();
        assert_eq!(live.len(), 1, "only the started one is in force");
        assert_eq!(live[0].package_id, Some(9));
        assert_eq!(list_all_in_force(&pool).await.unwrap().len(), 1);

        // Not due before the date, due on it.
        assert!(list_due_to_start(&pool, 999).await.unwrap().is_empty());
        let due = list_due_to_start(&pool, 1_000).await.unwrap();
        assert_eq!(due.iter().map(|r| r.id).collect::<Vec<_>>(), vec![w]);

        assert!(mark_started(&pool, w, None).await.unwrap());
        assert!(list_due_to_start(&pool, 5_000).await.unwrap().is_empty());
        assert_eq!(
            list_in_force_for_hosting(&pool, &h1).await.unwrap().len(),
            2
        );
    }

    fn activation(hosting: &str, package_id: i64, price_minor: i64) -> NewActivation {
        NewActivation {
            hosting_id: HostingId(hosting.into()),
            package_id,
            package_name: format!("pkg-{package_id}"),
            price_minor: Some(price_minor),
            price_currency: Some("Kč".into()),
            price_interval: Some("monthly".into()),
            // Non-empty on purpose, like the bundle below: a dropped bind
            // would leave it empty and a test that activated with "" could not
            // tell.
            letters_lang: "cs".into(),
            // Non-empty for the same reason, and this one is now the LAST bind
            // of the activation INSERT — the position a misalignment lands on
            // first.
            check_items: r#"[{"id":"gdpr","label":"GDPR"}]"#.into(),
            // The last binds of the INSERT now — the position a misalignment
            // lands on first. Non-empty / non-default for that reason.
            report_omit: "uptime".into(),
            valid_from: Some(40),
            enforcement_started: true,
            // A non-default bundle on purpose: the snapshot is what the drift
            // tick enforces, so a test that activated with an all-`leave`
            // bundle would pass even if the snapshot were dropped entirely.
            features: PackageFeatures {
                wp_auto_update: FeatureToggle::On,
                report_cadence: ReportCadence::Monthly,
                // Custom cadence + retention: the snapshot must carry the new
                // integer feature columns, and a dropped bind among the three
                // shifts letters_lang/check_items and this fixture makes it
                // visible in every activation test.
                backup_cadence: BackupCadence::Custom,
                backup_interval_days: 4,
                backup_keep_days: 60,
                backup_keep_last: 6,
                ..PackageFeatures::default()
            },
            next_billing_at: None,
            prior_state_json: None,
        }
    }

    /// The bundle must survive the round trip, because it — not the
    /// definition — is what a worker node enforces and what a cancel
    /// reasons about.
    #[tokio::test]
    async fn activation_snapshots_the_bundle_and_name() {
        let pool = fresh().await;
        let id = insert(&pool, &care_package(), 1).await.expect("insert");
        activate(&pool, &activation("h1", id, 49_000), 10)
            .await
            .expect("activate");
        let rows = list_for_hosting(&pool, &HostingId("h1".into()))
            .await
            .expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].features.wp_auto_update, FeatureToggle::On);
        assert_eq!(rows[0].features.report_cadence, ReportCadence::Monthly);
        assert_eq!(rows[0].features.backup_cadence, BackupCadence::Custom);
        // The custom period + retention overrides are part of the bundle a
        // worker node enforces and a cancel reasons about, so they must
        // survive the snapshot round-trip.
        assert_eq!(rows[0].features.backup_interval_days, 4);
        assert_eq!(rows[0].features.backup_keep_days, 60);
        assert_eq!(rows[0].features.backup_keep_last, 6);
        assert_eq!(rows[0].package_name, format!("pkg-{id}"));

        // Re-scoping the definition must NOT reach back into what was sold.
        let mut edited = care_package();
        edited.features.wp_auto_update = FeatureToggle::Off;
        update(&pool, id, &edited, 20).await.expect("update");
        let rows = list_for_hosting(&pool, &HostingId("h1".into()))
            .await
            .expect("relist");
        assert_eq!(
            rows[0].features.wp_auto_update,
            FeatureToggle::On,
            "the activation keeps the bundle it was sold with"
        );
    }

    /// The whole reason packages are not profiles: a hosting stacks them.
    #[tokio::test]
    async fn two_packages_active_on_one_hosting() {
        let pool = fresh().await;
        let backups = insert(
            &pool,
            &NewPackage {
                name: "Zálohy".into(),
                slug: "zalohy".into(),
                features: PackageFeatures {
                    backup_cadence: BackupCadence::Daily,
                    ..Default::default()
                },
                ..Default::default()
            },
            10,
        )
        .await
        .expect("insert backups");
        let monitoring = insert(
            &pool,
            &NewPackage {
                name: "Monitoring".into(),
                slug: "monitoring".into(),
                features: PackageFeatures {
                    monitoring: FeatureToggle::On,
                    ..Default::default()
                },
                ..Default::default()
            },
            10,
        )
        .await
        .expect("insert monitoring");

        activate(&pool, &activation("h1", backups, 19_000), 100)
            .await
            .expect("activate backups");
        activate(&pool, &activation("h1", monitoring, 9_000), 110)
            .await
            .expect("activate monitoring");

        let held = list_for_hosting(&pool, &HostingId("h1".into()))
            .await
            .expect("list");
        assert_eq!(held.len(), 2, "hosting_packages must stack");
        assert_eq!(held[0].package_id, Some(backups), "ordered by activated_at");
        assert_eq!(held[1].package_id, Some(monitoring));
        assert_eq!(count_active(&pool, backups).await.expect("count"), 1);

        // …and the other site is untouched.
        assert!(list_for_hosting(&pool, &HostingId("h2".into()))
            .await
            .expect("list h2")
            .is_empty());

        // The same package twice on one hosting is rejected: the second
        // activation would snapshot state the first one already forced.
        assert!(
            activate(&pool, &activation("h1", backups, 19_000), 120)
                .await
                .is_err(),
            "double activation of the same package must be refused"
        );
    }

    #[tokio::test]
    async fn cancel_leaves_the_other_package_untouched() {
        let pool = fresh().await;
        let a = insert(
            &pool,
            &NewPackage {
                name: "A".into(),
                slug: "a".into(),
                ..Default::default()
            },
            10,
        )
        .await
        .expect("A");
        let b = insert(
            &pool,
            &NewPackage {
                name: "B".into(),
                slug: "b".into(),
                ..Default::default()
            },
            10,
        )
        .await
        .expect("B");
        let act_a = activate(&pool, &activation("h1", a, 10_000), 100)
            .await
            .expect("act A");
        let act_b = activate(&pool, &activation("h1", b, 20_000), 100)
            .await
            .expect("act B");

        assert!(cancel(&pool, act_a, 500).await.expect("cancel"));

        let held = list_for_hosting(&pool, &HostingId("h1".into()))
            .await
            .expect("list");
        assert_eq!(held.len(), 1, "only the cancelled one leaves");
        assert_eq!(held[0].id, act_b);
        assert_eq!(held[0].state, PackageState::Active);

        let gone = get_activation(&pool, act_a)
            .await
            .expect("get")
            .expect("row still exists");
        assert_eq!(gone.state, PackageState::Cancelled);
        assert_eq!(gone.cancelled_at, Some(500));
        assert_eq!(gone.next_billing_at, None, "cancelling stops reminders");

        // A second cancel is a no-op, so a caller can't restore prior state
        // twice on top of whatever changed in between.
        assert!(!cancel(&pool, act_a, 600).await.expect("re-cancel"));
        assert_eq!(
            get_activation(&pool, act_a)
                .await
                .expect("get")
                .expect("row")
                .cancelled_at,
            Some(500),
            "the original cancellation timestamp survives"
        );

        // History keeps both; the drift tick's list keeps only the live one.
        assert_eq!(
            history_for_hosting(&pool, &HostingId("h1".into()))
                .await
                .expect("history")
                .len(),
            2
        );
        assert_eq!(list_all_active(&pool).await.expect("all").len(), 1);

        // Re-buying the cancelled package is allowed — the partial unique
        // index only covers active rows.
        activate(&pool, &activation("h1", a, 12_000), 700)
            .await
            .expect("re-activate after cancel");
    }

    #[tokio::test]
    async fn price_snapshot_survives_definition_edit_and_delete() {
        let pool = fresh().await;
        let id = insert(&pool, &care_package(), 100).await.expect("insert");
        let act = activate(&pool, &activation("h1", id, 49_000), 100)
            .await
            .expect("activate");

        // Re-price the definition…
        update(
            &pool,
            id,
            &NewPackage {
                price_minor: Some(99_000),
                ..care_package()
            },
            200,
        )
        .await
        .expect("re-price");
        let row = get_activation(&pool, act).await.expect("get").expect("row");
        assert_eq!(
            row.price_minor,
            Some(49_000),
            "the customer keeps the price they agreed to"
        );

        // …and delete it entirely. The activation survives AND stays
        // enforceable: it carries its own bundle snapshot, so a customer
        // who is still paying keeps getting what they bought even though
        // the operator retired the definition.
        delete(&pool, id).await.expect("delete");
        let row = get_activation(&pool, act).await.expect("get").expect("row");
        assert_eq!(row.price_minor, Some(49_000));
        assert_eq!(row.state, PackageState::Active);
        assert_eq!(
            row.features.wp_auto_update,
            FeatureToggle::On,
            "a deleted definition must not silently stop enforcement"
        );
        assert_eq!(
            row.package_name,
            format!("pkg-{id}"),
            "the name snapshot still says what was bought"
        );
    }

    #[tokio::test]
    async fn prior_state_round_trips_through_the_column() {
        let pool = fresh().await;
        let id = insert(&pool, &care_package(), 100).await.expect("insert");
        let features = get(&pool, id).await.expect("get").expect("row").features();
        // What the site looked like before anyone bought anything: the
        // customer had monitoring on themselves and backups weekly.
        let live = LiveFeatureState {
            wp_auto_update: false,
            integrity_scan: false,
            monitoring: true,
            hardening: false,
            backup_cadence: BackupCadence::Weekly,
            backup_interval_days: 0,
            backup_keep_days: 45,
            backup_keep_last: 3,
        };
        let prior = PackagePriorState::capture(&features, &live);
        let json = serde_json::to_string(&prior).expect("ser");

        let act = activate(
            &pool,
            &NewActivation {
                prior_state_json: Some(json),
                ..activation("h1", id, 49_000)
            },
            100,
        )
        .await
        .expect("activate");

        let stored = get_activation(&pool, act)
            .await
            .expect("get")
            .expect("row")
            .prior_state_json
            .expect("prior state persisted");
        let back: PackagePriorState = serde_json::from_str(&stored).expect("de");
        assert_eq!(back, prior);
        assert_eq!(back.wp_auto_update, Some(false));
        assert_eq!(back.monitoring, Some(true));
        assert_eq!(back.backup_cadence, Some(BackupCadence::Weekly));
        // Forcing backups captures the retention keys alongside the cadence,
        // so a cancel restores the site's prior retention too.
        assert_eq!(back.backup_interval_days, Some(0));
        assert_eq!(back.backup_keep_days, Some(45));
        assert_eq!(back.backup_keep_last, Some(3));
        // The package says nothing about hardening, so cancellation has
        // nothing to restore there.
        assert_eq!(back.hardening, None);
    }

    #[tokio::test]
    async fn due_billings_boundary_and_exclusions() {
        let pool = fresh().await;
        let id = insert(&pool, &care_package(), 1).await.expect("insert");
        let other = insert(
            &pool,
            &NewPackage {
                name: "Druhý".into(),
                slug: "druhy".into(),
                ..Default::default()
            },
            1,
        )
        .await
        .expect("insert 2");

        let now = 1_000_000i64;
        let window = 3 * 86_400;
        // Exactly on the edge — must be included (<=, not <).
        let on_edge = activate(
            &pool,
            &NewActivation {
                next_billing_at: Some(now + window),
                ..activation("h1", id, 49_000)
            },
            1,
        )
        .await
        .expect("edge");
        // One second past the edge — must not be.
        activate(
            &pool,
            &NewActivation {
                next_billing_at: Some(now + window + 1),
                ..activation("h2", id, 49_000)
            },
            1,
        )
        .await
        .expect("beyond");
        // No clock at all — never due.
        activate(&pool, &activation("h1", other, 1_000), 1)
            .await
            .expect("no clock");

        let due = due_billings(&pool, now, window).await.expect("due");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, on_edge);

        // The sweep advances the clock past the window; the row goes quiet.
        set_next_billing(&pool, on_edge, Some(now + window + 10))
            .await
            .expect("advance");
        assert!(due_billings(&pool, now, window)
            .await
            .expect("due")
            .is_empty());

        // A cancelled activation stops being due even with a clock set…
        set_next_billing(&pool, on_edge, Some(now))
            .await
            .expect("re-arm");
        assert_eq!(
            due_billings(&pool, now, window).await.expect("due").len(),
            1
        );
        assert!(cancel(&pool, on_edge, now).await.expect("cancel"));
        assert!(due_billings(&pool, now, window)
            .await
            .expect("due")
            .is_empty());

        // …and so does a site in the bin: h2 buys `other` and is due now.
        let act_h2 = activate(
            &pool,
            &NewActivation {
                next_billing_at: Some(now),
                ..activation("h2", other, 1_000)
            },
            1,
        )
        .await
        .expect("h2");
        let due = due_billings(&pool, now, window).await.expect("due");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, act_h2);
        assert_eq!(count_active(&pool, other).await.expect("count"), 2);

        sqlx::query("UPDATE hostings SET state = 'trashed' WHERE id = 'h2'")
            .execute(&pool)
            .await
            .expect("trash h2");
        assert!(due_billings(&pool, now, window)
            .await
            .expect("due")
            .is_empty());
        // h1 still holds `other` (no clock), so the drift tick keeps exactly
        // that one — the trashed site's two activations drop out.
        let live = list_all_active(&pool).await.expect("all");
        assert_eq!(live.len(), 1, "the drift tick skips trashed sites too");
        assert_eq!(live[0].hosting_id, HostingId("h1".into()));
        assert_eq!(
            count_active(&pool, other).await.expect("count"),
            1,
            "and so does the in-use badge"
        );
    }

    #[tokio::test]
    async fn counts_active_groups_by_package() {
        let pool = fresh().await;
        let a = insert(
            &pool,
            &NewPackage {
                name: "A".into(),
                slug: "a".into(),
                ..Default::default()
            },
            1,
        )
        .await
        .expect("A");
        let b = insert(
            &pool,
            &NewPackage {
                name: "B".into(),
                slug: "b".into(),
                ..Default::default()
            },
            1,
        )
        .await
        .expect("B");
        activate(&pool, &activation("h1", a, 0), 1)
            .await
            .expect("h1 a");
        activate(&pool, &activation("h2", a, 0), 1)
            .await
            .expect("h2 a");
        activate(&pool, &activation("h1", b, 0), 1)
            .await
            .expect("h1 b");

        let mut counts = counts_active(&pool).await.expect("counts");
        counts.sort();
        assert_eq!(counts, vec![(a, 2), (b, 1)]);
    }
}
