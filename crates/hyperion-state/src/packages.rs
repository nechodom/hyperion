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
use hyperion_types::package::{BackupCadence, FeatureToggle, PackageFeatures, PackageState};
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
}

// ---------------------------------------------------------------- definitions

const SELECT_PACKAGES: &str =
    "SELECT id, name, slug, description, enabled, price_minor, price_currency,
            price_interval, feat_wp_auto_update, feat_integrity_scan, feat_monitoring,
            feat_hardening, feat_backup_cadence, created_at, updated_at
     FROM service_packages";

/// Create a definition. A duplicate `name` or `slug` surfaces as a
/// `StateError` (the web layer turns it into a flash).
pub async fn insert(pool: &SqlitePool, p: &NewPackage, now: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO service_packages
           (name, slug, description, enabled, price_minor, price_currency, price_interval,
            feat_wp_auto_update, feat_integrity_scan, feat_monitoring, feat_hardening,
            feat_backup_cadence, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING id"#,
    )
    // 14 columns, 14 placeholders, 14 binds — in column order.
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
            feat_hardening = ?, feat_backup_cadence = ?,
            updated_at = ?
           WHERE id = ?"#,
    )
    // 13 SET placeholders + the WHERE id — the trailing `.bind(id)` is what
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
            a.feat_hardening, a.feat_backup_cadence
     FROM hosting_packages a";

/// Raw activation row. A `FromRow` struct rather than a tuple: sqlx only
/// implements `FromRow` for tuples up to 16 elements and this has 17, and
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
        features: PackageFeatures {
            wp_auto_update: FeatureToggle::from_stored(&r.feat_wp_auto_update),
            integrity_scan: FeatureToggle::from_stored(&r.feat_integrity_scan),
            monitoring: FeatureToggle::from_stored(&r.feat_monitoring),
            hardening: FeatureToggle::from_stored(&r.feat_hardening),
            backup_cadence: BackupCadence::from_stored(&r.feat_backup_cadence),
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
            feat_monitoring, feat_hardening, feat_backup_cadence)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL, ?, ?, ?, ?, ?, ?)
           RETURNING id"#,
    )
    // 14 placeholders (state / cancelled_at are literals), 14 binds.
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

/// End an activation: mark it cancelled and stop its billing reminders.
///
/// Returns `false` when the row was already cancelled or does not exist —
/// the guard that keeps a double-cancel from restoring `prior_state_json` a
/// second time, on top of whatever the customer changed in between.
/// `prior_state_json` is kept for the audit trail; the restore has already
/// happened by the time this is called.
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
                features: PackageFeatures {
                    wp_auto_update: FeatureToggle::Off,
                    hardening: FeatureToggle::On,
                    backup_cadence: BackupCadence::Weekly,
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
        assert_eq!(f.backup_cadence, BackupCadence::Weekly);
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

    fn activation(hosting: &str, package_id: i64, price_minor: i64) -> NewActivation {
        NewActivation {
            hosting_id: HostingId(hosting.into()),
            package_id,
            package_name: format!("pkg-{package_id}"),
            price_minor: Some(price_minor),
            price_currency: Some("Kč".into()),
            price_interval: Some("monthly".into()),
            // A non-default bundle on purpose: the snapshot is what the drift
            // tick enforces, so a test that activated with an all-`leave`
            // bundle would pass even if the snapshot were dropped entirely.
            features: PackageFeatures {
                wp_auto_update: FeatureToggle::On,
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
