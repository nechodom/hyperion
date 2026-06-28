//! Granular RBAC capabilities.
//!
//! A role — built-in [`WebRole`] or a custom role — is a **set of capabilities**
//! ([`CapSet`], a `u64` bitmask) plus a **scope** (all hostings vs only assigned).
//! Built-in roles map to fixed presets ([`WebRole::capabilities`]); custom roles
//! store their own bitmask. The web layer resolves a logged-in user's effective
//! `CapSet` and gates actions on `Capability`s instead of hardcoded role names.
//!
//! Adding a capability: add the variant, extend [`Capability::ALL`], `as_str`,
//! `label`, and slot it into a group in [`groups`]. The `#[test] all_arrays_cover`
//! test fails if you forget one.
//!
//! See `docs/superpowers/specs/2026-06-28-custom-roles-design.md`.

use crate::web_users::WebRole;

/// One grantable permission. Discriminant = bit index in a [`CapSet`] (≤ 63).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Capability {
    // — Hosting —
    HostingView,
    HostingCreate,
    HostingDelete,
    HostingSuspend,
    HostingEditConfig,
    HostingFiles,
    HostingDatabases,
    HostingCron,
    HostingMigrateClone,
    // — WordPress —
    WpManage,
    WpVulnView,
    // — Backups —
    BackupRun,
    BackupRestore,
    BackupTargets,
    // — TLS —
    CertManage,
    // — Security —
    SecurityManage,
    // — Monitoring —
    MonitoringView,
    MonitoringManage,
    // — Cluster —
    NodesView,
    NodesManage,
    ServicesView,
    ServicesManage,
    // — Platform —
    UsersManage,
    RolesManage,
    SettingsManage,
    ProfilesManage,
    AuditView,
    EmailLogView,
    PanelImport,
    TrashManage,
}

impl Capability {
    /// Every capability, in display order. Keep in sync with the enum.
    pub const ALL: [Capability; 30] = [
        Capability::HostingView,
        Capability::HostingCreate,
        Capability::HostingDelete,
        Capability::HostingSuspend,
        Capability::HostingEditConfig,
        Capability::HostingFiles,
        Capability::HostingDatabases,
        Capability::HostingCron,
        Capability::HostingMigrateClone,
        Capability::WpManage,
        Capability::WpVulnView,
        Capability::BackupRun,
        Capability::BackupRestore,
        Capability::BackupTargets,
        Capability::CertManage,
        Capability::SecurityManage,
        Capability::MonitoringView,
        Capability::MonitoringManage,
        Capability::NodesView,
        Capability::NodesManage,
        Capability::ServicesView,
        Capability::ServicesManage,
        Capability::UsersManage,
        Capability::RolesManage,
        Capability::SettingsManage,
        Capability::ProfilesManage,
        Capability::AuditView,
        Capability::EmailLogView,
        Capability::PanelImport,
        Capability::TrashManage,
    ];

    /// Bit for this capability in a [`CapSet`].
    pub fn bit(self) -> u64 {
        1u64 << (self as u8)
    }

    /// Stable machine id (form field values, storage notes, audit lines).
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::HostingView => "hosting_view",
            Capability::HostingCreate => "hosting_create",
            Capability::HostingDelete => "hosting_delete",
            Capability::HostingSuspend => "hosting_suspend",
            Capability::HostingEditConfig => "hosting_edit_config",
            Capability::HostingFiles => "hosting_files",
            Capability::HostingDatabases => "hosting_databases",
            Capability::HostingCron => "hosting_cron",
            Capability::HostingMigrateClone => "hosting_migrate_clone",
            Capability::WpManage => "wp_manage",
            Capability::WpVulnView => "wp_vuln_view",
            Capability::BackupRun => "backup_run",
            Capability::BackupRestore => "backup_restore",
            Capability::BackupTargets => "backup_targets",
            Capability::CertManage => "cert_manage",
            Capability::SecurityManage => "security_manage",
            Capability::MonitoringView => "monitoring_view",
            Capability::MonitoringManage => "monitoring_manage",
            Capability::NodesView => "nodes_view",
            Capability::NodesManage => "nodes_manage",
            Capability::ServicesView => "services_view",
            Capability::ServicesManage => "services_manage",
            Capability::UsersManage => "users_manage",
            Capability::RolesManage => "roles_manage",
            Capability::SettingsManage => "settings_manage",
            Capability::ProfilesManage => "profiles_manage",
            Capability::AuditView => "audit_view",
            Capability::EmailLogView => "email_log_view",
            Capability::PanelImport => "panel_import",
            Capability::TrashManage => "trash_manage",
        }
    }

    /// Human label for the builder UI.
    pub fn label(self) -> &'static str {
        match self {
            Capability::HostingView => "View hostings",
            Capability::HostingCreate => "Create hostings",
            Capability::HostingDelete => "Delete hostings",
            Capability::HostingSuspend => "Suspend / resume",
            Capability::HostingEditConfig => "Edit hosting config (PHP, nginx, cache, …)",
            Capability::HostingFiles => "File manager",
            Capability::HostingDatabases => "Manage databases",
            Capability::HostingCron => "Manage cron jobs",
            Capability::HostingMigrateClone => "Migrate / clone hostings",
            Capability::WpManage => "Manage WordPress (plugins, staging, …)",
            Capability::WpVulnView => "View WordPress vulnerability scans",
            Capability::BackupRun => "Run backups",
            Capability::BackupRestore => "Restore backups",
            Capability::BackupTargets => "Manage off-site backup targets",
            Capability::CertManage => "Manage TLS certificates",
            Capability::SecurityManage => "Manage security (WAF, fail2ban, firewall)",
            Capability::MonitoringView => "View monitoring & stats",
            Capability::MonitoringManage => "Manage monitors & alerts",
            Capability::NodesView => "View cluster nodes",
            Capability::NodesManage => "Manage nodes (enroll, update, install)",
            Capability::ServicesView => "View service health",
            Capability::ServicesManage => "Manage services (restart, ROFS fix)",
            Capability::UsersManage => "Manage web users",
            Capability::RolesManage => "Manage roles",
            Capability::SettingsManage => "Edit global settings",
            Capability::ProfilesManage => "Manage hosting profiles",
            Capability::AuditView => "View audit log",
            Capability::EmailLogView => "View email log",
            Capability::PanelImport => "Import from another panel",
            Capability::TrashManage => "Manage trash (restore / purge)",
        }
    }

    pub fn from_machine_str(s: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// A set of [`Capability`]s, packed into a `u64` for cheap storage + session
/// carriage. Unknown bits are masked off on load (forward-compat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapSet(u64);

impl CapSet {
    pub const fn empty() -> Self {
        CapSet(0)
    }

    /// Every known capability.
    pub fn all() -> Self {
        let mut bits = 0u64;
        let mut i = 0;
        while i < Capability::ALL.len() {
            bits |= Capability::ALL[i].bit();
            i += 1;
        }
        CapSet(bits)
    }

    /// Build from a stored bitmask, masking off any bits we don't recognise.
    pub fn from_bits(bits: u64) -> Self {
        CapSet(bits & Self::all().0)
    }

    pub fn bits(self) -> u64 {
        self.0
    }

    pub fn contains(self, c: Capability) -> bool {
        self.0 & c.bit() != 0
    }

    pub fn insert(&mut self, c: Capability) {
        self.0 |= c.bit();
    }

    pub fn with(mut self, c: Capability) -> Self {
        self.insert(c);
        self
    }

    /// `true` if every capability in `other` is present in `self` (used by the
    /// no-privilege-escalation guard).
    pub fn is_superset_of(self, other: CapSet) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |c| self.contains(*c))
    }

    pub fn count(self) -> u32 {
        self.0.count_ones()
    }
}

impl FromIterator<Capability> for CapSet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        let mut s = CapSet::empty();
        for c in iter {
            s.insert(c);
        }
        s
    }
}

/// Capability groups for the builder UI: (group label, ordered members).
pub fn groups() -> Vec<(&'static str, Vec<Capability>)> {
    use Capability::*;
    vec![
        (
            "Hosting",
            vec![
                HostingView,
                HostingCreate,
                HostingDelete,
                HostingSuspend,
                HostingEditConfig,
                HostingFiles,
                HostingDatabases,
                HostingCron,
                HostingMigrateClone,
            ],
        ),
        ("WordPress", vec![WpManage, WpVulnView]),
        ("Backups", vec![BackupRun, BackupRestore, BackupTargets]),
        ("TLS", vec![CertManage]),
        ("Security", vec![SecurityManage]),
        ("Monitoring", vec![MonitoringView, MonitoringManage]),
        (
            "Cluster",
            vec![NodesView, NodesManage, ServicesView, ServicesManage],
        ),
        (
            "Platform",
            vec![
                UsersManage,
                RolesManage,
                SettingsManage,
                ProfilesManage,
                AuditView,
                EmailLogView,
                PanelImport,
                TrashManage,
            ],
        ),
    ]
}

impl WebRole {
    /// Fixed capability preset for a built-in role. **Must reproduce the role's
    /// pre-capability behavior** (guarded by parity in the web tests).
    pub fn capabilities(self) -> CapSet {
        use Capability::*;
        match self {
            WebRole::SuperAdmin => CapSet::all(),
            // Admin = everything except managing users + roles.
            WebRole::Admin => CapSet(CapSet::all().0 & !UsersManage.bit() & !RolesManage.bit()),
            // Operator = full control of assigned hostings + their tooling.
            WebRole::Operator => [
                HostingView,
                HostingCreate,
                HostingDelete,
                HostingSuspend,
                HostingEditConfig,
                HostingFiles,
                HostingDatabases,
                HostingCron,
                HostingMigrateClone,
                WpManage,
                WpVulnView,
                BackupRun,
                BackupRestore,
                CertManage,
                SecurityManage,
                MonitoringView,
                MonitoringManage,
            ]
            .into_iter()
            .collect(),
            // Customer = operate their own sites, slim surface.
            WebRole::Customer => [
                HostingView,
                HostingFiles,
                HostingDatabases,
                WpManage,
                WpVulnView,
                BackupRun,
                BackupRestore,
                CertManage,
                MonitoringView,
            ]
            .into_iter()
            .collect(),
            // Viewer = read-only on granted hostings.
            WebRole::Viewer => [HostingView, WpVulnView, MonitoringView]
                .into_iter()
                .collect(),
        }
    }

    /// Does this built-in see ALL hostings (vs only `web_user_hosting_access`)?
    /// Equivalent to the existing `sees_all_hostings()`.
    pub fn scope_all(self) -> bool {
        self.sees_all_hostings()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_array_matches_count() {
        // 30 distinct bits, none above 63.
        let s = CapSet::all();
        assert_eq!(s.count(), 30);
        assert_eq!(Capability::ALL.len(), 30);
    }

    #[test]
    fn machine_strings_unique_and_roundtrip() {
        let mut seen = std::collections::HashSet::new();
        for c in Capability::ALL {
            assert!(
                seen.insert(c.as_str()),
                "duplicate machine str: {}",
                c.as_str()
            );
            assert_eq!(Capability::from_machine_str(c.as_str()), Some(c));
        }
    }

    #[test]
    fn groups_cover_every_capability_once() {
        let mut flat: Vec<Capability> = groups().into_iter().flat_map(|(_, v)| v).collect();
        flat.sort_by_key(|c| *c as u8);
        let mut all = Capability::ALL.to_vec();
        all.sort_by_key(|c| *c as u8);
        assert_eq!(
            flat, all,
            "groups() must list every capability exactly once"
        );
    }

    #[test]
    fn bits_roundtrip_and_mask_unknown() {
        let s = WebRole::Operator.capabilities();
        assert_eq!(CapSet::from_bits(s.bits()), s);
        // A high bit we don't define is masked away.
        let dirty = s.bits() | (1u64 << 60);
        assert_eq!(CapSet::from_bits(dirty), s);
    }

    #[test]
    fn builtin_presets() {
        assert_eq!(WebRole::SuperAdmin.capabilities(), CapSet::all());
        assert!(WebRole::SuperAdmin.scope_all());

        let admin = WebRole::Admin.capabilities();
        assert!(!admin.contains(Capability::UsersManage));
        assert!(!admin.contains(Capability::RolesManage));
        assert!(admin.contains(Capability::SettingsManage));
        assert!(admin.contains(Capability::NodesManage));
        assert!(WebRole::Admin.scope_all());

        // Tenant roles don't see all hostings.
        assert!(!WebRole::Operator.scope_all());
        assert!(!WebRole::Customer.scope_all());
        assert!(!WebRole::Viewer.scope_all());

        // Viewer ⊂ Customer ⊂ Operator ⊂ Admin (monotonic view→manage).
        let viewer = WebRole::Viewer.capabilities();
        let customer = WebRole::Customer.capabilities();
        let operator = WebRole::Operator.capabilities();
        assert!(customer.is_superset_of(viewer), "customer ⊇ viewer");
        assert!(operator.is_superset_of(customer), "operator ⊇ customer");
        assert!(admin.is_superset_of(operator), "admin ⊇ operator");

        // Viewer has no write capabilities.
        for w in [
            Capability::HostingCreate,
            Capability::HostingDelete,
            Capability::BackupRun,
            Capability::WpManage,
        ] {
            assert!(!viewer.contains(w), "viewer must not have {}", w.as_str());
        }
    }
}
