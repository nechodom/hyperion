//! WordPress install request + status types.
//!
//! `wp-cli` itself lives in `hyperion-adapters::wpcli` — these are the
//! crate-boundary DTOs that travel over the RPC wire and end up in the
//! `wp_installs` state table.

use serde::{Deserialize, Serialize};

use crate::HostingId;

/// serde default for a boolean field that should be on unless said otherwise.
fn default_true() -> bool {
    true
}

/// Operator-supplied options for `wp core install`.
///
/// All strings are validated at the boundary (`hyperion-validate`) before
/// they ever reach `wp-cli`. Plaintext `admin_password` lives in memory
/// only as long as the request takes to dispatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpInstallRequest {
    /// Canonical site URL (with scheme). E.g. `https://example.com`.
    pub site_url: String,
    /// `wp_options.blogname` — shown in the admin bar.
    pub title: String,
    /// Initial admin username for the WP user table.
    pub admin_user: String,
    pub admin_email: String,
    pub admin_password: String,
    /// Locale code (`cs_CZ`, `en_US`, `sk_SK`, …). Default `en_US`.
    #[serde(default = "default_locale")]
    pub locale: String,
    /// `latest` or a specific version like `6.5.3`.
    #[serde(default = "default_version")]
    pub version: String,
    /// When true, the post-install runs `wp option update blog_public 0`
    /// — flips the WP admin's "Discourage search engines from
    /// indexing this site" toggle on. Set by the web layer for
    /// hostings on test nodes when `cluster.test_wp_no_index` is on.
    #[serde(default)]
    pub no_index: bool,
}

fn default_locale() -> String {
    "en_US".into()
}

fn default_version() -> String {
    "latest".into()
}

/// Current WordPress-install state for a hosting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpInstallStatus {
    pub hosting_id: HostingId,
    pub site_url: String,
    pub wp_version: String,
    pub installed_at: i64,
    pub last_pack_hash: String,
}

/// One row in the WordPress plugin manager UI. Maps 1:1 to a
/// `wp plugin list --format=json` row from wp-cli — fields filtered
/// to what the operator actually needs and re-serialized to a
/// stable Rust-friendly shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpPlugin {
    /// Plugin folder slug — the `wp plugin <action> <slug>` argument.
    pub slug: String,
    /// Human-readable name from the plugin's main PHP file header.
    pub name: String,
    /// Installed version.
    pub version: String,
    /// "active" | "inactive" | "must-use" | "dropin" | "active-network"
    pub status: String,
    /// `true` if wp-cli reports a newer version is available.
    pub update_available: bool,
    /// Latest known upstream version, when `update_available == true`.
    /// Empty otherwise.
    pub latest_version: String,
    /// Whether `auto_update` is enabled at the WordPress level for
    /// this plugin (independent of Hyperion's bulk `auto_update_plugins`
    /// flag on the install).
    pub auto_update: bool,
    /// Set by the master when the keyless defender has PAUSED auto-updates
    /// for this plugin: a minor/patch update kept failing, almost always
    /// because the plugin is commercial and the package download needs a
    /// license key. The plugin is still listed and usable — auto-update just
    /// won't keep retrying (and re-alerting) until the pause lapses or an
    /// operator clicks Resume. Defaults `false`; the agent doesn't know about
    /// the skip-list, so the service layer overlays this in `wp_plugin_list`.
    #[serde(default)]
    pub auto_update_blocked: bool,
    /// One-line reason for the pause (the trimmed wp-cli error), shown next to
    /// the "Auto-update paused" badge. `None` unless `auto_update_blocked`.
    #[serde(default)]
    pub auto_update_block_reason: Option<String>,
}

/// Response payload for `WpPluginList` — the plugin table plus
/// some metadata about the current WordPress install.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpPluginListResponse {
    pub plugins: Vec<WpPlugin>,
    /// WordPress core version on disk.
    pub wp_version: String,
    /// Sum of `update_available == true` rows — surfaced as a badge
    /// in the UI without re-counting client-side.
    pub updates_pending: i64,
    /// `auto_update_plugins` flag from `wp_installs` — the bulk
    /// switch in the Hosting Detail UI.
    pub bulk_auto_update: bool,
    /// Set when the live `wp plugin list` lookup FAILED (wp-cli couldn't
    /// bootstrap WordPress — e.g. a database connection error, a PHP
    /// fatal/notice corrupting the JSON, or a permissions problem). The
    /// web layer puts the reason here instead of silently returning an
    /// empty list, so the panel can show "couldn't list plugins" with the
    /// cause rather than a misleading "no plugins installed". `None` on a
    /// successful lookup (including a genuinely empty install).
    #[serde(default)]
    pub error: Option<String>,
}

/// One outdated installed component (plugin / theme). The "defender" is
/// keyless: it flags components with an available update rather than
/// matching a third-party CVE feed — outdated components are the #1
/// real-world WordPress attack vector, and wp-cli already knows the
/// latest version (it queries WordPress.org).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpVulnFinding {
    pub slug: String,
    pub name: String,
    /// Currently-installed version.
    pub installed_version: String,
    pub title: String,
    /// "high" (major behind) | "medium" (minor) | "low" (patch).
    pub severity: String,
    /// CVE id — empty in keyless mode (kept for wire compatibility).
    pub cve: String,
    /// Version to update TO (the latest available).
    pub patched_version: String,
    /// "plugin" | "theme".
    pub kind: String,
    /// "major" | "minor" | "patch" — how far behind the latest is.
    #[serde(default)]
    pub update_type: String,
    /// True when the latest is a same-major bump, so the defender will
    /// auto-apply it (minor/patch policy). Majors are left to the operator.
    #[serde(default)]
    pub auto_updatable: bool,
    /// Consecutive failed auto-update attempts for this plugin, from the
    /// node's pause map at the time the finding was read (not stored with
    /// the scan, so a Resume shows at once). 0 = none.
    #[serde(default)]
    pub auto_update_failures: u32,
    /// Unix seconds the auto-update is paused until; later than now means
    /// the sweep will not try it (a licence-gated plugin, usually). 0 = not
    /// paused.
    #[serde(default)]
    pub auto_update_paused_until: i64,
    /// The last auto-update error for this plugin, trimmed. Empty = none.
    #[serde(default)]
    pub auto_update_error: String,
}

/// One WordPress core release `wp core check-update` offers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpCoreUpdate {
    pub version: String,
    /// wp-cli's own classification: "minor" (a point/security release the
    /// sweep applies by itself when auto-update is on) or "major".
    pub update_type: String,
}

impl WpCoreUpdate {
    /// Safe to apply unattended — same rule the sweep uses.
    pub fn is_minor(&self) -> bool {
        self.update_type.eq_ignore_ascii_case("minor")
    }
}

/// Result of a WordPress update/outdated scan (keyless — via wp-cli's own
/// update status, no external feed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpVulnScanResult {
    pub findings: Vec<WpVulnFinding>,
    /// True when wp-cli couldn't enumerate the install (broken WP, perms) —
    /// the UI shows "couldn't check" rather than a false "all clear".
    #[serde(alias = "feed_unavailable")]
    pub feed_unavailable: bool,
    /// Unused in keyless mode (kept for wire compatibility).
    #[serde(default)]
    pub feed_age_secs: i64,
    /// Plugins + themes actually checked.
    pub checked: i64,
    /// How many components the defender auto-updated on this run (tick only).
    #[serde(default)]
    pub auto_updated: i64,
    /// WordPress core version on disk, as wp-cli reported it. Empty when the
    /// scan could not read it (or came from an older agent).
    #[serde(default)]
    pub core_version: String,
    /// True when `wp core check-update` answered. False means "core was not
    /// checked" — never read it as "core is current".
    #[serde(default)]
    pub core_checked: bool,
    /// Core releases on offer, newest first. Empty + `core_checked` = current.
    #[serde(default)]
    pub core_updates: Vec<WpCoreUpdate>,
    /// Why the scan could not read the install, when `feed_unavailable`.
    #[serde(default)]
    pub error: String,
}

/// One hosting's last stored vuln-scan result, for the cluster-wide
/// vulnerability dashboard. Findings are pre-sorted highest-severity
/// first by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingVulnSummary {
    pub hosting_id: String,
    pub domain: String,
    /// Node the hosting lives on (filled by the web aggregator).
    pub node_id: String,
    /// Unix seconds of the scan. 0 = never scanned.
    pub scanned_at: i64,
    pub findings: Vec<WpVulnFinding>,
    /// The site's daily minor/patch auto-update switch, read when the list
    /// was built. `None` = the node's agent is too old to say — the page
    /// must not assume either way.
    #[serde(default)]
    pub auto_update: Option<bool>,
    /// Components the last sweep updated by itself.
    #[serde(default)]
    pub auto_updated: i64,
    /// Plugins + themes the last good scan checked.
    #[serde(default)]
    pub checked: i64,
    #[serde(default)]
    pub core_version: String,
    #[serde(default)]
    pub core_checked: bool,
    #[serde(default)]
    pub core_updates: Vec<WpCoreUpdate>,
    /// Unix seconds of the last attempt that could NOT read the site, when it
    /// is newer than `scanned_at`; the findings are then from the last good
    /// scan. 0 = the last attempt worked.
    #[serde(default)]
    pub failed_at: i64,
    /// Why that attempt failed.
    #[serde(default)]
    pub error: String,
}

impl HostingVulnSummary {
    /// Count of findings at the given severity.
    pub fn count_severity(&self, sev: &str) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}

/// One file inside a verified plugin that didn't match the checksums
/// WordPress.org publishes for that exact plugin version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpIntegrityFileIssue {
    /// Path relative to the plugin directory (wp-cli reports it that way).
    pub path: String,
    /// wp-cli's own wording, passed through verbatim rather than
    /// re-classified: "Checksum does not match" | "File was added" |
    /// "File is missing". Keeping the source string means a wp-cli
    /// version that adds a new message still renders something true.
    pub message: String,
}

/// One plugin whose files failed checksum verification. Grouped per plugin
/// (not a flat file list) because the operator acts per plugin — reinstall
/// it, or look at it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpIntegrityPluginResult {
    /// Plugin directory slug, as wp-cli reports it.
    pub slug: String,
    pub issues: Vec<WpIntegrityFileIssue>,
    /// The version that was compared. Empty on a record from before this field.
    #[serde(default)]
    pub version: String,
    /// What it was compared with: the same label as its findings'.
    #[serde(default)]
    pub source: Option<String>,
}

/// `source_label` on a comparison with a vendor's package.
pub const VENDOR_PACKAGE_LABEL: &str = "vendor package";
/// `source_label` when packages for one slug and version were seen to differ.
pub const PACKAGES_DISAGREE_LABEL: &str = "packages for this version disagree";

/// One ClamAV detection: the file, and the signature that matched it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpMalwareHit {
    /// Absolute path on the node.
    pub path: String,
    /// ClamAV signature name, e.g. `Php.Trojan.Webshell-1`.
    pub signature: String,
}

/// What the scan says about a hard-linked file: it never reads one.
pub const HARD_LINKED_SNIPPET: &str = "hard-linked file: not read";
/// How the scan's words for a file it didn't read end.
const NOT_READ_SNIPPET_END: &str = "too large to read";

/// The root file quarantine refuses by name.
const WP_CONFIG_REL: &str = "wp-config.php";
/// How the scanner marks a name it cut, and the shortest such name. The name of a
/// file that really ends this way only loses its buttons.
const CUT_NAME_MARK: char = '…';
const CUT_NAME_MIN_BYTES: usize = 200;

/// How the native site scanner came to report a file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// A core file whose content differs from the release.
    CoreModified,
    /// In `wp-admin`, `wp-includes` or the docroot root, but not in the release.
    CoreUnexpected,
    /// A release file that is gone.
    CoreMissing,
    /// A plugin or theme file whose content differs from its reference copy.
    UpstreamModified,
    /// In a plugin or theme tree, but not in its reference copy.
    UpstreamAdded,
    /// A file of the reference copy that is gone.
    UpstreamMissing,
    /// A file nothing vouches for hit a rule.
    RuleHit,
    /// Too big for the rules to read in full.
    TooLargeToInspect,
    /// New or changed since the baseline, with no rule hit.
    #[default]
    BaselineChange,
}

/// One file the native scanner reports. `snippet` is plain text from a tenant
/// file: the template escapes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SiteFileFinding {
    /// Relative to the docroot. A whole component's finding uses its folder.
    #[serde(default)]
    pub rel: String,
    #[serde(default)]
    pub kind: FindingKind,
    /// "high" | "medium".
    #[serde(default)]
    pub severity: String,
    /// The worst rule that hit, when one did.
    #[serde(default)]
    pub rule_id: Option<String>,
    /// 1-based line of `rule_id`'s match; 0 when no rule hit.
    #[serde(default)]
    pub line: u32,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub snippet: String,
    /// Hex. Empty when the file wasn't read.
    #[serde(default)]
    pub sha256: String,
    /// Slug of the plugin or theme the file belongs to.
    #[serde(default)]
    pub component: Option<String>,
    /// "wordpress.org" | "vendor package", on upstream findings.
    #[serde(default)]
    pub source_label: Option<String>,
    /// The name is a symlink: `sha256` is what it points at, not any content.
    #[serde(default)]
    pub symlink: bool,
}

/// One file held in quarantine: what restoring it needs and what the card lists.
/// Never its content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QuarantinedFile {
    /// Random hex, never tenant text.
    #[serde(default)]
    pub id: String,
    /// Where it was, relative to the docroot.
    #[serde(default)]
    pub rel: String,
    /// The hash the scan reported.
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size: u64,
    /// As it was. Restoring masks it to the permission bits.
    #[serde(default)]
    pub mode: u32,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    /// Unix seconds it was quarantined.
    #[serde(default)]
    pub time: i64,
    #[serde(default)]
    pub kind: FindingKind,
    #[serde(default)]
    pub rule_id: Option<String>,
    /// ClamAV's hits on this file when it was moved. They went with it, and come
    /// back with it: a hit only ever clears by a ClamAV pass not finding it.
    #[serde(default)]
    pub malware: Vec<WpMalwareHit>,
}

/// What a hosting has in quarantine, newest first. `total` counts what the cap
/// left out of `items`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QuarantineList {
    #[serde(default)]
    pub items: Vec<QuarantinedFile>,
    #[serde(default)]
    pub total: u64,
}

impl QuarantineList {
    /// The cap left something out.
    pub fn is_cut(&self) -> bool {
        self.total > u64::try_from(self.items.len()).unwrap_or(u64::MAX)
    }
}

impl FindingKind {
    /// What the card says about a file of this kind.
    pub fn label(self) -> &'static str {
        match self {
            Self::CoreModified => "core file differs from the release",
            Self::CoreUnexpected => "not part of the release",
            Self::CoreMissing => "official core file is missing",
            Self::UpstreamModified => "differs from its reference copy",
            Self::UpstreamAdded => "not in the reference copy",
            Self::UpstreamMissing => "missing from the reference copy",
            Self::RuleHit => "matches a malware rule",
            Self::TooLargeToInspect => "too large to inspect",
            Self::BaselineChange => "new or changed since the first scan",
        }
    }
}

impl SiteFileFinding {
    /// A failed comparison with core, a plugin or a theme: the card lists these
    /// under that component, where its fix is.
    pub fn is_comparison(&self) -> bool {
        matches!(
            self.kind,
            FindingKind::CoreModified
                | FindingKind::CoreUnexpected
                | FindingKind::CoreMissing
                | FindingKind::UpstreamModified
                | FindingKind::UpstreamAdded
                | FindingKind::UpstreamMissing
        )
    }

    /// Does a core, plugin or theme section of the card show this comparison?
    /// Hyperion's own files belong to no component, so none does.
    pub fn has_section(&self) -> bool {
        self.is_comparison()
            && (self.component.is_some()
                || matches!(
                    self.kind,
                    FindingKind::CoreModified
                        | FindingKind::CoreUnexpected
                        | FindingKind::CoreMissing
                ))
    }

    /// "plugin" or "theme" when the finding stands for that whole folder rather
    /// than a file in it. Core's whole-component finding is `.`, which the card
    /// words on its own.
    pub fn component_wide(&self) -> Option<&'static str> {
        let slug = self.component.as_deref()?;
        let mut parts = self.rel.rsplit('/');
        if !self.is_comparison() || parts.next() != Some(slug) {
            return None;
        }
        match parts.next() {
            Some("plugins" | "mu-plugins") => Some("plugin"),
            Some("themes") => Some("theme"),
            _ => None,
        }
    }

    /// Does this item name one file the actions can reach? Not a whole core or
    /// component, not a name the scan had to cut, and not a file it never hashed.
    pub fn is_actionable(&self) -> bool {
        !self.sha256.is_empty()
            && self.rel != "."
            && self.component_wide().is_none()
            && !(self.rel.ends_with(CUT_NAME_MARK) && self.rel.len() >= CUT_NAME_MIN_BYTES)
    }

    /// Trust is for what nothing else can speak for. A file that fails its
    /// comparison can be repaired, reinstalled or quarantined, so no trust list
    /// can override a manifest.
    pub fn can_trust(&self) -> bool {
        self.is_actionable() && !self.is_comparison()
    }

    /// Root doesn't touch a symlink, and `wp-config.php` isn't a file a site can
    /// lose. Hard-linked files never get a hash, and missing ones have nothing
    /// to move.
    pub fn can_quarantine(&self) -> bool {
        self.is_actionable()
            && !self.symlink
            && self.rel != WP_CONFIG_REL
            && !matches!(
                self.kind,
                FindingKind::CoreMissing | FindingKind::UpstreamMissing
            )
    }

    /// A difference from a vendor's package held for review, in the card's words:
    /// the pilot's, or a version whose packages disagree. Quarantine isn't offered
    /// next to one, since nothing has shown the reference is right. A rule hit isn't
    /// held, and speaks for itself.
    pub fn held_vendor_note(&self) -> Option<&'static str> {
        if !self.is_comparison() || self.rule_id.is_some() {
            return None;
        }
        match self.source_label.as_deref() {
            Some(VENDOR_PACKAGE_LABEL) => Some("differs from the vendor's package, not confirmed"),
            Some(PACKAGES_DISAGREE_LABEL) => Some(PACKAGES_DISAGREE_LABEL),
            _ => None,
        }
    }

    /// Would moving this file away likely stop the site loading? Core and
    /// component files, and the ones WordPress or PHP load by name.
    pub fn looks_loaded_by_site(&self) -> bool {
        if self.is_comparison() {
            return true;
        }
        let rel = self.rel.as_str();
        if matches!(
            rel,
            "index.php"
                | ".htaccess"
                | ".user.ini"
                | "wp-content/db.php"
                | "wp-content/object-cache.php"
                | "wp-content/advanced-cache.php"
        ) || rel.starts_with("wp-content/mu-plugins/")
        {
            return true;
        }
        if let Some(rest) = rel.strip_prefix("wp-content/themes/") {
            return rest.split('/').nth(1) == Some("functions.php") && rest.split('/').count() == 2;
        }
        let Some(rest) = rel.strip_prefix("wp-content/plugins/") else {
            return false;
        };
        match rest.split_once('/') {
            // A single-file plugin.
            None => true,
            Some((slug, file)) => file.strip_suffix(".php") == Some(slug),
        }
    }

    /// Too large for the scan to have opened: its hash is only of its metadata, so
    /// nothing at all is known about what's in it.
    pub fn never_read(&self) -> bool {
        self.rule_id.is_none() && self.snippet.ends_with(NOT_READ_SNIPPET_END)
    }

    /// Read in part: past the size the rules look at, so its hash is real but the
    /// rest of it wasn't inspected.
    pub fn read_in_part(&self) -> bool {
        self.kind == FindingKind::TooLargeToInspect && self.rule_id.is_some()
    }

    /// Reported without being read because it has other names. It gets no hash, so
    /// no button, and SFTP is how to deal with it.
    pub fn is_hard_linked(&self) -> bool {
        self.sha256.is_empty() && self.snippet == HARD_LINKED_SNIPPET
    }

    /// Is this the file a failed component lists as `path`? Issue paths are
    /// relative to the component, and a single-file plugin's is its own name.
    pub fn is_issue(&self, slug: &str, path: &str) -> bool {
        if self.component.as_deref() != Some(slug) {
            return false;
        }
        ["plugins", "mu-plugins", "themes"].iter().any(|kind| {
            self.rel == format!("wp-content/{kind}/{slug}/{path}")
                || (!path.contains('/') && self.rel == format!("wp-content/{kind}/{path}"))
        })
    }
}

/// What the card says about a hosting, in the order the answers win.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanVerdict {
    /// Something needs a look: a failed comparison, a rule hit, a ClamAV hit.
    Findings,
    /// Only changes to review.
    Review,
    /// The scan ran, covered the site and found nothing.
    Clean,
    /// A named part didn't run, so nothing here is a clean result.
    Partial,
    /// A scan is queued and nothing standing outranks it.
    Running,
    /// No scan has finished.
    Never,
}

impl ScanVerdict {
    /// Stable name for markup and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Findings => "findings",
            Self::Review => "review",
            Self::Clean => "clean",
            Self::Partial => "partial",
            Self::Running => "running",
            Self::Never => "never",
        }
    }
}

/// What the native scan could speak for. A verdict states this rather than
/// implying everything was looked at.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ScanCoverage {
    #[serde(default)]
    pub plugins_verified: i64,
    #[serde(default)]
    pub plugins_total: i64,
    #[serde(default)]
    pub themes_verified: i64,
    #[serde(default)]
    pub themes_total: i64,
    /// Files under change detection.
    #[serde(default)]
    pub files_watched: i64,
    /// Unix seconds of the first scan; earlier changes can't be proven.
    #[serde(default)]
    pub watching_since: i64,
    /// Non-PHP files bigger than the rules read: hashed and watched, with only
    /// the start inspected (or, at the extreme, not read at all).
    #[serde(default)]
    pub files_partly_inspected: i64,
    /// Symlinks not followed where a file of that name wouldn't have been looked
    /// at anyway. Any other symlink is a review item.
    #[serde(default)]
    pub symlinks_skipped: i64,
    /// Core was compared with its release.
    #[serde(default)]
    pub upstream_ran: bool,
    /// Not WordPress, so there is no release to compare with. Not a failure.
    #[serde(default)]
    pub no_upstream: bool,
    /// What couldn't be looked at. Non-empty means the scan is partial.
    #[serde(default)]
    pub partial_reasons: Vec<String>,
    /// Hosts this site's package URLs name that aren't on the vendor list, so the
    /// list can grow from real data. Validated hostnames, at most 20, for the
    /// operator: no card shows them to a customer.
    #[serde(default)]
    pub unknown_vendor_hosts: Vec<String>,
    /// Why this site's premium plugins and themes weren't compared with their
    /// vendors' packages. Not a gap in the scan, so not a partial reason: they stay
    /// watched like any custom code, and aren't counted as verified.
    #[serde(default)]
    pub vendor_note: Option<String>,
    /// Of `plugins_verified`, those compared with a vendor's package.
    #[serde(default)]
    pub plugins_vendor_verified: i64,
    /// Of `themes_verified`, those compared with a vendor's package.
    #[serde(default)]
    pub themes_vendor_verified: i64,
    /// The vendor packages behind this scan's differences, for the operator.
    #[serde(default)]
    pub vendor_packages: Vec<VendorPackageInfo>,
}

impl ScanCoverage {
    pub fn any_vendor_verified(&self) -> bool {
        self.plugins_vendor_verified > 0 || self.themes_vendor_verified > 0
    }

    pub fn themes_wporg_verified(&self) -> i64 {
        (self.themes_verified - self.themes_vendor_verified).max(0)
    }
}

/// Where a cached vendor manifest came from. Never a URL. Names other hostings, so
/// it's for operators only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VendorPackageInfo {
    #[serde(default)]
    pub theme: bool,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub version: String,
    /// The host the package finally came from.
    #[serde(default)]
    pub final_host: String,
    /// Who produced it, then who downloaded the same thing.
    #[serde(default)]
    pub hostings: Vec<String>,
    /// Unix seconds it was first cached.
    #[serde(default)]
    pub at: i64,
    #[serde(default)]
    pub disputed: bool,
}

/// Result of a WordPress **integrity** scan — the sibling of
/// [`WpVulnScanResult`]. Where the vuln scan answers "is anything
/// outdated?", this answers "has anything been *tampered with*?" using
/// two independent, keyless signals:
///
///   1. wp-cli checksum verification of core + plugins against the
///      hashes WordPress.org publishes (catches injected/modified PHP),
///   2. a ClamAV pass over the docroot (catches uploaded webshells in
///      `wp-content`, which core checksum verification deliberately skips).
///
/// Both signals can be *absent*: wp-cli may fail to bootstrap a broken
/// install and ClamAV is optional on a shared host. Those cases set
/// `wp_cli_ok` / `clamav_available` to false so the UI says "couldn't
/// check" instead of a false "all clear" — the same honesty
/// `WpVulnScanResult::feed_unavailable` buys the vuln panel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpIntegrityScanResult {
    /// True only when core verification actually ran AND found nothing.
    /// Never true when `wp_cli_ok` is false.
    #[serde(default)]
    pub core_ok: bool,
    /// Core files present on disk whose content differs from the official
    /// release ("File doesn't verify against checksum"). This is the
    /// signal that matters: a modified `wp-includes/*.php` is a backdoor
    /// until proven otherwise.
    #[serde(default)]
    pub core_modified: Vec<String>,
    /// Files that are not part of the official release at all ("File
    /// should not exist") — a dropper parked inside `wp-admin`.
    #[serde(default)]
    pub core_unexpected: Vec<String>,
    /// Official files that are gone ("File doesn't exist"). Usually a
    /// botched update or an over-eager "security" plugin, but it also
    /// means the install no longer matches upstream.
    #[serde(default)]
    pub core_missing: Vec<String>,
    /// Plugins with at least one file that failed verification.
    #[serde(default)]
    pub plugins_failed: Vec<WpIntegrityPluginResult>,
    /// Slugs wp-cli could NOT verify because WordPress.org publishes no
    /// checksums for them — every premium/private plugin (Elementor Pro,
    /// ACF Pro, WP Rocket, …). This is explicitly **not** a finding:
    /// conflating "unknown" with "failed" would cry wolf on every paying
    /// customer's site and train the operator to ignore the panel.
    #[serde(default)]
    pub plugins_unknown: Vec<String>,
    /// ClamAV detections under the docroot. Empty when `clamav_available`
    /// is false — which means "not scanned", not "clean".
    #[serde(default)]
    pub malware: Vec<WpMalwareHit>,
    /// Whether a ClamAV pass over this docroot actually ran, i.e. whether
    /// `malware` means anything. False is a normal, expected state (clamd
    /// is heavy for a shared host) — never an error.
    #[serde(default)]
    pub clamav_available: bool,
    /// Whether `clamscan` exists on the node, separately from whether it
    /// ran for this site. An installed scanner still produces no pass when
    /// the node's one scan slot is busy or clamscan cannot finish, and the
    /// UI must not tell the operator to install what is already there.
    /// Absent (false) from nodes older than this field.
    #[serde(default)]
    pub clamav_installed: bool,
    /// Unix seconds the node's weekly ClamAV pass last covered this site; 0 =
    /// never. The card says when ClamAV last looked, since it is not part of
    /// "Scan now".
    #[serde(default)]
    pub clamav_at: i64,
    /// Whether core was compared with its release at all (wp-cli did this once,
    /// hence the name). False for a broken install, a site with no WordPress, or
    /// a WordPress.org lookup that failed.
    #[serde(default)]
    pub wp_cli_ok: bool,
    /// Plugins actually compared against published checksums (excludes
    /// `plugins_unknown`) — the denominator behind "verified N of M plugins".
    #[serde(default)]
    pub plugins_checked: i64,
    /// Every plugin installed, checked or not.
    #[serde(default)]
    pub plugins_total: i64,
    /// Why the scan couldn't complete, when it couldn't. `None` on a
    /// successful run. Same role as `WpPluginListResponse::error`.
    #[serde(default)]
    pub error: Option<String>,
    /// Unix seconds of the scan. 0 = never scanned.
    #[serde(default)]
    pub scanned_at: i64,
    /// A scan was asked for and has not finished. A view flag set by the
    /// panel, never stored: it only tells the card to keep polling.
    #[serde(default)]
    pub scan_queued: bool,
    /// The native scanner ran, so the fields below mean something.
    #[serde(default)]
    pub native_scan_ran: bool,
    /// The native layers are in their silent pilot: shown in the panel only.
    #[serde(default)]
    pub report_only: bool,
    /// Rule hits and failed comparisons.
    #[serde(default)]
    pub findings: Vec<SiteFileFinding>,
    /// Changes to review: the lower bucket.
    #[serde(default)]
    pub review: Vec<SiteFileFinding>,
    /// Files a git deploy or a restore changed that no rule objected to, accepted
    /// without review. `source_label` says which. Not a verdict on them.
    #[serde(default)]
    pub accepted_by_writer: Vec<SiteFileFinding>,
    /// Themes with at least one file that failed comparison.
    #[serde(default)]
    pub themes_failed: Vec<WpIntegrityPluginResult>,
    #[serde(default)]
    pub coverage: ScanCoverage,
    /// Someone's quarantine, restore or trust edited this record since a scan wrote
    /// it, and no scan has spoken since. What's here is still the last scan's minus
    /// what was acted on, so nothing may call it clean: on the card or in a report.
    /// Gone with the next result a scan stores.
    #[serde(default)]
    pub awaiting_rescan: bool,
}

impl WpIntegrityScanResult {
    /// Total core files flagged, across all three buckets.
    pub fn core_issue_count(&self) -> usize {
        self.core_modified.len() + self.core_unexpected.len() + self.core_missing.len()
    }

    /// Total plugin files flagged, across all failed plugins.
    pub fn plugin_issue_count(&self) -> usize {
        self.plugins_failed.iter().map(|p| p.issues.len()).sum()
    }

    /// Everything an operator would have to look at on this hosting.
    pub fn total_findings(&self) -> usize {
        self.core_issue_count() + self.plugin_issue_count() + self.malware.len()
    }

    /// Plugins compared with wordpress.org, apart from those compared with a vendor.
    pub fn plugins_wporg_checked(&self) -> i64 {
        (self.plugins_checked - self.coverage.plugins_vendor_verified).max(0)
    }

    /// The label the scan put on a plugin or theme's findings.
    pub fn source_label_of(&self, slug: &str) -> Option<&str> {
        self.findings
            .iter()
            .chain(&self.review)
            .filter(|f| f.component.as_deref() == Some(slug))
            .find_map(|f| f.source_label.as_deref())
    }

    /// What a plugin or theme was compared with, as a phrase: its finding's
    /// label. Without one, a record from before the labels can only have meant
    /// wordpress.org; on a native record the list was cut short and nobody knows.
    pub fn reference_of(&self, slug: &str) -> &str {
        match self.source_label_of(slug) {
            Some(VENDOR_PACKAGE_LABEL) => "the vendor's package",
            Some(l) => l,
            None if self.native_scan_ran => "its source",
            None => "wordpress.org",
        }
    }

    /// May the card offer to replace this plugin with wordpress.org's copy?
    /// Only when that is what it was compared with. A private plugin that shares
    /// a slug with a wordpress.org one would be swapped for a different plugin.
    /// A native record whose findings carry no label (cut by the item cap) is not
    /// assumed to be wordpress.org; only a record from before the label is. A
    /// plugin and a theme can share a slug, so one other label is enough to say no.
    pub fn reinstallable_from_wordpress_org(&self, slug: &str) -> bool {
        let mut labels = self
            .findings
            .iter()
            .chain(&self.review)
            .filter(|f| f.component.as_deref() == Some(slug))
            .filter_map(|f| f.source_label.as_deref())
            .peekable();
        if labels.peek().is_none() {
            return !self.native_scan_ran;
        }
        labels.all(|l| l == "wordpress.org")
    }

    /// The finding behind a line of the core lists.
    pub fn finding_at(&self, rel: &str) -> Option<&SiteFileFinding> {
        self.findings.iter().find(|f| f.rel == rel)
    }

    /// The finding behind a failed plugin's or theme's line.
    pub fn finding_of_issue(&self, slug: &str, path: &str) -> Option<&SiteFileFinding> {
        self.findings.iter().find(|f| f.is_issue(slug, path))
    }

    /// What "Trust all changes to review" takes: no rule hit, nothing a comparison
    /// failed, a hash to hold it to, and nothing too large to inspect. Padding a
    /// PHP file past what's read mustn't get it through in bulk; one at a time, the
    /// dialog says it was never read.
    pub fn trust_all_items(&self) -> impl Iterator<Item = &SiteFileFinding> {
        self.review.iter().filter(|f| {
            f.can_trust() && f.rule_id.is_none() && f.kind != FindingKind::TooLargeToInspect
        })
    }

    /// Would "Trust all" accept a symlink? Its dialog has to say what that means.
    pub fn trust_all_has_symlink(&self) -> bool {
        self.trust_all_items().any(|f| f.symlink)
    }

    /// Theme files flagged, across all failed themes.
    pub fn theme_issue_count(&self) -> usize {
        self.themes_failed.iter().map(|t| t.issues.len()).sum()
    }

    /// The findings the card lists on their own. Failed comparisons are left out:
    /// the core, plugin and theme sections already show them, with the fix. One
    /// that also hit a rule stays, because those sections don't carry the rule,
    /// and so does one no section carries, such as Hyperion's own file.
    pub fn listed_findings(&self) -> impl Iterator<Item = &SiteFileFinding> {
        self.findings
            .iter()
            .filter(|f| !f.has_section() || f.rule_id.is_some())
    }

    /// The number in the headline: `shown_finding_count`, but never below what
    /// the findings list shows, so a lone rule-carrying comparison reads 1, not 0.
    pub fn headline_count(&self) -> usize {
        self.shown_finding_count()
            .max(self.listed_findings().count())
    }

    /// Everything the card puts under "needs attention". A failed comparison
    /// that also hit a rule is listed twice but is one file, already counted with
    /// its core, plugin or theme.
    pub fn shown_finding_count(&self) -> usize {
        self.total_findings()
            + self.theme_issue_count()
            + self.listed_findings().filter(|f| !f.has_section()).count()
    }

    /// What the card says. Standing findings and changes to review come first and
    /// stay in front of a queued scan, which only adds its spinner; a queued scan
    /// otherwise stands in for the last verdict. A record from before the native
    /// scan keeps its old meanings. `report_only` doesn't matter here: the panel
    /// shows the pilot's results, it is the alerts and reports that wait. Any
    /// finding at all is Findings, so the card never reads Clean where
    /// `is_clean` doesn't.
    pub fn verdict(&self) -> ScanVerdict {
        if self.shown_finding_count() > 0 || !self.findings.is_empty() {
            return ScanVerdict::Findings;
        }
        if !self.review.is_empty() {
            return ScanVerdict::Review;
        }
        if self.scan_queued || self.awaiting_rescan {
            return ScanVerdict::Running;
        }
        if self.scanned_at == 0 {
            return ScanVerdict::Never;
        }
        if !self.native_scan_ran {
            return if self.is_clean() {
                ScanVerdict::Clean
            } else {
                ScanVerdict::Partial
            };
        }
        if self.scan_partial() || !(self.coverage.upstream_ran || self.coverage.no_upstream) {
            ScanVerdict::Partial
        } else {
            ScanVerdict::Clean
        }
    }

    /// The native scan ran but couldn't look at all of the site: it stopped, hit
    /// a limit, or something in the tree couldn't be read.
    pub fn scan_partial(&self) -> bool {
        self.native_scan_ran && !self.coverage.partial_reasons.is_empty()
    }

    /// The native scan ran and its results count: not the silent pilot, and not
    /// a record from before the scan existed.
    pub fn is_live(&self) -> bool {
        self.native_scan_ran && !self.report_only
    }

    /// A scan that covered the whole site and found nothing. A scan where
    /// upstream couldn't be compared, or that was partial, is "unknown", never
    /// clean — the UI must not print a green tick for it.
    ///
    /// A live native scan needs no ClamAV: it is its own malware check. It reads
    /// the new buckets too, and a site with no upstream to compare (not
    /// WordPress) is clean on the scan alone. The silent pilot and records from
    /// before the scan keep the older rule: wp-cli's comparison AND ClamAV, both
    /// ran and both came back empty.
    pub fn is_clean(&self) -> bool {
        if self.is_live() {
            return (self.coverage.upstream_ran || self.coverage.no_upstream)
                && !self.scan_partial()
                && !self.awaiting_rescan
                && self.total_findings() == 0
                && self.theme_issue_count() == 0
                && self.findings.is_empty()
                && self.review.is_empty();
        }
        self.wp_cli_ok
            && self.clamav_available
            && !self.scan_partial()
            && !self.awaiting_rescan
            && self.total_findings() == 0
    }
}

/// One hosting's last stored integrity-scan result, for the cluster-wide
/// integrity dashboard. Mirrors [`HostingVulnSummary`] so the two
/// dashboards can share a layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingIntegritySummary {
    pub hosting_id: String,
    pub domain: String,
    /// Node the hosting lives on (filled by the web aggregator).
    pub node_id: String,
    /// Unix seconds of the scan. 0 = never scanned.
    pub scanned_at: i64,
    pub result: WpIntegrityScanResult,
}

/// Whitelisted plugin actions exposed via the web UI. Anything not
/// in this enum cannot be invoked from a form — the wp-cli surface
/// is large and we'd rather grow it deliberately than expose
/// arbitrary subcommands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WpPluginAction {
    /// `wp plugin install <slug> --activate`. Pulls from wordpress.org
    /// or a public URL if `source` starts with http(s)://.
    /// `wp plugin install <source>`, optionally `--activate`.
    ///
    /// `activate` is a field rather than always-on because the two are
    /// separate operations under one exit code: a plugin that installs
    /// cleanly and then fatals on load was reported as an INSTALL failure,
    /// sending the operator to look at downloads and permissions instead of
    /// at the plugin. Defaults to true, matching what the button says.
    Install {
        source: String,
        #[serde(default = "default_true")]
        activate: bool,
    },
    /// `wp plugin activate <slug>`.
    Activate,
    /// `wp plugin deactivate <slug>`.
    Deactivate,
    /// `wp plugin update <slug>` (or "all" for every plugin).
    Update,
    /// `wp plugin update --all`.
    UpdateAll,
    /// `wp plugin delete <slug>`. Refused if the plugin is currently
    /// active — the operator must deactivate first (matches wp-cli's
    /// own safety check).
    Delete,
    /// `wp plugin auto-updates enable <slug>` or `disable`.
    SetAutoUpdate { enabled: bool },
    /// Clear the keyless defender's auto-update PAUSE for this plugin, so the
    /// next sweep retries it. NOT a wp-cli action — handled entirely in the
    /// service layer (drops the slug from the per-hosting skip-list). Used by
    /// the "Resume" button after a licensed plugin's key has been added.
    ResumeAutoUpdate,
    /// Re-download the version that is ALREADY installed from wordpress.org
    /// and replace the plugin's directory with it — the fix for a plugin
    /// that failed checksum verification. Same version on purpose: a repair
    /// that silently upgrades is a different operation with different
    /// consequences. Activation state lives in the database and survives.
    Reinstall,
}

/// Outcome of a `WpPluginAction`. `output_tail` carries the last
/// ~4 KiB of stdout/stderr from wp-cli so the UI can show "what
/// happened" without us trying to fully parse wp-cli's textual
/// output (which changes across versions).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpPluginActionResult {
    /// Best-effort status string. "ok" on success; "failed" when
    /// wp-cli exited non-zero; "noop" when the action was already
    /// in the target state.
    pub state: String,
    pub message: String,
    pub output_tail: String,
}

/// One installed theme — parallel to `WpPlugin` but for `wp theme list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpTheme {
    /// Theme directory slug (the `wp theme <action> <slug>` arg).
    pub slug: String,
    /// Human-readable name from the theme's style.css header.
    pub name: String,
    pub version: String,
    /// "active" | "inactive" | "parent" (when it's the parent of an
    /// active child theme).
    pub status: String,
    pub update_available: bool,
    pub latest_version: String,
}

/// Response for `Request::WpThemeList`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpThemeListResponse {
    pub themes: Vec<WpTheme>,
    /// WordPress core version on disk — same field shape as
    /// WpPluginListResponse so the UI can reuse a header.
    pub wp_version: String,
    pub updates_pending: i64,
    /// Set when the live `wp theme list` lookup FAILED — same semantics as
    /// `WpPluginListResponse::error`. `None` on success.
    #[serde(default)]
    pub error: Option<String>,
}

/// Whitelisted theme actions exposed via the web UI. Mirrors
/// `WpPluginAction` but with theme-specific subset (no
/// auto-update-flag since wp-cli doesn't have a per-theme
/// equivalent — theme auto-updates are managed cluster-wide).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WpThemeAction {
    /// `wp theme install <slug> [--activate]`.
    Install { source: String },
    /// `wp theme activate <slug>` — exactly one theme is active at
    /// any time; activating a new one deactivates the current.
    Activate,
    /// `wp theme update <slug>`.
    Update,
    /// `wp theme update --all`.
    UpdateAll,
    /// `wp theme delete <slug>`. Refuses if the theme is currently
    /// active (matches wp-cli's safety check).
    Delete,
    /// `wp theme install <slug> --version=<version> --force`: the same release
    /// over the top, for a theme that failed its comparison. Same version on
    /// purpose, like [`WpPluginAction::Reinstall`].
    Reinstall { version: String },
}

/// Outcome of a `WpThemeAction` — same shape as the plugin variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpThemeActionResult {
    pub state: String,
    pub message: String,
    pub output_tail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A partial scan isn't clean, and a record from before the native scan
    /// keeps the meaning it had.
    /// A record someone's action edited says less than a scan's would: nothing in
    /// it reads as clean, and standing findings still come first.
    #[test]
    fn a_record_awaiting_a_rescan_has_no_clean_verdict() {
        let mut r = WpIntegrityScanResult {
            wp_cli_ok: true,
            clamav_available: true,
            native_scan_ran: true,
            scanned_at: 1,
            coverage: ScanCoverage {
                upstream_ran: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(r.is_clean());
        assert_eq!(r.verdict(), ScanVerdict::Clean);
        r.awaiting_rescan = true;
        assert!(!r.is_clean());
        assert_eq!(r.verdict(), ScanVerdict::Running);
        r.review = vec![SiteFileFinding::default()];
        assert_eq!(r.verdict(), ScanVerdict::Review);
        // An older record has no such field and keeps its meaning.
        let old: WpIntegrityScanResult = serde_json::from_str("{}").expect("json");
        assert!(!old.awaiting_rescan);
    }

    /// Padding a file past what's read mustn't get it through in bulk.
    #[test]
    fn trust_all_takes_nothing_it_never_read() {
        let file = |kind| SiteFileFinding {
            rel: "a.php".into(),
            kind,
            sha256: "aa".into(),
            ..Default::default()
        };
        let r = WpIntegrityScanResult {
            review: vec![
                file(FindingKind::TooLargeToInspect),
                file(FindingKind::BaselineChange),
            ],
            ..Default::default()
        };
        let kinds: Vec<FindingKind> = r.trust_all_items().map(|f| f.kind).collect();
        assert_eq!(kinds, [FindingKind::BaselineChange]);
        assert!(file(FindingKind::TooLargeToInspect).can_trust());
    }

    #[test]
    fn is_clean_needs_a_scan_that_covered_the_site() {
        let mut r = WpIntegrityScanResult {
            wp_cli_ok: true,
            clamav_available: true,
            native_scan_ran: true,
            coverage: ScanCoverage {
                upstream_ran: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(r.is_clean());
        r.coverage.partial_reasons = vec!["stopped early".into()];
        assert!(r.scan_partial());
        assert!(!r.is_clean());
        r.native_scan_ran = false;
        assert!(!r.scan_partial());
        assert!(r.is_clean(), "old records keep their old meaning");
    }

    fn finding(kind: FindingKind) -> SiteFileFinding {
        SiteFileFinding {
            rel: "wp-content/x.php".into(),
            kind,
            ..Default::default()
        }
    }

    fn native() -> WpIntegrityScanResult {
        WpIntegrityScanResult {
            native_scan_ran: true,
            scanned_at: 100,
            coverage: ScanCoverage {
                upstream_ran: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// One state per answer the card can give, and the order they win in.
    #[test]
    fn verdict_names_what_the_scan_found() {
        use ScanVerdict::*;
        assert_eq!(WpIntegrityScanResult::default().verdict(), Never);
        assert_eq!(native().verdict(), Clean);

        let mut r = native();
        r.review = vec![finding(FindingKind::BaselineChange)];
        assert_eq!(r.verdict(), Review);

        // Findings outrank a review bucket.
        r.findings = vec![finding(FindingKind::RuleHit)];
        assert_eq!(r.verdict(), Findings);

        let mut r = native();
        r.malware = vec![WpMalwareHit::default()];
        assert_eq!(r.verdict(), Findings);

        let mut r = native();
        r.themes_failed = vec![WpIntegrityPluginResult {
            source: None,
            slug: "t".into(),
            issues: vec![WpIntegrityFileIssue::default()],
            ..Default::default()
        }];
        assert_eq!(r.verdict(), Findings);

        let mut r = native();
        r.coverage.partial_reasons = vec!["stopped early".into()];
        assert_eq!(r.verdict(), Partial);

        // WordPress, and wordpress.org could not be reached: a part didn't run.
        let mut r = native();
        r.coverage.upstream_ran = false;
        assert_eq!(r.verdict(), Partial);
        // Not WordPress: nothing to compare with is not a failure.
        r.coverage.no_upstream = true;
        assert_eq!(r.verdict(), Clean);
    }

    /// Standing findings stay in front while a scan is queued; anything weaker
    /// gives way to the spinner. ClamAV is not needed for a clean native scan.
    #[test]
    fn running_never_hides_standing_findings() {
        use ScanVerdict::*;
        let mut r = native();
        r.scan_queued = true;
        assert_eq!(r.verdict(), Running);
        r.review = vec![finding(FindingKind::BaselineChange)];
        assert_eq!(r.verdict(), Review);
        r.findings = vec![finding(FindingKind::RuleHit)];
        assert_eq!(r.verdict(), Findings);
        let first = WpIntegrityScanResult {
            scan_queued: true,
            ..Default::default()
        };
        assert_eq!(first.verdict(), Running);
        let mut r = native();
        r.clamav_available = false;
        assert_eq!(r.verdict(), Clean);
    }

    /// A record from before the native scan keeps the meanings it had, and
    /// `report_only` changes nothing about what the card says.
    #[test]
    fn verdict_of_an_old_record_keeps_its_meaning() {
        use ScanVerdict::*;
        let old = WpIntegrityScanResult {
            wp_cli_ok: true,
            clamav_available: true,
            scanned_at: 1,
            ..Default::default()
        };
        assert_eq!(old.verdict(), Clean);
        let no_clamav = WpIntegrityScanResult {
            clamav_available: false,
            ..old.clone()
        };
        assert_eq!(no_clamav.verdict(), Partial);
        let no_wpcli = WpIntegrityScanResult {
            wp_cli_ok: false,
            ..old.clone()
        };
        assert_eq!(no_wpcli.verdict(), Partial);
        let hit = WpIntegrityScanResult {
            core_modified: vec!["wp-includes/load.php".into()],
            ..old.clone()
        };
        assert_eq!(hit.verdict(), Findings);
        let mut pilot = native();
        pilot.report_only = true;
        pilot.findings = vec![finding(FindingKind::RuleHit)];
        assert_eq!(pilot.verdict(), Findings);
    }

    /// A live scan is its own malware check: ClamAV is optional, and a missing
    /// one neither blocks nor adds to the verdict.
    #[test]
    fn live_clean_needs_no_clamav() {
        let mut r = native();
        assert!(!r.clamav_available && !r.wp_cli_ok);
        assert!(r.is_live() && r.is_clean());
        // Not WordPress: nothing to compare with, clean on the scan alone.
        r.coverage.upstream_ran = false;
        assert!(!r.is_clean(), "WordPress whose release wasn't compared");
        r.coverage.no_upstream = true;
        assert!(r.is_clean());
        // What stands in the way, one at a time.
        let blocked = |f: fn(&mut WpIntegrityScanResult)| {
            let mut r = native();
            f(&mut r);
            assert!(!r.is_clean());
        };
        blocked(|r| r.coverage.partial_reasons = vec!["stopped".into()]);
        blocked(|r| r.awaiting_rescan = true);
        blocked(|r| r.malware = vec![WpMalwareHit::default()]);
        blocked(|r| r.core_modified = vec!["wp-includes/load.php".into()]);
        blocked(|r| {
            r.plugins_failed = vec![WpIntegrityPluginResult {
                slug: "p".into(),
                issues: vec![WpIntegrityFileIssue::default()],
                ..Default::default()
            }]
        });
        blocked(|r| {
            r.themes_failed = vec![WpIntegrityPluginResult {
                slug: "t".into(),
                issues: vec![WpIntegrityFileIssue::default()],
                ..Default::default()
            }]
        });
        blocked(|r| r.findings = vec![finding(FindingKind::RuleHit)]);
        blocked(|r| r.review = vec![finding(FindingKind::BaselineChange)]);
    }

    /// The pilot's results are for the panel: whatever they hold, the record
    /// still reads the way it did before the scan existed.
    #[test]
    fn report_only_record_uses_old_logic() {
        let mut r = native();
        r.report_only = true;
        assert!(!r.is_live());
        assert!(!r.is_clean(), "wp-cli and ClamAV never ran");
        r.wp_cli_ok = true;
        r.clamav_available = true;
        assert!(r.is_clean());
        // New buckets are not read by the old rule.
        r.findings = vec![finding(FindingKind::RuleHit)];
        r.review = vec![finding(FindingKind::BaselineChange)];
        assert!(r.is_clean());
        r.clamav_available = false;
        assert!(!r.is_clean(), "ClamAV is still required in the pilot");
    }

    /// A record stored before any of this has none of the new fields and keeps
    /// the meaning it had.
    #[test]
    fn old_stored_record_keeps_old_meaning() {
        let old: WpIntegrityScanResult = serde_json::from_str(
            r#"{"core_ok":true,"wp_cli_ok":true,"clamav_available":true,"scanned_at":5}"#,
        )
        .expect("json");
        assert!(!old.native_scan_ran && !old.is_live());
        assert!(old.is_clean());
        let no_clamav: WpIntegrityScanResult =
            serde_json::from_str(r#"{"wp_cli_ok":true,"scanned_at":5}"#).expect("json");
        assert!(!no_clamav.is_clean());
    }

    /// A failed comparison is listed under its core, plugin or theme section;
    /// the findings list adds only what those sections can't say.
    #[test]
    fn listed_findings_skip_what_the_component_sections_show() {
        let mut r = native();
        let of_plugin = |kind| SiteFileFinding {
            component: Some("p".into()),
            ..finding(kind)
        };
        r.findings = vec![
            finding(FindingKind::CoreModified),
            of_plugin(FindingKind::UpstreamModified),
            of_plugin(FindingKind::UpstreamAdded),
            finding(FindingKind::RuleHit),
            SiteFileFinding {
                rule_id: Some("php.eval".into()),
                ..of_plugin(FindingKind::UpstreamModified)
            },
        ];
        assert_eq!(r.listed_findings().count(), 2);
        let folder = SiteFileFinding {
            rel: "wp-content/plugins/akismet".into(),
            component: Some("akismet".into()),
            ..finding(FindingKind::UpstreamModified)
        };
        assert_eq!(folder.component_wide(), Some("plugin"));
        let file = SiteFileFinding {
            rel: "wp-content/plugins/akismet/a.php".into(),
            ..folder.clone()
        };
        assert_eq!(file.component_wide(), None);
        assert_eq!(finding(FindingKind::RuleHit).component_wide(), None);
        // Counted on top of the core, plugin, theme and ClamAV lists.
        r.core_modified = vec!["a".into()];
        // The rule hit, plus the core file; the comparison that carries a rule id
        // is that same file, not a third.
        assert_eq!(r.shown_finding_count(), 2);
        assert_eq!(r.verdict(), ScanVerdict::Findings);

        // Only a comparison that carries a rule stands: still one, never 0.
        let mut lone = native();
        lone.findings = vec![SiteFileFinding {
            rule_id: Some("php.eval".into()),
            ..of_plugin(FindingKind::UpstreamModified)
        }];
        assert_eq!(lone.shown_finding_count(), 0);
        assert_eq!(lone.verdict(), ScanVerdict::Findings);
        assert_eq!(lone.headline_count(), 1);
    }

    /// Hyperion's own mu-plugin, tampered with: a comparison no core, plugin or
    /// theme section carries, so the findings list is where it shows.
    #[test]
    fn a_comparison_no_section_carries_is_listed() {
        let mut r = native();
        r.findings = vec![SiteFileFinding {
            rel: "wp-content/mu-plugins/hyperion.php".into(),
            severity: "high".into(),
            source_label: Some("hyperion".into()),
            ..finding(FindingKind::UpstreamModified)
        }];
        assert_eq!(r.listed_findings().count(), 1);
        assert_eq!(r.shown_finding_count(), 1);
        assert_eq!(r.headline_count(), 1);
        assert_eq!(r.verdict(), ScanVerdict::Findings);
        assert!(!r.is_clean());
        // A core comparison has its section even without a component.
        r.findings = vec![finding(FindingKind::CoreUnexpected)];
        assert_eq!(r.listed_findings().count(), 0);
    }

    /// Whatever is in `findings`, the card can't read Clean while `is_clean`
    /// says no: a live record reads Clean exactly when it is clean.
    #[test]
    fn verdict_clean_is_is_clean_for_a_live_record() {
        let items = [
            None,
            Some(finding(FindingKind::RuleHit)),
            Some(finding(FindingKind::UpstreamModified)),
            Some(finding(FindingKind::CoreMissing)),
            Some(SiteFileFinding {
                component: Some("p".into()),
                ..finding(FindingKind::UpstreamAdded)
            }),
            Some(finding(FindingKind::TooLargeToInspect)),
        ];
        for item in items {
            for partial in [false, true] {
                for upstream in [false, true] {
                    for review in [false, true] {
                        let mut r = native();
                        r.findings = item.clone().into_iter().collect();
                        if partial {
                            r.coverage.partial_reasons = vec!["stopped".into()];
                        }
                        r.coverage.upstream_ran = upstream;
                        if review {
                            r.review = vec![finding(FindingKind::BaselineChange)];
                        }
                        assert_eq!(
                            r.verdict() == ScanVerdict::Clean,
                            r.is_clean(),
                            "{item:?} partial={partial} upstream={upstream} review={review}"
                        );
                        if !r.findings.is_empty() {
                            assert_eq!(r.verdict(), ScanVerdict::Findings, "{item:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn request_defaults_apply_when_optional_fields_absent() {
        let minimal = serde_json::json!({
            "site_url": "https://example.com",
            "title": "x",
            "admin_user": "admin",
            "admin_email": "a@b.cz",
            "admin_password": "secret"
        });
        let r: WpInstallRequest = serde_json::from_value(minimal).expect("parse");
        assert_eq!(r.locale, "en_US");
        assert_eq!(r.version, "latest");
    }

    #[test]
    fn request_round_trips_through_json() {
        let r = WpInstallRequest {
            site_url: "https://example.com".into(),
            title: "Site".into(),
            admin_user: "admin".into(),
            admin_email: "a@b.cz".into(),
            admin_password: "secret".into(),
            locale: "cs_CZ".into(),
            version: "6.5.3".into(),
            no_index: false,
        };
        let s = serde_json::to_string(&r).expect("ser");
        let back: WpInstallRequest = serde_json::from_str(&s).expect("de");
        assert_eq!(r, back);
    }

    #[test]
    fn status_round_trips() {
        let s = WpInstallStatus {
            hosting_id: HostingId("01J".into()),
            site_url: "https://example.com".into(),
            wp_version: "6.5.3".into(),
            installed_at: 1_700_000_000,
            last_pack_hash: "abc".into(),
        };
        let json = serde_json::to_string(&s).expect("ser");
        let back: WpInstallStatus = serde_json::from_str(&json).expect("de");
        assert_eq!(s, back);
    }
}

/// Result of the "is the site throwing a fatal?" probe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct WpFatalReport {
    /// HTTP status the site answered with over loopback. 0 = no answer.
    pub http_status: i64,
    /// True when the front page answers 5xx — the shape a WordPress
    /// "critical error" page takes in production.
    pub fatal: bool,
    /// Slug of the plugin/theme whose file threw, when a wp-cli run
    /// reproduced the fatal and named it. The single most actionable
    /// fact on the page: it says what to deactivate.
    pub culprit: Option<String>,
    /// "plugin" | "theme" — only meaningful when `culprit` is set.
    #[serde(default)]
    pub culprit_kind: String,
    /// First fatal line from the reproduction, for the operator to read.
    /// Capped server-side; never contains the full trace.
    #[serde(default)]
    pub error_excerpt: String,
    /// True when `wp-content/object-cache.php` is present.
    ///
    /// Reported separately from any plugin because it is a DROP-IN:
    /// WordPress loads it before plugins and regardless of whether its
    /// plugin is active or even still installed. When Redis stops answering
    /// it fatals every request including wp-cli's bootstrap, which is what
    /// makes the plugin impossible to deactivate or delete — the operator
    /// needs to move THIS file, and no amount of work on the plugin folder
    /// will do it.
    #[serde(default)]
    pub object_cache_dropin: bool,
    /// True when a parked `object-cache.php.hyperion-disabled` is waiting to
    /// be put back.
    #[serde(default)]
    pub object_cache_parked: bool,
    /// Plugins currently parked as `<slug>-old` by the emergency disable —
    /// each restorable with one click once the site is back.
    #[serde(default)]
    pub parked_plugins: Vec<String>,
    /// Why the probe got no answer at all (`http_status == 0`): curl's own
    /// message, e.g. "Connection refused" or "Operation timed out". Empty
    /// when the site answered — and from older nodes, which never sent it.
    #[serde(default)]
    pub probe_error: String,
}

impl WpFatalReport {
    /// What the front page told a visitor, for the health line:
    /// `fatal` (5xx), `no_answer` (nothing came back), `error_page` (4xx —
    /// not a WordPress fatal, but still not the site) or `ok`.
    ///
    /// Only a 5xx is `fatal` — that is what the culprit hunt keys on. The
    /// other two used to fall through to "no fatal error" and render green,
    /// which over a site nobody can reach is the wrong answer.
    pub fn verdict(&self) -> &'static str {
        if self.fatal {
            "fatal"
        } else if self.http_status <= 0 {
            "no_answer"
        } else if self.http_status >= 400 {
            "error_page"
        } else {
            "ok"
        }
    }
}
