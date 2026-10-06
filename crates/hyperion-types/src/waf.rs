//! The per-hosting WAF: rule catalogue, levels, overrides and the
//! activity DTOs the panel reads.
//!
//! One source of truth. The nginx renderer, the log ingest (which rules
//! may earn a firewall ban), the settings form and the activity panel all
//! read this table, so a rule cannot exist in one and not the others.
//!
//! Levels are presets; an override pins one rule on or off regardless of
//! the level. `Standard` is exactly the rule set the old single
//! `waf_enabled` switch applied, so a migrated site refuses exactly what
//! it refused before.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How much of the catalogue a site runs before overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WafLevel {
    #[default]
    Off,
    Standard,
    Strict,
}

impl WafLevel {
    /// Lenient parse: anything unknown is `None`, so the caller decides
    /// what an unreadable value means (the vhost reader falls back to the
    /// legacy bool, the form handler refuses it).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "standard" => Some(Self::Standard),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Standard => "standard",
            Self::Strict => "strict",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Standard => "Standard",
            Self::Strict => "Strict",
        }
    }

    fn includes(self, tier: Tier) -> bool {
        match self {
            Self::Off => false,
            Self::Standard => tier == Tier::Standard,
            Self::Strict => true,
        }
    }
}

impl std::fmt::Display for WafLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Which level first switches a rule on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Standard,
    Strict,
}

/// One rule in the catalogue.
#[derive(Debug, Clone, Copy)]
pub struct WafRuleDef {
    /// Stable id: written into the hit log, the overrides JSON and the
    /// form field name (`waf_rule_<id>`). Never rename one.
    pub id: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub tier: Tier,
    /// Whether a hit counts towards an automatic firewall ban.
    ///
    /// Only rules that no honest client — browser, crawler, download
    /// manager, plugin — trips over and over. A ban is node-wide (every
    /// site on the box, and SSH), so a false positive here costs far more
    /// than the 403 itself:
    /// - `dump_files` also refuses `.zip`/`.tar.gz`, and a site that links
    ///   downloads gets them crawled — counting it would ban Googlebot.
    /// - `php_in_uploads` fires on every page view of a site whose cache
    ///   plugin runs PHP from `wp-content/cache`.
    /// - `bad_methods` fires for Office and Windows WebDAV clients
    ///   (`PROPFIND`) opening a linked document.
    /// - `xmlrpc` is Jetpack and the mobile app; `empty_ua` is home-made
    ///   monitors; the enumeration rules are plain page views.
    pub counts_for_ban: bool,
    /// Rendered only for hostings that run PHP.
    pub php_only: bool,
}

pub const RULES: &[WafRuleDef] = &[
    WafRuleDef {
        id: "probe_args",
        label: "Attack patterns in the query string",
        help: "Path traversal, SQL injection, remote includes and <script> in the URL's query string.",
        tier: Tier::Standard,
        counts_for_ban: true,
        php_only: false,
    },
    WafRuleDef {
        id: "scanner_ua",
        label: "Vulnerability scanners",
        help: "Requests announcing a known scanner: nikto, sqlmap, wpscan, masscan, zgrab and similar.",
        tier: Tier::Standard,
        counts_for_ban: true,
        php_only: false,
    },
    WafRuleDef {
        id: "xmlrpc",
        label: "XML-RPC (xmlrpc.php)",
        help: "The old remote API brute-force tools love. Jetpack and the WordPress mobile app still use it — turn this rule off if the site relies on them.",
        tier: Tier::Standard,
        counts_for_ban: false,
        php_only: false,
    },
    WafRuleDef {
        id: "sensitive_files",
        label: "Sensitive WordPress files",
        help: "Direct requests for wp-config.php, readme.html and license.txt (the last two reveal the WordPress version).",
        tier: Tier::Standard,
        counts_for_ban: true,
        php_only: false,
    },
    WafRuleDef {
        id: "dump_files",
        label: "Backups, dumps and logs",
        help: "Files ending in .sql, .bak, .old, .orig, .save, .swp, .tar, .gz, .tgz, .zip, .log, .ini or .sh.",
        tier: Tier::Standard,
        counts_for_ban: false,
        php_only: false,
    },
    WafRuleDef {
        id: "php_in_uploads",
        label: "PHP in uploads and cache",
        help: "Running a .php file from wp-content/uploads or wp-content/cache — the usual malware drop.",
        tier: Tier::Standard,
        counts_for_ban: false,
        php_only: true,
    },
    WafRuleDef {
        id: "dotfiles",
        label: "Repository and secret files",
        help: "Probes for .env, .git, .svn, .hg and .DS_Store. Other hidden files are already a silent 404.",
        tier: Tier::Strict,
        counts_for_ban: true,
        php_only: false,
    },
    WafRuleDef {
        id: "author_enum",
        label: "Author enumeration",
        help: "?author=<number> on the public site, which redirects to the author's login name. wp-admin is not affected.",
        tier: Tier::Strict,
        counts_for_ban: false,
        php_only: false,
    },
    WafRuleDef {
        id: "rest_user_enum",
        label: "REST API user list",
        help: "/wp-json/wp/v2/users for visitors who are not logged in. The block editor keeps working. Stops scanners, not a determined attacker: nginx cannot tell a real login cookie from a forged one.",
        tier: Tier::Strict,
        counts_for_ban: false,
        php_only: false,
    },
    WafRuleDef {
        id: "bad_methods",
        label: "Unusual HTTP methods",
        help: "Anything other than GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS (TRACE, TRACK, CONNECT, WebDAV verbs).",
        tier: Tier::Strict,
        counts_for_ban: false,
        php_only: false,
    },
    WafRuleDef {
        id: "empty_ua",
        label: "Requests without a User-Agent",
        help: "Every browser sends one. Some uptime monitors and home-made scripts do not — check yours before turning this on.",
        tier: Tier::Strict,
        counts_for_ban: false,
        php_only: false,
    },
];

/// Hit-log tag for a country refusal. Never ban-counted.
pub const TAG_GEO: &str = "geo";
/// Hit-log tag for a bot-family refusal. Never ban-counted.
pub const TAG_BOT: &str = "bot";

pub fn rule(id: &str) -> Option<&'static WafRuleDef> {
    RULES.iter().find(|r| r.id == id)
}

/// Whether a hit tagged `id` may count towards a firewall ban. Unknown
/// tags (a newer node's rule, a hand-edited log line) never do.
pub fn counts_for_ban(id: &str) -> bool {
    rule(id).map(|r| r.counts_for_ban).unwrap_or(false)
}

/// Human name for a hit-log tag.
pub fn label_for(id: &str) -> &'static str {
    match id {
        TAG_GEO => "Blocked country",
        TAG_BOT => "Blocked bot family",
        _ => rule(id).map(|r| r.label).unwrap_or("Other"),
    }
}

/// Parse the stored overrides (`{"xmlrpc":false}`). Unknown ids and
/// non-bool values are dropped, and unreadable JSON is "no overrides":
/// a corrupt column must not take a site's vhost down with it.
pub fn parse_overrides(raw: &str) -> BTreeMap<String, bool> {
    let raw = raw.trim();
    if raw.is_empty() {
        return BTreeMap::new();
    }
    let Ok(map) = serde_json::from_str::<BTreeMap<String, serde_json::Value>>(raw) else {
        return BTreeMap::new();
    };
    map.into_iter()
        .filter(|(k, _)| rule(k).is_some())
        .filter_map(|(k, v)| v.as_bool().map(|b| (k, b)))
        .collect()
}

/// Canonical stored form; empty when there are no overrides.
pub fn overrides_to_string(map: &BTreeMap<String, bool>) -> String {
    let clean: BTreeMap<&String, &bool> = map.iter().filter(|(k, _)| rule(k).is_some()).collect();
    if clean.is_empty() {
        return String::new();
    }
    serde_json::to_string(&clean).unwrap_or_default()
}

/// The effective switch for every rule, flattened for the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WafRules {
    pub probe_args: bool,
    pub scanner_ua: bool,
    pub xmlrpc: bool,
    pub sensitive_files: bool,
    pub dump_files: bool,
    pub php_in_uploads: bool,
    pub dotfiles: bool,
    pub author_enum: bool,
    pub rest_user_enum: bool,
    pub bad_methods: bool,
    pub empty_ua: bool,
}

impl WafRules {
    pub fn get(&self, id: &str) -> bool {
        match id {
            "probe_args" => self.probe_args,
            "scanner_ua" => self.scanner_ua,
            "xmlrpc" => self.xmlrpc,
            "sensitive_files" => self.sensitive_files,
            "dump_files" => self.dump_files,
            "php_in_uploads" => self.php_in_uploads,
            "dotfiles" => self.dotfiles,
            "author_enum" => self.author_enum,
            "rest_user_enum" => self.rest_user_enum,
            "bad_methods" => self.bad_methods,
            "empty_ua" => self.empty_ua,
            _ => false,
        }
    }

    fn set(&mut self, id: &str, on: bool) {
        match id {
            "probe_args" => self.probe_args = on,
            "scanner_ua" => self.scanner_ua = on,
            "xmlrpc" => self.xmlrpc = on,
            "sensitive_files" => self.sensitive_files = on,
            "dump_files" => self.dump_files = on,
            "php_in_uploads" => self.php_in_uploads = on,
            "dotfiles" => self.dotfiles = on,
            "author_enum" => self.author_enum = on,
            "rest_user_enum" => self.rest_user_enum = on,
            "bad_methods" => self.bad_methods = on,
            "empty_ua" => self.empty_ua = on,
            _ => {}
        }
    }

    pub fn any(&self) -> bool {
        RULES.iter().any(|r| self.get(r.id))
    }

    /// Any rule decided in nginx's server-level rewrite pass (as opposed to
    /// a `location`). The renderer folds these into one verdict variable.
    pub fn any_server_level(&self) -> bool {
        self.probe_args
            || self.scanner_ua
            || self.author_enum
            || self.rest_user_enum
            || self.bad_methods
            || self.empty_ua
    }
}

/// Level plus overrides, for a hosting with or without PHP.
pub fn effective_rules(
    level: WafLevel,
    overrides: &BTreeMap<String, bool>,
    has_php: bool,
) -> WafRules {
    let mut out = WafRules::default();
    for r in RULES {
        let on = overrides
            .get(r.id)
            .copied()
            .unwrap_or_else(|| level.includes(r.tier));
        out.set(r.id, on && (has_php || !r.php_only));
    }
    out
}

/// Whether `level` alone (no override) turns rule `id` on.
pub fn level_default(level: WafLevel, id: &str) -> bool {
    rule(id).map(|r| level.includes(r.tier)).unwrap_or(false)
}

/// Refusals read from one hit log in one pass, already aggregated, so a
/// flood costs a handful of row writes instead of one per request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WafBatch {
    /// `(hour start, rule tag)` → refusals.
    pub hourly: BTreeMap<(i64, String), i64>,
    /// `(address, minute start)` → refusals by ban-counted rules only, so
    /// a tag that must never ban cannot reach the threshold at all.
    pub ip_minute: BTreeMap<(String, i64), i64>,
    /// The newest refusals, oldest first, at most [`WafBatch::RECENT_KEEP`].
    pub recent: std::collections::VecDeque<WafHit>,
    /// Lines that parsed.
    pub lines: u64,
    /// Bytes of backlog skipped, unread, to keep up with a flood.
    pub skipped_bytes: u64,
}

impl WafBatch {
    /// How many refusals a batch keeps verbatim.
    pub const RECENT_KEEP: usize = 200;

    pub fn push(&mut self, hit: WafHit) {
        self.lines += 1;
        let hour = hit.ts - hit.ts.rem_euclid(3600);
        *self.hourly.entry((hour, hit.rule.clone())).or_insert(0) += 1;
        if counts_for_ban(&hit.rule) {
            let minute = hit.ts - hit.ts.rem_euclid(60);
            *self.ip_minute.entry((hit.ip.clone(), minute)).or_insert(0) += 1;
        }
        if self.recent.len() == Self::RECENT_KEEP {
            self.recent.pop_front();
        }
        self.recent.push_back(hit);
    }

    pub fn is_empty(&self) -> bool {
        self.lines == 0
    }

    pub fn from_hits(hits: impl IntoIterator<Item = WafHit>) -> Self {
        let mut b = Self::default();
        for h in hits {
            b.push(h);
        }
        b
    }
}

/// Hits for one rule tag over a period.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WafRuleCount {
    pub rule: String,
    pub hits: i64,
}

/// One refused request, as recorded from the root-owned hit log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WafHit {
    pub ts: i64,
    pub ip: String,
    pub rule: String,
    pub method: String,
    pub uri: String,
    pub ua: String,
}

/// What the activity panel shows for one hosting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WafActivity {
    pub totals_24h: Vec<WafRuleCount>,
    pub totals_7d: Vec<WafRuleCount>,
    pub recent: Vec<WafHit>,
    /// Per-site auto-ban switch (`hosting_kv` `waf_autoban_enabled`).
    pub autoban_enabled: bool,
    /// `[fail2ban] enabled` on the owning node — auto-ban needs both.
    pub fail2ban_enabled: bool,
    /// `[fail2ban] waf_threshold` on the owning node.
    pub threshold: u32,
    /// `[fail2ban] window_secs` on the owning node.
    pub window_secs: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids_on(r: &WafRules) -> Vec<&'static str> {
        RULES.iter().filter(|d| r.get(d.id)).map(|d| d.id).collect()
    }

    #[test]
    fn standard_is_exactly_the_legacy_bundle() {
        let r = effective_rules(WafLevel::Standard, &BTreeMap::new(), true);
        assert_eq!(
            ids_on(&r),
            vec![
                "probe_args",
                "scanner_ua",
                "xmlrpc",
                "sensitive_files",
                "dump_files",
                "php_in_uploads"
            ]
        );
    }

    #[test]
    fn strict_is_everything_and_off_is_nothing() {
        let all = effective_rules(WafLevel::Strict, &BTreeMap::new(), true);
        assert_eq!(ids_on(&all).len(), RULES.len());
        let none = effective_rules(WafLevel::Off, &BTreeMap::new(), true);
        assert!(!none.any());
    }

    #[test]
    fn overrides_beat_the_level_both_ways() {
        let ov = parse_overrides(r#"{"xmlrpc":false,"dotfiles":true}"#);
        let r = effective_rules(WafLevel::Standard, &ov, true);
        assert!(!r.xmlrpc);
        assert!(r.dotfiles);
        let off = effective_rules(WafLevel::Off, &ov, true);
        assert!(off.dotfiles, "an override applies even with the level off");
    }

    #[test]
    fn php_only_rules_never_render_for_static_sites() {
        let ov = parse_overrides(r#"{"php_in_uploads":true}"#);
        assert!(!effective_rules(WafLevel::Strict, &ov, false).php_in_uploads);
    }

    #[test]
    fn junk_overrides_are_dropped() {
        let ov = parse_overrides(r#"{"nope":true,"xmlrpc":"yes","probe_args":false}"#);
        assert_eq!(ov.len(), 1);
        assert_eq!(ov.get("probe_args"), Some(&false));
        assert!(parse_overrides("not json").is_empty());
        assert!(parse_overrides("").is_empty());
        assert_eq!(overrides_to_string(&ov), r#"{"probe_args":false}"#);
        assert_eq!(overrides_to_string(&BTreeMap::new()), "");
    }

    #[test]
    fn only_listed_rules_count_for_bans() {
        let ban: Vec<&str> = RULES
            .iter()
            .filter(|r| r.counts_for_ban)
            .map(|r| r.id)
            .collect();
        assert_eq!(
            ban,
            vec!["probe_args", "scanner_ua", "sensitive_files", "dotfiles"]
        );
        assert!(counts_for_ban("probe_args"));
        assert!(!counts_for_ban("xmlrpc"));
        assert!(
            !counts_for_ban("dump_files"),
            "archives are legitimate downloads"
        );
        assert!(!counts_for_ban(TAG_GEO));
        assert!(!counts_for_ban(TAG_BOT));
        assert!(!counts_for_ban("made_up"));
    }

    #[test]
    fn batch_aggregates_and_keeps_only_the_newest() {
        let hit = |ts: i64, ip: &str, rule: &str| WafHit {
            ts,
            ip: ip.into(),
            rule: rule.into(),
            ..Default::default()
        };
        let mut hits = vec![
            hit(3600, "1.1.1.1", "probe_args"),
            hit(3601, "1.1.1.1", "probe_args"),
        ];
        hits.push(hit(3659, "2.2.2.2", "dump_files"));
        for i in 0..(WafBatch::RECENT_KEEP as i64) {
            hits.push(hit(7200 + i, "3.3.3.3", "xmlrpc"));
        }
        let b = WafBatch::from_hits(hits);
        assert_eq!(b.hourly.get(&(3600, "probe_args".into())), Some(&2));
        assert_eq!(b.hourly.get(&(3600, "dump_files".into())), Some(&1));
        assert_eq!(b.ip_minute.get(&("1.1.1.1".into(), 3600)), Some(&2));
        assert_eq!(
            b.ip_minute.len(),
            1,
            "only ban-counted rules reach the ban counts"
        );
        assert_eq!(b.recent.len(), WafBatch::RECENT_KEEP);
        assert_eq!(
            b.recent.back().map(|h| h.ts),
            Some(7200 + WafBatch::RECENT_KEEP as i64 - 1)
        );
        assert_eq!(b.lines, 3 + WafBatch::RECENT_KEEP as u64);
    }

    #[test]
    fn level_parses_leniently() {
        assert_eq!(WafLevel::parse(" Strict "), Some(WafLevel::Strict));
        assert_eq!(WafLevel::parse("on"), None);
    }
}
