//! The OWASP Core Rule Set tier of the per-site WAF (ModSecurity v3).
//!
//! Phase A's nginx rules refuse a handful of shapes cheaply; this tier runs
//! the full Core Rule Set over every request of a site that opts in. The
//! settings here are rendered into the site's server block (see the nginx
//! adapter), so everything that reaches a vhost is validated to a closed
//! set: numbers, CRS rule ids and a path alphabet with nothing nginx or
//! ModSecurity would interpret.

use serde::{Deserialize, Serialize};

/// What the Core Rule Set does on one site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CrsMode {
    #[default]
    Off,
    /// Evaluate and log, never refuse — the way to start on a live site.
    Detect,
    /// Refuse requests whose anomaly score reaches the threshold.
    Block,
}

impl CrsMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "detect" => Some(Self::Detect),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Detect => "detect",
            Self::Block => "block",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Detect => "Detection only",
            Self::Block => "Blocking",
        }
    }
}

/// Paranoia levels offered. 3 and 4 are left out on purpose: their false
/// positives need rule-by-rule tuning that no form here can offer.
pub const PARANOIA_CHOICES: [i64; 2] = [1, 2];
pub const DEFAULT_PARANOIA: i64 = 1;
/// Inbound anomaly thresholds offered. 5 is CRS's own default: one
/// critical-severity match blocks.
pub const THRESHOLD_CHOICES: [i64; 3] = [5, 10, 20];
pub const DEFAULT_THRESHOLD: i64 = 5;

pub const MAX_EXCLUSIONS: usize = 50;
pub const MAX_RULES_PER_EXCLUSION: usize = 20;
pub const MAX_PATH_LEN: usize = 200;

/// Rules switched off for a site — everywhere (`path` empty) or for request
/// paths starting with `path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CrsExclusion {
    pub rules: Vec<u32>,
    #[serde(default)]
    pub path: String,
}

/// Whether `id` may be excluded: a CRS rule (900000–999999) or one of the
/// engine's own request-body checks (200000–200099) — but never the rules
/// that make CRS work. Excluding the initialisation (901xxx) breaks every
/// rule after it, and excluding the blocking evaluation (949xxx/959xxx) or
/// the correlation (980xxx) silently turns blocking off — that is what
/// Detection only is for, and it says so.
pub fn excludable_rule(id: u32) -> bool {
    let crs = (900_000..=999_999).contains(&id);
    let engine = (200_000..=200_099).contains(&id);
    let structural = (901_000..=901_999).contains(&id)
        || (949_000..=949_999).contains(&id)
        || (959_000..=959_999).contains(&id)
        || (980_000..=980_999).contains(&id);
    (crs || engine) && !structural
}

/// Whether `path` may be inlined into a `@beginsWith` rule: empty, or `/`
/// followed by URL-safe characters only. No quote, space, backslash or
/// percent sign can reach the vhost.
pub fn valid_path(path: &str) -> bool {
    path.is_empty()
        || (path.starts_with('/')
            && path.len() <= MAX_PATH_LEN
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_.~-".contains(&b)))
}

/// The exclusion path for a request URI: the query dropped, then cut at the
/// first character outside the path alphabet. A prefix is still a correct
/// `@beginsWith` match — only a broader one.
pub fn exclusion_path_for(uri: &str) -> String {
    let path = uri.split(['?', '#']).next().unwrap_or("");
    if !path.starts_with('/') {
        return "/".to_string();
    }
    let cut = path
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b"/_.~-".contains(&b)))
        .unwrap_or(path.len());
    let mut p = path[..cut.min(MAX_PATH_LEN)].to_string();
    if p.is_empty() {
        p.push('/');
    }
    p
}

/// Check a list before it is stored. Names the first problem.
pub fn validate_exclusions(list: &[CrsExclusion]) -> Result<(), String> {
    if list.len() > MAX_EXCLUSIONS {
        return Err(format!("at most {MAX_EXCLUSIONS} CRS exclusions per site"));
    }
    for e in list {
        if e.rules.is_empty() {
            return Err("a CRS exclusion needs at least one rule id".into());
        }
        if e.rules.len() > MAX_RULES_PER_EXCLUSION {
            return Err(format!(
                "at most {MAX_RULES_PER_EXCLUSION} rule ids per CRS exclusion"
            ));
        }
        if let Some(bad) = e.rules.iter().find(|r| !excludable_rule(**r)) {
            return Err(format!(
                "rule {bad} cannot be excluded — only CRS rules (900000–999999) and the \
                 engine's request-body checks (200000–200099), and never the rules that \
                 run CRS itself (901xxx, 949xxx, 959xxx, 980xxx)"
            ));
        }
        if !valid_path(&e.path) {
            return Err(format!(
                "exclusion path {:?} must start with / and use only letters, digits and / _ . ~ -",
                e.path
            ));
        }
    }
    Ok(())
}

/// Lenient parse of the stored JSON: unreadable JSON is "none", invalid
/// rule ids and paths are dropped, rule lists are sorted and de-duplicated.
/// A corrupt column must never take a site's vhost down.
pub fn parse_exclusions(raw: &str) -> Vec<CrsExclusion> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let Ok(list) = serde_json::from_str::<Vec<CrsExclusion>>(raw) else {
        return Vec::new();
    };
    list.into_iter()
        .filter(|e| valid_path(&e.path))
        .map(|mut e| {
            e.rules.retain(|r| excludable_rule(*r));
            e.rules.sort_unstable();
            e.rules.dedup();
            e.rules.truncate(MAX_RULES_PER_EXCLUSION);
            e
        })
        .filter(|e| !e.rules.is_empty())
        .take(MAX_EXCLUSIONS)
        .collect()
}

/// Canonical stored form; empty when there are none. Entries with the same
/// path are merged, so "Allow this" twice on one page stays one row.
pub fn exclusions_to_string(list: &[CrsExclusion]) -> String {
    let mut merged: Vec<CrsExclusion> = Vec::new();
    for e in list {
        match merged.iter_mut().find(|m| m.path == e.path) {
            Some(m) => m.rules.extend(e.rules.iter().copied()),
            None => merged.push(e.clone()),
        }
    }
    for m in &mut merged {
        m.rules.sort_unstable();
        m.rules.dedup();
    }
    merged.retain(|m| !m.rules.is_empty());
    if merged.is_empty() {
        return String::new();
    }
    serde_json::to_string(&merged).unwrap_or_default()
}

/// The CRS settings a site's vhost renders, defaults resolved.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrsSettings {
    pub mode: CrsMode,
    pub paranoia: i64,
    pub threshold: i64,
    pub wordpress: bool,
    pub exclusions: Vec<CrsExclusion>,
}

/// One attack family, keyed by the CRS rule file it comes from.
struct Category {
    key: &'static str,
    label: &'static str,
    label_detected: &'static str,
}

const CATEGORIES: &[Category] = &[
    Category {
        key: "method",
        label: "OWASP CRS · HTTP method",
        label_detected: "OWASP CRS · HTTP method (detection only)",
    },
    Category {
        key: "dos",
        label: "OWASP CRS · DoS protection",
        label_detected: "OWASP CRS · DoS protection (detection only)",
    },
    Category {
        key: "scanner",
        label: "OWASP CRS · Scanner",
        label_detected: "OWASP CRS · Scanner (detection only)",
    },
    Category {
        key: "protocol",
        label: "OWASP CRS · Protocol violation",
        label_detected: "OWASP CRS · Protocol violation (detection only)",
    },
    Category {
        key: "protocol_attack",
        label: "OWASP CRS · Protocol attack",
        label_detected: "OWASP CRS · Protocol attack (detection only)",
    },
    Category {
        key: "multipart",
        label: "OWASP CRS · Multipart attack",
        label_detected: "OWASP CRS · Multipart attack (detection only)",
    },
    Category {
        key: "lfi",
        label: "OWASP CRS · Local file inclusion",
        label_detected: "OWASP CRS · Local file inclusion (detection only)",
    },
    Category {
        key: "rfi",
        label: "OWASP CRS · Remote file inclusion",
        label_detected: "OWASP CRS · Remote file inclusion (detection only)",
    },
    Category {
        key: "rce",
        label: "OWASP CRS · Command injection",
        label_detected: "OWASP CRS · Command injection (detection only)",
    },
    Category {
        key: "php",
        label: "OWASP CRS · PHP injection",
        label_detected: "OWASP CRS · PHP injection (detection only)",
    },
    Category {
        key: "nodejs",
        label: "OWASP CRS · JavaScript injection",
        label_detected: "OWASP CRS · JavaScript injection (detection only)",
    },
    Category {
        key: "xss",
        label: "OWASP CRS · Cross-site scripting",
        label_detected: "OWASP CRS · Cross-site scripting (detection only)",
    },
    Category {
        key: "sqli",
        label: "OWASP CRS · SQL injection",
        label_detected: "OWASP CRS · SQL injection (detection only)",
    },
    Category {
        key: "session",
        label: "OWASP CRS · Session fixation",
        label_detected: "OWASP CRS · Session fixation (detection only)",
    },
    Category {
        key: "java",
        label: "OWASP CRS · Java attack",
        label_detected: "OWASP CRS · Java attack (detection only)",
    },
    Category {
        key: "leakage",
        label: "OWASP CRS · Data leakage",
        label_detected: "OWASP CRS · Data leakage (detection only)",
    },
    Category {
        key: "body",
        label: "Unparseable request body",
        label_detected: "Unparseable request body (detection only)",
    },
    Category {
        key: "other",
        label: "OWASP CRS · Other",
        label_detected: "OWASP CRS · Other (detection only)",
    },
];

/// The attack family of a rule id, or `None` for the rules that only run
/// CRS (initialisation, exclusion sets, scoring, correlation).
pub fn category_of(rule_id: u32) -> Option<&'static str> {
    let key = match rule_id / 1000 {
        200 => "body",
        911 => "method",
        912 => "dos",
        913 => "scanner",
        920 => "protocol",
        921 => "protocol_attack",
        922 => "multipart",
        930 => "lfi",
        931 => "rfi",
        932 => "rce",
        933 => "php",
        934 => "nodejs",
        941 => "xss",
        942 => "sqli",
        943 => "session",
        944 => "java",
        950..=954 => "leakage",
        901 | 903 | 905 | 949 | 959 | 980 => return None,
        900..=999 => "other",
        _ => return None,
    };
    Some(key)
}

/// Whether a rule names an attack (930xxx–944xxx) rather than a protocol
/// or housekeeping finding — the better label when a request matched both.
pub fn is_attack_rule(rule_id: u32) -> bool {
    (930_000..=944_999).contains(&rule_id)
}

/// The hit-log tag for a CRS decision.
pub fn tag(category: &str, detected: bool) -> String {
    if detected {
        format!("crs_{category}_detected")
    } else {
        format!("crs_{category}")
    }
}

/// Human label for a `crs_*` tag, `None` for anything else.
pub fn tag_label(tag: &str) -> Option<&'static str> {
    let rest = tag.strip_prefix("crs_")?;
    let (key, detected) = match rest.strip_suffix("_detected") {
        Some(k) => (k, true),
        None => (rest, false),
    };
    let c = CATEGORIES.iter().find(|c| c.key == key)?;
    Some(if detected { c.label_detected } else { c.label })
}

/// Whether a tag records a request that was only detected, not refused.
pub fn tag_is_detection(tag: &str) -> bool {
    tag.starts_with("crs_") && tag.ends_with("_detected")
}

/// What a node reports about its ModSecurity engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ModsecStatus {
    /// The nginx connector is installed and enabled.
    pub module: bool,
    /// The Core Rule Set is installed.
    pub crs: bool,
    /// CRS version, e.g. "3.3.4" (empty when unknown).
    pub crs_version: String,
    /// Active sites on the node with CRS on.
    pub active_sites: u32,
    /// The rule set is currently loaded into nginx (http-level include).
    pub loaded: bool,
}

impl ModsecStatus {
    pub fn available(&self) -> bool {
        self.module && self.crs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse() {
        assert_eq!(CrsMode::parse(" Block "), Some(CrsMode::Block));
        assert_eq!(CrsMode::parse("detect"), Some(CrsMode::Detect));
        assert_eq!(CrsMode::parse("on"), None);
    }

    #[test]
    fn only_safe_rules_are_excludable() {
        assert!(excludable_rule(942100));
        assert!(excludable_rule(200002));
        for id in [901100, 949110, 959100, 980130, 10001, 1, 1_000_000, 199_999] {
            assert!(!excludable_rule(id), "{id}");
        }
    }

    #[test]
    fn paths_are_a_closed_alphabet() {
        assert!(valid_path(""));
        assert!(valid_path("/wp-admin/admin-ajax.php"));
        for bad in [
            "wp-admin", "/a b", "/a\"b", "/a'b", "/a%20", "/a\\b", "/a;b", "/a\nb",
        ] {
            assert!(!valid_path(bad), "{bad:?}");
        }
        assert!(!valid_path(&format!("/{}", "a".repeat(MAX_PATH_LEN))));
    }

    #[test]
    fn exclusion_path_is_the_safe_prefix() {
        assert_eq!(
            exclusion_path_for("/wp-admin/post.php?action=edit"),
            "/wp-admin/post.php"
        );
        assert_eq!(exclusion_path_for("/shop/caf%C3%A9/x"), "/shop/caf");
        assert_eq!(exclusion_path_for("/?q=1"), "/");
        assert_eq!(exclusion_path_for("*"), "/");
    }

    #[test]
    fn parse_is_lenient_and_store_is_canonical() {
        let raw = r#"[{"rules":[942100,942100,949110,941160],"path":"/x"},
                      {"rules":[901100]},
                      {"rules":[932100],"path":"/a b"},
                      {"rules":[920350]}]"#;
        let list = parse_exclusions(raw);
        assert_eq!(
            list,
            vec![
                CrsExclusion {
                    rules: vec![941160, 942100],
                    path: "/x".into()
                },
                CrsExclusion {
                    rules: vec![920350],
                    path: String::new()
                },
            ]
        );
        assert!(parse_exclusions("nope").is_empty());
        let merged = exclusions_to_string(&[
            CrsExclusion {
                rules: vec![942100],
                path: "/x".into(),
            },
            CrsExclusion {
                rules: vec![941100, 942100],
                path: "/x".into(),
            },
        ]);
        assert_eq!(merged, r#"[{"rules":[941100,942100],"path":"/x"}]"#);
        assert_eq!(exclusions_to_string(&[]), "");
    }

    #[test]
    fn validation_names_the_problem() {
        let ok = vec![CrsExclusion {
            rules: vec![942100],
            path: "/x".into(),
        }];
        assert!(validate_exclusions(&ok).is_ok());
        let structural = vec![CrsExclusion {
            rules: vec![949110],
            path: String::new(),
        }];
        assert!(validate_exclusions(&structural)
            .expect_err("949")
            .contains("949110"));
        let path = vec![CrsExclusion {
            rules: vec![942100],
            path: "/a'".into(),
        }];
        assert!(validate_exclusions(&path).is_err());
        let empty = vec![CrsExclusion {
            rules: vec![],
            path: String::new(),
        }];
        assert!(validate_exclusions(&empty).is_err());
    }

    #[test]
    fn categories_and_tags() {
        assert_eq!(category_of(942100), Some("sqli"));
        assert_eq!(category_of(941160), Some("xss"));
        assert_eq!(category_of(200002), Some("body"));
        assert_eq!(category_of(949110), None);
        assert_eq!(category_of(901100), None);
        assert_eq!(category_of(10001), None);
        assert!(is_attack_rule(942100));
        assert!(!is_attack_rule(920350));
        assert_eq!(tag("sqli", false), "crs_sqli");
        assert_eq!(tag_label("crs_sqli"), Some("OWASP CRS · SQL injection"));
        assert_eq!(
            tag_label("crs_protocol_attack_detected"),
            Some("OWASP CRS · Protocol attack (detection only)")
        );
        assert_eq!(tag_label("crs_nope"), None);
        assert_eq!(tag_label("probe_args"), None);
        assert!(tag_is_detection("crs_xss_detected"));
        assert!(!tag_is_detection("crs_xss"));
    }
}
