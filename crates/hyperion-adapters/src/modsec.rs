//! ModSecurity v3 + the OWASP Core Rule Set on a node — the engine behind
//! the WAF's CRS tier.
//!
//! Debian ships both: `libnginx-mod-http-modsecurity` (the nginx connector,
//! built against Debian's nginx, which is the nginx Hyperion installs) and
//! `modsecurity-crs`. The rule set is loaded ONCE, at http level, and only
//! while some site on the node uses it — it costs ~20 MB per nginx process.
//! Each site then turns the engine on in its own server block and sets its
//! mode, paranoia, threshold and exclusions there (`render_site_rules`).
//!
//! Facts this module relies on, all checked against the real packages:
//! - per-server `modsecurity_rules` run BEFORE the inherited http-level CRS,
//!   so a site's `setvar:tx.*` lands before CRS initialises (which only
//!   fills unset variables);
//! - per-server `SecAuditLog` is ignored — every site logs to the http-level
//!   audit log, attributed by `modsecurity_transaction_id`;
//! - libmodsecurity keeps the audit log open across reloads (only a restart
//!   reopens it), so rotation must be `copytruncate`.

use crate::cmd;
use crate::fs::atomic_write;
use crate::AdapterError;
use hyperion_types::crs::{self, CrsMode, CrsSettings};
use hyperion_types::waf::WafHit;
use std::path::Path;

pub const MODULE_SO: &str = "/usr/lib/nginx/modules/ngx_http_modsecurity_module.so";
/// The package's own `load_module` link. Removed if the module turns out
/// not to load into this nginx, so nginx keeps working.
pub const MODULE_ENABLED: &str = "/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf";
pub const CRS_RULES_DIR: &str = "/usr/share/modsecurity-crs/rules";
pub const CRS_SETUP: &str = "/etc/modsecurity/crs/crs-setup.conf";
pub const CRS_BEFORE: &str = "/etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf";
pub const CRS_AFTER: &str = "/etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf";
pub const UNICODE_MAP: &str = "/etc/nginx/unicode.mapping";
pub const CONF_DIR: &str = "/etc/hyperion/modsecurity";
pub const MAIN_CONF: &str = "/etc/hyperion/modsecurity/main.conf";
/// The http-level include that loads the rule set. Present only while some
/// site on the node has CRS on.
pub const HTTP_INCLUDE: &str = "/etc/nginx/conf.d/hyperion-modsecurity.conf";
/// root:adm 0750. Only the nginx master opens the audit log (at config
/// load); workers write through its descriptor, so they need no access.
pub const AUDIT_DIR: &str = "/var/log/hyperion/modsec";
pub const AUDIT_LOG: &str = "/var/log/hyperion/modsec/audit.log";
pub const LOGROTATE: &str = "/etc/logrotate.d/hyperion-modsec";

/// The connector is installed and enabled for nginx.
pub fn module_available() -> bool {
    Path::new(MODULE_SO).exists() && Path::new(MODULE_ENABLED).exists()
}

/// The Core Rule Set is installed.
pub fn crs_available() -> bool {
    Path::new(CRS_SETUP).exists()
        && std::fs::read_dir(CRS_RULES_DIR)
            .map(|mut d| {
                d.any(|e| {
                    e.map(|e| e.file_name().to_string_lossy().ends_with(".conf"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
}

/// The rule set is loaded into nginx right now.
pub fn http_include_present() -> bool {
    Path::new(HTTP_INCLUDE).exists()
}

/// Installed CRS version (`3.3.4`), or empty.
pub async fn crs_version() -> String {
    match cmd::run(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${Version}", "modsecurity-crs"],
    )
    .await
    {
        Ok(v) => upstream_version(&v),
        Err(_) => String::new(),
    }
}

/// `3.3.4-1+deb12u3` → `3.3.4`.
fn upstream_version(debian: &str) -> String {
    let v = debian.trim();
    let v = v.split_once(':').map(|(_, r)| r).unwrap_or(v);
    v.split('-').next().unwrap_or("").to_string()
}

/// Everything the node can say about its engine without the database.
pub async fn status() -> crs::ModsecStatus {
    crs::ModsecStatus {
        module: module_available(),
        crs: crs_available(),
        crs_version: crs_version().await,
        active_sites: 0,
        loaded: http_include_present(),
    }
}

/// Install the connector and the rule set, unless both are there.
///
/// Like the OpenDKIM install: a `policy-rc.d` that refuses every service
/// action keeps the packages' maintainer scripts from reloading nginx
/// half-way (the module package would otherwise reload a config we have not
/// checked). Afterwards `nginx -t` must pass with the module loaded; if it
/// does not — an nginx that is not Debian's, so not binary compatible — the
/// module's `load_module` link is removed so nginx keeps working, and the
/// error says why.
pub async fn ensure_installed() -> Result<(), AdapterError> {
    if module_available() && crs_available() {
        return Ok(());
    }
    let policy = Path::new("/usr/sbin/policy-rc.d");
    let created_policy = if policy.exists() {
        false
    } else {
        atomic_write(policy, b"#!/bin/sh\nexit 101\n", 0o755)
            .await
            .is_ok()
    };
    let apt = |args: &'static [&'static str]| async move {
        let mut argv = vec!["DEBIAN_FRONTEND=noninteractive", "apt-get"];
        argv.extend_from_slice(args);
        cmd::run_capturing_all("/usr/bin/env", &argv).await
    };
    let _ = cmd::run_capturing_all(
        "/usr/bin/env",
        &[
            "DEBIAN_FRONTEND=noninteractive",
            "dpkg",
            "--configure",
            "-a",
        ],
    )
    .await;
    let _ = apt(&["--fix-broken", "install", "-y", "-qq"]).await;
    let _ = apt(&["update", "-qq"]).await;
    let res = apt(&[
        "install",
        "-y",
        "-qq",
        "libnginx-mod-http-modsecurity",
        "modsecurity-crs",
    ])
    .await;
    if created_policy {
        let _ = tokio::fs::remove_file(policy).await;
    }
    if let Err(e) = res {
        let raw = e.to_string();
        return Err(match cmd::explain_apt_failure(&raw) {
            Some(reason) => AdapterError::Other(format!(
                "ModSecurity could not be installed — {reason}\n\n\
                 Original package-manager output:\n{raw}"
            )),
            None => e,
        });
    }
    if let Err(e) = cmd::run("/usr/sbin/nginx", &["-t"]).await {
        let _ = tokio::fs::remove_file(MODULE_ENABLED).await;
        return Err(AdapterError::Other(format!(
            "the ModSecurity module was installed but nginx refuses to load it — this \
             nginx is probably not Debian's own build. The module was disabled again so \
             nginx keeps working.\n\n{e}"
        )));
    }
    if !(module_available() && crs_available()) {
        return Err(AdapterError::Other(
            "the packages installed, but the ModSecurity module or the Core Rule Set is \
             still missing on this node"
                .into(),
        ));
    }
    Ok(())
}

/// The node-wide engine configuration: Debian's recommended settings with
/// these changes, then the Core Rule Set.
/// - request bodies over the limit are inspected up to it and let through
///   (`ProcessPartial`) instead of refused — nginx accepts 256 MB uploads;
/// - response bodies are not buffered (no response rules are used);
/// - `SecStatusEngine Off` — the sample config turns on a phone-home;
/// - the audit log is JSON, parts `AHZ` only: method, URI, status and the
///   rules that matched, never request headers or bodies (cookies,
///   passwords);
/// - CRS's own exclusion files are included only if present, so an operator
///   deleting one cannot break nginx.
pub fn render_main_conf(before: bool, after: bool, unicode_map: bool) -> String {
    let mut s = String::from(
        "# Auto-managed by Hyperion. Do not edit — each site's CRS settings live on\n\
         # its Protection card and are rendered into its own server block.\n\
         SecRuleEngine DetectionOnly\n\
         SecRequestBodyAccess On\n\
         SecRule REQUEST_HEADERS:Content-Type \"^(?:application(?:/soap\\+|/)|text/)xml\" \
         \"id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML\"\n\
         SecRule REQUEST_HEADERS:Content-Type \"^application/json\" \
         \"id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
         SecRequestBodyLimit 13107200\n\
         SecRequestBodyNoFilesLimit 131072\n\
         SecRequestBodyLimitAction ProcessPartial\n\
         SecRequestBodyJsonDepthLimit 512\n\
         SecArgumentsLimit 1000\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,t:none,log,deny,status:400,\
         msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2\"\n\
         SecPcreMatchLimit 1000\n\
         SecPcreMatchLimitRecursion 1000\n\
         SecResponseBodyAccess Off\n\
         SecTmpDir /tmp/\n\
         SecDataDir /tmp/\n\
         SecAuditEngine RelevantOnly\n\
         SecAuditLogRelevantStatus \"^(?:5|4(?!04))\"\n\
         SecAuditLogParts AHZ\n\
         SecAuditLogType Serial\n\
         SecAuditLogFormat JSON\n",
    );
    s.push_str(&format!("SecAuditLog {AUDIT_LOG}\n"));
    s.push_str("SecArgumentSeparator &\nSecCookieFormat 0\n");
    if unicode_map {
        s.push_str(&format!("SecUnicodeMapFile {UNICODE_MAP} 20127\n"));
    }
    s.push_str("SecStatusEngine Off\n");
    s.push_str(&format!("Include {CRS_SETUP}\n"));
    if before {
        s.push_str(&format!("Include {CRS_BEFORE}\n"));
    }
    s.push_str(&format!("Include {CRS_RULES_DIR}/*.conf\n"));
    if after {
        s.push_str(&format!("Include {CRS_AFTER}\n"));
    }
    s
}

fn render_http_include() -> String {
    format!(
        "# Auto-managed by Hyperion: present only while a site on this node has the\n\
         # OWASP Core Rule Set on. Sites switch the engine on in their own server\n\
         # block; everywhere else it stays off (the directive's default).\n\
         modsecurity_rules_file {MAIN_CONF};\n"
    )
}

fn render_logrotate() -> String {
    // copytruncate: libmodsecurity keeps the file open across reloads, so a
    // renamed log would go on receiving every entry until nginx restarts.
    format!(
        "# Auto-managed by Hyperion.\n\
         {AUDIT_LOG} {{\n\
         \x20   daily\n\
         \x20   rotate 7\n\
         \x20   missingok\n\
         \x20   notifempty\n\
         \x20   compress\n\
         \x20   delaycompress\n\
         \x20   copytruncate\n\
         }}\n"
    )
}

/// One site's rules, rendered into its server block inside
/// `modsecurity_rules '…'`. Every value is a number, a CRS rule id or a
/// path from a closed alphabet (see `hyperion_types::crs`), so nothing here
/// can close the quote or start a directive.
///
/// `id:10001` sets the site's variables before CRS initialises; path
/// exclusions take `id:10100…10149` (at most 50). Local rule ids sit below
/// the 100000 range ModSecurity reserves for published rule sets.
pub fn render_site_rules(s: &CrsSettings) -> String {
    let engine = if s.mode == CrsMode::Block {
        "On"
    } else {
        "DetectionOnly"
    };
    let mut out = format!(
        "SecRuleEngine {engine}\n\
         SecAction \"id:10001,phase:1,pass,nolog,\
         setvar:tx.paranoia_level={p},setvar:tx.executing_paranoia_level={p},\
         setvar:tx.inbound_anomaly_score_threshold={t}{wp}\"\n",
        p = s.paranoia,
        t = s.threshold,
        wp = if s.wordpress {
            ",setvar:tx.crs_exclusions_wordpress=1"
        } else {
            ""
        },
    );
    let mut site_wide: Vec<u32> = s
        .exclusions
        .iter()
        .filter(|e| e.path.is_empty())
        .flat_map(|e| e.rules.iter().copied())
        .filter(|r| crs::excludable_rule(*r))
        .collect();
    site_wide.sort_unstable();
    site_wide.dedup();
    if !site_wide.is_empty() {
        let ids: Vec<String> = site_wide.iter().map(u32::to_string).collect();
        out.push_str(&format!("SecRuleRemoveById {}\n", ids.join(" ")));
    }
    for (i, e) in s
        .exclusions
        .iter()
        .filter(|e| !e.path.is_empty() && crs::valid_path(&e.path))
        .take(crs::MAX_EXCLUSIONS)
        .enumerate()
    {
        let ctl: Vec<String> = e
            .rules
            .iter()
            .filter(|r| crs::excludable_rule(**r))
            .map(|r| format!("ctl:ruleRemoveById={r}"))
            .collect();
        if ctl.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "SecRule REQUEST_FILENAME \"@beginsWith {}\" \"id:{},phase:1,pass,nolog,{}\"\n",
            e.path,
            10100 + i,
            ctl.join(",")
        ));
    }
    out
}

async fn write_if_changed(path: &str, want: &str) -> Result<bool, AdapterError> {
    if let Ok(existing) = tokio::fs::read_to_string(path).await {
        if existing == want {
            return Ok(false);
        }
    }
    atomic_write(Path::new(path), want.as_bytes(), 0o644).await?;
    Ok(true)
}

/// Load the rule set at http level when `need` (some site on the node has
/// CRS on), unload it otherwise. Writes the base config, the audit log dir
/// and its rotation first. Every change is `nginx -t`ed and rolled back on
/// failure, then reloaded. Returns whether anything changed.
pub async fn sync_http(need: bool) -> Result<bool, AdapterError> {
    let had = http_include_present();
    if !need {
        if !had {
            return Ok(false);
        }
        let previous = tokio::fs::read_to_string(HTTP_INCLUDE).await.ok();
        tokio::fs::remove_file(HTTP_INCLUDE)
            .await
            .map_err(|e| AdapterError::Other(format!("remove {HTTP_INCLUDE}: {e}")))?;
        if let Err(e) = cmd::run("/usr/sbin/nginx", &["-t"]).await {
            if let Some(body) = previous {
                let _ = atomic_write(Path::new(HTTP_INCLUDE), body.as_bytes(), 0o644).await;
            }
            return Err(e);
        }
        crate::nginx::reload().await?;
        return Ok(true);
    }

    let audit_dir = Path::new(AUDIT_DIR);
    tokio::fs::create_dir_all(audit_dir)
        .await
        .map_err(|e| AdapterError::Other(format!("create {AUDIT_DIR}: {e}")))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = cmd::run("/usr/bin/chown", &["root:adm", AUDIT_DIR]).await;
        let _ = tokio::fs::set_permissions(audit_dir, std::fs::Permissions::from_mode(0o750)).await;
    }
    tokio::fs::create_dir_all(CONF_DIR)
        .await
        .map_err(|e| AdapterError::Other(format!("create {CONF_DIR}: {e}")))?;
    let main = render_main_conf(
        Path::new(CRS_BEFORE).exists(),
        Path::new(CRS_AFTER).exists(),
        Path::new(UNICODE_MAP).exists(),
    );
    let previous_main = tokio::fs::read_to_string(MAIN_CONF).await.ok();
    let main_changed = write_if_changed(MAIN_CONF, &main).await?;
    let include_changed = write_if_changed(HTTP_INCLUDE, &render_http_include()).await?;
    // Housekeeping: a box without logrotate still serves.
    let _ = write_if_changed(LOGROTATE, &render_logrotate()).await;
    if !(main_changed || include_changed) {
        return Ok(false);
    }
    if let Err(e) = cmd::run("/usr/sbin/nginx", &["-t"]).await {
        // Back to what nginx last accepted.
        if !had {
            let _ = tokio::fs::remove_file(HTTP_INCLUDE).await;
        }
        if let Some(body) = previous_main {
            let _ = atomic_write(Path::new(MAIN_CONF), body.as_bytes(), 0o644).await;
        }
        return Err(e);
    }
    crate::nginx::reload().await?;
    Ok(true)
}

/// One audit-log entry, as the JSON serial log writes it (only the fields
/// used here).
#[derive(serde::Deserialize)]
struct AuditLine {
    transaction: AuditTx,
}

#[derive(serde::Deserialize)]
struct AuditTx {
    #[serde(default)]
    client_ip: String,
    #[serde(default)]
    unique_id: String,
    #[serde(default)]
    request: AuditRequest,
    #[serde(default)]
    response: AuditResponse,
    #[serde(default)]
    producer: AuditProducer,
    #[serde(default)]
    messages: Vec<AuditMessage>,
}

#[derive(serde::Deserialize, Default)]
struct AuditRequest {
    #[serde(default)]
    method: String,
    #[serde(default)]
    uri: String,
}

#[derive(serde::Deserialize, Default)]
struct AuditResponse {
    #[serde(default)]
    http_code: i64,
}

#[derive(serde::Deserialize, Default)]
struct AuditProducer {
    #[serde(default)]
    secrules_engine: String,
}

#[derive(serde::Deserialize)]
struct AuditMessage {
    #[serde(default)]
    message: String,
    #[serde(default)]
    details: AuditDetails,
}

#[derive(serde::Deserialize, Default)]
struct AuditDetails {
    #[serde(rename = "ruleId", default)]
    rule_id: String,
}

/// The rule the blocking evaluation logs when a request's anomaly score
/// reaches the site's threshold.
const ANOMALY_RULE: u32 = 949_110;

/// Parse one audit-log line into `(hosting id, hit)`.
///
/// Recorded only when CRS DECIDED: the anomaly threshold was reached (rule
/// 949110 — in detection-only mode too, which is how "would have blocked"
/// becomes visible), or the engine refused the request outright (a body it
/// could not parse). A lone below-threshold match is noise and `None`.
///
/// The transaction id is `<hosting id>-<msec>-<request id>`, set in the
/// site's own server block — the hosting id is the part a request cannot
/// choose.
pub fn parse_audit_line(line: &str) -> Option<(String, WafHit)> {
    let parsed: AuditLine = serde_json::from_str(line.trim()).ok()?;
    let tx = parsed.transaction;
    let mut parts = tx.unique_id.rsplitn(3, '-');
    let _request_id = parts.next()?;
    let msec = parts.next()?;
    let hosting = parts.next()?;
    if hosting.is_empty()
        || hosting.len() > 64
        || !hosting
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    let ts = msec.split('.').next()?.parse::<i64>().ok()?;
    let ip: std::net::IpAddr = tx.client_ip.parse().ok()?;

    let ids: Vec<u32> = tx
        .messages
        .iter()
        .filter_map(|m| m.details.rule_id.parse().ok())
        .collect();
    let enforced = tx.producer.secrules_engine == "Enabled";
    let reached = ids.contains(&ANOMALY_RULE);
    let refused = enforced && matches!(tx.response.http_code, 400 | 403);
    if !(reached || refused) {
        return None;
    }
    let category = ids
        .iter()
        .copied()
        .find(|id| crs::is_attack_rule(*id) && crs::category_of(*id).is_some())
        .or_else(|| {
            ids.iter()
                .copied()
                .find(|id| crs::category_of(*id).is_some())
        })
        .and_then(crs::category_of)
        .unwrap_or("other");
    let score = tx
        .messages
        .iter()
        .find(|m| m.details.rule_id == ANOMALY_RULE.to_string())
        .and_then(|m| m.message.split("Total Score: ").nth(1))
        .and_then(|rest| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u32>()
                .ok()
        });
    let mut matched: Vec<u32> = ids
        .iter()
        .copied()
        .filter(|id| crs::category_of(*id).is_some())
        .collect();
    matched.dedup();
    matched.truncate(12);
    let mut detail = matched
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(score) = score {
        detail.push_str(&format!(" · score {score}"));
    }
    let method = if tx.request.method.len() <= 16
        && tx.request.method.bytes().all(|b| b.is_ascii_alphabetic())
    {
        tx.request.method
    } else {
        "?".to_string()
    };
    Some((
        hosting.to_string(),
        WafHit {
            ts,
            ip: ip.to_string(),
            rule: crs::tag(category, !enforced),
            method,
            uri: tx.request.uri,
            ua: String::new(),
            cross_site: false,
            detail: detail.trim().to_string(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::crs::CrsExclusion;

    /// Captured from nginx 1.22 + libmodsecurity 3.0.9 + CRS 3.3.4 on Debian
    /// 12 with the main.conf this module renders: a blocked SQLi, a blocked
    /// XSS, a detection-only XSS on another site, a below-threshold match,
    /// and a refused unparseable JSON body.
    const FIXTURE: &str = include_str!("../testdata/modsec_audit.jsonl");

    #[test]
    fn real_audit_lines_parse_into_attributed_hits() {
        let parsed: Vec<Option<(String, WafHit)>> = FIXTURE.lines().map(parse_audit_line).collect();
        assert_eq!(parsed.len(), 5);

        let (site, sqli) = parsed[0].clone().expect("sqli");
        assert_eq!(site, "01a110d5-1ee1-71c2-b98b-0e31aa826f3b");
        assert_eq!(sqli.rule, "crs_sqli");
        assert_eq!(sqli.ip, "127.0.0.1");
        assert_eq!(sqli.method, "GET");
        assert_eq!(sqli.uri, "/products/?id=1%27%20OR%20%271%27=%271");
        assert_eq!(sqli.ts, 1_791_287_026);
        assert_eq!(sqli.detail, "942100 · score 5");

        let (_, xss) = parsed[1].clone().expect("xss");
        assert_eq!(xss.rule, "crs_xss");
        assert_eq!(xss.detail, "941100 941110 941160 · score 15");

        let (other, detected) = parsed[2].clone().expect("detection only");
        assert_eq!(other, "01a110d5-0000-7000-8000-000000000002");
        assert_eq!(detected.rule, "crs_xss_detected");

        assert!(parsed[3].is_none(), "below the threshold: not recorded");

        let (_, body) = parsed[4].clone().expect("unparseable body");
        assert_eq!(body.rule, "crs_body");
        assert_eq!(body.method, "POST");
    }

    #[test]
    fn malformed_and_foreign_lines_are_dropped() {
        assert!(parse_audit_line("").is_none());
        assert!(parse_audit_line("{not json").is_none());
        // A transaction id nobody rendered (the default numeric one).
        let line = FIXTURE.lines().next().expect("line").replace(
            "01a110d5-1ee1-71c2-b98b-0e31aa826f3b-1791287026.001-e73f7454a54333a7540def707eee3d25",
            "179128670275.676807",
        );
        assert!(parse_audit_line(&line).is_none());
    }

    #[test]
    fn detail_ids_round_trip_for_allow_this() {
        let (_, hit) = parse_audit_line(FIXTURE.lines().nth(1).expect("xss")).expect("hit");
        assert_eq!(
            crs::detail_rule_ids(&hit.detail),
            vec![941100, 941110, 941160]
        );
    }

    #[test]
    fn site_rules_render_closed_values_only() {
        let s = CrsSettings {
            mode: CrsMode::Block,
            paranoia: 2,
            threshold: 10,
            wordpress: true,
            exclusions: vec![
                CrsExclusion {
                    rules: vec![942100, 941160],
                    path: String::new(),
                },
                CrsExclusion {
                    rules: vec![932100],
                    path: "/wp-admin/admin-ajax.php".into(),
                },
                CrsExclusion {
                    rules: vec![949110],
                    path: "/x".into(),
                },
            ],
        };
        let r = render_site_rules(&s);
        assert!(r.starts_with("SecRuleEngine On\n"));
        assert!(r.contains(
            "setvar:tx.paranoia_level=2,setvar:tx.executing_paranoia_level=2,\
             setvar:tx.inbound_anomaly_score_threshold=10,setvar:tx.crs_exclusions_wordpress=1"
        ));
        assert!(r.contains("SecRuleRemoveById 941160 942100\n"));
        assert!(r.contains(
            "SecRule REQUEST_FILENAME \"@beginsWith /wp-admin/admin-ajax.php\" \
             \"id:10100,phase:1,pass,nolog,ctl:ruleRemoveById=932100\"\n"
        ));
        assert!(!r.contains("949110"), "structural rules never excluded");
        assert!(!r.contains('\''), "nothing can close the nginx quote");

        let detect = render_site_rules(&CrsSettings {
            mode: CrsMode::Detect,
            paranoia: 1,
            threshold: 5,
            ..Default::default()
        });
        assert!(detect.starts_with("SecRuleEngine DetectionOnly\n"));
        assert!(!detect.contains("crs_exclusions_wordpress"));
        assert!(!detect.contains("SecRuleRemoveById"));
    }

    #[test]
    fn main_conf_never_logs_headers_or_bodies_and_never_phones_home() {
        let c = render_main_conf(true, false, true);
        assert!(c.contains("SecAuditLogParts AHZ\n"));
        assert!(c.contains("SecStatusEngine Off\n"));
        assert!(c.contains("SecRequestBodyLimitAction ProcessPartial\n"));
        assert!(c.contains(&format!("SecAuditLog {AUDIT_LOG}\n")));
        assert!(c.contains(&format!("Include {CRS_BEFORE}\n")));
        assert!(!c.contains(CRS_AFTER));
        let setup = c.find(CRS_SETUP).expect("setup");
        let rules = c.find(CRS_RULES_DIR).expect("rules");
        assert!(setup < rules);
        assert!(render_logrotate().contains("copytruncate"));
        assert!(render_http_include().contains(&format!("modsecurity_rules_file {MAIN_CONF};")));
    }

    /// The real thing, on a disposable Debian box with nginx running as
    /// root: install, load the rule set, unload it. Never runs by accident —
    /// ignored AND gated on HYPERION_LIVE_MODSEC=1, because it installs
    /// packages and rewrites nginx config.
    #[tokio::test]
    #[ignore]
    async fn live_install_and_sync_on_debian() {
        if std::env::var_os("HYPERION_LIVE_MODSEC").is_none() {
            return;
        }
        ensure_installed().await.expect("install");
        assert!(module_available() && crs_available());
        assert!(!crs_version().await.is_empty());
        // Idempotent: a second call is a no-op.
        ensure_installed().await.expect("install again");

        assert!(
            sync_http(true).await.expect("load"),
            "first load changes things"
        );
        assert!(http_include_present());
        assert!(Path::new(MAIN_CONF).exists());
        assert!(Path::new(LOGROTATE).exists());
        cmd::run("/usr/sbin/nginx", &["-t"])
            .await
            .expect("nginx -t with CRS");
        assert!(!sync_http(true).await.expect("load again"), "idempotent");

        // A broken base config must be rolled back, not left for the next
        // reload to trip over.
        tokio::fs::write(MAIN_CONF, "SecRuleEngine Bogus\n")
            .await
            .expect("break");
        tokio::fs::remove_file(HTTP_INCLUDE)
            .await
            .expect("rm include");
        let restored = sync_http(true).await;
        assert!(
            restored.is_ok(),
            "re-rendered over the broken file: {restored:?}"
        );
        cmd::run("/usr/sbin/nginx", &["-t"])
            .await
            .expect("nginx -t after repair");

        assert!(sync_http(false).await.expect("unload"));
        assert!(!http_include_present());
        cmd::run("/usr/sbin/nginx", &["-t"])
            .await
            .expect("nginx -t without CRS");
        assert!(!sync_http(false).await.expect("unload again"), "idempotent");
    }

    #[test]
    fn debian_versions_reduce_to_upstream() {
        assert_eq!(upstream_version("3.3.4-1+deb12u3"), "3.3.4");
        assert_eq!(upstream_version("1:3.3.7-1"), "3.3.7");
        assert_eq!(upstream_version(""), "");
    }
}
