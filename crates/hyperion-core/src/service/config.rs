//! Readers for agent.toml sections the service consults at run time.

use super::*;

/// `[enrollment] master_url` from agent.toml — the master this node talks
/// to. `None` on the master itself or when unreadable.
pub(super) fn read_master_url(cfg_path: Option<&std::path::Path>) -> Option<String> {
    let raw = std::fs::read_to_string(cfg_path?).ok()?;
    let doc = raw.parse::<toml_edit::DocumentMut>().ok()?;
    let url = doc
        .get("enrollment")?
        .get("master_url")?
        .as_str()?
        .trim()
        .to_string();
    (!url.is_empty()).then_some(url)
}

/// The `[backup_remote]` section as it is ON DISK.
///
/// See the call site for why this must not come from the running agent's
/// memory. Missing section or unreadable file yields the defaults, which is
/// the same answer as "nothing configured" — the fail-safe direction here,
/// because the alternative is showing an operator a destination that is not
/// really set.
pub(crate) fn read_backup_remote_section(
    cfg_path: Option<&std::path::Path>,
) -> hyperion_types::BackupRemoteConfigView {
    let mut v = hyperion_types::BackupRemoteConfigView::default();
    let Some(doc) = read_agent_doc(cfg_path) else {
        return v;
    };
    let Some(sec) = doc.get("backup_remote") else {
        return v;
    };
    let s = |k: &str| {
        sec.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    v.enabled = sec
        .get("enabled")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    v.scheme = s("scheme");
    v.host = s("host");
    v.port = sec
        .get("port")
        .and_then(|x| x.as_integer())
        .unwrap_or(0)
        .clamp(0, 65535) as u16;
    v.user = s("user");
    // The password itself never leaves the node. Only whether one is set.
    v.password_set = !s("password").is_empty();
    v.base_path = s("base_path");
    v.keep_latest = read_ftp_keep_latest(cfg_path) as i64;
    v
}

/// The `[backup_retention]` section as it is ON DISK. Same reasoning.
pub(crate) fn read_backup_retention_section(
    cfg_path: Option<&std::path::Path>,
) -> hyperion_types::BackupRetentionConfigView {
    let d = hyperion_types::BackupRetentionConfigView::default();
    let Some(doc) = read_agent_doc(cfg_path) else {
        return d;
    };
    let Some(sec) = doc.get("backup_retention") else {
        return d;
    };
    hyperion_types::BackupRetentionConfigView {
        max_age_days: sec
            .get("max_age_days")
            .and_then(|x| x.as_integer())
            .unwrap_or(d.max_age_days),
        keep_latest_n: sec
            .get("keep_latest_n")
            .and_then(|x| x.as_integer())
            .unwrap_or(d.keep_latest_n),
    }
}

/// The `[backup]` local-copy policy: drop local copies once they are verified
/// off-site, and how many of each site's newest local copies to keep anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct LocalCopyPolicy {
    /// `drop_local_after_offsite`.
    pub drop: bool,
    /// `keep_local_latest` — 0 drops every local copy that is verified
    /// off-site, which is what the option meant before this knob existed.
    pub keep_latest: usize,
    /// `keep_local_latest` is there but does not read as a whole number >= 0.
    /// Nothing may drop local copies then — not the per-backup step (`drop`
    /// is forced off) and not an on-demand sweep that would otherwise read
    /// `keep_latest` 0 as "keep none".
    pub keep_unreadable: bool,
}

/// `[backup]` as it is ON DISK, defaulting to "keep every local copy".
///
/// Read fresh whenever it is acted on, NOT from agent boot state — same
/// reasoning as retention: the panel saves this on every node, and a worker
/// running the value it booted with would ignore the save until it restarted.
/// Missing section/key/file all mean "keep the local copy", which is the
/// fail-safe direction: an unreadable agent.toml must never start deleting
/// local backups nobody asked it to. An unreadable keep count turns dropping
/// off (see below); one above 1000 is clamped down, which keeps more.
pub(crate) fn read_local_copy_policy(cfg_path: Option<&std::path::Path>) -> LocalCopyPolicy {
    let doc = read_agent_doc(cfg_path);
    let sec = doc.as_ref().and_then(|d| d.get("backup"));
    let drop = sec
        .and_then(|s| s.get("drop_local_after_offsite"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Missing = 0. Present but not a whole number >= 0 (a quoted "3", 3.0, a
    // negative) is NOT read as 0: 0 is the most aggressive setting, and a
    // typo must not delete the copies its author meant to keep. Dropping is
    // off until the file says something readable.
    let keep_latest = match sec.and_then(|s| s.get("keep_local_latest")) {
        None => 0,
        Some(v) => match v.as_integer() {
            Some(n) if n >= 0 => n.min(1000) as usize,
            _ => {
                if drop {
                    tracing::warn!(value = %v.to_string().trim(),
                        "[backup] keep_local_latest is not a whole number >= 0 — \
                         not dropping any local backup copy until it is fixed");
                }
                return LocalCopyPolicy {
                    keep_unreadable: true,
                    ..LocalCopyPolicy::default()
                };
            }
        },
    };
    LocalCopyPolicy {
        drop,
        keep_latest,
        keep_unreadable: false,
    }
}

/// Parse agent.toml once, for the readers above.
pub(super) fn read_agent_doc(cfg_path: Option<&std::path::Path>) -> Option<toml_edit::DocumentMut> {
    let path = cfg_path?;
    let raw = std::fs::read_to_string(path).ok()?;
    raw.parse::<toml_edit::DocumentMut>().ok()
}

pub(crate) fn read_cluster_section(
    cfg_path: Option<&std::path::Path>,
) -> hyperion_types::ClusterConfigView {
    let Some(path) = cfg_path else {
        return hyperion_types::ClusterConfigView::default();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return hyperion_types::ClusterConfigView::default();
    };
    let Ok(doc) = raw.parse::<toml_edit::DocumentMut>() else {
        return hyperion_types::ClusterConfigView::default();
    };
    let section = doc.get("cluster");
    let accept = section
        .and_then(|s| s.get("master_accepts_hostings"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    // Absent, empty or unrecognised all resolve to "master" — i.e. exactly
    // today's behaviour, which is what lets an existing install upgrade with
    // no config change. The fail-safe direction matters: a broken or
    // unreadable agent.toml must never HIDE the cluster surface from an
    // operator who has real workers.
    let mode = match section
        .and_then(|s| s.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
    {
        "standalone" => "standalone",
        _ => "master",
    }
    .to_string();
    // Absent / unrecognised = "both", i.e. today's behaviour. `parse` owns
    // that rule; spelling it again here is how the two would drift.
    // From its OWN section, not from `[cluster]`: every node parses this one,
    // and `[cluster]` is master-only. Surfaced on this view anyway because it
    // is what the settings page renders, and one view beats two round trips.
    let protection_mode = hyperion_types::ProtectionMode::parse(
        doc.get("protection")
            .and_then(|s| s.get("mode"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )
    .as_str()
    .to_string();
    let test_node_ids = section
        .and_then(|s| s.get("test_node_ids"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let test_domain_template = section
        .and_then(|s| s.get("test_domain_template"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let test_wp_no_index = section
        .and_then(|s| s.get("test_wp_no_index"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let trash_enabled = section
        .and_then(|s| s.get("trash_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let trash_retention_days = section
        .and_then(|s| s.get("trash_retention_days"))
        .and_then(|v| v.as_integer())
        .unwrap_or(30)
        .clamp(1, 365);
    let panel_hostname = section
        .and_then(|s| s.get("panel_hostname"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let audit_retention_days = section
        .and_then(|s| s.get("audit_retention_days"))
        .and_then(|v| v.as_integer())
        .unwrap_or(0)
        .clamp(0, 3650);
    let enforce_admin_2fa = section
        .and_then(|s| s.get("enforce_admin_2fa"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let enforce_worker_cert_pinning = section
        .and_then(|s| s.get("enforce_worker_cert_pinning"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Same shape (and same fail-safe-to-false story) as cert pinning: an
    // unreadable/unparseable agent.toml already returned the Default view
    // above, where this is false, so a broken config can never silently
    // switch enforcement ON and take a mixed-version cluster offline.
    let enforce_response_auth = section
        .and_then(|s| s.get("enforce_response_auth"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    hyperion_types::ClusterConfigView {
        mode,
        protection_mode,
        master_accepts_hostings: accept,
        test_node_ids,
        test_domain_template,
        test_wp_no_index,
        panel_hostname,
        trash_enabled,
        trash_retention_days,
        audit_retention_days,
        enforce_admin_2fa,
        enforce_worker_cert_pinning,
        enforce_response_auth,
    }
}

pub(super) fn parse_agent_section_fields(
    section: &str,
    fields: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<(String, crate::config_persist::FieldValue)>, RpcError> {
    let bad = |msg: String| RpcError::Validation { message: msg };
    let mut out = Vec::with_capacity(fields.len());
    for (k, v) in fields {
        let parsed = match (section, k.as_str()) {
            // [acme]
            ("acme", "contact_email") => {
                if !v.contains('@') || v.len() > 254 {
                    return Err(bad("invalid email".into()));
                }
                crate::config_persist::FieldValue::Str(v.clone())
            }
            // `directory_url` is deliberately NOT settable. It was writable
            // but never read back and never honoured — issuance hardcodes the
            // Let's Encrypt endpoints — so saving it persisted a value into
            // agent.toml that reads as authoritative and changes nothing.
            // A knob that lies is worse than no knob.
            ("acme", "challenge_dir") => crate::config_persist::FieldValue::Str(v.clone()),
            // [email]
            ("email", "enabled") => crate::config_persist::FieldValue::Bool(parse_bool(v)?),
            ("email", "smtp_host")
            | ("email", "smtp_user")
            | ("email", "smtp_password")
            | ("email", "from_address")
            | ("email", "from_name")
            | ("email", "security")
            | ("email", "inet_protocols")
            | ("email", "bind_address")
            | ("email", "default_to") => crate::config_persist::FieldValue::Str(v.clone()),
            ("email", "smtp_port") => crate::config_persist::FieldValue::Int(parse_int(v)?),
            // [slack]
            ("slack", "default_webhook") => crate::config_persist::FieldValue::Str(v.clone()),
            // [backup_remote]
            ("backup_remote", "enabled") => crate::config_persist::FieldValue::Bool(parse_bool(v)?),
            ("backup_remote", "scheme")
            | ("backup_remote", "host")
            | ("backup_remote", "user")
            | ("backup_remote", "password")
            | ("backup_remote", "base_path") => crate::config_persist::FieldValue::Str(v.clone()),
            ("backup_remote", "port") => crate::config_persist::FieldValue::Int(parse_int(v)?),
            // 0 = off: the FTP target keeps everything, as it always has.
            ("backup_remote", "keep_latest") => {
                let n = parse_int(v)?;
                if !(0..=1000).contains(&n) {
                    return Err(bad(format!("keep_latest must be 0..=1000, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            // [backup_retention] — the same floors the agent applies at boot,
            // enforced where the value is typed rather than silently later.
            ("backup_retention", "max_age_days") => {
                let n = parse_int(v)?;
                if !(1..=3650).contains(&n) {
                    return Err(bad(format!("max_age_days must be 1..=3650, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("backup_retention", "keep_latest_n") => {
                let n = parse_int(v)?;
                if !(1..=1000).contains(&n) {
                    return Err(bad(format!("keep_latest_n must be 1..=1000, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            // [backup] — node-wide backup behaviour. `drop_local_after_offsite`
            // deletes the local copy once the off-site copy is verified.
            ("backup", "drop_local_after_offsite") => {
                crate::config_persist::FieldValue::Bool(parse_bool(v)?)
            }
            // How many of each site's newest local copies stay on disk even
            // with dropping on. 0 = drop every copy that is verified off-site.
            ("backup", "keep_local_latest") => {
                let n = parse_int(v)?;
                if !(0..=1000).contains(&n) {
                    return Err(bad(format!("keep_local_latest must be 0..=1000, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            // [snapshots] retention. keep_days = 0 means "never by age".
            ("snapshots", "keep_days") => {
                let n = parse_int(v)?;
                if !(0..=3650).contains(&n) {
                    return Err(bad(format!("snapshot keep_days must be 0..=3650, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("snapshots", "keep_last") => {
                let n = parse_int(v)?;
                if !(0..=1000).contains(&n) {
                    return Err(bad(format!("snapshot keep_last must be 0..=1000, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            // [cluster] — master web UI placement preferences
            ("cluster", "master_accepts_hostings")
            | ("cluster", "test_wp_no_index")
            | ("cluster", "trash_enabled")
            | ("cluster", "enforce_admin_2fa")
            | ("cluster", "enforce_worker_cert_pinning")
            | ("cluster", "enforce_response_auth") => {
                crate::config_persist::FieldValue::Bool(parse_bool(v)?)
            }
            ("cluster", "test_node_ids")
            | ("cluster", "test_domain_template")
            | ("cluster", "panel_hostname") => {
                crate::config_persist::FieldValue::Str(v.trim().to_string())
            }
            // Two-valued on purpose: "worker" is not settable, because it is
            // decided by the enrollment credential on disk. Reject anything
            // else rather than silently resolving it to master — a typo here
            // would otherwise be invisible.
            ("update", "auto") => crate::config_persist::FieldValue::Bool(parse_bool(v)?),
            ("cluster", "mode") => match v.trim() {
                m @ ("standalone" | "master") => {
                    crate::config_persist::FieldValue::Str(m.to_string())
                }
                other => {
                    return Err(bad(format!(
                        "cluster mode must be \"standalone\" or \"master\", got {other:?}"
                    )))
                }
            },
            // An explicit match with a REJECTING arm, deliberately unlike the
            // free-text cluster keys below. A typo saved as a mode would be
            // read back as "both" by `parse`, so the operator would see an
            // engine they thought they had switched off still running, with
            // nothing anywhere to explain it.
            ("protection", "mode") => match v.trim() {
                m @ ("backups" | "snapshots" | "both") => {
                    crate::config_persist::FieldValue::Str(m.to_string())
                }
                other => {
                    return Err(bad(format!(
                        "protection mode must be \"backups\", \"snapshots\" or \"both\", \
                         got {other:?}"
                    )))
                }
            },
            // [performance] — Core Web Vitals source. A rejecting match, like
            // [protection] mode: a typo saved as a source would resolve back
            // to "off" on read, so the operator would think measurement was on
            // and see nothing, with nothing to explain it.
            ("performance", "cwv_source") => match v.trim() {
                m @ ("off" | "psi" | "lighthouse") => {
                    crate::config_persist::FieldValue::Str(m.to_string())
                }
                other => {
                    return Err(bad(format!(
                        "Core Web Vitals source must be \"off\", \"psi\" or \"lighthouse\", \
                         got {other:?}"
                    )))
                }
            },
            ("performance", "strategy") => match v.trim() {
                m @ ("mobile" | "desktop") => crate::config_persist::FieldValue::Str(m.to_string()),
                other => {
                    return Err(bad(format!(
                        "performance strategy must be \"mobile\" or \"desktop\", got {other:?}"
                    )))
                }
            },
            ("performance", "psi_api_key") => {
                crate::config_persist::FieldValue::Str(v.trim().to_string())
            }
            ("performance", "cwv_interval_days") => {
                let n = parse_int(v)?;
                if !(0..=365).contains(&n) {
                    return Err(bad(format!(
                        "auto-measure interval must be 0..=365 days, got {n}"
                    )));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("cluster", "trash_retention_days") => {
                let n = parse_int(v)?;
                if !(1..=365).contains(&n) {
                    return Err(bad(format!(
                        "trash_retention_days must be 1..=365, got {n}"
                    )));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("cluster", "audit_retention_days") => {
                let n = parse_int(v)?;
                if !(0..=3650).contains(&n) {
                    return Err(bad(format!(
                        "audit_retention_days must be 0..=3650 (0 = keep forever), got {n}"
                    )));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            // [fail2ban] — native brute-force scanner tunables.
            ("fail2ban", "enabled") => crate::config_persist::FieldValue::Bool(parse_bool(v)?),
            // Every range below is a SUBSET of what `Fail2banConfig::sanitized`
            // leaves untouched, so the UI can never persist a number the agent
            // silently overrides at boot — a saved `ban_ttl_secs = 0` would
            // otherwise sit in the file reading as a PERMANENT node-wide ban
            // while the running scanner used 60 s.
            ("fail2ban", "window_secs") => {
                let n = parse_int(v)?;
                if !(1..=86_400).contains(&n) {
                    return Err(bad(format!("window_secs must be 1..=86400, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("fail2ban", "ban_ttl_secs") | ("fail2ban", "repeat_ttl_secs") => {
                let n = parse_int(v)?;
                if !(60..=31_536_000).contains(&n) {
                    return Err(bad(format!("{k} must be 60..=31536000 (1 year), got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("fail2ban", "repeat_lookback_secs") => {
                let n = parse_int(v)?;
                if !(0..=31_536_000).contains(&n) {
                    return Err(bad(format!(
                        "repeat_lookback_secs must be 0..=31536000 (0 = never escalate), got {n}"
                    )));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("fail2ban", "http_threshold")
            | ("fail2ban", "ssh_threshold")
            | ("fail2ban", "ftp_threshold")
            | ("fail2ban", "mail_threshold") => {
                let n = parse_int(v)?;
                // Floor 2: a threshold of 1 bans on the first observed
                // failure, which is one fat-fingered password.
                if !(2..=10_000).contains(&n) {
                    return Err(bad(format!("{k} must be 2..=10000, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("fail2ban", "waf_threshold") => {
                let n = parse_int(v)?;
                // Floor 3: a WAF rule can be tripped by an honest client once
                // (a stale bookmark to /readme.html), never as a pattern.
                if !(3..=1000).contains(&n) {
                    return Err(bad(format!("waf_threshold must be 3..=1000, got {n}")));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            // [notifications] — editable Slack + email message wording.
            ("notifications", "slack_template")
            | ("notifications", "email_subject_template")
            | ("notifications", "email_body_template") => {
                if v.len() > 4000 {
                    return Err(bad("template too long (max 4000 characters)".into()));
                }
                crate::config_persist::FieldValue::Str(v.clone())
            }
            // [notifications] — the two CUSTOMER LETTERS. Whole letters
            // rather than one-line wrappers, hence the roomier cap: the
            // built-in care report is ~1.2 kB before the operator adds a
            // word. Empty stays empty and means "use the built-in letter".
            ("notifications", "care_report_body_template")
            | ("notifications", "care_report_subject_template")
            | ("notifications", "expiry_warning_subject_template")
            | ("notifications", "expiry_warning_body_template") => {
                if v.len() > 20_000 {
                    return Err(bad("letter too long (max 20000 characters)".into()));
                }
                // A <textarea> submits CRLF line endings per the HTML spec.
                // Left alone they would end up in a plain-text mail body and
                // would stop a saved copy of the default letter from being
                // byte-identical to the built-in one.
                crate::config_persist::FieldValue::Str(v.replace("\r\n", "\n"))
            }
            // [letters] — the language pack and the per-string overrides.
            // Every word the two customer letters can say is one of these,
            // which is what makes "translate the whole thing" a thing an
            // operator can do rather than a code change.
            ("letters", "lang") => {
                // Normalised rather than rejected: an unrecognised language
                // resolves to English, and a customer's report going out in
                // the wrong language beats one not going out at all.
                crate::config_persist::FieldValue::Str(LetterLang::parse(v).as_str().to_string())
            }
            // Which language the operator's rewritten sentences are in.
            //
            // An explicit match with an EMPTY arm, unlike `lang` above which
            // normalises. Empty is a real answer here and the default — "I
            // have not said" — and it must be storable so an operator can take
            // a declaration back. A typo must not silently become "en": that
            // would withhold every sentence from every Czech site, which is
            // the exact failure this key was added to end.
            // Case-insensitive like the reader: a hand-written "CS" works
            // locally, and refusing it here would make the master's settings
            // sync refuse the whole payload on every node.
            ("letters", "overrides_lang") => match v.trim().to_ascii_lowercase().as_str() {
                l @ ("" | "en" | "cs") => crate::config_persist::FieldValue::Str(l.to_string()),
                other => {
                    return Err(bad(format!(
                        "letter wording language must be \"en\", \"cs\" or empty, got {other:?}"
                    )))
                }
            },
            // The operator's own alerts (bell + admin mail). Read since #179 but
            // never writable: this arm was missing, so every Settings save that
            // carried it — the whole letter-language form — was refused with
            // "field `operator_lang` is not editable". Normalised like `lang`.
            ("letters", "operator_lang") => {
                crate::config_persist::FieldValue::Str(LetterLang::parse(v).as_str().to_string())
            }
            // The billing reminder. Empty = follow the customer `lang`, so it
            // must be storable; a typo must not silently pin it to English.
            // Case-insensitive like the reader: a hand-written "CS" works
            // locally, and refusing it here would make the master's settings
            // sync refuse the whole payload on every node.
            ("letters", "billing_lang") => match v.trim().to_ascii_lowercase().as_str() {
                l @ ("" | "en" | "cs") => crate::config_persist::FieldValue::Str(l.to_string()),
                other => {
                    return Err(bad(format!(
                        "billing reminder language must be \"en\", \"cs\" or empty, got {other:?}"
                    )))
                }
            },
            // Only ids the catalogue actually has. An unknown one is either
            // a hand-edited file or a string this version removed, and
            // storing it would put wording in agent.toml that nothing reads.
            ("letters", id) if crate::letters::lookup(id).is_some() => {
                if v.len() > 20_000 {
                    return Err(bad("letter string too long (max 20000 characters)".into()));
                }
                // A <textarea> submits CRLF line endings per the HTML spec.
                // Left alone they would end up in a plain-text mail body.
                crate::config_persist::FieldValue::Str(v.replace("\r\n", "\n"))
            }
            // Reject anything else.
            _ => {
                return Err(bad(format!(
                    "field `{k}` is not editable in section `{section}` (or section unknown)"
                )));
            }
        };
        out.push((k.clone(), parsed));
    }
    Ok(out)
}

pub(super) fn parse_bool(v: &str) -> Result<bool, RpcError> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Ok(true),
        "false" | "off" | "no" | "0" | "" => Ok(false),
        _ => Err(RpcError::Validation {
            message: format!("expected bool, got {v:?}"),
        }),
    }
}

pub(super) fn parse_int(v: &str) -> Result<i64, RpcError> {
    v.trim().parse::<i64>().map_err(|_| RpcError::Validation {
        message: format!("expected integer, got {v:?}"),
    })
}
