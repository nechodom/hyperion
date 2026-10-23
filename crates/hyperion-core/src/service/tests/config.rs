//! Tests for `service::config`.

use super::*;

/// The policy as written by the Settings save (a real TOML bool + int) is
/// what a backup reads back; anything else is "keep every local copy".
#[test]
fn local_copy_policy_reads_back_what_settings_writes() {
    use super::{read_local_copy_policy, LocalCopyPolicy};
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("agent.toml");
    // No file / no section → keep everything.
    assert_eq!(read_local_copy_policy(None), LocalCopyPolicy::default());
    assert_eq!(
        read_local_copy_policy(Some(&cfg)),
        LocalCopyPolicy::default()
    );
    std::fs::write(&cfg, "[agent]\n").expect("write");
    assert_eq!(
        read_local_copy_policy(Some(&cfg)),
        LocalCopyPolicy::default()
    );

    // Through the same parser + writer the Settings form goes through.
    let mut f = std::collections::BTreeMap::new();
    f.insert("drop_local_after_offsite".to_string(), "true".to_string());
    f.insert("keep_local_latest".to_string(), "2".to_string());
    let parsed = super::parse_agent_section_fields("backup", &f).expect("valid");
    let view: Vec<(&str, crate::config_persist::FieldValue)> = parsed
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    crate::config_persist::set_many(&cfg, "backup", &view).expect("write");
    assert_eq!(
        read_local_copy_policy(Some(&cfg)),
        LocalCopyPolicy {
            drop: true,
            keep_latest: 2,
            keep_unreadable: false,
        }
    );

    // Out of range is refused at the door…
    let mut f = std::collections::BTreeMap::new();
    f.insert("keep_local_latest".to_string(), "-1".to_string());
    assert!(super::parse_agent_section_fields("backup", &f).is_err());
    f.insert("keep_local_latest".to_string(), "1001".to_string());
    assert!(super::parse_agent_section_fields("backup", &f).is_err());
    // …and a hand-edited file: a quoted "true" is NOT a yes…
    std::fs::write(
        &cfg,
        "[backup]\ndrop_local_after_offsite = \"true\"\nkeep_local_latest = -5\n",
    )
    .expect("write");
    assert!(!read_local_copy_policy(Some(&cfg)).drop);
    // …and a keep count that does not read as a whole number turns
    // dropping OFF — never into "keep 0", the most aggressive setting.
    for bad in ["\"3\"", "3.0", "-5", "true"] {
        std::fs::write(
            &cfg,
            format!("[backup]\ndrop_local_after_offsite = true\nkeep_local_latest = {bad}\n"),
        )
        .expect("write");
        let p = read_local_copy_policy(Some(&cfg));
        assert!(!p.drop, "keep_local_latest = {bad}");
        assert!(p.keep_unreadable, "keep_local_latest = {bad}");
    }
    // Too large is clamped down, which keeps more.
    std::fs::write(
        &cfg,
        "[backup]\ndrop_local_after_offsite = true\nkeep_local_latest = 5000\n",
    )
    .expect("write");
    assert_eq!(
        read_local_copy_policy(Some(&cfg)),
        LocalCopyPolicy {
            drop: true,
            keep_latest: 1000,
            keep_unreadable: false,
        }
    );
}

#[test]
fn master_url_is_read_from_the_enrollment_section() {
    let dir = tempfile::tempdir().expect("dir");
    let p = dir.path().join("agent.toml");
    std::fs::write(
        &p,
        "[enrollment]\nmaster_url = \"https://m.example.cz:8443\"\n",
    )
    .expect("w");
    assert_eq!(
        read_master_url(Some(&p)).as_deref(),
        Some("https://m.example.cz:8443")
    );
    std::fs::write(&p, "[cluster]\nmode = \"master\"\n").expect("w");
    assert_eq!(read_master_url(Some(&p)), None);
    assert_eq!(read_master_url(None), None);
}

#[test]
fn retention_fields_are_range_checked_where_they_are_typed() {
    let one = |section: &str, key: &str, v: &str| {
        let mut f = std::collections::BTreeMap::new();
        f.insert(key.to_string(), v.to_string());
        parse_agent_section_fields(section, &f).is_ok()
    };
    assert!(one("snapshots", "keep_days", "14"));
    assert!(one("snapshots", "keep_days", "0"), "0 = never by age");
    assert!(!one("snapshots", "keep_days", "-1"));
    assert!(!one("snapshots", "keep_days", "99999"));
    assert!(one("snapshots", "keep_last", "0"));
    assert!(!one("snapshots", "keep_last", "abc"));
    assert!(
        !one("snapshots", "enabled_typo", "1"),
        "unknown keys are refused"
    );
    assert!(one("backup_retention", "max_age_days", "30"));
    assert!(
        !one("backup_retention", "max_age_days", "0"),
        "the agent floors this at 1"
    );
    assert!(!one("backup_retention", "keep_latest_n", "0"));
}

/// "worker" is not a settable mode — it is a fact about the disk, and a
/// key that can contradict it is a bug factory.
#[tokio::test]
async fn mode_key_rejects_anything_but_standalone_or_master() {
    for good in ["standalone", "master"] {
        let mut f = std::collections::BTreeMap::new();
        f.insert("mode".to_string(), good.to_string());
        assert!(
            parse_agent_section_fields("cluster", &f).is_ok(),
            "{good} must be accepted"
        );
    }
    for bad in ["worker", "", "Standalone", "yes"] {
        let mut f = std::collections::BTreeMap::new();
        f.insert("mode".to_string(), bad.to_string());
        assert!(
            parse_agent_section_fields("cluster", &f).is_err(),
            "{bad:?} must be rejected rather than silently resolved"
        );
    }
}

#[tokio::test]
async fn is_worker_node_false_when_no_state_file_configured() {
    let s = svc_with_state_file(None).await;
    assert!(!s.is_worker_node(), "missing config path → assume master");
}

#[test]
fn enforce_response_auth_defaults_off_and_fails_safe() {
    let tmp = tempfile::tempdir().expect("dir");
    // No config path at all → Default view, enforcement OFF.
    assert!(!read_cluster_section(None).enforce_response_auth);
    // Unparseable config → also OFF. A broken agent.toml must never
    // silently switch enforcement ON and strand a mixed-version cluster.
    let broken = tmp.path().join("broken.toml");
    std::fs::write(&broken, b"[cluster\nenforce_response_auth = true").expect("write");
    assert!(!read_cluster_section(Some(broken.as_path())).enforce_response_auth);
    // Section present but the key absent → OFF (opt-in only).
    let quiet = tmp.path().join("quiet.toml");
    std::fs::write(&quiet, b"[cluster]\npanel_hostname = \"p\"\n").expect("write");
    assert!(!read_cluster_section(Some(quiet.as_path())).enforce_response_auth);
    // Explicitly on → on.
    let on = tmp.path().join("on.toml");
    std::fs::write(&on, b"[cluster]\nenforce_response_auth = true\n").expect("write");
    assert!(read_cluster_section(Some(on.as_path())).enforce_response_auth);
}

#[test]
fn enforce_response_auth_is_settings_writable() {
    let fields =
        std::collections::BTreeMap::from([("enforce_response_auth".to_string(), "on".to_string())]);
    let parsed = parse_agent_section_fields("cluster", &fields).expect("allow-listed");
    assert!(matches!(
        parsed.as_slice(),
        [(_, crate::config_persist::FieldValue::Bool(true))]
    ));
}

/// `operator_lang` and `billing_lang` were read but never writable, so the
/// Settings form that set them was refused as a whole.
#[test]
fn the_letter_language_keys_are_writable() {
    let one = |k: &str, v: &str| {
        let mut f = std::collections::BTreeMap::new();
        f.insert(k.to_string(), v.to_string());
        parse_agent_section_fields("letters", &f)
    };
    assert!(one("operator_lang", "cs").is_ok());
    assert!(
        one("billing_lang", "").is_ok(),
        "empty = follow the customer letters"
    );
    assert!(one("billing_lang", "en").is_ok());
    assert!(
        one("billing_lang", "sk").is_err(),
        "a typo is named, not pinned to English"
    );
    assert!(crate::cluster_sync::is_synced_key(
        "letters",
        "operator_lang"
    ));
    assert!(crate::cluster_sync::is_synced_key(
        "letters",
        "billing_lang"
    ));
}

#[test]
fn customer_letter_templates_are_settings_writable() {
    // A <textarea> posts CRLF; storing it would put \r into a
    // plain-text mail body, so the parser normalises it.
    let fields = std::collections::BTreeMap::from([(
        "care_report_body_template".to_string(),
        "Hi {domain}\r\nbye\r\n".to_string(),
    )]);
    let parsed = parse_agent_section_fields("notifications", &fields).expect("allow-listed");
    assert!(matches!(
        parsed.as_slice(),
        [(_, crate::config_persist::FieldValue::Str(s))] if s == "Hi {domain}\nbye\n"
    ));
    // Both letters are allow-listed, and both are length-capped.
    let big = std::collections::BTreeMap::from([(
        "expiry_warning_body_template".to_string(),
        "x".repeat(20_001),
    )]);
    assert!(parse_agent_section_fields("notifications", &big).is_err());
    // The subjects are allow-listed too — this letter goes to a paying
    // customer, and until they were, a translated body arrived under an
    // English subject with no field anywhere to change it.
    let subj = std::collections::BTreeMap::from([
        (
            "care_report_subject_template".to_string(),
            "Report údržby — {domain}".to_string(),
        ),
        (
            "expiry_warning_subject_template".to_string(),
            "Hosting {domain} končí za {days_left_count} dní".to_string(),
        ),
    ]);
    assert!(parse_agent_section_fields("notifications", &subj).is_ok());
    // A field that is NOT in the section's allow-list is still refused.
    let bogus = std::collections::BTreeMap::from([(
        "care_report_footer_template".to_string(),
        "nope".to_string(),
    )]);
    assert!(parse_agent_section_fields("notifications", &bogus).is_err());
}
