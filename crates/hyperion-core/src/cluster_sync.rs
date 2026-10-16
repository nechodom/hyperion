//! Master → node settings sync.
//!
//! Settings that are ACTED ON by the node that owns a site (backup rules, the
//! off-site targets, the customer letters, brute-force thresholds, ...) used
//! to be written to the master's agent.toml and pushed to the other nodes
//! once, at save time. A node that was down for that save, or enrolled after
//! it, never got the value — and nothing ever said so.
//!
//! This module is the shared half of the fix. The master builds a
//! [`SyncPayload`] out of its own agent.toml plus its S3 targets and hashes it
//! into a revision; its sync loop asks each node which revision it last
//! applied and sends the payload to every node that is behind. The node
//! replaces each synced section with the master's (the master always wins)
//! and keeps the S3 targets in a 0600 file next to agent.toml, where its
//! scheduled backups read them.
//!
//! "Replaces" is literal: a synced key the master does not have is REMOVED on
//! the node, so the node falls back to the same built-in default the master
//! uses. Leaving it would let an old per-node edit outlive every save. Keys
//! that are not synced (node-local paths, anything hand-written that the
//! panel does not manage) are never touched.

use std::collections::BTreeMap;

use toml_edit::{DocumentMut, Item};

use crate::config_persist::FieldValue;

/// Every agent.toml section the master owns for the whole cluster, in the
/// order they are sent. `[email]` is per node (each node's own MTA),
/// `[slack]` is only read on the master, and `[agent]`/`[enrollment]`/
/// `[remote_rpc]` are the node's own identity. `[cluster]` is master-only
/// except for the trash keys and the preview template, which every node
/// reads for its own sites — [`is_synced_key`] carries only those.
pub const SYNCED_SECTIONS: &[&str] = &[
    "backup",
    "backup_retention",
    "backup_remote",
    "snapshots",
    "protection",
    "performance",
    "notifications",
    "letters",
    "acme",
    "update",
    "fail2ban",
    "cluster",
];

/// Sections the running agent reads only at start-up. A change to one of
/// these needs an agent restart before it does anything; every other synced
/// section is re-read from disk each time it is used.
pub const RESTART_SECTIONS: &[&str] = &["backup_remote", "acme", "fail2ban"];

/// Bumped whenever the payload's meaning changes, so a node that applied an
/// older shape is seen as behind even if the values happen to hash alike.
const PAYLOAD_VERSION: &str = "cluster-sync/1";

/// Is `section.key` one the master owns? Mirrors the keys the settings forms
/// write (and `parse_agent_section_fields` accepts), minus the node-local
/// ones: `[acme] challenge_dir` is a path on THAT node's disk.
pub fn is_synced_key(section: &str, key: &str) -> bool {
    match section {
        "backup" => matches!(key, "drop_local_after_offsite" | "keep_local_latest"),
        "backup_retention" => {
            matches!(
                key,
                "max_age_days" | "keep_latest_n" | "pre_update_keep_days"
            )
        }
        "backup_remote" => matches!(
            key,
            "enabled" | "scheme" | "host" | "port" | "user" | "password" | "base_path"
        ),
        "snapshots" => matches!(key, "keep_days" | "keep_last"),
        "protection" => key == "mode",
        "performance" => matches!(
            key,
            "cwv_source" | "strategy" | "psi_api_key" | "cwv_interval_days"
        ),
        "notifications" => matches!(
            key,
            "slack_template"
                | "email_subject_template"
                | "email_body_template"
                | "care_report_body_template"
                | "care_report_subject_template"
                | "expiry_warning_subject_template"
                | "expiry_warning_body_template"
        ),
        // `operator_lang` and `billing_lang` too: every node renders its own
        // alerts and runs its own billing sweep, so a language set only on
        // the master governed only the master's.
        "letters" => {
            matches!(
                key,
                "lang" | "overrides_lang" | "operator_lang" | "billing_lang"
            ) || crate::letters::lookup(key).is_some()
        }
        "acme" => key == "contact_email",
        "update" => key == "auto",
        // A worker's delete reads ITS OWN trash switch and its trash GC its
        // own retention, and its nginx builds each site's preview alias from
        // ITS OWN preview template. Everything else in [cluster] (sign-in,
        // placement, hardening, test nodes, the node's mode) stays the
        // master's or the node's own.
        "cluster" => matches!(
            key,
            "trash_enabled" | "trash_retention_days" | "test_domain_template"
        ),
        "fail2ban" => matches!(
            key,
            "enabled"
                | "window_secs"
                | "ban_ttl_secs"
                | "repeat_ttl_secs"
                | "repeat_lookback_secs"
                | "http_threshold"
                | "ssh_threshold"
                | "ftp_threshold"
                | "mail_threshold"
                | "waf_threshold"
        ),
        _ => false,
    }
}

/// One synced section as it travels: the master's values as strings, the
/// same shape a settings form posts, so the node validates them with the
/// same per-field rules.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SyncedSection {
    pub section: String,
    pub fields: BTreeMap<String, String>,
}

/// A value from agent.toml in the string form the field parser takes. Only
/// the three shapes the panel ever writes; anything else (an array someone
/// typed by hand) is not ours to carry.
fn render(item: &Item) -> Option<String> {
    let v = item.as_value()?;
    if let Some(s) = v.as_str() {
        Some(s.to_string())
    } else if let Some(n) = v.as_integer() {
        Some(n.to_string())
    } else {
        v.as_bool().map(|b| b.to_string())
    }
}

/// The synced keys of `section` in `doc`, rendered. Missing section = empty.
fn synced_values(doc: &DocumentMut, section: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(t) = doc.get(section).and_then(|i| i.as_table_like()) {
        for (k, item) in t.iter() {
            if is_synced_key(section, k) {
                if let Some(v) = render(item) {
                    out.insert(k.to_string(), v);
                }
            }
        }
    }
    out
}

/// Every synced section out of the master's agent.toml text. A section the
/// master does not have is still sent, empty: it means "built-in defaults",
/// and the node must drop whatever it had to get the same.
pub fn extract_sections(raw_toml: &str) -> Result<Vec<SyncedSection>, String> {
    let doc: DocumentMut = raw_toml
        .parse()
        .map_err(|e| format!("agent.toml does not parse: {e}"))?;
    Ok(SYNCED_SECTIONS
        .iter()
        .map(|s| SyncedSection {
            section: (*s).to_string(),
            fields: synced_values(&doc, s),
        })
        .collect())
}

/// Content hash of what the master would send. Equal revisions = nothing to
/// do; it is the only thing the sync loop asks a node for, so the secrets in
/// the payload cross the wire only when something actually changed.
pub fn revision(
    sections: &[SyncedSection],
    s3_targets: &[hyperion_types::S3BackupTarget],
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(PAYLOAD_VERSION.as_bytes());
    // serde_json of BTreeMaps + Vecs is deterministic.
    let body = serde_json::to_vec(&(sections, s3_targets)).unwrap_or_default();
    h.update(&body);
    h.finalize().to_hex()[..32].to_string()
}

/// What applying a payload to one agent.toml did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Sections whose synced values are now different from before.
    pub changed: Vec<String>,
    /// `section.key`s the master sent that this node does not manage (a key
    /// newer than this agent). Reported, never written.
    pub ignored: Vec<String>,
}

/// Replace every synced section of `doc` with the master's values.
///
/// `parse` is the node's own per-field validator; a section it refuses fails
/// the WHOLE apply before anything is changed, so a node is never left with
/// half of a payload. Unknown keys are skipped (and listed), not refused: a
/// newer master must not lock an older node out of every other value.
pub fn apply_sections(
    doc: &mut DocumentMut,
    sections: &[SyncedSection],
    parse: impl Fn(&str, &BTreeMap<String, String>) -> Result<Vec<(String, FieldValue)>, String>,
) -> Result<ApplyOutcome, String> {
    let mut out = ApplyOutcome::default();
    // Validate everything first.
    let mut parsed: Vec<(&str, Vec<(String, FieldValue)>)> = Vec::new();
    for s in sections {
        if !SYNCED_SECTIONS.contains(&s.section.as_str()) {
            out.ignored.push(format!("[{}]", s.section));
            continue;
        }
        let mut known = BTreeMap::new();
        for (k, v) in &s.fields {
            if is_synced_key(&s.section, k) {
                known.insert(k.clone(), v.clone());
            } else {
                out.ignored.push(format!("{}.{k}", s.section));
            }
        }
        let fields = parse(&s.section, &known).map_err(|e| format!("[{}]: {e}", s.section))?;
        parsed.push((s.section.as_str(), fields));
    }
    for (section, fields) in parsed {
        let before = synced_values(doc, section);
        match doc.as_table().get(section) {
            Some(Item::Table(_)) => {}
            Some(_) => return Err(format!("[{section}] in agent.toml is not a table")),
            None if fields.is_empty() && before.is_empty() => continue,
            None => {
                let mut t = toml_edit::Table::new();
                t.set_implicit(false);
                doc[section] = Item::Table(t);
            }
        }
        let table = doc[section]
            .as_table_mut()
            .ok_or_else(|| format!("[{section}] in agent.toml is not a table"))?;
        // Drop synced keys the master does not have (→ built-in default).
        let stale: Vec<String> = table
            .iter()
            .map(|(k, _)| k.to_string())
            .filter(|k| is_synced_key(section, k) && !fields.iter().any(|(f, _)| f == k))
            .collect();
        for k in stale {
            table.remove(&k);
        }
        for (k, v) in fields {
            table[k.as_str()] = match v {
                FieldValue::Str(s) => toml_edit::value(s),
                FieldValue::Int(n) => toml_edit::value(n),
                FieldValue::Bool(b) => toml_edit::value(b),
            };
        }
        if synced_values(doc, section) != before {
            out.changed.push(section.to_string());
        }
    }
    Ok(out)
}

/// What a node keeps from the last payload it applied, in a 0600 JSON file
/// next to its agent.toml.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct NodeSyncState {
    pub revision: String,
    pub applied_at: i64,
    /// The master's enabled S3 targets, secrets inline — this file is the
    /// worker's equivalent of the master's `backup_targets` table.
    pub s3_targets: Vec<hyperion_types::S3BackupTarget>,
}

/// File name of [`NodeSyncState`], beside agent.toml.
pub const STATE_FILE: &str = "cluster-sync.json";

/// Read the node's sync state. Missing or unreadable = never synced.
pub fn read_state(path: &std::path::Path) -> Option<NodeSyncState> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Write the node's sync state atomically, 0600 from the first byte (it holds
/// S3 secret keys).
pub fn write_state(path: &std::path::Path, st: &NodeSyncState) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let body = serde_json::to_vec_pretty(st).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&body)?;
    f.sync_all()?;
    drop(f);
    std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(
        _s: &str,
        f: &BTreeMap<String, String>,
    ) -> Result<Vec<(String, FieldValue)>, String> {
        Ok(f.iter()
            .map(|(k, v)| {
                let fv = if let Ok(n) = v.parse::<i64>() {
                    FieldValue::Int(n)
                } else if v == "true" || v == "false" {
                    FieldValue::Bool(v == "true")
                } else {
                    FieldValue::Str(v.clone())
                };
                (k.clone(), fv)
            })
            .collect())
    }

    #[test]
    fn extract_keeps_only_synced_keys_and_sends_every_section() {
        let raw = r#"
[agent]
backup_root = "/var/backups/hyperion"
[acme]
contact_email = "ops@example.com"
challenge_dir = "/var/www/acme"
[backup_remote]
enabled = true
host = "ftp.example.com"
port = 21
password = "s3cret"
[cluster]
mode = "master"
"#;
        let secs = extract_sections(raw).unwrap();
        assert_eq!(secs.len(), SYNCED_SECTIONS.len());
        let acme = secs.iter().find(|s| s.section == "acme").unwrap();
        assert_eq!(acme.fields.get("contact_email").unwrap(), "ops@example.com");
        assert!(
            !acme.fields.contains_key("challenge_dir"),
            "node-local path"
        );
        let remote = secs.iter().find(|s| s.section == "backup_remote").unwrap();
        assert_eq!(remote.fields.get("port").unwrap(), "21");
        assert_eq!(remote.fields.get("enabled").unwrap(), "true");
        assert!(secs.iter().all(|s| s.section != "agent"));
        let cluster = secs.iter().find(|s| s.section == "cluster").unwrap();
        assert!(
            cluster.fields.is_empty(),
            "[cluster] carries only the trash keys, never the node's mode"
        );
        let f2b = secs.iter().find(|s| s.section == "fail2ban").unwrap();
        assert!(f2b.fields.is_empty(), "absent on master = defaults");
    }

    #[test]
    fn revision_changes_with_values_and_targets() {
        let a = extract_sections("[backup_retention]\nkeep_latest_n = 3\n").unwrap();
        let b = extract_sections("[backup_retention]\nkeep_latest_n = 4\n").unwrap();
        assert_ne!(revision(&a, &[]), revision(&b, &[]));
        assert_eq!(revision(&a, &[]), revision(&a, &[]));
        let t = hyperion_types::S3BackupTarget {
            name: "b2".into(),
            endpoint: "https://s3".into(),
            bucket: "bk".into(),
            region: "eu".into(),
            access_key_id: "AK".into(),
            secret_access_key: "SK".into(),
            age_recipient: None,
            retention_daily: 7,
        };
        assert_ne!(revision(&a, &[]), revision(&a, &[t]));
    }

    #[test]
    fn apply_replaces_synced_keys_and_keeps_node_local_ones() {
        let mut doc: DocumentMut = r#"
[acme]
contact_email = "old@example.com"
challenge_dir = "/srv/acme"
[fail2ban]
enabled = true
ssh_threshold = 99
"#
        .parse()
        .unwrap();
        let master = extract_sections(
            "[acme]\ncontact_email = \"new@example.com\"\n[fail2ban]\nenabled = true\n",
        )
        .unwrap();
        let out = apply_sections(&mut doc, &master, parse_ok).unwrap();
        assert_eq!(
            doc["acme"]["contact_email"].as_str(),
            Some("new@example.com")
        );
        assert_eq!(doc["acme"]["challenge_dir"].as_str(), Some("/srv/acme"));
        assert!(
            doc["fail2ban"].get("ssh_threshold").is_none(),
            "a per-node override the master lacks falls back to the default"
        );
        assert_eq!(
            out.changed,
            vec!["acme".to_string(), "fail2ban".to_string()]
        );

        // Second apply of the same payload changes nothing.
        let again = apply_sections(&mut doc, &master, parse_ok).unwrap();
        assert!(again.changed.is_empty());
    }

    #[test]
    fn cluster_trash_keys_sync_and_the_rest_of_cluster_stays_put() {
        let mut doc: DocumentMut = r#"
[cluster]
mode = "worker"
enforce_admin_2fa = false
trash_enabled = true
trash_retention_days = 3
"#
        .parse()
        .unwrap();
        let master = extract_sections(
            "[cluster]\nmode = \"master\"\nenforce_admin_2fa = true\ntrash_retention_days = 30\ntest_domain_template = \"{name}.preview.example.com\"\n",
        )
        .unwrap();
        let cluster = master.iter().find(|s| s.section == "cluster").unwrap();
        assert_eq!(
            cluster.fields.keys().collect::<Vec<_>>(),
            vec!["test_domain_template", "trash_retention_days"]
        );
        apply_sections(&mut doc, &master, parse_ok).unwrap();
        assert_eq!(doc["cluster"]["mode"].as_str(), Some("worker"));
        assert_eq!(doc["cluster"]["enforce_admin_2fa"].as_bool(), Some(false));
        assert_eq!(
            doc["cluster"]["trash_retention_days"].as_integer(),
            Some(30)
        );
        assert_eq!(
            doc["cluster"]["test_domain_template"].as_str(),
            Some("{name}.preview.example.com"),
            "a worker builds its own sites' preview aliases from it"
        );
        assert!(
            doc["cluster"].get("trash_enabled").is_none(),
            "the master has no trash switch, so the node falls back to the default too"
        );
    }

    #[test]
    fn apply_is_all_or_nothing_when_a_section_is_refused() {
        let mut doc: DocumentMut = "[acme]\ncontact_email = \"old@example.com\"\n"
            .parse()
            .unwrap();
        let master = extract_sections(
            "[acme]\ncontact_email = \"new@example.com\"\n[snapshots]\nkeep_days = 5\n",
        )
        .unwrap();
        let err = apply_sections(&mut doc, &master, |s, f| {
            if s == "snapshots" {
                Err("nope".into())
            } else {
                parse_ok(s, f)
            }
        })
        .unwrap_err();
        assert!(err.contains("[snapshots]"));
        assert_eq!(
            doc["acme"]["contact_email"].as_str(),
            Some("old@example.com")
        );
    }

    #[test]
    fn apply_skips_keys_this_node_does_not_know() {
        let mut doc = DocumentMut::new();
        let secs = vec![SyncedSection {
            section: "backup".into(),
            fields: [
                ("drop_local_after_offsite".to_string(), "true".to_string()),
                ("from_the_future".to_string(), "1".to_string()),
            ]
            .into(),
        }];
        let out = apply_sections(&mut doc, &secs, parse_ok).unwrap();
        assert_eq!(out.ignored, vec!["backup.from_the_future".to_string()]);
        assert_eq!(
            doc["backup"]["drop_local_after_offsite"].as_bool(),
            Some(true)
        );
        assert!(doc["backup"].get("from_the_future").is_none());
    }

    #[test]
    fn empty_master_section_does_not_create_an_empty_table() {
        let mut doc = DocumentMut::new();
        let secs = extract_sections("").unwrap();
        let out = apply_sections(&mut doc, &secs, parse_ok).unwrap();
        assert!(out.changed.is_empty());
        assert!(doc.as_table().is_empty());
    }

    #[test]
    fn state_file_is_0600_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(STATE_FILE);
        let st = NodeSyncState {
            revision: "abc".into(),
            applied_at: 7,
            s3_targets: vec![],
        };
        write_state(&p, &st).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(read_state(&p).unwrap().revision, "abc");
    }
}
