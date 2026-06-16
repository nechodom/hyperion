//! Read + write per-section updates to `/etc/hyperion/agent.toml`
//! while preserving comments, blank lines, and field ordering.
//!
//! Uses `toml_edit` (vs `toml::ser`) so the operator's hand-edited
//! file isn't reformatted out from under them. Every write goes
//! through an atomic rename + creates a `.bak` of the previous
//! contents.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;
use toml_edit::{value, DocumentMut, Item};

#[derive(Debug, Error)]
pub enum ConfigPersistError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse: {0}")]
    Parse(#[from] toml_edit::TomlError),
    #[error("section `{0}` is not a table in agent.toml")]
    NotATable(String),
}

/// Load + parse + return the editable document.
pub fn load(path: &Path) -> Result<DocumentMut, ConfigPersistError> {
    let raw = std::fs::read_to_string(path)?;
    Ok(raw.parse::<DocumentMut>()?)
}

/// Atomic write back to `path`. Creates a sibling `.bak` of the
/// previous contents (best-effort).
pub fn save(path: &Path, doc: &DocumentMut) -> Result<(), ConfigPersistError> {
    let serialised = doc.to_string();
    if path.exists() {
        let bak = path.with_extension("toml.bak");
        if let Err(e) = std::fs::copy(path, &bak) {
            // The backup is a convenience, not a correctness requirement —
            // continue, but don't let the failure vanish.
            tracing::warn!(error = %e, ?bak, "could not write agent.toml backup (continuing)");
        }
    }
    let tmp = sibling_tmp(path);
    // Create the temp 0600 from the start: agent.toml carries the master-RPC
    // key, so it must never be even momentarily world-readable (which a
    // write-then-chmod sequence allows under the default umask).
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(serialised.as_bytes())?;
    f.sync_all()?;
    drop(f);
    // Belt-and-suspenders if the tmp pre-existed with looser perms. This is a
    // HARD error: refusing to publish a secret at 0644 beats best-effort.
    if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[allow(dead_code)]
pub fn set_string(
    path: &Path,
    section: &str,
    field: &str,
    new_value: &str,
) -> Result<(), ConfigPersistError> {
    let mut doc = load(path)?;
    ensure_table(&mut doc, section)?;
    doc[section][field] = value(new_value);
    save(path, &doc)
}

#[allow(dead_code)]
pub fn set_int(
    path: &Path,
    section: &str,
    field: &str,
    new_value: i64,
) -> Result<(), ConfigPersistError> {
    let mut doc = load(path)?;
    ensure_table(&mut doc, section)?;
    doc[section][field] = value(new_value);
    save(path, &doc)
}

#[allow(dead_code)]
pub fn set_bool(
    path: &Path,
    section: &str,
    field: &str,
    new_value: bool,
) -> Result<(), ConfigPersistError> {
    let mut doc = load(path)?;
    ensure_table(&mut doc, section)?;
    doc[section][field] = value(new_value);
    save(path, &doc)
}

/// Set multiple fields in one section atomically (single file write).
pub fn set_many(
    path: &Path,
    section: &str,
    fields: &[(&str, FieldValue)],
) -> Result<(), ConfigPersistError> {
    let mut doc = load(path)?;
    ensure_table(&mut doc, section)?;
    for (k, v) in fields {
        let item = match v {
            FieldValue::Str(s) => value(s.as_str()),
            FieldValue::Int(n) => value(*n),
            FieldValue::Bool(b) => value(*b),
        };
        doc[section][k] = item;
    }
    save(path, &doc)
}

#[derive(Debug, Clone)]
pub enum FieldValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

fn ensure_table(doc: &mut DocumentMut, section: &str) -> Result<(), ConfigPersistError> {
    match doc.as_table().get(section) {
        Some(Item::Table(_)) => Ok(()),
        Some(_) => Err(ConfigPersistError::NotATable(section.to_string())),
        None => {
            let mut t = toml_edit::Table::new();
            t.set_implicit(false);
            doc[section] = toml_edit::Item::Table(t);
            Ok(())
        }
    }
}

fn sibling_tmp(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".new");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_sample(d: &Path) -> PathBuf {
        let p = d.join("agent.toml");
        let sample = r#"# Hyperion agent config
[agent]
socket_path = "/run/hyperion.sock"
state_db = "/var/lib/hyperion/state.db"

[acme]
contact_email = "old@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"

[email]
enabled = false
smtp_host = "smtp.example.com"
smtp_port = 587
"#;
        std::fs::write(&p, sample).expect("write");
        p
    }

    #[test]
    fn set_string_preserves_comments_and_layout() {
        let d = tempfile::tempdir().expect("tmp");
        let p = write_sample(d.path());
        set_string(&p, "acme", "contact_email", "ops@cz.example").expect("set");
        let after = std::fs::read_to_string(&p).expect("read");
        assert!(after.starts_with("# Hyperion agent config"));
        assert!(after.contains(r#"contact_email = "ops@cz.example""#));
        assert!(after.contains("directory_url"));
        assert!(d.path().join("agent.toml.bak").exists());
    }

    #[test]
    fn set_int_and_bool_write_correct_types() {
        let d = tempfile::tempdir().expect("tmp");
        let p = write_sample(d.path());
        set_int(&p, "email", "smtp_port", 465).expect("port");
        set_bool(&p, "email", "enabled", true).expect("enabled");
        let after = std::fs::read_to_string(&p).expect("read");
        assert!(after.contains("smtp_port = 465"));
        assert!(after.contains("enabled = true"));
    }

    #[test]
    fn set_many_writes_atomically() {
        let d = tempfile::tempdir().expect("tmp");
        let p = write_sample(d.path());
        set_many(
            &p,
            "email",
            &[
                ("enabled", FieldValue::Bool(true)),
                ("smtp_host", FieldValue::Str("mail.cz".into())),
                ("smtp_port", FieldValue::Int(587)),
            ],
        )
        .expect("set many");
        let after = std::fs::read_to_string(&p).expect("read");
        assert!(after.contains("enabled = true"));
        assert!(after.contains(r#"smtp_host = "mail.cz""#));
        assert!(after.contains("smtp_port = 587"));
    }

    #[test]
    fn creates_missing_section() {
        let d = tempfile::tempdir().expect("tmp");
        let p = write_sample(d.path());
        set_string(&p, "slack", "default_webhook", "https://hooks.slack.com/aaa")
            .expect("set new section");
        let after = std::fs::read_to_string(&p).expect("read");
        assert!(after.contains("[slack]"));
        assert!(after.contains(r#"default_webhook = "https://hooks.slack.com/aaa""#));
    }

    #[test]
    fn empty_file_seeds_section() {
        let d = tempfile::tempdir().expect("tmp");
        let p = d.path().join("agent.toml");
        std::fs::write(&p, "").expect("write empty");
        set_string(&p, "acme", "contact_email", "x@y.cz").expect("seed");
        let after = std::fs::read_to_string(&p).expect("read");
        assert!(after.contains("[acme]"));
        assert!(after.contains(r#"contact_email = "x@y.cz""#));
    }
}
