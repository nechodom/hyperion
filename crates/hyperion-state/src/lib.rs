//! SQLite-backed state for `hyperion-agent`.
//!
//! The pool is the single source of truth for hostings, users, DBs, and
//! certificates on the node. All public functions are async.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
// sqlx row tuples / multi-column query helpers are intentionally "complex" and
// "many-argument"; aliasing each adds noise without clarity.
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
#![forbid(unsafe_code)]

pub mod api_keys;
pub mod audit;
pub mod backup_targets;
pub mod backups;
pub mod bans;
pub mod capabilities;
pub mod certificates;
pub mod custom_roles;
pub mod databases;
pub mod db;
pub mod email_log;
pub mod hosting_kv;
pub mod hosting_quotas;
pub mod hostings;
pub mod import_tokens;
pub mod invites;
pub mod jobs;
pub mod limits;
pub mod metrics;
pub mod monitors;
pub mod nodejs;
pub mod nodes;
pub mod notifications;
pub mod oom_events;
pub mod packages;
pub mod profiles;
pub mod reports;
pub mod scheduler;
pub mod system_users;
pub mod web_sessions;
pub mod web_users;
pub mod wordpress;
pub mod wp_assets;

pub use db::{open, open_memory, StateError};

#[cfg(test)]
mod migration_immutability {
    /// Applied migrations are IMMUTABLE — sqlx checksums every applied
    /// migration at startup and refuses to run when one changed, which
    /// takes the whole agent down on every box that already ran it. Even a
    /// comment edit counts: the checksum is over bytes.
    ///
    /// This lock exists because exactly that happened: a comments-only
    /// rewrite of 060 shipped in a release, and the next update on a live
    /// box failed its migration dry-run with "migration 60 was previously
    /// applied but has been modified" — services stopped, panel down,
    /// until the original bytes were restored.
    ///
    /// To ADD a migration: create the new file and add its line to
    /// migrations.sha256 (sha256sum <file>). To CHANGE schema that an old
    /// migration created: write a NEW migration. Editing the lock line of
    /// an EXISTING migration is never correct and will be caught in
    /// review — that is the point of keeping the lock in the diff.
    #[test]
    fn applied_migrations_are_never_edited() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let lock_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations.sha256");
        let lock = std::fs::read_to_string(&lock_path).expect("migrations.sha256 missing");
        let mut locked = std::collections::BTreeMap::new();
        for line in lock.lines().filter(|l| !l.trim().is_empty()) {
            let (hash, name) = line
                .split_once("  ")
                .expect("lock line format: <sha256>  <file>");
            locked.insert(name.trim().to_string(), hash.trim().to_string());
        }
        let mut seen = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&dir).expect("read migrations dir") {
            let entry = entry.expect("dir entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".sql") {
                continue;
            }
            seen.insert(name.clone());
            let bytes = std::fs::read(entry.path()).expect("read migration");
            let actual = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(&bytes);
                hex::encode(h.finalize())
            };
            match locked.get(&name) {
                Some(expected) if *expected == actual => {}
                Some(_) => panic!(
                    "{name} was EDITED after being locked. An applied migration must never \
                     change — sqlx checksums it and every box that already ran it goes down \
                     on the next update. Revert the edit and put the change in a NEW migration."
                ),
                None => panic!(
                    "{name} is not in migrations.sha256 — add its line:\n  sha256sum {}",
                    entry.path().display()
                ),
            }
        }
        for name in locked.keys() {
            assert!(
                seen.contains(name),
                "{name} is locked but the file is gone — deleting an applied migration \
                 breaks every existing database the same way editing one does"
            );
        }
    }
}
