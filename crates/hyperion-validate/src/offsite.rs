//! The name a backup file carries on the off-site store.

use crate::Domain;

/// What a backup file's name says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsiteBackupName {
    pub domain: Domain,
    /// The unix time `backup_run` put in the name.
    pub stamp: i64,
    /// A database dump (`.sql`) rather than an archive.
    pub is_dump: bool,
}

/// Read `<domain>-<digits>.tar.gz|.tgz|.sql`, the only names a backup run
/// writes to the off-site store, or say it is not one of them.
///
/// Strict, because the answer decides whether a file may be offered for
/// deletion. The stamp is what follows the LAST hyphen, so
/// `a.cz-shop.cz-100.tar.gz` is `a.cz-shop.cz` and never `a.cz`. The domain
/// has to come back from [`Domain::parse`] unchanged, since that trims and
/// lowercases what a backup run would never have written, and its top-level
/// name has to be a real one: `a.cz-100-200.tar.gz` would otherwise pass as a
/// site under the top-level name `cz-100`.
pub fn parse_offsite_backup_name(name: &str) -> Option<OffsiteBackupName> {
    if name.len() > 255 {
        return None;
    }
    let (stem, is_dump) = if let Some(s) = name.strip_suffix(".tar.gz") {
        (s, false)
    } else if let Some(s) = name.strip_suffix(".tgz") {
        (s, false)
    } else {
        (name.strip_suffix(".sql")?, true)
    };
    let (raw_domain, digits) = stem.rsplit_once('-')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let stamp = digits.parse::<i64>().ok()?;
    let domain = Domain::parse(raw_domain).ok()?;
    if domain.as_str() != raw_domain {
        return None;
    }
    let tld = raw_domain.rsplit('.').next()?;
    if !(tld.starts_with("xn--") || tld.bytes().all(|b| b.is_ascii_alphabetic())) {
        return None;
    }
    Some(OffsiteBackupName {
        domain,
        stamp,
        is_dump,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain_of(name: &str) -> Option<String> {
        parse_offsite_backup_name(name).map(|p| p.domain.as_str().to_string())
    }

    #[test]
    fn reads_the_three_names_a_backup_run_writes() {
        for name in [
            "a.cz-100.tar.gz",
            "a.cz-100.tgz",
            "a.cz-100.sql",
            "www.a.cz-1762000000.tar.gz",
            "xn--bcher-kva.example-100.sql",
            "shop.xn--p1ai-100.tgz",
        ] {
            assert!(domain_of(name).is_some(), "{name}");
        }
        let p = parse_offsite_backup_name("a.cz-1762000000.sql").expect("parse");
        assert_eq!(p.domain.as_str(), "a.cz");
        assert_eq!(p.stamp, 1_762_000_000);
        assert!(p.is_dump);
        assert!(
            !parse_offsite_backup_name("a.cz-1.tar.gz")
                .expect("parse")
                .is_dump
        );
    }

    /// The whole point: the file belongs to the longest name, and it is never
    /// mistaken for a shorter one that happens to be its prefix.
    #[test]
    fn a_hyphen_in_the_domain_does_not_cut_it_short() {
        assert_eq!(
            domain_of("a.cz-shop.cz-100.tar.gz").as_deref(),
            Some("a.cz-shop.cz")
        );
        assert_eq!(
            domain_of("my-shop.cz-100.sql").as_deref(),
            Some("my-shop.cz")
        );
    }

    #[test]
    fn anything_a_backup_run_would_not_write_is_not_recognised() {
        for name in [
            "",
            "a.cz",
            "a.cz.tar.gz",
            "a.cz-.tar.gz",
            "-100.tar.gz",
            "a-100.tar.gz",     // one label is no domain
            "A.cz-100.tar.gz",  // never written in capitals
            "a.cz.-100.tar.gz", // parsing would quietly trim the dot
            " a.cz-100.tar.gz", // or the space
            "a.cz-100x.tar.gz", // not a stamp
            "a.cz-+100.tar.gz", // parses as a number, is not all digits
            "a.cz-100.zip",
            "a.cz-100.tar",
            "a.cz-100.manifest.json",
            "a.cz-100.sql.tar.gz",
            "a.cz-100-200.tar.gz", // its top-level name would be `cz-100`
            "a.123-100.tar.gz",
            "a..cz-100.tar.gz",
            "../a.cz-100.tar.gz",
            "x/a.cz-100.tar.gz",
            "a.cz-99999999999999999999.tar.gz", // overflows a stamp
        ] {
            assert!(domain_of(name).is_none(), "{name:?}");
        }
        let long = format!("{}.cz-100.tar.gz", vec!["a".repeat(63); 4].join("."));
        assert!(domain_of(&long).is_none(), "longer than a file name may be");
    }
}
