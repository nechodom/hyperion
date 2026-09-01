//! Does a certificate name cover a hostname?
//!
//! Lives here rather than in the certificate adapter because BOTH sides need
//! it and they sit on opposite sides of a dependency wall: the adapter uses it
//! to validate an uploaded certificate, and the panel uses it to tell the
//! operator which of a hosting's names the certificate on disk does not carry.
//! `hyperion-web` deliberately does not link `hyperion-adapters`.
//!
//! One implementation, because a second one would disagree at exactly the
//! wildcard cases that decide whether a browser accepts the site.

/// True when the certificate name `pattern` (possibly a `*.foo` wildcard)
/// matches the concrete hostname `host`.
///
/// A wildcard matches exactly ONE left-most label: `*.example.com` matches
/// `www.example.com` but neither `example.com` (the apex) nor
/// `a.b.example.com` (nested). Case-insensitive, and a trailing FQDN-root dot
/// — which a SAN may carry and a configured name will not — is ignored on
/// both sides.
pub fn name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) if !suffix.is_empty() => {
            // host must be exactly "<single-label>.<suffix>".
            match host.strip_suffix(suffix).and_then(|p| p.strip_suffix('.')) {
                Some(label) => !label.is_empty() && !label.contains('.'),
                None => false,
            }
        }
        _ => pattern == host,
    }
}

/// Which of `names` the certificate's `covered` list does NOT carry.
///
/// Empty `covered` yields an empty answer on purpose: an unreadable or absent
/// certificate is a different problem, already reported elsewhere, and
/// listing every name as uncovered would be a second alarm for one fact.
pub fn uncovered_names<'a>(
    covered: &[String],
    names: impl Iterator<Item = &'a str>,
) -> Vec<String> {
    if covered.is_empty() {
        return Vec::new();
    }
    names
        .filter(|n| !covered.iter().any(|san| name_matches(san, n)))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{name_matches, uncovered_names};

    #[test]
    fn an_exact_name_matches_case_and_root_dot_insensitively() {
        assert!(name_matches("example.cz", "example.cz"));
        assert!(name_matches("EXAMPLE.CZ", "example.cz"));
        assert!(name_matches("example.cz.", "example.cz"));
        assert!(name_matches("example.cz", "Example.CZ."));
        assert!(!name_matches("example.cz", "www.example.cz"));
        assert!(!name_matches("", "example.cz"));
        assert!(!name_matches("example.cz", ""));
    }

    /// The case the alias warning turns on: a wildcard covers exactly one
    /// label, so `*.example.cz` is not a reason to stay silent about the apex.
    #[test]
    fn a_wildcard_covers_one_label_only() {
        assert!(name_matches("*.example.cz", "www.example.cz"));
        assert!(name_matches("*.example.cz", "shop.example.cz"));
        assert!(!name_matches("*.example.cz", "example.cz"));
        assert!(!name_matches("*.example.cz", "a.b.example.cz"));
        assert!(!name_matches("*.", "www.example.cz"));
        assert!(!name_matches("*", "example.cz"));
    }

    /// The whole point: adding `www` to a certificate that only carries the
    /// apex must be reported, and nothing else must be.
    #[test]
    fn only_the_names_the_certificate_lacks_are_reported() {
        let covered = vec!["example.cz".to_string()];
        assert_eq!(
            uncovered_names(&covered, ["example.cz", "www.example.cz"].into_iter()),
            vec!["www.example.cz".to_string()]
        );
        assert!(uncovered_names(&covered, ["example.cz"].into_iter()).is_empty());
        // A wildcard certificate covers the alias without carrying it verbatim.
        let wild = vec!["example.cz".to_string(), "*.example.cz".to_string()];
        assert!(uncovered_names(&wild, ["example.cz", "www.example.cz"].into_iter()).is_empty());
    }

    /// No certificate on disk is a different problem, reported elsewhere.
    #[test]
    fn an_empty_covered_list_reports_nothing() {
        assert!(uncovered_names(&[], ["example.cz", "www.example.cz"].into_iter()).is_empty());
    }
}
