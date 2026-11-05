//! Askama template filters.
//!
//! Askama resolves `{{ x|foo }}` against a module named `filters` that is in
//! scope where the template struct is defined, so `use crate::filters;` next
//! to a `#[derive(Template)]` makes everything here available to it.
//!
//! These exist because raw unix timestamps kept reaching the screen. A cell
//! reading `1794055205` is not a date to anyone — it is the kind of thing
//! that is obvious to whoever wrote the query and useless to whoever reads
//! the page.

/// A unix timestamp as `YYYY-MM-DD` (UTC).
///
/// UTC rather than local time on purpose: the agent, the database and
/// Let's Encrypt all speak UTC, so rendering local time here would make the
/// panel disagree with `openssl x509 -dates` and with its own logs for
/// anyone east or west of Greenwich — for a value whose precision only
/// matters to the day.
pub fn date(ts: &i64) -> askama::Result<String> {
    Ok(chrono::DateTime::from_timestamp(*ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "—".to_string()))
}

/// A unix timestamp as `YYYY-MM-DD HH:MM` (UTC), for values where the time
/// of day carries information (an audit entry, a last-checked stamp).
pub fn datetime(ts: &i64) -> askama::Result<String> {
    Ok(chrono::DateTime::from_timestamp(*ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "—".to_string()))
}

/// Text a tenant chose (a file name, a snippet of their code) made safe to read.
/// Askama still escapes the result for HTML; this is for what escaping leaves:
/// terminal escapes, line breaks that split a row, and the right-to-left marks
/// that make a name ending in U+202E then `gpj.php` read as `php.jpg`. Each
/// becomes U+FFFD.
pub fn tenant_text<T: std::fmt::Display>(s: T) -> askama::Result<String> {
    Ok(s.to_string()
        .chars()
        .map(|c| {
            let bidi = matches!(
                c,
                '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            );
            if c.is_control() || bidi {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_text_replaces_what_escaping_leaves() {
        assert_eq!(tenant_text("a/b.php").unwrap(), "a/b.php");
        assert_eq!(
            tenant_text("a\n\u{1b}[0m\u{202e}b").unwrap(),
            "a\u{fffd}\u{fffd}[0m\u{fffd}b"
        );
        // Not HTML escaping: that is askama's, applied after.
        assert_eq!(tenant_text("<b>").unwrap(), "<b>");
    }

    #[test]
    fn formats_a_known_timestamp() {
        // 2026-11-07T12:40:05Z — the shape the certs table renders.
        assert_eq!(date(&1_794_055_205).unwrap(), "2026-11-07");
        assert_eq!(datetime(&1_794_055_205).unwrap(), "2026-11-07 12:40");
    }

    /// Out-of-range input renders an em dash rather than panicking or
    /// printing something that looks like a real date.
    #[test]
    fn out_of_range_is_a_dash() {
        assert_eq!(date(&i64::MAX).unwrap(), "—");
    }
}
