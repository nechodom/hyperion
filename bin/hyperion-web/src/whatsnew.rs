//! What's new: the short list of added features behind the icon next to
//! the notification bell.
//!
//! A user-visible feature adds one [`Entry`] at the END of [`ENTRIES`], in
//! the same pull request. Ids rise and are never reused: a browser
//! remembers the highest id it has shown, so a reused or lowered id would
//! never be announced.

use hyperion_state::capabilities::Capability;

pub struct Entry {
    pub id: u32,
    /// Day the feature was merged, `YYYY-MM-DD`.
    pub date: &'static str,
    pub title: &'static str,
    /// One or two plain sentences. No markup.
    pub body: &'static str,
    /// Panel path the reader is sent to.
    pub link: &'static str,
    pub link_label: &'static str,
    /// Capability the link needs. An entry is left out of the feed of a
    /// session that lacks it, so nobody is sent to a 403.
    pub needs: Option<Capability>,
    /// The linked page covers every site (the scanner, Docker), so it also
    /// refuses a session scoped to some hostings only.
    pub all_sites: bool,
}

/// How many entries the panel shows.
pub const FEED_LIMIT: usize = 10;

/// Oldest first. Add new entries at the end.
pub const ENTRIES: &[Entry] = &[
    Entry {
        id: 1,
        date: "2026-11-05",
        title: "Site scanner",
        body: "Hyperion now scans site files itself, without wp-cli or a per-site ClamAV. \
               It watches for new or changed PHP and flags what looks like malware.",
        link: "/antivirus",
        link_label: "Open the scanner",
        needs: Some(Capability::SecurityManage),
        all_sites: true,
    },
    Entry {
        id: 2,
        date: "2026-11-11",
        title: "Docker tab on reverse-proxy sites",
        body: "A reverse-proxy site has a Docker tab on its page with the containers behind it. \
               The Docker page lists every stack.",
        link: "/docker",
        link_label: "Open Docker",
        needs: Some(Capability::DockerView),
        all_sites: true,
    },
    Entry {
        id: 3,
        date: "2026-11-12",
        title: "Contact form guard",
        body: "Refuses Elementor Pro form submissions nobody can act on: empty, repeated \
               or sent in bulk. Switch it on per site, on the WordPress tab.",
        link: "/hostings",
        link_label: "Pick a site",
        needs: Some(Capability::WpManage),
        all_sites: false,
    },
    Entry {
        id: 4,
        date: "2026-11-17",
        title: "Contact form guard can ask a sum",
        body: "An optional \"What is 3 + 4?\" field on every Elementor Pro form of a site. \
               It is a second switch on the Contact form guard card, on the WordPress tab.",
        link: "/hostings",
        link_label: "Pick a site",
        needs: Some(Capability::WpManage),
        all_sites: false,
    },
    Entry {
        id: 5,
        date: "2026-11-18",
        title: "File manager rework",
        body: "The Files tab of a site was rebuilt: it looks like the rest of the panel \
               and keeps what you save.",
        link: "/hostings",
        link_label: "Pick a site",
        needs: Some(Capability::HostingFiles),
        all_sites: false,
    },
];

/// The entries a session may see: newest first, at most [`FEED_LIMIT`],
/// without those whose link it could not open.
pub fn visible(
    entries: &'static [Entry],
    scope_all: bool,
    can: impl Fn(Capability) -> bool,
) -> Vec<&'static Entry> {
    entries
        .iter()
        .rev()
        .filter(|e| (scope_all || !e.all_sites) && e.needs.map_or(true, &can))
        .take(FEED_LIMIT)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_rise_and_dates_do_not_go_back() {
        for w in ENTRIES.windows(2) {
            assert!(w[0].id < w[1].id, "id {} not above {}", w[1].id, w[0].id);
            assert!(
                w[0].date <= w[1].date,
                "entry {} is dated before {}",
                w[1].id,
                w[0].id
            );
        }
    }

    #[test]
    fn every_entry_is_complete() {
        assert!(!ENTRIES.is_empty());
        for e in ENTRIES {
            assert!(
                e.link.starts_with('/') && !e.link.starts_with("//"),
                "entry {} link",
                e.id
            );
            assert!(!e.title.is_empty() && !e.body.is_empty() && !e.link_label.is_empty());
            assert_eq!(e.date.len(), 10, "entry {} date is YYYY-MM-DD", e.id);
            assert!(
                e.body.len() <= 240,
                "entry {} body is one or two sentences",
                e.id
            );
        }
    }

    const fn sample(id: u32, needs: Option<Capability>) -> Entry {
        sample_scoped(id, needs, false)
    }

    const fn sample_scoped(id: u32, needs: Option<Capability>, all_sites: bool) -> Entry {
        Entry {
            id,
            date: "2026-01-01",
            title: "t",
            body: "b",
            link: "/x",
            link_label: "l",
            needs,
            all_sites,
        }
    }

    const SCOPED: &[Entry] = &[sample(1, None), sample_scoped(2, None, true)];

    #[test]
    fn visible_drops_all_site_pages_for_a_session_scoped_to_some_sites() {
        assert_eq!(ids(visible(SCOPED, false, |_| true)), vec![1]);
        assert_eq!(ids(visible(SCOPED, true, |_| true)), vec![2, 1]);
    }

    const SAMPLE: &[Entry] = &[
        sample(1, None),
        sample(2, Some(Capability::DockerView)),
        sample(3, None),
    ];

    const THIRTEEN: &[Entry] = &[
        sample(1, None),
        sample(2, None),
        sample(3, None),
        sample(4, None),
        sample(5, None),
        sample(6, None),
        sample(7, None),
        sample(8, None),
        sample(9, None),
        sample(10, None),
        sample(11, None),
        sample(12, None),
        sample(13, Some(Capability::DockerView)),
    ];

    fn ids(v: Vec<&'static Entry>) -> Vec<u32> {
        v.iter().map(|e| e.id).collect()
    }

    #[test]
    fn visible_is_newest_first_and_drops_what_the_session_cannot_open() {
        assert_eq!(ids(visible(SAMPLE, true, |_| false)), vec![3, 1]);
        assert_eq!(ids(visible(SAMPLE, true, |_| true)), vec![3, 2, 1]);
    }

    #[test]
    fn visible_stops_at_the_limit_after_filtering() {
        assert_eq!(
            ids(visible(THIRTEEN, true, |_| false)),
            (3..=12).rev().collect::<Vec<u32>>()
        );
    }
}
