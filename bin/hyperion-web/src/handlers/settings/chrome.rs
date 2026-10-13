//! The frame every Settings page shares.
//!
//! Settings used to be one template with ten tabs and ~8 000 words, loaded in
//! one request that probed DNS, SMTP ports and every node before showing the
//! first tab. It is now an overview plus one page per section, each loading
//! only what it shows. This module holds what they have in common:
//!
//!   * [`SECTIONS`] — the pages, in sub-navigation order;
//!   * [`CARDS`] — every card anchor and the page that holds it. Every save
//!     redirect, every deep link from another page and the overview's
//!     old-bookmark map go through it, and `template_lint.rs` checks each
//!     entry against the section's template;
//!   * [`Chrome`] — the per-request facts the layout renders from: may this
//!     user write agent.toml, are there worker nodes, which flash to show.

use crate::auth::AuthCtx;
use crate::state::SharedState;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

/// One Settings page.
pub struct Section {
    /// URL segment: `/settings/<slug>`.
    pub slug: &'static str,
    /// Sub-navigation label and the page's `<h1>`.
    pub title: &'static str,
    /// Sub-navigation group heading.
    pub group: &'static str,
    /// One sentence under the `<h1>`: the question this page answers.
    pub lead: &'static str,
    /// Only shown when worker nodes are enrolled.
    pub cluster_only: bool,
}

/// Every Settings page, in sub-navigation order. Grouped by the question the
/// operator is asking: set the box up, talk to people, keep data safe, keep
/// people out, run more than one box.
pub const SECTIONS: &[Section] = &[
    Section {
        slug: "panel",
        title: "Panel",
        group: "Basics",
        lead: "Where the panel is reached and whether Hyperion updates itself.",
        cluster_only: false,
    },
    Section {
        slug: "https",
        title: "HTTPS & previews",
        group: "Basics",
        lead: "The Let's Encrypt contact, and preview addresses that work before a site's DNS points here.",
        cluster_only: false,
    },
    Section {
        slug: "mail",
        title: "Mail",
        group: "Basics",
        lead: "How each node sends email: its relay and sender address.",
        cluster_only: false,
    },
    Section {
        slug: "alerts",
        title: "Alerts",
        group: "Communication",
        lead: "Who hears about problems, where, in which language and in what words.",
        cluster_only: false,
    },
    Section {
        slug: "letters",
        title: "Customer letters",
        group: "Communication",
        lead: "What site owners receive from you: the care report and the expiry warning.",
        cluster_only: false,
    },
    Section {
        slug: "backups",
        title: "Backups",
        group: "Data",
        lead: "What is kept, where off-site copies go, how long everything stays.",
        cluster_only: false,
    },
    Section {
        slug: "access",
        title: "Access",
        group: "Security",
        lead: "Who can sign in to the panel, and how long their actions are on record.",
        cluster_only: false,
    },
    Section {
        slug: "bans",
        title: "Brute-force & GeoIP",
        group: "Security",
        lead: "When repeated failed logins earn an address a firewall ban, and the country database.",
        cluster_only: false,
    },
    Section {
        slug: "cluster",
        title: "Cluster",
        group: "Cluster",
        lead: "Where new sites go, which nodes are for testing, and how the master talks to its nodes.",
        cluster_only: true,
    },
];

/// Every card anchor on the Settings pages, and the page that holds it.
///
/// A card is the unit a save returns to and a link points at, so its id is
/// part of the panel's address space: other pages, handlers, the CLI docs
/// and operators' bookmarks all name them. Rename one only together with
/// the overview's old-bookmark map ([`legacy_targets`]).
pub const CARDS: &[(&str, &str)] = &[
    ("panel-domain", "panel"),
    ("updates", "panel"),
    ("acme", "https"),
    ("preview-address", "https"),
    ("preview-wildcard", "https"),
    ("smtp-relay", "mail"),
    ("mail-test", "mail"),
    ("mail-health", "mail"),
    ("slack", "alerts"),
    ("alert-recipients", "alerts"),
    ("alert-language", "alerts"),
    ("alert-templates", "alerts"),
    ("letter-language", "letters"),
    ("customer-letters", "letters"),
    ("letter-wording", "letters"),
    ("email-branding", "letters"),
    ("performance", "letters"),
    ("protection-mode", "backups"),
    ("offsite-targets", "backups"),
    ("offsite-ftp", "backups"),
    ("offsite-s3", "backups"),
    ("local-copies", "backups"),
    ("backup-retention", "backups"),
    ("snapshot-retention", "backups"),
    ("trash", "backups"),
    ("offsite-backfill", "backups"),
    ("sign-in", "access"),
    ("users-roles", "access"),
    ("audit-retention", "access"),
    ("bruteforce-scanner", "bans"),
    ("geoip", "bans"),
    ("placement", "cluster"),
    ("test-nodes", "cluster"),
    ("hardening", "cluster"),
    ("settings-sync", "cluster"),
];

/// Ids that USED to resolve on the one-page Settings (tab ids, retired cards,
/// cards that moved to another page), and where each one lives now. The
/// overview turns a `/settings#<id>` bookmark into a jump to the new place.
/// Card ids in [`CARDS`] are added to the map automatically.
const LEGACY: &[(&str, &str)] = &[
    // The ten old tabs.
    ("general", "/settings/panel"),
    ("tls", "/settings/https"),
    ("mail", "/settings/mail"),
    ("notifications", "/settings/alerts"),
    ("letters", "/settings/letters"),
    ("backups", "/settings/backups"),
    ("access", "/settings/access"),
    ("bruteforce", "/settings/bans"),
    ("cluster", "/settings/cluster"),
    ("raw", "/install/node-settings?node_id=local#raw-toml"),
    // Tab ids retired before that.
    ("system", "/settings/panel#updates"),
    ("testnodes", "/settings/https#preview-address"),
    ("retention", "/settings/backups#trash"),
    // Cards that left Settings or were folded into another.
    ("https-howto", "/settings/https"),
    ("mail-howto", "/settings/mail"),
    ("local-mta", "/services#mail-delivery"),
    ("default_to", "/settings/alerts#alert-recipients"),
    ("multinode-tips", "/settings/cluster"),
    ("api", "/admin/api-keys"),
    ("api-keys", "/admin/api-keys"),
    ("raw-toml", "/install/node-settings?node_id=local#raw-toml"),
];

/// The page `slug` names, if it is one.
pub fn section(slug: &str) -> Option<&'static Section> {
    SECTIONS.iter().find(|s| s.slug == slug)
}

/// The page holding card `card`, if it is a card.
pub fn card_section(card: &str) -> Option<&'static str> {
    CARDS.iter().find(|(c, _)| *c == card).map(|(_, s)| *s)
}

/// Where card `card` is: `/settings/<page>?<query>#<card>`. The query (no
/// leading `?`) goes before the fragment, which must come last. An unknown
/// card lands on the overview rather than on a page that does not exist.
pub fn card_url(card: &str, query: &str) -> String {
    let q = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    match card_section(card) {
        Some(s) => format!("/settings/{s}{q}#{card}"),
        None => format!("/settings{q}"),
    }
}

/// A redirect to card `card` carrying a success flash.
pub fn back_with_flash(card: &str, msg: &str) -> Response {
    Redirect::to(&card_url(card, &format!("flash={}", urlencode(msg)))).into_response()
}

/// A redirect to card `card` carrying an error flash.
pub fn back_with_error(card: &str, msg: &str) -> Response {
    Redirect::to(&card_url(card, &format!("flash_error={}", urlencode(msg)))).into_response()
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Every old `/settings#<id>` and where it goes now, for the overview's
/// bookmark redirect: the legacy ids above plus every live card.
pub fn legacy_targets() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = LEGACY
        .iter()
        .map(|(id, to)| (id.to_string(), to.to_string()))
        .collect();
    out.extend(
        CARDS
            .iter()
            .map(|(card, _)| (card.to_string(), card_url(card, ""))),
    );
    out
}

/// One heading of the sub-navigation and the pages under it.
pub struct NavGroup {
    pub label: &'static str,
    pub items: Vec<&'static Section>,
}

/// What every Settings page renders its frame from.
pub struct Chrome {
    /// The page's slug, or `"overview"`.
    pub section: &'static str,
    pub title: &'static str,
    pub lead: &'static str,
    /// May this user write agent.toml? Only an Owner can; everybody else
    /// with Settings access sees the values with the forms disabled, instead
    /// of filling one in and being refused after pressing Save.
    pub can_edit: bool,
    /// Any worker node enrolled. Drives the scope tags ("All nodes", "Each
    /// node", "Master only") — meaningless on one server — and the Cluster
    /// page's place in the sub-navigation.
    pub has_nodes: bool,
    pub flash: Option<String>,
    pub flash_error: Option<String>,
}

impl Chrome {
    pub fn nav(&self) -> Vec<NavGroup> {
        let mut out: Vec<NavGroup> = Vec::new();
        for s in SECTIONS
            .iter()
            .filter(|s| self.has_nodes || !s.cluster_only)
        {
            match out.last_mut() {
                Some(g) if g.label == s.group => g.items.push(s),
                _ => out.push(NavGroup {
                    label: s.group,
                    items: vec![s],
                }),
            }
        }
        out
    }

    /// ` disabled` for a `<fieldset>` of owner-only forms when this user
    /// cannot save them; empty otherwise.
    pub fn ro(&self) -> &'static str {
        if self.can_edit {
            ""
        } else {
            " disabled"
        }
    }
}

/// The query string every Settings page accepts.
#[derive(Deserialize, Default)]
pub struct PageQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_error: Option<String>,
    /// Mail: the node whose `[email]` the page edits ("" / "local" = master).
    #[serde(default)]
    pub node: String,
    /// Backups: set by the redirect after saving the FTP target, so the page
    /// re-runs the connection check once the agent is back.
    #[serde(default)]
    pub probe_backup_remote: Option<String>,
    /// Overview: a pre-upgrade `/settings?mail_node=X#mail` bookmark.
    #[serde(default)]
    pub mail_node: String,
}

/// Build the frame for page `slug` (or `"overview"`), plus the enrolled
/// worker nodes it was derived from, which most pages need anyway.
pub async fn chrome(
    state: &SharedState,
    ctx: &AuthCtx,
    slug: &'static str,
    q: &PageQuery,
) -> (Chrome, Vec<hyperion_types::NodeSummary>) {
    let nodes = enrolled_nodes(state).await;
    let (title, lead) = match section(slug) {
        Some(s) => (s.title, s.lead),
        None => (
            "Settings",
            "Everything that configures this install, by the question it answers.",
        ),
    };
    let chrome = Chrome {
        section: slug,
        title,
        lead,
        can_edit: ctx.is_super_admin(),
        has_nodes: !nodes.is_empty(),
        flash: q.flash.clone().filter(|s| !s.trim().is_empty()),
        flash_error: q.flash_error.clone().filter(|s| !s.trim().is_empty()),
    };
    (chrome, nodes)
}

/// Enrolled worker nodes, best effort: a failed list reads as "no workers",
/// which only hides the cluster parts of the pages.
pub async fn enrolled_nodes(state: &SharedState) -> Vec<hyperion_types::NodeSummary> {
    crate::dispatcher::cached_nodes(state)
        .await
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_card_names_a_section() {
        for (card, sec) in CARDS {
            assert!(section(sec).is_some(), "card {card} → unknown page {sec}");
        }
    }

    #[test]
    fn card_ids_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for (card, _) in CARDS {
            assert!(seen.insert(*card), "card {card} listed twice");
        }
    }

    #[test]
    fn legacy_ids_do_not_shadow_live_cards() {
        for (id, _) in LEGACY {
            assert!(
                card_section(id).is_none(),
                "{id} is both a live card and a legacy alias — the alias would hide it"
            );
        }
    }

    #[test]
    fn card_url_puts_the_query_before_the_fragment() {
        assert_eq!(card_url("acme", ""), "/settings/https#acme");
        assert_eq!(card_url("acme", "flash=x"), "/settings/https?flash=x#acme");
        assert_eq!(card_url("no-such-card", "flash=x"), "/settings?flash=x");
    }

    #[test]
    fn cluster_page_is_hidden_without_workers() {
        let c = |has_nodes| Chrome {
            section: "overview",
            title: "",
            lead: "",
            can_edit: true,
            has_nodes,
            flash: None,
            flash_error: None,
        };
        let slugs = |ch: Chrome| -> Vec<&str> {
            ch.nav()
                .into_iter()
                .flat_map(|g| g.items.into_iter().map(|s| s.slug))
                .collect()
        };
        assert!(!slugs(c(false)).contains(&"cluster"));
        assert!(slugs(c(true)).contains(&"cluster"));
    }
}
