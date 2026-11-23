//! What the content monitor found in a site's database and on its pages.
//!
//! The file scanner compares files. This is the other half: what the site
//! *says*. Hidden links written into a post, a script tag in a widget, a host
//! shown only to search engines. None of it changes a file, so none of it is
//! visible to a checksum.
//!
//! Both layers (database rows, fetched pages) reduce what they read to items.
//! An item's key leaves out where it was seen: the same spam host in 500 posts
//! is one item with a count, and a video host accepted once is accepted for
//! the site.

use serde::{Deserialize, Serialize};

/// Places listed per item. The count says how many there were.
pub const MAX_PLACES: usize = 20;
/// Characters of markup kept per item, for a person to recognise it by.
pub const MAX_SNIPPET: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    /// An external link inside something an inline style hides.
    HiddenLink,
    /// A script or handler that matched a rule.
    InlineScript,
    /// A host served to a crawler's user agent and to nobody else.
    Cloaked,
    /// An external `<script src>`.
    ScriptHost,
    /// An external `<iframe>`, `<object>` or `<embed>`.
    FrameHost,
    /// A meta refresh or canonical pointing at another host.
    Redirect,
    /// A visible outbound link on a fetched page. Inventory, never an alert.
    LinkHost,
    /// Ten or more new link hosts in one sweep, as one thing to look at.
    LinkBurst,
}

impl ContentKind {
    /// Findings are broken-now; the rest wait for a person to say they're expected.
    pub fn is_finding(self) -> bool {
        matches!(
            self,
            ContentKind::HiddenLink | ContentKind::InlineScript | ContentKind::Cloaked
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ContentKind::HiddenLink => "hidden_link",
            ContentKind::InlineScript => "inline_script",
            ContentKind::Cloaked => "cloaked",
            ContentKind::ScriptHost => "script_host",
            ContentKind::FrameHost => "frame_host",
            ContentKind::Redirect => "redirect",
            ContentKind::LinkHost => "link_host",
            ContentKind::LinkBurst => "link_burst",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            ContentKind::HiddenLink,
            ContentKind::InlineScript,
            ContentKind::Cloaked,
            ContentKind::ScriptHost,
            ContentKind::FrameHost,
            ContentKind::Redirect,
            ContentKind::LinkHost,
            ContentKind::LinkBurst,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
    }

    /// The kind in the words the card uses.
    pub fn label(self) -> &'static str {
        match self {
            ContentKind::HiddenLink => "Hidden link",
            ContentKind::InlineScript => "Suspicious script",
            ContentKind::Cloaked => "Shown only to search engines",
            ContentKind::ScriptHost => "Script loaded from",
            ContentKind::FrameHost => "Frame or embed from",
            ContentKind::Redirect => "Redirect or canonical to",
            ContentKind::LinkHost => "Link to",
            ContentKind::LinkBurst => "New outbound link domains",
        }
    }
}

/// One thing the monitor wants a person to see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentItem {
    pub kind: ContentKind,
    /// A host, or `rule-id:hash` for a script that matched a rule.
    pub key: String,
    /// How many places it was seen in this sweep.
    #[serde(default)]
    pub count: u32,
    /// `posts:123`, `options:widget_text`, a page URL. At most [`MAX_PLACES`].
    #[serde(default)]
    pub places: Vec<String>,
    /// The markup, cut to [`MAX_SNIPPET`]. Tenant text: escape it wherever shown.
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub first_seen: i64,
    /// Was there when watching began, so nobody can say when it arrived.
    #[serde(default)]
    pub at_first_scan: bool,
    /// Someone has been told. What the pilot found and nobody heard about still
    /// has this unset when alerts go live.
    #[serde(default)]
    pub notified: bool,
    /// Seen in database rows.
    #[serde(default)]
    pub in_db: bool,
    /// Seen on a fetched page.
    #[serde(default)]
    pub on_page: bool,
}

/// How one layer's read went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "note", rename_all = "snake_case")]
pub enum ContentLayer {
    /// Nothing to read here: no WordPress database, or the site isn't served.
    #[default]
    NotApplicable,
    Complete,
    /// Read in part; the note says which part wasn't.
    Partial(String),
    /// Couldn't be read; the note says why.
    Failed(String),
}

impl ContentLayer {
    pub fn is_complete(&self) -> bool {
        matches!(self, ContentLayer::Complete)
    }

    pub fn ran(&self) -> bool {
        matches!(self, ContentLayer::Complete | ContentLayer::Partial(_))
    }

    pub fn note(&self) -> Option<&str> {
        match self {
            ContentLayer::Partial(n) | ContentLayer::Failed(n) => Some(n),
            _ => None,
        }
    }
}

/// The stored result of the last content scan of one site.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentScanResult {
    #[serde(default)]
    pub scanned_at: i64,
    /// When the baseline began. Nothing before it can be judged.
    #[serde(default)]
    pub watching_since: i64,
    #[serde(default)]
    pub rule_pack: u32,
    /// The node's alerts for this are off: shown here, told to no one.
    #[serde(default)]
    pub report_only: bool,
    #[serde(default)]
    pub db: ContentLayer,
    #[serde(default)]
    pub pages: ContentLayer,
    #[serde(default)]
    pub pages_fetched: u32,
    /// Why the crawler's view couldn't be compared, when it couldn't.
    #[serde(default)]
    pub crawler_note: Option<String>,
    #[serde(default)]
    pub findings: Vec<ContentItem>,
    #[serde(default)]
    pub review: Vec<ContentItem>,
    /// Outbound link hosts known for the site. A number, not a list.
    #[serde(default)]
    pub link_hosts: u32,
    /// Script and frame hosts the baseline holds.
    #[serde(default)]
    pub known_hosts: u32,
    /// Items there was no room to list.
    #[serde(default)]
    pub more: u32,
}

impl ContentScanResult {
    /// A layer that should have run didn't, or ran in part.
    pub fn is_partial(&self) -> bool {
        let short =
            |l: &ContentLayer| matches!(l, ContentLayer::Partial(_) | ContentLayer::Failed(_));
        short(&self.db) || short(&self.pages)
    }

    /// Nothing to show and everything read.
    pub fn nothing_new(&self) -> bool {
        self.findings.is_empty() && self.review.is_empty() && !self.is_partial()
    }

    pub fn item(&self, kind: ContentKind, key: &str) -> Option<&ContentItem> {
        self.findings
            .iter()
            .chain(&self.review)
            .find(|i| i.kind == kind && i.key == key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip_by_name() {
        for k in [
            ContentKind::HiddenLink,
            ContentKind::InlineScript,
            ContentKind::Cloaked,
            ContentKind::ScriptHost,
            ContentKind::FrameHost,
            ContentKind::Redirect,
            ContentKind::LinkHost,
            ContentKind::LinkBurst,
        ] {
            assert_eq!(ContentKind::parse(k.as_str()), Some(k));
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_str()));
        }
        assert_eq!(ContentKind::parse("nope"), None);
    }

    #[test]
    fn an_empty_record_parses_and_is_not_partial() {
        let r: ContentScanResult = serde_json::from_str("{}").unwrap();
        assert!(!r.is_partial());
        assert_eq!(r.db, ContentLayer::NotApplicable);
    }

    #[test]
    fn a_failed_layer_is_never_nothing_new() {
        let r = ContentScanResult {
            db: ContentLayer::Failed("no login".into()),
            pages: ContentLayer::Complete,
            ..Default::default()
        };
        assert!(!r.nothing_new());
    }
}
