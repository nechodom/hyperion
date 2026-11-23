//! Content monitor building blocks: what a site says, as opposed to what its
//! files are. Stored content and fetched pages go in as text; hosts, hidden
//! links and rule hits come out. Everything here reads tenant-controlled text
//! and does nothing else with it.

pub mod db;
pub mod html;
pub mod rules;

pub use html::{extract, normal_host, unescape_json, url_host, Seen};

/// How the page layer identifies itself. Distinctive, like the site check's, so
/// its handful of requests a day can be found in an access log.
pub const USER_AGENT: &str = "Hyperion-ContentCheck/1 (+https://github.com/nechodom/hyperion)";

/// The second look at the homepage, as a search engine's crawler announces
/// itself. Spam that is served to crawlers only keys on this.
pub const CRAWLER_USER_AGENT: &str =
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
/// Where a visitor from a results page says they came from.
pub const CRAWLER_REFERER: &str = "https://www.google.com/";

/// Pages fetched per sweep beside the homepage.
pub const MAX_EXTRA_PAGES: usize = 4;
