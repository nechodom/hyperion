//! Tests for `service::content_scan`. Every host here is invented: `.test` and
//! `example.*` only.

use super::*;
use crate::service::content_scan::*;
use chrono::TimeZone;
use hyperion_adapters::contentscan::db::{Budget, Cursor, DbObserved, ReadEnd, Row, Table};
use hyperion_adapters::sitecheck::Fetched;
use hyperion_state::web_users::WebRole;
use hyperion_types::content::{ContentKind, ContentLayer, ContentScanResult};
use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

const DAY: i64 = 86_400;
const HOME: &str = "https://a.test/";

/// 2026-11-02 is a Monday; any day would do.
fn at(day: u32, hour: u32) -> i64 {
    chrono::Utc
        .with_ymd_and_hms(2026, 11, 2 + day, hour, 0, 0)
        .single()
        .expect("valid date")
        .timestamp()
}

/// What the fake site holds and serves. Tests change it between sweeps.
#[derive(Default)]
struct World {
    rows: Vec<Row>,
    /// How the database read ends, when not by itself.
    db_end: Option<ReadEnd>,
    db_fails: bool,
    /// What `wp-config.php` claims; `None` = not a WordPress site.
    config_db: Option<String>,
    pages: BTreeMap<String, (u16, String)>,
    crawler: Option<(u16, String, String)>,
    asked: Vec<(String, bool)>,
    cursors: Vec<Cursor>,
    logins: Vec<(String, String, String)>,
}

type Shared = Arc<StdMutex<World>>;

fn fetched(url: &str, status: u16, body: &str, location: &str) -> Fetched {
    Fetched {
        url: url.to_string(),
        status,
        ttfb_ms: 1,
        total_ms: 1,
        bytes: body.len() as i64,
        content_encoding: String::new(),
        cache_control: String::new(),
        location: location.to_string(),
        body: body.to_string(),
    }
}

fn world() -> Shared {
    let w = World {
        config_db: Some("lm_a".into()),
        pages: BTreeMap::from([(HOME.to_string(), (200, "<p>Welcome</p>".to_string()))]),
        ..Default::default()
    };
    Arc::new(StdMutex::new(w))
}

fn mocks(w: &Shared) -> MockAdapterPort {
    let mut a = happy_mocks();
    let w1 = w.clone();
    a.expect_site_scan_wp_config_db().returning(move |_| {
        let w = w1.lock().expect("lock");
        w.config_db.clone().map(|db| (db, "wp_".to_string()))
    });
    let w2 = w.clone();
    a.expect_content_db_read()
        .returning(move |db, prefix, user, password, cursor, hosts| {
            let mut w = w2.lock().expect("lock");
            w.logins.push((
                format!("{db}.{prefix}"),
                user.to_string(),
                password.to_string(),
            ));
            w.cursors.push(cursor);
            if w.db_fails {
                return Err(hyperion_adapters::AdapterError::Other("down".into()));
            }
            let mut budget = Budget::default();
            for row in &w.rows {
                assert!(budget.take(row, &hosts));
            }
            let mut read: DbObserved = budget.finish(false, None);
            if let Some(end) = w.db_end.clone() {
                read.end = end;
            }
            Ok(read)
        });
    let w3 = w.clone();
    a.expect_content_page()
        .returning(move |url, host, crawler| {
            assert_eq!(host, "a.test");
            let mut w = w3.lock().expect("lock");
            w.asked.push((url.to_string(), crawler));
            if crawler {
                return Ok(match &w.crawler {
                    Some((status, body, location)) => fetched(url, *status, body, location),
                    None => {
                        let (status, body) =
                            w.pages.get(url).cloned().unwrap_or((404, String::new()));
                        fetched(url, status, &body, "")
                    }
                });
            }
            let (status, body) = w.pages.get(url).cloned().unwrap_or((404, String::new()));
            Ok(fetched(url, status, &body, ""))
        });
    a
}

fn post(id: u64, value: &str) -> Row {
    Row {
        table: Table::Posts,
        id,
        name: String::new(),
        value: value.to_string(),
    }
}

fn hidden(host: &str) -> String {
    format!(
        r#"<p>News</p><div style="position:absolute;left:-9999px"><a href="https://{host}/">cheap</a></div>"#
    )
}

async fn site(s: &HostingService<MockAdapterPort>) -> HostingDetail {
    s.create(req("a.test")).await.expect("create");
    s.get(HostingSelector::Domain(
        Domain::parse("a.test").expect("parse"),
    ))
    .await
    .expect("get")
}

fn sel() -> HostingSelector {
    HostingSelector::Domain(Domain::parse("a.test").expect("parse"))
}

async fn stored(s: &HostingService<MockAdapterPort>) -> ContentScanResult {
    s.content_scan_stored(sel())
        .await
        .expect("stored")
        .expect("a result")
}

fn live() -> (std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, "[integrity]\ncontent_live = true\n").expect("write");
    (path, dir)
}

fn keys(items: &[hyperion_types::content::ContentItem]) -> Vec<(ContentKind, String)> {
    items.iter().map(|i| (i.kind, i.key.clone())).collect()
}

async fn feed(s: &HostingService<MockAdapterPort>, admin: i64) -> Vec<(String, String)> {
    s.notifications_feed(admin, 50)
        .await
        .expect("feed")
        .items
        .into_iter()
        .map(|n| (n.severity, n.kind))
        .collect()
}

// ---------------------------------------------------------------- acceptance 1

/// The October shape: links nobody can see, written into stored content. In a
/// post, in a text widget, and in page-builder data.
#[tokio::test]
async fn hidden_links_in_stored_content_are_findings_that_name_host_and_place() {
    let w = world();
    {
        let mut w = w.lock().expect("lock");
        w.rows = vec![
            post(41, &hidden("pills.spam.test")),
            Row {
                table: Table::Options,
                id: 7,
                name: "widget_text".into(),
                value: format!(
                    "a:1:{{i:2;a:1:{{s:4:\"text\";s:90:\"{}\";}}}}",
                    r#"<span style="display:none"><a href="https://casino.spam.test/x">x</a></span>"#
                ),
            },
            Row {
                table: Table::Postmeta,
                id: 3,
                name: "55".into(),
                value: r#"[{"widgetType":"html","settings":{"html":"<div style=\"font-size:0\"><a href=\"https:\/\/loans.spam.test\/\">x<\/a><\/div>"}}]"#.into(),
            },
        ];
    }
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12))
        .await
        .expect("ran");
    let r = stored(&s).await;
    assert_eq!(r.db, ContentLayer::Complete);
    assert_eq!(
        keys(&r.findings),
        vec![
            (ContentKind::HiddenLink, "casino.spam.test".to_string()),
            (ContentKind::HiddenLink, "loans.spam.test".to_string()),
            (ContentKind::HiddenLink, "pills.spam.test".to_string()),
        ]
    );
    let places: Vec<&str> = r.findings.iter().map(|f| f.places[0].as_str()).collect();
    assert_eq!(
        places,
        [
            "options:widget_text",
            "postmeta:55:_elementor_data",
            "posts:41"
        ]
    );
    assert!(r.findings.iter().all(|f| f.in_db && !f.on_page));
    assert!(r.review.is_empty());
    // The pilot: on the card, told to no one.
    assert!(r.report_only);
    assert!(r.findings.iter().all(|f| !f.notified));
}

#[tokio::test]
async fn the_database_is_read_as_the_hostings_own_login() {
    let w = world();
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12))
        .await
        .expect("ran");
    let w = w.lock().expect("lock");
    assert_eq!(
        w.logins,
        vec![("lm_a.wp_".to_string(), "lm_u".to_string(), "p".to_string())]
    );
}

// ---------------------------------------------------------------- acceptance 2, 4

#[tokio::test]
async fn a_second_sweep_is_quiet_and_one_new_host_is_one_message() {
    let w = world();
    w.lock().expect("lock").rows = vec![post(1, &hidden("pills.spam.test"))];
    let (cfg, _dir) = live();
    let s = svc(open_memory().await.expect("open"), mocks(&w)).with_agent_config_path(cfg);
    let admin = seed_web_user(&s, "boss", WebRole::Admin).await;
    let detail = site(&s).await;

    assert_eq!(s.content_scan_site(&detail.id, at(0, 12)).await, Some(true));
    assert_eq!(
        feed(&s, admin).await,
        [("error".to_string(), "content:a.test".to_string())]
    );

    assert_eq!(s.content_scan_site(&detail.id, at(1, 3)).await, Some(false));
    assert_eq!(
        feed(&s, admin).await.len(),
        1,
        "a standing finding isn't told again"
    );
    assert_eq!(stored(&s).await.findings.len(), 1);

    w.lock()
        .expect("lock")
        .rows
        .push(post(2, &hidden("casino.spam.test")));
    assert_eq!(s.content_scan_site(&detail.id, at(2, 3)).await, Some(true));
    let told = feed(&s, admin).await;
    assert_eq!(told.len(), 2);
    assert!(told
        .iter()
        .all(|(sev, kind)| sev == "error" && kind == "content:a.test"));
    let r = stored(&s).await;
    assert_eq!(r.findings.len(), 2);
    assert!(r.findings.iter().all(|f| f.notified));
}

#[tokio::test]
async fn with_the_flag_off_results_are_stored_and_nobody_is_told() {
    let w = world();
    {
        let mut w = w.lock().expect("lock");
        w.rows = vec![post(1, &hidden("pills.spam.test"))];
        w.pages.insert(
            HOME.into(),
            (
                200,
                r#"<script src="https://cdn.loader.test/a.js"></script>"#.into(),
            ),
        );
    }
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let admin = seed_web_user(&s, "boss", WebRole::Admin).await;
    let detail = site(&s).await;
    assert_eq!(
        s.content_scan_site(&detail.id, at(0, 12)).await,
        Some(false)
    );
    assert_eq!(s.content_scan_site(&detail.id, at(1, 3)).await, Some(false));
    assert!(feed(&s, admin).await.is_empty());
    let r = stored(&s).await;
    assert!(r.report_only);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.review.len(), 1);
}

/// What the pilot found and nobody heard about is said once when alerts go
/// live. Changes to review were on the card all along and aren't.
#[tokio::test]
async fn switching_the_flag_on_tells_standing_findings_once_and_not_review_items() {
    let w = world();
    w.lock().expect("lock").rows = vec![post(1, &hidden("pills.spam.test"))];
    let pool = open_memory().await.expect("open");
    let quiet = svc(pool.clone(), mocks(&w));
    let admin = seed_web_user(&quiet, "boss", WebRole::Admin).await;
    let detail = site(&quiet).await;
    quiet.content_scan_site(&detail.id, at(0, 12)).await;
    // A script host appears during the pilot: a change to review, unannounced.
    w.lock().expect("lock").pages.insert(
        HOME.into(),
        (
            200,
            r#"<script src="https://cdn.loader.test/a.js"></script>"#.into(),
        ),
    );
    quiet.content_scan_site(&detail.id, at(1, 3)).await;
    assert!(feed(&quiet, admin).await.is_empty());
    assert_eq!(stored(&quiet).await.review.len(), 1);

    let (cfg, _dir) = live();
    let loud = svc(pool, mocks(&w)).with_agent_config_path(cfg);
    assert_eq!(
        loud.content_scan_site(&detail.id, at(2, 3)).await,
        Some(true)
    );
    assert_eq!(
        feed(&loud, admin).await,
        [("error".to_string(), "content:a.test".to_string())]
    );
    assert_eq!(
        loud.content_scan_site(&detail.id, at(3, 3)).await,
        Some(false)
    );
    assert_eq!(feed(&loud, admin).await.len(), 1);
}

// ---------------------------------------------------------------- acceptance 3

#[tokio::test]
async fn the_first_scan_blesses_nothing_that_matters() {
    let w = world();
    {
        let mut w = w.lock().expect("lock");
        w.rows = vec![
            post(1, &hidden("pills.spam.test")),
            post(
                2,
                r#"<iframe src="https://video.example.net/embed/1"></iframe>"#,
            ),
        ];
        w.pages.insert(
            HOME.into(),
            (
                200,
                r#"<a href="https://friend.example.org/">friend</a>
                   <script src="https://tags.example.net/t.js"></script>"#
                    .into(),
            ),
        );
    }
    let (cfg, _dir) = live();
    let s = svc(open_memory().await.expect("open"), mocks(&w)).with_agent_config_path(cfg);
    let admin = seed_web_user(&s, "boss", WebRole::Admin).await;
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert_eq!(r.watching_since, at(0, 12));
    assert_eq!(
        keys(&r.findings),
        [(ContentKind::HiddenLink, "pills.spam.test".to_string())]
    );
    // The embed and the tag were already here: listed once, for a person, and
    // not announced.
    assert_eq!(
        keys(&r.review),
        [
            (ContentKind::ScriptHost, "tags.example.net".to_string()),
            (ContentKind::FrameHost, "video.example.net".to_string()),
        ]
    );
    assert!(r.review.iter().all(|i| i.at_first_scan));
    // An ordinary outbound link is the site's business.
    assert_eq!(r.link_hosts, 1);
    assert_eq!(
        feed(&s, admin).await,
        [("error".to_string(), "content:a.test".to_string())]
    );

    // Later, a script host that wasn't there is announced as a change to review.
    w.lock().expect("lock").rows.push(post(
        3,
        r#"<script src="https://new.loader.test/x.js"></script>"#,
    ));
    s.content_scan_site(&detail.id, at(1, 3)).await;
    let told = feed(&s, admin).await;
    assert_eq!(told.len(), 2);
    assert!(told.contains(&("warn".to_string(), "content.review:a.test".to_string())));
}

// ---------------------------------------------------------------- trust

#[tokio::test]
async fn trusting_an_item_removes_it_and_keeps_it_quiet() {
    let w = world();
    w.lock().expect("lock").rows = vec![
        post(1, &hidden("skip.example.org")),
        post(
            2,
            r#"<iframe src="https://video.example.net/embed/1"></iframe>"#,
        ),
    ];
    let (cfg, _dir) = live();
    let s = svc(open_memory().await.expect("open"), mocks(&w)).with_agent_config_path(cfg);
    let admin = seed_web_user(&s, "boss", WebRole::Admin).await;
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;

    // A made-up key trusts nothing.
    let refused = s
        .content_trust(
            sel(),
            "hidden_link".into(),
            "other.test".into(),
            "boss".into(),
        )
        .await;
    assert!(matches!(refused, Err(RpcError::Conflict { .. })));
    assert!(s
        .content_trust(
            sel(),
            "nonsense".into(),
            "skip.example.org".into(),
            "boss".into()
        )
        .await
        .is_err());

    let after = s
        .content_trust(
            sel(),
            "hidden_link".into(),
            "skip.example.org".into(),
            "boss".into(),
        )
        .await
        .expect("trust");
    assert!(after.findings.is_empty());
    assert_eq!(after.review.len(), 1);

    // Trust-all takes what waits for review, never a finding.
    w.lock()
        .expect("lock")
        .rows
        .push(post(3, &hidden("pills.spam.test")));
    s.content_scan_site(&detail.id, at(1, 3)).await;
    let after = s
        .content_trust_all_review(sel(), "boss".into())
        .await
        .expect("trust all");
    assert!(after.review.is_empty());
    assert_eq!(
        keys(&after.findings),
        [(ContentKind::HiddenLink, "pills.spam.test".to_string())]
    );
    assert!(s
        .content_trust_all_review(sel(), "boss".into())
        .await
        .is_err());

    // Still there next sweep, still quiet.
    let before = feed(&s, admin).await.len();
    s.content_scan_site(&detail.id, at(2, 3)).await;
    let r = stored(&s).await;
    assert_eq!(r.findings.len(), 1);
    assert!(r.review.is_empty());
    assert_eq!(feed(&s, admin).await.len(), before);
    let base = s.content_baseline(detail.id.as_str()).await;
    assert!(base.keys["hidden_link|skip.example.org"].trusted);
    assert!(base.keys["frame_host|video.example.net"].trusted);
}

// ---------------------------------------------------------------- hostile input

#[tokio::test]
async fn a_config_naming_someone_elses_database_is_refused_and_said() {
    let w = world();
    w.lock().expect("lock").config_db = Some("lm_victim".into());
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert!(matches!(&r.db, ContentLayer::Failed(why) if why.contains("doesn't own")));
    assert!(
        w.lock().expect("lock").logins.is_empty(),
        "nothing was read"
    );
    assert!(!r.nothing_new(), "couldn't check is never clean");
    assert_eq!(r.pages, ContentLayer::Complete);
}

#[tokio::test]
async fn a_site_without_wordpress_gets_the_page_layer_alone() {
    let w = world();
    w.lock().expect("lock").config_db = None;
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert_eq!(r.db, ContentLayer::NotApplicable);
    assert_eq!(r.pages, ContentLayer::Complete);
    assert!(r.nothing_new());
}

#[tokio::test]
async fn a_database_that_does_not_answer_is_could_not_check() {
    let w = world();
    w.lock().expect("lock").db_fails = true;
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert!(matches!(r.db, ContentLayer::Failed(_)));
    assert!(r.is_partial());
}

/// Review focus 2: rows a capped read didn't reach aren't "gone".
#[tokio::test]
async fn partial_layer_carries_prior_items() {
    let w = world();
    w.lock().expect("lock").rows = vec![post(1, &hidden("pills.spam.test"))];
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    assert_eq!(stored(&s).await.findings.len(), 1);

    // Tonight the read stops before that row.
    let stop = Cursor {
        table: Table::Posts,
        after: 5_000,
    };
    {
        let mut w = w.lock().expect("lock");
        w.rows.clear();
        w.db_end = Some(ReadEnd::Capped(stop));
    }
    s.content_scan_site(&detail.id, at(1, 3)).await;
    let r = stored(&s).await;
    assert!(matches!(r.db, ContentLayer::Partial(_)));
    assert_eq!(r.findings.len(), 1, "unread is not gone");
    assert!(!r.nothing_new());

    // The next read starts where that one stopped, and a complete one that
    // doesn't find the row lets the finding go.
    w.lock().expect("lock").db_end = None;
    s.content_scan_site(&detail.id, at(2, 3)).await;
    assert_eq!(w.lock().expect("lock").cursors.last(), Some(&stop));
    assert!(stored(&s).await.findings.is_empty());
    s.content_scan_site(&detail.id, at(3, 3)).await;
    assert_eq!(
        w.lock().expect("lock").cursors.last(),
        Some(&Cursor::default())
    );
}

// ---------------------------------------------------------------- pages

fn sitemap(urls: &[&str]) -> String {
    let locs: String = urls
        .iter()
        .map(|u| format!("<url><loc>{u}</loc></url>"))
        .collect();
    format!("<?xml version=\"1.0\"?><urlset>{locs}</urlset>")
}

#[tokio::test]
async fn the_homepage_four_more_pages_and_one_crawler_view_are_fetched() {
    let w = world();
    {
        let mut w = w.lock().expect("lock");
        let pages = [
            "https://a.test/",
            "https://a.test/one",
            "https://a.test/two",
            "https://a.test/three",
            "https://a.test/four",
            "https://a.test/five",
            // The site's own text: an address elsewhere is never fetched.
            "http://169.254.169.254/latest",
        ];
        w.pages.insert(
            "https://a.test/wp-sitemap.xml".into(),
            (200, sitemap(&pages)),
        );
        for p in &pages[1..6] {
            w.pages.insert((*p).into(), (200, "<p>page</p>".into()));
        }
    }
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert_eq!(r.pages, ContentLayer::Complete);
    assert_eq!(r.pages_fetched, 5);
    let asked = w.lock().expect("lock").asked.clone();
    assert_eq!(
        asked,
        vec![
            (HOME.to_string(), false),
            ("https://a.test/wp-sitemap.xml".to_string(), false),
            ("https://a.test/one".to_string(), false),
            ("https://a.test/two".to_string(), false),
            ("https://a.test/three".to_string(), false),
            ("https://a.test/four".to_string(), false),
            (HOME.to_string(), true),
        ]
    );
    // The next night the sitemap isn't asked again: six requests.
    w.lock().expect("lock").asked.clear();
    s.content_scan_site(&detail.id, at(1, 3)).await;
    assert_eq!(w.lock().expect("lock").asked.len(), 6);
}

// ---------------------------------------------------------------- acceptance 7

#[tokio::test]
async fn a_host_served_only_to_a_crawler_is_cloaked() {
    let w = world();
    {
        let mut w = w.lock().expect("lock");
        w.pages.insert(
            HOME.into(),
            (
                200,
                r#"<a href="https://friend.example.org/">friend</a>"#.into(),
            ),
        );
        w.crawler = Some((
            200,
            r#"<a href="https://friend.example.org/">friend</a>
               <a href="https://pills.spam.test/">cheap pills</a>"#
                .into(),
            String::new(),
        ));
    }
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert_eq!(
        keys(&r.findings),
        [(ContentKind::Cloaked, "pills.spam.test".to_string())]
    );
    assert_eq!(r.findings[0].places, [HOME]);
    assert_eq!(r.crawler_note, None);
}

#[tokio::test]
async fn a_crawler_sent_elsewhere_is_cloaked() {
    let w = world();
    w.lock().expect("lock").crawler = Some((
        302,
        String::new(),
        "https://pharma.spam.test/landing".into(),
    ));
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert_eq!(
        keys(&r.findings),
        [(ContentKind::Cloaked, "pharma.spam.test".to_string())]
    );
}

/// Review focus 4: a security plugin turning the crawler away is not a finding.
#[tokio::test]
async fn a_refused_crawler_view_is_could_not_check_never_a_finding() {
    let w = world();
    {
        let mut w = w.lock().expect("lock");
        w.crawler = Some((
            403,
            "<a href=\"https://block.example.net/why\">blocked</a>".into(),
            String::new(),
        ));
    }
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert!(r.findings.is_empty());
    assert!(r.crawler_note.as_deref().is_some_and(|n| n.contains("403")));
    assert_eq!(r.pages, ContentLayer::Complete);
}

#[tokio::test]
async fn what_the_site_is_already_known_for_is_not_cloaking() {
    let w = world();
    w.lock().expect("lock").pages.insert(
        HOME.into(),
        (200, r#"<a href="https://ads-a.example.net/">ad</a>"#.into()),
    );
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    // The rotation shows a visitor one advert and the crawler the other.
    {
        let mut w = w.lock().expect("lock");
        w.pages.insert(
            HOME.into(),
            (200, r#"<a href="https://ads-b.example.net/">ad</a>"#.into()),
        );
        w.crawler = Some((
            200,
            r#"<a href="https://ads-a.example.net/">ad</a>"#.into(),
            String::new(),
        ));
    }
    s.content_scan_site(&detail.id, at(1, 3)).await;
    assert!(stored(&s).await.findings.is_empty());
}

#[tokio::test]
async fn a_homepage_that_does_not_answer_is_could_not_check() {
    let w = world();
    w.lock()
        .expect("lock")
        .pages
        .insert(HOME.into(), (500, String::new()));
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_site(&detail.id, at(0, 12)).await;
    let r = stored(&s).await;
    assert!(matches!(&r.pages, ContentLayer::Failed(why) if why.contains("500")));
    assert_eq!(r.pages_fetched, 0);
    assert_eq!(
        w.lock().expect("lock").asked.len(),
        1,
        "nothing more is asked of it"
    );
}

// ---------------------------------------------------------------- judge (pure)

fn link(host: &str) -> Sighting {
    Sighting {
        kind: ContentKind::LinkHost,
        key: host.to_string(),
        snippet: String::new(),
        place: HOME.to_string(),
        from_db: false,
    }
}

fn complete(seen: Vec<Sighting>) -> Observed {
    Observed {
        db: ContentLayer::Complete,
        pages: ContentLayer::Complete,
        pages_fetched: 1,
        seen,
        cursor: Some(Cursor::default()),
        ..Default::default()
    }
}

#[test]
fn ten_new_link_hosts_at_once_are_one_thing_to_review() {
    let mut base = Baseline::default();
    let first = judge(
        &mut base,
        &complete(
            (0..30)
                .map(|n| link(&format!("old{n}.example.org")))
                .collect(),
        ),
        None,
        100,
    );
    assert!(
        first.review.is_empty(),
        "the first scan's links are the site's own"
    );
    assert_eq!(first.link_hosts, 30);

    let nine: Vec<Sighting> = (0..9).map(|n| link(&format!("n{n}.spam.test"))).collect();
    let r = judge(&mut base, &complete(nine), Some(&first), 200);
    assert!(r.review.is_empty(), "nine is a busy editor");

    let ten: Vec<Sighting> = (0..LINK_BURST)
        .map(|n| link(&format!("m{n}.spam.test")))
        .collect();
    let r = judge(&mut base, &complete(ten), Some(&r), 300);
    assert_eq!(r.review.len(), 1);
    assert_eq!(r.review[0].kind, ContentKind::LinkBurst);
    assert_eq!(r.review[0].count, 10);
    assert_eq!(r.review[0].places.len(), 10);
    // It stays until someone has looked.
    let r = judge(&mut base, &complete(vec![]), Some(&r), 400);
    assert_eq!(r.review.len(), 1);
}

#[test]
fn a_key_unseen_for_thirty_days_leaves_only_after_a_complete_sweep() {
    let mut base = Baseline::default();
    judge(
        &mut base,
        &complete(vec![link("friend.example.org")]),
        None,
        0,
    );
    assert!(base.keys.contains_key("link_host|friend.example.org"));

    let mut partial = complete(vec![]);
    partial.pages = ContentLayer::Failed("down".into());
    judge(&mut base, &partial, None, 40 * DAY);
    assert!(
        base.keys.contains_key("link_host|friend.example.org"),
        "unread isn't unseen"
    );

    judge(&mut base, &complete(vec![]), None, 41 * DAY);
    assert!(base.keys.is_empty());
}

#[test]
fn the_baseline_stays_within_its_size_and_keeps_what_was_trusted() {
    let mut base = Baseline {
        since: 1,
        ..Default::default()
    };
    base.keys.insert(
        "hidden_link|skip.example.org".into(),
        BaseKey {
            first_seen: 1,
            last_seen: 1,
            trusted: true,
        },
    );
    let many: Vec<Sighting> = (0..MAX_KEYS + 50)
        .map(|n| link(&format!("h{n}.example.org")))
        .collect();
    let mut obs = complete(many);
    // Not a complete sweep, so expiry isn't what trims it.
    obs.db = ContentLayer::Partial("more".into());
    judge(&mut base, &obs, None, 2);
    assert_eq!(base.keys.len(), MAX_KEYS);
    assert!(base.keys.contains_key("hidden_link|skip.example.org"));
}

#[test]
fn the_listing_is_bounded_and_says_how_much_more() {
    let seen: Vec<Sighting> = (0..150)
        .map(|n| Sighting {
            kind: ContentKind::HiddenLink,
            key: format!("s{n:03}.spam.test"),
            snippet: String::new(),
            place: "posts:1".into(),
            from_db: true,
        })
        .collect();
    let r = judge(&mut Baseline::default(), &complete(seen), None, 1);
    assert_eq!(r.findings.len(), 100);
    assert_eq!(r.more, 50);
}

// ---------------------------------------------------------------- acceptance 5

async fn scanned_at(s: &HostingService<MockAdapterPort>) -> i64 {
    stored(s).await.scanned_at
}

#[tokio::test]
async fn a_site_never_scanned_is_scanned_at_any_hour_and_then_nightly() {
    let w = world();
    let s = svc(open_memory().await.expect("open"), mocks(&w));
    site(&s).await;
    // Midday: the first scan doesn't wait for the night.
    s.content_scan_tick_at(&chrono::Utc, at(0, 12))
        .await
        .expect("tick");
    assert_eq!(scanned_at(&s).await, at(0, 12));
    // Later that day, and the next morning before the window: nothing.
    s.content_scan_tick_at(&chrono::Utc, at(0, 18))
        .await
        .expect("tick");
    s.content_scan_tick_at(&chrono::Utc, at(1, 1))
        .await
        .expect("tick");
    assert_eq!(scanned_at(&s).await, at(0, 12));
    // In the window: once.
    s.content_scan_tick_at(&chrono::Utc, at(1, 2))
        .await
        .expect("tick");
    assert_eq!(scanned_at(&s).await, at(1, 2));
    s.content_scan_tick_at(&chrono::Utc, at(1, 3))
        .await
        .expect("tick");
    assert_eq!(scanned_at(&s).await, at(1, 2));
    // After the window, nothing until the next night.
    s.content_scan_tick_at(&chrono::Utc, at(1, 9))
        .await
        .expect("tick");
    assert_eq!(scanned_at(&s).await, at(1, 2));
    s.content_scan_tick_at(&chrono::Utc, at(2, 4))
        .await
        .expect("tick");
    assert_eq!(scanned_at(&s).await, at(2, 4));
}

/// Every deploy restarts the agent. A fresh process in the same night, with the
/// night's sweep already done, reads nothing.
#[tokio::test]
async fn a_restart_starts_nothing() {
    let w = world();
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), mocks(&w));
    site(&s).await;
    s.content_scan_tick_at(&chrono::Utc, at(0, 12))
        .await
        .expect("tick");
    s.content_scan_tick_at(&chrono::Utc, at(1, 2))
        .await
        .expect("tick");
    let stamp = hyperion_state::node_kv::get(&pool, CONTENT_SWEEP_KV)
        .await
        .expect("kv");
    assert_eq!(stamp, Some(at(1, 2).to_string()));

    let asked_before = w.lock().expect("lock").asked.len();
    let restarted = svc(pool, mocks(&w));
    assert_eq!(
        restarted
            .content_scan_tick_at(&chrono::Utc, at(1, 3))
            .await
            .expect("tick"),
        0
    );
    assert_eq!(w.lock().expect("lock").asked.len(), asked_before);
    assert_eq!(scanned_at(&restarted).await, at(1, 2));
}

#[tokio::test]
async fn a_site_with_scanning_switched_off_is_left_alone() {
    let w = world();
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), mocks(&w));
    let detail = site(&s).await;
    hyperion_state::hosting_kv::set(
        &pool,
        detail.id.as_str(),
        "integrity_scan_enabled",
        "off",
        1,
    )
    .await
    .expect("kv");
    s.content_scan_tick_at(&chrono::Utc, at(0, 12))
        .await
        .expect("tick");
    assert!(s
        .content_scan_stored(sel())
        .await
        .expect("stored")
        .is_none());
    assert!(w.lock().expect("lock").asked.is_empty());
}

#[tokio::test]
async fn scan_now_is_honoured_outside_the_night_but_not_twice_in_ten_minutes() {
    let w = world();
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), mocks(&w));
    let detail = site(&s).await;
    s.content_scan_tick_at(&chrono::Utc, at(0, 12))
        .await
        .expect("tick");

    s.content_scan_request(detail.id.as_str(), at(0, 12) + 60)
        .await;
    s.content_scan_tick_at(&chrono::Utc, at(0, 12) + 120)
        .await
        .expect("tick");
    assert_eq!(
        scanned_at(&s).await,
        at(0, 12),
        "too soon after the last one"
    );

    s.content_scan_tick_at(&chrono::Utc, at(0, 13))
        .await
        .expect("tick");
    assert_eq!(scanned_at(&s).await, at(0, 13));
    // Answered, so not again.
    s.content_scan_tick_at(&chrono::Utc, at(0, 14))
        .await
        .expect("tick");
    assert_eq!(scanned_at(&s).await, at(0, 13));
}
