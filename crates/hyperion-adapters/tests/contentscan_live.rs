//! The content monitor's statements against a real MariaDB.
//!
//! The unit tests prove the statements' text. Only a server can say whether it
//! accepts them: the marker's dialect, the per-statement time limit, the
//! read-only session, the hex framing. This runs them in a throwaway container,
//! as an ordinary database user, the way the agent runs them as a hosting's own
//! login.
//!
//! Off unless told where: start a container and name it, for example
//!
//! ```text
//! docker run -d --name content-try -e MARIADB_ROOT_PASSWORD=try-only \
//!   -e MARIADB_DATABASE=lm_abc -e MARIADB_USER=lm_u -e MARIADB_PASSWORD=try-only-u mariadb:10.11
//! HYPERION_CONTENT_LIVE_CONTAINER=content-try cargo test -p hyperion-adapters --test contentscan_live
//! ```
//!
//! Every host in the fixture is invented.

use hyperion_adapters::contentscan::db::{
    parse_line, statements, Budget, Cursor, DbObserved, ReadEnd, Table,
};
use hyperion_types::content::ContentKind;
use std::io::Write;
use std::process::{Command, Stdio};

const DB: &str = "lm_abc";
const USER: &str = "lm_u";
const PASSWORD: &str = "try-only-u";

const SEED: &str = r#"
DROP TABLE IF EXISTS wp_posts, wp_options, wp_postmeta;
CREATE TABLE wp_posts (ID bigint unsigned AUTO_INCREMENT PRIMARY KEY, post_title text NOT NULL, post_excerpt text NOT NULL, post_content longtext NOT NULL, post_status varchar(20) NOT NULL DEFAULT 'publish', post_type varchar(20) NOT NULL DEFAULT 'post') DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
CREATE TABLE wp_options (option_id bigint unsigned AUTO_INCREMENT PRIMARY KEY, option_name varchar(191) NOT NULL, option_value longtext NOT NULL) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
CREATE TABLE wp_postmeta (meta_id bigint unsigned AUTO_INCREMENT PRIMARY KEY, post_id bigint unsigned NOT NULL, meta_key varchar(255), meta_value longtext) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
INSERT INTO wp_posts (post_title, post_excerpt, post_content, post_status, post_type) VALUES
 ('Plain', '', '<p>An ordinary paragraph with a <a href="https://friend.example.org/">link</a>.</p>', 'publish', 'post'),
 ('Hidden', '', '<p>News</p>\n<div style="position:absolute; left:-9999px"><a href="https://pills.spam.test/">cheap</a>\tžluťoučký</div>', 'publish', 'post'),
 ('Revision', '', '<script src="https://rev.loader.test/a.js"></script>', 'inherit', 'revision'),
 ('Trash', '', '<script src="https://trash.loader.test/a.js"></script>', 'trash', 'post'),
 ('Upper', '', '<SCRIPT SRC="https://cdn.loader.test/a.js"></SCRIPT>', 'draft', 'page');
INSERT INTO wp_options (option_name, option_value) VALUES
 ('blogname', 'Shop'),
 ('widget_text', 'a:1:{i:2;a:1:{s:4:"text";s:80:"<span style="display:none"><a href="https://casino.spam.test/x">x</a></span>";}}'),
 ('_transient_feed', '<script src="https://transient.loader.test/a.js"></script>'),
 ('_site_transient_update_plugins', '<iframe src="https://st.loader.test/"></iframe>');
INSERT INTO wp_postmeta (post_id, meta_key, meta_value) VALUES
 (55, '_elementor_data', '[{"widgetType":"html","settings":{"html":"<div style=\\"font-size:0\\"><a href=\\"https:\\/\\/loans.spam.test\\/\\">x<\\/a><\\/div>"}}]'),
 (56, '_edit_lock', '<script src="https://other.loader.test/a.js"></script>');
"#;

/// Run SQL in the container as the ordinary user, with the flags the agent uses.
fn run(container: &str, sql: &str) -> (bool, String) {
    let mut child = Command::new("docker")
        .args(["exec", "-i", "-e"])
        .arg(format!("MYSQL_PWD={PASSWORD}"))
        .arg(container)
        .args([
            "mariadb",
            &format!("--user={USER}"),
            "--local-infile=0",
            "--batch",
            "--raw",
            "--quick",
            "--skip-column-names",
            "--default-character-set=utf8mb4",
            DB,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("docker runs");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(sql.as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn read(container: &str, cursor: &Cursor) -> DbObserved {
    let sql = statements(DB, "wp_", cursor).expect("statements");
    let (ok, out) = run(container, &sql);
    assert!(ok, "the server refused the statements:\n{out}");
    let site = vec!["shop.example.com".to_string()];
    let mut budget = Budget::default();
    for line in out.lines() {
        let row = parse_line(line).unwrap_or_else(|| panic!("not a row: {line:?}"));
        assert!(budget.take(&row, &site));
    }
    budget.finish(false, None)
}

#[test]
fn the_statements_run_on_a_real_server_and_find_what_was_hidden() {
    let Ok(container) = std::env::var("HYPERION_CONTENT_LIVE_CONTAINER") else {
        eprintln!("skipped: set HYPERION_CONTENT_LIVE_CONTAINER to a MariaDB container's name");
        return;
    };
    let (ok, out) = run(&container, SEED);
    assert!(ok, "seeding failed:\n{out}");

    let got = read(&container, &Cursor::default());
    assert_eq!(got.end, ReadEnd::Complete);
    // Two posts, one option, one meta row carry a marker and are in scope. The
    // plain post, the revision, the trashed post, both transients, `blogname`
    // and the other meta key never leave the server.
    assert_eq!(got.rows, 4, "{:?}", got.placed);
    let mut seen: Vec<(ContentKind, &str, &str)> = got
        .placed
        .iter()
        .map(|p| (p.seen.kind, p.seen.key.as_str(), p.place.as_str()))
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![
            (
                ContentKind::HiddenLink,
                "casino.spam.test",
                "options:widget_text"
            ),
            (
                ContentKind::HiddenLink,
                "loans.spam.test",
                "postmeta:55:_elementor_data"
            ),
            (ContentKind::HiddenLink, "pills.spam.test", "posts:2"),
            (ContentKind::ScriptHost, "cdn.loader.test", "posts:5"),
        ]
    );

    // A cursor reads the rest first and comes round: nothing is left out.
    let from = Cursor {
        table: Table::Posts,
        after: 2,
    };
    let round = read(&container, &from);
    assert_eq!(round.rows, 4);
    assert_eq!(round.placed[0].place, "posts:5");
    assert_eq!(round.placed.last().expect("last").place, "posts:2");
}

/// The session is told to refuse writes, and it does: whatever follows the
/// statements in that session can't change the site.
#[test]
fn the_session_refuses_a_write() {
    let Ok(container) = std::env::var("HYPERION_CONTENT_LIVE_CONTAINER") else {
        eprintln!("skipped: set HYPERION_CONTENT_LIVE_CONTAINER to a MariaDB container's name");
        return;
    };
    let (ok, out) = run(&container, SEED);
    assert!(ok, "seeding failed:\n{out}");
    let sql = statements(DB, "wp_", &Cursor::default()).expect("statements");
    let first = sql.lines().next().expect("first line");
    let (ok, out) = run(
        &container,
        &format!(
            "{first}\nUPDATE wp_options SET option_value = 'x' WHERE option_name = 'blogname';\n"
        ),
    );
    assert!(!ok, "a write went through:\n{out}");
    assert!(
        out.contains("READ ONLY") || out.contains("read only"),
        "{out}"
    );
}
