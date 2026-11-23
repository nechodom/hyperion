//! Reading a WordPress site's stored content, without running it and without
//! changing it.
//!
//! The statements are a fixed set of `SELECT`s. The database does the first
//! cut: only rows whose value carries a marker (a script or frame tag, a
//! hiding declaration, a decoder) come back, so a site with fifty thousand
//! posts costs a table scan and a few rows, not fifty thousand rows.
//!
//! `post_modified` is deliberately not used to find what changed. Whoever
//! writes rows with SQL doesn't update it, the same way the file incident
//! forged mtimes.
//!
//! Every value arrives hex-encoded, one row per line, so nothing a tenant
//! stores can forge a row boundary.

use super::html::{extract, unescape_json, Seen};
use crate::mariadb::valid_table_prefix;
use crate::AdapterError;
use serde::{Deserialize, Serialize};

/// Rows taken from one site in one sweep.
pub const MAX_ROWS: usize = 5_000;
/// Decoded bytes taken from one site in one sweep.
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Characters of one value the database sends.
pub const VALUE_CHARS: usize = 2 * 1024 * 1024;
/// Seconds one statement may run, enforced by the server.
pub const STATEMENT_SECS: u32 = 60;
/// Observations kept from one sweep's rows.
pub const MAX_OBSERVED: usize = 50_000;

/// What a row must contain to be worth sending. Broad on purpose: this only
/// decides what leaves the database, the rules decide what it means. No
/// backslash and no single quote, so it sits in a SQL string as it is. A bare
/// `style=` is not here: nearly every block-editor row has one.
pub const MARKER: &str = "(?i)<script|<iframe|<frame|<object|<embed|<meta|javascript:|eval[(]|atob[(]|unescape[(]|fromCharCode|base64|[[:space:]]on[a-z]+[[:space:]]*=|display[[:space:]]*:[[:space:]]*none|visibility[[:space:]]*:[[:space:]]*(hidden|collapse)|opacity[[:space:]]*:[[:space:]]*0|font-size[[:space:]]*:[[:space:]]*0|(left|top|indent)[[:space:]]*:[[:space:]]*-|(width|height)[[:space:]]*:[[:space:]]*[01]([^0-9.%a-z]|px)|[[:space:]]hidden[[:space:]>=]|u003c";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Table {
    #[default]
    Posts,
    Options,
    Postmeta,
}

impl Table {
    const ORDER: [Table; 3] = [Table::Posts, Table::Options, Table::Postmeta];

    fn tag(self) -> char {
        match self {
            Table::Posts => 'p',
            Table::Options => 'o',
            Table::Postmeta => 'm',
        }
    }

    fn from_tag(tag: &str) -> Option<Table> {
        Table::ORDER.into_iter().find(|t| t.tag().to_string() == tag)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Table::Posts => "posts",
            Table::Options => "options",
            Table::Postmeta => "postmeta",
        }
    }
}

/// Where the last sweep stopped: the next one starts after this row and comes
/// round to everything before it, so no row is the one always left out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    #[serde(default)]
    pub table: Table,
    #[serde(default)]
    pub after: u64,
}

/// One stretch of one table, in the order a sweep reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Segment {
    table: Table,
    /// Rows with a key above this.
    above: u64,
    /// And at most this, when the stretch is the part a cursor came round to.
    up_to: Option<u64>,
}

fn segments(cursor: &Cursor) -> Vec<Segment> {
    let start = Table::ORDER
        .iter()
        .position(|t| *t == cursor.table)
        .unwrap_or(0);
    let mut out: Vec<Segment> = (0..Table::ORDER.len())
        .map(|i| Segment {
            table: Table::ORDER[(start + i) % Table::ORDER.len()],
            above: if i == 0 { cursor.after } else { 0 },
            up_to: None,
        })
        .collect();
    if cursor.after > 0 {
        out.push(Segment {
            table: cursor.table,
            above: 0,
            up_to: Some(cursor.after),
        });
    }
    out
}

fn valid_db_name(db: &str) -> bool {
    (1..=64).contains(&db.len())
        && db
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'$'))
}

fn select(db: &str, prefix: &str, seg: &Segment) -> String {
    let (table, key, name, value, extra) = match seg.table {
        Table::Posts => (
            "posts",
            "ID",
            "''",
            "CONCAT_WS(CHAR(10), post_title, post_excerpt, post_content)",
            "post_type <> 'revision' AND post_status NOT IN ('trash', 'auto-draft')",
        ),
        Table::Options => (
            "options",
            "option_id",
            "option_name",
            "option_value",
            "LEFT(option_name, 11) <> '_transient_' AND LEFT(option_name, 16) <> '_site_transient_'",
        ),
        Table::Postmeta => (
            "postmeta",
            "meta_id",
            "CAST(post_id AS CHAR)",
            "meta_value",
            "meta_key = '_elementor_data'",
        ),
    };
    let up_to = seg
        .up_to
        .map(|n| format!(" AND {key} <= {n}"))
        .unwrap_or_default();
    format!(
        "SET STATEMENT max_statement_time={STATEMENT_SECS} FOR \
         SELECT '{tag}', {key}, HEX({name}), HEX(LEFT({value}, {VALUE_CHARS})) \
         FROM `{db}`.`{prefix}{table}` \
         WHERE {key} > {above}{up_to} AND {extra} AND {value} REGEXP '{MARKER}' \
         ORDER BY {key} LIMIT {limit};\n",
        tag = seg.table.tag(),
        above = seg.above,
        limit = MAX_ROWS + 1,
    )
}

/// Everything sent to the server for one sweep. Read-only by construction and by
/// session: a `SELECT` is all there is, and the session is told to refuse more.
pub fn statements(db: &str, prefix: &str, cursor: &Cursor) -> Result<String, AdapterError> {
    if !valid_db_name(db) {
        return Err(AdapterError::Other("refusing a database name".into()));
    }
    if !valid_table_prefix(prefix) {
        return Err(AdapterError::Other("refusing a table prefix".into()));
    }
    let mut sql = String::from("SET SESSION TRANSACTION READ ONLY;\n");
    for seg in segments(cursor) {
        sql.push_str(&select(db, prefix, &seg));
    }
    Ok(sql)
}

/// One row of stored content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub table: Table,
    pub id: u64,
    /// The option's name, or the post a meta row belongs to. Empty for a post.
    pub name: String,
    pub value: String,
}

impl Row {
    /// Where a person would look for it.
    pub fn place(&self) -> String {
        let name: String = self
            .name
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect();
        match self.table {
            Table::Posts => format!("posts:{}", self.id),
            Table::Options => format!("options:{name}"),
            Table::Postmeta => format!("postmeta:{name}:_elementor_data"),
        }
    }
}

/// One line of the client's output as a row. Anything that isn't exactly the
/// four fields asked for is dropped: it wasn't written by the statements above.
pub fn parse_line(line: &str) -> Option<Row> {
    let mut fields = line.trim_end_matches(['\r', '\n']).split('\t');
    let (tag, id, name, value) = (fields.next()?, fields.next()?, fields.next()?, fields.next()?);
    if fields.next().is_some() {
        return None;
    }
    let text = |h: &str| Some(String::from_utf8_lossy(&hex::decode(h).ok()?).into_owned());
    Some(Row {
        table: Table::from_tag(tag)?,
        id: id.parse().ok()?,
        name: text(name)?,
        value: text(value)?,
    })
}

/// Something seen, and the row it was seen in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    pub place: String,
    pub seen: Seen,
}

/// What a row's content loads, frames, hides and runs.
pub fn observe(row: &Row, site_hosts: &[String]) -> Vec<Placed> {
    let place = row.place();
    let seen = match row.table {
        Table::Postmeta => extract(&unescape_json(&row.value), site_hosts, false),
        _ => extract(&row.value, site_hosts, false),
    };
    seen.into_iter()
        .map(|seen| Placed {
            place: place.clone(),
            seen,
        })
        .collect()
}

/// How a sweep's read ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadEnd {
    /// Every row was read.
    Complete,
    /// A limit stopped it here; the next sweep goes on from this row.
    Capped(Cursor),
    /// The server or the client gave up. What was read before that still counts.
    Broken(String),
}

/// What one sweep read from a site's database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbObserved {
    pub placed: Vec<Placed>,
    pub rows: usize,
    pub end: ReadEnd,
}

/// Counts what a sweep has taken and says when it has taken enough.
#[derive(Debug, Default)]
pub struct Budget {
    rows: usize,
    bytes: usize,
    last: Option<(Table, u64)>,
    placed: Vec<Placed>,
}

impl Budget {
    /// Take one row. `false` means the sweep is over its limits and this row was
    /// not taken: stop reading.
    pub fn take(&mut self, row: &Row, site_hosts: &[String]) -> bool {
        if self.rows >= MAX_ROWS || self.bytes + row.value.len() > MAX_BYTES {
            return false;
        }
        self.rows += 1;
        self.bytes += row.value.len();
        self.last = Some((row.table, row.id));
        let room = MAX_OBSERVED.saturating_sub(self.placed.len());
        self.placed
            .extend(observe(row, site_hosts).into_iter().take(room));
        true
    }

    /// The read is over. `capped` says a limit ended it, not the last row.
    pub fn finish(self, capped: bool, broken: Option<String>) -> DbObserved {
        let end = match (broken, capped, self.last) {
            (Some(why), _, _) => ReadEnd::Broken(why),
            (None, true, Some((table, after))) => ReadEnd::Capped(Cursor { table, after }),
            // Capped before a single row fitted: one value over the byte limit
            // can't happen (values are cut far below it), so this is "nothing
            // read", and saying complete would be a lie.
            (None, true, None) => ReadEnd::Broken("nothing could be read within the limits".into()),
            (None, false, _) => ReadEnd::Complete,
        };
        DbObserved {
            placed: self.placed,
            rows: self.rows,
            end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::content::ContentKind;

    fn site() -> Vec<String> {
        vec!["shop.example.com".into()]
    }

    fn line(tag: char, id: u64, name: &str, value: &[u8]) -> String {
        format!("{tag}\t{id}\t{}\t{}\n", hex::encode_upper(name), hex::encode_upper(value))
    }

    #[test]
    fn only_selects_in_a_read_only_session() {
        let sql = statements("lm_abc", "wp_", &Cursor::default()).expect("sql");
        assert!(sql.starts_with("SET SESSION TRANSACTION READ ONLY;\n"));
        let upper = sql.to_ascii_uppercase();
        for word in ["INSERT", "UPDATE ", "DELETE", "DROP", "ALTER", "CREATE", "REPLACE ", "GRANT", "INTO OUTFILE", "LOAD_FILE", "CALL "] {
            assert!(!upper.contains(word), "{word} in {sql}");
        }
        assert_eq!(sql.matches("SELECT").count(), 3);
        assert_eq!(sql.matches("max_statement_time=60").count(), 3);
        assert!(sql.contains("FROM `lm_abc`.`wp_posts`"));
        assert!(sql.contains("FROM `lm_abc`.`wp_options`"));
        assert!(sql.contains("FROM `lm_abc`.`wp_postmeta`"));
        assert!(sql.contains("meta_key = '_elementor_data'"));
        assert!(sql.contains("post_type <> 'revision'"));
        assert!(sql.contains("LIMIT 5001"));
    }

    #[test]
    fn the_marker_sits_in_a_sql_string_as_it_is() {
        assert!(!MARKER.contains('\''));
        assert!(!MARKER.contains('\\'));
        assert!(!MARKER.contains('\n'));
    }

    #[test]
    fn names_that_could_leave_the_quotes_are_refused() {
        assert!(statements("lm`; DROP", "wp_", &Cursor::default()).is_err());
        assert!(statements("lm_abc", "wp_`x", &Cursor::default()).is_err());
        assert!(statements("lm_abc", "", &Cursor::default()).is_err());
        assert!(statements("", "wp_", &Cursor::default()).is_err());
    }

    #[test]
    fn a_cursor_starts_after_its_row_and_comes_round() {
        let cursor = Cursor {
            table: Table::Options,
            after: 420,
        };
        let segs = segments(&cursor);
        assert_eq!(
            segs.iter().map(|s| (s.table, s.above, s.up_to)).collect::<Vec<_>>(),
            vec![
                (Table::Options, 420, None),
                (Table::Postmeta, 0, None),
                (Table::Posts, 0, None),
                (Table::Options, 0, Some(420)),
            ]
        );
        let sql = statements("lm_abc", "wp_", &cursor).expect("sql");
        assert!(sql.contains("WHERE option_id > 420 AND"));
        assert!(sql.contains("WHERE option_id > 0 AND option_id <= 420 AND"));
        let first = sql.find("wp_options").expect("options");
        assert!(first < sql.find("wp_postmeta").expect("postmeta"));
    }

    /// The server's dialect has the POSIX classes the marker uses and so does the
    /// `regex` crate, so the same text can be tried here.
    #[test]
    fn the_marker_lets_through_everything_the_rules_can_object_to() {
        let marker = regex::Regex::new(MARKER).expect("marker compiles");
        for value in [
            r#"<a href="https://spam.test/" style="display:none">x</a>"#,
            r#"<div style="position:absolute; left:-9999px"><a href="https://spam.test/">x</a></div>"#,
            r#"<p style="text-indent: -999em"><a href="https://spam.test/">x</a></p>"#,
            r#"<span style="font-size:0"><a href="https://spam.test/">x</a></span>"#,
            r#"<span style="opacity:0"><a href="https://spam.test/">x</a></span>"#,
            r#"<div style="height:1px;overflow:hidden"><a href="https://spam.test/">x</a></div>"#,
            r#"<div style="overflow:hidden;height:0"><a href="https://spam.test/">x</a></div>"#,
            r#"<div style="visibility:hidden"><a href="https://spam.test/">x</a></div>"#,
            r#"<div hidden><a href="https://spam.test/">x</a></div>"#,
            r#"<SCRIPT src="https://cdn.loader.test/a.js"></SCRIPT>"#,
            r#"<iframe src="https://video.example.net/1"></iframe>"#,
            r#"<img src=x onerror="eval(atob('QQ=='))">"#,
            r#"<a href="javascript:eval(unescape('%61'))">x</a>"#,
            r#"<meta http-equiv="refresh" content="0;url=https://away.spam.test/">"#,
            r#"[{"html":"<script src=\"https:\/\/cdn.loader.test\/a.js\">"}]"#,
            r#"[{"html":"<div style=\"display:none\"><a href=\"https:\/\/spam.test\">x<\/a><\/div>"}]"#,
        ] {
            assert!(marker.is_match(value), "{value}");
        }
        for value in [
            "<p>An ordinary paragraph with a <a href=\"https://friend.example.org/\">link</a>.</p>",
            "<!-- wp:paragraph --><p style=\"color:red\">Styled</p><!-- /wp:paragraph -->",
            "a:2:{s:5:\"title\";s:4:\"Menu\";s:8:\"nav_menu\";i:3;}",
        ] {
            assert!(!marker.is_match(value), "{value}");
        }
    }

    #[test]
    fn a_line_round_trips_whatever_the_value_holds() {
        let nasty = b"tab\there\nnewline\rp\t1\t00\t00\n\xff\xfe end";
        let row = parse_line(&line('o', 7, "widget_text", nasty)).expect("row");
        assert_eq!(row.table, Table::Options);
        assert_eq!(row.id, 7);
        assert_eq!(row.name, "widget_text");
        assert!(row.value.starts_with("tab\there\nnewline\rp\t1\t00\t00\n"));
        assert!(row.value.ends_with(" end"));
        assert_eq!(row.place(), "options:widget_text");
    }

    #[test]
    fn lines_the_statements_did_not_write_are_dropped() {
        for bad in [
            "",
            "p\t1\t\n",
            "p\t1\t00\t00\t00\n",
            "x\t1\t\t00\n",
            "p\tone\t\t00\n",
            "p\t1\t\tZZ\n",
            "p\t1\t\t0\n",
            "ERROR 1969 (70100): Query execution was interrupted\n",
        ] {
            assert!(parse_line(bad).is_none(), "{bad:?}");
        }
        assert!(parse_line("p\t1\t\t\n").is_some());
    }

    #[test]
    fn places_name_the_row() {
        let post = parse_line(&line('p', 123, "", b"x")).expect("row");
        assert_eq!(post.place(), "posts:123");
        let meta = parse_line(&line('m', 9, "55", b"x")).expect("row");
        assert_eq!(meta.place(), "postmeta:55:_elementor_data");
    }

    #[test]
    fn a_row_is_observed_with_its_place_and_builder_data_is_unescaped() {
        let post = Row {
            table: Table::Posts,
            id: 12,
            name: String::new(),
            value: r#"<div style="display:none"><a href="https://spam.test/">x</a></div>"#.into(),
        };
        let seen = observe(&post, &site());
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].place, "posts:12");
        assert_eq!(seen[0].seen.kind, ContentKind::HiddenLink);

        let meta = Row {
            table: Table::Postmeta,
            id: 3,
            name: "40".into(),
            value: r#"[{"html":"<div style=\"display:none\"><a href=\"https:\/\/spam.test\/\">x<\/a><\/div>"}]"#.into(),
        };
        let seen = observe(&meta, &site());
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].seen.key, "spam.test");
    }

    #[test]
    fn the_budget_stops_at_the_row_limit_and_remembers_where() {
        let mut budget = Budget::default();
        let mut taken = 0u64;
        for id in 1..=100_000u64 {
            let row = Row {
                table: Table::Posts,
                id,
                name: String::new(),
                value: "<script src=\"https://cdn.loader.test/a.js\"></script>".into(),
            };
            if !budget.take(&row, &site()) {
                break;
            }
            taken = id;
        }
        assert_eq!(taken, MAX_ROWS as u64);
        let read = budget.finish(true, None);
        assert_eq!(read.rows, MAX_ROWS);
        assert_eq!(
            read.end,
            ReadEnd::Capped(Cursor {
                table: Table::Posts,
                after: MAX_ROWS as u64
            })
        );
        assert_eq!(read.placed.len(), MAX_ROWS);
    }

    #[test]
    fn the_budget_stops_at_the_byte_limit() {
        let mut budget = Budget::default();
        let big = "x".repeat(10 * 1024 * 1024);
        let mut taken = 0;
        for id in 1..=10u64 {
            let row = Row {
                table: Table::Options,
                id,
                name: "o".into(),
                value: big.clone(),
            };
            if !budget.take(&row, &site()) {
                break;
            }
            taken += 1;
        }
        assert_eq!(taken, 6);
        assert!(matches!(
            budget.finish(true, None).end,
            ReadEnd::Capped(Cursor { table: Table::Options, after: 6 })
        ));
    }

    #[test]
    fn a_read_that_ended_by_itself_is_complete_and_a_broken_one_says_why() {
        assert_eq!(Budget::default().finish(false, None).end, ReadEnd::Complete);
        assert_eq!(
            Budget::default().finish(false, Some("timed out".into())).end,
            ReadEnd::Broken("timed out".into())
        );
        assert!(matches!(Budget::default().finish(true, None).end, ReadEnd::Broken(_)));
    }
}
