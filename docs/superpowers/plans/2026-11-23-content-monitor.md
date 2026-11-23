# Content Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect content injected into a WordPress site's database or rendered pages, alerting only on what is new, behind a per-node pilot flag.

**Architecture:** A pure parsing/rules module (`hyperion-adapters::contentscan`) turns HTML fragments and pages into `Seen` observations. A core service (`content_scan.rs`) gathers observations from a database reader and a page fetcher (both behind one trait), judges them against a per-site baseline in `hosting_kv`, stores a result, and notifies when `[integrity] content_live` is on. A tick drives it nightly. The integrity card and `hctl` read the stored result over a new RPC.

**Tech Stack:** Rust, `regex`, the `mariadb` client as the hosting's own login, `curl` through `sitecheck::fetch`, sqlx/SQLite kv stores, askama templates.

**Spec:** `docs/superpowers/specs/2026-11-23-content-monitor-design.md`

## Global Constraints

- Read-only: the only statements sent are fixed `SELECT`s inside a read-only session. No wp-cli, no PHP.
- The database is read as the hosting's own login, and only a database the hosting owns.
- Limits: value cut at 2 MiB; 5,000 rows and 64 MiB per site per sweep; 60 s per statement; baseline 2,000 keys; key expiry 30 days unseen; link burst at 10 new hosts; 20 places per item; snippet 120 chars.
- Page layer: homepage + up to 4 sitemap pages + one crawler view; loopback only.
- New RPC fields and stored fields are additive with `#[serde(default)]`; an old node answering "unknown variant" leaves the card as it is today.
- `[integrity] content_live`, per node, default false.
- Product text English; operator alerts have en + cs strings.
- The repo is public: fixtures use `example.*` and `.test` hosts only.

## Review Focus

1. Inline scripts whose text changes per request (nonces, timestamps): must not produce a new key every sweep. Pinned in Task 1 (`digits_do_not_change_the_key`).
2. A partial database read: items from rows not read tonight must not be treated as gone. Pinned in Task 4 (`partial_layer_carries_prior_items`).
3. The ordinary analytics loader (`createElement('script')` with a literal host) must be a `script-host` to review, not a finding. Pinned in Task 1.
4. A failed or refused crawler view is "couldn't check", never `cloaked`. Pinned in Task 4.
5. Switching the flag on: standing findings notify once, standing review items don't. Pinned in Task 6.

---

### Task 1: `contentscan` extraction and rules (pure)

**Files:**
- Create: `crates/hyperion-types/src/content.rs` (+ `pub mod content;` in `lib.rs`)
- Create: `crates/hyperion-adapters/src/contentscan/{mod.rs,html.rs,rules.rs}` (+ `pub mod contentscan;`)

**Produces:**
- `hyperion_types::content::{ContentKind, ContentItem, ContentLayer, ContentScanResult}`.
  `ContentKind`: `HiddenLink, InlineScript, Cloaked, ScriptHost, FrameHost, Redirect, LinkHost, LinkBurst` (serde snake_case), with `is_finding()`.
- `contentscan::Seen { kind: ContentKind, key: String, snippet: String }`.
- `contentscan::extract(html: &str, site_hosts: &[String], page: bool) -> Vec<Seen>`; `page` adds `LinkHost` and `Redirect`.
- `contentscan::unescape_json(text: &str) -> String`.
- `contentscan::rules::{RULE_PACK: u32, hides(style: &str) -> bool, inline_hits(script: &str) -> Vec<&'static str>, loader_hosts(script: &str) -> Vec<String>, snippet_key(rule: &str, text: &str) -> String}`.

- [ ] Tests first (in each file's `mod tests`): hidden link by each declared style on the link and on an ancestor; a visible link is no `HiddenLink`; an internal hidden link is nothing; `<script src>` external/internal/protocol-relative; iframe/object/embed; `atob`→`eval`, `document.write(unescape(`, `fromCharCode` chain, packer, encoded literal ≥ 1 kB (a `data:image` URI is exempt); analytics loader gives `ScriptHost`; `digits_do_not_change_the_key`; meta refresh and canonical off-site (page only); entity-encoded `href`; unclosed tags and invalid nesting don't panic; `unescape_json` on `<\/script>` and `<`.
- [ ] Implement; `cargo test -p hyperion-adapters contentscan`; commit.

### Task 2: database reader

**Files:**
- Modify: `crates/hyperion-adapters/src/mariadb.rs`
- Create: `crates/hyperion-adapters/src/contentscan/db.rs`

**Produces:**
- `contentscan::db::{Cursor { posts: u64, options: u64, postmeta: u64 }, Row { table: Table, id: u64, name: String, value: String }, Table, ReadEnd { Complete, Capped(Cursor) }, statements(db, prefix, &Cursor) -> Result<String, AdapterError>, parse_line(&str) -> Option<Row>, MAX_ROWS = 5000, MAX_BYTES = 64 MiB, VALUE_CHARS = 2_097_152}`.
- `mariadb::read_content(db, prefix, &DbLogin, &Cursor, on_row: impl FnMut(Row)) -> Result<ReadEnd, AdapterError>`: streams stdout line by line; kills the client at a cap.

Each row is one line: `table \t id \t HEX(name) \t HEX(value)`. Posts read `CONCAT_WS('\n', post_title, post_excerpt, post_content)`; options skip `\_transient\_%` and `\_site\_transient\_%`; postmeta is `meta_key = '_elementor_data'`. `ORDER BY` primary key, `WHERE pk > cursor`, `LIMIT 5001`. Each `SELECT` wrapped in `SET STATEMENT max_statement_time=60 FOR`; session `SET SESSION TRANSACTION READ ONLY`.

- [ ] Tests: statements contain only `SELECT`/`SET`, refuse a bad prefix or database name, carry the cursor; `parse_line` round-trips a value with tabs, newlines and invalid UTF-8; a forged line (wrong field count, odd hex) is dropped; cap arithmetic (`Capped` cursor is the last row taken).
- [ ] Implement; test; commit.

### Task 3: page fetch identity

**Files:** Modify `crates/hyperion-adapters/src/sitecheck.rs`.

**Produces:** `sitecheck::Identity { user_agent: &str, referer: Option<&str> }`, `sitecheck::fetch_as(url, host, resolve_to, keep_body, &Identity)`; `fetch` keeps its signature and delegates. `contentscan::{USER_AGENT = "Hyperion-ContentCheck/1 (+https://github.com/nechodom/hyperion)", CRAWLER_USER_AGENT, CRAWLER_REFERER}`.

- [ ] Test: the curl config carries the given user agent and referer, and the default is unchanged; commit.

### Task 4: judge and service

**Files:**
- Create: `crates/hyperion-core/src/service/content_scan.rs`, `crates/hyperion-core/src/service/tests/content_scan.rs`
- Modify: `service/mod.rs`, `service/wp_integrity.rs` (flag reader, scan-now also asks for content), `service/scan_actions.rs` or new fns for trust.

**Produces:**
- `Baseline { since, rule_pack, keys: BTreeMap<String, BaseKey { first_seen, last_seen, trusted }>, cursor }` in `hosting_kv` `content_baseline`; result in `content_scan`; request in `content_scan_requested`.
- `trait ContentSource { async fn db_rows(..) ; async fn page(url, identity) }` with a real and a fake implementation.
- `judge(baseline, observed: Observed, prior, now) -> ContentScanResult` (pure).
- `Service::{content_scan_site_with, content_scan_stored, content_trust, content_trust_all_review, content_scan_tick, content_scan_tick_at, content_live}`.

- [ ] Tests (acceptance 1–7 of the spec, with a fake source): October-shaped rows in post content, widget option and `_elementor_data`; quiet second sweep, one new host = one new key; first scan lists hidden link as finding and video embed as "already here" review; `partial_layer_carries_prior_items`; link burst at 10; key expiry after 30 days only on a complete sweep; cloaked host; refused crawler view = note, no finding; `wp-config.php` naming a foreign database refused; trust removes and silences; tick does nothing right after a restart for sites scanned tonight.
- [ ] Implement; `cargo test -p hyperion-core content_scan`; commit.

### Task 5: tick, RPC, card, hctl

**Files:** `bin/hyperion-agent/src/ticks.rs`, `crates/hyperion-rpc/src/codec.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `bin/hyperion-web/src/handlers/hostings/integrity.rs`, `bin/hyperion-web/src/lib.rs`, `bin/hyperion-web/templates/_hosting_integrity_card.html`, `bin/hctl/src/print.rs` (+ caller), `docs/cli.md` if guarded.

**Produces:** `Request::{ContentScanStored, ContentTrust, ContentTrustAllReview}`, `Response::ContentScan(Option<ContentScanResult>)`; routes `/hostings/integrity/content-trust` and `/hostings/integrity/content-trust-all`; `spawn_content_scan`.

- [ ] Tests: card renders findings, review, pilot note, coverage line; without a result the old sentence stays; Trust forms only with the capability, confirm attributes on the `<form>`; hctl block.
- [ ] Implement; test; commit.

### Task 6: alerts behind the flag

**Files:** `crates/hyperion-core/src/letters.rs`, `service/content_scan.rs`.

- [ ] Tests: flag off = zero notifications and review items marked as told; flag on = one `ops.content` per site per sweep for unnotified findings, one `ops.content_review` for new review items, none for "already here"; flipping the flag notifies standing findings once; letters exist in en and cs.
- [ ] Implement; `cargo test --workspace`; `cargo clippy --workspace --all-targets`; commit.
