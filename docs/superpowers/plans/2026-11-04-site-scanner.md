# Site Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the ClamAV-centred, wp-cli-driven integrity scan with a native, capped scanner that catches the a client site compromise, needs nothing installed, and runs no tenant code.

**Architecture:** A new `sitescan` module in `hyperion-adapters` holds pure, testable pieces (safe walker, rule pack, manifests, baseline, per-site scan). The agent binary gets a hidden `scan-worker` subcommand that runs them in a capped, read-only transient unit. `wp_integrity.rs` becomes the scheduler and result store; the web panel only reads stored results.

**Tech Stack:** Rust 1.96, tokio, rustix (`openat`, `O_NOFOLLOW`), regex, sha2, md-5 (new, 0.10), zip, flate2, curl subprocess, askama, htmx, SQLite `hosting_kv`/`node_kv`.

**Spec:** `docs/superpowers/specs/2026-11-04-site-scanner-design.md`

## Global Constraints

- Scanning never runs wp-cli or any tenant PHP. Repair and reinstall actions may.
- Worker caps: `MemoryMax=256M CPUWeight=10 IOWeight=10 Nice=19 IOSchedulingClass=idle`, `CPUQuota=50%` on <=2 cores else `100%`, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH NoNewPrivileges=yes PrivateNetwork=yes ProtectSystem=strict ReadWritePaths=/var/lib/hyperion/scan`.
- One worker per node. Oldest-scanned site first. "Scan now" goes to the front of the queue.
- Change detection: size + ctime, then SHA-256. Never mtime.
- Rule inspection cap: 2 MiB per file. Larger PHP = "too large to inspect" finding, never skipped silently.
- Schedule: tick every 10 min with node_kv stamps. First scan any time; delta every 6 h; full re-hash weekly, one seventh of sites per night, inside 02:00–06:00 local.
- ClamAV: optional, one `clamscan` per sweep via `--file-list`, weekly, only with `MemAvailable` >= 2 GiB. OOM kill backs off 7 days.
- Quarantine at `/var/lib/hyperion/quarantine/<hosting_id>/<id>`, root 0600, purged after 90 days. Automatic quarantine off.
- Package URLs may hold licence keys: never on argv, never logged, never stored.
- All new wire and stored fields `#[serde(default)]`. Product text English; letter strings in `letters.rs` (en + cs). `docs/cli.md` is test-guarded.
- Honesty: what didn't run is "couldn't check", never clean. New layers are report-only until the pilot flag flips.
- Tests must pass on macOS and in Linux. Linux-only behaviour goes behind `#[cfg(target_os = "linux")]`.
- Real malware samples never enter the repo. Fixtures are defanged and synthetic.
- Commit on this branch per task. No push and no PR until the owner asks.

## Review Focus

- A Czech site (`$wp_local_package = 'cs_CZ'`): core checksums must come from that locale, falling back to `en_US`. Must not flag translated core files. Test in Task 5.
- WordPress broken, partly installed, version unparsable, or `wp-config.php` above the docroot: "couldn't check", never clean. Test in Task 7.
- Very large docroot (500k files, `node_modules`): stops at a file cap with a partial verdict, stays under `MemoryMax`, never clean. Test in Task 7.
- Non-UTF-8 file names, files vanishing mid-walk, unreadable directories: no panic, no lost findings, reported as partial. Test in Task 3.
- A private plugin whose slug collides with a wordpress.org slug, and a single-file plugin (`wp-content/plugins/hello.php`): slug collision must not raise hundreds of high-severity findings at once; single-file plugin must verify. Test in Task 5.

---

## Part 1: stop the bleeding

### Task 1: Panel reads stored results; "Scan now" becomes a job

**Files:**
- Modify: `crates/hyperion-rpc/src/codec.rs`, `crates/hyperion-rpc/src/api.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`, `crates/hyperion-core/src/service/wp_integrity.rs`
- Modify: `bin/hyperion-web/src/handlers/hostings/integrity.rs`, `bin/hyperion-web/templates/_hosting_integrity_card.html`, `bin/hyperion-web/src/dispatcher.rs`
- Test: `bin/hyperion-web/src/handlers/hostings/tests.rs`, `crates/hyperion-core/src/service/tests/wp_integrity.rs`

**Interfaces:**
- Produces: `Request::WpIntegrityStored { hosting: HostingSelector }` answered by `Response::WpIntegrityScan`; `HostingService::wp_integrity_stored(sel) -> Result<WpIntegrityScanResult, RpcError>`. New field `WpIntegrityScanResult.scan_queued: bool`.

- [ ] **Step 1: Write failing tests.** `wp_integrity_stored_never_spawns_a_scan`: with no stored record returns `scanned_at == 0`, `is_clean() == false`, and no process-spawning adapter call. `integrity_panel_get_dispatches_stored_not_scan` in web tests.
- [ ] **Step 2: Run them.** `cargo test -p hyperion-core wp_integrity_stored` — expect FAIL, method not defined.
- [ ] **Step 3: Implement.** `get_integrity_panel` dispatches `WpIntegrityStored`. An old node answering with an unknown-request error renders `integrity_not_checked("this node needs updating to show scan results")`. `post_integrity_scan` uses `spawn_job` (kind `integrity_scan`) and returns the card with `scan_queued = true`; the card polls itself with `hx-trigger="every 10s"` only while queued. `integrity_fix` re-scan goes through the same job.
- [ ] **Step 4: Run.** `cargo test -p hyperion-core -p hyperion-web integrity` — expect PASS.
- [ ] **Step 5: Commit.** `fix(integrity): opening a page no longer starts a scan`

### Task 2: ClamAV keeps hits on exit 2; integrity tick stops firing on restart

**Files:**
- Modify: `crates/hyperion-adapters/src/integrity.rs`, `crates/hyperion-core/src/service/wp_integrity.rs`, `bin/hyperion-agent/src/ticks.rs`
- Test: `crates/hyperion-core/src/service/tests/wp_integrity.rs`, unit tests in `integrity.rs`

**Interfaces:**
- Produces: `MalwareScan.partial: bool`; `integrity::clamav_db_present() -> bool` (any `*.cvd`/`*.cld` in `/var/lib/clamav`); pure `classify_clamscan(code: i32, stdout: &str) -> MalwareScan`.

- [ ] **Step 1: Write failing tests.** `exit_two_keeps_real_hits_and_marks_partial`, `exit_zero_is_not_partial`, `missing_signature_db_is_not_a_failure`, `integrity_tick_does_not_rerun_after_restart` (via a `node_kv` stamp and an injected clock, same shape as `wp_defender_tick_at`).
- [ ] **Step 2: Run them.** `cargo test -p hyperion-adapters clamscan` — expect FAIL.
- [ ] **Step 3: Implement.** Exit 2 returns hits with `partial = true`, and the caller records "partial" without a failure back-off when hits exist. Missing database: "signatures still downloading", not an error. Replace `every(svc, 6*MIN, DAY, ...)` with a 10-minute check and the `integrity_last_run_at` stamp.
- [ ] **Step 4: Run.** `cargo test -p hyperion-adapters -p hyperion-core integrity` — expect PASS.
- [ ] **Step 5: Commit.** `fix(integrity): keep ClamAV hits from a partial pass; survive restarts`

---

## Part 2: the scanner

### Task 3: Safe walker

**Files:**
- Create: `crates/hyperion-adapters/src/sitescan/mod.rs`, `crates/hyperion-adapters/src/sitescan/walk.rs`
- Modify: `crates/hyperion-adapters/src/lib.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct WalkOpts { pub max_files: u64, pub prune: Vec<String> }
  pub struct FileMeta { pub rel: String, pub size: u64, pub ctime: i64, pub mode: u32, pub uid: u32, pub nlink: u64 }
  pub enum WalkEvent<'a> { File(&'a FileMeta), Skipped { rel: String, why: SkipReason } }
  pub enum SkipReason { Symlink, NotRegular, HardLinked, Unreadable, NonUtf8Name, Vanished, FileCapReached }
  pub struct WalkStats { pub files: u64, pub skipped: u64, pub capped: bool }
  pub fn walk(root: &Path, opts: &WalkOpts, visit: impl FnMut(WalkEvent<'_>)) -> io::Result<WalkStats>;
  pub fn open_file_at(root: &Path, rel: &str) -> io::Result<std::fs::File>; // re-walks by dirfd, NOFOLLOW
  ```

- [ ] **Step 1: Write failing tests.** `symlink_to_outside_is_reported_not_followed`, `fifo_does_not_hang`, `hard_linked_file_is_skipped`, `non_utf8_name_is_reported`, `symlink_swapped_for_dir_is_not_entered`, `open_file_at_refuses_symlinked_parent`, `file_cap_sets_capped`, `stays_on_one_filesystem` (linux only), `ctime_not_mtime_is_reported` (set mtime to 2024 with `utimensat`, assert `ctime` is recent).
- [ ] **Step 2: Run.** `cargo test -p hyperion-adapters sitescan::walk` — expect FAIL.
- [ ] **Step 3: Implement** with rustix: open root `O_DIRECTORY|O_NOFOLLOW`, descend with `openat(dirfd, name, O_DIRECTORY|O_NOFOLLOW)`, `statat` with `AT_SYMLINK_NOFOLLOW`. Compare `st_dev` to the root's. Iterative with an explicit stack, so deep trees can't overflow.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(sitescan): safe tenant-tree walker`

### Task 4: Rule pack with incident fixtures

**Files:**
- Create: `crates/hyperion-adapters/src/sitescan/rules.rs`, `crates/hyperion-adapters/tests/fixtures/sitescan/` (defanged samples)

**Interfaces:**
- Produces:
  ```rust
  pub const RULE_PACK_VERSION: u32;
  pub enum Severity { Medium, High }
  pub struct RuleHit { pub rule_id: &'static str, pub severity: Severity, pub line: u32, pub domains: Vec<String>, pub snippet: String }
  pub const INSPECT_MAX_BYTES: usize = 2 * 1024 * 1024;
  pub fn inspect(rel_path: &str, bytes: &[u8]) -> Vec<RuleHit>;
  pub fn is_php_like(rel_path: &str) -> bool;
  ```

- [ ] **Step 1: Write fixtures and failing tests.** One per incident row: `appended_js_loader.js` (minified body + tail creating a remote `<script>` that removes itself), `fake403_shell.php` (password gate, `header('HTTP/1.1 403')`, b374k marker, inert payload), `fake_doctrine.php` (`namespace Doctrine\Http; eval(base64_decode('ZWNobyAnJzs='));`), `functions_footer.php` (`add_action('wp_footer', ...)` + 4 kB encoded literal). Assert: high on shell and eval sample, at least medium on JS loader and footer sample, domains contain the fake host. Negatives: `clean_functions.php`, `clean_minified.js` with plain `eval` absent. `php_under_uploads_is_high`, `snippet_at_most_120_chars`, `binary_input_does_not_panic`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-adapters sitescan::rules` — expect FAIL.
- [ ] **Step 3: Implement** using the rule list in spec Layer C with `regex::bytes::RegexSet`, compiled once via `LazyLock`, then per-rule matching only for rules the set flags.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(sitescan): PHP-focused rule pack`

### Task 5: Manifests

**Files:**
- Create: `crates/hyperion-adapters/src/sitescan/manifest.rs`, `crates/hyperion-adapters/src/sitescan/discover.rs`
- Modify: `Cargo.toml`, `crates/hyperion-adapters/Cargo.toml` (add `md-5 = "0.10"`)

**Interfaces:**
- Consumes: `walk::open_file_at`.
- Produces:
  ```rust
  pub enum Digest { Md5([u8;16]), Sha256([u8;32]) }
  pub enum ManifestSource { WordPressOrg, VendorPackage }
  pub struct Manifest { pub source: ManifestSource, pub files: BTreeMap<String, Digest> } // Serialize
  pub enum ComponentKind { Core, Plugin, Theme }
  pub struct ComponentKey { pub kind: ComponentKind, pub slug: String, pub version: String, pub locale: Option<String> }
  pub fn parse_core_checksums(json: &str) -> Result<BTreeMap<String, Digest>, AdapterError>;
  pub fn parse_plugin_checksums(json: &str) -> Result<BTreeMap<String, Digest>, AdapterError>; // prefer sha256
  pub fn manifest_from_zip(path: &Path, expected: &ComponentKey) -> Result<Manifest, AdapterError>; // header version must match
  pub fn cache_path(cache_dir: &Path, key: &ComponentKey) -> PathBuf;
  pub async fn fetch_wporg_manifest(key: &ComponentKey, cache_dir: &Path) -> Result<Option<Manifest>, AdapterError>; // None = 404, unverifiable
  // discover.rs — parse only, never execute
  pub struct Component { pub key: ComponentKey, pub rel_root: String, pub is_child_theme: bool }
  pub struct Discovery { pub is_wordpress: bool, pub components: Vec<Component>, pub problems: Vec<String> }
  pub fn discover(root: &Path) -> Discovery;
  ```

- [ ] **Step 1: Write failing tests.** `czech_locale_is_read_from_version_php`, `core_falls_back_to_en_us_when_locale_has_no_checksums`, `plugin_prefers_sha256`, `plugin_md5_array_accepted`, `header_parser_ignores_commented_version`, `single_file_plugin_discovered`, `theme_version_from_style_css`, `child_theme_flagged_by_template_header`, `zip_with_wrong_version_is_rejected`, `zip_bomb_entry_over_cap_is_rejected`, `zip_path_traversal_entry_rejected`, `cache_key_rejects_path_chars_in_slug_and_version`, `readme_is_soft_file`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-adapters sitescan::manifest` — expect FAIL.
- [ ] **Step 3: Implement.** URLs from spec Layer A; curl with `--proto =https --max-filesize` and argv-only constants, matching `service/net.rs`. Slug regex `^[a-z0-9][a-z0-9._-]{0,127}$`, version `^[0-9A-Za-z._+-]{1,64}$`; refuse otherwise (both come from tenant files). Theme manifests come from downloading the ZIP to a temp file in the cache dir, then `manifest_from_zip`, then delete. A cached 404 retries after 24 h.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(sitescan): parse-only discovery and upstream manifests`

### Task 6: Baseline

**Files:**
- Create: `crates/hyperion-adapters/src/sitescan/baseline.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct BaselineEntry { pub size: u64, pub ctime: i64, pub sha256: [u8;32] }
  pub struct Baseline { pub since: i64, pub rule_pack: u32, pub entries: BTreeMap<String, BaselineEntry>, pub trusted: BTreeMap<String,[u8;32]> }
  impl Baseline {
      pub fn load(path: &Path) -> io::Result<Option<Baseline>>; // corrupt = None, rescan as first
      pub fn save_atomic(&self, path: &Path) -> io::Result<()>; // gz JSON lines, 0600, tmp + rename + fsync
  }
  pub enum Change { New, Changed, Unchanged }
  pub fn classify(entry: Option<&BaselineEntry>, meta: &FileMeta) -> ChangeHint; // Unchanged needs size+ctime match
  ```

- [ ] **Step 1: Write failing tests.** `forged_mtime_is_still_a_change` (rewrite content, restore mtime, ctime moved), `same_size_and_ctime_needs_no_hash`, `roundtrip_preserves_entries`, `corrupt_file_loads_as_none`, `save_is_atomic_and_0600`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-adapters sitescan::baseline` — expect FAIL.
- [ ] **Step 3: Implement** with flate2 and serde_json lines.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(sitescan): per-hosting baseline store`

### Task 7: Per-site scan, with the incident as the acceptance test

**Files:**
- Create: `crates/hyperion-adapters/src/sitescan/scan.rs`, `crates/hyperion-adapters/tests/sitescan_incident.rs`
- Modify: `crates/hyperion-types/src/wp.rs`, `crates/hyperion-types/src/lib.rs`

**Interfaces:**
- Consumes: Tasks 3–6.
- Produces, in `hyperion-types`:
  ```rust
  pub enum FindingKind { CoreModified, CoreUnexpected, CoreMissing, UpstreamModified, UpstreamAdded, RuleHit, TooLargeToInspect, BaselineChange }
  pub struct SiteFileFinding { pub rel: String, pub kind: FindingKind, pub severity: String, pub rule_id: Option<String>, pub line: u32, pub domains: Vec<String>, pub snippet: String, pub sha256: String, pub component: Option<String>, pub source_label: Option<String> }
  pub struct ScanCoverage { pub plugins_verified: i64, pub plugins_total: i64, pub themes_verified: i64, pub themes_total: i64, pub files_watched: i64, pub watching_since: i64, pub upstream_ran: bool, pub partial_reasons: Vec<String> }
  ```
  added to `WpIntegrityScanResult` with `#[serde(default)]`: `native_scan_ran: bool`, `report_only: bool`, `findings: Vec<SiteFileFinding>`, `review: Vec<SiteFileFinding>`, `themes_failed: Vec<WpIntegrityPluginResult>`, `coverage: ScanCoverage`.
- Produces, in `scan.rs`:
  ```rust
  pub struct ScanInput { pub root: PathBuf, pub is_static_or_php_only: bool, pub manifests_dir: PathBuf, pub baseline_path: PathBuf, pub mode: ScanMode, pub now: i64, pub accept_since: Option<(WriterKind, i64)> }
  pub enum ScanMode { Delta, FullRehash }
  pub enum WriterKind { GitDeploy, Restore }
  pub fn scan_site(input: &ScanInput, pause: &dyn Fn()) -> Result<SiteScanOutcome, AdapterError>;
  pub struct SiteScanOutcome { pub upstream: UpstreamResult, pub findings: Vec<SiteFileFinding>, pub review: Vec<SiteFileFinding>, pub coverage: ScanCoverage }
  ```

- [ ] **Step 1: Write the incident test.** Build a temp WordPress tree with fixture manifests pre-seeded in the cache dir. Plant each row of the spec's table: mismatched `elementor/assets/lib/swiper/swiper.min.js`; webshell at root and again in `wp-content/`; `wp-includes/class-wp-strongers.php` with forged mtime; extra file in a verified plugin; appended `woocommerce/.../js.cookie.min.js`; child theme `functions.php` edited after the first scan. Assert each is found, by the expected `FindingKind`. Also `seo_spam_is_not_claimed` is documented as not covered.
- [ ] **Step 2: Add failing tests.** `no_php_is_executed` (a fixture `wp-config.php`, `functions.php` and plugin that would write a marker file; assert no marker and no `php`/`wp` child spawned), `premium_plugin_change_without_rule_is_review_not_finding`, `premium_version_bump_auto_accepted_when_slug_unknown_to_wporg`, `wporg_slug_with_no_manifest_goes_to_review_after_retry`, `slug_collision_groups_to_one_finding` (> 50% of a plugin's files differ: one component-level finding, not hundreds), `first_scan_runs_rules_over_everything`, `first_scan_does_not_report_changes`, `trusted_hash_clears_review`, `trust_does_not_clear_upstream_failure`, `broken_wordpress_is_not_clean`, `file_cap_gives_partial`, `non_wp_site_watches_php_not_vendor_js`, `verified_tree_files_are_not_rule_inspected`, `rule_pack_bump_reinspects_once`.
- [ ] **Step 3: Run.** `cargo test -p hyperion-adapters --test sitescan_incident` — expect FAIL.
- [ ] **Step 4: Implement** following spec layers. Files under a verified component compare against the manifest; everything else goes through baseline and rules. Hash with a 64 KiB streaming buffer. Flush the baseline every 500 hashed files so a killed worker resumes. Call `pause()` every 256 files.
- [ ] **Step 5: Run** — expect PASS.
- [ ] **Step 6: Commit.** `feat(sitescan): per-site scan catching every stage of the incident`

### Task 8: Capped worker

**Files:**
- Create: `crates/hyperion-adapters/src/sitescan/runner.rs`, `crates/hyperion-adapters/src/sitescan/pressure.rs`
- Modify: `bin/hyperion-agent/src/main.rs`

**Interfaces:**
- Consumes: `scan_site`, `discover`.
- Produces:
  ```rust
  pub enum WorkerJob { Discover { root: PathBuf }, Scan(ScanInput) } // JSON on stdin
  pub enum WorkerReply { Discovery(Discovery), Scan(SiteScanOutcome), Failed(String) } // JSON on stdout
  pub fn unit_args(cores: usize, exe: &Path) -> Vec<String>;
  pub async fn run_worker(job: &WorkerJob, exe: &Path) -> Result<WorkerReply, AdapterError>;
  pub fn is_under_pressure(load1: f64, cores: usize, psi_some_avg10: Option<f64>) -> bool;
  ```
  Hidden clap subcommand `Command::ScanWorker`.

- [ ] **Step 1: Write failing tests.** `unit_args_contain_every_cap` asserts each value in Global Constraints, `cpu_quota_is_50_on_two_cores_100_on_eight`, `pressure_true_when_load_exceeds_cores`, `pressure_none_psi_uses_load_only`, `worker_roundtrip_direct_mode` (spawn the built binary without systemd), `killed_worker_is_failed_not_clean`, `oversized_reply_is_refused`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-adapters sitescan::runner` — expect FAIL.
- [ ] **Step 3: Implement.** `systemd-run --wait --pipe --collect` plus `-p` args and `ReadOnlyPaths=/home`. Missing `systemd-run` means direct spawn under `nice`, logged once. Worker must not initialise tokio or read `agent.toml`. Pressure pause sleeps in 30 s steps up to 30 min, then returns partial.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(sitescan): capped read-only scan worker`

### Task 9: Scheduler and result store

**Files:**
- Create: `crates/hyperion-core/src/service/scan_queue.rs`
- Modify: `crates/hyperion-core/src/service/wp_integrity.rs`, `crates/hyperion-core/src/service/mod.rs`, `crates/hyperion-core/src/service/trash.rs`, `bin/hyperion-agent/src/ticks.rs`
- Test: `crates/hyperion-core/src/service/tests/wp_integrity.rs`

**Interfaces:**
- Consumes: `run_worker`, `fetch_wporg_manifest`.
- Produces: `HostingService::site_scan_tick(&self) -> Result<i64, RpcError>`; `site_scan_enqueue(&self, id: &HostingId, front: bool)`; pure `site_scan_due(prior: Option<&StoredIntegrityScan>, now, tz, id) -> Option<ScanMode>`; `SCAN_DIR = "/var/lib/hyperion/scan"`; config `[integrity] new_layers_live: bool` (default false). `StoredIntegrityScan` gains `full_at: i64`.

- [ ] **Step 1: Write failing tests.** `new_hosting_is_due_immediately_any_time_of_day`, `delta_due_after_six_hours`, `full_rehash_only_in_night_window_and_only_its_weekday`, `seventh_of_sites_per_night_is_stable`, `restart_does_not_retrigger`, `reverse_proxy_is_skipped`, `scan_now_goes_to_front`, `only_one_worker_at_a_time`, `failed_run_keeps_prior_findings`, `purge_removes_baseline_and_quarantine_dir`, `new_layer_findings_do_not_alert_in_report_only`, `upstream_failures_still_alert_in_report_only`, `opted_out_hosting_is_skipped`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-core site_scan` — expect FAIL.
- [ ] **Step 3: Implement.** Discover, fetch manifests in the agent, scan in the worker, store in `integrity_scan` KV and map onto existing `core_*`/`plugins_*` fields so reports and dashboard keep working. `wp_integrity_scan` enqueues at the front and awaits that site. Remove the wp-cli calls from it.
- [ ] **Step 4: Run.** `cargo test -p hyperion-core` — expect PASS. Update tests that assert wp-cli behaviour.
- [ ] **Step 5: Commit.** `feat(integrity): native scan replaces wp-cli, report-only for new layers`

---

## Part 3: panel and actions

### Task 10: Card states and non-WordPress hostings

**Files:**
- Modify: `bin/hyperion-web/templates/_hosting_integrity_card.html`, `bin/hyperion-web/templates/hostings_detail.html`, `bin/hyperion-web/src/handlers/hostings/tests.rs`, `crates/hyperion-types/src/wp.rs`

**Interfaces:**
- Produces: `WpIntegrityScanResult::verdict(&self) -> ScanVerdict` with `Findings, Review, Clean, Partial, Running, Never`; `findings_visible()`.

- [ ] **Step 1: Write failing render tests.** One per verdict, `coverage_line_names_database_not_scanned`, `coverage_line_counts_themes`, `pilot_label_shown_while_report_only`, `watching_since_shown_after_first_scan`, `partial_names_what_did_not_run`, `snippet_is_escaped`, `card_on_overview_tab_for_php_kind_without_wordpress`, `no_card_for_reverse_proxy`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-web integrity` — expect FAIL.
- [ ] **Step 3: Implement.** Keep the existing `.chk-row` design. Non-WordPress hostings get the same lazy card on the overview tab.
- [ ] **Step 4: Verify in the dev panel.** `preview_start devpanel`, screenshot each state with seeded KV data.
- [ ] **Step 5: Commit.** `feat(integrity): verdict states and honest coverage line`

### Task 11: Quarantine, restore, trust, reinstall theme

**Files:**
- Create: `crates/hyperion-core/src/service/scan_actions.rs`, `crates/hyperion-adapters/src/sitescan/quarantine.rs`
- Modify: `crates/hyperion-state/src/capabilities.rs`, `crates/hyperion-rpc/src/codec.rs`, `crates/hyperion-rpc/src/api.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`, `bin/hyperion-web/src/handlers/hostings/integrity.rs`, `bin/hyperion-web/src/lib.rs`, `bin/hyperion-web/templates/_hosting_integrity_card.html`, `crates/hyperion-core/src/service/migration.rs`

**Interfaces:**
- Produces: `Capability::WpScanTrust` (`"wp_scan_trust"`, Admin and Operator, not Customer or Viewer). RPCs `ScanFileQuarantine { hosting, rel, sha256 }`, `ScanFileRestore { hosting, id }`, `ScanFileTrust { hosting, rel, sha256 }`, `ScanTrustAllReview { hosting }`, `ScanQuarantineList { hosting }`. KV `scan_trust` added to `carried_kv_scope`.

- [ ] **Step 1: Write failing tests.** `quarantine_moves_file_and_records_metadata`, `quarantine_refuses_symlink_and_path_escape`, `quarantine_refuses_when_hash_changed_since_scan`, `restore_refuses_occupied_path`, `restore_keeps_owner_and_mode`, `purge_after_90_days`, `customer_cannot_trust_but_can_quarantine`, `viewer_can_do_neither`, `trust_refuses_upstream_failure`, `trust_all_excludes_rule_hits`, `trust_cleared_when_content_changes`, `trust_travels_with_copy`, `actions_are_audited`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-core scan_actions` — expect FAIL.
- [ ] **Step 3: Implement.** `quarantine.rs` uses dirfd-based `renameat`, falling back to copy + fsync + `unlinkat` across filesystems. Trust writes into the baseline `trusted` map through the agent only. Confirm attributes go on the `<form>`. Reinstall theme reuses `WpPluginAction`'s pattern for wordpress.org themes.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(integrity): quarantine, restore and operator-only trust`

### Task 12: Hyperion's own writes

**Files:**
- Modify: `crates/hyperion-adapters/src/sitescan/scan.rs`, `crates/hyperion-adapters/src/wpplugin.rs`, `crates/hyperion-adapters/src/regguard.rs`, `crates/hyperion-adapters/src/wpmail.rs`, `crates/hyperion-core/src/service/git_sync.rs`, `crates/hyperion-core/src/service/backups.rs`, `crates/hyperion-core/src/service/scan_queue.rs`

**Interfaces:**
- Consumes: `ScanInput.accept_since`.
- Produces: `sitescan::own_manifest() -> BTreeMap<String, Digest>` built from the embedded content, each module exposing its embedded file list; `HostingService::scan_mark_writer(&self, id, WriterKind)` writing KV `scan_pending_accept` and enqueuing at the front.

- [ ] **Step 1: Write failing tests.** `own_mu_plugin_matches_after_agent_update_no_review`, `tampered_own_mu_plugin_is_finding`, `git_deploy_changes_accepted_when_no_rule_hit`, `git_deploy_rule_hit_is_finding`, `restore_of_infected_backup_is_flagged`, `file_manager_edit_is_review`, `copied_site_starts_fresh_with_rules`.
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement.** Files accepted through a writer get `source_label` "changed by deploy" / "changed by restore". Files whose ctime is older than the mark go through the normal flow.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(integrity): own writes don't raise false alarms`

---

## Part 4: premium, reports, ClamAV

### Task 13: Automatic premium package download

**Files:**
- Create: `crates/hyperion-adapters/src/sitescan/vendor.rs`
- Modify: `crates/hyperion-adapters/src/mariadb.rs`, `crates/hyperion-core/src/service/scan_queue.rs`

**Interfaces:**
- Consumes: `manifest_from_zip`, `Discovery`.
- Produces:
  ```rust
  pub enum PackageBucket { Response, NoUpdate }
  pub struct PackageRef { pub kind: ComponentKind, pub slug: String, pub version: Option<String>, pub url: Secret, pub bucket: PackageBucket }
  pub struct Secret(String); // Debug and Display print "<redacted>"
  pub fn parse_wp_config_db(text: &str) -> Option<(String, String)>; // DB_NAME, $table_prefix; regex only
  pub fn parse_update_transient(value: &str, kind: ComponentKind) -> Vec<PackageRef>; // no unserialize
  pub fn vendor_host_allowed(host: &str) -> bool;
  pub fn redirect_host_allowed(host: &str) -> bool;
  pub async fn download_package(url: &Secret, dest: &Path) -> Result<(), VendorError>; // VendorError::UnknownHost(String) carries the host only
  ```
  `mariadb::read_option(db: &str, prefix: &str, option: &str) -> Result<Option<String>, AdapterError>`, with `prefix` matching `^[A-Za-z0-9_]{1,64}$`. `ScanCoverage` gains `unknown_vendor_hosts: Vec<String>`.

- [ ] **Step 1: Write failing tests.** `parses_response_and_no_update_entries` on real-shaped serialized transients, `garbage_transient_yields_nothing`, `malicious_prefix_is_refused`, `http_url_refused`, `unknown_host_is_recorded_not_fetched`, `private_ip_refused`, `redirect_to_private_ip_refused`, `redirect_off_allowlist_refused` (against a local test HTTP server), `secret_never_in_debug_output`, `url_not_on_argv` (asserts the argv built for curl has no URL; passed through `--config -` on stdin), `zip_version_mismatch_discards_manifest`, `one_site_fills_cache_for_all`, `failed_download_backs_off_per_slug_and_version`, `added_file_is_review_changed_file_is_finding`, `no_update_verifies_current_version_response_only_prepares_next`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-adapters sitescan::vendor` — expect FAIL.
- [ ] **Step 3: Implement.** Initial hosts: `my.elementor.com`, `connect.advancedcustomfields.com`, `wp-rocket.me`, `my.yoast.com`, `wpml.org`, `wpforms.com`. Redirect-only CDNs: `*.s3.amazonaws.com`, `*.cloudfront.net`. None of these are confirmed against real licences; the test report must say so. Follow redirects manually with `--max-redirs 0`, re-checking each hop, same as `sitecheck.rs`. Size cap 200 MiB. Runs in the agent, between discover and scan.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(sitescan): verify premium plugins from the package WordPress already knows`

### Task 14: Share manifests and compare across sites

**Files:**
- Create: `bin/hyperion-web/src/scan_fleet.rs`, `crates/hyperion-types/src/scan_fleet.rs`
- Modify: `crates/hyperion-rpc/src/codec.rs`, `crates/hyperion-rpc/src/api.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`, `crates/hyperion-core/src/service/scan_queue.rs`, `bin/hyperion-web/src/lib.rs`

**Interfaces:**
- Produces: RPCs `ScanFleetExport -> Vec<ComponentReport { key, hosting_id, tree_hash, has_manifest }>`, `ScanManifestGet { key }`, `ScanManifestPut { key, manifest }`, `ScanFleetVerdicts { Vec<OutlierVerdict { hosting_id, key, peers: i64, majority_manifest: Manifest }> }`. Pure `find_outliers(reports: &[ComponentReport]) -> Vec<Outlier>`.

- [ ] **Step 1: Write failing tests.** `outlier_needs_at_least_three_sites`, `two_sites_differing_is_no_verdict`, `no_strict_majority_is_no_verdict`, `all_identical_is_not_verified`, `outlier_files_are_review_or_finding_on_rule_hit`, `label_says_same_as_n_other_sites`, `customer_view_has_no_other_domains`, `manifest_from_one_node_reaches_others`, `offline_node_does_not_block`, `old_node_unknown_rpc_is_skipped`.
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement** an hourly web-side tick, modelled on `wp_library.rs`. Only hashes and manifests travel, never file contents or licence data.
- [ ] **Step 4: Run** — expect PASS.
- [ ] **Step 5: Commit.** `feat(sitescan): share manifests and compare copies across sites`

### Task 15: Reports, letters, alerts switch, CLI

**Files:**
- Modify: `crates/hyperion-types/src/wp.rs`, `crates/hyperion-types/src/package.rs`, `crates/hyperion-state/src/reports.rs`, `crates/hyperion-core/src/service/care_report.rs`, `crates/hyperion-core/src/letters.rs`, `bin/hctl/src/print.rs`, `docs/cli.md`, `README.md`

**Interfaces:**
- Produces: `CareIntegrity` gains `rule_hits: i64`, `review_pending: i64`, `no_upstream: bool`. `is_clean()` per spec when `native_scan_ran && !report_only`; old logic otherwise.

- [ ] **Step 1: Write failing tests.** `old_stored_record_keeps_old_meaning`, `report_only_record_uses_old_logic`, `live_clean_needs_no_clamav`, `live_review_pending_blocks_clean_with_own_wording`, `non_wp_letter_never_mentions_wordpress_org`, `first_scan_alerts_high_only`, `alert_batches_review_per_site`, `letters_exist_in_en_and_cs`, `hctl_prints_verdict_and_coverage`.
- [ ] **Step 2: Run.** `cargo test -p hyperion-types -p hyperion-state -p hyperion-core care` — expect FAIL.
- [ ] **Step 3: Implement.** New alerts go behind `new_layers_live`, default false. Update `reports.rs`'s mirror struct in step.
- [ ] **Step 4: Run.** `cargo test --workspace` — expect PASS, including the `docs/cli.md` guard.
- [ ] **Step 5: Commit.** `feat(care): reports and alerts understand the new scan`

### Task 16: ClamAV as a bounded extra

**Files:**
- Modify: `crates/hyperion-adapters/src/integrity.rs`, `crates/hyperion-core/src/service/scan_queue.rs`, `crates/hyperion-core/src/service/wp_integrity.rs`, `crates/hyperion-core/src/service/system.rs`, `bin/hyperion-web/templates/_hosting_integrity_card.html`

**Interfaces:**
- Produces: `clamav_sweep(lists: &[(HostingId, Vec<String>)], list_path: &Path) -> Result<ClamSweep, AdapterError>`; pure `attribute_hits(hits, roots) -> HashMap<HostingId, Vec<WpMalwareHit>>`; `clamav_preflight(mem_available: u64, db_present: bool, backoff_until: i64, now: i64) -> ClamPreflight` (`Run`, `SkipLowMemory`, `SignaturesDownloading`, `BackingOff`, `NotInstalled`).

- [ ] **Step 1: Write failing tests.** `one_process_per_sweep_with_file_list`, `hits_attributed_by_path_prefix_not_substring` (`/home/a/htdocs2` must not match `/home/a/htdocs`), `low_memory_is_skip_not_failure_and_does_not_block_clean`, `oom_kill_backs_off_seven_days`, `weekly_cadence_survives_restart`, `partial_keeps_hits`, `old_per_site_pass_is_gone`.
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement** using the walker for lists. Delete `integrity_malware_pass`, `CLAMAV_GATE` and the per-site cadence fields' use.
- [ ] **Step 4: Run.** `cargo test --workspace` — expect PASS.
- [ ] **Step 5: Commit.** `feat(integrity): one bounded ClamAV pass per sweep`

---

## Part 5: local verification

### Task 17: End-to-end on this machine

**Files:**
- Create: `packaging/dev/sitescan-e2e.sh`, `crates/hyperion-adapters/examples/rule_false_positives.rs`

- [ ] **Step 1: Create a Debian 12 VM with Lima** (`limactl start template://debian-12`): real systemd, which Docker on this Mac doesn't give cleanly. Build the agent for Linux inside it.
- [ ] **Step 2: Unit caps are real.** Run the worker through `run_worker`. Confirm from inside the unit that it can read a file in `/home/site` and can't write it (EPERM), has no network, and that `systemctl show` reports `MemoryMax=268435456`.
- [ ] **Step 3: Real WordPress.** Install current WordPress with `cs_CZ` plus free Elementor, WooCommerce and `hello-elementor` from wordpress.org. A clean scan must give zero findings. Plant the incident fixtures, delta scan, and confirm every row of the spec's table.
- [ ] **Step 4: Resource numbers.** 20k-file site: record peak RSS, wall time, and file reads on a second unchanged scan (`/proc/<pid>/io`). Must stay under `MemoryMax`; second scan hashes nothing. Put the numbers in the final report.
- [ ] **Step 5: False-positive check.** `cargo run --example rule_false_positives` over the current top 50 wordpress.org plugins and themes. Zero high-severity; list each medium.
- [ ] **Step 6: Vendor flow.** Local TLS test server standing in for a vendor: transient → download → manifest → verified. State plainly that real vendors are untested without licences.
- [ ] **Step 7: Panel.** `preview_start devpanel`, walk each card state and action, screenshot.
- [ ] **Step 8: Full suite.** `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` on macOS and in the VM. All pass.
- [ ] **Step 9: Commit.** `test(sitescan): local end-to-end check`

Not covered locally, to report plainly: real premium licences, real samples from the incident samples (needs the owner's go-ahead to copy them here), and a pilot on a live server. `new_layers_live` stays false until the owner has seen those.
