# Content monitor: injected content in the database and on rendered pages — design

Status: approved 2026-11-23; built behind `[integrity] content_live` (see "As built").

## Intent

A client's contract review asked whether integrity monitoring would have caught the
October incident, where hidden links were inserted into a site's database. The honest
answer today is no. The site scanner (`2026-11-04-site-scanner-design.md`) compares
files; it lists database content and rendered pages as non-goals, and the integrity
card says so in plain words: "The database is not scanned."

This project closes that gap. It watches what a WordPress site *says* rather than what
its files *are*: content stored in the database, and the HTML the site serves.

| Injection | Caught today? | After this design |
|---|---|---|
| Hidden links in a post, page or widget (inline style hides them) | No | Yes, database layer |
| `<script src>` to an unfamiliar host stored in a post, option or builder data | No | Yes, database layer and page layer |
| Encoded inline script (`atob` into `eval`, `document.write(unescape(…))`) in content | No | Yes, rules on both layers |
| Script or links printed by a tampered theme/plugin or an option-driven "header/footer scripts" plugin | Files only, if the file changed | Yes, page layer, whatever stored it |
| Links shown to search engines only (cloaking by user agent) | No | Yes, page layer's second view |
| Links hidden by a CSS class defined elsewhere | No | Host appears in the page layer's link inventory; not flagged as hidden |
| Content added by a script at run time in the browser | No | No (non-goal: nothing here runs JavaScript) |

## Goals

1. **Would have caught October.** A hidden link inserted into database content raises a
   finding within a day, naming where it sits and where it points.
2. **Only what is new speaks.** Same alert model as the scanner: a baseline per site,
   one notification per site per sweep, nothing repeated.
3. **Read-only, and runs no tenant code.** No wp-cli, no PHP, no write to the tenant's
   database, ever.
4. **Cheap.** One site at a time, at night, bounded rows, bytes and seconds. A handful
   of page requests a day per site.
5. **Honest.** What couldn't be read is "couldn't check", never clean. The card states
   what was covered and that scripts are not executed.
6. **Report-only pilot first**, behind a per-node flag, like the scanner's new layers.

## Non-goals

- Cleaning or editing database content. Findings are shown; a person fixes them.
- Running JavaScript (no headless browser). Pages are read as served HTML.
- Comments, users and usermeta (rogue admin accounts are a separate detection, worth a
  follow-up).
- Multisite sub-sites (`<prefix>N_posts`). The main site's tables only; the card says so.
- Non-MariaDB databases.
- Care reports and customer letters. They keep today's meaning until the owner has seen
  pilot results; wiring this into `is_clean()` and `letters.rs` is a later PR.
- Crawling the whole site. The database layer covers all stored content; the page layer
  samples.

## Anti-goals (failure even if it technically works)

- A first baseline that silently blesses a site that is already infected.
- An alert every time an editor embeds a video or marketing adds a tag, until the
  operator stops reading.
- A root process steered by tenant-controlled text: a `wp-config.php` naming someone
  else's database, row content forging row boundaries, a value sized to exhaust memory.
- Page requests that distort the customer's traffic figures or trip the node's own WAF
  or ban rules.
- A client domain or server hostname in the repo. Fixtures use `example.*` and `.test`.

## Constraints from this codebase

- Background work is a tick in `bin/hyperion-agent/src/ticks.rs`. Heavy ticks use a
  node_kv stamp and a local-time window, so an agent restart (every deploy) starts
  nothing by itself.
- Per-site state lives in `hosting_kv`; it is deleted with the hosting.
- A site's database is read as the hosting's own login, never root, and only if the
  database named in `wp-config.php` is one this hosting owns (`mariadb::read_option`,
  `site_scan_vendor_pass`). Passwords go in a 0600 option file, never on argv.
- `sitecheck::fetch` already fetches a site pinned to loopback with a byte cap and a
  timeout. Reuse it.
- RPC is JSON: new fields need `#[serde(default)]`; old nodes and old stored records
  must still parse.
- Notification wording is in the editable message templates; product text is English;
  `docs/cli.md` is test-guarded.
- Trust belongs to admins and operators, not the Customer role (existing capability).

## Approaches considered

1. **Extend the file scanner's worker.** Rejected: the worker unit has no network and no
   socket access on purpose, and its record, queue and verdict are built around files.
   Mixing in a second cadence and a second kind of baseline would put the scanner's
   pilot at risk for no shared code.
2. **A WordPress-side module (mu-plugin) reporting its own content.** Rejected: it runs
   inside the thing being judged, so an attacker who can write the database can usually
   silence it; and it executes tenant PHP, which the scanner design forbids.
3. **Chosen: a separate monitor in the agent**, beside the scanner. A pure parsing and
   rules module in `hyperion-adapters` (`contentscan/`), a service in `hyperion-core`
   (`content_scan.rs`), its own tick, its own stored result and baseline, shown on the
   same integrity card. Two layers feed one inventory. It runs in the agent process, not
   the capped worker: its input is bounded strings fed to regexes, with no archive or
   file-tree parsing, and it needs the database socket and loopback HTTP.

## Design

### One inventory, two layers

Both layers reduce what they read to **items**. An item has a kind, a key, a severity,
a count and up to 20 places it was seen (`posts:123:post_content`, `options:widget_text`,
a page URL). The key deliberately leaves the place out: the same spam host in 500 posts
is one item, and a video host accepted once is accepted for the whole site.

| Kind | Key | Bucket when new |
|---|---|---|
| `hidden-link`: external link inside something hidden by inline style | host | finding |
| `inline-script`: script or handler matching a rule | rule id + hash of the normalised snippet | finding |
| `cloaked`: host present only in the search-engine view | host | finding |
| `script-host`: external `<script src>` | host | change to review |
| `frame-host`: external `<iframe>`, `<object>`, `<embed>` | host | change to review |
| `redirect`: meta refresh or canonical to another host (page layer) | host | change to review |
| `link-host`: visible outbound link (page layer only) | host | inventory only |

"External" means the host is neither the site's domain nor one of its aliases.
`link-host` items are recorded and shown but never alert and never block a clean
verdict; a blog links to new places every week. One exception: **ten or more new link
hosts in one sweep** become a single change to review ("N new outbound link domains"),
because spam injections arrive in bulk.

Hidden means an inline style on the link or an ancestor within the same fragment with
`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, a zero or one pixel box
with `overflow:hidden`, or an offset or `text-indent` of −500px or further. Inline-script
rules start from the scanner's JavaScript rules (remote script creation, `atob` into
`eval`/`new Function`) plus `document.write(unescape(…))`, `String.fromCharCode` chains
and encoded literals over about 1 kB. The rule pack is compiled in and versioned; a
version bump re-evaluates without re-alerting on keys already in the baseline.

Each item carries a snippet of at most 120 characters, always escaped.

### Layer 1: database content

WordPress sites with a MariaDB database only. Database name and prefix come from
`wp-config.php` by parsing (`read_wp_config_db`), accepted only when the hosting owns
that database, read with that hosting's login.

Sources:

- `<prefix>posts`: `post_content`, `post_excerpt`, `post_title`, every row except
  revisions, auto-drafts and trash. That includes reusable blocks, templates,
  navigation, custom CSS and builder library entries.
- `<prefix>options`: every option except transients. This is where widgets
  (`widget_text`, `widget_custom_html`, `widget_block`) and "header/footer scripts"
  plugins keep what they print.
- `<prefix>postmeta`: page-builder data, starting with `_elementor_data`. It is JSON, so
  it is unescaped (`\/`, `<`) before the rules read it.

The database does the first cut: each query returns only rows whose value matches a
marker pattern (`<script`, `<iframe`, `<object`, `<embed`, `<style`, `javascript:`,
`eval(`, `atob(`, `fromCharCode`, `base64`, an `on…=` handler, the hiding declarations
listed above, and their JSON-escaped forms). A bare `style=` is not a marker: nearly
every block-editor and builder row has one, and the cap below would be hit nightly. Rows without markers never leave the database, which keeps a
50,000-post site cheap. Change detection by `post_modified` is deliberately not used:
an attacker writing SQL doesn't update it, the same way the file incident forged mtime.

Limits, all stated on the card when hit ("partly read"), never silently:

- each value cut at 2 MiB;
- 5,000 candidate rows and 64 MiB per site per sweep;
- 60 seconds per statement (server-side statement timeout), read-only session;
- values framed so content can't forge row boundaries (hex or base64 from the server);
- rows processed one at a time as a stream; nothing holds the whole result in memory.

When a cap is hit the site is "partly checked", which is its own verdict and never
"nothing new". Rows are read in primary-key order and a per-site cursor remembers where
the sweep stopped, so the next night continues from there and every row gets its turn;
the same rows are never the ones left out.

A database that can't be reached, a login that fails, or a `wp-config.php` naming a
database the hosting doesn't own is "couldn't check" with the reason, for this layer only.

### Layer 2: rendered pages

Any hosting the scanner covers that answers HTTP (reverse proxies skipped, as today).
Fetched with `sitecheck::fetch`: pinned to loopback, so it is this node's copy; 8 MiB and
20 seconds per request; its own user agent, `Hyperion-ContentCheck/1`.

- **Pages:** the homepage, plus up to four more from the sitemap: the first URL of each
  child sitemap of a sitemap index (typically one post, one page, one product, one
  archive), or the first four of a flat sitemap. No sitemap means the homepage alone.
- **Second view:** the homepage once more with a search-engine user agent and a search
  referrer. A host is `cloaked` only when it is in that view and in none of: the normal
  views of this sweep, the baseline, and this sweep's database items. Ordinary variance
  between two fetches (rotating ads, random related posts) is thereby mostly known
  already; what remains goes through Trust. That view redirecting to another host is
  also `cloaked`. A second view that fails or is refused (security plugins often 403 a
  crawler that isn't one) is "couldn't check" for that view, never a finding. Cloaking
  that verifies the crawler by IP address can't be seen from loopback; the card says the
  search-engine view is "as served to a crawler's user agent".
- `sitecheck::fetch` has its user agent baked in and takes no referrer; it gains both as
  parameters, and the site check's callers pass what they pass today.
- Six requests per site per day at most. The requests land in the access log; the
  traffic figures must not count them (see builder notes).
- A page that doesn't answer 200 is not a finding here (that is the site check's job);
  it is "couldn't check" for that page.

Every page yields the same item kinds as Layer 1, plus `link-host` and `redirect`. This
layer doesn't care where the markup was stored: theme file, plugin option, builder data
or a table nobody thought of.

### Baseline and the first scan

Per site, in `hosting_kv`: the last result (clamped like the scanner's record) and the
baseline, the set of accepted item keys with the date each was first seen, capped at
2,000 keys. Neither travels with Move/Copy: the destination starts again.

- **First scan:** nothing that matters is blessed blind. `link-host` items seed the
  baseline quietly. `script-host`, `frame-host` and `redirect` items go on a one-time
  "already here when watching began" list: changes to review, shown on the card, **no
  notification**, cleared one by one or with "Trust all". An already-infected site's
  loader host is on that list for a person to see. **Findings are never seeded.** A
  hidden link or rule hit present on the first scan is shown as a finding and stays one
  until it is gone or someone trusts it.
- **Later scans:** an item whose key is in the baseline is quiet. A new key is a finding
  or a change to review, per the table. An item that disappears leaves the result, and
  its key leaves the baseline after 30 days unseen, so a host that comes back much later
  is news again.
- **Trust** (existing trust capability, audited, confirm on the form): accept one item,
  or all changes to review on the site. Trusting a finding is allowed, one at a time
  only; a site can legitimately hide a link (a skip-link, a menu that opens on hover).
- A change to review stays listed until trusted or gone. It doesn't re-alert.

### Schedule

One tick, `spawn_content_scan`, asking every ten minutes whether anything is due.

- A site never scanned: next tick, any time of day. The work is small and "works the
  first time" needs it.
- Otherwise once a day, inside the existing 02:00–06:00 local window. A node_kv stamp
  records the sweep the window has started, and each site's stored result carries its
  own `scanned_at`, so a restart starts nothing and an unfinished sweep resumes
  oldest-first the next night.
- One site at a time. Before each site, the node's load and memory pressure are checked
  (`sitescan::pressure`); a busy node waits.
- "Scan now" on the integrity card also asks for a content scan of that site, through
  its own request key; it doesn't wait for the night.
- Per-site switch: the existing `integrity_scan` one. No new setting.

### Verdict, panel and CLI

The integrity card gains a "Content" block; it reads the stored result and never scans.

- States: findings; changes to review; nothing new; partly checked (named part); not
  checked yet; pilot (report-only) note while the flag is off.
- Coverage line replaces "The database is not scanned." where a result exists:
  "Database content read and N pages fetched <ago>. Pages are read as served; scripts
  are not run." A site with no database layer says "pages only". An old node, or a site
  with no result yet, keeps today's sentence.
- Each item: kind in plain words, host or rule, count, places (post id links to the
  editor URL as text, not a fetched link), snippet, Trust for those who may.
- `hctl` prints the same block; `docs/cli.md` updated.

### Alerts and the pilot flag

- `[integrity] content_live`, per node, default **false**, read like `new_layers_live`.
  Off: scans run, results show on the card marked as pilot, no notifications, and a log
  line per sweep carries the node's item counts so the fleet can be compared.
- On: one notification per site per sweep, only for keys new since the last sweep.
  New findings at `error` (`ops.content`); new changes to review at `warn`, batched
  (`ops.content_review`). Both get message templates.
- The first scan of a site alerts on findings only.
- Each stored item records whether it has been notified. When the flag is switched on,
  findings found during the pilot and still standing notify once, as one message per
  site; standing changes to review don't.
- Care reports, `is_clean()` and letters don't change in this project.

## Acceptance

1. **October-shaped fixture test:** synthetic rows mimicking a hidden-link injection in
   `post_content`, in a text widget option, and in `_elementor_data`, with invented
   `.test` hosts. Each is a finding naming host and place.
2. **Quiet second sweep:** the same content again produces no notification; one new
   hidden host produces exactly one.
3. **First scan doesn't bless:** a hidden link present at the first scan is a finding;
   an ordinary video embed at the first scan is not.
4. **Pilot flag off:** results stored and rendered, zero notifications.
5. **Restart re-triggers nothing:** a tick right after start, with sites scanned
   earlier that night, does no work.
6. **Hostile input:** a value containing the row separator, invalid UTF-8, a 10 MiB
   value, 100,000 candidate rows, a `wp-config.php` naming another hosting's database.
   None crash, none exceed the limits, the last is refused and reported.
7. **Cloaking:** with a fake fetcher, a host served only to the search-engine view is a
   `cloaked` finding.
8. **False-positive check:** a dev tool runs the rules over the rendered homepages of a
   stock WordPress with the default themes and the top page builders' demo content.
   Zero findings. Not in CI.
9. **No write, no PHP:** the database statements are a fixed, tested set of `SELECT`s;
   no wp-cli is spawned.

The database reader and the fetcher sit behind traits, as the vendor downloader does,
so all of this runs on macOS without MariaDB.

## Build order

Each step leaves the product working.

1. `contentscan`: HTML/fragment item extraction and rules, pure, with fixtures.
2. Database reader (fixed statements, framing, limits) behind a trait.
3. Page layer on `sitecheck::fetch`, including the second view.
4. Service: inventory, baseline, first-scan rule, stored result, tick, node_kv stamp,
   "Scan now".
5. Card block, Trust actions, `hctl`, docs.
6. Notifications and templates behind `content_live`.

## Calls made by the author, for the owner to check

- **Every scanned site gets this, not only care-plan sites.** Six requests a day is
  small, and the gap the contract review found is a platform gap.
- **The search-engine view is fetched** (one extra request with a crawler user agent,
  from loopback). It is the only way to see cloaked spam; the risk is the node's own WAF
  or ban rules reacting, which the builder must rule out before it ships.
- **Daily, at night**, not every six hours like the file delta scan.
- New script and frame hosts are a `warn` to review; hidden links, encoded scripts and
  cloaking are an `error`.
- Visible outbound links never alert, except ten or more new hosts at once.
- No compiled-in list of "well-known" hosts. A new tag manager is one `warn`, once.
- Findings can be trusted (one at a time), unlike a failed wordpress.org comparison.
- Script and frame hosts already present at the first scan are listed for review, without
  a notification. Every existing site will therefore show a review list once after
  rollout; during the pilot that costs nothing, and it is the only way not to bless an
  infected site.
- A site over the row or byte cap is "partly checked" and rotates through its rows over
  several nights.
- Switching the flag on sends one catch-up message per site that has standing findings.
- Baseline in `hosting_kv`, not carried by Move/Copy.
- Care reports and letters wait for a later PR.
- Limits (2 MiB, 5,000 rows, 64 MiB, 60 s, 2,000 keys, 30 days, 10 hosts) are starting
  values.

## As built

Where the build departs from the text above, and why.

- **A script that builds a `<script>` element is not a finding by itself.** The
  ordinary analytics snippet does exactly that. The hosts such a script names are
  `script-host` items, to review like any `<script src>`. A loader that hides its host
  behind a decoder is what the decode rules catch.
- **Pages:** the homepage plus the first four addresses of the sitemap (for an index,
  of its first child that lists any), chosen once a week and kept, rather than one from
  each child sitemap. A night is then six requests; the week the pages are chosen adds
  up to four sitemap requests.
- **Markers:** `<style` is not one (style blocks aren't interpreted); `<meta`, `<frame`
  and the `hidden` attribute are.
- **Traffic figures are not adjusted.** They are byte counts from the access log and
  don't single out any user agent today, the site check's included. Six small requests
  a night are left in them.
- **The crawler view is unverified on a real node.** The generated nginx rules never
  name a search engine, and a refused view is "couldn't check", but nobody has yet
  watched ModSecurity or a security plugin meet it. Look at the `crawler` note on pilot
  sites before `content_live` is switched on.
- **`hctl wp content-scan`** prints the stored result; it is its own command, not part
  of `integrity-scan`.
- **The statements were run on a real server**, MariaDB 10.11 and 11.8, as an ordinary
  database user: accepted, the right rows come back, and the session refuses a write
  (`crates/hyperion-adapters/tests/contentscan_live.rs`, off unless given a container).
  They have not been run against a production-sized site; the 60-second limit and the
  row cap are what stand between a slow table scan and the node.
- Builder data read: `_elementor_data` only.
- The false-positive check (acceptance 8) has not been run; the pilot is where it
  happens.

## Open question for the owner

Not answered at approval; the fixtures assume an inline style.

Where exactly did October's links sit (post content, a widget, builder data, an option)
and how were they hidden (inline style, a CSS class, off-screen)? The fixture in
acceptance 1 should mirror the real shape. If it was a CSS class defined elsewhere, the
database layer alone would not have called it hidden, and the page layer's link
inventory would have been the only signal.

## Left to the builder

Exact regexes and marker pattern; the tag scanner (hand-rolled, as `sitecheck` does, or
a small dependency); statement text and framing; the shape of the stored result and how
the card's RPC carries it (additive, `#[serde(default)]`); whether the search-engine
view needs a WAF/ban exemption for loopback; making sure the traffic figures skip this
user agent (and checking whether they already skip the site check's); which builder
meta keys join `_elementor_data`; the log line for fleet counts.
