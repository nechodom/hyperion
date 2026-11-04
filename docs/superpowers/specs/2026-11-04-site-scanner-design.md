# Site scanner: modern, low-cost antivirus — design

Status: draft, awaiting owner approval. Date: 2026-11-04.

## Intent

The owner sells "balíček péče", which includes malware scanning. Today's scan
needs an optional package, does nothing for files no one publishes checksums
for, and can take down the small box it protects. The owner asked for an
antivirus that works the first time and does not eat the server.

The test case is a real compromise (a client site, November 2026). Reading the
current code against it:

| Stage | Caught today? | After this design |
|---|---|---|
| Loader appended to `swiper.min.js` (free Elementor) | Yes, checksum | Yes, checksum |
| 37 kB b374k webshell `wp-config-modules.php` | Only in docroot root, `wp-admin`, `wp-includes` | Yes everywhere: not in any manifest + rules |
| 13 `eval(base64_decode())` PHP files with forged mtime | Core and wordpress.org plugins only | Everywhere; premium plugins via baseline and rules |
| 872 bytes appended to `js.cookie.min.js`, `frontend-modules.min.js` | Yes, checksum | Yes, checksum |
| Obfuscated script in child theme `functions.php` `wp_footer` | No | Yes: baseline change + rules |
| SEO spam URLs hit by Googlebot | No | No (non-goal) |

Most of the detection came from comparing files, not from ClamAV signatures.
The hole is what nothing compares. So ClamAV stops being the centre.

## Goals

1. **Works the first time.** After an agent update, every eligible hosting gets
   scanned with nothing to install, enable or configure. No ClamAV required for
   a meaningful verdict.
2. **Cheap.** Hard caps, not politeness. Bounded memory, idle priority, and
   repeat scans that read almost nothing. Opening a page never starts a scan.
3. **Catches the incident above**, per the table.
4. **Scanning never runs tenant code.** Today `wp plugin verify-checksums` and
   `wp plugin list` boot WordPress as the site user with no `--skip-*`, so an
   infected `functions.php` executes during the scan and could forge its output.
5. **A finding can be acted on from the panel:** quarantine, restore, trust.
6. **Stays honest.** The existing rule holds: what could not be checked is
   "couldn't check", never clean. Coverage is stated on every verdict.

## Non-goals

- Realtime watching (inotify/fanotify).
- Scanning database content (`wp_options`, posts).
- Fetching rendered pages to inventory external scripts. Worth a later project;
  it would have flagged the loader's domain from the outside.
- SEO-spam detection from logs.
- Cleaning files automatically. Automatic quarantine stays off (see owner's
  calls below).
- Servers not running Hyperion. the compromised site's server runs CloudPanel;
  this does nothing there.
- Vendor API integrations or keys configured in Hyperion. The defender stays keyless;
  a download URL WordPress already holds is the only licensed source used.

## Anti-goals (failure even if it technically works)

- A resident daemon holding 1 GB of RAM.
- A false "clean", including a first baseline silently blessing an already
  infected site.
- Alert fatigue: every premium plugin update or developer edit raising an alarm
  until the operator stops reading.
- A tenant able to edit or poison the baseline, or to steer a root process with
  symlinks, FIFOs or hard links.
- A busy site slowing down visibly because a scan is running.

## Constraints from this codebase

- Root in a tenant tree: no path resolution by name (`resolve_inside_jail`,
  `O_NOFOLLOW`, regular files only). A directory's nlink is not an attack; a
  file's is. See `files.rs`.
- Long actions are background jobs (`spawn_job` then `/jobs/<id>`).
- Heavy ticks use a node_kv stamp and a local-time window (`wp_defender_due`),
  never bare `every(offset, DAY)`.
- RPC is JSON. New fields need `#[serde(default)]`; old nodes and old stored
  records must still parse. `reports.rs` reads the stored `integrity_scan` JSON
  through its own mirror struct, so it must be updated in step.
- `root_dir` is htdocs. Customer letter strings live in `letters.rs` (en + cs).
- Product text is English. `docs/cli.md` is test-guarded.
- Debian 12/13, systemd present. Transient units are existing practice.

## Design

Four layers, cheapest first. Each file is judged by the strongest layer that
can speak for it.

### Layer A: upstream verification, native

Replaces wp-cli for checking. Repair and reinstall actions keep using wp-cli.

- Read versions by parsing, never executing: `wp-includes/version.php`
  (`$wp_version`, `$wp_local_package`) and plugin/theme headers.
- Core: `api.wordpress.org/core/checksums/1.0/`. Plugins:
  `downloads.wordpress.org/plugin-checksums/<slug>/<version>.json`. Same sources
  wp-cli uses, same soft-file exemption (`readme.txt`, `readme.md`).
- **Themes (new):** wordpress.org publishes no theme checksums. Download
  `downloads.wordpress.org/theme/<slug>.<version>.zip` once, build a manifest,
  drop the ZIP. This covers `hello-elementor`.
- Manifests are immutable per slug + version, so cache them in
  `/var/lib/hyperion/scan/manifests/` and share across sites. Fifty sites on one
  Elementor version cost one download.
- No upstream data for a slug and version means **unverifiable**: it falls to
  Layer B and is listed as coverage, not as a finding (premium plugins, same
  rule as today). wordpress.org unreachable with no cached manifest means
  "couldn't check", also as today.
- Any file in a verified tree that is not in the manifest is a finding. Core
  scope is wider than wp-cli's: anything in `wp-admin`, `wp-includes` or the
  docroot root that the manifest doesn't know, except `wp-config.php`,
  `.htaccess` and the like. Unknown root files that aren't `wp-*` go to Layer B
  rather than straight to a finding, because sites legitimately keep files there
  (`google*.html`, custom PHP).

### Layer A+: reference copies for premium plugins and themes

The owner asked for premium plugins to be verified too, not just watched, with **no
manual work**: no uploading ZIPs, nothing to configure. No public checksums exist, but
two automatic references do. Both feed the same manifest cache and comparison as Layer
A, and each result is labelled with its source, because they aren't equally strong.

1. **Download the package automatically, using the URL WordPress already holds.** A
   licensed plugin's updater stores package data in the `update_plugins` and
   `update_themes` site transients. Read both the `response` and `no_update` entries
   from the database without running PHP (take `DB_NAME` and the prefix from
   `wp-config.php` by parsing, extract values without unserializing). Download in the
   agent, build the manifest, keep no ZIP. Label: "matches the vendor's package".
   - **Any site fills the cache for all of them.** A manifest is keyed by slug + version
     and shared across the cluster, so one site with a working licence and URL verifies
     every site running that version. Try each site holding the plugin until one works.
   - A `no_update` entry can verify the version installed today. A `response` entry only
     prepares the next version, so that site verifies after it updates. Which vendors
     expose which is unknown until tried on real sites; coverage is reported, not assumed.
   - The version inside the ZIP's header must equal the manifest key, or it is discarded.
   - Changed files in a verified tree are findings. Added files become changes to review,
     or findings on a rule hit, because some premium plugins write into their own folder.
   - The site's database is attacker-writable. A URL is used only if it is `https` on a
     compiled-in vendor host allowlist, every redirect hop is re-checked against the
     allowlist plus known vendor CDNs, private addresses are refused, and size is capped.
     An unknown host is skipped and its name recorded, so the list can grow from real data.
   - These URLs often carry a licence key, so treat them as secrets: never on argv, never
     logged or stored, per the repo's existing rule. Failed requests are backed off per
     slug + version so a vendor never sees repeated attempts from a licence.
2. **Comparison across the operator's own sites.** With the same slug and version on at
   least 3 sites, and one differing from a strict majority, the differing files become
   changes to review, or findings on a rule hit. Nodes send hashes only, never content.
   Customers never see other sites' names. Label: "same as N of your other sites", and
   this never counts as verified: if every copy is infected, they all agree.

No reference available means Layer B and Layer C only, stated in coverage as today.
Vendor-specific licence APIs are out of scope: each needs its own integration and a key
in Hyperion. Uploading ZIPs by hand was rejected by the owner as too much work.

### Layer B: baseline of everything upstream can't vouch for

Scope: child themes, custom and premium plugins and themes, `mu-plugins`,
drop-ins, unknown root files. On a non-WordPress hosting, the whole docroot.
File types: `.php .phtml .phar .php3-8 .pht .inc .js .mjs .htaccess .user.ini`.

- One record per file: path, size, ctime, SHA-256. Stored per hosting in
  `/var/lib/hyperion/scan/baselines/<hosting_id>`, root 0600, atomic replace,
  removed with the hosting. Outside the tenant tree so the tenant can't touch it.
- **Change detection uses size + ctime, then the hash. Never mtime.** This
  attacker forged mtimes; a site user can't forge ctime.
- First scan: the baseline is written and Layer C runs over all of it, so nothing
  is blessed blind. The card says "watching since <date>; earlier changes can't
  be proven".
- New or changed file with a rule hit: **finding**.
- New or changed file with no rule hit: **change to review**, a separate, lower
  bucket. It stays until someone trusts it or it changes again.
- Premium plugin or theme whose header `Version` changed: its changed files with
  no rule hit are accepted automatically and recorded in the audit log as an
  update. That avoids alarms on every update. Accepted risk: an attacker who also
  bumps the version header and evades the rules goes unseen by this layer.
- **That acceptance applies only to slugs wordpress.org doesn't know.** A free
  plugin or theme edited to claim a version with no manifest would otherwise drop
  out of Layer A and get waved through. A wordpress.org slug whose version has no
  manifest yet is retried on the next delta scan, and if it still has none, its
  changed files become changes to review. Betas may raise review items; that noise
  is accepted.
- Deleted files just leave the baseline.
- Churn paths (`wp-content/cache`, `wflogs`, `upgrade`, `uploads` generated
  assets) stay out of the baseline but still get Layer C on `.php`-like files.
- On non-WordPress hostings, `vendor/` and `node_modules/` count as churn paths,
  and `.js` gets Layer C only, not baseline change detection.

### Changes Hyperion makes itself

Other writers change Layer B files, and a mass review alarm from our own actions
is the alert fatigue the anti-goals forbid. None of them may bless content blind.

- **Hyperion's own files** (`mu-plugins` written by `wpplugin.rs`, `regguard.rs`,
  `wpmail.rs`): each version's expected hashes are compiled in, like a manifest.
  A match is verified. A mismatch is a finding. An agent update never raises review
  items.
- **Git deploy and backup restore:** the changed files go through Layer C at once.
  No rule hit means accepted and audited, listed on the card as "changed by deploy"
  or "changed by restore". A rule hit is a normal finding. A restored backup or a
  pushed commit can be infected, so Layer C is not skipped.
- **Panel file manager:** a normal change to review, same as FTP.
- **Move/Copy:** the destination starts a fresh baseline with Layer C over all of it.
  Trust records travel through the `carried_kv_scope` allow-list, so trusted files
  stay trusted when path and hash still match.

### Layer C: PHP-focused rules

Compiled-in rule pack in Rust (`regex::RegexSet`, already a dependency) with a
version number. Not YARA: `yara-x` pulls in a large runtime for what a small set
of targeted regexes does here, and third-party rule packs bring licence and
false-positive review. Our licence is AGPL-3.0.

Rules run only on: files in Layer B scope that are new or changed, files that
failed Layer A, and PHP-like files in `uploads` and churn paths. Files proven by
Layer A are never inspected. This removes most false positives (minified JS in
popular plugins) and most of the cost. A rule-pack version bump re-inspects Layer
B scope once.

Starting rules, each with an id and a severity:

- High: `eval`/`assert` over a decoder (`base64_decode`, `gzinflate`,
  `str_rot13`, …); request data reaching `eval`/`system`/`passthru`/`shell_exec`;
  known webshell markers (b374k, wso, c99, …); any PHP executable under `uploads`.
- Medium: encoded literal over about 3 kB in PHP; `wp_footer`/`wp_head` hook plus
  an encoded payload; JS that creates a remote `<script>`, or `atob` into
  `eval`/`new Function`; file named like core (`class-wp-*.php`) outside core and
  containing a medium rule.

A finding carries rule id, line number and any URL domains found. Snippet at most
120 characters, always escaped. Inspection is capped at 2 MiB per file; a larger
PHP file is reported as "too large to inspect", never skipped silently.

### Layer D: ClamAV, optional and bounded

Stays one click on Services. Never required and never auto-installed, because its
signature database costs over 1 GB of RAM.

- **One `clamscan` per sweep**, with `--file-list` from our walker, instead of one
  per site reloading the database each time. Hits are attributed to hostings by
  path. Weekly.
- Runs only when binary and database exist and `MemAvailable` is at least 2 GiB.
  Otherwise the card says "skipped: not enough free memory", and that is not a
  failure and doesn't affect "clean".
- Signature database still downloading after install is its own state, not
  "scan failed".
- **Exit 2 keeps its hits** and marks the pass partial. Today a single file
  vanishing mid-walk throws away real detections.
- A killed `clamscan` (OOM) backs off 7 days and says so.

### The scan worker

The scan runs as a separate process, the same agent binary with a hidden
subcommand, in a transient service unit:

```
systemd-run --wait --pipe --collect
  -p MemoryMax=256M -p CPUWeight=10 -p IOWeight=10 -p Nice=19
  -p IOSchedulingClass=idle -p CPUQuota=<50% on <=2 cores, else 100%>
  -p CapabilityBoundingSet=CAP_DAC_READ_SEARCH -p NoNewPrivileges=yes
  -p PrivateNetwork=yes -p ProtectSystem=strict
  -p ReadWritePaths=/var/lib/hyperion/scan
```

- It can read every tenant file and write none, which is the point: a root
  process parsing hostile input. Network stays in the agent, which fetches
  manifests between a discover phase and a scan phase.
- Walks with `O_NOFOLLOW`, regular files only, no symlink following, stays on one
  filesystem. A file with nlink > 1 is reported, not read. Hashes with a streaming
  buffer.
- Checks `/proc/loadavg` and memory PSI every few hundred files and pauses when
  the box is busy. A site that can't finish is resumed on the next run and marked
  stale rather than clean.
- At most one worker per node. Sites go oldest-first.

### Schedule

- Tick checks every 10 minutes with node_kv stamps.
- First scan of any hosting without a baseline: as soon as possible, any time of
  day. The caps make that safe, and "works the first time" needs it.
- Delta scan (stat walk, hash what changed): every 6 hours.
- Full re-hash: weekly, staggered so one seventh of sites run per night, inside
  the existing 02:00–06:00 local window.
- Restart does not re-trigger anything.

### Panel

- `GET /hostings/:sel/integrity-panel` **reads the stored result and never scans.**
  Today every open runs wp-cli, and `clamscan` if the last pass is over 20 hours old.
- "Scan now" queues the site at the front through a background job. The card shows
  queued/running and updates in place. `Request::WpIntegrityScan` stays for `hctl`.
- Card verdict states: findings; changes to review; clean; partial (a named part
  couldn't run); running; never scanned. Coverage line: core, N of M plugins,
  N of M themes against wordpress.org, K files watched since <date>, ClamAV state,
  plus the plain statement that the database isn't scanned.
- Non-WordPress hostings get the card too. Reverse proxies are skipped.
- Per-finding actions, confirm dialog on the `<form>`, audited. Quarantine and Restore
  need `WpManage`. **Trust needs a new capability that admins and operators have and
  the Customer role doesn't**, so a stolen customer login can't approve a webshell or
  turn a paid report green. Customers see the item as waiting for the operator.
  - **Quarantine:** resolve inside jail, move to
    `/var/lib/hyperion/quarantine/<hosting_id>/<id>` (root 0600) with metadata
    (original path, hash, mode, owner, time). Purged after 90 days. The dialog warns
    when the file is core or looks loaded by the site.
  - **Restore:** puts it back with original owner and mode, refusing if the path is
    now occupied.
  - **Trust:** accept this path + hash into the baseline. New content flags it again.
    Applies to Layer B and Layer C items only. A file that fails Layer A can't be
    trusted, only repaired, reinstalled or quarantined, so no trust list can override
    a manifest. "Trust all changes to review on this site" exists for bulk edits and
    excludes anything with a rule hit.
- Existing Repair core and Reinstall plugin stay as the right fix for tampered
  upstream files. Add Reinstall theme for wordpress.org themes.

### Alerts and reports

- Same diff-based "only what's new" as today, one notification per site per sweep.
  Findings at `error`; changes to review at `warn`, batched.
- First-ever scan alerts on high-severity only, so rollout doesn't flood.
- **Silent pilot first.** The new layers start report-only behind a node setting: results
  show in the panel, with no alerts, no effect on care reports, and hit counts readable
  across the fleet. Reports keep today's meaning meanwhile. Alerts go live only after the
  owner has seen pilot results, because the false-positive check can't sample the premium
  and custom code the rules actually run on.
- `is_clean()` becomes: upstream verification ran, native scan ran, no findings, no
  changes to review. ClamAV no longer required. `CareIntegrity::malware_scan_ran` is
  true when the native scan or ClamAV ran. Letters updated in `letters.rs` (en + cs).
  Old stored records keep their old meaning.
- A site with no upstream to compare (non-WordPress) is clean on the native scan
  alone, and its wording never mentions wordpress.org.
- Pending changes to review get their own letter wording. They aren't "only partly
  checked", because the check did run.
- `hctl`, `docs/cli.md` and README updated.

## Acceptance

1. **Incident fixture test in the repo:** synthetic files that mimic each table row
   (appended JS loader, password-gated fake-403 shell, `eval(base64_decode)` with
   forged mtime, obfuscated `wp_footer` in a child theme), defanged, no real payload.
   Each stage must be found by the layer the table says.
2. **Forged mtime is still detected.**
3. **False-positive check:** a dev tool runs the rule pack over the current top 50
   wordpress.org plugins and themes. Zero high-severity hits; each medium reviewed.
   Not in CI (network).
4. **Hostile-tree tests:** symlink to `/etc/shadow`, FIFO, hard link, huge file,
   symlink swapped mid-walk. None read, none hang.
5. **Resource check on a test node with a 20k-file site:** worker stays under
   `MemoryMax`; a repeat scan with no changes hashes nothing but the stat walk;
   measured numbers go in the PR.
6. **Page view starts no process.** Tested.
7. **No wp-cli during a scan**, so no tenant PHP executes. Tested with a fixture whose
   PHP would write a marker file if run.
8. **Real samples:** run against the incident samples copied to an isolated machine,
   with the owner's go-ahead. Samples never enter the repo. Not on s3 (1.9 GB, recent
   OOM events).

## Build order

Each part ships on its own and leaves the product working.

1. Stop the bleeding: panel reads stored results, "Scan now" as a job, ClamAV exit 2
   keeps hits, tick moved to node_kv stamps.
2. Worker, walker, Layer A with manifest cache, then Layer C and Layer B, report-only.
3. New verdict states and coverage line in the panel. Pilot on a real node starts here.
4. Quarantine, restore, trust, Reinstall theme.
5. Premium references: automatic package download, then cross-site comparison.
6. Reports, letters, `hctl`, then alerts switched on after pilot review.
7. ClamAV rework.

Acceptance 5 and 8 must pass before step 6. Testing happens on the owner's local machine
(macOS), which has no systemd, so Linux-specific behaviour runs in a local container and
the worker must also run directly for tests. Real premium downloads need licensed sites,
so vendor coverage stays unproven until a real server is tried. Pilot server: not chosen.

## Decided by the owner

- Build this on file comparison and PHP rules, with ClamAV as an optional extra.
- Trust is for admins and operators, not customers.
- Silent pilot before alerts and reports go live.
- Premium plugins are verified automatically where a package can be downloaded, with no
  manual uploads, using any site that has the same plugin.
- Testing happens on the local machine.

## Calls made by the author, for the owner to check

- Automatic quarantine is off. A file gets moved only by a person, because moving a
  wrong file breaks a paying customer's site.
- Non-WordPress hostings are scanned too.
- ClamAV is not auto-installed.
- A file changed with no rule hit is a "change to review" that blocks the green
  "clean" verdict until trusted. A developer editing a child theme by FTP will see it.
- Premium plugin updates are accepted when the version header changed and no rule hit;
  wordpress.org slugs don't get that pass.
- Git deploys and restores are accepted when no rule hits; file manager edits are not.
- Trust never overrides a failed comparison with wordpress.org.
- Own rule pack, not YARA.
- Thresholds (256 MiB, 2 GiB, 6 h, weekly, 90 days) are starting values.

## Left to the builder

Exact regexes, baseline file format, worker IPC format, how quarantine metadata is
stored, and how `WpIntegrityScanResult` grows, within the compatibility constraint.
