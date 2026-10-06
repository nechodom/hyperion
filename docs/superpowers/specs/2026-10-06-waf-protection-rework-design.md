# WAF protection rework (phase A — native) — design

Date: 2026-10-06. Status: approved in chat.

## Why

Today's per-hosting WAF is one bool (`hostings.waf_enabled`, migration 036)
that switches a fixed bundle of nginx rules on or off. Four problems:

1. **All or nothing.** Blanket `xmlrpc.php` deny breaks Jetpack and the WP
   mobile app; the only fix is turning every rule off.
2. **No visibility.** Nothing records what was refused or why. A WAF 403 is
   indistinguishable from any other 403, so false positives cannot be
   diagnosed.
3. **Weak.** Only `$args` and the UA are inspected; refused probes never feed
   the native fail2ban, so a scanner can keep trying forever.
4. **Buried.** The switch sits in "Vhost options" between cache TTL and HSTS.

Phase B (separate spec, later): an opt-in "Full WAF" tier — ModSecurity v3 +
OWASP CRS from apt — that plugs into the log/ban/UI plumbing built here.

## Rule catalogue

One source of truth in `hyperion-types::waf`. Each rule: `id`, `label`,
`help`, `tier` (Standard | Strict), `counts_for_ban`, `php_only`.

| id | tier | ban | what |
|----|------|-----|------|
| `probe_args` | Standard | yes | traversal / SQLi / RFI / `<script` in query string (today's regex) |
| `scanner_ua` | Standard | yes | nikto, sqlmap, wpscan… (today's regex) |
| `xmlrpc` | Standard | no | `/xmlrpc.php` |
| `sensitive_files` | Standard | yes | `wp-config.php`, `readme.html`, `license.txt` |
| `dump_files` | Standard | no | `.sql .bak .old .orig .save .swp .tar .gz .tgz .zip .log .ini .sh` |
| `php_in_uploads` | Standard | no | PHP under `wp-content/uploads|cache` (php only) |
| `dotfiles` | Strict | yes | `/.env`, `/.git/`, `/.svn/`, `/.hg/`, `.DS_Store` (logged + banned; other dotfiles stay a silent 404) |
| `author_enum` | Strict | no | `?author=<n>` |
| `rest_user_enum` | Strict | no | `/wp-json/wp/v2/users` and `?rest_route=/wp/v2/users` |
| `bad_methods` | Strict | no | anything but GET HEAD POST PUT PATCH DELETE OPTIONS |
| `empty_ua` | Strict | no | empty / `-` User-Agent |

Standard = exactly today's rule set, so a migrated site refuses exactly what it
refused before. `xmlrpc` is not ban-counted: Jetpack and app clients hit it
legitimately and must not get the caller firewalled.

Country and bot refusals are tagged too (`geo`, `bot`), for visibility only,
and are **never** ban-counted. The wp-admin IP lock is not tagged: it refuses in
nginx's access phase (`allow`/`deny`), where no variable can be set, and an
operator abroad must never be banned by it anyway.

`author_enum` skips `/wp-admin/` (the post list filters by `?author=`), and
`rest_user_enum` skips requests carrying a `wordpress_logged_in_` cookie (the
block editor reads `/wp/v2/users`).

## Model

- `WafLevel`: `off | standard | strict`.
- `waf_overrides`: map rule id → `on | off`. Missing = level default.
- `effective_rules(level, overrides, has_php) -> WafRules` — pure; one bool per
  rule. The template receives only the flat bools.
- Unknown override ids are dropped on parse (forward compat).

## Storage

Migration 077 on `hostings`: `waf_level TEXT NOT NULL DEFAULT 'off'`,
`waf_overrides TEXT NOT NULL DEFAULT ''` (JSON object). Backfill
`waf_level='standard' WHERE waf_enabled=1`. `waf_enabled` stays one release and
is written as `level != off` so an older master or node reading it still sees
a sensible value.

`VhostOptions` gains `waf_level: String` and `waf_overrides: String`
(`#[serde(default)]`). On read, an empty `waf_level` with `waf_enabled=true`
is treated as `standard` (old master → new node).

Node-local hit tables (migration 078 … same file is fine):

- `waf_hits_hourly(hosting_id, hour, rule, hits)` PK all but `hits`; upsert adds.
- `waf_recent(id, hosting_id, ts, ip, rule, method, uri, ua)`; capped at 200
  per hosting, uri/ua truncated to 200 chars.
- Retention: hourly rows 30 days.

Ingest offset per hosting in `hosting_kv` `waf_log_pos` = `"<inode>:<offset>"`.

## nginx

- Every WAF refusal becomes `set $hyperion_waf "<id>"; return 403;`. All
  server-level checks — including `sensitive_files` and `dotfiles` — record a
  verdict in one pass, the ACME path is cleared in the same rewrite phase, and
  one `if` refuses. Every match overwrites the verdict, so the refuse-only
  tags come first and the ban-counted ones last: a scanner that also drops its
  User-Agent or comes from a blocked country is still recorded as a scanner.
  `xmlrpc`, `dump_files` and `php_in_uploads` stay `location` rules (first
  match, before the PHP location).
- Server block gets a second, conditional log:
  `access_log /var/log/hyperion-waf/<hosting_id>.log hyperion_waf if=$hyperion_waf;`
  It sits next to the tenant `access_log`, so both apply.
- `/etc/nginx/conf.d/hyperion-waf.conf` declares `$hyperion_waf` with a `map`
  default (a config naming an undefined variable fails `nginx -t` once no
  vhost sets it) and the `log_format hyperion_waf escape=json`:
  `$msec\t$remote_addr\t$hyperion_waf\t$request_method\t$request_uri\t$http_user_agent\t$http_sec_fetch_site`.
- The log dir `/var/log/hyperion-waf` is root:<nginx group> 0750: nginx
  workers reopen their logs on USR1 (Debian's own nginx logrotate sends it
  daily) and need to reach it; site users cannot. It is **not
  tenant-writable**: today's brute-force scanner reads the tenant-writable
  access.log, so a tenant can forge lines and get an arbitrary IP banned. WAF
  bans come only from this log.
- `geo` and `bot` refusals set `$hyperion_waf` to their id.
- logrotate: `/etc/logrotate.d/hyperion-waf`, daily, rotate 7, compress,
  `copytruncate` — the live file keeps its inode, so rotation never depends on
  a reopen.

## Ingest + auto-ban

In the fail2ban tick on each node, per hosting with a WAF log:

1. Read from the stored offset, streamed and aggregated, at most 64 MiB per
   tick; a larger backlog is skipped from its oldest end so bans are decided on
   recent hits. A truncation (`copytruncate`) or inode change finishes the rest
   from `<log>.1` first.
2. Parse lines (tab-separated, JSON-escaped fields). Malformed lines are skipped;
   unknown rule ids count as `other` and are never ban-counted.
3. Upsert hourly counts, insert recent rows, prune (per-address counts are
   kept twice the ban window).
4. Per-IP count of ban-counted hits inside the window; ≥ `waf_threshold`
   (new `[fail2ban]` key, default 20, clamped 3..=1000) ⇒ `BanIntent` through the
   existing `auto_ban` (public-IP guard, repeat escalation). Source label `waf`.
   Not counted: requests another page made a browser send
   (`Sec-Fetch-Site: cross-site`/`same-site` — an `<img>` on someone else's
   page must not get its viewers banned). At most 10,000 address counters per
   batch.
5. Never banned, from any source: this node's own interface addresses and the
   cluster's (node public IPs, the master's address).
6. Per-hosting opt-out: `hosting_kv` `waf_autoban_enabled` = `off`.

## UI

- New **Protection** card on hosting detail (`id="protection"`, always
  rendered). It takes WAF, the wp-admin IP lock, the sign-up limit, bots and
  countries out of Vhost options. It posts to the same `/hostings/vhost-options`
  handler with the same field names; Vhost options keeps HTTPS/HSTS, basic auth,
  maintenance, cache, custom snippet and redirect. Each form sends a `section`
  hidden field so a save from one card never resets the other card's fields.
- WAF block: level select; a "Rules" fold with per-rule override select
  (Level default / Always on / Always off) and the effective state; auto-ban
  switch (shows the node threshold).
- **Activity panel**: lazy HTMX (`intersect once`), owning-node dispatch.
  24 h and 7 d totals per rule; last 50 refusals (time, IP, rule, method, path,
  UA — escaped, truncated). Per row "Allow this" = set that rule to Always off,
  confirm on the `<form>`.
- Security tile on the overview: level + blocked-24h count.
- Packages: `hardening` stays a tri-state toggle; Enable ⇒ `standard`,
  Disable ⇒ `off`. Pill shows the level name.

Gates unchanged: view = HostingView; edit = the gates the vhost-options save
already applies.

## Compatibility

- Old node + new master: the node ignores unknown fields and still reads
  `waf_enabled`. The Activity panel gets an unsupported-method error and says
  "update this node".
- New node + old master: empty `waf_level` + `waf_enabled` ⇒ standard.
- Standard renders the same set of refusals as before (status 403 either way).

## Testing

- Unit: `effective_rules` matrix; override parse; log-line parser (good, bad,
  escaped, truncated); offset/rotation; ban counting ignores non-ban rules.
- Render: each rule appears only when on; ACME never refused under Strict with
  every rule plus geo/bot; Standard set equals the legacy set.
- Migration: backfill + write/read-back.
- Web e2e: Protection card renders; saves round-trip level + overrides; a save
  from either card leaves the other card's fields untouched.

## Out of scope (phase B or later)

ModSecurity/CRS, request-body inspection, cluster-wide WAF dashboard,
cross-node ban sharing.
