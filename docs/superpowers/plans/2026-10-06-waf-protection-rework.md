# WAF protection rework (phase A) — implementation plan

Spec: `docs/superpowers/specs/2026-10-06-waf-protection-rework-design.md`.
Execution: inline, task by task, tests first where a pure function exists.

## Task 1 — rule catalogue (`hyperion-types::waf`)
- `WafLevel {Off, Standard, Strict}` (`parse`, `as_str`, `label`).
- `WafRuleDef { id, label, help, tier, counts_for_ban, php_only }`, `RULES`.
- `TAG_GEO`, `TAG_BOT`; `counts_for_ban(id)`, `label_for(id)`.
- `parse_overrides(&str) -> BTreeMap<String,bool>` (JSON object; unknown ids
  and junk dropped), `overrides_to_string`.
- `WafRules` (one bool per rule, `any()`), `effective_rules(level, &overrides,
  has_php)`.
- `VhostOptions`: add `waf_level`, `waf_overrides`; `effective_waf_level()`
  (empty level + legacy `waf_enabled` ⇒ Standard).
- Activity types: `WafHit`, `WafRuleCount`, `WafActivity`.
- Tests: level parse, Standard set = legacy six, Strict = all, overrides win,
  php_only off for static, junk overrides dropped.

## Task 2 — state
- Migration `077_waf_rework.sql`: `waf_level`, `waf_overrides`, backfill;
  `waf_hits_hourly`, `waf_recent`, `waf_ip_minute`. Add sha256 line.
- `hostings.rs`: read/write the two columns; write `waf_enabled = level != off`.
- `waf.rs`: `record(pool, hosting, hits, now)` (hourly upsert, recent insert +
  cap, ip-minute upsert for ban rules), `totals(pool, hosting, since)`,
  `recent(pool, hosting, limit)`, `ip_offenders(pool, hosting, since,
  threshold)`, `prune(pool, now)`, `delete_hosting`.
- Tests: write/read-back, cap, offenders ignore non-ban rules, prune.

## Task 3 — nginx render
- Template: `set $hyperion_waf ""`; server-level rules + geo/bot fold into the
  one pass with the ACME clear; location rules `set …; return 403;`; conditional
  `access_log` to `/var/log/hyperion/waf/<id>.log`.
- `hyperion-waf.conf` (log_format) + logrotate file + log dir, written by
  `write_vhost` when the WAF log is referenced (content-idempotent).
- Tests: per-rule presence, ACME never refused (Strict + geo + bot), Standard
  emits legacy six, off ⇒ nothing; logrotate/log_format content.

## Task 4 — log ingest + auto-ban (`hyperion-adapters::waflog` + service)
- Pure parser `parse_line` (tab-separated, JSON-escaped fields) → `WafLogHit`.
- Incremental reader: `<inode>:<offset>` in `hosting_kv` `waf_log_pos`; reset on
  inode change / shrink; 8 MiB per tick cap; only whole lines.
- `waf_ingest` runs every fail2ban tick (even with fail2ban disabled — it is
  visibility); bans only when enabled and `waf_autoban_enabled != off`.
- `[fail2ban] waf_threshold` (default 20, 3..=1000) + settings save validation.
- Hosting delete removes log + rows.
- `waf_activity(hosting)` service method.
- Tests: parser cases, offset/rotation, ban intents only for ban rules over
  threshold.

## Task 5 — RPC
- `Request::HostingWafActivity { hosting_id }` → `Response::HostingWafActivity`.
  api trait, codec, rpc-server dispatch + stub, agent, web dispatcher timeout,
  hctl print arm.

## Task 6 — web
- Handler: `section` field (`protection` | `vhost` | absent = legacy full form).
  Protection fields: `waf_level`, `waf_rule_<id>` (default|on|off),
  `wp_admin_allowlist`, `signup_limit_enabled`, `blocked_bots`,
  `blocked_countries`. The other section is taken from stored options; stored
  lookup failure ⇒ refuse instead of resetting.
- Template: new Protection card (`id="protection"`), Vhost options trimmed.
- `GET /hostings/:selector/waf-panel` (activity, lazy) and
  `POST /hostings/waf-autoban` (owning-node kv), template `_hosting_waf_panel.html`.
- "Allow this" = POST protection override for one rule (`/hostings/waf-rule`).
- Overview Security tile: level + 24 h count (from the lazy panel; tile shows
  level only).
- Packages: hardening pill/feature reads level; `package_set_hardening` sets
  level standard/off.
- e2e: protection save round-trip, vhost save keeps protection fields.

## Task 7 — verify
- `cargo test --workspace --all-targets`, clippy, devpanel walk with
  screenshot, `nginx -t` of rendered Strict vhost in Docker if available.
