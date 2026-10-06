# WAF phase B (ModSecurity + OWASP CRS) — implementation plan

Spec: `docs/superpowers/specs/2026-10-06-waf-modsecurity-crs-design.md`.
Branch `claude/waf-modsecurity-crs`, stacked on phase A (PR #236).
Execution: inline, tests first where a pure function exists.

## B1 — types (`hyperion-types::waf::crs`)
- `CrsMode {Off, Detect, Block}` (parse/as_str/label), `CrsExclusion
  {rules: Vec<u32>, path: String}` + `parse_exclusions` (drops invalid
  entries) / `validate_exclusions` (named error) / `exclusions_to_string`,
  `PARANOIA_CHOICES`, `THRESHOLD_CHOICES`, `category_of(rule_id)`,
  `crs_tag(category, detected)`, `label_for` handling `crs_*` tags.
- `VhostOptions`: `crs_mode`, `crs_paranoia`, `crs_threshold`,
  `crs_wordpress`, `crs_exclusions`; `crs_settings()` resolving defaults.
- `WafHit.detail`; `ModsecStatus` DTO.

## B2 — state
- Migration 078: hostings CRS columns, `waf_recent.detail`. sha256 line.
- `hostings.rs` read/write (bind order!), `waf::record`/`recent` carry
  `detail`. Read-back test.

## B3 — adapters
- `modsec.rs`: paths, `module_available()`, `crs_available()` +
  `crs_version()`, `ensure_installed()` (policy-rc.d, apt, nginx -t, unlink
  module on failure), `render_main_conf()`, `sync_http_conf(need)` (main.conf
  + include + log dir + logrotate; nginx -t; reload; rollback on failure),
  `parse_audit_line()` → `(hosting_id, WafHit)`.
- `nginx.rs`/template: `VhostInput.modsec_available`; CRS block in the HTTPS
  body; `modsecurity off` in the ACME location; render tests.
- `waflog.rs`: generic line reader (callback) + shrink → `<log>.1` remainder.

## B4 — service
- `set_vhost_options`: CRS validation, legacy merge, engine-required check,
  `crs_sync` before the vhost write (and after a rollback).
- `crs_sync()`, `modsec_status()`, `modsec_install()`; boot sync in agent.
- Audit ingest inside the WAF ingest (node_kv position), records per site.

## B5 — RPC
- `ModsecStatus`, `ModsecInstall` (+ dispatcher timeout), hctl arms.

## B6 — web
- Detail: fetch `ModsecStatus` from the owning node; CRS group in the
  Protection card; form fields in `apply_protection`.
- `POST /hostings/modsec-install` (admin, background job → `/jobs/<id>`).
- `POST /hostings/crs-exclusion` (add / remove; also "Allow this").
- Activity panel: CRS labels, detail, "Allow this" for CRS rows.

## B7 — verify
- `cargo test --workspace --all-targets`, clippy `-D warnings`, fmt.
- Docker: real packages, rendered vhosts + main.conf, behaviour probes,
  ingest of a real audit log line.
- Dev panel walk; stacked PR.
