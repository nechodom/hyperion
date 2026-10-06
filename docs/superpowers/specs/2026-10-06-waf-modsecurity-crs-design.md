# WAF phase B — opt-in ModSecurity v3 + OWASP CRS tier — design

Date: 2026-10-06. Status: approved to build ("start phase B, get the job
done"). Builds on phase A (`2026-10-06-waf-protection-rework-design.md`,
PR #236): the per-site WAF log, the activity panel and the Protection card.

## Goal

Per site, an optional full WAF: ModSecurity v3 running the OWASP Core Rule
Set, inspecting what phase A's nginx rules cannot (request bodies, headers,
encodings, hundreds of attack signatures). Opt-in, detection-only first,
visible in the same activity panel, tunable without a shell.

## Facts established by spike (Docker, real packages)

Debian 12 and 13 both ship `libnginx-mod-http-modsecurity` 1.0.3 (the nginx
connector, matching Debian's nginx, which is what Hyperion installs) and
`modsecurity-crs` 3.3.x (3.3.4 / 3.3.7), CRS files under
`/usr/share/modsecurity-crs/rules/`, setup in `/etc/modsecurity/crs/`.

| Question | Answer |
|---|---|
| Module enabled by the package? | Yes, `/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf`. |
| CRS loaded once at http level, per-site `modsecurity on` + `modsecurity_rules` | Works. Per-server rules are evaluated **before** the inherited http-level CRS. |
| Per-site engine mode (`SecRuleEngine DetectionOnly`/`On`) | Works. |
| Per-site paranoia level / anomaly threshold / WordPress exclusions via a site `SecAction` setting `tx.*` | Works — runs before CRS's own init, which only sets unset vars. |
| Per-site `SecRuleRemoveById`, path-scoped `ctl:ruleRemoveById` (ranges too) | Works. |
| `modsecurity off` in the ACME location | Works. |
| Per-site `SecAuditLog` | **Ignored** — every site logs to the http-level audit log. |
| Attribute a log entry to a site | `modsecurity_transaction_id "<id>-$msec-$request_id"` per server ⇒ `transaction.unique_id`. |
| Audit parts `AHZ` | Method, URI, status, engine, messages — **no** request headers or bodies (no cookies/passwords in the log). |
| Rotation | libmodsecurity keeps its file open across reloads (only a restart reopens): rename+reload loses every entry. `copytruncate` works. |
| Memory | CRS adds ~20 MB per nginx process (~45–50 MB after reloads, flat — no per-reload leak). |
| Config load | ~60 ms with 917 CRS rules. |

## Model (per hosting)

`VhostOptions` + `hostings` columns (migration 078):

- `crs_mode`: `off` (default) | `detect` | `block`.
- `crs_paranoia`: 1 (default) or 2. Higher levels are left out: their false
  positives need rule-by-rule tuning no panel form can offer.
- `crs_threshold`: inbound anomaly threshold, 5 (CRS default) / 10 / 20.
- `crs_wordpress`: apply CRS's WordPress exclusion set (default on).
- `crs_exclusions`: JSON list of `{rules: [942100, …], path: "/x"}`; empty
  path = whole site. Rule ids must be CRS ids (900000–999999), at most 20 per
  entry and 50 entries; a path starts with `/` and is limited to
  `[A-Za-z0-9/_.~-]`, max 200 chars (it is inlined into nginx config).

An empty `crs_mode` on the wire is a caller that predates phase B: the
service keeps every stored CRS field.

A non-off mode is refused when this node has no engine.

## Node engine

- **Install** (admins, per node, from the Protection card): background job →
  RPC `ModsecInstall` → apt `libnginx-mod-http-modsecurity modsecurity-crs`
  under a `policy-rc.d` guard (as OpenDKIM does), then `nginx -t`. If the
  module does not load (non-Debian nginx), the module's `modules-enabled`
  link is removed and the error reported.
- **Status** RPC `ModsecStatus`: module present, CRS present + version, sites
  using it.
- **http-level CRS only while needed**: `/etc/nginx/conf.d/hyperion-modsecurity.conf`
  (`modsecurity_rules_file /etc/hyperion/modsecurity/main.conf;`) exists only
  while at least one active local site has a non-off mode, so installing
  costs no memory until a site turns it on. Synced before each vhost write
  that changes CRS fields, after install, and at agent start.
- `main.conf`: Debian's recommended engine settings with these changes —
  body limit action `ProcessPartial` (large uploads are inspected up to the
  limit instead of rejected), response body off, `SecStatusEngine Off` (the
  sample turns on a phone-home), JSON audit log `AHZ` to
  `/var/log/hyperion/modsec/audit.log` (root:adm 0750), then CRS setup +
  rules (+ the two operator exclusion files when present).
- logrotate `/etc/logrotate.d/hyperion-modsec`: daily, 7, `copytruncate`.

## Rendering

In the HTTPS server body, only when the site's mode is on **and** the module
is loaded on this node (otherwise nothing — `modsecurity` would be an unknown
directive):

```
modsecurity on;
modsecurity_transaction_id "<id>-$msec-$request_id";
modsecurity_rules '
SecRuleEngine DetectionOnly|On
SecAction "id:10001,phase:1,pass,nolog,setvar:tx.paranoia_level=N,setvar:tx.executing_paranoia_level=N,setvar:tx.inbound_anomaly_score_threshold=T[,setvar:tx.crs_exclusions_wordpress=1]"
SecRuleRemoveById <ids>                                   # site-wide exclusions
SecRule REQUEST_FILENAME "@beginsWith /p" "id:101NN,phase:1,pass,nolog,ctl:ruleRemoveById=<id>,…"
';
```

and `modsecurity off;` in the ACME location. Phase A's server-level rules
run first (rewrite phase) and short-circuit before ModSecurity.

## Visibility

The agent's tick reads the node audit log (incrementally; position in
`node_kv`; `copytruncate` handled — a shrink reads the rest of `<log>.1`),
attributes each entry by its transaction id, and records it through phase
A's store:

- recorded only when CRS decided (message `949110`, anomaly threshold
  reached) or the engine denied the request;
- tag `crs_<category>` (blocked) or `crs_<category>_detected` (detection
  only), category from the first attack rule (`942` → `sqli`, `941` → `xss`,
  `930` → `lfi`, `931` → `rfi`, `932` → `rce`, `933` → `php`, …);
- `waf_recent.detail` (new column): matched rule ids + total score.

CRS refusals **never** count towards a firewall ban: CRS false positives
are real (an editor saving a post that discusses SQL), and a node-wide ban
for one is unacceptable.

Activity panel: CRS rows labelled "OWASP CRS · SQL injection" (+ "detection
only"). "Allow this" on a CRS row adds a path-scoped exclusion for that
request's rule ids (confirm dialog), re-rendered with `nginx -t`.

## UI

Protection card, new group "OWASP Core Rule Set (ModSecurity)":

- engine missing on the node: what it is, memory cost, "Install on <node>"
  (admins) / "ask an administrator" (others);
- engine present: Mode, Paranoia, Threshold, WordPress exclusions, the
  exclusions list (remove buttons) and an add-exclusion row;
- detection-only hint: run it a few days and watch the activity panel before
  blocking.

## Gates

Install: admin or higher. Per-site CRS settings and exclusions:
`HostingEditConfig` (same as the rest of the card). Panel: `HostingView`.

## Compatibility

Old master → new node: empty `crs_mode` keeps stored CRS settings. New
master → old node: CRS fields ignored; `ModsecStatus` fails ⇒ the card says
the node needs an update. Sites with CRS on moved to a node without the
engine render without it (never an unknown directive) and the card says so.

Not handled: removing the package by hand while sites use it leaves vhosts
naming an unknown directive. The card states "turn CRS off on every site
first".

## Testing

Unit: mode/exclusion validation, render (directives present only when on +
available, quoting, ids, ACME off), audit-line parser on captured JSON,
category mapping, ingest attribution, legacy merge, migration read-back.
Docker: rendered vhosts + generated `main.conf` pass `nginx -t` with the real
packages; detect logs and passes, block returns 403, exclusions and WP set
apply, ACME passes, phase A rules short-circuit first, audit entries
attributed to the right site.

## Out of scope

Paranoia 3–4, CRS 4 plugins, response-body inspection, CRS-driven bans,
per-node engine removal, a node-wide CRS dashboard.
