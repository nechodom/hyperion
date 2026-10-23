# Wildcard Auto-Renew via acme-dns CNAME Delegation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delegated wildcard certificates (`<base>` + `*.<base>`) renew unattended: the master serves the DNS-01 TXT in its own delegated zone and drives begin/finish on the owning node.

**Architecture:** A tiny authoritative-only DNS responder runs in the master's `hyperion-agent` (state in the master's state DB). `hyperion-web` on the master owns orchestration: a periodic tick lists every node's expiring wildcards, re-probes the customer CNAME, publishes the TXT through local-agent RPCs, and calls a new STRICT finish RPC on the owning node. Two prerequisite fixes land first: DNS-01 finish must not un-suspend a site, and the automatic path must fail closed when the pre-flight can't run.

**Tech Stack:** Rust (workspace, latest stable), tokio, sqlx/SQLite migrations in `hyperion-state`, `instant-acme` 0.8, in-house DNS wire code (`dns_probe.rs`), askama templates + htmx in `hyperion-web`.

**Spec:** `docs/superpowers/specs/2026-10-23-wildcard-auto-renew-acme-dns-design.md`

## Global Constraints

- No public update API for TXT values; values are written only through master local-socket RPCs.
- Responder: authoritative only, never recurses, REFUSED for out-of-zone names, per-source-IP rate limit, TTL 60 on TXT, SOA negative TTL (minimum) 60.
- Bind UDP+TCP 53 on every non-loopback interface address, never `0.0.0.0`/`::`.
- Responder runs ONLY when the master's local agent was explicitly enabled via `AcmeDnsConfigSet`; never driven by cluster-settings sync.
- Labels: random, stable, 16 chars, lowercase `[a-z0-9]`, created only by the explicit "Set up automatic renewal" action.
- TXT values expire on their own after 24 h (`expires_at`) and are cleared after every finish (success or failure).
- One challenge name per wildcard: `_acme-challenge.<base>` (aliases are out of scope).
- Automatic path uses STRICT finish: `ProbeError::NoResolver` is a failure, never a bypass. Manual UI path keeps today's lenient behaviour.
- New request variants (not new fields) for strict finish, so old nodes refuse instead of silently running lenient (`#[serde(default)]` fields would be ignored by an old node).
- RBAC: admin/operator = `ctx.can(Capability::CertManage) && ctx.scope_all()`. Customer sees only "Automatic renewal: on / off" for its own hosting — no CNAME target, no buttons, no label creation.
- Alerts: delegated+verified wildcard → no "renew by hand" alert while > 14 days left; alert on every failed automatic attempt (with reason); alert always at ≤ 14 days left; one admin alert when the zone delegation check fails.
- Every new `notify_admins_say` key gets BOTH `en` and `cs` strings in `crates/hyperion-core/src/letters.rs`.
- Master's own node id must be normalized to the LOCAL sentinel (`None`/`"local"` in `dispatch_to_node`) wherever node ids are aggregated.
- Long actions in the web UI (one-click issuance) run as background jobs (`spawn_job` → `/jobs/<id>`), never inline.
- Migration number: next free in `crates/hyperion-state/migrations` (086 at time of writing; re-check before creating). After adding it, force-rebuild `hyperion-state` and run `cargo test --workspace` (stale embed gotcha).
- `cargo check` skips test targets — always run `cargo test -p <crate>` / `--workspace`.
- RPC convention: every new `Request::X` gets its own `Response::X` (unit variant when there is no payload, e.g. `Response::AcmeDnsValuesClear`). "→ `Ok`" below means that unit variant. Every new variant is also added to `request_kind_label` (dispatcher) and `bin/hctl/src/print.rs`.

## Review Focus

1. **Customer removed the CNAME after setup** → no ACME order is created; label marked unverified with the probe's reason; admin alert. (Task 8 test `removed_cname_creates_no_order`.)
2. **Worker on an older build without the strict RPC** → finish returns unknown-method; master records a failure "node needs an update", alerts, and does NOT fall back to lenient finish. (Task 8 test `old_node_refusing_strict_finish_is_a_failure_not_a_fallback`.)
3. **Port 53 already held on the master (bind9, dnsmasq, unbound)** → `AcmeDnsConfigSet { enabled: true }` fails with a message naming the holder; stored config stays `enabled = false`; firewall template not applied. (Task 5 test `enable_refuses_when_port_53_is_taken`.)
4. **Hosting suspended when its wildcard renews** → cert installed, site stays suspended with the same notice. (Task 1 test.)
5. **Master crashes between `AcmeDnsValuesSet` and clear** → responder stops serving the values after 24 h; next tick's `begin` resumes the same order. (Task 3 test `expired_values_are_not_served`; Task 4 test uses only non-expired values.)

---

### Task 1: DNS-01 finish keeps a suspended site suspended

**Files:**
- Modify: `crates/hyperion-core/src/service.rs` (`cert_dns01_finish`, ~26548)
- Test: `crates/hyperion-core/src/service.rs` (tests module, next to `cert_renew_tick_renews_a_suspended_site_without_unsuspending_it`)

**Interfaces:**
- Produces: `async fn install_dns01_cert(&self, detail: &HostingDetail, cert: &CertInfo) -> Result<(), RpcError>` (private to `Service`), used by `cert_dns01_finish` and Task 2's strict variant.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn dns01_install_keeps_a_suspended_site_suspended() {
    // suspend_mocks(): expect nginx_apply_suspended().times(1), nginx_write_vhost().times(0) after suspend
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), suspend_mocks());
    s.create(req("paused.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("paused.cz").unwrap());
    s.suspend(sel.clone(), SuspendReason::Manual { message: Some("Unpaid invoice".into()) }).await.expect("suspend");
    let detail = s.get(sel.clone()).await.expect("get");
    s.install_dns01_cert(&detail, &fake_cert_info("paused.cz")).await.expect("install");
    assert_eq!(s.get(sel).await.unwrap().state, HostingState::Suspended);
    assert!(certificates::is_wildcard(&pool, "paused.cz").await.unwrap());
}

#[tokio::test]
async fn dns01_install_rewrites_the_serving_vhost_for_an_active_site() {
    // mocks: nginx_write_vhost().times(1), nginx_apply_suspended().times(0)
}
```

Mocks must also assert the suspended re-apply receives the SAME notice (`suspended_notice`) and the hosting's aliases. Add `fake_cert_info` test helper if none exists.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p hyperion-core dns01_install_ -- --nocapture`
Expected: FAIL (`install_dns01_cert` not found).

- [ ] **Step 3: Implement**

Move everything after the `acme::dns01_finish(..)` call in `cert_dns01_finish` (certificates upsert, `set_wildcard`, vhost, audit) into `install_dns01_cert`. Branch on the hosting row's state: `Suspended | Trashed` → `self.adapters.nginx_apply_suspended(&domain, aliases, self.suspended_notice(&row.id, row.state).await)`; otherwise today's `nginx_write_vhost(&new_detail)`. Mirror the comment in `cert_renew_tick` explaining why.

- [ ] **Step 4: Run tests** — `cargo test -p hyperion-core dns01_install_` → PASS; `cargo test -p hyperion-core cert_` → PASS.

- [ ] **Step 5: Commit** — `fix(certs): a DNS-01 wildcard issuance never un-suspends a site`

---

### Task 2: Strict DNS-01 finish (fail closed) as new RPC variants

**Files:**
- Modify: `crates/hyperion-adapters/src/acme.rs` (`dns01_finish`)
- Modify: `crates/hyperion-rpc/src/codec.rs` (Request + Response), `crates/hyperion-rpc/src/api.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`, `crates/hyperion-core/src/service.rs`, `bin/hctl/src/print.rs`, `bin/hyperion-web/src/dispatcher.rs` (`request_kind_label`)

**Interfaces:**
- Consumes: Task 1 `install_dns01_cert`.
- Produces:
  - `pub async fn dns01_finish_with(domain: &str, certs_root: &str, strict: bool) -> Result<CertInfo, AdapterError>`; `dns01_finish(domain, root)` = `dns01_finish_with(domain, root, false)`.
  - `Request::CertDns01FinishStrict { sel: HostingSelector }` → `Response::CertDns01Finish(CertInfo)`
  - `Request::CertDns01FinishDomainStrict { domain: Domain }` → `Response::CertDns01FinishDomain(CertInfo)`
  - `Service::cert_dns01_finish_strict(sel)`, `Service::cert_dns01_finish_domain_strict(domain)`; api trait methods of the same names.

- [ ] **Step 1: Failing tests**

In `acme.rs` tests, extract the pre-flight decision into a pure fn and test it:

```rust
// fn preflight_verdict(result: Result<(), ProbeError>, strict: bool) -> Result<(), String>
#[test]
fn strict_preflight_refuses_when_no_resolver() {
    let r = preflight_verdict(Err(ProbeError::NoResolver("blocked".into())), true);
    assert!(r.unwrap_err().contains(hyperion_types::DNS01_NOT_READY));
}
#[test]
fn lenient_preflight_proceeds_when_no_resolver() {
    assert!(preflight_verdict(Err(ProbeError::NoResolver("blocked".into())), false).is_ok());
}
```

In `codec.rs` tests: `cert_dns01_finish_strict_round_trips` (serialize → `"method":"cert_dns01_finish_strict"` → deserialize equal), same for the domain variant.

- [ ] **Step 2: Run** — `cargo test -p hyperion-adapters strict_preflight lenient_preflight` and `cargo test -p hyperion-rpc cert_dns01_finish` → FAIL.

- [ ] **Step 3: Implement** the adapter flag, the two variants end-to-end (codec, api trait, rpc-server dispatch, agent.rs forwarding, service methods reusing the existing bodies with `strict = true`), hctl printing, dispatcher label. Lenient paths unchanged.

- [ ] **Step 4: Run** — `cargo test -p hyperion-adapters -p hyperion-rpc -p hyperion-rpc-server -p hyperion-core` → PASS.

- [ ] **Step 5: Commit** — `feat(certs): strict DNS-01 finish that never asks LE without a passing pre-flight`

---

### Task 3: State — acme-dns tables, delegated flag, shared types

**Files:**
- Create: `crates/hyperion-state/migrations/086_acme_dns.sql`
- Create: `crates/hyperion-state/src/acme_dns.rs` (+ `pub mod acme_dns;` in `lib.rs`)
- Modify: `crates/hyperion-state/src/certificates.rs` (delegated flag)
- Create: `crates/hyperion-types/src/acme_dns.rs` (+ re-export in `lib.rs`)

**Interfaces:**
- Produces (types, `hyperion-types`, all `Serialize/Deserialize/Clone/Debug/PartialEq`):

```rust
pub struct AcmeDnsConfig {
    pub zone: Option<String>,          // e.g. "acme.panel.example", lowercase, no trailing dot
    pub ns_host: String,               // e.g. "ns-acme.panel.example" (lives in the PARENT zone)
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub enabled: bool,
    pub check_token: String,           // random 32 chars, generated once
    #[serde(default)] pub listening: Vec<String>,     // runtime, filled by agent
    #[serde(default)] pub last_error: Option<String>, // runtime
}
pub struct AcmeDnsLabel {
    pub base: String,                  // "example.com"
    pub label: String,                 // 16 chars [a-z0-9]
    pub hosting_id: Option<String>,    // None = preview base
    pub created_at: i64,
    pub verified_at: Option<i64>,
    pub last_check_error: Option<String>,
}
impl AcmeDnsLabel {
    pub fn challenge_name(&self) -> String;          // "_acme-challenge.<base>"
    pub fn target(&self, zone: &str) -> String;      // "<label>.<zone>"
}
```

- Produces (state fns, `hyperion_state::acme_dns`):
  - `config_get(pool) -> Result<Option<AcmeDnsConfig>, StateError>`; `config_put(pool, &AcmeDnsConfig)` (single row, id = 1; runtime fields not stored)
  - `label_ensure(pool, base: &str, hosting_id: Option<&str>, now: i64) -> Result<AcmeDnsLabel, StateError>` (idempotent; returns existing)
  - `label_get(pool, base)`, `labels_all(pool)`, `label_mark(pool, base, ok: bool, error: Option<&str>, now)`, `label_delete(pool, base)`, `labels_delete_for_hosting(pool, hosting_id) -> u64`
  - `values_set(pool, label, values: &[String], expires_at: i64)` (replaces), `values_clear(pool, label)`, `values_live(pool, now) -> HashMap<String, Vec<String>>` (label → values, expired rows excluded)
  - `certificates::set_delegated(pool, domain, bool)`, `CertRow.dns01_delegated: bool`

Migration 086 creates `acme_dns_config` (single row), `acme_dns_labels` (base PK, label UNIQUE, hosting_id, created_at, verified_at, last_check_error), `acme_dns_values` (label, value, expires_at; index on label), and `ALTER TABLE certificates ADD COLUMN dns01_delegated INTEGER NOT NULL DEFAULT 0`.

- [ ] **Step 1: Failing tests** in `acme_dns.rs` (use `open_memory()`):
  - `label_ensure_is_idempotent_and_random` — two calls same base → same label; two bases → different labels; label matches `^[a-z0-9]{16}$`.
  - `expired_values_are_not_served` — `values_set(.., expires_at = now - 1)` → `values_live(now)` has no entry.
  - `values_set_replaces_and_holds_two_values` — set `["a","b"]` then `["c","d"]` → live = `["c","d"]`.
  - `labels_delete_for_hosting_leaves_preview_labels` — hosting label removed, `hosting_id = None` label kept.
  - `config_round_trips` and `label_mark_records_error_then_clears_it` — write-then-read-back (sqlx bind-misalignment guard).
  - In `certificates.rs`: `delegated_flag_round_trips`.
- [ ] **Step 2: Run** `cargo test -p hyperion-state acme_dns delegated_flag` → FAIL.
- [ ] **Step 3: Implement.** Labels from `rand` (already a workspace dep? if not, use the existing random-token helper the codebase uses for secrets).
- [ ] **Step 4: Run** `touch crates/hyperion-state/src/lib.rs && cargo test --workspace` → PASS.
- [ ] **Step 5: Commit** — `feat(state): acme-dns zone config, labels and TXT values`

---

### Task 4: Responder answer logic (pure)

**Files:**
- Create: `crates/hyperion-adapters/src/dns_responder.rs` (+ `pub mod dns_responder;`)
- Modify: `crates/hyperion-adapters/src/dns_probe.rs` — make the wire helpers it already has (`read_name`, name encoding, constants) `pub(crate)` for reuse; no behaviour change.

**Interfaces:**
- Produces:

```rust
pub struct ZoneView {
    pub zone: String,                         // lowercase, no trailing dot
    pub ns_host: String,
    pub check_token: String,
    pub serial: u32,
    pub txt: HashMap<String, Vec<String>>,    // label -> values (already filtered for expiry)
    pub known_labels: HashSet<String>,        // labels that exist even with no values
}
/// None = drop silently (unparseable / a response packet).
pub fn answer(query: &[u8], zone: &ZoneView, max_udp: usize) -> Option<Vec<u8>>;
```

Answer rules (exactly):
| Query | Reply |
|---|---|
| opcode ≠ QUERY | NOTIMP |
| QDCOUNT ≠ 1 | FORMERR |
| name outside zone | REFUSED, `aa=0` |
| apex SOA | SOA (mname=`ns_host`, rname=`hostmaster.<zone>`, serial, 3600/600/86400/60), `aa=1` |
| apex NS | NS `ns_host`, `aa=1` |
| `_hyperion-check.<zone>` TXT | TXT `check_token`, TTL 60 |
| `<known label>.<zone>` TXT | every value, TTL 60 (empty answer NOERROR when none) |
| known name, other qtype (incl. ANY) | NOERROR, empty answer, SOA in authority |
| unknown name in zone | NXDOMAIN, SOA in authority |

Always `aa=1` in-zone, `ra=0`, RD copied but ignored, question echoed with its original case. If the reply exceeds `max_udp`, return a header-only reply with `tc=1`.

- [ ] **Step 1: Failing tests** (build queries with `dns_probe::build_query`, parse replies with `dns_probe::parse_reply`):
  - `txt_for_label_returns_both_values_authoritatively`
  - `known_label_without_values_is_empty_noerror_not_nxdomain`
  - `unknown_label_is_nxdomain_with_soa`
  - `out_of_zone_is_refused_and_not_authoritative`
  - `recursion_desired_is_never_honoured` (`ra == false`, out-of-zone still REFUSED)
  - `apex_soa_and_ns`
  - `check_token_is_served`
  - `name_match_is_case_insensitive_and_echoes_case`
  - `any_query_gets_no_records` (amplification guard)
  - `oversize_reply_sets_tc` (`max_udp = 40`)
  - `garbage_is_dropped` (`answer(&[1,2,3], ..) == None`)
  - Round-trip: `dns_probe::verdict` accepts the TXT reply for the label (proves the probe the finish path uses would pass).
- [ ] **Step 2: Run** `cargo test -p hyperion-adapters dns_responder` → FAIL.
- [ ] **Step 3: Implement** `answer`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(dns): authoritative-only acme zone responder`

---

### Task 5: Agent serves the zone + config RPCs + firewall template

**Files:**
- Create: `bin/hyperion-agent/src/acme_dns.rs` (socket loop; `mod acme_dns;` + `acme_dns::spawn(pool.clone())` in `main.rs`)
- Modify: `crates/hyperion-rpc/src/codec.rs`, `api.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`, `crates/hyperion-core/src/service.rs` (config methods + `firewall_template_commands`/`firewall_template_tags` entry `"acme-dns"`), `bin/hyperion-web/src/handlers/firewall.rs` (`port_templates()` entry so the rule is recognised), `bin/hctl/src/print.rs`, dispatcher label.

**Interfaces:**
- Consumes: Task 3 state fns, Task 4 `answer`/`ZoneView`.
- Produces RPCs:
  - `Request::AcmeDnsConfigGet` → `Response::AcmeDnsConfig(AcmeDnsConfig)` (runtime `listening`/`last_error` filled from a process-wide status cell the server loop updates)
  - `Request::AcmeDnsConfigSet { zone: Option<String>, ns_host: String, public_ipv4: Option<String>, public_ipv6: Option<String>, enabled: bool }` → `Response::AcmeDnsConfig(..)`
- Firewall template `"acme-dns"`: `udp dport 53 accept comment "hyperion:acme-dns"` and `tcp dport 53 accept comment "hyperion:acme-dns-tcp"`.

Behaviour:
- `AcmeDnsConfigSet { enabled: true }`: validate zone with `Domain::parse`, ns_host likewise and NOT inside the zone; generate `check_token` on first save; check port 53 is free on every non-loopback address (`ss -Hlunp` / `ss -Hltnp`, parse the holder process name); on conflict return `RpcError::Validation` naming the holder and persist with `enabled = false`; otherwise persist, `firewall_apply_template("acme-dns")`.
- `enabled: false`: persist, `firewall_remove_template("acme-dns")`.
- Server loop (`acme_dns::spawn`): every 10 s read `config_get`; when enabled-state/zone changes, (re)bind UDP+TCP 53 on each non-loopback interface address (enumerate with `getifaddrs` via `nix` if already a dep, else parse `ip -j addr`); build `ZoneView` per query from a cache refreshed when `values_live` changes (re-read at most every 1 s). Per-source-IP token bucket: 20 qps, burst 40, excess dropped. TCP: max 32 concurrent connections, 5 s read timeout, 2-byte length framing, `max_udp = 65535`. UDP `max_udp = 1232`.

- [ ] **Step 1: Failing tests**
  - service: `enable_refuses_when_port_53_is_taken` — feed the port check a fake `ss` output containing `users:(("named",pid=1,fd=5))` on `203.0.113.5:53` → error message contains `named`; `config_get` shows `enabled == false`.
  - service: `enable_rejects_ns_host_inside_zone`.
  - service: `acme_dns_firewall_template_has_udp_and_tcp_53` (inspect `firewall_template_commands("acme-dns")`).
  - agent: `token_bucket_drops_after_burst` (pure struct test).
  - agent: `udp_loop_answers_on_an_ephemeral_port` — bind the loop to `127.0.0.1:0` via a test-only constructor, send a TXT query, assert the value.
- [ ] **Step 2: Run** `cargo test -p hyperion-core acme_dns enable_ && cargo test -p hyperion-agent acme_dns` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS; `cargo test --workspace` → PASS.
- [ ] **Step 5: Commit** — `feat(agent): serve the delegated acme zone on the master`

---

### Task 6: Label/value RPCs, delegated flag on nodes, node tick + alerts

**Files:**
- Modify: codec/api/rpc-server/agent.rs/service.rs/hctl print/dispatcher label (as Task 5)
- Modify: `crates/hyperion-types/src/cert.rs` (`CertOverviewItem`), service `CertOverview` builder
- Modify: `crates/hyperion-core/src/service.rs` (`cert_renew_tick` skip branch + alert, `wildcard_renew_hint`)
- Modify: `crates/hyperion-core/src/letters.rs`

**Interfaces:**
- Produces RPCs (master local agent):
  - `AcmeDnsLabelEnsure { base: Domain, hosting_id: Option<String> }` → `Response::AcmeDnsLabel(AcmeDnsLabel)`
  - `AcmeDnsLabels` → `Response::AcmeDnsLabels(Vec<AcmeDnsLabel>)`
  - `AcmeDnsLabelMark { base: Domain, ok: bool, error: Option<String> }` → `Ok`
  - `AcmeDnsLabelDelete { base: Domain }`, `AcmeDnsLabelsDeleteForHosting { hosting_id: String }` → `Ok`
  - `AcmeDnsValuesSet { label: String, values: Vec<String> }` (expires_at = now + 86400), `AcmeDnsValuesClear { label: String }` → `Ok`
  - `AcmeDnsRenewReport { domain: String, node_id: String, ok: bool, detail: String, days_left: i64 }` → `Ok` (audit `cert.renew.dns01_delegated` + alert on `!ok`)
  - `AcmeDnsZoneBroken { detail: String }` → `Ok` (one admin alert, kind `acme_dns.zone_broken`)
- Produces RPC (owning node): `CertSetDelegated { domain: Domain, delegated: bool }` → `Ok`
- `CertOverviewItem` gains `#[serde(default)] wildcard: bool`, `#[serde(default)] renewal_type: String`, `#[serde(default)] hosting_id: Option<String>`, `#[serde(default)] delegated: bool`.
- Letters (en + cs): `ops.cert_wildcard_auto_failed` (params `domain`, `reason`, `days`), `ops.acme_dns_zone_broken` (param `reason`), `ops.cert_wildcard_delegated_skip` (skip reason text: renewed by the master over the delegated acme zone).

Node tick change (`cert_renew_tick`, wildcard arm): if `cert.dns01_delegated` → `Skipped { reason: <delegated_skip letter> }`, and in the alert match only raise `ops.cert_wildcard_manual` when `!delegated || days_left <= 14`.

- [ ] **Step 1: Failing tests**
  - `delegated_wildcard_is_skipped_without_manual_alert` — upsert wildcard LE cert, `set_wildcard`, `set_delegated(true)`, 25 days left → outcome Skipped with delegated reason; no notification row of kind `cert.wildcard_manual:*`.
  - `delegated_wildcard_alerts_at_14_days` — same with 10 days left → notification exists.
  - `undelegated_wildcard_still_alerts` — unchanged behaviour.
  - `renew_report_failure_raises_auto_failed_alert`.
  - codec round-trip for each new variant; `cert_overview_item_old_json_still_parses` (JSON without new fields).
  - `letters_have_cs_for_new_keys` (or extend the existing catalogue completeness test).
- [ ] **Step 2: Run** `cargo test -p hyperion-core delegated_ renew_report && cargo test -p hyperion-rpc acme_dns cert_overview` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test --workspace` → PASS.
- [ ] **Step 5: Commit** — `feat(certs): delegated wildcards skip the manual nag; acme-dns label RPCs`

---

### Task 7: Probes — customer CNAME and zone delegation

**Files:**
- Modify: `crates/hyperion-adapters/src/dns_probe.rs`

**Interfaces:**
- Produces:
  - `pub async fn check_cname(name: &str, expected_target: &str) -> Result<(), CnameProblem>` — asks the authoritative NS of `name`'s zone (existing `find_zone` + `ask_authorities`).
  - `pub enum CnameProblem { Missing, PointsElsewhere(String), PlainTxtPresent, NoResolver(String), Other(String) }` with `Display` giving the operator-facing sentence (e.g. PlainTxtPresent: "a TXT record sits at <name>; replace it with the CNAME").
  - `pub async fn check_zone_delegated(zone: &str, check_token: &str) -> Result<(), String>` — TXT `_hyperion-check.<zone>` through the PUBLIC recursors (`PUBLIC_RESOLVERS`, recursion on); Ok only when one answers exactly `check_token`.
  - `pub async fn txt_visible_via_public(name: &str, values: &[String]) -> Result<(), String>` — through public recursors, following CNAMEs.

- [ ] **Step 1: Failing tests** — pure interpretation fns over canned `Reply`s (same style as `cname_is_reported_for_following`): `cname_to_expected_target_is_ok`, `cname_case_and_trailing_dot_are_normalised`, `cname_elsewhere_is_reported_with_target`, `txt_instead_of_cname_is_reported`, `nxdomain_is_missing`. `check_zone_delegated` interpretation: `wrong_token_is_refused` (another panel's zone).
- [ ] **Step 2: Run** `cargo test -p hyperion-adapters dns_probe` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(dns): probes for acme CNAME delegation and zone reachability`

---

### Task 8: Master renewal orchestrator

**Files:**
- Create: `bin/hyperion-web/src/acme_dns_renew.rs` (+ `pub mod` in `lib.rs`, `hyperion_web::acme_dns_renew::spawn(state.clone())` in `main.rs` next to `notify_collector::spawn`)

**Interfaces:**
- Consumes: Tasks 2, 3, 5, 6, 7.
- Produces:

```rust
pub struct DueCert { pub node_id: Option<String>, pub domain: String, pub hosting_id: Option<String>, pub label: AcmeDnsLabel, pub days_left: i64 }
/// Pure: LE-issued (issuer starts_with "letsencrypt"), renewal_type != "manual",
/// wildcard, days_left <= window_days, and a label exists for the domain.
pub fn select_due(items: &[(Option<String>, CertOverviewItem)], labels: &[AcmeDnsLabel], window_days: i64) -> Vec<DueCert>;
pub async fn run_once(state: &SharedState) -> Vec<(String, Result<(), String>)>;
pub fn spawn(state: SharedState);
```

`run_once` (only when `AcmeDnsConfigGet` says enabled; only on the master):
1. `check_zone_delegated(zone, check_token)`; failure → `AcmeDnsZoneBroken` once, stop.
2. Gather `CertOverview` from LOCAL + every node in `NodesList` (normalize master hostname to `None`); `select_due` with `renewal_window_days` (30 default; read the master agent's `[acme]` value from `AgentConfigView`).
3. Per due cert, sequentially:
   a. `check_cname(label.challenge_name(), label.target(zone))` → `AcmeDnsLabelMark`; on failure report `ok=false` with the `CnameProblem` text and `continue` (no order).
   b. Begin on owning node: hosting → `CertDns01Begin { sel: HostingSelector::Id(HostingId::parse(&hosting_id)?), staging: false }`, preview → `CertDns01BeginDomain { domain, email: None, staging: false }`.
   c. Every returned record name must equal `label.challenge_name()`, else failure; `AcmeDnsValuesSet { label, values }`.
   d. `txt_visible_via_public(challenge_name, values)` with up to 6 attempts, 10 s apart.
   e. Strict finish on owning node (`CertDns01FinishStrict` / `CertDns01FinishDomainStrict`). An unknown-method / deserialize error → failure "node <id> needs an update for automatic wildcard renewal". No lenient fallback.
   f. `AcmeDnsValuesClear` always (also on every error path after c).
   g. `AcmeDnsRenewReport` with outcome.
4. Also, for every label with `verified_at` set, `CertSetDelegated { domain, delegated }` to the owning node so node-side alerts follow (delegated = last check ok).

`spawn`: first run 10 min after start, then every 24 h (spec: daily tick), `MissedTickBehavior::Delay`. Make the dispatch layer injectable (a small trait or closure param on an inner `run_once_with`) so tests run without sockets.

- [ ] **Step 1: Failing tests**
  - `select_due_picks_only_le_wildcards_with_labels_inside_window` — table of items: manual, non-LE, non-wildcard, outside window, no label, one valid → exactly the valid one.
  - `select_due_normalises_master_hostname_to_local`.
  - `removed_cname_creates_no_order` — fake probe returns `Missing` → no `CertDns01Begin` dispatched; `AcmeDnsLabelMark { ok: false }` and a failure report sent.
  - `values_are_cleared_when_finish_fails` — fake finish error → `AcmeDnsValuesClear` dispatched.
  - `old_node_refusing_strict_finish_is_a_failure_not_a_fallback` — fake node returns unknown-method → report contains "needs an update"; no `CertDns01Finish` (lenient) dispatched.
  - `happy_path_dispatch_order` — Begin → ValuesSet → FinishStrict → ValuesClear → RenewReport.
  - `broken_zone_alerts_once_and_stops`.
- [ ] **Step 2: Run** `cargo test -p hyperion-web acme_dns_renew` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(certs): master renews delegated wildcards unattended`

---

### Task 9: Settings → HTTPS "Automatic wildcard renewal" card

**Files:**
- Modify: the HTTPS settings handler under `bin/hyperion-web/src/handlers/settings/` and `bin/hyperion-web/templates/settings_https.html`
- Modify: `bin/hyperion-web/src/handlers/settings/chrome.rs` (`CARDS`: `("acme-dns", "https")`)
- Modify: `bin/hyperion-web/src/lib.rs` (routes)
- Test: `bin/hyperion-web/tests/web_e2e.rs`

**Interfaces:**
- Consumes: Task 5 RPCs, Task 7 `check_zone_delegated`.
- Routes (admin/operator gate: `ctx.can(Capability::CertManage) && ctx.scope_all()`, else 403):
  - `POST /settings/https/acme-dns` — form `zone`, `ns_host`, `enabled` → `AcmeDnsConfigSet` on LOCAL agent; refusal re-renders the card in place with the message.
  - `POST /settings/https/acme-dns/check` — htmx partial with state: not set up / delegation missing / points elsewhere (another token) / working.

Card contents: zone input (default suggestion `acme.<panel_hostname>`), ns host (default `ns-acme.<panel parent>`), the records to add (NS, A, AAAA when IPv6 known) with copy buttons, enable toggle, Check button + state, list of delegated wildcards (domain, node, verified, last error). Follow `.group`/`.item` card conventions; confirm dialogs live on the `<form>` (`data-confirm-*`), not the button.

- [ ] **Step 1: Failing e2e tests**: `acme_dns_card_renders_records_for_admin`, `acme_dns_save_refusal_rerenders_in_place`, `acme_dns_settings_forbidden_for_customer` (403 on both POSTs), deep link `/settings/https#acme-dns` resolves via `CARDS`.
- [ ] **Step 2: Run** `cargo test -p hyperion-web --test web_e2e acme_dns` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS; also `template_lint` tests pass.
- [ ] **Step 5: Commit** — `feat(web): Settings → HTTPS card for the delegated acme zone`

---

### Task 10: Hosting SSL tab + preview wildcards + one-click issuance + purge cleanup

**Files:**
- Modify: `bin/hyperion-web/src/handlers/hostings.rs` (SSL tab, DNS-01 handlers near `post_cert_dns01_begin` ~13013, purge/delete handlers), `bin/hyperion-web/templates/cert_dns01.html` and the SSL tab template, the Preview-certificates section of `settings_https.html` + its handler
- Modify: `bin/hyperion-web/src/lib.rs` (routes)
- Test: `bin/hyperion-web/tests/web_e2e.rs`

**Interfaces:**
- Consumes: Tasks 2, 3, 6, 7.
- Routes (admin/operator gate as Task 9; customer gets 403):
  - `POST /hostings/{id}/cert/acme-dns/setup` → `AcmeDnsLabelEnsure { base, hosting_id: Some(id) }`, then probe + `AcmeDnsLabelMark`; renders the block.
  - `POST /hostings/{id}/cert/acme-dns/check` → re-probe + mark; htmx partial.
  - `POST /hostings/{id}/cert/dns01/auto` → `spawn_job` running begin → ValuesSet → public visibility wait → strict finish → clear (reuse Task 8's per-cert fn, exposed as `pub async fn renew_one(state, &DueCert) -> Result<(), String>`), redirect `/jobs/<id>`. Only offered when the label is verified.
  - Certificates overview (`certs.html`): each wildcard row shows "auto-renew on/off" next to its expiry (from `CertOverviewItem.delegated`).
  - Preview equivalents under `/settings/https/preview/{node}/acme-dns/{setup,check,auto}` with `hosting_id: None`.
- Purge/delete: after a successful hosting purge or final delete dispatch, call `AcmeDnsLabelsDeleteForHosting { hosting_id }` on LOCAL; the purge confirmation text adds one line that the customer's `_acme-challenge` CNAME can now be removed. Trash keeps labels.

Block for admin/operator: challenge name, CNAME target, copy button, live state (`CnameProblem` text), one sentence that the CNAME lets this panel obtain certificates for the domain until removed, one-click issue button when verified. Customer: only "Automatic renewal: on" (label verified and zone enabled) or "off".

- [ ] **Step 1: Failing e2e tests**: `ssl_tab_shows_cname_block_to_operator`, `ssl_tab_shows_only_state_to_customer` (no `.acme.` target string, no setup form in HTML), `acme_dns_setup_forbidden_for_customer` (403), `setup_is_idempotent_label_unchanged`, `auto_issue_starts_a_job` (303 to `/jobs/`), `purge_deletes_acme_labels`, `trash_keeps_acme_labels`.
- [ ] **Step 2: Run** `cargo test -p hyperion-web --test web_e2e ssl_tab acme_dns purge_ trash_keeps auto_issue` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test --workspace` → PASS.
- [ ] **Step 5: Commit** — `feat(web): set up automatic wildcard renewal from the SSL tab`

---

### Task 11: Runbook + staging end-to-end

**Files:**
- Modify: `docs/RUNBOOK.md` (new section "Automatic wildcard renewal": NS delegation records, check, troubleshooting: port 53 holder, CNAME problems, node too old)

- [ ] **Step 1:** Write the runbook section.
- [ ] **Step 2:** Manual e2e on a real master against LE **staging** (temporarily point the orchestrator at staging via a test-only flag or run `renew_one` from a debug hctl command if added): delegate a test zone, CNAME a test domain, force a renewal, confirm new `not_after`, confirm a suspended test site stays suspended, confirm `dig @<master> TXT example.<zone>` returns REFUSED for out-of-zone names and `dig +norec` works.
- [ ] **Step 3:** `cargo fmt --all --check && cargo clippy --workspace --all-targets && cargo test --workspace` → clean/PASS.
- [ ] **Step 4: Commit** — `docs: runbook for automatic wildcard renewal`
