# Wildcard certificates renew themselves (acme-dns style CNAME delegation)

Status: draft 2026-10-23 — awaiting approval

## Why

A wildcard certificate can only be validated over DNS-01, and Hyperion holds
no DNS credentials. Today `cert_renew_tick` therefore skips every wildcard
(`service.rs`, `CertRenewOutcome::Skipped` + `wildcard_renew_hint`) and the
operator re-runs the manual flow every ~60 days: start issuance, copy the TXT
values into someone's DNS panel, wait, validate. That is recurring manual work
per wildcard, it fails silently when someone is on holiday, and Let's Encrypt
is shortening certificate lifetimes, so the cadence only gets worse.

The standard fix (the "acme-dns" pattern) needs no DNS credentials: the
domain owner adds ONE permanent record,

    _acme-challenge.example.com.  CNAME  k3f9q2xw7hm4p8ta.acme.panel.example.

and from then on Hyperion publishes the challenge TXT under its own zone,
where it is authoritative. Let's Encrypt follows the CNAME. Renewal becomes
unattended.

## Goals

- A wildcard whose challenge names are delegated renews with nobody touching
  it, on every node, including test-node preview wildcards (`*.<base>`).
- First issuance of a delegated wildcard is one click (no TXT copying).
- Setup cost for the operator: one NS delegation, once per cluster. For each
  wildcard domain: one CNAME per challenge name, once, forever.
- The panel says plainly, per wildcard, whether auto-renew is on, and if not,
  exactly which record is missing or wrong.

## Non-goals (v1)

- DNS provider APIs (Cloudflare, Wedos, …). The design leaves room for them
  as another "publisher" later, but they are not built now.
- Using DNS-01 for non-wildcard certificates. HTTP-01 stays the path for those.
- Redundant/HA nameservers. One authoritative server (the master) is enough:
  if the master is down, the panel is down anyway, and the 30-day renewal
  window absorbs outages.
- DNSSEC for the acme zone.
- Serving any record other than what the zone needs (SOA, NS, TXT).

## Anti-goals (a failure even if renewals work)

- Becoming an open resolver or a DNS amplification source.
- Asking Let's Encrypt to validate before the TXT is really served, burning
  the failed-validation rate limit (5/hour/hostname) and invalidating orders.
- Losing the "this cert will expire" alert: a delegated wildcard that fails
  to renew must still reach a human, with time left to act.
- A delegation that keeps working for a domain after its hosting is gone
  (the panel must stop answering for it).

## Constraints from the existing code

- The ACME DNS-01 flow already exists in two phases:
  `hyperion_adapters::acme::dns01_begin` / `dns01_finish`, exposed per node
  as RPCs `cert_dns01_begin` / `cert_dns01_finish` (hosting) and
  `cert_dns01_begin_domain` / `cert_dns01_finish_domain` (bare preview base).
  The master already drives these RPCs from the web UI. The pending order is
  resumable (same TXT values on repeat `begin`).
- `dns01_finish` already pre-flights against the zone's authoritative
  nameservers and **already follows a CNAME chain** (`dns_probe.rs`,
  `MAX_CNAME_HOPS = 5`); the responder must answer with `aa` set. BUT the
  pre-flight is not fail-closed: on `ProbeError::NoResolver` (outbound DNS
  blocked on the node) it logs and asks LE anyway (acme.rs ~647). The
  automatic path must not do that — see 5.
- `cert_dns01_begin` / `_begin_domain` request exactly `<base>` and
  `*.<base>`; aliases are never added to a wildcard. So every wildcard has
  exactly ONE challenge name, `_acme-challenge.<base>`.
- `cert_dns01_finish` always calls `nginx_write_vhost` with no state check,
  so calling it on a suspended/trashed hosting un-suspends the site.
  `_finish_domain` is safe. This must be fixed before any unattended call.
- The agent has no notion of "am I the master" (`is_master` lives only in
  hyperion-web), and cluster settings are pushed to every node.
- One `_acme-challenge.<base>` name covers both `<base>` and `*.<base>`, and
  both authorizations publish two TXT values on that name at the same time.
  (Covering aliases in a wildcard is out of scope for v1 — *my call*; the
  label table is keyed by challenge name so it can grow to that later.)
- Per-node renewal runs in each agent (`bin/hyperion-agent/src/main.rs`,
  daily tick). Cross-node orchestration lives in `hyperion-web` on the master
  (`dispatcher.rs::dispatch_to_node`). The master's own node id is its
  hostname and must be normalized to the LOCAL sentinel (memory:
  master-node-id-is-hostname).
- The agent runs as root and can bind :53; the web process should not.
- Firewall: nft-based, with base rules managed by Hyperion. Opening a port
  must go through that mechanism, not a hand-written rule.

## Design

### 1. The acme zone (once per cluster)

Settings → HTTPS gets a new card "Automatic wildcard renewal".

- Operator enters a zone name. Default suggestion: `acme.<panel domain>`.
- Panel shows the two records to add at the parent zone's DNS provider:

      acme.panel.example.      NS  ns-acme.panel.example.
      ns-acme.panel.example.   A   <master public IPv4>
      (AAAA too when the master has public IPv6)

- "Check" button: resolves `SOA acme.panel.example` through the public
  recursors and confirms the answer came from the master. States: not set up
  / delegation missing / delegation points elsewhere / working.
- Enabling the feature: hyperion-web on the master sends an explicit enable
  call to its LOCAL agent only (`AcmeDnsResponderSet { zone, enabled }`),
  which persists it in the master agent's own config/state and starts the
  responder; the firewall opens udp+tcp 53 on the master only. Disabling
  closes both. NOT driven by cluster-settings sync — that reaches every node,
  and workers must never start the responder.
- The zone name may additionally live in cluster settings for display, but
  only the explicit local call turns serving on.

### 2. The responder (master agent)

A small authoritative-only DNS server inside `hyperion-agent`, active only on
the master and only when the feature is enabled.

- Binds UDP and TCP port 53 on every non-loopback interface address, not
  `0.0.0.0` (avoids colliding with systemd-resolved's 127.0.0.53 stub). This
  also works behind 1:1 NAT, where the public IPv4 is on no interface — *my
  call*. The glue record shown to the operator uses the configured/discovered
  public IP; the Check button verifies from outside (public recursors), not
  by comparing addresses. If the port is held by something else, enabling
  fails with a message naming the holder.
- Answers only names at or under the configured zone:
  - zone apex: SOA and NS (the `ns-acme` name), `aa` set.
  - `ns-acme.<zone>`: A/AAAA of the master.
  - `<label>.<zone>` TXT: every value currently stored for that label (0, 1
    or 2+ values); NOERROR with empty answer when the label exists but has no
    value right now; NXDOMAIN for unknown labels.
  - anything outside the zone: REFUSED. No recursion, ever.
- TTL 60 on TXT, short negative TTL in SOA (60) so a freshly published value
  is not hidden by a cached NXDOMAIN.
- Per-source-IP response rate limit (simple token bucket); responses are tiny
  anyway, but it must never be useful as an amplifier.
- Data source: a table in the master's state DB (see 4), read per query or
  via an in-memory cache invalidated on write. Values are written only by the
  master's renewal/issuance code path through a local-agent RPC
  (`AcmeDnsSet { label, values }` / `AcmeDnsClear { label }`); there is no
  public update API (unlike upstream acme-dns, which exposes one).

Implementation: in-house, reusing `dns_probe.rs`'s wire parsing, in keeping
with that module's "deliberately small" stance — *my call; the builder may
pick `hickory-server` instead if it is clearly less code, latest version per
project preference.*

### 3. Per-domain delegation

- Each wildcard base's challenge name (`_acme-challenge.<base>`) gets a
  random, stable, 16-char lowercase label, created on an explicit "Set up
  automatic renewal" action (not on page view, so hostings that never get a
  wildcard leave no orphan labels) — *my call*. Random,
  not derived from the domain, so labels can't be guessed or collide, and a
  hosting moved to another node keeps the same CNAME.
- Hosting SSL tab, for a wildcard (or when starting wildcard issuance): an
  "Automatic renewal" block showing the challenge name with its CNAME target, a copy button, and a live status from a probe that
  walks the authoritative NS (reuse `dns_probe`): missing / CNAME points
  elsewhere / OK. A plain TXT at the name (left over from manual issuance)
  is reported as "replace this TXT with the CNAME".
- Settings → HTTPS → Preview certificates: the same block for each node's
  `*.<base>`.
- A wildcard is "auto-renew on" when the zone works AND its challenge name
  is verified OK. That state is shown next to the cert's expiry
  everywhere the cert is listed.
- With delegation verified, wildcard issuance becomes one button: the panel
  runs begin → publish → finish itself (as a background job, memory:
  long-actions-are-background-jobs) instead of showing TXT values.
- When a hosting is purged (not trashed) its labels are deleted, so the
  responder stops answering for them. The purge confirmation reminds the
  operator the customer's CNAME can be removed. Trash keeps them (restore
  must keep working).

### Who can do what (decided 2026-10-23)

- Setting up the acme zone, creating a label ("Set up automatic renewal"),
  seeing the CNAME target, and one-click delegated issuance: admin and
  operator only (gate with the existing cert-management capability, or a new
  one if none fits — builder's call).
- Customer role: sees at most the state of its own hosting's wildcard
  ("automatic renewal: on / off"). No CNAME target, no buttons, no label
  creation. Viewer follows the existing read-only rules.

### 4. Data (master state DB, new migration)

`acme_dns_labels`:

| column           | meaning                                                   |
|------------------|-----------------------------------------------------------|
| challenge_name   | `_acme-challenge.example.com` (lowercase, punycode), PK   |
| label            | random 16-char, UNIQUE                                    |
| hosting_id       | NULL for a preview base                                   |
| created_at       |                                                           |
| verified_at      | last time the probe saw the correct CNAME, NULL if never  |
| last_check_error | human-readable reason from the last failed probe          |

`acme_dns_values`: `(label, value, expires_at)` — current TXT values. Rows
are cleared after `finish` (success or failure) and expire on their own after
24 h so a crash can't leave stale values served forever.

Exact schema and names are the builder's call.

### 5. Renewal orchestration (master)

A daily tick in `hyperion-web` on the master (offset from the agents' tick):

1. For every node (master included, normalized to LOCAL), list certificates
   that are LE-issued, not `renewal_type = manual`, wildcard, and expire
   within `renewal_window_days`.
2. Keep those whose challenge name is delegated and verified. Before any
   order, the MASTER re-probes from itself: the customer's CNAME still points
   at our label, and the zone delegation resolves to our responder. Either
   failing = no order, alert instead (a removed CNAME must never cost a
   failed validation).
3. Per cert, sequentially (LE rate limits are per account/hostname; there are
   few wildcards):
   - call `cert_dns01_begin` / `_begin_domain` on the owning node → records;
   - map each record name to its label, `AcmeDnsSet` on the local agent;
   - master checks via public recursors that the new TXT values are visible
     through the CNAME;
   - call `cert_dns01_finish` / `_finish_domain` on the owning node in a new
     STRICT mode (new flag on the RPC + adapter): the pre-flight must pass,
     and `NoResolver` is a failure, not a bypass. The manual UI path keeps
     today's lenient behaviour;
   - `AcmeDnsClear` regardless of outcome;
   - audit log entry `cert.renew.dns01_delegated` with outcome.
4. Suspended / trashed hostings: renew, same rule as the HTTP-01 path.
   Prerequisite fix: `cert_dns01_finish` must re-apply the suspended vhost
   (not `nginx_write_vhost`) for Suspended/Trashed hostings, mirroring what
   `cert_renew_tick` does for HTTP-01. This also fixes the manual UI path.

The node's own daily tick keeps skipping wildcards (it can't publish DNS),
but its skip reason changes when the cert is delegated: "renewed by the
master over the delegated acme zone" instead of the "renew by hand" hint.

### 6. Alerts

- Delegated + verified wildcard: no "renew by hand" alert while the master is
  handling it. Alert when an automatic attempt fails (with the reason: NS
  delegation broken, CNAME missing, LE error), and always when the cert has
  ≤ 14 days left regardless of state.
- Not delegated: today's alert, plus one line suggesting the CNAME with the
  exact record.
- Zone delegation stops working (daily self-check): one admin alert, since it
  breaks every delegated wildcard at once.

## Security notes

- A CNAME is standing permission for the panel to obtain certificates for
  that name. That is the point, but the UI must say so once where the
  CNAME instructions are shown (admin/operator view), and purge removes the
  label.
- Anyone who controls the master can already issue for those names; the
  responder adds no new holder of that power.
- The responder never recurses, refuses out-of-zone names, rate-limits per
  source, and accepts no updates from the network.
- Port 53 is opened on the master only, only while the feature is enabled.

## Left to the builder

- In-house responder vs `hickory-server` (default: in-house, see 2).
- Exact RPC names/shapes for the master→local-agent set/clear calls and for
  listing a node's expiring wildcards (reuse an existing cert list RPC if one
  fits).
- Table names/columns, cache strategy in the responder.
- UI copy and layout within existing patterns (`.group`/`.item` cards, IA
  rules in memory: settings-sidebar-ia, ui-keep-design-fix-ia).
- Tick time of day.

## Testing

- Responder unit tests: SOA/NS/TXT answers, multiple TXT values, NXDOMAIN vs
  empty NOERROR, REFUSED out of zone, no RD honoured, TCP, rate limit.
- `dns_probe` against the responder in-process: a CNAME chain from a fake
  customer zone ends at our TXT and the verdict passes.
- Orchestration with a fake node + fake ACME (no live LE in CI): begin →
  set → finish → clear, clear on failure, removed CNAME skips the order,
  manual/non-LE certs untouched.
- Manual end-to-end on a real master against LE staging before release.
