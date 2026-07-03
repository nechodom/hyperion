# Per-site HA — active-passive with Cloudflare DNS failover — design

Status: proposed (2026-07-03). Driver: issue #1 follow-up (@LaAlexita), clarified
to **"the second option: if a node is down, the system continues to function."**
This is **per-site HA** (a hosted site survives its node dying) — distinct from,
and complementary to, the **control-plane HA** in
`2026-06-30-ha-control-plane-design.md` (keeping the panel/master available).

## What the requester wants (and what this is not)

- **Wants:** a site keeps serving when the node it lives on goes down.
- **Not this doc:** control-plane HA (panel staying up). Sites already survive a
  master outage — nginx/PHP run on the workers. This doc is about surviving a
  **worker** outage, per site.
- **Locked constraints (from the exchange):**
  1. **DNS is managed via Cloudflare only** — the operator does not run DNS and
     won't. Failover must repoint the record through the **Cloudflare API**
     (reuse the token Hyperion already stores for DNS-01 wildcard certs).
  2. **Failover must work with the master OFFLINE.** "Master off for 2 days,
     node dies, site must still recover." → the failover decision + action MUST
     live on the nodes, not the master.

## Model shift (be honest about scope)

Today: **1 site = 1 node** (Linux user + FPM pool + nginx vhost + local DB on one
box). This design adds an **opt-in active-passive pair** per HA-enabled site:

```
        Cloudflare DNS  (A record, TTL 60s)  ◄── flipped via CF API on failover
                    ▲
   node A (PRIMARY) ── continuous replication ──► node B (STANDBY)
   serves the site       files + database          warm copy, idle, watches A,
                                                    holds CF token + peer info
```

Full **active-active** (same site served concurrently from N nodes behind a load
balancer, shared storage, DB cluster, shared sessions) is a much larger, separate
end-state and is explicitly out of scope here (tracked as v3).

## The make-or-break principle: masterless failover

If health-checking + the DNS flip lived on the master, a master outage would mean
**no failover** — useless exactly when you need it. So:

> The **standby node** watches its primary directly and performs the failover
> (activate locally + flip Cloudflare) on its own. The master only **sets pairs
> up** and **shows status** — it is never in the failover path.

Each node caches locally (in its agent state, pushed by the master when last up):
its **role** (primary/standby) per HA site, its **peer's** address, and the
**Cloudflare token + zone/record id** for the sites it stands by for. So a
standby has everything it needs to fail over with the master dark.

## Components

### 1. HA pair
When HA is enabled for a site, the master picks a **standby node** (auto-placement,
excluding the primary) and records the pair. Role + peer + CF record info are
replicated to **both** nodes' local state.

### 2. Continuous replication (primary → standby)
Runs on the nodes, independent of the master once configured.
- **Files:** `lsyncd`/`rsync` of `htdocs` A→B (near-continuous).
- **Database:**
  - **v1:** periodic `dump → ship (ssh) → restore` on the standby. Simple, no new
    daemons. **RPO = the dump interval (minutes).**
  - **v2:** MariaDB async replication A→B (per-site), promote on failover.
    **RPO seconds.** (The hard, higher-risk part — deferred.)

### 3. Health check + failover (on the STANDBY, masterless)
- B probes A's site (HTTP health + a node heartbeat) on a short interval.
- After **N consecutive misses**, B **promotes**: activates the vhost + FPM pool
  locally from its replicated copy, promotes its DB (v2) / uses the last dump
  (v1), and **calls the Cloudflare API to point the record at B's IP**.
- Because B holds the token + record id locally, this works with the master off.

### 4. Cloudflare DNS
Reuse the existing Cloudflare-token integration.
- **(a) API record flip (free, recommended):** on failover B rewrites the site's
  A/AAAA record to its own IP. **TTL 60s** so failover propagates fast. DIY health
  check (§3).
- **(b) Cloudflare Load Balancing (paid, optional):** a pool with A+B origins +
  Cloudflare health checks; Cloudflare fails over/anycasts for you — no DIY health
  logic, but a paid feature and both origins must be health-checkable.

### 5. Failback
When A returns, it rejoins as the **new standby** (re-syncs FROM B). **No
auto-failback flap** — an operator (or a later v2 policy) decides when/if to flip
back.

## Master-offline behaviour (the requester's scenario)

Master off 2 days, a node then dies:
- **Sites keep serving** — nodes are autonomous for traffic.
- **Failover still happens** — the standby detects the primary's death and flips
  Cloudflare on its own. ✅ No master needed.
- **What does NOT work while the master is down:** enabling *new* HA pairs /
  config changes, the panel UI, and the singleton **ACME auto-renewal** (a master
  scheduler — certs would only lapse after ~a month near expiry; 2 days is fine).
  → Combine with **control-plane HA** (the S3-free warm-standby master from the
  companion doc) so the master also recovers.

## Split-brain / fencing (the real hazard)

If A isn't actually dead (an A↔B network partition, A still serving), B promoting
→ both serve → divergent DB writes.
- **v1 (best-effort):** B promotes only if it **cannot reach A but CAN reach the
  internet (Cloudflare)** — distinguishing "A is down" from "B is isolated" — and
  makes a **best-effort fence** (tell A to demote/stop serving if reachable).
  Residual risk documented; acceptable for opt-in active-passive.
- **v2 (proper):** a **witness / quorum** (the master when up + a 3rd small node)
  that both A and B consult; B promotes only with witness agreement that A is
  down. Removes simple-partition split-brain.

## RPO / RTO (state it plainly)

| | RPO (data loss window) | RTO (downtime) |
|---|---|---|
| v1 (dump-ship + DNS flip) | minutes (last DB dump) | ~TTL + probe window (≈1–2 min) |
| v2 (live replication + witness) | seconds | seconds–TTL |

Not zero-downtime. "The system continues to function" after a short blip — honest.

## Phasing

- **v1 (target for "node HA now"):** HA pair + rsync files + dump-ship DB +
  masterless health-check on the standby + Cloudflare API flip + best-effort
  fencing. Opt-in per site. Delivers the requester's ask.
- **v2:** live DB replication (RPO seconds) + witness/quorum fencing + optional
  auto-failback.
- **v3 (end-state, separate):** true active-active behind a load balancer
  (shared/replicated storage + DB cluster + session store).

## Constraints / applicability

- **Opt-in per site** — redundancy costs a second node's resources.
- **App must tolerate active-passive** — normal PHP/WordPress does; apps writing
  to node-local external state may not.
- **Two nodes minimum** per HA site (primary + standby); a shared standby can back
  several primaries if capacity allows.
- **Reuses existing primitives:** Cloudflare token (DNS-01), backups/restore,
  node registry + signed RPC, cert-pinning, auto-placement.

## Open questions for the maintainer

1. **RPO tolerance:** is v1 (minutes, last dump) acceptable to start, or is
   seconds (v2 live replication) required from day one?
2. **Fencing:** ship v1 best-effort first (documented residual split-brain risk),
   or hold for the v2 witness?
3. **Cloudflare:** API record flip (free, DIY health) or Cloudflare Load Balancing
   (paid, CF does health/failover)?
4. **Shared vs dedicated standby:** one standby per primary, or a shared spare
   backing several sites?
