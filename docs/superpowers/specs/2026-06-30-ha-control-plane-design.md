# High availability (control plane) — design

Status: proposed (2026-06-30). Driver: issue #1 follow-up (@LaAlexita): "It would
also be interesting to add a high-availability option."

## Reframe first (scope)

The **hosted sites already survive a master outage.** nginx + php-fpm run on the
**worker nodes** and serve traffic independently of the master. The master is the
**control plane** only — it holds the authoritative state DB and runs the web UI
+ singleton schedulers (ACME renewals, scheduled backups, billing sweep,
expiries).

So "HA" here means **keeping the panel/control-plane available**, not keeping
sites up (those already are). A *different*, larger topic — running the same site
on multiple nodes behind a load balancer (per-site HA) — is explicitly out of
scope here; confirm with the requester which they mean.

## The single point of failure

The master node holds:
- the authoritative **SQLite** state (`hyperion-state`) — hostings, profiles,
  users, sessions, quotas, billing, audit;
- the web UI;
- the singleton drivers (ACME, scheduled backups, billing, expiry sweeps).

If the master dies: no UI, no changes, scheduled jobs pause — **but existing
sites keep serving.** Recovery today = rebuild the master and re-attach workers
(workers already re-enroll/re-pin — Block B). There is no replication or
failover.

## What we already have to build on

- **Off-site state** path: S3 is wired for backups (creds + age) — reuse it.
- **Pinned master identity:** workers pin `master_rpc_pubkey` and there's a panel
  cert. **This is the crux of standby design** (below).
- **Config replication to workers** (Block A) + idempotent **re-enroll/re-pin**
  (Block B) + cert-pinning (Block C).

## Approach A — warm standby + continuous state replication (recommended)

1. **Replicate the master SQLite DB continuously** with **Litestream** (or
   LiteFS) to **S3** (already integrated). RPO ≈ seconds.
2. **Standby master**: a second master install that restores the live replica
   but stays **idle** — web served read-only, **schedulers/ACME/billing OFF** —
   to avoid split-brain.
3. **Promotion** on failure: flip the standby to active (start the write path +
   schedulers) and repoint the panel **DNS/VIP** at it.
4. **Identity reuse (make-or-break):** the standby MUST present the **same master
   RPC identity + panel cert** as the dead master, or every worker rejects it
   (cert-pinning). So standby provisioning replicates the master keypair + panel
   cert material as part of setup. (Alternative: a documented cluster-wide
   re-pin, but that's slower and touches every node.)

**Trade-offs:** RPO seconds, **RTO minutes** (manual/scripted promote); modest
new infra (Litestream + an S3 bucket + a standby box); no schema change. Not
automatic failover in P0/P1.

**Phasing:**
- **P0 (do now — cheap, high value):** Litestream → S3 + a tested *"rebuild
  master from replica"* runbook. This is real **disaster recovery** immediately,
  even before any standby exists.
- **P1:** a documented warm standby + `hctl cluster promote-standby` (restore
  latest, adopt master identity, start schedulers, health-check).
- **P2:** health-checked **auto-promotion** (a small witness/lease so a watchdog
  promotes the standby and only one master ever runs the schedulers).

## Approach B — externalized replicated state + N stateless masters (end-state)

Move `hyperion-state` to **Postgres** (or support both), run 2+ stateless
master/web instances behind a load balancer, and use **leader election** (a DB
advisory lock) so only one runs the singleton jobs. Postgres HA (streaming
replication / Patroni / a managed service) provides data HA.

**Trade-offs:** true active-active control plane + clean horizontal scale, but a
**large** change — sqlx is SQLite-shaped in places, migrations, and you'd run
Postgres-HA. **Defer** until the panel is past pre-production.

## Approach C — DR only (baseline, subset of A's P0)

No structural change: frequent state backups to S3 + a tested rebuild runbook +
the existing worker re-enroll/re-pin. Lowest effort; gives *recovery*, not
*availability*. This is effectively A-P0 and should ship first regardless.

## Critical design notes / gotchas

- **Split-brain:** only ONE master may run ACME/backups/billing at a time. The
  standby stays idle until promoted; full HA needs a lease/leader-lock so a
  flapping network can't run two schedulers (double cert renew / double billing).
- **Standby identity vs. cert-pinning:** the standby must reuse the master's
  pinned RPC key + panel cert, or workers reject it. Replicate the key material.
- **RPO/RTO:** warm standby = RPO seconds, RTO minutes. State it plainly; it is
  not zero-downtime.
- **Singleton side effects:** billing sweep advances `next_billing_at`; a
  promoted standby restoring a slightly-stale replica must not double-charge —
  the sweep is idempotent per cycle, but verify after promotion.

## Recommendation

Ship **A-P0 now** (Litestream → S3 + DR runbook) — it's small and removes the
"lose everything if the master dies" risk immediately. Treat **A-P1 warm
standby** as the next milestone, and **B (Postgres active-active)** as the
real-HA end-state once the project is production-bound. Be explicit with the
requester that the *sites themselves already survive* a master outage — this is
about the management plane.

## Open questions for the maintainer

1. Which HA does the requester want — **control-plane** (this doc) or **per-site**
   (same site on N nodes behind a LB)?
2. Acceptable **RTO** — minutes (warm standby) enough, or is automatic failover
   required?
3. Willing to run **Postgres** eventually (unlocks B), or keep SQLite + standby?
