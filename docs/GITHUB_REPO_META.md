# GitHub repo metadata — promotional copy

Suggestions for the public-facing presentation of the Hyperion
repository: the **About** sidebar, topics, social-share preview,
and ready-to-paste pitches for Hacker News / Reddit / Lobsters.

---

## GitHub repo "About" sidebar

### Description (max 350 chars — appears at top of repo page + in search)

Pick one — A is for "what is it", B for "why is it different",
C for the developer audience.

**A · Plain pitch**
> Self-hosted, multi-node hosting control panel written in Rust.
> One binary on each server, one web UI on the master. Provisions
> PHP / static / Node.js sites end-to-end (nginx + FPM + DB + TLS
> + WordPress) in a single atomic transaction. Debian 12+.

**B · Differentiator pitch**
> Rust hosting control panel for Debian. Multi-node clustering,
> kernel-enforced quotas, tamper-evident audit log, and live
> progress bars on every operation. The Cloudpanel / HestiaCP
> alternative that doesn't shell-template PHP at root.

**C · Engineer pitch**
> A small Rust core that provisions nginx + PHP-FPM + MariaDB /
> Postgres + Let's Encrypt + WordPress with LIFO rollback. axum +
> askama + HTMX UI, signed Ed25519 RPC between nodes, BLAKE3 audit
> chain, `#![forbid(unsafe_code)]` everywhere. Debian 12+.

### Website

`https://github.com/nechodom/hyperion` until there's a docs site.
Once you set up `docs.hyperion.dev` (suggested) → point here.

### Topics (max 20)

Paste these in the GitHub topics input — they boost discoverability
in `/topics/<x>` listings:

```
hosting-control-panel
hosting-panel
web-hosting
rust
axum
htmx
sqlite
self-hosted
self-hosting
debian
nginx
php-fpm
wordpress
mariadb
postgresql
letsencrypt
multi-node
cloudpanel-alternative
hestiacp-alternative
hosting-automation
```

GitHub caps at 20 topics; if you want to swap, the highest-value
ones for search are `hosting-control-panel`, `self-hosted`, `rust`,
`hosting-panel`, `hestiacp-alternative`.

### Social preview image

GitHub recommends 1280×640 PNG. Suggested content:

```
┌────────────────────────────────────────────────────────┐
│                                                        │
│   🦅 Hyperion                                          │
│                                                        │
│   The Rust hosting control panel that ships its own    │
│   multi-node cluster, kernel-enforced quotas, and a    │
│   tamper-evident audit log out of the box.             │
│                                                        │
│   github.com/nechodom/hyperion                         │
│                                                        │
│                              [ small dashboard shot ]  │
│                                                        │
│   ─── Rust · Debian 12+ · AGPL-3.0 ────────────────    │
│                                                        │
└────────────────────────────────────────────────────────┘
```

If you don't want to design one yet, GitHub auto-generates one
from the README's first heading + description — which is fine for
v0.

---

## Hacker News submission

### Title (max 80 chars)

Pick one — top one is the safest "Show HN" framing:

- **Show HN: Hyperion – a multi-node hosting control panel written in Rust**
- **Show HN: A Rust alternative to HestiaCP with built-in clustering**
- **Hyperion: open-source hosting control panel with kernel-enforced quotas**

### First comment (auto-post after submit)

```
Hi HN — I'm Kevin, a solo dev running a small Czech hosting business.
After two years of fighting HestiaCP's shell templating in production,
I rewrote the parts I actually use in Rust + axum + HTMX.

The pitch:

* Multi-node out of the box — master + N workers over a signed Ed25519
  RPC channel. Most open-source panels are single-node.
* Atomic provisioning — LIFO rollback if any step fails. No orphan
  Linux users, no half-created FPM pools.
* Tamper-evident audit log (BLAKE3 hash chain) with a Verify button.
* Per-session revocation ledger, TOTP 2FA, kernel-enforced disk quotas,
  CSP + HSTS headers — security stuff that's usually a bolt-on.
* HTMX-polled progress bar on every long-running op (migration, backup,
  cert issue, hosting clone).

It powers a small fleet today; I'm putting it out under AGPL-3.0 so
anyone who needs a self-hosted alternative to cPanel / Plesk /
CloudPanel can pick it up.

Happy to answer questions about the architecture, the security model,
or how a single dev shipped a multi-node control panel.

Repo: https://github.com/nechodom/hyperion
```

---

## Reddit submissions

### r/selfhosted

**Title:**
> [Project] Hyperion — a Rust hosting control panel with built-in multi-node clustering

**Body:**

```
Hey r/selfhosted —

Sharing a project I've been building for ~6 months: a hosting
control panel written in Rust that runs across multiple servers
out of the box.

Why another one? The PHP-based panels (HestiaCP, CloudPanel,
aapanel) are great for a single VPS but the moment you grow to
2–3 boxes you're back to manual config management. Hyperion's
multi-node model is a master + N workers — you provision a hosting
on whichever node you want from one web UI, migrate between them
with one click, and update them remotely with live log streaming
into the panel.

What ships today:

* Hosting CRUD: PHP 8.1–8.4, MariaDB / Postgres, nginx vhost,
  Let's Encrypt with auto-renewal, all in one atomic transaction
* WordPress install + plugin manage + admin reset + Redis cache
* Per-hosting kernel-enforced disk quota (setquota), bandwidth alerts
* Off-site backups: local + S3 + age encryption + retention policy
* TOTP 2FA, per-session revocation, BLAKE3 audit chain
* Cross-node hosting migration AND clone (e.g. prod → staging on
  a different node) with live progress
* Live HTMX-polled progress bar on every long-running operation

GitHub: https://github.com/nechodom/hyperion
AGPL-3.0, Debian 12+, single curl-pipe-bash installer.

Happy to answer questions — what would you want in your panel
that I'm missing?
```

### r/rust

**Title:**
> Hyperion — multi-node hosting control panel in axum + askama + HTMX

**Body:**

```
Sharing the Rust side of a panel I've been building.

Architecture: workspace with 9 crates, single-process binary per
node, no async-trait gymnastics outside the AdapterPort boundary.
SQLite via sqlx (31 migrations, BLAKE3 hash-chained audit log),
axum + askama + HTMX for the UI (no JS build step), Ed25519
envelope over self-signed HTTPS between nodes.

A few Rust-flavoured highlights:

* `#![forbid(unsafe_code)]` in every crate
* Every system effect goes through a typed AdapterPort trait
  that's mockable end-to-end — orchestrator rollback paths are
  unit-tested without touching the filesystem
* Wire protocol is u32be length || JSON, max frame 128 MiB
* Custom session signer + per-form CSRF tokens, no Tower-Sessions
* Type-tagged ULID IDs (HostingId(String) etc.) prevent FK mix-ups
  at compile time
* LIFO rollback registry: every mutating step pushes a tear-down
  closure; on failure the trace unwinds in reverse

The "interesting" file is probably crates/hyperion-core/src/service.rs
(big — multiple thousand LOC but everything's one method per RPC).

Repo: https://github.com/nechodom/hyperion
```

### r/devops (or r/sysadmin)

Same as r/selfhosted but emphasise the operational angles: live job
progress, audit chain for compliance, atomic provisioning that
doesn't leave orphan rows, remote node update from the UI.

---

## Lobsters submission

Title: same as HN.

Tags (Lobsters caps at 3):
- `release`
- `rust`
- `sysadmin`

---

## ProductHunt submission

ProductHunt rewards a tight pitch + a clean GIF.

**Tagline:** "The Rust hosting control panel for the self-hosted era."

**Description (260 chars):**
> Hyperion is an open-source hosting control panel written in Rust.
> Provisions PHP / static / Node.js sites end-to-end (nginx + DB +
> TLS) with atomic rollback, runs a multi-node cluster from one
> dashboard, and ships TOTP 2FA + kernel-enforced quotas in core.

**Topics:** Developer Tools, Open Source, Web Hosting, Servers.

---

## Twitter / Mastodon

**Launch tweet:**
```
🦅 Just open-sourced Hyperion — a hosting control panel written in
Rust, with a multi-node cluster out of the box.

Provisions sites end-to-end (nginx + PHP-FPM + DB + TLS) with
atomic rollback. Kernel-enforced quotas, BLAKE3 audit chain, TOTP
2FA in core. AGPL-3.0.

github.com/nechodom/hyperion
```

**Follow-up thread bullets** (one per tweet):
1. "Why another panel?" — HestiaCP / CloudPanel work for one VPS;
   multi-node is back to manual config. Hyperion's master + workers
   over signed RPC fixes that.
2. "Why Rust?" — `#![forbid(unsafe_code)]` everywhere. Every
   `Command::new()` takes pre-validated typed args. The orchestrator's
   rollback paths are unit-tested with mock adapters.
3. "What's a 'kernel-enforced quota'?" — `setquota -u` per hosting
   owner uid. Hard cap returns ENOSPC, soft cap triggers the grace
   period. Pure setquota, no fuse layer.
4. "Live progress?" — HTMX-polled `/jobs/<id>` page on every long
   operation. Migrate a hosting across nodes and watch the bar tick
   through Export → Bundle → Import → Suspend → Done.

---

## "Hyperion vs. ..." comparison table (for blog posts)

Reuse the table from the README:

|                                           | HestiaCP / Vesta / aapanel | **Hyperion**                       |
| ----------------------------------------- | -------------------------- | ---------------------------------- |
| Memory-safe language                      | ❌ PHP + bash               | ✅ Rust, `#![forbid(unsafe_code)]`  |
| Multi-node cluster                        | ❌ single-node              | ✅ master + N workers, signed RPC   |
| Atomic provisioning (no half-creates)     | ⚠️ partial                  | ✅ LIFO rollback on every step      |
| Live progress for long operations         | ❌                          | ✅ HTMX-polled bar on every job     |
| Tamper-evident audit log                  | ❌                          | ✅ BLAKE3 hash chain                |
| TOTP 2FA + per-session revocation         | ⚠️ partial                  | ✅ in core                          |
| Per-hosting disk quota (kernel-enforced)  | ✅                          | ✅                                  |
| Off-site backups (S3 + age encryption)    | ⚠️ FTP only                 | ✅ S3 + age (multi-target)          |
| One-click cross-node hosting migration    | ❌                          | ✅                                  |
| Hosting clone to a new domain             | ❌                          | ✅                                  |

---

## What to do FIRST after open-sourcing

1. **Edit the repo's "About"** sidebar — paste description A above,
   add topics.
2. **Pin a Discussion** with a "Welcome / FAQ / Roadmap" template.
3. **Enable GitHub Discussions** (Settings → Features) — lower bar
   than Issues for "hey, how do I…?".
4. **Add a small SUPPORT.md** linking Discussions for questions,
   Issues for bug reports, security@nechodom.dev for vulns.
5. **Tag a `v0.1.0` release** with auto-generated release notes —
   without a release the repo looks abandoned to drive-by visitors.
6. **Post to HN at 6–9 AM PT on a weekday** (Tuesday / Wednesday
   best). Use the title from the HN section above. Be in the
   comment thread for the first 2 hours — drop-off after that is
   steep.
7. **Post to /r/selfhosted right after HN** — different audience,
   no rule against cross-posting. The HN post brings traffic; the
   subreddit post tends to bring actual installs.
