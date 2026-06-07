# Security policy

## Supported versions

Hyperion is pre-1.0; only the `main` branch receives security
updates. Pin to a tagged release for production deploys, then
fast-forward when a security advisory lands.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| tagged releases | latest only |

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.**

Email `security@nechodom.dev` (PGP key fingerprint on request).
Include:

* Affected Hyperion version (commit SHA from `hctl info` or
  `git rev-parse HEAD` in `/opt/hyperion`).
* Minimal reproduction steps.
* Your assessment of impact (RCE, privilege escalation, info leak,
  CSRF, XSS, etc.) — best-effort, no expertise required.
* Whether you'd like attribution in the eventual advisory.

You'll get a human reply within **72 hours**. If you don't, please
ping again — the address is monitored by a solo maintainer and
spam can swallow things.

## Disclosure timeline

* **Day 0:** report received, acknowledged.
* **Day 0–14:** triage + reproduction + fix in a private branch.
* **Day 14–30:** patch released as a tagged commit + a GitHub
  Security Advisory with credit.
* **Day 30+:** full technical write-up if the bug is interesting.

We aim for the 30-day window; some classes (e.g. anything needing
a coordinated upstream fix in nginx / sqlx / axum) may take longer.

## Scope

In scope:

* Authentication / authorization bypass on the web panel.
* Privilege escalation against `hyperion-agent` (runs as root).
* RPC envelope forgery between master and worker nodes.
* Unsafe handling of operator-supplied input (template injection,
  command injection, path traversal).
* TOTP / session token weaknesses.
* Secret exfiltration via logs, audit trail, or UI side channels.

Out of scope:

* Reports requiring root on the machine running Hyperion (root is
  already trusted — that's the whole product).
* Self-XSS, social engineering against the operator.
* DoS against the operator-facing port from the same machine.
* Issues in third-party dependencies that are already public
  upstream (file those upstream).

## Bug bounty

There isn't one yet. If your finding leads to a real CVE on a
deployed Hyperion install, get in touch — we'll work out a
recognition (mention in the changelog, attribution in the
advisory, maybe a small thank-you depending on impact).
