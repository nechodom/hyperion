# Support

Where to ask for help, depending on what you need.

## Quick answers + setup help

→ **[GitHub Discussions](https://github.com/nechodom/hyperion/discussions)**

Best for:
* "How do I configure X?"
* "Is Y supported?"
* "Has anyone deployed in setup Z?"
* Sharing wins and patterns.

Lower bar than a bug report — no template required.

## Bug reports

→ **[GitHub Issues](https://github.com/nechodom/hyperion/issues)**

Open an issue when something's actually broken (panel crash, wrong
behaviour, unexpected error). Include:

* Hyperion version (`hctl info`).
* Debian version (`cat /etc/os-release | head -2`).
* Steps to reproduce.
* What you expected vs what happened.
* Relevant log lines (`journalctl -u hyperion-agent` /
  `-u hyperion-web`).

## Security vulnerabilities

→ See [`SECURITY.md`](SECURITY.md).

Do **not** open a public GitHub issue for security bugs.

## Feature requests

→ **[GitHub Discussions](https://github.com/nechodom/hyperion/discussions/categories/ideas)**

Drop a one-paragraph proposal in Discussions before opening an
issue. If it sticks (gets thumbs-up, gets discussed) we promote to
an issue and a milestone.

## Commercial support / sponsored features

If you run Hyperion in production and need:

* SLA on bug fixes / response time
* A specific feature prioritised
* Help migrating from HestiaCP / CloudPanel / cPanel

→ Email `hello@nechodom.dev` with a short description of your
deployment + what you need. Sliding-scale pricing for non-profits
and OSS infrastructure projects.

## What we can't help with

* Generic Linux / nginx / PHP / MariaDB administration questions —
  those have great Stack Exchange and r/sysadmin communities.
* Hosting business advice — happy to chat in Discussions but it's
  not a support load we can SLA.
* Custom panel modifications that you'd rather not contribute back
  — see commercial support above.
