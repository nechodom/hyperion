# Sub-project 9 — Security Hardening — Design Spec

| Field | Value |
|---|---|
| Sub-project | 9 of N — Hardening |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation, Controller (1.5), Admin UI (2), Limits (3) |
| Theme | Defense-in-depth across the stack |

## 1. Summary

Adds **active defenses** on top of the bare panel: managed **nftables**
firewall with sensible defaults and per-hosting overlays, **fail2ban**
integration for SSH / login / 4xx-from-PHP brute force, **ModSecurity v3**
WAF with OWASP CRS for nginx vhosts, **agent hardening checklist** that
runs at install and on demand, **TLS strict mode** for all nginx vhosts,
and **secret rotation** runbooks (CA, session keys, repo passwords).

Many primitives already touch security incidentally (rollback, audit log,
mTLS, etc.); this sub-project consolidates them and adds the layers that
explicitly defend against attackers.

## 2. Goals

1. `lm hardening apply` on a fresh agent produces a known-good
   configuration: firewall closes everything except 80/443/22 + agent
   mTLS port; fail2ban enabled with default jails; nginx vhosts get
   security headers + ModSecurity in DetectionOnly initially.
2. Per-hosting WAF toggles: `lm hosting waf <id> --mode off|detection|block`.
3. `lm hardening check` runs a 30-point checklist and outputs a
   pass/fail report. Used in CI to detect drift.
4. `lm secrets rotate <kind>` rotates: CA key, session key, TOTP KEK,
   any backup repo password (with re-encrypt).
5. fail2ban hits surface in admin UI as a "Banned IPs" table with
   manual unban.

## 3. Non-Goals

- IDS / IPS for network traffic (Suricata, Snort).
- HIDS / file integrity monitoring (AIDE, Tripwire).
- Centralized SIEM. Audit logs stay on-box (controller aggregates).
- DDoS mitigation beyond fail2ban + nginx `limit_req`.
- Email security (SPF/DKIM/DMARC) — separate concern if we ever add mail.

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **nftables** managed via small DSL → rendered `.nft` files in `/etc/nftables.d/lm-*.nft` | Standard since Debian 11 |
| D2 | Default INPUT policy DROP; explicit ACCEPT for 22/80/443 + agent TCP | Whitelist > blacklist |
| D3 | **fail2ban** with custom filters for nginx + sshd; ban via nftables `set` | nftables-native action |
| D4 | **ModSecurity v3 + OWASP CRS** as nginx module | Standard WAF stack |
| D5 | WAF default per-hosting mode: **DetectionOnly** for first 7 days, then auto-promote to Block (operator can opt out) | Avoid surprise blocks |
| D6 | Hardening checks codified in Rust as a list of named `Check` trait impls | Versionable, testable |
| D7 | TLS profile: TLSv1.2 + 1.3, Mozilla "intermediate" cipher list, OCSP stapling, HSTS preload eligible | Best-practice |
| D8 | SSH (system, not agent): disable password auth, key-only; enforced via `/etc/ssh/sshd_config.d/50-lm.conf` | Standard hardening |
| D9 | Secret rotation: all secrets identifiable by purpose + ID; rotate produces a new id and atomically swaps consumers | Auditable |
| D10 | Sysctl hardening profile applied via `/etc/sysctl.d/50-lm.conf` | Standard kernel hardening |

## 5. nftables Layout

```
/etc/nftables.conf                          (Debian default; we leave alone)
/etc/nftables.d/
├── lm-base.nft                             default policy + accept loopback
├── lm-services.nft                         accept SSH, 80, 443, agent TCP
├── lm-bw-counters.nft                      from sub-project 3 (bandwidth)
├── lm-fail2ban.nft                         ban set populated by fail2ban
└── lm-overlays.nft                         per-hosting overrides (e.g. IP allow)
```

Top-level `lm-base.nft`:

```
table inet lm {
    set blocked_ips_v4 { type ipv4_addr; flags interval; timeout 3h; }
    set blocked_ips_v6 { type ipv6_addr; flags interval; timeout 3h; }

    chain input {
        type filter hook input priority filter; policy drop;
        ct state vmap { invalid : drop, established : accept, related : accept }
        iif lo accept
        icmp type echo-request limit rate 5/second accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-solicit } accept

        ip  saddr @blocked_ips_v4 drop
        ip6 saddr @blocked_ips_v6 drop

        tcp dport { 22, 80, 443 } accept
        # agent mTLS (sub-project 1.5)
        tcp dport 8443 accept
    }
}
```

## 6. fail2ban Integration

Jail config in `/etc/fail2ban/jail.d/lm-jails.local`:

```ini
[DEFAULT]
banaction = nftables-multiport[blocktype=drop]
bantime  = 3h
findtime = 10m
maxretry = 8

[sshd]
enabled = true

[nginx-4xx]                    # 401/403/404 burst per ip from nginx access log
enabled  = true
port     = http,https
filter   = lm-nginx-4xx
logpath  = /home/*/*/logs/access.log

[lm-admin-login]               # rate brute on /login from controller logs
enabled = true
filter  = lm-admin-login
logpath = /var/log/linux-manager-controller/web.log
maxretry = 5
```

Custom filters at `/etc/fail2ban/filter.d/lm-nginx-4xx.conf` and
`/etc/fail2ban/filter.d/lm-admin-login.conf`. nftables action
`/etc/fail2ban/action.d/nftables-multiport.local` updates
`lm.blocked_ips_v4` / `blocked_ips_v6` sets.

Banned IPs visible via:
```
nft list set inet lm blocked_ips_v4
```

Agent surfaces these via new RPC `fail2ban_banned() -> Vec<BannedIp>` for
UI display.

## 7. ModSecurity Integration

- Install: `libnginx-mod-http-modsecurity` + `modsecurity-crs`.
- Global config `/etc/nginx/modsec/main.conf` loaded once.
- Per-hosting include controlled by a flag:

```nginx
# in vhost template
{% if waf_mode != "off" %}
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
{%   if waf_mode == "detection" %}
modsecurity_rules 'SecRuleEngine DetectionOnly';
{%   endif %}
{% endif %}
```

New table:

```sql
CREATE TABLE waf_settings (
    hosting_id    TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    mode          TEXT NOT NULL CHECK (mode IN ('off','detection','block')),
    promoted_at   INTEGER,        -- NULL until auto-promoted to block
    last_changed_at INTEGER NOT NULL
);
```

Auto-promote logic: a background daily task scans `waf_settings` for
rows in `detection` whose `last_changed_at` is more than 7 days old and
moves them to `block` (operator can disable via per-hosting flag in
the table or globally in `agent.toml`).

## 8. SSH Hardening

`/etc/ssh/sshd_config.d/50-lm.conf` written by `lm-agent` at install
(and reapplied during `hardening apply`):

```sshd_config
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintMotd no
ClientAliveInterval 60
ClientAliveCountMax 5
MaxAuthTries 5
MaxStartups 5:30:60
LoginGraceTime 30
# subsystem sftp (left default)
# Match Group lm-sftp-users (defined in sub-project 6)
```

Reload via `systemctl reload ssh`.

## 9. sysctl Hardening

`/etc/sysctl.d/50-lm.conf`:

```
# network
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# kernel
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
```

Applied via `sysctl --system`.

## 10. Hardening Checklist (`lm hardening check`)

30 named checks; each impl is a small Rust struct:

```rust
trait Check {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn run(&self) -> CheckResult;       // Pass | Warn | Fail with message
}
```

Sample IDs:
- `LM-SEC-01` /etc/nftables.d/lm-*.nft present and loaded
- `LM-SEC-02` default INPUT policy is DROP
- `LM-SEC-03` SSH `PasswordAuthentication no` effective
- `LM-SEC-04` SSH root login disabled
- `LM-SEC-05` fail2ban service active
- `LM-SEC-06` sysctl hardening file present and applied
- `LM-SEC-07` audit log hash chain valid (Foundation cross-check)
- `LM-SEC-08` `lm-agent` socket mode 0660 + group lm-admin
- `LM-SEC-09` `/etc/linux-manager/secrets/` mode 0700
- `LM-SEC-10` agent TLS cert valid + matches pinned controller_cert_sha256
- `LM-SEC-11` ModSecurity module loaded by nginx
- `LM-SEC-12` All vhosts use Mozilla intermediate TLS profile
- `LM-SEC-13` HSTS enabled on all vhosts
- `LM-SEC-14` `unattended-upgrades` package present and enabled
- `LM-SEC-15` AppArmor profiles enabled (Debian default for nginx etc.)
- … (and so on; full list maintained in `lm-hardening-checks/checks.rs`)

Output is a table + summary:

```
PASS  LM-SEC-01  nftables lm tables loaded
FAIL  LM-SEC-14  unattended-upgrades disabled; security updates not applied
WARN  LM-SEC-11  modsecurity-crs version older than 4.x
...
17/30 pass, 2 warn, 11 fail
```

`--json` for machine consumption. Exit code = number of fails.

## 11. Secret Rotation

```
lm secrets rotate ca                  # controller CA (re-sign all agent certs)
lm secrets rotate session-key         # web session signing key (forces re-login)
lm secrets rotate totp-kek            # re-encrypts admin TOTP secrets
lm secrets rotate backup-repo <name>  # generates new restic password, re-encrypts repo
```

Each rotation:

```text
01 generate new secret (CSPRNG)
02 write to new file with new id
03 update consumers atomically (controller config, agents, etc.)
04 verify consumers can read with new id
05 retire old file (delete after grace 24h)
06 audit append
```

Backup-repo rotate uses `restic key add` to add the new password, then
`restic key remove` for the old.

## 12. Configuration Additions

```toml
[hardening]
auto_promote_waf_after_days   = 7
unattended_upgrades            = "on"          # 'on' | 'off' | 'check-only'
allowed_inbound_tcp_ports      = [22, 80, 443, 8443]

[hardening.checks]
skip_ids = []                                  # operator can ignore specific checks
```

## 13. RPC Additions

### AgentApi

```rust
async fn hardening_apply(&self) -> Result<HardeningReport, RpcError>;
async fn hardening_check(&self) -> Result<HardeningReport, RpcError>;
async fn waf_set_mode(&self, sel: HostingSelector, mode: WafMode)
    -> Result<(), RpcError>;
async fn fail2ban_banned(&self) -> Result<Vec<BannedIp>, RpcError>;
async fn fail2ban_unban(&self, ip: String) -> Result<(), RpcError>;
```

### ControllerApi

```rust
async fn secrets_rotate(&self, kind: SecretRotateKind, opts: RotateOpts)
    -> Result<RotateReport, RpcError>;
```

## 14. UI

- `/agents/:id/hardening` — runs `hardening_check` on demand, renders
  table.
- Hosting detail: WAF mode toggle.
- `/security/banned` — table of banned IPs across agents; unban
  button per row.
- Settings: secret rotation form (Admin role only, TOTP re-auth).

## 15. Testing

- Unit: each Check has a Pass + a Fail unit test using fixture filesystem.
- Integration (testcontainer): apply hardening to a fresh Debian
  container; run check; expect all pass except those needing systemd
  features not present in the container (skipped explicitly).
- e2e (nightly VM): apply hardening on a real systemd VM; verify
  network policy via `nmap` from a peer VM; verify nginx vhost has
  expected headers via `curl -I`.
- Adversarial: invoke a synthetic 4xx-burst, assert ban appears.

## 16. Open Questions

1. **Custom ModSecurity rule curation.** OWASP CRS will produce false
   positives for some apps. **Proposal:** per-hosting "WAF exception"
   table that maps rule IDs to disable; surface in UI.
2. **Egress filtering** (rate-limit outbound to mitigate exfil). Out of
   scope; can be added as an nftables overlay.
3. **CA rotation downtime.** Rotating the controller CA invalidates all
   existing agent certs; we'd need a controlled re-signing window where
   both old and new CAs are trusted. **Proposal:** implement as a
   multi-stage rotation: add new CA to agents → sign new certs from
   new CA → remove old CA. Stretch goal; document only in v1.
4. **WAF auto-promotion safety.** Auto-promoting from detection to block
   might break a quiet site. **Proposal:** only auto-promote if 0
   would-have-blocked events in the last 24 h; otherwise hold and ping
   admin.

## 17. Glossary Additions

| Term | Meaning |
|---|---|
| WAF mode | One of off / detection / block |
| nftables set | A named set in the kernel — used for fail2ban bans |
| Hardening check | A single named pass/fail probe in the agent |
| Rotation | Issuing a new secret, swapping consumers, retiring old |

---

*End of spec.*
