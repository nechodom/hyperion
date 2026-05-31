# Sub-project 1.5 — Controller + Multi-Agent Enrollment — Design Spec

| Field | Value |
|---|---|
| Sub-project | 1.5 of N — Controller + Enrollment |
| Status | Draft, depends on Foundation |
| Date | 2026-05-31 |
| Depends on | Foundation (sub-project 1) |
| Enables | Sub-projects 2–9 (all multi-node features) |

## 1. Summary

Adds a **controller** process that orchestrates one or more `lm-agent` nodes
over **mTLS-encrypted TCP**. Introduces a self-signed CA on the controller,
one-time **enrollment tokens** for bootstrapping new agents, an agents
inventory in the controller's state, and a one-liner installer for new VPSes.

The same `AgentApi` trait from Foundation is served by `lm-agent` both on
the **local Unix socket** (for the on-host CLI) and over **mTLS TCP** (for
the controller). Implementation is identical; only the transport differs.

## 2. Goals

1. `lm-controller agent invite <hostname>` produces a one-time
   bootstrap token + a copy-paste installer line.
2. On a fresh Debian 12 VPS, the installer one-liner sets up `lm-agent`,
   enrolls with the controller, and exposes the RPC over mTLS in under
   3 minutes, with no manual config beyond pasting one command.
3. `lm-controller agent list` shows status (online/offline), version,
   hosting count, and last-seen timestamp for every enrolled agent.
4. Every controller→agent RPC call is mTLS-authenticated with **certificate
   pinning** on both sides (controller pins agent cert SHA-256;
   agent pins controller CA).
5. Agent certs auto-renew 30 days before expiry via the same mTLS channel.
6. Removing an agent revokes its cert (CRL or just delete-and-pin-changes;
   spec chooses CRL) and removes it from the inventory.

## 3. Non-Goals

- **Multi-controller HA.** Single controller only in this sub-project.
  HA controller is a future sub-project (out of scope here).
- **Agent → controller push.** Connection initiation is controller → agent
  (pull model, decided in brainstorming).
- **Cross-tenant separation on a single agent.** Multi-tenancy is at the
  hosting level; one agent serves one operator's hostings.
- **Auto-discovery / mDNS.** Operators run `agent invite` explicitly.
- **Web UI for invitation.** CLI-only in 1.5; web UI for invites is part
  of sub-project 2 (Admin UI).

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Single controller node, dedicated `lm-controller` binary | Clear deployment story; HA later if needed |
| D2 | mTLS via `rustls` + `rcgen` for CA + cert generation | Pure-Rust, no OpenSSL dep; avoids C ABI surface |
| D3 | Controller has its own self-signed root CA | We sign all agent certs; no PKI dependency |
| D4 | Listen on TCP 8443 on agents (configurable) | Standard alt-HTTPS port |
| D5 | One-time enrollment token: 32 bytes from OS CSPRNG, base32 | 160 bits entropy, copyable, single-use |
| D6 | Token TTL 1 hour | Long enough to paste on a VPS; short enough to limit window |
| D7 | Agent cert lifetime 365 days, auto-renew at 30 days remaining | Matches LE cycle conceptually; long enough to survive controller downtime |
| D8 | Certificate **pinning** on both sides (SHA-256 fingerprint) | Defense-in-depth: even if CA leaked, attacker cannot impersonate without exact cert |
| D9 | Same `AgentApi` trait, different transport crate | Zero RPC duplication; CLI tests & e2e covers both transports |
| D10 | Connection model: short-lived per-call (TCP+TLS handshake cached) | Simpler than long-lived bidi; rustls session resumption keeps overhead low |
| D11 | Wire format identical to Unix socket transport (`u32be len || JSON`) | One serde model, two streams |
| D12 | Installer script is bash, served from controller over HTTPS | Same trust root as controller; no separate distribution |
| D13 | Apt repo hosted by controller at `/apt`, signed with offline GPG key | Operator does not need third-party registrar |

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Controller node (Debian 12)                                    │
│                                                                 │
│   ┌─────────────────┐      ┌─────────────────────────────┐      │
│   │ lm-controller   │      │ lm-controller-web (later in │      │
│   │  (daemon, uid:  │      │  sub-project 2)             │      │
│   │  lm-controller) │      └─────────────────────────────┘      │
│   │                 │                                           │
│   │  - state DB     │      ┌─────────────────────────────┐      │
│   │  - CA           │      │ HTTPS endpoint              │      │
│   │  - agent client │      │   /enroll  (POST CSR+token) │      │
│   │  - scheduler    │      │   /install (GET install.sh) │      │
│   │  - HTTPS server │◄────►│   /apt/*   (apt repo)       │      │
│   └────────┬────────┘      └─────────────────────────────┘      │
│            │                                                    │
│            │ mTLS / TCP 8443 (pinned)                           │
└────────────┼────────────────────────────────────────────────────┘
             │
   ┌─────────┼──────────────┐
   ▼                        ▼
┌─────────────────────┐  ┌─────────────────────┐
│  agent node #1      │  │  agent node #N      │
│                     │  │                     │
│  lm-agent (root)    │  │  lm-agent (root)    │
│   - Unix socket     │  │   - Unix socket     │
│     /run/lm.sock    │  │     /run/lm.sock    │
│   - mTLS TCP 8443   │  │   - mTLS TCP 8443   │
│   - state DB        │  │   - state DB        │
└─────────────────────┘  └─────────────────────┘
```

### 5.1 New crates

```
crates/
├── lm-ca/                      controller's CA: rcgen + key persistence
├── lm-rpc-tls/                 mTLS transport: server + client framing
├── lm-rpc-router/              controller-side trait that routes RPC to
│                               an agent by id (calls into lm-rpc-tls client)
└── lm-controller-core/         agent inventory, enrollment service,
                                health-check loop
```

### 5.2 New binaries

```
bin/
├── lm-controller/              daemon: listens on 80/443 for /enroll +
│                               /install + /apt; talks mTLS to agents
└── lm-controller-cli/          short alias `lmc`: agent invite/list/remove
```

### 5.3 Agent-side changes from Foundation

- `lm-agent` gains a second listener: mTLS-wrapped TCP on the port specified
  in `agent.toml [tls] listen = "0.0.0.0:8443"`.
- Both listeners (Unix and TCP) dispatch to the **same** `HostingService`
  via the same `AgentApi` trait. The TCP listener additionally captures the
  peer cert's SHA-256 fingerprint into the audit log's `actor_label`
  (`"controller:<sha8>"`).
- Authorization on TCP: only the pinned controller CA may connect, and the
  peer cert must match the agent's configured `controller_cert_sha256`.

## 6. State Schema (Controller-side)

The controller has its own SQLite DB at
`/var/lib/linux-manager-controller/state.db`. Agents do not learn the
controller's state; the controller is authoritative.

```sql
CREATE TABLE agents (
    id                   TEXT PRIMARY KEY,            -- UUID v7
    hostname             TEXT NOT NULL UNIQUE,
    endpoint             TEXT NOT NULL,               -- e.g. 'node5.example.com:8443'
    cert_sha256          TEXT NOT NULL UNIQUE,        -- pinned agent cert fingerprint
    cert_not_after       INTEGER NOT NULL,
    agent_version        TEXT,                        -- last seen agent version
    last_seen_at         INTEGER,                     -- unix epoch; NULL if never
    state                TEXT NOT NULL CHECK (state IN ('enrolling','active','quarantined','removed')),
    created_at           INTEGER NOT NULL
);

CREATE TABLE agent_invites (
    token_hash           TEXT PRIMARY KEY,            -- BLAKE3(token), never plaintext
    hostname             TEXT NOT NULL,
    expires_at           INTEGER NOT NULL,
    consumed_at          INTEGER,                     -- nullable; non-null = used
    consumed_by_agent_id TEXT REFERENCES agents(id)
);

CREATE TABLE ca_state (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton
    ca_cert_pem          TEXT NOT NULL,
    -- ca_private_key NEVER in this table. Lives in
    -- /etc/linux-manager-controller/ca/ca.key (mode 0600).
    created_at           INTEGER NOT NULL,
    not_after            INTEGER NOT NULL
);

CREATE TABLE crl_entries (
    agent_id             TEXT PRIMARY KEY REFERENCES agents(id),
    revoked_at           INTEGER NOT NULL,
    reason               TEXT
);

CREATE TABLE controller_audit_log (
    -- same shape as agent's audit_log
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor_uid INTEGER NOT NULL,
    actor_label TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    payload_json TEXT NOT NULL,
    result TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
```

## 7. RPC Additions

### 7.1 Controller-local API (`ControllerApi`)

New trait, implemented by `lm-controller-core`; used by `lm-controller-cli`
over a controller-side Unix socket `/run/lm-controller.sock` (same model
as Foundation's agent socket).

```rust
#[async_trait]
pub trait ControllerApi: Send + Sync + 'static {
    async fn agent_invite(&self, req: AgentInviteReq)
        -> Result<AgentInvite, RpcError>;
    async fn agent_list(&self) -> Result<Vec<AgentSummary>, RpcError>;
    async fn agent_get(&self, id: AgentId) -> Result<AgentDetail, RpcError>;
    async fn agent_remove(&self, id: AgentId, opts: AgentRemoveOpts)
        -> Result<(), RpcError>;
    async fn agent_health(&self, id: AgentId) -> Result<AgentHealth, RpcError>;

    /// Proxies an AgentApi call through to a specific agent.
    /// All public AgentApi methods get a mirror here that takes AgentId
    /// as the first argument.
    async fn proxy(&self, agent: AgentId, call: AgentApiCall)
        -> Result<AgentApiResponse, RpcError>;
}
```

### 7.2 Enrollment HTTP endpoint (no auth besides the token)

```
POST https://master.example.com/enroll
Content-Type: application/json
{
  "token": "ABCD-EFGH-...",         // base32, 32-byte token
  "hostname": "node5.example.com",  // must match invite's hostname
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."
}

Response 200:
{
  "agent_cert_pem": "...",          // signed by controller CA
  "ca_cert_pem": "...",             // controller's CA cert, to pin
  "agent_id": "0193e7..."            // UUID
}

Errors:
  400 invalid token / hostname mismatch / bad CSR
  409 token already consumed
  410 token expired
```

The endpoint runs over **regular TLS** (controller has a Let's Encrypt
cert on its public hostname). No client cert here — the token is the
secret.

### 7.3 Installer endpoint

```
GET https://master.example.com/install
```

Returns a bash script (Content-Type: text/plain). The script is
generated dynamically from a template baked into `lm-controller` binary;
content depends on the controller's hostname (substituted) and is signed
inline via a comment trailer (operators can verify with `gpg --verify`
if they pull the file separately).

## 8. Key Flows

### 8.1 Inviting and enrolling a new agent

```text
Operator on controller:
  $ lmc agent invite node5.example.com
  Token (1 hour, single-use):
    AB42-CDEF-7H8J-9KMN-PQRS-TUVW-XY23-4567
  Install:
    curl -fsSL https://master.example.com/install \
      | sudo bash -s -- \
          --token=AB42-CDEF-7H8J-9KMN-PQRS-TUVW-XY23-4567 \
          --controller=master.example.com

Operator on the new VPS:
  $ <paste line above>
  [+] OS: Debian 12 ✓
  [+] Adding apt repo (signed key SHA-256: e3:b0:...)
  [+] apt-get update && apt-get install -y lm-agent
  [+] Generating agent key (ED25519)
  [+] Building CSR for hostname 'node5.example.com'
  [+] POST /enroll
  [+] Received cert chain, fingerprint: 7c:4a:..
  [+] Pinned controller CA fingerprint:  9e:11:..
  [+] Writing /etc/linux-manager/agent/tls/{cert.pem,key.pem,ca.pem}
  [+] systemctl daemon-reload
  [+] systemctl enable --now lm-agent
  [✓] Enrolled. Reachable at node5.example.com:8443.

Controller-side:
  - upon /enroll POST: verify token hash matches a row in agent_invites,
    not consumed, not expired, hostname matches
  - sign the CSR (rcgen) for the requested hostname, valid 365 days
  - INSERT into agents (state='enrolling', cert_sha256=fp(signed_cert))
  - UPDATE agent_invites SET consumed_at, consumed_by_agent_id
  - return signed cert + CA cert
  - kick off a health-check ping (mTLS connect); on first success update
    agents.state='active', agents.last_seen_at
```

### 8.2 Controller → agent RPC call

```text
Caller: lm-controller-core; needs to run hosting_create on agent A:
  1. lookup agents row by id → endpoint + pinned cert_sha256
  2. open mTLS TCP to endpoint using rustls config with:
       - controller's client cert (signed by our own CA)
       - root CA = our own CA (verifies agent cert chain)
       - custom verifier asserts SHA-256(peer leaf cert) == cert_sha256
  3. send frame (u32be len || JSON RPC request)
  4. read response frame, parse
  5. update agents.last_seen_at on success
  6. on connection failure: increment failure counter, log; if >3 consecutive
     mark agents.state='quarantined' until next successful health-check
```

### 8.3 Removing an agent

```text
$ lmc agent remove node5.example.com [--purge-hostings]
  - controller adds row to crl_entries
  - controller updates agents.state='removed'
  - if --purge-hostings: for each hosting belonging to this agent,
    call hosting_delete on the agent BEFORE removing (best-effort;
    may fail if agent is dead — in that case operator must do manual
    cleanup on the agent or just leave it offline)
  - agent's TCP listener is not informed; on its next reconnect attempt
    the controller refuses the cert (CRL check)
  - controller publishes updated CRL at GET /crl.der for any process
    that wants to consume it
```

### 8.4 Cert auto-renewal

A background task in `lm-controller-core` scans `agents` daily for
`cert_not_after - now < 30 days` AND `state = 'active'`. For each:

1. Connect via current mTLS using existing cert (still valid).
2. Send RPC `renew_my_cert` (new method in `AgentApi`; agent generates
   new keypair + CSR, controller signs, returns the new cert).
3. Agent atomically swaps `cert.pem` + `key.pem`, restarts TCP listener.
4. Controller updates `agents.cert_sha256` + `cert_not_after`.

## 9. Security Model

- **Trust root:** controller's CA private key at
  `/etc/linux-manager-controller/ca/ca.key` (mode 0600, root:root).
  Compromise of this key would allow signing rogue agent certs, but
  pinning (D8) means the attacker would also need to alter the
  controller's `agents.cert_sha256` to be useful.
- **Token interception:** tokens are stored hashed (BLAKE3) in DB; transit
  over HTTPS; lifetime 1 hour; single-use. Worst case if intercepted
  *during the install* window: attacker enrolls a rogue agent — the
  legitimate enrollment then fails (`409 already consumed`), prompting
  operator to investigate.
- **mTLS handshake:** rustls with `WantsVerifier::with_root_certificates`
  scoped to the controller's CA only; custom `ServerCertVerifier` for
  pinning the agent leaf cert; rejects all other roots.
- **Replay:** wire-format requests include a `nonce` field; controller
  refuses repeats within 60s sliding window (cheap in-memory LRU).
- **Audit:** every controller → agent RPC produces one entry on each side.
  Both sides' `actor_label` makes correlation easy: controller logs
  `agent:<id>`, agent logs `controller:<sha8>`.

## 10. Installer Script (`/install` content)

Sketch (the real script is longer, see `crates/lm-controller-core/templates/install.sh.j2`):

```bash
#!/usr/bin/env bash
set -euo pipefail

# args:
TOKEN="" CONTROLLER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --token=*)       TOKEN="${1#*=}";;
    --controller=*)  CONTROLLER="${1#*=}";;
    *) echo "unknown arg: $1"; exit 2;;
  esac; shift
done
[[ -n "$TOKEN" && -n "$CONTROLLER" ]] || { echo "missing args"; exit 2; }
[[ $EUID -eq 0 ]] || { echo "must run as root"; exit 2; }

# 1. OS check
. /etc/os-release
[[ "$ID" == "debian" && "${VERSION_ID%%.*}" -ge 12 ]] || {
  echo "Debian 12+ required, found $PRETTY_NAME"; exit 3;
}

# 2. Add apt repo (signed)
mkdir -p /etc/apt/keyrings
curl -fsSL "https://${CONTROLLER}/apt/key.gpg" \
  -o /etc/apt/keyrings/linux-manager.gpg
cat > /etc/apt/sources.list.d/linux-manager.list <<EOF
deb [signed-by=/etc/apt/keyrings/linux-manager.gpg] \
  https://${CONTROLLER}/apt bookworm main
EOF
apt-get update -qq
apt-get install -y lm-agent

# 3. Enroll
mkdir -p /etc/linux-manager/agent/tls
chmod 0700 /etc/linux-manager/agent/tls

# generate keypair + CSR via lm-agent helper subcommand
lm-agent enroll \
  --token "$TOKEN" \
  --controller "https://${CONTROLLER}" \
  --tls-dir /etc/linux-manager/agent/tls

# 4. Activate
systemctl daemon-reload
systemctl enable --now lm-agent
echo "[✓] Enrolled."
```

## 11. Configuration Additions

`/etc/linux-manager-controller/controller.toml` (new):

```toml
[controller]
state_db        = "/var/lib/linux-manager-controller/state.db"
socket_path     = "/run/lm-controller.sock"
socket_group    = "lm-controller-admin"

[http]
listen          = "0.0.0.0:443"
public_hostname = "master.example.com"
acme_email      = "you@example.com"
# controller obtains its own LE cert for the public hostname

[ca]
ca_cert_path    = "/etc/linux-manager-controller/ca/ca.crt"
ca_key_path     = "/etc/linux-manager-controller/ca/ca.key"
agent_cert_ttl_days = 365
```

`/etc/linux-manager/agent.toml` additions:

```toml
[tls]
listen                = "0.0.0.0:8443"
cert_path             = "/etc/linux-manager/agent/tls/cert.pem"
key_path              = "/etc/linux-manager/agent/tls/key.pem"
controller_ca_path    = "/etc/linux-manager/agent/tls/ca.pem"
# pinned fingerprint of expected controller-signed cert presenter:
controller_cert_sha256 = "9e11ab..."
```

## 12. Testing Additions

- Unit: `lm-ca` round-trip CSR → cert → verify chain. `lm-rpc-tls`
  pin-mismatch tests.
- Integration: testcontainers spins up two containers (controller +
  agent). The test runs full enrollment via HTTP, then issues mTLS
  RPC calls. Asserts: token consumption, pin enforcement, CRL refusal.
- e2e: nightly libvirt scenario — three VMs (controller, agent1,
  agent2). Provisions hostings on both agents; runs `agent remove
  agent2 --purge-hostings`; asserts state.

## 13. Open Questions

1. **Apt repo signing key custody.** The GPG private key for the apt
   repo can either live on the controller (simpler, but compromise =
   ability to push rogue packages) or stay offline (operator signs
   builds out-of-band). **Proposal:** start with controller-resident
   key (mode 0600, root) for sub-project 1.5; offline-only path is a
   later hardening step in sub-project 9.
2. **CRL distribution.** Inline CRL check on every connection vs OCSP
   stapling vs short-lived certs? **Proposal:** inline CRL (cheap, small
   number of agents).
3. **Controller HA.** Out of scope here; flagged for the day someone
   asks. Likely model: SQLite → Postgres or rqlite, plus controller
   stateless behind a TCP load balancer.

## 14. Glossary Additions

| Term | Meaning |
|---|---|
| Controller | The master node running `lm-controller`; authoritative state |
| Agent | A managed Debian 12 node running `lm-agent`, identified by hostname |
| Invite | A row in `agent_invites`; expires; single-use |
| Token | The base32 secret an operator pastes into the installer |
| Pinning | Storing a peer cert's SHA-256 and refusing any other on connect |
| CRL | Certificate Revocation List; published at `/crl.der` |

---

*End of spec. Implementation depends on Foundation being complete.*
