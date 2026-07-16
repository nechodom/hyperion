# Cluster master↔node RPC — security audit + remediation plan

Adversarial audit (17 confirmed findings) of the master↔node control channel:
signed-HTTPS RPC to `https://<node>:9443/agent-rpc`. Auth is an Ed25519
envelope over `(node_id, ts, nonce, body_hash)`; TLS is self-signed and (by
default) unverified.

## Threat model

The load-bearing control is the **Ed25519 request signature** — an attacker
without the master's private key cannot forge a master→node command. That part
is sound. Every serious finding below needs an **active on-path MITM** on the
public-internet path to `:9443`, because TLS is `curl -k` (unverified) and cert
pinning is off by default. **Removing that path (private network) is therefore
the single highest-leverage mitigation** — it denies the position the top
findings require.

## Confirmed findings (grouped)

### A. TLS / MITM (the channel isn't authenticated)
1. **Unauthenticated response** (`remote.rs:200`, HIGH) — only the *request* is
   signed; the node's response is bare JSON the master trusts byte-for-byte. A
   MITM (given `-k`) fabricates responses: fake reset-passwords shown to the
   operator, fake "provisioned OK", poisoned NodesList/ClusterStats.
2. **`curl -k` hardcoded** (`remote.rs:155`, HIGH) — `verify_tls` defaults false
   and is never set true; the master accepts any cert → a MITM reads plaintext
   RPC bodies carrying DB/WP/FTP passwords + provisioning creds.
3. **SPKI pinning off / warn-only / self-reported** (`stats.rs:448`, HIGH).

### B. Enrollment / trust bootstrap
4. **Enroll TOFU over `-k`** (`enroll.rs:325`, HIGH) — a MITM at first enroll
   pins its own `master_rpc_pubkey` → persistent node takeover. No OOB verify.
5. **One-way bootstrap** (`install-node.sh:420`, HIGH) — master never proves
   identity to the node.
6. `agent_repin` reopens TOFU over heartbeat (`agent.rs:120`, LOW).

### C. Exposure
7. **Listener 0.0.0.0 + installer opens `9443` to the whole internet**
   (`install-node.sh:460`, HIGH).
8. **Private-interface bind is configurable but unusable** — the node only
   advertises its public IP (`dispatcher.rs:315`, MEDIUM).
9. No pre-auth DoS controls (body cap / timeout / conn limit) (`inbound_rpc.rs:92`,
   MEDIUM).

### D. Secret leakage
10. **Enroll parse-error logs the plaintext node secret** (`enroll.rs:296`, HIGH).
11. `http://` master sends the invite token in cleartext (`enroll.rs:176`, LOW).
12. Plaintext `String` secrets in Request variants rely on a never-Debug
    convention (`codec.rs:132`, LOW).
13. Handler echoes serde error text (`inbound_rpc.rs:161`, INFO).

### E. Replay / misc
14. In-memory nonce cache → replay across agent restart (`inbound_rpc.rs:90`,
    MEDIUM).
15. Re-enroll rotates the secret on reuse (`service.rs:8266`, MEDIUM).
16. XFF trusted from any peer (`enroll.rs:29`, LOW).
17. Asymmetric freshness window, 5 s future tolerance (`master_rpc.rs:288`, INFO).

## Remediation plan (staged — protocol changes need rollout care)

**Slice 1 — private-network transport + safe leak fixes (DONE, this PR):**
- `[remote_rpc] advertise_addr` — node advertises a private IP; master dials it
  → the whole channel leaves the public internet (mitigates #1–#5, #7, #8).
- Installer: bind to the private IP + **scope** the firewall to the master /
  private subnet instead of world-open (#7).
- Drop the secret from the enroll parse-error log (#10); generic listener
  errors (#13).

**Slice 2 — authenticate the response (#1):** HMAC the response with the
per-node shared secret (master + node already share it), verified master-side.
Needs a version-gated rollout (both ends upgrade) so a rolling cluster doesn't
break mid-update.

**Slice 3 — make TLS real (#2, #3):** flip cert-pinning enforce to default-on
once a pin is observed (warn → enforce), and prefer `--pinnedpubkey` over `-k`.

**Slice 4 — bootstrap + exposure hardening:** OOB master-pubkey fingerprint at
enroll (#4/#5), pre-auth body cap + timeout (#9), persist the nonce cache (#14),
single-use invite tokens / no silent secret rotation (#15).

Ed25519 request signing stays throughout — private network + these are
defense-in-depth, not replacements.
