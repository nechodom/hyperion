-- Block C (worker cert pinning), warn-only phase. Each worker reports
-- the SPKI pin of its inbound RPC listener's TLS certificate on every
-- heartbeat (curl --pinnedpubkey form: base64(sha256(DER SPKI))). The
-- master records it here so it can (a) display which pin it has on file
-- per node, and (b) warn — without failing — if the cert presented on an
-- RPC connection ever differs. NULL until the first heartbeat carrying
-- it (or for nodes whose agent predates this feature / has remote_rpc
-- disabled). Later flips to enforced `--pinnedpubkey`.
ALTER TABLE nodes ADD COLUMN tls_spki_pin TEXT;
