-- Per-node shared secret hash for heartbeat authentication.
-- Generated on enrollment; node persists the plaintext locally, master
-- only stores BLAKE3(secret) for verification.
ALTER TABLE nodes ADD COLUMN secret_hash TEXT NOT NULL DEFAULT '';
