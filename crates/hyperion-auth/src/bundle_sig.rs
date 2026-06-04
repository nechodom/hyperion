//! Signed-URL helper for migration bundles.
//!
//! Source-side `hosting_export` returns a `bundle_id` plus a token
//! that covers `(bundle_id, exp_ts)`. The web layer serves the
//! bundle's files at `/api/migration/bundle/:bundle_id/:filename`
//! and only serves them when `?t=<token>` verifies — that lets the
//! source put the bundle behind a public URL safe to paste into a
//! target node's hctl or web UI.
//!
//! Cryptography: BLAKE3 keyed hash. Same primitive the CSRF code
//! uses, same audit trail of inputs (no key separation needed
//! because the format is distinct — payload contains `b"BUNDLE|"`
//! prefix, so a stolen migration token can never collide with a
//! CSRF or session token).

use base64::Engine;
use subtle::ConstantTimeEq;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const PREFIX: &[u8] = b"BUNDLE|";

/// Mint a signed token covering `(bundle_id, exp_ts)`. The signed
/// payload is opaque to the caller — they just round-trip it via
/// the `?t=…` query string and we verify on download.
pub fn mint(key: &[u8], bundle_id: &str, exp_ts: i64) -> String {
    let mut payload = Vec::with_capacity(PREFIX.len() + bundle_id.len() + 16);
    payload.extend_from_slice(PREFIX);
    payload.extend_from_slice(bundle_id.as_bytes());
    payload.push(b'|');
    payload.extend_from_slice(exp_ts.to_be_bytes().as_ref());
    let mac = blake3::keyed_hash(&key32(key), &payload);
    format!("{}.{}", B64.encode(payload), B64.encode(mac.as_bytes()))
}

/// Verify a migration token. Returns Ok with the contained `exp_ts`
/// when the token is well-formed, the MAC matches, and the
/// embedded bundle_id matches the caller's expectation.
///
/// The caller still has to compare `exp_ts` against `now_secs()`
/// — different endpoints want different freshness rules (a 1h
/// download window is typical).
pub fn verify(
    key: &[u8],
    bundle_id_expected: &str,
    token: &str,
) -> Result<i64, &'static str> {
    let (payload_b64, mac_b64) = token.split_once('.').ok_or("malformed token")?;
    let payload = B64.decode(payload_b64.as_bytes()).map_err(|_| "bad payload b64")?;
    let mac_given = B64.decode(mac_b64.as_bytes()).map_err(|_| "bad mac b64")?;

    // Layout: PREFIX || bundle_id || '|' || exp_ts (8 BE bytes)
    if !payload.starts_with(PREFIX) {
        return Err("wrong prefix");
    }
    let after_prefix = &payload[PREFIX.len()..];
    let pipe_pos = after_prefix
        .iter()
        .position(|b| *b == b'|')
        .ok_or("missing separator")?;
    if pipe_pos + 1 + 8 != after_prefix.len() {
        return Err("payload length wrong");
    }
    let bundle_id_bytes = &after_prefix[..pipe_pos];
    if bundle_id_bytes.ct_eq(bundle_id_expected.as_bytes()).unwrap_u8() != 1 {
        return Err("bundle_id mismatch");
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&after_prefix[pipe_pos + 1..]);
    let exp_ts = i64::from_be_bytes(ts_bytes);

    let expected = blake3::keyed_hash(&key32(key), &payload);
    if expected.as_bytes().ct_eq(mac_given.as_slice()).unwrap_u8() != 1 {
        return Err("mac mismatch");
    }
    Ok(exp_ts)
}

fn key32(key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if key.len() >= 32 {
        out.copy_from_slice(&key[..32]);
    } else {
        for (i, b) in key.iter().enumerate() {
            out[i] = *b;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-key-32-bytes-long-padding!!";

    #[test]
    fn round_trip_ok() {
        let t = mint(KEY, "mig_abc", 1700);
        let exp = verify(KEY, "mig_abc", &t).expect("verify");
        assert_eq!(exp, 1700);
    }

    #[test]
    fn wrong_bundle_rejected() {
        let t = mint(KEY, "mig_abc", 1700);
        assert!(verify(KEY, "mig_other", &t).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let t = mint(KEY, "mig_abc", 1700);
        let other = b"other-key-32-bytes-long-padding!";
        assert!(verify(other, "mig_abc", &t).is_err());
    }

    #[test]
    fn tampered_payload_rejected() {
        let t = mint(KEY, "mig_abc", 1700);
        // Flip the mac.
        let (p, _m) = t.split_once('.').expect("split");
        let evil = format!("{p}.{}", B64.encode([0u8; 32]));
        assert!(verify(KEY, "mig_abc", &evil).is_err());
    }

    #[test]
    fn malformed_tokens_rejected() {
        for bad in ["", ".", "no-dot", "###.###", "a.b.c"] {
            assert!(verify(KEY, "x", bad).is_err());
        }
    }

    #[test]
    fn csrf_token_does_not_verify_as_bundle_token() {
        // CSRF tokens have a different prefix (no PREFIX, ts is first
        // bytes instead). A CSRF token in the bundle slot must fail.
        let csrf = crate::csrf::mint(KEY, "sid-1", "*", 1700);
        assert!(verify(KEY, "mig_x", &csrf).is_err());
    }
}
