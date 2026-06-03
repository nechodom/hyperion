//! CSRF tokens — HMAC-blake3 of session_id + form_id + timestamp.

use base64::Engine;
use subtle::ConstantTimeEq;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Tokens valid for 4 hours. Long enough that an operator who opens a
/// form, gets distracted, and comes back later doesn't lose their work.
/// The blast radius of a stolen token is bounded by the session
/// cookie (HttpOnly, SameSite) — token alone is useless without it.
const TTL_SECS: i64 = 4 * 60 * 60;
/// Sentinel `form_id` for session-wide tokens — one token that works
/// for any POST in the same session. Used by the universal `csrf_token`
/// template variable.
pub const SESSION_WIDE_FORM_ID: &str = "*";

/// Mint a CSRF token scoped to `(session_id, form_id)` valid for 30 minutes.
pub fn mint(key: &[u8], session_id: &str, form_id: &str, now: i64) -> String {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(now.to_be_bytes().as_ref());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(session_id.as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(form_id.as_bytes());
    let mac = blake3::keyed_hash(&key32(key), &payload);
    format!("{}.{}", B64.encode(payload), B64.encode(mac.as_bytes()))
}

/// Verify a CSRF token.
pub fn verify(key: &[u8], session_id: &str, form_id: &str, token: &str, now: i64) -> bool {
    let Some((payload_b64, mac_b64)) = token.split_once('.') else {
        return false;
    };
    let Ok(payload) = B64.decode(payload_b64.as_bytes()) else {
        return false;
    };
    let Ok(mac_given) = B64.decode(mac_b64.as_bytes()) else {
        return false;
    };
    // payload = 8 (ts) + 1 (|) + session_id + 1 + form_id
    if payload.len() < 10 {
        return false;
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&payload[..8]);
    let ts = i64::from_be_bytes(ts_bytes);
    if now > ts + TTL_SECS || now < ts - 60 {
        return false;
    }
    // Re-verify scope
    let mut expected = Vec::with_capacity(payload.len());
    expected.extend_from_slice(&ts_bytes);
    expected.extend_from_slice(b"|");
    expected.extend_from_slice(session_id.as_bytes());
    expected.extend_from_slice(b"|");
    expected.extend_from_slice(form_id.as_bytes());
    if expected.as_slice().ct_eq(payload.as_slice()).unwrap_u8() != 1 {
        return false;
    }
    let mac_expected = blake3::keyed_hash(&key32(key), &payload);
    mac_expected
        .as_bytes()
        .ct_eq(mac_given.as_slice())
        .unwrap_u8()
        == 1
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

    #[test]
    fn round_trip_ok() {
        let key = b"some-secret-key-with-enough-bytes-to-fill-32";
        let tok = mint(key, "sid-1", "create-hosting", 1000);
        assert!(verify(key, "sid-1", "create-hosting", &tok, 1100));
    }

    #[test]
    fn different_session_rejected() {
        let key = b"some-secret-key-with-enough-bytes-to-fill-32";
        let tok = mint(key, "sid-1", "create-hosting", 1000);
        assert!(!verify(key, "sid-other", "create-hosting", &tok, 1100));
    }

    #[test]
    fn different_form_rejected() {
        let key = b"some-secret-key-with-enough-bytes-to-fill-32";
        let tok = mint(key, "sid-1", "create-hosting", 1000);
        assert!(!verify(key, "sid-1", "delete-hosting", &tok, 1100));
    }

    #[test]
    fn expired_rejected() {
        let key = b"some-secret-key-with-enough-bytes-to-fill-32";
        let tok = mint(key, "sid-1", "x", 1000);
        // Reject just after the 4-hour TTL window.
        assert!(!verify(key, "sid-1", "x", &tok, 1000 + 4 * 60 * 60 + 1));
        // Still valid within the window.
        assert!(verify(key, "sid-1", "x", &tok, 1000 + 30 * 60));
    }

    #[test]
    fn session_wide_token_works_for_any_form_id() {
        let key = b"some-secret-key-with-enough-bytes-to-fill-32";
        // Mint with the wildcard form_id.
        let tok = mint(key, "sid-1", SESSION_WIDE_FORM_ID, 1000);
        // Verifies against the same wildcard.
        assert!(verify(key, "sid-1", SESSION_WIDE_FORM_ID, &tok, 1100));
        // Does NOT verify against a specific form_id (caller must
        // explicitly try the wildcard alongside the scoped check).
        assert!(!verify(key, "sid-1", "/some/route", &tok, 1100));
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = b"some-secret-key-with-enough-bytes-to-fill-32";
        let tok = mint(key, "sid-1", "x", 1000);
        let (_, mac) = tok.split_once('.').expect("split");
        let bogus_payload = b"\x00\x00\x00\x00\x00\x00\x00\x00|sid-1|x";
        let evil = format!("{}.{}", B64.encode(bogus_payload), mac);
        assert!(!verify(key, "sid-1", "x", &evil, 1000));
    }

    #[test]
    fn malformed_rejected() {
        let key = b"k";
        for bad in ["", ".", "no-dot", "a.b.c", "###.###"] {
            assert!(!verify(key, "s", "f", bad, 0));
        }
    }
}
