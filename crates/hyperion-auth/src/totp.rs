//! RFC 6238 TOTP — 6-digit codes, 30-second time step, SHA-1.
//!
//! Wire format compatible with Google Authenticator, 1Password, Authy,
//! Bitwarden, etc. Secrets are 20 bytes (160 bits — RFC recommendation)
//! base32-encoded for the otpauth:// URL.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use subtle::ConstantTimeEq;

const DIGITS: u32 = 6;
const TIME_STEP_SECS: u64 = 30;
/// How many adjacent time-steps either side of the current one count
/// as a valid code. 1 → ±30s tolerance for clock skew.
const SKEW_STEPS: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("base32 decode: {0}")]
    Base32(String),
    #[error("hmac key length")]
    HmacKey,
    #[error("code must be exactly {DIGITS} digits, got {0}")]
    CodeLength(usize),
    #[error("code must be all ASCII digits")]
    CodeNotDigits,
}

/// Generate a fresh 20-byte secret + return as a base32 string for
/// storage. Use `otpauth_url()` to render the QR-code URI for the
/// enrollment flow.
pub fn generate_secret_base32() -> String {
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill(&mut bytes);
    base32_encode(&bytes)
}

/// Build the otpauth:// URI a TOTP app reads when scanning the QR
/// code. `issuer` shows in the app's account list (e.g. "Hyperion");
/// `account` is the user-visible label (typically the username).
pub fn otpauth_url(issuer: &str, account: &str, secret_base32: &str) -> String {
    // Both issuer and account go in the path AND as ?issuer= for
    // compatibility — Google Authenticator wants the path form,
    // some others prefer the query form.
    let label_encoded =
        url::form_urlencoded::byte_serialize(format!("{issuer}:{account}").as_bytes())
            .collect::<String>();
    let issuer_encoded =
        url::form_urlencoded::byte_serialize(issuer.as_bytes()).collect::<String>();
    format!(
        "otpauth://totp/{label_encoded}?secret={secret_base32}&issuer={issuer_encoded}&algorithm=SHA1&digits={DIGITS}&period={TIME_STEP_SECS}"
    )
}

/// Compute the 6-digit TOTP code for a given Unix timestamp.
/// Public for testing; in production code use `verify_code` instead.
pub fn code_at(secret_base32: &str, ts: u64) -> Result<String, TotpError> {
    let key = base32_decode(secret_base32)?;
    let counter = ts / TIME_STEP_SECS;
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&counter.to_be_bytes());
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).map_err(|_| TotpError::HmacKey)?;
    mac.update(&counter_bytes);
    let hash = mac.finalize().into_bytes();
    // RFC 4226 dynamic truncation.
    let offset = (hash[hash.len() - 1] & 0x0F) as usize;
    let value = ((hash[offset] & 0x7F) as u32) << 24
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | (hash[offset + 3] as u32);
    let code = value % 10u32.pow(DIGITS);
    Ok(format!("{:0width$}", code, width = DIGITS as usize))
}

/// Verify a user-supplied code against the current time (with ±1-step
/// skew tolerance). Constant-time compare against each candidate.
pub fn verify_code(secret_base32: &str, supplied: &str) -> Result<bool, TotpError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_code_at(secret_base32, supplied, now)
}

/// Same as `verify_code` but with an explicit clock — used by tests.
pub fn verify_code_at(secret_base32: &str, supplied: &str, now: u64) -> Result<bool, TotpError> {
    if supplied.len() != DIGITS as usize {
        return Err(TotpError::CodeLength(supplied.len()));
    }
    if !supplied.chars().all(|c| c.is_ascii_digit()) {
        return Err(TotpError::CodeNotDigits);
    }
    let supplied_bytes = supplied.as_bytes();
    for step in -SKEW_STEPS..=SKEW_STEPS {
        let candidate_ts = (now as i64 + step * TIME_STEP_SECS as i64).max(0) as u64;
        let candidate = code_at(secret_base32, candidate_ts)?;
        if supplied_bytes.ct_eq(candidate.as_bytes()).unwrap_u8() == 1 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Generate N backup codes. Returns (plaintext_to_show, hashes_to_store).
/// Plaintext is `XXXX-XXXX` (8 random alphanumeric chars + separator),
/// hashes are blake3 hex.
pub fn generate_backup_codes(n: usize) -> (Vec<String>, Vec<String>) {
    let mut plain = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    for _ in 0..n {
        let code = random_backup_code();
        let h = hash_backup_code(&code);
        plain.push(code);
        hashes.push(h);
    }
    (plain, hashes)
}

/// Hash a backup code for comparison against the stored hash.
pub fn hash_backup_code(code: &str) -> String {
    // Normalise: strip dashes + upper-case so user can type either way.
    let norm: String = code
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    hex::encode(blake3::hash(norm.as_bytes()).as_bytes())
}

fn random_backup_code() -> String {
    // Use a base32-ish alphabet (no 0/1/O/I to avoid confusion).
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let mut chars = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            chars.push('-');
        }
        let idx = rng.gen_range(0..ALPHABET.len());
        chars.push(ALPHABET[idx] as char);
    }
    chars
}

// --- base32 (RFC 4648) encode/decode ---

const B32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in input {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = (buffer >> bits) & 0x1F;
            out.push(B32_ALPHABET[idx as usize] as char);
        }
    }
    if bits > 0 {
        let idx = (buffer << (5 - bits)) & 0x1F;
        out.push(B32_ALPHABET[idx as usize] as char);
    }
    out
}

fn base32_decode(input: &str) -> Result<Vec<u8>, TotpError> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    for c in input.chars() {
        if c == '=' || c == ' ' {
            continue;
        }
        let value = match c {
            'A'..='Z' => (c as u8 - b'A') as u32,
            'a'..='z' => (c as u8 - b'a') as u32,
            '2'..='7' => (c as u8 - b'2' + 26) as u32,
            other => return Err(TotpError::Base32(format!("invalid char {other:?}"))),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B reference vectors (for 8-digit codes, T_0 = 0,
    /// time-step = 30). We use 6 digits + SHA-1, so we verify against
    /// the truncated form of the published test vector.
    /// Secret in ASCII: "12345678901234567890" → base32:
    /// `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`
    #[test]
    fn rfc_6238_vector_t1_59s() {
        // RFC 6238 vector: T = 59 (counter = 1) → 8-digit code 94287082
        // 6-digit truncation = 287082.
        let secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = code_at(secret_b32, 59).expect("code");
        assert_eq!(code, "287082");
    }

    #[test]
    fn rfc_6238_vector_t1111111109() {
        // RFC 6238: T = 1111111109 → 8-digit 07081804 → 6 digits 081804
        let secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = code_at(secret_b32, 1111111109).expect("code");
        assert_eq!(code, "081804");
    }

    #[test]
    fn verify_accepts_current_and_skew() {
        let secret = generate_secret_base32();
        let now: u64 = 1_700_000_000;
        let current = code_at(&secret, now).expect("now");
        let prev = code_at(&secret, now - 30).expect("prev");
        let next = code_at(&secret, now + 30).expect("next");
        let two_ago = code_at(&secret, now - 60).expect("two_ago");
        assert!(verify_code_at(&secret, &current, now).expect("v cur"));
        assert!(verify_code_at(&secret, &prev, now).expect("v prev"));
        assert!(verify_code_at(&secret, &next, now).expect("v next"));
        // Outside ±1 step window must be rejected.
        assert!(!verify_code_at(&secret, &two_ago, now).expect("v 2ago"));
    }

    #[test]
    fn verify_rejects_wrong_length_and_non_digits() {
        let secret = generate_secret_base32();
        let err = verify_code(&secret, "12345").unwrap_err();
        assert!(matches!(err, TotpError::CodeLength(5)));
        let err = verify_code(&secret, "abcdef").unwrap_err();
        assert!(matches!(err, TotpError::CodeNotDigits));
    }

    #[test]
    fn otpauth_url_includes_required_fields() {
        let u = otpauth_url("Hyperion", "alice", "JBSWY3DPEHPK3PXP");
        assert!(u.starts_with("otpauth://totp/"));
        assert!(u.contains("Hyperion%3Aalice"));
        assert!(u.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(u.contains("issuer=Hyperion"));
        assert!(u.contains("algorithm=SHA1"));
        assert!(u.contains("digits=6"));
        assert!(u.contains("period=30"));
    }

    #[test]
    fn backup_codes_shape() {
        let (plain, hashes) = generate_backup_codes(10);
        assert_eq!(plain.len(), 10);
        assert_eq!(hashes.len(), 10);
        for c in &plain {
            assert_eq!(c.len(), 9, "9 chars incl dash: got {c:?}");
            assert!(c.chars().nth(4) == Some('-'));
        }
        // Hash matches.
        for (p, h) in plain.iter().zip(hashes.iter()) {
            assert_eq!(&hash_backup_code(p), h);
        }
    }

    #[test]
    fn backup_code_hash_is_normalised() {
        let h1 = hash_backup_code("ABCD-EFGH");
        let h2 = hash_backup_code("abcdefgh");
        let h3 = hash_backup_code("AbCd-eFgH");
        assert_eq!(h1, h2);
        assert_eq!(h1, h3);
    }

    #[test]
    fn base32_round_trip_arbitrary_bytes() {
        for n in [1usize, 5, 10, 20, 100] {
            let original: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let enc = base32_encode(&original);
            let back = base32_decode(&enc).expect("decode");
            assert_eq!(back, original, "len={n}");
        }
    }
}
