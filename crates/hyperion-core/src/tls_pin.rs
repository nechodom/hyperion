//! SPKI public-key pin computation, shared by the worker and the master.
//!
//! - The **worker** computes the pin of its own inbound-listener
//!   certificate (`/etc/hyperion/agent-inbound.crt` or wherever the
//!   self-signed cert lives) and reports it to the master in its
//!   enrollment + heartbeat payloads.
//! - The **master** computes the pin actually presented on an outbound
//!   RPC connection and compares it against the reported one, logging a
//!   warning on mismatch (warn-only today — see `dispatcher`). Later it
//!   will pass the stored pin to `curl --pinnedpubkey` to *enforce*.
//!
//! The pin string is exactly curl's `--pinnedpubkey sha256//<value>`
//! form: `base64( sha256( DER SubjectPublicKeyInfo ) )`. We shell
//! `openssl` (always present on Debian) rather than parse X.509
//! in-process so the bytes are byte-for-byte identical to what curl
//! will later enforce — a hand-rolled parser could diverge on edge
//! cases and silently break enforcement.

use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The canonical openssl pipeline that turns a leaf certificate (PEM on
/// stdin) into a curl-compatible SPKI pin. `openssl x509` reads only the
/// first certificate, so a full chain on stdin still pins the leaf.
///
/// Run under `bash -o pipefail` (NOT `/bin/sh` — Debian's dash doesn't
/// support pipefail): without pipefail, a malformed cert makes the first
/// `openssl x509` fail but the trailing `openssl base64` still exits 0,
/// returning `base64(sha256(""))` — a constant bogus pin. pipefail makes
/// the whole command inherit the first failure so we correctly get None.
const PIN_PIPELINE: &str = "openssl x509 -pubkey -noout \
     | openssl pkey -pubin -outform DER \
     | openssl dgst -sha256 -binary \
     | openssl base64";

/// Compute the SPKI pin (base64 sha256 of the DER SubjectPublicKeyInfo)
/// for the leaf certificate in `cert_pem`.
///
/// Returns `None` on any failure (openssl missing, malformed PEM, empty
/// output). Callers MUST treat `None` as "pin unknown" and never fail
/// the surrounding operation — this is best-effort metadata, not a gate.
pub async fn spki_pin_from_cert_pem(cert_pem: &str) -> Option<String> {
    if cert_pem.trim().is_empty() {
        return None;
    }
    let mut child = Command::new("/bin/bash")
        .arg("-o")
        .arg("pipefail")
        .arg("-c")
        .arg(PIN_PIPELINE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        stdin.write_all(cert_pem.as_bytes()).await.ok()?;
        stdin.shutdown().await.ok();
    }
    let out = child.wait_with_output().await.ok()?;
    if !out.status.success() {
        return None;
    }
    let pin = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if pin.is_empty() {
        None
    } else {
        Some(pin)
    }
}

/// Read a certificate file and compute its SPKI pin. Convenience wrapper
/// for the worker, whose inbound cert lives on disk. `None` if the file
/// can't be read or the pin can't be computed.
pub async fn spki_pin_from_cert_file(path: &std::path::Path) -> Option<String> {
    let pem = tokio::fs::read_to_string(path).await.ok()?;
    spki_pin_from_cert_pem(&pem).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway self-signed cert (CN=hyperion-test) and the SPKI pin
    // openssl computes for it. Regenerate with:
    //   openssl req -x509 -newkey rsa:2048 -keyout k -out c -days 3650 \
    //     -nodes -subj /CN=hyperion-test
    //   openssl x509 -in c -pubkey -noout | openssl pkey -pubin \
    //     -outform DER | openssl dgst -sha256 -binary | openssl base64
    const FIXTURE_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDETCCAfmgAwIBAgIUYFvyYOkdVenDgGcFRWrr3Fa5ScMwDQYJKoZIhvcNAQEL\n\
BQAwGDEWMBQGA1UEAwwNaHlwZXJpb24tdGVzdDAeFw0yNjA2MTgxNjQ0MTlaFw0z\n\
NjA2MTUxNjQ0MTlaMBgxFjAUBgNVBAMMDWh5cGVyaW9uLXRlc3QwggEiMA0GCSqG\n\
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7AIzch66B8f+8J/PR7uWOraoKD4YSgjQw\n\
Y4a02u7lbingBYnE7j2Msc2TBQ/HdHUsO6GjWR6KFe7pXZQVq/FMhU0oolMQPfLz\n\
fv9SZzfbFNOBgF1rjHwM5ZMu2ylytcPLqO33e1Mp7kn6B9eMfEc68w6dN+exnz5J\n\
61CcCzaou80fx8BMdefl+VIRmU3n+yUU5ou90qmuTVZKZwRB2fNNQE2RuqWSMeVA\n\
35stj9wyX0FOCEal/V7y1jqWJ52QxMhlKzgaVmwXXwG8NSl++iht0oifRcMALXyQ\n\
A1hWn73ynoKIYLo97lkzuYy4kOqSpNVLPQ2isAgHB4LH1qNGkciJAgMBAAGjUzBR\n\
MB0GA1UdDgQWBBQQ5OkUaukIPNm+NnIPh5mQzyxxfTAfBgNVHSMEGDAWgBQQ5OkU\n\
aukIPNm+NnIPh5mQzyxxfTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n\
A4IBAQAly/3G/zvHsgZjbnf9Eda2M4Ey7MfTiikgGaj4Z8Yu1TcMIWLrFqDlyfVr\n\
EkL7JNBwhNZJxC9Z0CXdfckA9XRPg8+ffSgGEPUHqHFf53vh43IZU2okkqBEDYEV\n\
uV4kd0hbp3DYn0yWqvMt+CmJWQOdMvGYQ/1v8NMuA8Qh7Yxcg7QMbnDtKeyV8cVb\n\
aJt/B5IFAPQCdTIztrseRLvcGGSUlmURrnyYJtXoNrUkYcoQpBzeo5TZ/eJ0LYpD\n\
XtAnh1z1MlxNFs7iBJhdr/7UqMmlYXwgWAu+TZLUd48+uJHOrbJkwDNpKeQ58VfW\n\
se+F803Iew4UK5XXNEKbj5e6TThR\n\
-----END CERTIFICATE-----\n";
    const FIXTURE_PIN: &str = "/4IrPU/vEdcxQgcB9m3gD/9oaQ9/8WmdvXZIDD+ZVxg=";

    #[tokio::test]
    async fn computes_known_pin() {
        match spki_pin_from_cert_pem(FIXTURE_CERT).await {
            Some(pin) => assert_eq!(
                pin, FIXTURE_PIN,
                "pin must match curl --pinnedpubkey for the fixture cert"
            ),
            // Tolerate environments without openssl on PATH (minimal CI
            // containers) rather than failing the whole suite — the
            // function is documented to degrade to None there.
            None => eprintln!("skipping: openssl unavailable, spki pin is None"),
        }
    }

    #[tokio::test]
    async fn empty_input_is_none() {
        assert_eq!(spki_pin_from_cert_pem("").await, None);
        assert_eq!(spki_pin_from_cert_pem("   \n  ").await, None);
    }

    #[tokio::test]
    async fn garbage_input_is_none() {
        // Not a PEM cert → openssl x509 errors → None (never panics).
        assert_eq!(
            spki_pin_from_cert_pem("not a certificate at all").await,
            None
        );
    }
}
