//! A newline in a mail subject must not become a header.
//!
//! Operators can edit the care-report subject, the expiry subject and every
//! operator-alert title from Settings, and those strings are handed straight
//! to the SMTP layer. In most mail code a `\r\n` there is a `Bcc:` — it is
//! the classic header injection, and here it would be reachable by anyone
//! with panel access to the wording fields.
//!
//! It is closed by the LIBRARY: lettre encodes the whole subject as an
//! RFC 2047 encoded-word, so the CRLF ends up inside base64 rather than in
//! the header block. That is a dependency's behaviour, not ours, which is
//! exactly why it is pinned here — a lettre upgrade that changed it would
//! otherwise open the hole silently.

#[test]
fn a_newline_in_a_subject_cannot_inject_a_header() {
    use lettre::Message;
    let evil = "Hi\r\nBcc: attacker@evil.cz\r\nX-Injected: yes";
    let m = Message::builder()
        .from("a@x.cz".parse().expect("from"))
        .to("b@x.cz".parse().expect("to"))
        .subject(evil)
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body("body".to_string())
        .expect("build");
    let raw = String::from_utf8_lossy(&m.formatted()).to_lowercase();

    // The header block ends at the first blank line; everything the attacker
    // wanted must be inside the Subject value, not beside it.
    let headers = raw.split("\r\n\r\n").next().unwrap_or(&raw).to_string();
    assert!(
        !headers.contains("\nbcc:") && !headers.starts_with("bcc:"),
        "header injection via subject:\n{raw}"
    );
    assert!(
        !headers.contains("x-injected:"),
        "header injection via subject:\n{raw}"
    );
}

/// The same question for the RECIPIENT, which `resolve_recipients` may pass
/// through unparsed when it cannot make sense of it.
#[test]
fn a_newline_in_a_recipient_is_refused_rather_than_injected() {
    use lettre::Message;
    let built = Message::builder().from("a@x.cz".parse().expect("from")).to(
        "b@x.cz\r\nBcc: attacker@evil.cz"
            .parse()
            .unwrap_or_else(|_| "nobody@invalid".parse().expect("fallback")),
    );
    // The point is that the hostile string does not PARSE as a mailbox, so
    // it can never reach the header. If lettre ever accepted it, this would
    // build a message whose To carries a newline.
    let raw = String::from_utf8_lossy(
        &built
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .body("body".to_string())
            .expect("build")
            .formatted(),
    )
    .to_lowercase();
    assert!(
        !raw.contains("bcc:"),
        "header injection via recipient:\n{raw}"
    );
}
