//! How an extra FTP login is spelled.
//!
//! Lives here rather than in the FTP adapter because it is pure string
//! policy with no system in it, and BOTH sides need it: the adapter builds
//! the login it hands to `useradd`, and the panel renders the exact login a
//! given name would produce so the form does not promise a shape the 32-byte
//! limit cannot deliver.

use crate::ValidationError;

/// A Linux login is capped at 32 bytes (`useradd`, and `utmp`'s `ut_user`).
pub const MAX_LOGIN_LEN: usize = 32;

/// How much of those 32 bytes the operator's own name may take.
///
/// The rest belongs to the domain qualifier, and the split is fixed rather
/// than "whatever is left" so the limit is the same on every hosting. An
/// operator who learns "names go up to 16 characters" on one site is not
/// told a different number on the next one.
pub const MAX_LOGIN_NAME_LEN: usize = 16;

/// Shortest useful qualifier: 10 characters of domain, a dash, and the
/// 4-character tag. `MAX_LOGIN_NAME_LEN` is chosen so this always fits.
const MIN_QUALIFIER_LEN: usize = 15;
const DOMAIN_TAG_LEN: usize = 4;

/// Build the login for an extra FTP account: `<name>.<domain>`.
///
/// The domain is not decoration. `passwd` is a NODE-WIDE namespace, so a bare
/// "deploy" on two sites is a collision that `useradd` reports without ever
/// naming the other site. Qualifying with the domain makes the login unique
/// by construction and makes `getent passwd` readable.
///
/// The catch is the 32-byte cap. `<name>.<domain>` fits comfortably for
/// `example.cz`, and not at all for the long municipal and school domains
/// this panel actually hosts: `obecni-urad-velke-prilepy.cz` is 28 characters,
/// which would leave three for the name, and a 31-character domain would leave
/// zero — no extra login could ever be created for that site. So when the full
/// domain does not fit, it is SHORTENED rather than the operator being turned
/// away:
///
/// * `deploy` + `example.cz`                   -> `deploy.example.cz`
/// * `deploy` + `obecni-urad-velke-prilepy.cz` -> `deploy.obecni-urad-velke-pr-3f9a`
///
/// The trailing tag is 4 hex characters of BLAKE3 over the FULL domain, and it
/// is what keeps the shortened form unique: two sites sharing the first twenty
/// characters of their domain still get different logins. BLAKE3 is used
/// because the tag is persisted in `passwd` forever — `DefaultHasher` is not
/// stable across Rust releases and would silently rename accounts on upgrade.
///
/// A tag collision is possible in principle and harmless in practice:
/// the FTP adapter refuses a login the system already has, so the
/// operator is told to pick another name rather than getting someone else's
/// account.
pub fn compose_extra_login(name: &str, domain: &str) -> Result<String, ValidationError> {
    let domain = domain.trim().trim_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err(ValidationError::InvalidFtpLogin(
            "this hosting has no domain to qualify the login with".into(),
        ));
    }
    // An operator pasting a login back in gets the name they originally
    // typed, not `deploy.example.cz.example.cz`.
    let name = name.trim().trim_matches('.').to_ascii_lowercase();
    let name = name
        .strip_suffix(&format!(".{domain}"))
        .unwrap_or(&name)
        .trim_matches('.')
        .to_string();

    if name.is_empty() {
        return Err(ValidationError::InvalidFtpLogin(
            "give the login a name — Hyperion adds the domain to it".into(),
        ));
    }
    // Dots separate the name from the qualifier, so the name itself may not
    // contain one: `deploy.staging` would read as an already-qualified login.
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        return Err(ValidationError::InvalidFtpLogin(format!(
            "the name {name:?} may use lowercase letters, digits, underscore and \
             dash only — Hyperion adds the domain itself"
        )));
    }
    if name.starts_with('-') {
        return Err(ValidationError::InvalidFtpLogin(
            "the name may not start with a dash".into(),
        ));
    }
    if name.len() > MAX_LOGIN_NAME_LEN {
        return Err(ValidationError::InvalidFtpLogin(format!(
            "the name {name:?} is {} characters and the limit is \
             {MAX_LOGIN_NAME_LEN} — Linux allows {MAX_LOGIN_LEN} for the whole login \
             and the domain takes the rest",
            name.len(),
        )));
    }

    let full = format!("{name}.{domain}");
    let login = if full.len() <= MAX_LOGIN_LEN {
        full
    } else {
        // Everything after `<name>.` is the qualifier's to spend.
        let budget = MAX_LOGIN_LEN - name.len() - 1;
        debug_assert!(budget >= MIN_QUALIFIER_LEN);
        let head_len = budget - DOMAIN_TAG_LEN - 1;
        // Dots become dashes: truncating a domain can land right after one,
        // and `deploy.obecni.-3f9a` is both ugly and a `..` risk once the
        // dash is stripped.
        let flat: String = domain
            .chars()
            .map(|c| if c == '.' { '-' } else { c })
            .collect();
        let head = flat
            .get(..head_len)
            .unwrap_or(&flat)
            .trim_end_matches('-')
            .to_string();
        let tag = domain_tag(&domain);
        format!("{name}.{head}-{tag}")
    };

    // The composed login is what actually reaches useradd and vsftpd's
    // user_config_dir, so it is checked by the same rule as any other login
    // rather than trusted because this function built it.
    validate_login_name(&login)?;
    Ok(login)
}

/// 4 hex characters of BLAKE3 over the domain — stable across releases,
/// because it ends up in `passwd` and must never change under a hosting.
fn domain_tag(domain: &str) -> String {
    let h = blake3::hash(domain.as_bytes());
    hex::encode(&h.as_bytes()[..DOMAIN_TAG_LEN / 2])
}

/// Reject a login that cannot safely become a filename under
/// `user_config_dir`, or a passwd field.
///
/// Dots are ALLOWED. They were banned outright when every login was a
/// system-user name that could not contain one; extra FTP logins are named
/// `<name>.<domain>`, so a blanket ban would refuse every one of them. The
/// danger was never the dot itself but path traversal, so that is what this
/// refuses: a separator, a name that IS `.` or `..`, and a leading dot (which
/// would hide the config file from anything listing the directory).
pub fn validate_login_name(login: &str) -> Result<(), ValidationError> {
    if login.is_empty() {
        return Err(ValidationError::InvalidFtpLogin("empty FTP login".into()));
    }
    // useradd caps a login at 32 characters; a longer one fails at the shell
    // with a message that says nothing about which part was too long.
    if login.len() > MAX_LOGIN_LEN {
        return Err(ValidationError::InvalidFtpLogin(format!(
            "FTP login {login:?} is {} characters — the limit is {MAX_LOGIN_LEN}",
            login.len()
        )));
    }
    if login == "." || login == ".." || login.starts_with('.') || login.starts_with('-') {
        return Err(ValidationError::InvalidFtpLogin(format!(
            "FTP login {login:?} may not start with a dot or a dash"
        )));
    }
    if login.contains("..") {
        return Err(ValidationError::InvalidFtpLogin(format!(
            "FTP login {login:?} may not contain '..'"
        )));
    }
    if !login
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(ValidationError::InvalidFtpLogin(format!(
            "FTP login {login:?} may use lowercase letters, digits, dot, underscore and dash only"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{compose_extra_login, validate_login_name, MAX_LOGIN_LEN, MAX_LOGIN_NAME_LEN};

    /// The pretty case: the domain fits, so the login reads exactly as the
    /// operator was promised in the form.
    #[test]
    fn a_domain_that_fits_is_used_whole() {
        assert_eq!(
            compose_extra_login("deploy", "example.cz").unwrap(),
            "deploy.example.cz"
        );
        assert_eq!(
            compose_extra_login("  Deploy  ", "Example.CZ").unwrap(),
            "deploy.example.cz"
        );
        assert_eq!(
            compose_extra_login("ci", "masarykovazs.eu").unwrap(),
            "ci.masarykovazs.eu"
        );
    }

    /// The regression this whole function exists for. `<name>.<domain>` against
    /// a 32-byte cap left three characters for the name on an ordinary Czech
    /// municipal domain, and NOTHING at all past 31 characters — the panel
    /// told the operator their name could be "at most 0" characters, with no
    /// way out, for a domain they do not control.
    #[test]
    fn a_domain_too_long_to_fit_is_shortened_not_refused() {
        // 28 characters: three would have been left for the name.
        let login = compose_extra_login("deploy", "obecni-urad-velke-prilepy.cz").unwrap();
        assert!(login.len() <= MAX_LOGIN_LEN, "{login} is too long");
        assert!(login.starts_with("deploy."), "{login} lost the name");
        assert!(
            login.contains("obecni-urad"),
            "{login} should still name the site"
        );

        // 32+ characters: previously impossible to create an account at all.
        for domain in [
            "zakladni-skola-hradec-kralove.cz",
            "mestska-knihovna-usti-nad-labem.cz",
            "a-very-long-domain-name-that-nobody-would-choose-but-is-legal.example.com",
        ] {
            let login = compose_extra_login("deploy", domain)
                .unwrap_or_else(|e| panic!("refused {domain}: {e}"));
            assert!(login.len() <= MAX_LOGIN_LEN, "{login} is too long");
            validate_login_name(&login).unwrap_or_else(|e| panic!("{login} invalid: {e}"));
        }
    }

    /// Whatever the domain, the composed login must be something useradd and
    /// vsftpd will actually accept. A domain may be up to 253 characters.
    #[test]
    fn every_domain_length_yields_a_usable_login() {
        for name in ["a", "ci", "deploy", &"x".repeat(MAX_LOGIN_NAME_LEN)] {
            for len in 3..=253usize {
                // Shaped like a real domain: labels, dots, and a TLD.
                let body = "ab-cd."
                    .repeat(len.div_ceil(6))
                    .chars()
                    .take(len - 3)
                    .collect::<String>();
                let domain = format!("{}.cz", body.trim_end_matches(['.', '-']));
                let login = compose_extra_login(name, &domain)
                    .unwrap_or_else(|e| panic!("refused {name}@{domain}: {e}"));
                assert!(
                    login.len() <= MAX_LOGIN_LEN,
                    "{login} is {} characters",
                    login.len()
                );
                validate_login_name(&login).unwrap_or_else(|e| panic!("{login} invalid: {e}"));
                assert!(
                    login.starts_with(&format!("{name}.")),
                    "{login} does not start with the operator's name"
                );
            }
        }
    }

    /// Shortening must not collapse two sites onto one login — that is the
    /// entire reason the domain is in the login in the first place. These two
    /// share their first 24 characters.
    #[test]
    fn two_long_domains_sharing_a_prefix_get_different_logins() {
        let a = compose_extra_login("deploy", "zakladni-skola-praha-sever.cz").unwrap();
        let b = compose_extra_login("deploy", "zakladni-skola-praha-jizni.cz").unwrap();
        assert_ne!(a, b, "two sites collapsed onto one login");
    }

    /// The tag is persisted in `passwd`. If a refactor changes the hash, every
    /// existing shortened account silently stops matching its site — so the
    /// exact output is pinned rather than merely shape-checked.
    #[test]
    fn the_shortened_form_is_stable() {
        assert_eq!(
            compose_extra_login("deploy", "obecni-urad-velke-prilepy.cz").unwrap(),
            compose_extra_login("deploy", "obecni-urad-velke-prilepy.cz").unwrap(),
        );
        let pinned = compose_extra_login("deploy", "obecni-urad-velke-prilepy.cz").unwrap();
        assert_eq!(
            pinned, "deploy.obecni-urad-velke-pr-8527",
            "the shortened login changed — every existing account with this \
             shape would be orphaned in passwd"
        );
    }

    /// An operator who copies the login out of the panel and pastes it back
    /// into the form must not get the domain twice.
    #[test]
    fn pasting_a_full_login_back_does_not_double_the_domain() {
        assert_eq!(
            compose_extra_login("deploy.example.cz", "example.cz").unwrap(),
            "deploy.example.cz"
        );
        // A "name" that is only the domain leaves nothing for the operator
        // to have chosen, so it is refused rather than turned into a login
        // identical to the domain.
        assert!(compose_extra_login("example.cz", "example.cz").is_err());
    }

    /// The name is the operator's half of a fixed budget, so the cap does not
    /// move from hosting to hosting, and the refusal says what the cap is.
    #[test]
    fn an_over_long_name_is_refused_with_the_limit_named() {
        let err = compose_extra_login(&"d".repeat(MAX_LOGIN_NAME_LEN + 1), "example.cz")
            .expect_err("must refuse");
        assert!(
            format!("{err}").contains(&MAX_LOGIN_NAME_LEN.to_string()),
            "the refusal should name the limit: {err}"
        );
        assert!(compose_extra_login(&"d".repeat(MAX_LOGIN_NAME_LEN), "example.cz").is_ok());
    }

    /// Dots separate the name from the qualifier, so a dot inside the name
    /// would read as an already-qualified login.
    #[test]
    fn a_name_hyperion_cannot_qualify_is_refused() {
        for bad in [
            "deploy.staging",
            "-deploy",
            "de ploy",
            "de/ploy",
            "de:ploy",
            "",
            "   ",
            "...",
        ] {
            assert!(
                compose_extra_login(bad, "example.cz").is_err(),
                "accepted a bad name: {bad:?}"
            );
        }
        assert!(compose_extra_login("deploy", "").is_err(), "empty domain");
    }

    /// Extra FTP logins are `<name>.<domain>`, so a blanket ban on dots —
    /// which is what the old check did, inherited from system-user names —
    /// would refuse every one of them.
    #[test]
    fn a_dotted_login_is_accepted() {
        for ok in [
            "deploy.example.cz",
            "ci.masarykovazs.eu",
            "a.b.c.example.com",
            "designer_2.example.cz",
            "x-y.example.cz",
        ] {
            assert!(validate_login_name(ok).is_ok(), "rejected: {ok}");
        }
    }

    /// The login becomes a filename under vsftpd's user_config_dir, so the
    /// traversal shapes must still be refused — that was the real reason
    /// dots were banned, and it has to survive relaxing them.
    #[test]
    fn traversal_and_hidden_names_are_refused() {
        for bad in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "a/b",
            ".hidden.example.cz",
            "deploy..example.cz",
            "-deploy.example.cz",
            "UPPER.example.cz",
            "with space.example.cz",
            "with:colon.example.cz",
            "with\nnewline.example.cz",
        ] {
            assert!(
                validate_login_name(bad).is_err(),
                "accepted a dangerous login: {bad:?}"
            );
        }
    }

    /// useradd caps a login at 32 characters. Catching it here means the
    /// message can say WHICH part is too long; useradd only says "invalid
    /// user name", which sends the operator to look at the characters.
    #[test]
    fn an_over_long_login_is_refused_with_a_reason() {
        let long = format!("deploy.{}.example.com", "x".repeat(40));
        let err = validate_login_name(&long).expect_err("must refuse");
        assert!(
            format!("{err}").contains("32"),
            "the refusal should name the limit: {err}"
        );
        assert!(
            validate_login_name(&"a".repeat(32)).is_ok(),
            "32 is allowed"
        );
        assert!(validate_login_name(&"a".repeat(33)).is_err(), "33 is not");
    }
}
