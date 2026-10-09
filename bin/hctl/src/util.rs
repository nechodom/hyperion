//! Small argument parsers and terminal helpers shared by the commands.

use anyhow::{bail, Context, Result};
use hyperion_rpc::wire::{HostingCreateReq, HostingSelector};
use hyperion_types::{DbProvision, HostingId, PhpVersion};
use hyperion_validate::{Domain, SystemUserName};
use std::io::{BufRead, IsTerminal, Write};
use std::str::FromStr;

/// A hosting is named by its id (ULID, no dots) or by its domain.
pub fn parse_selector(s: &str) -> Result<HostingSelector> {
    if s.contains('.') {
        Ok(HostingSelector::Domain(Domain::parse(s)?))
    } else {
        Ok(HostingSelector::Id(HostingId(s.to_string())))
    }
}

pub fn build_create(
    domain: &str,
    aliases: &[String],
    php: Option<&str>,
    db: Option<&str>,
    user: Option<&str>,
    proxy: Option<&str>,
) -> Result<HostingCreateReq> {
    let domain = Domain::parse(domain)?;
    let aliases = aliases
        .iter()
        .map(|a| Domain::parse(a))
        .collect::<Result<Vec<_>, _>>()?;
    let php_version = php
        .map(PhpVersion::from_str)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let database = db
        .map(DbProvision::from_str)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let system_user = user.map(SystemUserName::parse).transpose()?;
    let (kind, proxy_upstream_url) = match proxy {
        Some(url) => ("reverse_proxy".to_string(), Some(url.to_string())),
        None => ("php".to_string(), None),
    };
    Ok(HostingCreateReq {
        domain,
        aliases,
        php_version,
        database,
        system_user,
        kind,
        proxy_upstream_url,
    })
}

/// `10G`, `512M`, `1.5T`, `2048` (bytes). Binary units, like `du -h`.
pub fn parse_size(s: &str) -> Result<i64, String> {
    let t = s.trim();
    let (num, mult) = match t.char_indices().find(|(_, c)| c.is_ascii_alphabetic()) {
        None => (t, 1i64),
        Some((i, _)) => {
            let unit = t[i..].to_ascii_uppercase();
            let mult = match unit.trim_end_matches("IB").trim_end_matches('B') {
                "" => 1,
                "K" => 1 << 10,
                "M" => 1 << 20,
                "G" => 1 << 30,
                "T" => 1 << 40,
                _ => return Err(format!("unknown size unit in {s:?} (use K, M, G or T)")),
            };
            (t[..i].trim(), mult)
        }
    };
    let n: f64 = num
        .parse()
        .map_err(|_| format!("not a size: {s:?} (e.g. 2048, 500M, 10G)"))?;
    if !n.is_finite() || n < 0.0 {
        return Err(format!("size must be positive: {s:?}"));
    }
    Ok((n * mult as f64).round() as i64)
}

/// A limit in bytes; `None` = unlimited. A newtype because clap reads a
/// bare `Option<Option<_>>` field as "flag with an optional value".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeLimit(pub Option<i64>);

/// A size, or `none` / `unlimited` / `0` to clear the limit.
pub fn parse_opt_size(s: &str) -> Result<SizeLimit, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "none" | "unlimited" | "0" | "-" => Ok(SizeLimit(None)),
        _ => parse_size(s).map(|n| SizeLimit(Some(n))),
    }
}

/// `90`, `90s`, `30m`, `12h`, `7d` → seconds.
pub fn parse_duration(s: &str) -> Result<i64, String> {
    let t = s.trim();
    let (num, mult) = match t.chars().last() {
        Some('s') => (&t[..t.len() - 1], 1),
        Some('m') => (&t[..t.len() - 1], 60),
        Some('h') => (&t[..t.len() - 1], 3600),
        Some('d') => (&t[..t.len() - 1], 86_400),
        _ => (t, 1),
    };
    let n: i64 = num
        .parse()
        .map_err(|_| format!("not a duration: {s:?} (e.g. 3600, 30m, 12h, 7d)"))?;
    if n <= 0 {
        return Err(format!("duration must be positive: {s:?}"));
    }
    Ok(n * mult)
}

/// Ask before something destructive. `--yes` skips the question; with no
/// terminal on stdin (a script, a pipe) there is nobody to ask, so the
/// command runs — the same as it always did before the prompt existed.
pub fn confirm(question: &str, yes: bool) -> Result<()> {
    if yes || !std::io::stdin().is_terminal() {
        return Ok(());
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        bail!("aborted")
    }
}

/// A password for a command that sets one. Never taken from argv — any
/// local user can read another process's command line from /proc. With
/// `--password-stdin` it is the first line of stdin; otherwise a random
/// one is generated and the caller shows it once.
pub fn new_secret(from_stdin: bool) -> Result<(String, bool)> {
    if from_stdin {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("read password from stdin")?;
        let pw = line.trim_end_matches(['\r', '\n']).to_string();
        if pw.is_empty() {
            bail!("--password-stdin: stdin was empty");
        }
        Ok((pw, false))
    } else {
        Ok((generate_password(), true))
    }
}

/// 24 alphanumeric characters (~143 bits).
pub fn generate_password() -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_selector_domain_vs_id() {
        match parse_selector("example.cz").expect("ok") {
            HostingSelector::Domain(d) => assert_eq!(d.as_str(), "example.cz"),
            other => panic!("wrong: {other:?}"),
        }
        match parse_selector("01J7A8GQX").expect("ok") {
            HostingSelector::Id(id) => assert_eq!(id.0, "01J7A8GQX"),
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn build_create_full() {
        let r = build_create(
            "example.cz",
            &["www.example.cz".into()],
            Some("8.3"),
            Some("mariadb"),
            None,
            None,
        )
        .expect("build");
        assert_eq!(r.domain.as_str(), "example.cz");
        assert_eq!(r.aliases.len(), 1);
        assert_eq!(r.php_version, Some(PhpVersion::V8_3));
        assert_eq!(r.database, Some(DbProvision::MariaDB));
        assert_eq!(r.kind, "php");
    }

    #[test]
    fn build_create_static() {
        let r = build_create("a.cz", &[], None, None, None, None).expect("build");
        assert_eq!(r.php_version, None);
        assert_eq!(r.database, None);
        assert_eq!(r.system_user, None);
    }

    #[test]
    fn build_create_proxy() {
        let r = build_create("a.cz", &[], None, None, None, Some("http://127.0.0.1:3000"))
            .expect("build");
        assert_eq!(r.kind, "reverse_proxy");
        assert_eq!(
            r.proxy_upstream_url.as_deref(),
            Some("http://127.0.0.1:3000")
        );
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("2048"), Ok(2048));
        assert_eq!(parse_size("1K"), Ok(1024));
        assert_eq!(parse_size("500M"), Ok(500 * 1024 * 1024));
        assert_eq!(parse_size("10G"), Ok(10 << 30));
        assert_eq!(parse_size("10GiB"), Ok(10 << 30));
        assert_eq!(parse_size("1.5g"), Ok(3 << 29));
        assert!(parse_size("10X").is_err());
        assert!(parse_size("-1").is_err());
        assert_eq!(parse_opt_size("none"), Ok(SizeLimit(None)));
        assert_eq!(parse_opt_size("1T"), Ok(SizeLimit(Some(1 << 40))));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90"), Ok(90));
        assert_eq!(parse_duration("30m"), Ok(1800));
        assert_eq!(parse_duration("12h"), Ok(43_200));
        assert_eq!(parse_duration("7d"), Ok(604_800));
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("soon").is_err());
    }

    #[test]
    fn generated_passwords_are_long_and_distinct() {
        let a = generate_password();
        assert_eq!(a.len(), 24);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, generate_password());
    }
}
