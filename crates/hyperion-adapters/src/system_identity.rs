//! Server identity for the setup wizard: hostname and time zone.
//!
//! Neither could be set from the panel before, and both look like one-liners
//! that are not:
//!
//! * The hostname is also `/etc/hosts`' `127.0.1.1` line on Debian. Change one
//!   without the other and `sudo` prints "unable to resolve host" — and every
//!   wp-cli call runs through `sudo -u <site user>`, so every WordPress action
//!   starts with a resolver timeout and an error line on stderr.
//! * The master's node id IS its hostname (see `Service::current_node_id`), so
//!   the caller refuses a change once any hosting row exists. That guard lives
//!   in the service, which can count hostings; this module only validates and
//!   applies.

use crate::AdapterError;
use std::path::Path;
use tokio::process::Command;

const HOSTS: &str = "/etc/hosts";
const ZONEINFO: &str = "/usr/share/zoneinfo";

/// RFC 1123 host name, lower-cased. A single label (`s5`) is allowed; so is an
/// FQDN (`s5.example.net`), which is what Debian's installer would set too.
pub fn validate_hostname(raw: &str) -> Result<String, String> {
    let h = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return Err("hostname is empty".into());
    }
    if h.len() > 253 {
        return Err("hostname is longer than 253 characters".into());
    }
    for label in h.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!(
                "\"{h}\" has an empty or over-long part — each part between dots is 1 to 63 characters"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "\"{label}\" starts or ends with a hyphen, which host names do not allow"
            ));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(format!(
                "\"{h}\" may contain only letters, digits, hyphens and dots"
            ));
        }
    }
    Ok(h)
}

/// The shape of an IANA zone name (`Europe/Prague`, `UTC`,
/// `America/Argentina/Buenos_Aires`, `Etc/GMT+1`). Existence is checked
/// separately against the zoneinfo database.
pub fn timezone_shape_ok(tz: &str) -> bool {
    !tz.is_empty()
        && tz.len() <= 64
        && !tz.starts_with('/')
        && !tz.split('/').any(|p| p.is_empty() || p == "." || p == "..")
        && tz
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+'))
}

/// A zone the system can actually use.
pub fn validate_timezone(raw: &str) -> Result<String, String> {
    let tz = raw.trim();
    if !timezone_shape_ok(tz) {
        return Err(format!("\"{tz}\" is not a time zone name"));
    }
    if !Path::new(ZONEINFO).join(tz).is_file() {
        return Err(format!("unknown time zone \"{tz}\""));
    }
    Ok(tz.to_string())
}

/// `/etc/hosts` with its `127.0.1.1` line pointing at `fqdn`. Every other line
/// is kept as written. When there is no such line one is added after the
/// `127.0.0.1` line, which is where Debian's installer puts it.
pub fn rewrite_hosts(content: &str, fqdn: &str) -> String {
    let short = fqdn.split('.').next().unwrap_or(fqdn);
    let names = if short == fqdn {
        fqdn.to_string()
    } else {
        format!("{fqdn} {short}")
    };
    let wanted = format!("127.0.1.1\t{names}");
    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in content.lines() {
        let first = line.split_whitespace().next().unwrap_or("");
        if first == "127.0.1.1" {
            if !replaced {
                out.push(wanted.clone());
                replaced = true;
            }
            continue;
        }
        out.push(line.to_string());
    }
    if !replaced {
        let at = out
            .iter()
            .position(|l| l.split_whitespace().next() == Some("127.0.0.1"))
            .map(|i| i + 1)
            .unwrap_or(0);
        out.insert(at, wanted);
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// The static hostname as `/etc/hostname` has it.
pub async fn current_hostname() -> String {
    tokio::fs::read_to_string("/etc/hostname")
        .await
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// The configured zone, from the `/etc/localtime` symlink.
pub async fn current_timezone() -> String {
    match tokio::fs::read_link("/etc/localtime").await {
        Ok(p) => {
            let s = p.to_string_lossy().to_string();
            s.split_once("zoneinfo/")
                .map(|(_, z)| z.to_string())
                .unwrap_or_default()
        }
        Err(_) => String::new(),
    }
}

async fn run(cmd: &str, args: &[&str]) -> Result<(), AdapterError> {
    let out = Command::new(cmd).args(args).output().await?;
    if out.status.success() {
        return Ok(());
    }
    Err(AdapterError::Command {
        cmd: format!("{cmd} {}", args.join(" ")),
        code: out.status.code().unwrap_or(-1),
        stderr_tail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
    })
}

/// Set the hostname (already validated) and keep `/etc/hosts` in step.
pub async fn apply_hostname(fqdn: &str) -> Result<(), AdapterError> {
    run("/usr/bin/hostnamectl", &["set-hostname", fqdn]).await?;
    let current = tokio::fs::read_to_string(HOSTS).await.unwrap_or_default();
    let next = rewrite_hosts(&current, fqdn);
    if next != current {
        let tmp = format!("{HOSTS}.hyperion-tmp");
        tokio::fs::write(&tmp, next.as_bytes()).await?;
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).await?;
        }
        tokio::fs::rename(&tmp, HOSTS).await?;
    }
    Ok(())
}

/// Set the time zone (already validated).
pub async fn apply_timezone(tz: &str) -> Result<(), AdapterError> {
    run("/usr/bin/timedatectl", &["set-timezone", tz]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames() {
        assert_eq!(
            validate_hostname("S5.Example.NET.").unwrap(),
            "s5.example.net"
        );
        assert_eq!(validate_hostname("s5").unwrap(), "s5");
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-s5.example.net").is_err());
        assert!(validate_hostname("s5..example.net").is_err());
        assert!(validate_hostname("s5_x.example.net").is_err());
        assert!(validate_hostname("s5.example.net; reboot").is_err());
        assert!(validate_hostname(&"a".repeat(64)).is_err());
    }

    #[test]
    fn timezone_shapes() {
        assert!(timezone_shape_ok("Europe/Prague"));
        assert!(timezone_shape_ok("UTC"));
        assert!(timezone_shape_ok("America/Argentina/Buenos_Aires"));
        assert!(timezone_shape_ok("Etc/GMT+1"));
        assert!(!timezone_shape_ok("../../etc/passwd"));
        assert!(!timezone_shape_ok("/etc/localtime"));
        assert!(!timezone_shape_ok("Europe/"));
        assert!(!timezone_shape_ok("Europe/Prague;id"));
        assert!(!timezone_shape_ok(""));
    }

    #[test]
    fn hosts_line_is_replaced_in_place() {
        let before = "127.0.0.1\tlocalhost\n127.0.1.1\tvps-3f91a2\n\n::1 localhost ip6-localhost\n";
        let after = rewrite_hosts(before, "s5.example.net");
        assert_eq!(
            after,
            "127.0.0.1\tlocalhost\n127.0.1.1\ts5.example.net s5\n\n::1 localhost ip6-localhost\n"
        );
    }

    #[test]
    fn hosts_line_is_added_after_localhost_when_missing() {
        let before = "127.0.0.1 localhost\n::1 localhost\n";
        let after = rewrite_hosts(before, "s5");
        assert_eq!(after, "127.0.0.1 localhost\n127.0.1.1\ts5\n::1 localhost\n");
    }

    #[test]
    fn duplicate_hosts_lines_collapse_to_one() {
        let before = "127.0.0.1 localhost\n127.0.1.1 a\n127.0.1.1 b\n";
        assert_eq!(
            rewrite_hosts(before, "s5.example.net"),
            "127.0.0.1 localhost\n127.0.1.1\ts5.example.net s5\n"
        );
    }

    #[test]
    fn rewrite_is_idempotent() {
        let once = rewrite_hosts("127.0.0.1 localhost\n", "s5.example.net");
        assert_eq!(rewrite_hosts(&once, "s5.example.net"), once);
    }
}
